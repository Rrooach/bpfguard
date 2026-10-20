#!/usr/bin/env python3
"""Cooperative, fixed-work search experiments; measurement, never audit evidence."""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import resource
import selectors
import shutil
import signal
import stat
import statistics
import subprocess
import sys
import time
import uuid

import analyze

CGROOT = Path('/sys/fs/cgroup')
MAX_FILES = 200000
MAX_BYTES = 8 * 1024 ** 3
GREP_OPTIONS = ['-r', '-l', '-Z', '-F', '--binary-files=without-match', '--exclude-dir=.git']


def dump(path, value):
    with Path(path).open('x', encoding='utf-8') as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.write('\n')


def sha_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as src:
        for block in iter(lambda: src.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def corpus_inventory(root):
    """Hash before cache preparation, and again only after the campaign."""
    files, permissions, total = [], [], 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != '.git')
        for name in dirs + sorted(names):
            path = Path(directory) / name
            if path.is_symlink():
                raise ValueError('corpus symlinks are unsupported: ' + str(path))
        paths = [Path(directory)] + [Path(directory) / name for name in sorted(names)]
        for path in paths:
            metadata = path.lstat()
            attrs = {}
            if hasattr(os, 'listxattr'):
                for key in sorted(os.listxattr(path)):
                    attrs[key] = hashlib.sha256(os.getxattr(path, key)).hexdigest()
            permissions.append({'path': str(path.relative_to(root)), 'mode': stat.S_IMODE(metadata.st_mode),
                                'uid': metadata.st_uid, 'gid': metadata.st_gid, 'xattrs': attrs})
        for name in sorted(names):
            path = Path(directory) / name
            if not path.is_file():
                raise ValueError('corpus must contain only regular files/directories')
            st = path.stat()
            total += st.st_size
            if total > MAX_BYTES or len(files) >= MAX_FILES:
                raise ValueError('corpus exceeds bounded inventory budget')
            files.append({'path': str(path.relative_to(root)), 'size': st.st_size,
                          'sha256': sha_file(path)})
    if not files:
        raise ValueError('empty corpus')
    files.sort(key=lambda row: row['path'])
    permissions.sort(key=lambda row: row['path'])
    return {'files': files, 'bytes': total, 'sha256': canonical_digest(files),
            'permission_scope_sha256': canonical_digest(permissions), 'permissions': permissions}


def security_context():
    namespaces = {name: Path('/proc/self/ns', name).stat().st_ino for name in ('user', 'mnt')}
    try:
        label = Path('/proc/self/attr/current').read_text().strip()
    except OSError as error:
        label = {'unavailable_errno': error.errno}
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    authority = {name: status.get(name, '').strip() for name in
                 ('Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp', 'Seccomp_filters')}
    return {'euid': os.geteuid(), 'egid': os.getegid(), 'groups': sorted(os.getgroups()),
            'namespaces': namespaces, 'lsm_label': label, 'authority': authority}


def query_reuse_key(inventory, query, options, grep_sha256, repo_version, permission_context):
    """Never share on query text alone: version/options/permission view are bound."""
    if not inventory.get('permission_scope_sha256') or not repo_version:
        raise ValueError('query reuse requires repository version and permission scope')
    return canonical_digest({'repository_version': repo_version, 'content_sha256': inventory['sha256'],
        'permission_scope_sha256': inventory['permission_scope_sha256'], 'query': query,
        'options': options, 'grep_sha256': grep_sha256, 'security_context': permission_context})


def protocol_line(proc, timeout=120):
    data, deadline = bytearray(), time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                continue
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError('Observer closed protocol output; inspect observer.stderr')
            data.extend(chunk)
            if len(data) > 1024 * 1024:
                raise RuntimeError('Observer protocol output exceeds bound')
            if b'\n' in data:
                if data.count(b'\n') != 1 or not data.endswith(b'\n'):
                    raise RuntimeError('Observer emitted multiple protocol responses')
                return json.loads(data)
    raise RuntimeError('Observer protocol timed out')


def freeze_group(group, expected, frozen):
    if cgroup_identity(group) != expected:
        raise RuntimeError('cgroup identity changed before freezer barrier')
    (group / 'cgroup.freeze').write_text(str(int(frozen)))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        fields = dict(line.split() for line in (group / 'cgroup.events').read_text().splitlines())
        if fields.get('frozen') == str(int(frozen)):
            return
        time.sleep(.01)
    raise RuntimeError('cgroup freezer barrier timed out')


def reap_with_usage(proc, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
        if pid:
            proc.returncode = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
            return {'returncode': proc.returncode, 'user_seconds': usage.ru_utime,
                    'system_seconds': usage.ru_stime, 'max_rss_kb': usage.ru_maxrss,
                    'scope': 'COLLECTOR_PROCESS_LIFETIME_WAIT4_INCLUDING_REAPED_CHILDREN'}
        time.sleep(.01)
    raise RuntimeError('collector finalization timed out')


class ProfileObserver:
    """One real recorder/lifecycle instance for the same shared leaf in all arms."""
    def __init__(self, args, trial, group, identity, run_id, root_pid):
        self.args, self.trial, self.group, self.identity = args, trial, group, identity
        self.run_id, self.process, self.stderr = run_id, None, None
        self.config = {'protocol_version': 2, 'deployment': {'deployment_kind': 'DIRECT',
            'configuration': {'root_pid': root_pid, 'expected_cgroup_path': '/' + str(group.relative_to(CGROOT)),
                'require_dedicated_cgroup': True, 'limits': {'max_proc_entries': 131072, 'max_cgroup_nodes': 4096,
                    'max_cgroup_depth': 64, 'max_open_fds_per_process': 8192}}},
            'recorder_object_path': str(args.recorder_object), 'recorder_object_sha256': args.recorder_sha256,
            'lifecycle_object_path': str(args.lifecycle_object), 'lifecycle_object_sha256': args.lifecycle_sha256,
            'output_directory': str(trial / 'observer'), 'run_id': run_id, 'epoch': 1,
            'profile': args.observer_profile, 'object_resolution_mode': 'KERNEL_OBJECT_EXPANDED_PARTIAL',
            'bpf_state_scope': None, 'filesystem_state_scope': None, 'linux_state_scope': None,
            'poll_interval_ms': 20, 'drain_timeout_ms': 5000}

    def start(self):
        freeze_group(self.group, self.identity, True)
        dump(self.trial / 'observer-config.json', self.config)
        self.stderr = (self.trial / 'observer.stderr').open('xb')
        self.process = subprocess.Popen([str(self.args.observer_binary), '--config', str(self.trial / 'observer-config.json')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr, bufsize=0)
        ready = protocol_line(self.process)
        if (ready.get('protocol_version') != 2 or ready.get('status') != 'READY'
                or ready.get('run_id') != self.run_id or ready.get('epoch') != 1
                or ready.get('recorder_object_sha256') != self.args.recorder_sha256
                or ready.get('lifecycle_object_sha256') != self.args.lifecycle_sha256
                or ready.get('registration_cgroup_ids') != [self.identity['inode']]):
            raise RuntimeError('Observer READY identity or object binding failed')
        nonce = ready.get('finish_nonce')
        if not isinstance(nonce, str) or len(nonce) != 64 or any(c not in '0123456789abcdef' for c in nonce):
            raise RuntimeError('Observer READY nonce malformed')
        self.nonce = nonce
        dump(self.trial / 'observer-ready.json', ready)
        freeze_group(self.group, self.identity, False)

    def finish(self):
        started = time.monotonic_ns()
        freeze_group(self.group, self.identity, True)
        request = {'protocol_version': 2, 'command': 'FINISH', 'run_id': self.run_id, 'finish_nonce': self.nonce}
        dump(self.trial / 'observer-finish-request.json', request)
        self.process.stdin.write(json.dumps(request).encode() + b'\n')
        self.process.stdin.flush()
        self.process.stdin.close()
        finished = protocol_line(self.process, 120)
        usage = reap_with_usage(self.process, 30)
        if (finished.get('protocol_version') != 2 or finished.get('status') != 'FINISHED'
                or finished.get('run_id') != self.run_id or usage['returncode'] != 0):
            raise RuntimeError('Observer FINISH failed')
        for key in ('report_sha256', 'artifact_manifest_sha256'):
            value = finished.get(key)
            if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                raise RuntimeError('Observer FINISH invalid digest: ' + key)
        dump(self.trial / 'observer-finished.json', finished)
        expectation = {'expected_config': self.config, 'expected_report_sha256': finished['report_sha256'],
                       'expected_artifact_manifest_sha256': finished['artifact_manifest_sha256']}
        dump(self.trial / 'observer-expectation.json', expectation)
        result = subprocess.run([str(self.args.verifier_binary), '--artifacts', str(self.trial / 'observer'),
            '--expectation', str(self.trial / 'observer-expectation.json')], capture_output=True, timeout=120)
        (self.trial / 'verifier.stdout').write_bytes(result.stdout)
        (self.trial / 'verifier.stderr').write_bytes(result.stderr)
        verified = json.loads(result.stdout)
        dump(self.trial / 'observer-verification.json', verified)
        if result.returncode != 0 or verified.get('verified') is not True:
            raise RuntimeError('Independent Observer verifier rejected evidence')
        return {'verification': verified, 'boundary_and_verifier_ns': time.monotonic_ns() - started,
                'collector_usage': usage,
                'evidence_bytes': sum(p.stat().st_size for p in (self.trial / 'observer').rglob('*') if p.is_file())}

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.stderr:
            self.stderr.close()
        if self.process and self.process.stdout:
            self.process.stdout.close()
        if self.process and self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()


def parse_ints(value, allowed=None):
    result = [int(v) for v in value.split(',')]
    if not result or len(result) != len(set(result)) or any(v < 1 for v in result):
        raise ValueError('positive unique integers required')
    if allowed and any(v not in allowed for v in result):
        raise ValueError('unsupported value')
    return result


def schedule(concurrency, modes, repetitions, warmups, seed):
    rng, result = random.Random(seed), []
    for warmup, count in ((True, warmups), (False, repetitions)):
        for repetition in range(count):
            block = [{'concurrency': c, 'mode': m, 'repetition': repetition,
                      'warmup': warmup} for c in concurrency for m in modes]
            rng.shuffle(block)
            result.extend(block)
    return result


def prepare_cache(root, inventory, mode, allow_drop):
    if mode == 'uncontrolled':
        return {'mode': mode, 'verified_residency': False}
    if mode == 'guest-cold':
        vendor = ' '.join(p.read_text(errors='replace') for p in
                          (Path('/sys/class/dmi/id/product_name'), Path('/sys/class/dmi/id/sys_vendor'))
                          if p.exists()).lower()
        if not allow_drop or not any(v in vendor for v in ('qemu', 'kvm')):
            raise ValueError('guest-cold requires explicit consent and a QEMU/KVM guest')
        os.sync()
        Path('/proc/sys/vm/drop_caches').write_text('3\n')
        return {'mode': mode, 'verified_residency': False,
                'scope': 'guest page/dentry/inode caches only; host caches unknown'}
    # Warming is explicit read-through, not an assertion that the entire corpus
    # remains resident when it exceeds the available memory working set.
    for row in inventory['files']:
        with (root / row['path']).open('rb') as src:
            while src.read(1024 * 1024):
                pass
    return {'mode': mode, 'bytes_read': inventory['bytes'], 'verified_residency': False,
            'scope': 'read-through immediately before timing; residency not proven'}


def process_identity(pid):
    stat = Path('/proc', str(pid), 'stat').read_text()
    fields = stat[stat.rfind(')') + 2:].split()
    return {'pid': pid, 'start_ticks': int(fields[19])}


def cgroup_identity(path):
    st = path.stat()
    return {'path': str(path), 'inode': st.st_ino, 'device': st.st_dev}


def io_prime_command(device):
    executable = shutil.which('dd')
    if not executable:
        raise RuntimeError('dd required for explicit I/O baseline priming')
    # launch_stopped intentionally uses execve, never PATH lookup.
    return [str(Path(executable).resolve(strict=True)), 'if=' + str(device),
            'of=/dev/null', 'iflag=direct', 'bs=4096', 'count=1', 'status=none']


def requested_io_prime_devices(args):
    """Repeatable CLI list, with the previous single-device Python API retained."""
    devices = getattr(args, 'io_prime_devices', None)
    if devices:
        return list(devices)
    legacy = getattr(args, 'io_prime_device', None)
    return [legacy] if legacy is not None else []


def ensure_cgroup_parent(path):
    if not path.is_absolute() or path == CGROOT or path.resolve() != path:
        raise ValueError('cgroup parent must be a canonical non-root absolute path')
    path.relative_to(CGROOT)
    if not (CGROOT / 'cgroup.controllers').exists():
        raise ValueError('unified cgroup v2 is required')
    created = not path.exists()
    if created:
        path.mkdir()
    try:
        if (path / 'cgroup.procs').read_text().strip():
            raise ValueError('cgroup parent must have no direct processes')
        controllers = set((path / 'cgroup.controllers').read_text().split())
        required = {'cpu', 'memory', 'io'}
        if not required <= controllers:
            raise ValueError('delegate cpu memory io controllers to cgroup parent first')
        (path / 'cgroup.subtree_control').write_text('+cpu +memory +io\n')
    except BaseException:
        if created:
            path.rmdir()
        raise
    return created


def terminate_child(pid):
    # Only called for unreaped children we created; their PID cannot be reused.
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def wait_child_stop(pid, timeout=30):
    deadline = time.monotonic() + timeout
    while True:
        waited, status = os.waitpid(pid, os.WUNTRACED | os.WNOHANG)
        if waited:
            return status
        if time.monotonic() >= deadline:
            raise RuntimeError('stopped workload preparation timed out')
        time.sleep(0.001)


def cleanup_owned_cgroup(path, expected_identity, errors, kill_remaining=True):
    """Remove only the exact created cgroup; errors never abort later cleanup."""
    try:
        if cgroup_identity(path) != expected_identity:
            errors.append('cgroup identity changed; retained path: ' + str(path))
            return False
        populated = (path / 'cgroup.events').read_text().split('populated ', 1)[1].split()[0]
        if populated not in ('0', '1'):
            raise RuntimeError('invalid populated value')
        if populated == '1':
            errors.append('descendants remained at cleanup: ' + str(path))
            if not kill_remaining or not (path / 'cgroup.kill').exists():
                return False
            (path / 'cgroup.kill').write_text('1\n')
            deadline = time.monotonic() + 5
            while 'populated 1' in (path / 'cgroup.events').read_text():
                if time.monotonic() >= deadline:
                    raise RuntimeError('owned cgroup did not empty')
                time.sleep(0.01)
        if cgroup_identity(path) != expected_identity:
            errors.append('cgroup identity changed before removal: ' + str(path))
            return False
        path.rmdir()
        return True
    except (OSError, ValueError, IndexError, RuntimeError) as error:
        errors.append('cgroup cleanup ' + str(path) + ': ' + str(error))
        return False


def launch_stopped(argv, cwd, stdout_path, stderr_path, cgroup, cpus, prepare_worker=False):
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            os.sched_setaffinity(0, cpus)
            resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 ** 2,) * 2)
            os.chdir(cwd)
            with open(stdout_path, 'xb', buffering=0) as out, open(stderr_path, 'xb', buffering=0) as err:
                os.dup2(out.fileno(), 1)
                os.dup2(err.fileno(), 2)
                os.kill(os.getpid(), signal.SIGSTOP)
                env = dict(os.environ, LC_ALL='C', LANG='C', PYTHONDONTWRITEBYTECODE='1')
                os.execve(argv[0], argv, env)
        except BaseException:
            os._exit(127)
    reaped = False
    try:
        status = wait_child_stop(pid)
        if not os.WIFSTOPPED(status):
            reaped = True
            raise RuntimeError('workload failed before stopped launch')
        (cgroup / 'cgroup.procs').write_text(str(pid))
        expected = '/' + str(cgroup.relative_to(CGROOT))
        if Path('/proc', str(pid), 'cgroup').read_text().strip() != '0::' + expected:
            raise RuntimeError('workload cgroup membership mismatch')
        if prepare_worker:
            # The first gate enrolls before exec; the second excludes interpreter
            # startup/job parsing from the search interval. No search runs yet.
            os.kill(pid, signal.SIGCONT)
            status = wait_child_stop(pid)
            if not os.WIFSTOPPED(status):
                reaped = True
                raise RuntimeError('worker failed before prepared gate')
            if os.WSTOPSIG(status) != signal.SIGSTOP:
                raise RuntimeError('worker stopped for an unexpected signal')
        return process_identity(pid)
    except BaseException:
        if not reaped:
            terminate_child(pid)
        raise


class SemanticEvents:
    def __init__(self, path, run_id, boot_id):
        self.stream = Path(path).open('x', encoding='utf-8')
        self.run_id, self.boot_id, self.seq = run_id, boot_id, 0
        self.records = []

    def emit(self, task, event, now=None, **extra):
        value = {'schema_version': 1, 'seq': self.seq, 'run_id': self.run_id,
                 'task_id': task['task_id'], 'agent_id': task['agent_id'],
                 'attempt': 1, 'epoch': 1, 'tool_call_id': task['tool_call_id'],
                 'request_id': None, 'parent_task_id': None, 'dependencies': [],
                 'phase': task.get('phase', 'search'), 'priority': 0, 'event': event,
                 'monotonic_ns': time.monotonic_ns() if now is None else now,
                 'boot_id': self.boot_id, 'process': task['process'],
                 'cgroup': task['cgroup'], **extra}
        # Bounded task lifecycle records, not an audit WAL. Result digests are
        # filled after all tasks exit; never serialize/hash on a worker's path.
        self.records.append(value)
        self.seq += 1
        return value

    def close(self):
        for seq, row in enumerate(sorted(self.records, key=lambda r: r['monotonic_ns'])):
            row['seq'] = seq
            self.stream.write(json.dumps(row, separators=(',', ':')) + '\n')
        self.stream.close()


def await_ready(proc, timeout):
    deadline, data = time.monotonic() + timeout, b''
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while b'\n' not in data:
            if len(data) > 1024 or not selector.select(max(0, deadline - time.monotonic())):
                raise RuntimeError('sampler READY timeout/oversize')
            part = os.read(proc.stdout.fileno(), 1024)
            if not part:
                break
            data += part
    if data.strip() != b'READY':
        raise RuntimeError('sampler failed before first flushed sample; see sampler.stderr')


def validate_first_sample(meta, first, run_id, boot_id, identities):
    actual = [{key: group.get(key) for key in ('path', 'inode', 'device')}
              for group in meta.get('cgroups', []) if isinstance(group, dict)]
    if meta.get('label') != run_id or meta.get('boot_id') != boot_id or actual != identities:
        raise RuntimeError('sampler READY run/boot/cgroup identity binding failed')
    start, end = first.get('monotonic_ns'), first.get('collection_end_ns')
    groups = first.get('cgroups')
    if (first.get('seq') != 0 or type(start) is not int or type(end) is not int
            or start < 0 or end < start or end > time.monotonic_ns()
            or not isinstance(groups, list) or len(groups) != len(identities)
            or any(not isinstance(group, dict) or group.get('present') is not True for group in groups)):
        raise RuntimeError('sampler READY lacks a bound complete first collection window')


class QueryMeasurements:
    """Buffered cooperative tool spans, reusable by other benchmark adapters.

    Construct before releasing the task, enter ``span(index)`` around one
    logical query, and set execution_kind/returncode on the yielded dict. The
    identity must identify the calling tool process, not an inferred grep PID.
    No serialization, hashing, /proc reads or fsync occurs on the query path.
    These are performance measurements, not authenticated Observer events.
    """
    def __init__(self, identity, query_sha256, query_index=0, mode='none'):
        self.identity = dict(identity)
        self.query_sha256, self.query_index, self.mode = query_sha256, query_index, mode
        self.rows = []

    @contextlib.contextmanager
    def span(self, index):
        row = {**self.identity, 'schema_version': 1, 'query_ordinal': index,
               'query_id': '{}:query-{:06d}'.format(self.identity.get('tool_call_id', 'unbound'), index),
               'query_index': self.query_index, 'query_sha256': self.query_sha256,
               'mode': self.mode, 'execution_kind': 'UNKNOWN', 'lock_wait_ns': 0,
               'timing_scope': 'WORKER_QUERY_CALL_INCLUDING_LOCK_CACHE_OUTPUT_AND_SUBPROCESS',
               'identity_scope': 'CALLING_WORKER; GREP_DESCENDANT_NOT_INDIVIDUALLY_RESOLVED',
               'begin_ns': time.monotonic_ns(), 'status': 'FAILED'}
        try:
            yield row
            row['status'] = 'COMPLETE' if row.get('returncode') in (0, 1) else 'FAILED'
        finally:
            row['end_ns'] = time.monotonic_ns()
            row['duration_ns'] = row['end_ns'] - row['begin_ns']
            self.rows.append(row)


def worker(jobfile):
    job = json.loads(Path(jobfile).read_text())
    process = process_identity(os.getpid())
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    queries = QueryMeasurements({**job.get('query_identity', {}), 'process': process, 'boot_id': boot_id},
        hashlib.sha256(job.get('query', '').encode()).hexdigest(), job.get('query_index', 0),
        'exact-reuse' if job.get('reuse') else 'none')
    if job.get('preflight_stop'):
        # This is a measurement baseline, not an authenticated claim by a
        # hostile process. The cooperative worker has not invoked grep yet.
        usage = resource.getrusage(resource.RUSAGE_SELF)
        dump(job['ready_file'], {'schema_version': 1, 'process': process, 'boot_id': boot_id,
                                'monotonic_ns': time.monotonic_ns(),
                                'rusage_user_usec': round(usage.ru_utime * 1e6),
                                'rusage_system_usec': round(usage.ru_stime * 1e6)})
        os.kill(os.getpid(), signal.SIGSTOP)
    kind = job.get('calibration_kind')
    if kind == 'cpu':
        end = time.process_time() + job['calibration_seconds']
        value = 1
        while time.process_time() < end:
            for i in range(10000):
                value = (value * 33 + i) & 0xffffffff
        return 0
    if kind == 'sleep':
        time.sleep(job['calibration_seconds'])
        return 0
    if kind == 'read':
        for _ in range(job['passes']):
            for name in job['files']:
                with (Path(job['corpus']) / name).open('rb') as src:
                    while src.read(1024 * 1024):
                        pass
        return 0
    scans, hits = 0, 0
    reuse = job.get('reuse')
    if reuse and security_context() != reuse['security_context']:
        raise RuntimeError('query reuse security context differs from bound contract')
    try:
        for index in range(job['passes']):
            with queries.span(index) as span:
                command = [job['grep'], *GREP_OPTIONS, '--', job['query'], '.']
                if reuse:
                    cache = Path(reuse['directory'])
                    with (cache / (reuse['key'] + '.lock')).open('ab') as lock:
                        lock_begin = time.monotonic_ns()
                        fcntl.flock(lock, fcntl.LOCK_EX)
                        span['lock_wait_ns'] = time.monotonic_ns() - lock_begin
                        value = cache / (reuse['key'] + '.json')
                        if value.exists():
                            entry = json.loads(value.read_text())
                            hits += 1
                            span['execution_kind'] = 'CACHE_HIT'
                        else:
                            span['execution_kind'] = 'SCAN'
                            result = subprocess.run(command, cwd=job['corpus'], capture_output=True, check=False)
                            scans += 1
                            span['returncode'] = result.returncode
                            if result.returncode not in (0, 1):
                                os.write(2, result.stderr)
                                return 2
                            entry = {'key': reuse['key'], 'returncode': result.returncode,
                                     'stdout_hex': result.stdout.hex(), 'stdout_sha256': hashlib.sha256(result.stdout).hexdigest()}
                            dump(value, entry)
                        raw = bytes.fromhex(entry['stdout_hex'])
                        if (entry.get('key') != reuse['key'] or entry.get('returncode') not in (0, 1)
                                or hashlib.sha256(raw).hexdigest() != entry.get('stdout_sha256')):
                            raise RuntimeError('invalid query reuse entry')
                        span['returncode'] = entry['returncode']
                        sys.stdout.buffer.write(raw)
                        sys.stdout.buffer.flush()
                else:
                    span['execution_kind'] = 'SCAN'
                    result = subprocess.run(command, cwd=job['corpus'], check=False)
                    scans += 1
                    span['returncode'] = result.returncode
                    if result.returncode not in (0, 1):
                        return 2
    finally:
        if job.get('statistics_file'):
            dump(job['statistics_file'], {'schema_version': 2, 'physical_grep_executions': scans,
                 'cache_hits': hits, 'logical_queries': job['passes'],
                 'intervention': 'exact-reuse' if reuse else 'none', 'query_spans': queries.rows,
                 'query_timing_contract': 'WORKER_MONOTONIC_PER_LOGICAL_QUERY_V1'})
    return 0


def run_trial(args, campaign, condition, inventory, queries, index):
    trial_begin_ns = time.monotonic_ns()
    run_id = 'search-' + uuid.uuid4().hex
    trial = campaign / 'trials' / ('%03d-' % index + run_id)
    trial.mkdir()
    group = args.cgroup_parent / run_id
    group.mkdir()
    group_identity = cgroup_identity(group)
    children, tasks, events, sampler, observer = [], [], None, None, None
    active, reaped, errors, results = {}, set(), [], []
    cache_proof = None
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    meta = {'schema_version': 1, 'run_id': run_id, 'boot_id': boot_id,
            'root_cgroup': group_identity,
            'config': {**condition, 'jobs': args.jobs, 'passes': args.passes,
                       'calibration_kind': args.calibration_kind,
                       'calibration_seconds': args.calibration_seconds,
                       'timing_scope': 'PREPARED_WORKER_SIGCONT_TO_WAIT4_OBSERVATION',
                       'query_measurement_version': 1,
                       'cpu_time_scope': 'WAIT4_LIFETIME_MINUS_WORKER_PREFLIGHT_RUSAGE',
                       'corpus_sha256': inventory['sha256'], 'queries_sha256': canonical_digest(queries),
                       'permission_scope_sha256': inventory['permission_scope_sha256'],
                       'repository_version': args.repository_version, 'intervention': args.intervention,
                       'workspace_layout': args.workspace_layout, 'cgroup_layout': args.cgroup_layout,
                       'memory_max_mb': args.memory_max_mb, 'memory_high_mb': args.memory_high_mb,
                       'memory_limit_start': 'AFTER_WORKER_PREFLIGHT_BEFORE_COLLECTOR_READY',
                       'sample_threads': args.sample_threads,
                       'cache': args.cache, 'cpus': sorted(args.cpus),
                       'interval_ms': args.interval_ms, 'process_interval_ms': args.process_interval_ms},
            'status': 'PREPARING', 'measurement_only': True,
            'observer_audit': 'NOT_ENABLED', 'tasks': tasks}
    try:
        if args.cgroup_layout == 'shared-leaf':
            (group / 'cgroup.max.depth').write_text('0')
            (group / 'cgroup.max.descendants').write_text('0')
        else:
            (group / 'cgroup.subtree_control').write_text('+cpu +memory +io\n')
        reuse_directory = trial / 'query-reuse'
        if args.intervention == 'exact-reuse':
            reuse_directory.mkdir(mode=0o700)
        permission_context = security_context()
        for task_index in range(args.jobs):
            cg = group if args.cgroup_layout == 'shared-leaf' else group / ('task-%04d' % task_index)
            if cg != group:
                cg.mkdir()
                children.append((cg, cgroup_identity(cg)))
            cg_identity = cgroup_identity(cg)
            task_id = 'task-%04d' % task_index
            jobfile = trial / (task_id + '-job.json')
            readyfile = trial / (task_id + '-ready.json')
            query = queries[task_index % len(queries)]
            reuse = None if args.intervention == 'none' else {'directory': str(reuse_directory),
                'key': query_reuse_key(inventory, query, GREP_OPTIONS, args.grep_sha256,
                                      args.repository_version, permission_context), 'security_context': permission_context}
            dump(jobfile, {'grep': args.grep, 'corpus': str(args.workspaces[task_index]),
                           'preflight_stop': True, 'ready_file': str(readyfile),
                           'query': query, 'passes': args.passes, 'reuse': reuse,
                           'query_index': task_index % len(queries),
                           'query_identity': {'run_id': run_id, 'task_id': task_id,
                               'agent_id': 'agent-%04d' % task_index, 'tool_call_id': 'search-%04d' % task_index,
                               'attempt': 1, 'epoch': 1, 'cgroup': cg_identity,
                               'corpus_sha256': inventory['sha256'], 'grep_sha256': args.grep_sha256,
                               'repository_version': args.repository_version,
                               'cache_state': args.cache, 'workspace_layout': args.workspace_layout},
                           'statistics_file': str(trial / (task_id + '-statistics.json')),
                           'calibration_kind': args.calibration_kind,
                           'calibration_seconds': args.calibration_seconds,
                           'files': [r['path'] for r in inventory['files']] if args.calibration_kind == 'read' else []})
            stdout, stderr = trial / (task_id + '.stdout'), trial / (task_id + '.stderr')
            identity = launch_stopped([sys.executable, str(Path(__file__).resolve()),
                                       '--worker', str(jobfile)], str(trial), stdout, stderr, cg, args.cpus,
                                       prepare_worker=True)
            tasks.append({'task_id': task_id, 'agent_id': 'agent-%04d' % task_index,
                          'phase': 'calibration:' + args.calibration_kind if args.calibration_kind else 'search',
                          'tool_call_id': 'search-%04d' % task_index, 'query_index': task_index % len(queries),
                          'process': identity, 'cgroup': cg_identity,
                          'stdout_path': str(stdout), 'stderr_path': str(stderr)})
            prepared = json.loads(readyfile.read_text())
            if prepared.get('process') != identity or prepared.get('boot_id') != boot_id:
                raise RuntimeError('prepared worker identity mismatch')
            for field in ('rusage_user_usec', 'rusage_system_usec', 'monotonic_ns'):
                if type(prepared.get(field)) is not int or prepared[field] < 0:
                    raise RuntimeError('invalid worker preparation counter: ' + field)
            tasks[-1]['preparation'] = prepared
        if args.memory_max_mb:
            (group / 'memory.max').write_text(str(args.memory_max_mb * 1024 ** 2))
        if args.memory_high_mb:
            current_memory = int((group / 'memory.current').read_text())
            if current_memory >= args.memory_high_mb * 1024 ** 2:
                raise RuntimeError('memory.high is below prepared worker resident set; choose a meaningful workload working-set limit')
            (group / 'memory.high').write_text(str(args.memory_high_mb * 1024 ** 2))
        # Optional measured preflight I/O establishes the selected block
        # device's real io.stat baseline. An absent device row is still never
        # invented as zero. This happens before cache preparation and timing.
        prime_devices = requested_io_prime_devices(args)
        for prime_index, prime_device in enumerate(prime_devices):
            device = Path(prime_device).resolve(strict=True)
            if not stat.S_ISBLK(device.stat().st_mode):
                raise ValueError('I/O baseline priming requires an explicit block device')
            prime = launch_stopped(io_prime_command(device), str(trial), trial / ('io-prime-%d.stdout' % prime_index),
                trial / ('io-prime-%d.stderr' % prime_index), group, args.cpus)
            os.kill(prime['pid'], signal.SIGCONT)
            waited, status, _ = os.wait4(prime['pid'], 0)
            if waited != prime['pid'] or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                raise RuntimeError('explicit preflight device read failed')
            meta.setdefault('io_baseline_priming', []).append({'device': str(device), 'bytes': 4096,
                'process': prime, 'timing': 'BEFORE_CACHE_PREPARATION_AND_RELEASE',
                'purpose': 'ESTABLISH_OBSERVED_DEVICE_COUNTER_NOT_ZERO_IMPUTATION'})
        events = SemanticEvents(trial / 'task-events.jsonl', run_id, boot_id)
        if condition['mode'] in ('observer', 'observer-sampler'):
            observer = ProfileObserver(args, trial, group, group_identity, run_id, tasks[0]['process']['pid'])
            begin = time.monotonic_ns()
            observer.start()
            meta['observer_prepare_ns'] = time.monotonic_ns() - begin
            meta['observer_audit'] = 'RECORDING'
        if condition['mode'] in ('sampler', 'kernel-hist', 'observer-sampler'):
            command = [str(args.sampler), '--output-dir', str(trial / 'load'), '--label', run_id,
                       '--interval-ms', str(args.interval_ms), '--process-interval-ms', str(args.process_interval_ms),
                       '--cgroup', str(group)]
            for cg, _ in children:
                command += ['--cgroup', str(cg)]
            if args.sample_threads:
                command += ['--sample-threads']
            if condition['mode'] == 'kernel-hist':
                command += ['--kernel-hist-object', str(args.kernel_hist_object),
                            '--kernel-hist-sha256', args.kernel_hist_sha256,
                            '--kernel-hist-groups', args.kernel_hist_groups,
                            '--kernel-hist-syscall-backend', args.kernel_hist_syscall_backend,
                            '--kernel-hist-memory-backend', args.kernel_hist_memory_backend]
            with (trial / 'sampler.stderr').open('xb') as err:
                sampler = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err)
            await_ready(sampler, 30)
            # READY is meaningful only with a complete first flushed JSON line.
            first = (trial / 'load/load-samples.jsonl').read_text().splitlines()
            if not first:
                raise RuntimeError('sampler has no valid first sample')
            validate_first_sample(json.loads((trial / 'load/load-meta.json').read_text()), json.loads(first[0]),
                                  run_id, boot_id, [group_identity] + [identity for _, identity in children])
        roots = sorted(set(args.workspaces))
        cache_pins = None
        if getattr(args, 'verify_cache_residency', False):
            import cache_probe
            cache_pins = getattr(args, 'cache_pins', None)
            if cache_pins is None:
                cache_pins = cache_probe.pin_roots(roots, inventory['files'],
                    independent=args.workspace_layout == 'independent')
            if sorted(pin['root'] for pin in cache_pins['roots']) != [str(root) for root in roots]:
                raise ValueError('preparation cache pins do not match exact workload roots')
            if any(pin.get('inventory_sha256') != cache_probe._digest(inventory['files'])
                   for pin in cache_pins['roots']):
                raise ValueError('cache pins do not cover the exact fixed file inventory')
            if args.cache == 'warm':
                os.sync()  # Drain previous evidence/setup writes before warming.
        if args.cache == 'warm':
            meta['cache_preparation'] = [prepare_cache(root, inventory, args.cache, args.allow_guest_drop_caches) for root in roots]
        else:
            meta['cache_preparation'] = [prepare_cache(args.corpus, inventory, args.cache, args.allow_guest_drop_caches)]
        if cache_pins is not None:
            cache_proof = cache_probe.probe_roots(cache_pins)
            validator = getattr(args, 'cache_proof_validator', None)
            if validator:
                validator(cache_proof, args.cache)
        release = time.monotonic_ns()
        meta['release_ns'] = release
        if cache_proof is not None:
            meta['cache_probe_end_to_release_ns'] = release - max(row['end_monotonic_ns'] for row in cache_proof['roots'])
            meta['cache_memory_charge_scope'] = 'WARM_PRELOAD_FIRST_TOUCH_OUTSIDE_WORKLOAD_CGROUP; COLD_READS_INSIDE; MEMORY.FILE_NOT_COMPARABLE_AS_TOTAL_CACHE_FOOTPRINT'
        meta['setup_ns'] = release - trial_begin_ns
        pending = list(tasks)
        while pending or active:
            if sampler and sampler.poll() is not None:
                raise RuntimeError('sampler exited while workload was running')
            while pending and len(active) < condition['concurrency']:
                task = pending.pop(0)
                pid = task['process']['pid']
                start = time.monotonic_ns()
                events.emit(task, 'START', start, queue_ns=start - release)
                os.kill(pid, signal.SIGCONT)
                active[pid] = (task, start)
            done = False
            for pid, (task, start) in list(active.items()):
                waited, status, usage = os.wait4(pid, os.WNOHANG)
                if not waited:
                    if time.monotonic_ns() - start > args.timeout_seconds * 1_000_000_000:
                        raise RuntimeError('search timed out: ' + task['task_id'])
                    continue
                end = time.monotonic_ns()
                reaped.add(pid)
                del active[pid]
                done = True
                exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
                lifetime_user = round(usage.ru_utime * 1e6)
                lifetime_system = round(usage.ru_stime * 1e6)
                measured_user = lifetime_user - task['preparation']['rusage_user_usec']
                measured_system = lifetime_system - task['preparation']['rusage_system_usec']
                if min(measured_user, measured_system) < 0:
                    raise RuntimeError('worker CPU counter baseline exceeds final usage')
                result = {'task_id': task['task_id'], 'query_index': task['query_index'],
                          'exit_code': exit_code,
                          'wall_ns': end - start, 'queue_ns': start - release,
                          'completion_latency_ns': end - release,
                          'user_usec': measured_user, 'system_usec': measured_system,
                          'lifetime_user_usec': lifetime_user, 'lifetime_system_usec': lifetime_system,
                          'cpu_time_scope': 'WAIT4_LIFETIME_MINUS_WORKER_PREFLIGHT_RUSAGE',
                          'max_rss_kb': usage.ru_maxrss, 'minor_faults': usage.ru_minflt,
                          'major_faults': usage.ru_majflt, 'voluntary_switches': usage.ru_nvcsw,
                          'involuntary_switches': usage.ru_nivcsw,
                          'other_rusage_scope': 'WHOLE_WORKER_LIFETIME_INCLUDING_PREPARATION'}
                results.append(result)
                terminal = events.emit(task, 'COMPLETE' if exit_code == 0 else 'FAILED', end,
                                       **{k: v for k, v in result.items() if k != 'task_id'})
                task['terminal_event'] = terminal
                if exit_code != 0:
                    raise RuntimeError('search command failed: ' + task['task_id'])
                if args.cgroup_layout != 'shared-leaf' and (Path(task['cgroup']['path']) / 'cgroup.events').read_text().split('populated ', 1)[1].split()[0] != '0':
                    raise RuntimeError('search left a populated cgroup')
            if not done:
                time.sleep(0.001)
        end = release + max(r['completion_latency_ns'] for r in results)
        meta.update(status='COMPLETE', end_ns=end, makespan_ns=end - release, results=results)
        finalization_begin_ns = time.monotonic_ns()
        if (group / 'cgroup.events').read_text().split('populated ', 1)[1].split()[0] != '0':
            raise RuntimeError('workload left descendants in execution cgroup')
        if sampler:
            # Need a full post-exit sample, not a timer-based assumption.
            deadline = time.monotonic() + 10
            while True:
                rows = (trial / 'load/load-samples.jsonl').read_text().splitlines()
                last = None
                for line in reversed(rows):
                    try:
                        last = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        continue
                if last and last['monotonic_ns'] > end:
                    break
                if sampler.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('missing final bracketing sample')
                time.sleep(0.01)
            sampler.send_signal(signal.SIGTERM)
            meta['sampler_usage'] = reap_with_usage(sampler, 15)
            if meta['sampler_usage']['returncode'] != 0:
                raise RuntimeError('sampler failed finalization')
        if observer:
            meta['observer_result'] = observer.finish()
            meta['observer_audit'] = 'INDEPENDENTLY_VERIFIED'
        if cache_proof is not None:
            # No serialization, hashing or proof writes between cache probing
            # and task release. Persist details only after the measured window
            # and collector finalization, retaining exact per-file evidence.
            details = trial / 'cache-residency-files.json.gz'
            with gzip.open(details, 'xt', encoding='utf-8', compresslevel=1) as stream:
                json.dump(cache_proof, stream, separators=(',', ':'))
            for root_proof in cache_proof['roots']:
                root_proof.pop('files', None)
            cache_proof['file_details'] = {'path': details.name, 'sha256': sha_file(details)}
            proof_path = trial / 'cache-residency.json'
            dump(proof_path, cache_proof)
            meta['cache_residency'] = {'path': proof_path.name, 'sha256': sha_file(proof_path),
                'scope': 'DATA_PAGE_RESIDENCY; PROBING_TRAVERSES_METADATA; NOT_DENTRY_INODE_COLD_PROOF'}
        # Content/result verification is outside every timed task and campaign
        # execution window; NUL-delimited names handle embedded newlines safely.
        for result in results:
            task = next(t for t in tasks if t['task_id'] == result['task_id'])
            raw = Path(task['stdout_path']).read_bytes()
            fields = raw.split(b'\0')
            if fields[-1] != b'':
                raise RuntimeError('grep returned malformed filename output')
            digest = hashlib.sha256(b'\0'.join(sorted(fields[:-1])) + b'\0').hexdigest()
            result.update(output_sha256=digest, output_bytes=len(raw))
            statistics_file = trial / (result['task_id'] + '-statistics.json')
            if statistics_file.exists():
                result['query_statistics'] = json.loads(statistics_file.read_text())
            task.pop('terminal_event').update(output_sha256=digest, output_bytes=len(raw))
        meta['finalization_ns'] = time.monotonic_ns() - finalization_begin_ns
    except BaseException as error:
        meta.update(status='FAILED', error=str(error))
        errors.append(str(error))
        now = time.monotonic_ns()
        for pid, (task, start) in active.items():
            if events:
                events.emit(task, 'CANCELLED', now, reason=str(error), wall_ns=now - start)
    finally:
        # Never kill arbitrary PID read from a cgroup: only known children not
        # yet reaped. Incomplete cleanup remains visible and forbids success.
        for task in tasks:
            try:
                if task['process']['pid'] not in reaped:
                    terminate_child(task['process']['pid'])
            except OSError as error:
                errors.append('child cleanup: ' + str(error))
        try:
            if sampler and sampler.poll() is None:
                sampler.terminate()
                try:
                    sampler.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    sampler.kill()
                    sampler.wait(timeout=5)
            if sampler and sampler.stdout:
                sampler.stdout.close()
        except (OSError, subprocess.TimeoutExpired) as error:
            errors.append('sampler cleanup: ' + str(error))
        try:
            if observer:
                observer.close()
            if events:
                events.close()
        except OSError as error:
            errors.append('event finalization: ' + str(error))
        for cg, expected_identity in reversed(children):
            cleanup_owned_cgroup(cg, expected_identity, errors)
        cleanup_owned_cgroup(group, group_identity, errors, kill_remaining=False)
        meta['cleanup_errors'] = errors
        if errors:
            meta['status'] = 'FAILED'
        meta['total_trial_ns'] = time.monotonic_ns() - trial_begin_ns
        dump(trial / 'profile-run.json', meta)
    if errors:
        raise RuntimeError('trial failed; inspect ' + str(trial / 'profile-run.json'))
    report = analyze.write_report(trial)
    return {'path': str(trial.relative_to(campaign)), **condition,
            'run_id': run_id, 'makespan_ns': meta['makespan_ns'], 'results': results,
            'analysis_status': report.get('status', report.get('health', {}).get('status'))}


def bootstrap_ci(values, seed=1):
    if len(values) < 3:
        return None
    rng = random.Random(seed)
    means = sorted(statistics.mean(rng.choices(values, k=len(values))) for _ in range(2000))
    return [means[49], means[1949]]


def summarize(trials):
    expected, groups = {}, {}
    for trial in trials:
        for result in trial['results']:
            key = result['query_index']
            value = (result['exit_code'], result['output_sha256'], result['output_bytes'])
            if key in expected and expected[key] != value:
                raise ValueError('search output differs across equivalent conditions')
            expected[key] = value
        if not trial['warmup']:
            groups.setdefault((trial['mode'], trial['concurrency']), []).append(trial)
    summaries = []
    for (mode, concurrency), rows in sorted(groups.items()):
        durations = [r['makespan_ns'] / 1e9 for r in rows]
        summaries.append({'mode': mode, 'concurrency': concurrency, 'samples': len(rows),
                          'median_makespan_seconds': statistics.median(durations),
                          'mean_makespan_seconds_ci95_bootstrap': bootstrap_ci(durations),
                          'query_completion_seconds': [x['completion_latency_ns'] / 1e9 for r in rows for x in r['results']],
                          'query_completion_seconds_legacy_meaning': 'TASK_COMPLETION_LATENCY_FROM_COMMON_RELEASE_NOT_INDIVIDUAL_QUERY_DURATION; use campaign-report.json logical_query_duration_seconds',
                          'total_cpu_seconds': [(sum(x['user_usec'] + x['system_usec'] for x in r['results']) / 1e6) for r in rows]})
    paired = []
    for concurrency in sorted({c for _, c in groups}):
        base = {t['repetition']: t for t in groups.get(('baseline', concurrency), [])}
        for mode in ('sampler', 'kernel-hist', 'observer', 'observer-sampler'):
            ratios = [t['makespan_ns'] / base[t['repetition']]['makespan_ns'] - 1
                      for t in groups.get((mode, concurrency), []) if t['repetition'] in base]
            if ratios:
                paired.append({'mode': mode, 'concurrency': concurrency, 'pairs': len(ratios),
                               'median_slowdown': statistics.median(ratios),
                               'mean_slowdown_ci95_bootstrap': bootstrap_ci(ratios)})
    return {'output_equivalence': 'PASS', 'conditions': summaries, 'paired_overhead': paired,
            'interpretation': 'Candidate observations, not causal attribution. Fixed total work; no automatic optimizer. Small samples do not establish tail latency or production overhead.'}


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        return worker(sys.argv[2])
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--corpus', type=Path, required=True)
    p.add_argument('--queries-file', type=Path, required=True)
    p.add_argument('--output-dir', type=Path, required=True)
    p.add_argument('--sampler', type=Path, required=True)
    p.add_argument('--concurrency', default='1,2,4,8')
    p.add_argument('--modes', default='baseline,sampler')
    p.add_argument('--workspace-layout', choices=['shared', 'independent'], default='shared')
    p.add_argument('--cgroup-layout', choices=['per-task', 'shared-leaf'], default='per-task')
    p.add_argument('--intervention', choices=['none', 'exact-reuse'], default='none')
    p.add_argument('--repository-version', default='content-addressed')
    p.add_argument('--memory-max-mb', type=int, default=0)
    p.add_argument('--memory-high-mb', type=int, default=0)
    p.add_argument('--jobs', type=int, default=8)
    p.add_argument('--passes', type=int, default=1)
    p.add_argument('--repetitions', type=int, default=5)
    p.add_argument('--warmups', type=int, default=1)
    p.add_argument('--seed', type=int, default=1)
    p.add_argument('--cache', choices=['warm', 'guest-cold', 'uncontrolled'], default='warm')
    p.add_argument('--allow-guest-drop-caches', action='store_true')
    p.add_argument('--verify-cache-residency', action='store_true',
                   help='Guest-only non-faulting file-data mincore proof; traverses metadata before timing')
    p.add_argument('--io-prime-device', type=Path, action='append', dest='io_prime_devices', default=[],
                   help='repeat for explicit Guest block devices; one pre-cache 4KiB direct read per device establishes real io.stat baselines')
    p.add_argument('--cpus', default=None, help='comma-separated allowed CPU IDs (workers only)')
    p.add_argument('--interval-ms', type=int, default=100)
    p.add_argument('--process-interval-ms', type=int, default=500)
    p.add_argument('--sample-threads', action='store_true', help='opt-in polled TID instances; not full lifecycle coverage')
    p.add_argument('--timeout-seconds', type=int, default=120)
    p.add_argument('--calibration-kind', choices=['cpu', 'sleep', 'read'],
                   help='controlled calibration instead of grep; explicitly labeled in reports')
    p.add_argument('--calibration-seconds', type=float, default=0.4)
    p.add_argument('--cgroup-parent', type=Path, default=CGROOT / 'search-profile')
    p.add_argument('--grep', default=shutil.which('grep'))
    p.add_argument('--kernel-hist-object', type=Path)
    p.add_argument('--kernel-hist-sha256')
    p.add_argument('--kernel-hist-groups', default='sched,syscall')
    p.add_argument('--kernel-hist-syscall-backend', choices=['kprobe', 'raw-btf'], default='kprobe')
    p.add_argument('--kernel-hist-memory-backend', choices=['kprobe-tracefs', 'fentry'], default='kprobe-tracefs')
    p.add_argument('--observer-binary', type=Path)
    p.add_argument('--verifier-binary', type=Path)
    p.add_argument('--recorder-object', type=Path)
    p.add_argument('--recorder-sha256')
    p.add_argument('--lifecycle-object', type=Path)
    p.add_argument('--lifecycle-sha256')
    p.add_argument('--observer-profile', choices=['control', 'balanced', 'full'], default='balanced')
    args = p.parse_args()
    concurrency = parse_ints(args.concurrency)
    modes = args.modes.split(',')
    if len(set(modes)) != len(modes) or not set(modes) <= {'baseline', 'sampler', 'kernel-hist', 'observer', 'observer-sampler'}:
        p.error('modes must be unique baseline,sampler,kernel-hist,observer,observer-sampler')
    if not 0 <= args.memory_max_mb <= 16384 or not 0 <= args.memory_high_mb <= 16384:
        p.error('memory bounds must be 0..16384 MiB')
    if args.memory_max_mb and args.memory_high_mb > args.memory_max_mb:
        p.error('memory.high must not exceed memory.max')
    if args.intervention != 'none' and args.calibration_kind:
        p.error('query reuse is only meaningful for GNU grep workload')
    if not 1 <= args.jobs <= 128 or max(concurrency) > args.jobs or not 1 <= args.passes <= 1000:
        p.error('jobs 1..128, concurrency <= jobs, passes 1..1000 required')
    if 'kernel-hist' in modes and args.cgroup_layout == 'per-task' and args.jobs > 15:
        p.error('multi-domain kernel-hist supports root plus at most 15 task cgroups')
    if not 1 <= args.repetitions <= 100 or not 0 <= args.warmups <= 10 or args.timeout_seconds < 1:
        p.error('invalid repetition/warmup/timeout limits')
    if not 10 <= args.interval_ms <= 60000 or args.process_interval_ms < 0 or (
            args.process_interval_ms and args.process_interval_ms < args.interval_ms):
        p.error('invalid sample/process interval')
    if not 0.05 <= args.calibration_seconds <= 10:
        p.error('calibration seconds must be 0.05..10')
    args.corpus = args.corpus.resolve(strict=True)
    args.sampler = args.sampler.resolve(strict=True)
    args.output_dir = args.output_dir.absolute()
    args.cgroup_parent = args.cgroup_parent.absolute()
    if args.output_dir.resolve() == args.corpus or args.corpus in args.output_dir.resolve().parents:
        p.error('output must be outside corpus')
    args.cpus = set(os.sched_getaffinity(0) if args.cpus is None else map(int, args.cpus.split(',')))
    if not args.cpus or not args.cpus <= os.sched_getaffinity(0):
        p.error('CPU affinity must be a nonempty subset of available CPUs')
    if not args.grep:
        p.error('GNU grep required')
    args.grep = str(Path(args.grep).resolve(strict=True))
    args.grep_sha256 = sha_file(args.grep)
    queries = json.loads(args.queries_file.read_text())
    if not isinstance(queries, list) or not 1 <= len(queries) <= args.jobs or any(
            not isinstance(q, str) or not q or '\x00' in q or '\n' in q or len(q) > 4096 for q in queries):
        p.error('queries must be a bounded nonempty JSON string array without newline/NUL')
    if 'kernel-hist' in modes:
        if not args.kernel_hist_object or not args.kernel_hist_sha256:
            p.error('kernel-hist mode requires object and expected SHA256')
        args.kernel_hist_object = args.kernel_hist_object.resolve(strict=True)
        if sha_file(args.kernel_hist_object) != args.kernel_hist_sha256:
            p.error('kernel histogram object digest mismatch')
    if set(modes) & {'observer', 'observer-sampler'}:
        if args.cgroup_layout != 'shared-leaf':
            p.error('Observer experiments require the same shared-leaf cgroup layout in every arm')
        for name in ('observer_binary', 'verifier_binary', 'recorder_object', 'lifecycle_object'):
            if getattr(args, name) is None:
                p.error('Observer modes require --' + name.replace('_', '-'))
            setattr(args, name, getattr(args, name).resolve(strict=True))
        for name in ('recorder', 'lifecycle'):
            if sha_file(getattr(args, name + '_object')) != getattr(args, name + '_sha256'):
                p.error(name + ' object digest mismatch')
    if os.geteuid() != 0:
        p.error('requires root in the disposable target Linux')
    args.output_dir.mkdir(mode=0o700)
    (args.output_dir / 'trials').mkdir()
    inventory = corpus_inventory(args.corpus)
    dump(args.output_dir / 'corpus-inventory.json', inventory)
    args.workspaces = [args.corpus] * args.jobs
    if args.workspace_layout == 'independent':
        workspace_parent = args.output_dir / 'workspaces'
        workspace_parent.mkdir(mode=0o700)
        args.workspaces = []
        for i in range(args.jobs):
            target = workspace_parent / ('agent-%04d' % i)
            shutil.copytree(args.corpus, target, ignore=shutil.ignore_patterns('.git'))
            copied = corpus_inventory(target)
            if (copied['sha256'], copied['permission_scope_sha256']) != (inventory['sha256'], inventory['permission_scope_sha256']):
                raise RuntimeError('independent workspace copy changes content or permission scope')
            args.workspaces.append(target)
    conditions = schedule(concurrency, modes, args.repetitions, args.warmups, args.seed)
    campaign = {'schema_version': 1, 'campaign_id': uuid.uuid4().hex,
                'status': 'RUNNING', 'scope': 'cooperative fixed-work GNU grep tools in target Linux',
                'calibration_kind': args.calibration_kind,
                'calibration_seconds': args.calibration_seconds,
                'timing_scope': 'PREPARED_WORKER_SIGCONT_TO_WAIT4_OBSERVATION',
                'cpu_time_scope': 'WAIT4_LIFETIME_MINUS_WORKER_PREFLIGHT_RUSAGE',
                'corpus': str(args.corpus), 'corpus_sha256': inventory['sha256'],
                'permission_scope_sha256': inventory['permission_scope_sha256'],
                'repository_version': args.repository_version, 'grep_options': GREP_OPTIONS,
                'security_context': security_context(), 'intervention': args.intervention,
                'workspace_layout': args.workspace_layout, 'cgroup_layout': args.cgroup_layout,
                'memory_max_mb': args.memory_max_mb, 'memory_high_mb': args.memory_high_mb,
                'sample_threads': args.sample_threads,
                'queries': queries, 'jobs': args.jobs, 'passes': args.passes, 'cache': args.cache,
                'seed': args.seed, 'conditions': conditions, 'trials': [],
                'binaries': {'sampler_sha256': sha_file(args.sampler), 'grep_sha256': sha_file(args.grep),
                             'runner_sha256': sha_file(__file__), 'analyzer_sha256': sha_file(analyze.__file__)},
                'observer_audit': 'PER_TRIAL' if set(modes) & {'observer', 'observer-sampler'} else 'NOT_ENABLED',
                'limits': ['Performance side channel, not WAL/manifest/verdict.',
                           'GNU grep -l -Z fixed-string search; results reusable only for identical corpus/query/options/permissions.',
                           'No shared-service/request/GPU attribution; no whole-system state claim.',
                           'Filesystem hashing occurs before cache preparation and after all timed trials.']}
    created_parent = False
    try:
        created_parent = ensure_cgroup_parent(args.cgroup_parent)
        for index, condition in enumerate(conditions):
            print(json.dumps({'trial': index, **condition}), flush=True)
            campaign['trials'].append(run_trial(args, args.output_dir, condition, inventory, queries, index))
        for root in sorted(set([args.corpus] + args.workspaces)):
            final = corpus_inventory(root)
            if (final['sha256'], final['permission_scope_sha256']) != (inventory['sha256'], inventory['permission_scope_sha256']):
                raise RuntimeError('corpus content or permissions changed during campaign')
        campaign['summary'] = summarize(campaign['trials'])
        campaign['status'] = 'COMPLETE'
    except BaseException as error:
        campaign.update(status='FAILED', error=str(error))
        raise
    finally:
        if created_parent:
            try:
                args.cgroup_parent.rmdir()
            except OSError as error:
                campaign.update(status='FAILED', cleanup_error=str(error))
        dump(args.output_dir / 'campaign.json', campaign)
        analyze.write_campaign_report(args.output_dir, campaign)
    print(str(args.output_dir / 'campaign.json'))
    return 0 if campaign['status'] == 'COMPLETE' else 1


if __name__ == '__main__':
    sys.exit(main())
