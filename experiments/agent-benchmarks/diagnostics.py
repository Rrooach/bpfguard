#!/usr/bin/env python3
"""Explicit, independently costed diagnostics for real benchmark containers.

The caller owns freezing/unfreezing the workload and the normal load sampler.
Call start while frozen, add sampler_options(config) to the sampler command,
unfreeze for the task, freeze again, then finish. No mode silently falls back.
Configuration is artifact['diagnostics']; omitted configuration means baseline.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time


CGROUP_ROOT = Path('/sys/fs/cgroup')
SCHEDSTATS = Path('/proc/sys/kernel/sched_schedstats')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
MODES = {'baseline', 'threads', 'kernel', 'files', 'perf'}
KERNEL_GROUPS = 'sched,mem,lock,blk,irq,syscall'


def _config(config):
    if config is None:
        config = {}
    if not isinstance(config, dict) or config.get('mode', 'baseline') not in MODES:
        raise ValueError('diagnostics mode must be baseline, threads, kernel, files or perf')
    return dict(config)


def _pinned(config, path_key, digest_key):
    value, digest = config.get(path_key), config.get(digest_key)
    if not isinstance(value, (str, os.PathLike)) or not isinstance(digest, str) or len(digest) != 64:
        raise ValueError('diagnostics requires pinned ' + path_key + '/' + digest_key)
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        raise ValueError('diagnostic artifact must be an absolute regular file: ' + str(path))
    actual = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            actual.update(block)
    if actual.hexdigest() != digest.lower():
        raise ValueError('diagnostic artifact SHA256 mismatch: ' + path_key)
    return str(path)


def sampler_options(config=None):
    """Additional arguments only; caller supplies nonzero process interval."""
    config = _config(config)
    mode = config.get('mode', 'baseline')
    if mode not in {'threads', 'kernel'}:
        return []
    if SCHEDSTATS.read_text().strip() != '1':
        raise RuntimeError('thread diagnostics require kernel.sched_schedstats=1 before READY')
    result = ['--sample-threads']
    if mode == 'kernel':
        obj = _pinned(config, 'kernel_hist_object', 'kernel_hist_sha256')
        result += ['--kernel-hist-object', obj, '--kernel-hist-sha256', config['kernel_hist_sha256'],
                   '--kernel-hist-groups', KERNEL_GROUPS,
                   '--kernel-hist-syscall-backend', 'kprobe',
                   '--kernel-hist-memory-backend', 'kprobe-tracefs']
    return result


def _write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def _identity(path):
    path = Path(path)
    canonical = path.resolve(strict=True)
    try:
        relative = canonical.relative_to(CGROUP_ROOT)
    except ValueError:
        raise ValueError('diagnostics cgroup is outside the cgroup-v2 mount') from None
    if path != canonical or not relative.parts:
        raise ValueError('diagnostics require an exact canonical non-root cgroup-v2 path')
    if not (path / 'cgroup.controllers').is_file():
        raise ValueError('diagnostics target is not cgroup v2')
    stat = path.stat()
    return {'path': str(path), 'inode': stat.st_ino, 'device': stat.st_dev}


def _line(fd, timeout, maximum=65536, allow_nul_padding=False):
    deadline = time.monotonic() + timeout
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                continue
            chunk = os.read(fd, min(4096, maximum + 1 - len(data)))
            if not chunk:
                raise RuntimeError('diagnostic closed its readiness/control stream')
            data.extend(chunk)
            if len(data) > maximum:
                raise RuntimeError('diagnostic readiness/control response exceeds bound')
            # perf evlist__ctlfd_ack uses sizeof("ack\n") in some releases,
            # including the terminal NUL. A split NUL can precede the next ACK.
            payload = bytes(data).strip(b'\0') if allow_nul_padding else bytes(data)
            if b'\n' in payload:
                if payload.count(b'\n') != 1 or not payload.endswith(b'\n'):
                    raise RuntimeError('unexpected diagnostic readiness/control response')
                return bytes(data)
    raise TimeoutError('diagnostic readiness/control timeout')


def _usage(usage):
    return {'user_cpu_seconds': usage.ru_utime, 'system_cpu_seconds': usage.ru_stime,
            'max_rss_kib': usage.ru_maxrss, 'read_blocks': usage.ru_inblock,
            'written_blocks': usage.ru_oublock, 'source': 'wait4_child_rusage_linux_kib'}


def _reap(process, timeout):
    if process.returncode is not None:
        return {'returncode': process.returncode, 'usage_status': 'UNAVAILABLE_ALREADY_REAPED'}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            waited, status, usage = os.wait4(process.pid, os.WNOHANG)
        except ChildProcessError:
            return {'returncode': process.returncode, 'usage_status': 'UNAVAILABLE_EXTERNALLY_REAPED'}
        if waited:
            process.returncode = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
            return {'returncode': process.returncode, 'usage_status': 'COMPLETE', **_usage(usage)}
        time.sleep(.02)
    raise TimeoutError('diagnostic collector shutdown timeout')


class Diagnostics:
    def __init__(self, config, output_path, cgroup_path, label):
        self.config = _config(config)
        self.mode = self.config.get('mode', 'baseline')
        self.output = Path(output_path)
        self.cgroup = Path(cgroup_path)
        self.label = label
        self.process = None
        self.handles = []
        self.control_write = self.ack_read = None
        self.started = self.finished = False
        self.issues = []
        self.report = {'schema_version': 1, 'mode': self.mode, 'label': label,
            'status': 'NOT_STARTED', 'collector_usage': None,
            'scope': 'EXPLICIT_DIAGNOSTIC_NOT_DEFAULT_OR_FULL_SYSTEM_OBSERVATION',
            'overhead_scope': 'measure paired same-task baseline; do not reuse unrelated diagnosis timing'}

    def _boundary(self):
        if _identity(self.cgroup) != self.report['cgroup']:
            raise RuntimeError('diagnostic cgroup identity changed')
        if BOOT_ID.read_text().strip() != self.report['boot_id']:
            raise RuntimeError('diagnostic boot identity changed')
        events = dict(line.split() for line in (self.cgroup / 'cgroup.events').read_text().splitlines())
        if self.mode != 'baseline' and events.get('frozen') != '1':
            raise RuntimeError('diagnostic boundary requires workload cgroup frozen=1')
        if self.mode in {'threads', 'kernel'} and SCHEDSTATS.read_text().strip() != '1':
            raise RuntimeError('kernel.sched_schedstats must remain enabled throughout diagnostics')
        return {'monotonic_ns': time.monotonic_ns(), 'cgroup_events': events,
                'schedstats': SCHEDSTATS.read_text().strip() if self.mode in {'threads', 'kernel'} else None}

    def _spawn(self, command, **kwargs):
        self.report['command'] = command
        err = (self.output / 'collector.stderr').open('xb')
        self.handles.append(err)
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=err, bufsize=0, **kwargs)
        self.report['collector_pid'] = self.process.pid

    def start(self):
        if self.started or self.finished:
            raise RuntimeError('diagnostics cannot start twice')
        self.output.mkdir(parents=True, exist_ok=False)
        self.started = True
        try:
            self.report.update(cgroup=_identity(self.cgroup), boot_id=BOOT_ID.read_text().strip())
            self.report['start_boundary'] = self._boundary()
            self.report['sampler_options'] = sampler_options(self.config)
            if self.mode == 'files':
                binary = _pinned(self.config, 'file_profiler_binary', 'file_profiler_sha256')
                obj = _pinned(self.config, 'file_profiler_object', 'file_profiler_object_sha256')
                maximum = self.config.get('max_file_records', 8192)
                seconds = self.config.get('max_seconds', 1200)
                if type(maximum) is not int or not 1024 <= maximum <= 131072 or type(seconds) is not int or not 1 <= seconds <= 3600:
                    raise ValueError('file diagnostic limits outside collector bounds')
                self._spawn([binary, '--output-dir', str(self.output / 'files'), '--bpf-object', obj,
                    '--bpf-sha256', self.config['file_profiler_object_sha256'], '--cgroup', str(self.cgroup),
                    '--label', self.label, '--max-seconds', str(seconds), '--max-file-records', str(maximum)])
                ready = _line(self.process.stdout.fileno(), 30)
                _write(self.output / 'collector-ready.json', {'raw': ready.decode('ascii', errors='replace')})
                if ready != b'READY\n':
                    raise RuntimeError('file profiler did not send exact READY')
                self._file_metadata()
            elif self.mode == 'perf':
                self._start_perf()
            self.report['ready_boundary'] = self._boundary()
            self.report['status'] = 'READY'
            _write(self.output / 'diagnostics-ready.json', self.report)
            return dict(self.report)
        except BaseException as error:
            self.issues.append(type(error).__name__ + ': ' + str(error))
            self._cleanup()
            self._finalize('START_FAILED')
            raise

    def _file_metadata(self):
        meta = json.loads((self.output / 'files/file-profile-meta.json').read_text())
        if (meta.get('label') != self.label or meta.get('boot_id') != self.report['boot_id'] or
                meta.get('bpf_sha256') != self.config['file_profiler_object_sha256'].lower()):
            raise RuntimeError('file profiler run/boot/object binding mismatch')
        domains = meta.get('domains')
        if (not isinstance(domains, list) or len(domains) != 1 or
                any(domains[0].get(key) != value for key, value in self.report['cgroup'].items())):
            raise RuntimeError('file profiler exact cgroup binding mismatch')
        self.report['file_metadata_binding_validated'] = True

    def _perf_control(self, command):
        os.write(self.control_write, command.encode('ascii') + b'\n')
        ack = _line(self.ack_read, 30, allow_nul_padding=True)
        with (self.output / 'perf-control.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'command': command, 'ack': ack.decode('ascii', errors='replace'),
                                     'monotonic_ns': time.monotonic_ns()}) + '\n')
        if ack.strip(b'\0\r\n') != b'ack':
            raise RuntimeError('perf did not acknowledge ' + command)
        self.report.setdefault('perf_acknowledged_commands', []).append(command)

    def _start_perf(self):
        binary = _pinned(self.config, 'perf_binary', 'perf_sha256')
        control_read, self.control_write = os.pipe()
        self.ack_read, ack_write = os.pipe()
        frequency = self.config.get('frequency_hz', 99)
        if type(frequency) is not int or not 1 <= frequency <= 1000:
            os.close(control_read)
            os.close(ack_write)
            raise ValueError('perf frequency must be 1..1000 Hz')
        relative = str(self.cgroup.relative_to(CGROUP_ROOT))
        command = [binary, 'record', '-e', 'cpu-clock', '-a', '-G', relative,
            '-F', str(frequency), '--call-graph', 'dwarf,8192', '--delay=-1',
            '--control', 'fd:%d,%d' % (control_read, ack_write), '-o', str(self.output / 'perf.data')]
        try:
            self._spawn(command, pass_fds=(control_read, ack_write))
        finally:
            os.close(control_read)
            os.close(ack_write)
        self._perf_control('enable')
        self.report['perf_scope'] = {'event': 'software cpu-clock', 'frequency_hz': frequency,
            'cgroup_relative_path': relative, 'enable_ack_received': True,
            'interpretation': 'SAMPLED_DSO_SYMBOL_CANDIDATES_NOT_PRECISE_ACCOUNTING'}

    def _stop_collector(self):
        if self.process is None:
            return
        if self.process.returncode is None:
            # os.kill avoids Popen.poll silently reaping an already exited child
            # before wait4 can preserve its exact CPU and maximum RSS counters.
            try:
                os.kill(self.process.pid, signal.SIGINT if self.mode == 'perf' else signal.SIGTERM)
            except ProcessLookupError:
                pass
        self.report['collector_usage'] = _reap(self.process, 20)
        code = self.report['collector_usage']['returncode']
        # perf record deliberately re-raises its stop signal after finalizing
        # perf.data (builtin-record.c: record__sig_exit). Keep the raw status;
        # accept SIGINT only after our acknowledged disable, and still require
        # nonempty data plus a successful independent perf report below.
        expected_perf_stop = (self.mode == 'perf' and code == -signal.SIGINT and
                              self.report.get('perf_acknowledged_commands') == ['enable', 'disable'])
        if expected_perf_stop:
            self.report['collector_termination'] = 'EXPECTED_PERF_SIGINT_REQUIRES_VALID_REPORT'
        if code != 0 and not expected_perf_stop:
            raise RuntimeError('diagnostic collector returned failure: ' + str(self.report['collector_usage']['returncode']))

    def _cleanup(self):
        if self.process is not None and self.process.returncode is None:
            try:
                self._stop_collector()
            except BaseException as error:
                self.issues.append('cleanup: ' + str(error))
                if self.process.returncode is None:
                    try:
                        os.kill(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self.report['collector_usage'] = _reap(self.process, 10)
                    self.issues.append('collector_forced_kill')
        for fd in (self.control_write, self.ack_read):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as error:
                    self.issues.append('control_fd_close: ' + str(error))
        self.control_write = self.ack_read = None
        if self.process is not None and self.process.stdout is not None:
            self.process.stdout.close()
        for handle in self.handles:
            handle.close()
        self.handles = []

    def _finalize(self, status):
        self.finished = True
        self.report.update(status=status, issues=list(self.issues), finalized_monotonic_ns=time.monotonic_ns(),
            evidence_bytes_excluding_this_summary=sum(path.stat().st_size for path in self.output.rglob('*') if path.is_file()))
        _write(self.output / 'diagnostics.json', self.report)
        return dict(self.report)

    def finish(self):
        if not self.started:
            raise RuntimeError('diagnostics must start before finish')
        if self.finished:
            return dict(self.report)
        error = None
        try:
            self.report['finish_boundary'] = self._boundary()
            if self.mode == 'perf':
                self._perf_control('disable')
            self._stop_collector()
            if self.mode == 'files':
                self._file_metadata()
                profile = json.loads((self.output / 'files/file-profile.json').read_text())
                self.report['file_observation_health'] = profile.get('observation_health', 'UNKNOWN')
                self.report['file_health'] = profile.get('health')
                if profile.get('boot_id') != self.report['boot_id'] or profile.get('timed_out') is not False:
                    self.issues.append('file_profile_boot_mismatch_or_timeout')
                if profile.get('observation_health') != 'COMPLETE_FOR_SELECTED_HOOKS':
                    self.issues.append('file_profile_incomplete_for_selected_hooks')
            elif self.mode == 'perf':
                if not (self.output / 'perf.data').is_file() or (self.output / 'perf.data').stat().st_size == 0:
                    raise RuntimeError('perf did not retain nonempty raw perf.data')
                begin = time.monotonic_ns()
                with (self.output / 'perf-report.txt').open('xb') as out, (self.output / 'perf-report.stderr').open('xb') as err:
                    report = subprocess.run([self.config['perf_binary'], 'report', '--stdio', '--no-children',
                        '--sort', 'dso,symbol', '-i', str(self.output / 'perf.data')], stdout=out, stderr=err, timeout=30)
                self.report['perf_report_returncode'] = report.returncode
                self.report['perf_report_duration_ns'] = time.monotonic_ns() - begin
                if report.returncode:
                    raise RuntimeError('perf report failed; retained stderr')
        except BaseException as caught:
            error = caught
            self.issues.append(type(caught).__name__ + ': ' + str(caught))
        finally:
            self._cleanup()
            result = self._finalize('INCOMPLETE' if self.issues else 'COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE')
        if error is not None:
            raise error
        return result
