#!/usr/bin/env python3
"""A short, separate diagnosis run: actual two-tool reads + user/kernel perf.
No timing result here is reused as baseline or a measured optimization.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
import uuid

import analyze
from run import wait_ready, write


def inventory(root):
    result = []
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(names):
            path = Path(directory, name)
            if path.is_symlink() or not path.is_file() or len(result) >= 20000:
                raise ValueError('bounded regular read-only corpus required')
            stat = path.stat()
            result.append({'path': str(path.relative_to(root)), 'inode': stat.st_ino,
                'kernel_device': os.major(stat.st_dev) << 20 | os.minor(stat.st_dev),
                'size': stat.st_size, 'mtime_sec': stat.st_mtime_ns // 1_000_000_000,
                'mtime_nsec': stat.st_mtime_ns % 1_000_000_000,
                'ctime_sec': stat.st_ctime_ns // 1_000_000_000,
                'ctime_nsec': stat.st_ctime_ns % 1_000_000_000,
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    return result


def identity(pid):
    text = Path('/proc', str(pid), 'stat').read_text()
    return {'pid': pid, 'start_ticks': int(text[text.rfind(')') + 2:].split()[19])}


def worker(args):
    digest = hashlib.sha256()
    size = 0
    for _ in range(args.passes):
        result = subprocess.run(['/usr/bin/grep', '-r', '-l', '-Z', '-F', '--',
                                 args.query, args.corpus], stdout=subprocess.PIPE, timeout=30)
        if result.returncode not in (0, 1) or len(result.stdout) > 16 * 1024 * 1024:
            raise RuntimeError('bounded search failed')
        digest.update(result.stdout)
        size += len(result.stdout)
    print(json.dumps({'sha256': digest.hexdigest(), 'bytes': size, 'queries': args.passes}))


def search(args):
    vendor = ' '.join(path.read_text() for path in (Path('/sys/class/dmi/id/product_name'),
        Path('/sys/class/dmi/id/sys_vendor')) if path.exists()).lower()
    if not any(word in vendor for word in ('qemu', 'kvm')):
        raise ValueError('diagnostic workload is Guest-only')
    output = Path(args.output).absolute()
    output.mkdir()
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    run_id = output.name
    original_inventory = inventory(Path(args.corpus))
    parent = Path('/sys/fs/cgroup') / ('file-search-' + uuid.uuid4().hex[:12])
    parent.mkdir()
    parent_id = parent.stat().st_ino
    children, roots, events = [], [], []
    collector = None
    def emit(task, event):
        events.append({'schema_version': 1, 'seq': len(events), 'run_id': run_id, 'boot_id': boot,
            'attempt': 1, 'epoch': 1, 'request_id': None, 'parent_task_id': None,
            'dependencies': [], 'phase': 'SEARCH_DIAGNOSTIC', 'priority': 0,
            **task, 'event': event, 'monotonic_ns': time.monotonic_ns()})
    try:
        tasks = []
        for i in range(2):
            root = parent / ('agent-' + str(i))
            root.mkdir()
            stat = root.stat()
            roots.append((root, stat.st_ino))
            pid = os.fork()
            if pid == 0:
                try:
                    os.setsid()
                    os.sched_setaffinity(0, {int(v) for v in args.cpus.split(',')})
                    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 ** 2,) * 2)
                    with (output / ('agent-%d.json' % i)).open('x') as out:
                        os.dup2(out.fileno(), 1)
                        os.kill(os.getpid(), signal.SIGSTOP)
                        os.execv(sys.executable, [sys.executable, '-B', __file__, '--worker',
                            '--corpus', args.corpus, '--query', args.query, '--passes', str(args.passes)])
                except BaseException:
                    os._exit(127)
            children.append(pid)
            _, status = os.waitpid(pid, os.WUNTRACED)
            if not os.WIFSTOPPED(status):
                raise RuntimeError('search child not stopped')
            (root / 'cgroup.procs').write_text(str(pid))
            tasks.append({'task_id': 'task-%d' % i, 'agent_id': 'agent-%d' % i,
                'tool_call_id': 'grep-%d' % i, 'process': identity(pid),
                'cgroup': {'path': str(root), 'inode': stat.st_ino, 'device': stat.st_dev}})
        command = [args.profiler, '--output-dir', str(output / 'files'), '--bpf-object', args.bpf_object,
            '--bpf-sha256', hashlib.sha256(Path(args.bpf_object).read_bytes()).hexdigest(), '--label', run_id,
            '--max-file-records', str(args.max_file_records)]
        for root, _ in roots:
            command += ['--cgroup', str(root)]
        with (output / 'collector.stderr').open('x') as err:
            collector = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=err)
            wait_ready(collector)
            for pid, task in zip(children, tasks):
                emit(task, 'START')
                os.kill(pid, signal.SIGCONT)
            for task in tasks:
                pid = task['process']['pid']
                _, status = os.waitpid(pid, 0)
                children.remove(pid)
                emit(task, 'COMPLETE' if os.waitstatus_to_exitcode(status) == 0 else 'FAILED')
                if os.waitstatus_to_exitcode(status):
                    raise RuntimeError('diagnostic search failed')
            if any('populated 1' in (root / 'cgroup.events').read_text() for root, _ in roots):
                raise RuntimeError('search descendants remain')
            collector.send_signal(signal.SIGTERM)
            if collector.wait(timeout=20):
                raise RuntimeError('collector failed')
        with (output / 'task-events.jsonl').open('x') as stream:
            for event in events:
                stream.write(json.dumps(event) + '\n')
        results = [json.loads((output / ('agent-%d.json' % i)).read_text()) for i in range(2)]
        if results[0] != results[1]:
            raise ValueError('search results not equivalent')
        profile = analyze.read(output / 'files/file-profile.json')
        if inventory(Path(args.corpus)) != original_inventory:
            raise ValueError('read-only diagnostic corpus changed')
        object_inventory = {'boot_id': boot, 'objects': original_inventory,
            'pre_post_identical': True, 'scope': str(Path(args.corpus).resolve()),
            'version_quality': 'READ_ONLY_COOPERATIVE_INVENTORY_NOT_ATOMIC_SNAPSHOT'}
        write(output / 'file-inventory.json', object_inventory)
        report = analyze.analyze(profile, events, object_inventory,
                                 analyze.read(output / 'files/file-profile-meta.json'))
        write(output / 'file-report.json', report)
        # This separate perf workload must not alter or contaminate timed
        # campaign results. CPU-clock does not depend on a virtual PMU.
        perf_command = ['/usr/bin/perf', 'record', '-e', 'cpu-clock', '-F', '999', '-g',
            '--call-graph', 'dwarf,8192', '-o', str(output / 'perf.data'), '--',
            '/usr/bin/taskset', '-c', args.cpus, sys.executable, '-B', __file__, '--worker',
            '--corpus', args.corpus, '--query', args.query, '--passes', str(args.passes)]
        with (output / 'perf.stdout').open('x') as out, (output / 'perf.stderr').open('x') as err:
            perf_result = subprocess.run(perf_command, stdout=out, stderr=err, timeout=60)
        with (output / 'perf-report.txt').open('x') as stream:
            perf_report = subprocess.run(['/usr/bin/perf', 'report', '--stdio', '--no-children',
                '--sort', 'dso,symbol', '-i', str(output / 'perf.data')], stdout=stream,
                stderr=subprocess.PIPE, text=True, timeout=30)
        write(output / 'validation.json', {'schema_version': 1,
            'status': ('PASS' if profile['observation_health'] == 'COMPLETE_FOR_SELECTED_HOOKS'
                else 'INCOMPLETE_DIAGNOSTIC') if perf_result.returncode == perf_report.returncode == 0
                else 'PERF_UNAVAILABLE',
            'file_hook_health': profile['observation_health'],
            'domain_interval_unresolved_calls': report['unresolved_association_calls'],
            'identical_tool_output': True, 'physical_searches_per_agent': args.passes,
            'perf_event': 'software CPU-clock 999Hz; sampled DSO/symbol candidates, not precise accounting',
            'perf_returncode': perf_result.returncode, 'perf_report_returncode': perf_report.returncode,
            'perf_version': subprocess.check_output(['/usr/bin/perf', '--version'], text=True).strip(),
            'limits': ['separate diagnosis, not overhead or slowdown estimate',
                'unsymbolized addresses stay unknown, not classified as matching or metadata cost',
                'aggregate VFS time overlaps with kernel perf samples; never add them as wall time']})
    finally:
        for pid in children:
            try:
                os.killpg(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
        if collector and collector.poll() is None:
            collector.send_signal(signal.SIGTERM)
            collector.wait(timeout=20)
        for root, expected in reversed(roots):
            if root.stat().st_ino != expected:
                raise ValueError('cgroup identity changed; refusing cleanup')
            if 'populated 0' in (root / 'cgroup.events').read_text():
                root.rmdir()
        if parent.stat().st_ino == parent_id and not any(root.exists() for root, _ in roots):
            parent.rmdir()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--corpus', required=True)
    parser.add_argument('--query', default='return')
    parser.add_argument('--passes', type=int, default=32)
    parser.add_argument('--cpus', default='0,1')
    parser.add_argument('--output')
    parser.add_argument('--profiler')
    parser.add_argument('--bpf-object')
    parser.add_argument('--max-file-records', type=int, default=32768)
    args = parser.parse_args()
    if not 1 <= args.passes <= 256:
        parser.error('passes must be 1..256')
    worker(args) if args.worker else search(args)
