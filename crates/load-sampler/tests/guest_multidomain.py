#!/usr/bin/env python3
"""Cooperative fixture for a fresh disposable Guest only; no Host mutations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
import uuid


def wait_until(predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise RuntimeError('fixture barrier timed out')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sampler', type=Path, required=True)
    parser.add_argument('--object', type=Path, required=True)
    parser.add_argument('--workload', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--groups', default='sched,syscall')
    parser.add_argument('--empty-domains', type=int, default=0)
    parser.add_argument('--syscall-backend', choices=('kprobe', 'raw-btf'), default='kprobe')
    parser.add_argument('--syscall-stress', action='store_true', help='select only getpid (x86-64 nr39), four workers x100000 fixed completed calls')
    parser.add_argument('--workload-mode', choices=('cpu', 'fault', 'lock', 'reclaim'), default='cpu')
    parser.add_argument('--require-metric', action='append', default=[])
    parser.add_argument('--memory-backend', choices=('kprobe-tracefs', 'fentry'), default='kprobe-tracefs')
    parser.add_argument('--workload-cpu', type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.empty_domains <= 13:
        parser.error('--empty-domains must be 0..13 (16 domains total maximum)')
    args.output.mkdir(mode=0o700)
    cgroup = Path('/sys/fs/cgroup') / ('khist-cal-' + uuid.uuid4().hex)
    children = [cgroup / name for name in ('cpu', 'sleep')]
    children += [cgroup / ('empty-%02d' % index) for index in range(args.empty_domains)]
    previous_schedstats = Path('/proc/sys/kernel/sched_schedstats').read_text()
    processes = []
    streams = []
    sampler = None
    try:
        cgroup.mkdir()
        (cgroup / 'cgroup.subtree_control').write_text('+cpu +memory +io\n')
        for child in children:
            child.mkdir()
        Path('/proc/sys/kernel/sched_schedstats').write_text('1\n')
        for name, child in zip(('cpu', 'sleep'), children):
            output = (args.output / (name + '.jsonl')).open('wb')
            error = (args.output / (name + '.stderr')).open('wb')
            streams.extend([output, error])
            mode = ('getpid' if args.syscall_stress else args.workload_mode) if name == 'cpu' else name
            workload_command = [str(args.workload.resolve()), mode]
            if name == 'cpu' and mode in ('lock', 'reclaim'):
                workload_command += [str((args.output / 'owned-workload-data').resolve())]
                if mode == 'reclaim':
                    workload_command += [str(child / 'memory.reclaim')]
            process = subprocess.Popen(workload_command, stdout=output, stderr=error)
            processes.append(process)
            wait_until(lambda: Path('/proc/%d/stat' % process.pid).read_text().rsplit(')', 1)[1].split()[0] == 'T')
            (child / 'cgroup.procs').write_text(str(process.pid))
            expected = '0::/' + str(child.relative_to('/sys/fs/cgroup'))
            actual = Path('/proc/%d/cgroup' % process.pid).read_text().strip()
            assert actual == expected, (actual, expected)
            os.sched_setaffinity(process.pid, {args.workload_cpu})
        sampler_error = (args.output / 'sampler.stderr').open('wb')
        streams.append(sampler_error)
        digest = hashlib.sha256(args.object.read_bytes()).hexdigest()
        command = [str(args.sampler.resolve()), '--output-dir', str(args.output / 'load'),
                   '--interval-ms', '50', '--process-interval-ms', '50', '--sample-threads',
                   '--kernel-hist-object', str(args.object.resolve()), '--kernel-hist-sha256', digest,
                   '--kernel-hist-groups', args.groups, '--kernel-hist-syscall-backend', args.syscall_backend,
                   '--kernel-hist-memory-backend', args.memory_backend,
                   '--label', 'multidomain-pthread-calibration']
        for group in [cgroup] + children:
            command += ['--cgroup', str(group)]
        if args.syscall_stress:
            command += ['--kernel-hist-syscall-nr', '39']
        sampler = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=sampler_error)
        selector = selectors.DefaultSelector()
        selector.register(sampler.stdout, selectors.EVENT_READ)
        ready = bytearray()
        deadline = time.monotonic() + 30
        while b'\n' not in ready:
            if time.monotonic() > deadline:
                raise RuntimeError('sampler READY timed out')
            for key, _ in selector.select(0.1):
                block = os.read(key.fd, 4096)
                if not block:
                    raise RuntimeError('sampler failed before READY; inspect sampler.stderr')
                ready.extend(block)
        assert bytes(ready).splitlines()[0] == b'READY'
        selector.close()
        started = time.monotonic_ns()
        for process in processes:
            os.kill(process.pid, signal.SIGCONT)
        for process in processes:
            assert process.wait(timeout=20) == 0
        ended = time.monotonic_ns()
        (cgroup / 'cgroup.freeze').write_text('1\n')
        wait_until(lambda: 'populated 0' in (cgroup / 'cgroup.events').read_text() and 'frozen 1' in (cgroup / 'cgroup.events').read_text())
        def post_exit_sample():
            lines = (args.output / 'load/load-samples.jsonl').read_text().splitlines()
            return lines and json.loads(lines[-1])['monotonic_ns'] > ended + 50000000
        wait_until(post_exit_sample)
        sampler.terminate()
        assert sampler.wait(timeout=20) == 0
        rows = [json.loads(line) for line in (args.output / 'load/load-samples.jsonl').read_text().splitlines()]
        meta = json.loads((args.output / 'load/load-meta.json').read_text())
        stats = json.loads((args.output / 'load/load-sampler-stats.json').read_text())
        snapshot = rows[-1]['khist']
        assert meta['kernel_hist']['probe_sets_loaded'] == 1
        assert len(snapshot['domains']) == 3 + args.empty_domains and snapshot['system']['scope'] == 'SYSTEM_UNATTRIBUTED'
        metrics = {item['name']: i for i, item in enumerate(meta['kernel_hist']['metrics'])}
        counters = {name: i for i, name in enumerate(meta['kernel_hist']['counters'])}
        root, cpu, sleep = snapshot['domains'][:3]
        for empty in snapshot['domains'][3:]:
            assert all(metric[0] == metric[1] == 0 for metric in empty['m'])
            assert all(counter == 0 for counter in empty['c'])
        for metric in metrics:
            i = metrics[metric]
            assert root['m'][i][0] == cpu['m'][i][0] + sleep['m'][i][0], metric
            assert root['m'][i][1] == cpu['m'][i][1] + sleep['m'][i][1], metric
        cpu_truth = sum(json.loads(line)['cpu_ns'] for line in (args.output / 'cpu.jsonl').read_text().splitlines())
        cpu_observed = cpu['m'][metrics['sched_oncpu']][1]
        assert 0.95 * cpu_truth <= cpu_observed <= 1.10 * cpu_truth, (cpu_observed, cpu_truth)
        if not args.syscall_stress and args.workload_mode == 'cpu':
            assert cpu['m'][metrics['sched_runq']][1] > 400000000
        assert sleep['m'][metrics['sched_offcpu_s']][1] > 2000000000
        assert sleep['m'][metrics['sched_oncpu']][1] < 100000000
        for metric in args.require_metric:
            assert cpu['m'][metrics[metric]][0] > 0, (metric, 'requested positive control was not observed')
        for domain in snapshot['domains']:
            assert domain['c'][counters['task_enrolled']] == domain['c'][counters['task_exit']]
            assert domain['c'][counters['storage_miss']] == 0
            assert domain['c'][counters['domain_change']] == 0
        process_samples = [json.loads(line) for line in (args.output / 'load/load-processes.jsonl').read_text().splitlines()]
        observed = [thread for sample in process_samples for group in sample['cgroups']
                    for process in group['processes'] for thread in process.get('tid_samples', [])]
        expected_tids = {json.loads(line)['tid'] for name in ('cpu', 'sleep')
                         for line in (args.output / (name + '.jsonl')).read_text().splitlines()}
        assert expected_tids <= {thread['identity']['tid'] for thread in observed}
        assert all(thread['identity']['boot_id'] == meta['boot_id'] for thread in observed)
        assert any(thread['wait_ns'] and thread['wait_ns'] > 10000000 for thread in observed)
        programs = stats['kernel_hist']['programs']
        syscall_truth = None
        if args.syscall_stress:
            syscall_truth = sum(json.loads(line)['getpid_completed'] for line in (args.output / 'cpu.jsonl').read_text().splitlines())
            assert syscall_truth == 400000
            assert cpu['m'][metrics['syscall_other']][0] == syscall_truth
            assert root['m'][metrics['syscall_other']][0] == syscall_truth
            assert sleep['m'][metrics['syscall_other']][0] == 0
            for domain in snapshot['domains']:
                assert domain['c'][counters['unpaired_end']] == 0
        diagnostic_issues = []
        for program in programs:
            if program['recursion_misses'] and program.get('role') != 'REGISTRATION_ONLY_NO_HISTOGRAM_PAYLOAD':
                diagnostic_issues.append({'kind': 'PROGRAM_RECURSION_MISS', 'program': program['name'],
                                          'count': program['recursion_misses']})
        if stats['kernel_hist']['program_info_read_errors']:
            diagnostic_issues.append({'kind': 'PROGRAM_INFO_READ_ERROR',
                                      'count': stats['kernel_hist']['program_info_read_errors']})
        for domain in snapshot['domains']:
            for counter in ('unpaired_end', 'storage_miss', 'task_exit_unfinished', 'domain_change'):
                count = domain['c'][counters[counter]]
                if count:
                    diagnostic_issues.append({'kind': 'DOMAIN_COVERAGE_GAP', 'domain': domain['identity']['path'],
                                              'counter': counter, 'count': count})
        for event in stats['kernel_hist'].get('memory_return_probe_profiles', []):
            if event['profile_status'] != 'OBSERVED' or event['misses']:
                diagnostic_issues.append({'kind': 'MEMORY_PROBE_KERNEL_MISS_OR_UNKNOWN', 'event': event['name'],
                                          'profile_status': event['profile_status'], 'misses': event['misses']})
        if stats['kernel_hist'].get('tracefs_cleanup', {}).get('status') != 'COMPLETE':
            diagnostic_issues.append({'kind': 'TRACEFS_CLEANUP_INCOMPLETE'})
        if stats['kernel_hist']['online_cpu_identity']['status'] != 'STABLE':
            diagnostic_issues.append({'kind': 'ONLINE_CPU_SET_CHANGED_OR_UNKNOWN'})
        result = {'schema_version': 1, 'status': 'PASS', 'boot_id': meta['boot_id'],
                  'sampler_sha256': hashlib.sha256(args.sampler.read_bytes()).hexdigest(),
                  'object_sha256': digest, 'started_ns': started, 'ended_ns': ended,
                  'fixture_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'workload_sha256': hashlib.sha256(args.workload.read_bytes()).hexdigest(),
                  'groups': meta['kernel_hist']['groups'],
                  'syscall_number_selection': meta['kernel_hist']['syscall_number_selection'],
                  'registry_frozen': meta['kernel_hist']['registry_frozen'],
                  'one_probe_set': True, 'domain_count': len(snapshot['domains']), 'inclusive_root_equals_children_at_quiescence': True,
                  'cpu_truth_ns': cpu_truth, 'cpu_observed_ns': cpu_observed,
                  'syscall_backend': args.syscall_backend, 'selected_getpid_completed_truth': syscall_truth,
                  'workload_mode': args.workload_mode,
                  'positive_controls': {metric: cpu['m'][metrics[metric]][:2] for metric in args.require_metric},
                  'worker_minor_fault_truth': sum(json.loads(line)['minor_faults'] for line in (args.output / 'cpu.jsonl').read_text().splitlines()),
                  'memory_backend': args.memory_backend,
                  'workload_cpu': args.workload_cpu,
                  'memory_probe_profiles': stats['kernel_hist'].get('memory_return_probe_profiles', []),
                  'tracefs_cleanup': stats['kernel_hist'].get('tracefs_cleanup'),
                  'cpu_runq_ns': cpu['m'][metrics['sched_runq']][1],
                  'sleep_offcpu_ns': sleep['m'][metrics['sched_offcpu_s']][1],
                  'expected_worker_tids': sorted(expected_tids), 'thread_polling_lifecycle': 'PARTIAL',
                  'thread_sampling_status': stats['thread_sampling_status'],
                  'diagnostic_health': 'INCOMPLETE' if diagnostic_issues else 'COMPLETE_WITHIN_DECLARED_HOOKS',
                  'diagnostic_issues': diagnostic_issues,
                  'program_recursion_misses': {program['name']: program['recursion_misses'] for program in programs},
                  'system_metric_attribution': 'SYSTEM_UNATTRIBUTED',
                  'limits': ['pthread calibration is not an Agent or GPU benchmark', 'root/child counters overlap and must not be summed', 'thread polling does not prove full lifecycle', 'no block requeue/partial-completion hardware workload was forced in this fixture']}
        (args.output / 'validation.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
    finally:
        if sampler and sampler.poll() is None:
            sampler.terminate()
            try:
                sampler.wait(timeout=10)
            except subprocess.TimeoutExpired:
                sampler.kill(); sampler.wait()
        for process in processes:
            if process.poll() is None:
                process.kill(); process.wait()
        for stream in streams:
            stream.close()
        Path('/proc/sys/kernel/sched_schedstats').write_text(previous_schedstats)
        for child in reversed(children):
            if child.exists():
                child.rmdir()
        if cgroup.exists():
            cgroup.rmdir()


if __name__ == '__main__':
    main()
