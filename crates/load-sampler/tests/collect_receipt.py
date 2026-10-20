#!/usr/bin/env python3
"""Hash exported raw calibration evidence and independently replay final checks.

This is a profiling-fixture audit, not the cryptographic system-effect verifier.
It assumes the collector and target kernel remain trusted.
"""
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def read_jsonl(path):
    with path.open() as stream:
        return [json.loads(line) for line in stream if line.strip()]


def replay_final(directory):
    report = read_json(directory / 'validation.json')
    meta = read_json(directory / 'load/load-meta.json')
    stats = read_json(directory / 'load/load-sampler-stats.json')
    samples = read_jsonl(directory / 'load/load-samples.jsonl')
    processes = read_jsonl(directory / 'load/load-processes.jsonl')
    cpu = read_jsonl(directory / 'cpu.jsonl')
    sleep = read_jsonl(directory / 'sleep.jsonl')
    final = samples[-1]['khist']
    assert meta['boot_id'] == report['boot_id']
    assert meta['kernel_hist']['object_sha256'] == report['object_sha256']
    assert meta['kernel_hist']['registry_frozen']
    assert len(final['domains']) == len(meta['kernel_hist']['domains']) == report['domain_count']
    assert final['system']['scope'] == 'SYSTEM_UNATTRIBUTED'
    for i, domain in enumerate(final['domains']):
        assert domain['identity'] == meta['kernel_hist']['domains'][i]
        assert domain['identity']['domain_index'] == i
    root, leaf_cpu, leaf_sleep = final['domains'][:3]
    for i, metric in enumerate(root['m']):
        assert metric[0] == sum(domain['m'][i][0] for domain in final['domains'][1:])
        assert metric[1] == sum(domain['m'][i][1] for domain in final['domains'][1:])
    for empty in final['domains'][3:]:
        assert all(row[:2] == [0, 0] for row in empty['m']) and not any(empty['c'])
    metrics = {metric['name']: i for i, metric in enumerate(meta['kernel_hist']['metrics'])}
    counters = {name: i for i, name in enumerate(meta['kernel_hist']['counters'])}
    for domain in final['domains']:
        assert domain['c'][counters['task_enrolled']] == domain['c'][counters['task_exit']]
        for name in ('storage_miss', 'unpaired_end', 'domain_change', 'task_exit_unfinished'):
            assert domain['c'][counters[name]] == 0
    programs = stats['kernel_hist']['programs']
    assert len(programs) == stats['kernel_hist']['program_info_expected_count']
    assert stats['kernel_hist']['program_info_read_errors'] == 0
    ignored_noop = {}
    for program in programs:
        if program['name'] in ('kh_sys_enter_dispatch', 'kh_sys_exit_dispatch'):
            assert program['role'] == 'REGISTRATION_ONLY_NO_HISTOGRAM_PAYLOAD'
            ignored_noop[program['name']] = program['recursion_misses']
        else:
            assert program['role'] == 'MEASUREMENT' and program['recursion_misses'] == 0
    profiles_s0 = {p['name']: p for p in meta['kernel_hist']['programs']['memory_return_probe_profiles']}
    profiles_s1 = stats['kernel_hist']['memory_return_probe_profiles']
    assert len(profiles_s0) == len(profiles_s1) == 6
    for end in profiles_s1:
        start = profiles_s0[end['name']]
        for key in ('name', 'group', 'anchor', 'definition', 'event_id', 'device', 'directory_inode', 'maxactive', 'is_return'):
            assert start[key] == end[key], key
        assert start['profile_status'] == end['profile_status'] == 'OBSERVED'
        assert end['hits'] >= start['hits'] >= end['initial_hits']
        assert end['misses'] == start['misses'] == end['initial_misses'] == 0
        if end['is_return']:
            assert end['maxactive'] == 1024
        assert end['initial_collection_start_ns'] <= end['initial_collection_end_ns'] <= report['started_ns']
        assert end['collection_end_ns'] >= end['collection_start_ns'] >= report['ended_ns']
    cleanup = stats['kernel_hist']['tracefs_cleanup']
    assert cleanup['status'] == 'COMPLETE' and cleanup['owned_events'] == 6 and cleanup['remaining_owned_events'] == 0
    assert stats['kernel_hist']['online_cpu_identity']['status'] == 'STABLE'
    tids = {row['tid'] for row in cpu + sleep}
    observed = [thread for sample in processes for group in sample['cgroups']
                for process in group['processes'] for thread in process.get('tid_samples', [])]
    assert tids <= {thread['identity']['tid'] for thread in observed}
    assert all(thread['identity']['boot_id'] == meta['boot_id'] for thread in observed)
    assert stats['thread_sampling_status'] == 'PARTIAL_POLLED'
    if report['selected_getpid_completed_truth'] is not None:
        truth = sum(row['getpid_completed'] for row in cpu)
        assert truth == report['selected_getpid_completed_truth'] == 400000
        assert root['m'][metrics['syscall_other']][0] == leaf_cpu['m'][metrics['syscall_other']][0] == truth
        assert leaf_sleep['m'][metrics['syscall_other']][0] == 0
    for name, expected in report['positive_controls'].items():
        assert leaf_cpu['m'][metrics[name]][:2] == expected and expected[0] > 0
    assert report['status'] == 'PASS' and report['diagnostic_health'] == 'COMPLETE_WITHIN_DECLARED_HOOKS'
    result = {key: report[key] for key in ('status', 'diagnostic_health', 'domain_count', 'workload_cpu', 'positive_controls',
            'selected_getpid_completed_truth', 'worker_minor_fault_truth', 'thread_polling_lifecycle')}
    result.update({
        'directory': directory.name, 'independent_raw_replay': 'PASS',
        'measurement_recursion_misses': 0, 'registration_only_recursion_misses_retained': ignored_noop,
        'kernel_probe_misses': 0, 'tracefs_cleanup': 'COMPLETE'})
    return result


def replay_block(directory):
    report = read_json(directory / 'validation.json')
    meta = read_json(directory / 'load/load-meta.json')
    stats = read_json(directory / 'load/load-sampler-stats.json')
    workload = read_jsonl(directory / 'workload.jsonl')
    diag = stats['kernel_hist']['block_diagnostics']
    assert report['status'] == 'PASS_WITH_BLOCK_BOUNDARIES_EXPLICIT'
    assert report['boot_id'] == meta['boot_id']
    assert report['object_sha256'] == meta['kernel_hist']['object_sha256']
    assert report['block_diagnostics'] == diag
    assert meta['kernel_hist']['abi_version'] == 2
    assert diag['version'] == 1 and diag['scope'] == 'SYSTEM_UNATTRIBUTED'
    assert diag['counters']['request_read_failed'] == 0
    flush = diag['flush_service']
    assert sum(flush['buckets']) == flush['count'] > 0
    assert flush['sum_ns'] > 0 and diag['counters']['flush_completed'] >= flush['count']
    assert len(workload) == 1 and workload[0]['write_bytes'] == 262144
    assert workload[0]['write_calls'] == workload[0]['fdatasync_calls'] == 8
    assert report['workload_window_ns'][0] <= workload[0]['start_ns'] <= workload[0]['end_ns'] <= report['workload_window_ns'][1]
    expected = b''.join(bytes([i]) * 32768 for i in range(8))
    assert digest(directory / 'owned-fdatasync-data') == hashlib.sha256(expected).hexdigest() == report['fixture_content_sha256']
    programs = stats['kernel_hist']['programs']
    assert len(programs) == stats['kernel_hist']['program_info_expected_count'] == 4
    assert all(row['role'] == 'MEASUREMENT' and row['recursion_misses'] == 0 for row in programs)
    assert stats['kernel_hist']['program_info_read_errors'] == 0
    samples = diag['samples']
    assert all(row['object_fields_status'] == 'RESOLVED_REQUEST_FIELDS' for row in samples)
    assert all(row['cmd_flags'] & 0xff == 2 and row['nr_bytes'] == 0
               for row in samples if row['reason'] == 'ZERO_BYTE_FLUSH_COMPLETED')
    return {'path':str(directory),'status':report['status'],'flush_service_count':flush['count'],
            'flush_completed':diag['counters']['flush_completed'],
            'queue_span_unknown':diag['counters']['queue_span_unknown'],
            'untracked_complete_unknown':diag['counters']['untracked_complete'],
            'bounded_samples_truncated':diag['samples_truncated'],'measurement_recursion_misses':0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--frozen-version', default='p1-v7-frozen', help='one preserved child directory inside --evidence')
    parser.add_argument('--source-binding', choices=('workspace', 'frozen'), default='workspace',
                        help='workspace requires exact current-source match; frozen hashes preserved source only, for historic replay')
    parser.add_argument('--expected-cells', type=int, default=4)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('receipt output already exists; preserve raw evidence and choose a new path')
    if Path(args.frozen_version).name != args.frozen_version or args.expected_cells < 1:
        parser.error('frozen version must be a single directory name, expected cells positive')
    final = args.evidence / args.frozen_version
    expected_sources = {'main.rs': 'crates/load-sampler/src/main.rs', 'khist.rs': 'crates/load-sampler/src/khist.rs',
        'lib.rs': 'crates/load-sampler/src/lib.rs', 'kernel_hist.h': 'bpf/kernel_hist.h',
        'kernel_hist.bpf.c': 'bpf/kernel_hist.bpf.c', 'pthread_calibration.c': 'crates/load-sampler/tests/pthread_calibration.c',
        'guest_multidomain.py': 'crates/load-sampler/tests/guest_multidomain.py'}
    source_hashes = {}
    for copied, original in {'guest_block.py':'crates/load-sampler/tests/guest_block.py',
                             'block_completion.rs':'crates/load-sampler/tests/block_completion.rs'}.items():
        if (final / copied).exists():
            expected_sources[copied] = original
    for copied, original in expected_sources.items():
        actual = digest(final / copied)
        if args.source_binding == 'workspace':
            assert actual == digest(args.project / original), original
        source_hashes[original] = actual
    artifacts = {name: digest(final / name) for name in ('allox-load-sampler', 'kernel_hist.bpf.o', 'pthread-khist-calibration')}
    results = [(replay_block if read_json(path).get('status') == 'PASS_WITH_BLOCK_BOUNDARIES_EXPLICIT' else replay_final)(path.parent)
               for path in sorted(final.glob('*/validation.json'))]
    assert len(results) == args.expected_cells
    raw_files = [path for path in sorted(args.evidence.rglob('*')) if path.is_file() and path != args.output]
    assert len(raw_files) <= 4096 and all(not path.is_symlink() for path in raw_files)
    raw_digests = {str(path.relative_to(args.evidence)): digest(path) for path in raw_files}
    previous = [{**{key: read_json(path).get(key) for key in ('status', 'diagnostic_health', 'diagnostic_issues')},
                 'path': str(path.relative_to(args.evidence))}
                for path in sorted(args.evidence.glob('p1-v*/**/validation.json')) if final not in path.parents]
    receipt = {'schema_version': 1, 'status': 'PASS_WITH_EXPLICIT_SCOPE', 'source_hashes': source_hashes,
        'frozen_version':args.frozen_version,'source_binding':args.source_binding,
        'final_artifact_hashes': artifacts, 'final_cells': results, 'old_profiles_preserved': previous,
        'raw_file_hashes': raw_digests, 'raw_file_count': len(raw_files),
        'receipt_collector_sha256': digest(Path(__file__)),
        'limits': ['cooperative kernel profiling fixtures, not whole-kernel causal attribution',
            'thread sampling remains PARTIAL, not full thread lifecycle',
            'block partial/requeue/error paths have actual-source native replay, not forced hardware E2E',
            'optional v8 zero-byte FLUSH control is system-scoped; unknown queue/untracked requests remain unknown',
            'non-major handle_mm_fault completed returns include retry/errors and are not identical to rusage faults',
            'registration-only syscall callback misses retained separately from known-count kprobe measurements',
            'kprobe/kretprobe and detailed TID diagnostics are opt-in overhead, not lightweight sampler SLA']}
    args.output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'final_cells': len(results), 'raw_files': len(raw_files),
                      'receipt': str(args.output), 'receipt_sha256': digest(args.output)}))


if __name__ == '__main__':
    main()
