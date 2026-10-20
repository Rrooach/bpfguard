#!/usr/bin/env python3
"""Offline, identity-bound thread counter intervals for benchmark load samples.

Never enables schedstats or reads live /proc. Polling, including a clean polling
run, cannot establish complete thread lifecycle or exact per-request cost.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


IDENTITY = ('boot_id', 'pid', 'process_start_ticks', 'tid', 'thread_start_ticks')
COUNTERS = ('run_ns', 'wait_ns', 'timeslices', 'utime', 'stime')


def integer(value, positive=False):
    return type(value) is int and value >= int(positive)


def cgroup_key(row):
    if (not isinstance(row, dict) or not isinstance(row.get('path'), str) or not row['path'].startswith('/')
            or not integer(row.get('inode'), True) or not integer(row.get('device'))):
        return None
    return row['path'], row['inode'], row['device']


def analyze(meta, stats, rows, expectation=None, window=None):
    issues = []

    def issue(code, location, detail):
        issues.append({'code': code, 'location': location, 'detail': detail})

    boot = meta.get('boot_id')
    label = meta.get('label')
    thread_config = meta.get('thread_sampling') if isinstance(meta.get('thread_sampling'), dict) else {}
    schedstats_at_start = thread_config.get('schedstats_runtime_enabled_at_start') is True
    if not isinstance(boot, str) or not boot or not isinstance(label, str) or not label:
        issue('MISSING_BOOT_OR_RUN_IDENTITY', 'load-meta.json', 'nonempty boot_id and label/run_id required')
    if thread_config.get('enabled') is not True:
        issue('THREAD_SAMPLING_NOT_ENABLED', 'load-meta.json', 'no thread wait coverage is inferred')
    if not schedstats_at_start:
        issue('SCHEDSTATS_NOT_ENABLED_AT_READY', 'load-meta.json', 'runtime-enabled=true must be recorded before the task')
    raw_groups = meta.get('cgroups')
    groups = raw_groups if isinstance(raw_groups, list) else []
    identities = [cgroup_key(group) for group in groups]
    registry_valid = bool(identities) and not any(key is None for key in identities) and len(set(identities)) == len(identities)
    if not registry_valid:
        issue('INVALID_CGROUP_REGISTRY', 'load-meta.json', 'unique path/inode/device identities required')
    anchor_valid = (registry_valid and bool(boot) and isinstance(boot, str) and bool(label)
                    and isinstance(label, str) and thread_config.get('enabled') is True)
    if expectation is not None:
        for key in ('label', 'boot_id'):
            if key not in expectation or expectation[key] != meta.get(key):
                anchor_valid = False
                issue('EXTERNAL_IDENTITY_MISMATCH', 'expectation/' + key, 'saved metadata differs from supplied identity anchor')
        expected_groups = expectation.get('cgroups')
        expected_identities = [cgroup_key(group) for group in expected_groups] if isinstance(expected_groups, list) else []
        if not expected_identities or any(key is None for key in expected_identities) or expected_identities != identities:
            anchor_valid = False
            issue('EXTERNAL_IDENTITY_MISMATCH', 'expectation/cgroups', 'path/inode/device must match; ancillary sampler availability fields are not identity')
    if window is not None and (not isinstance(window, (list, tuple)) or len(window) != 2
            or not all(integer(value) for value in window) or window[1] <= window[0]):
        raise ValueError('execution window requires two increasing nonnegative monotonic timestamps')
    if not isinstance(rows, list):
        raise ValueError('process samples must be a list')
    if stats.get('process_samples') != len(rows) or type(stats.get('process_samples')) is not int:
        issue('PROCESS_SAMPLE_COUNT_MISMATCH', 'load-sampler-stats.json', 'final count differs from raw rows')
    if not rows:
        issue('NO_PROCESS_SAMPLES', 'load-processes.jsonl', 'no endpoint observations')
    for key in ('read_errors', 'vanished_processes', 'truncated_process_sets', 'truncated_cgroup_traversals',
                'cgroup_traversal_read_errors', 'thread_read_errors', 'vanished_threads_during_read',
                'truncated_thread_samples', 'thread_identity_changes', 'missed_ticks'):
        value = stats.get(key)
        if not integer(value):
            issue('MISSING_HEALTH_COUNTER', 'stats/' + key, 'missing is unknown, not zero')
        elif value:
            issue('SAMPLER_REPORTED_GAP', 'stats/' + key, value)
    instances = {}
    previous_row_end = None
    previous_source_seq = None
    valid_row_indices = set()
    for index, row in enumerate(rows):
        location = 'process-sample:' + str(index)
        if not isinstance(row, dict):
            issue('INVALID_PROCESS_SAMPLE', location, 'expected object')
            continue
        begin, end = row.get('monotonic_ns'), row.get('collection_end_ns')
        source_seq = row.get('seq')
        valid_clock = (integer(source_seq) and (previous_source_seq is None or source_seq > previous_source_seq)
                       and integer(begin) and integer(end) and end >= begin
                       and (previous_row_end is None or begin >= previous_row_end))
        if not valid_clock:
            issue('INVALID_PROCESS_SAMPLE_TIME_OR_SEQUENCE', location, 'ordered nonoverlapping source windows and increasing system-sample sequence required; process cadence may skip system indices')
        else:
            previous_row_end = end
            previous_source_seq = source_seq
            valid_row_indices.add(index)
        enabled = schedstats_at_start and row.get('schedstats_runtime_enabled') is True
        if not enabled:
            issue('SCHEDSTATS_DISABLED_OR_UNKNOWN', location, 'wait deltas are unknown, including zero-valued counters')
        selected_groups = row.get('cgroups')
        if not isinstance(selected_groups, list) or len(selected_groups) != len(groups):
            issue('CGROUP_SAMPLE_COUNT_MISMATCH', location, 'domain indices cannot be safely associated')
            continue
        for group_index, group in enumerate(selected_groups):
            scope = location + '/cgroup:' + str(group_index)
            if not isinstance(group, dict) or group.get('present') is not True:
                issue('CGROUP_SAMPLE_UNAVAILABLE', scope, 'target absent or malformed')
                continue
            if group.get('thread_sampling') != 'PARTIAL_POLLED_NOT_FULL_LIFECYCLE':
                issue('UNKNOWN_THREAD_SAMPLING_SCOPE', scope, 'polling coverage descriptor missing')
            for key in ('truncated_cgroup_dirs', 'truncated_process_set'):
                if group.get(key) is not False:
                    issue('CGROUP_TRAVERSAL_INCOMPLETE', scope + '/' + key, group.get(key))
            if group.get('traversal_errors') != []:
                issue('CGROUP_TRAVERSAL_ERRORS', scope, group.get('traversal_errors'))
            processes = group.get('processes')
            if not isinstance(processes, list):
                issue('MISSING_PROCESS_SET', scope, 'not an empty observed set')
                continue
            seen = set()
            for process in processes:
                if not isinstance(process, dict):
                    issue('INVALID_PROCESS_IDENTITY', scope, 'expected process object')
                    continue
                if process.get('tid_sampling_issues') != []:
                    issue('THREAD_SCAN_ISSUES', scope + '/pid:' + str(process.get('pid')), process.get('tid_sampling_issues'))
                threads = process.get('tid_samples')
                if not isinstance(threads, list):
                    issue('MISSING_THREAD_SET', scope, 'thread samples required when enabled')
                    continue
                for thread in threads:
                    identity = thread.get('identity') if isinstance(thread, dict) else None
                    if (not isinstance(identity, dict) or identity.get('boot_id') != boot
                            or any(not integer(identity.get(key), key in ('pid', 'tid')) for key in IDENTITY[1:])
                            or process.get('boot_id') != boot or identity.get('pid') != process.get('pid')
                            or identity.get('process_start_ticks') != process.get('start_ticks')):
                        issue('THREAD_IDENTITY_MISMATCH', scope, identity)
                        continue
                    key = tuple(identity[name] for name in IDENTITY)
                    if key in seen:
                        issue('DUPLICATE_THREAD_IN_DOMAIN', scope, list(key))
                        continue
                    seen.add(key)
                    thread_begin, thread_end = thread.get('collection_start_ns'), thread.get('collection_end_ns')
                    valid_thread_clock = (valid_clock and integer(thread_begin) and integer(thread_end)
                                          and begin <= thread_begin <= thread_end <= end)
                    if not valid_thread_clock:
                        issue('INVALID_THREAD_COLLECTION_WINDOW', scope, identity)
                    if thread.get('lifecycle_status') != 'POLLED_INSTANCE_NOT_FULL_LIFECYCLE':
                        issue('UNKNOWN_THREAD_LIFECYCLE_SCOPE', scope, identity)
                    if thread.get('wait_counter_status') != 'ENABLED':
                        issue('THREAD_WAIT_COUNTER_DISABLED_OR_UNKNOWN', scope, identity)
                    item = instances.setdefault((group_index, key), {'identity': identity,
                        'domain_index': group_index, 'cgroup': groups[group_index], 'comm': thread.get('comm'),
                        'observations': [], 'intervals': []})
                    item['observations'].append({'sample_index': index, 'source_seq': source_seq,
                        'collection': [thread_begin, thread_end], 'clock_valid': valid_thread_clock,
                        'wait_enabled': enabled and thread.get('wait_counter_status') == 'ENABLED',
                        'counters': {name: thread.get(name) for name in COUNTERS}})
    observed_intervals = wait_intervals = 0
    for item in instances.values():
        for first, last in zip(item['observations'], item['observations'][1:]):
            location = 'domain:{}/pid:{}/tid:{}/{}-{}'.format(item['domain_index'], item['identity']['pid'],
                item['identity']['tid'], first['sample_index'], last['sample_index'])
            contiguous = (last['sample_index'] == first['sample_index'] + 1
                          and first['sample_index'] in valid_row_indices and last['sample_index'] in valid_row_indices)
            clock_valid = (first['clock_valid'] and last['clock_valid']
                           and first['collection'][1] <= last['collection'][0])
            record = {'first_collection': first['collection'], 'last_collection': last['collection'],
                'first_sample': first['sample_index'], 'last_sample': last['sample_index'],
                'first_source_seq': first['source_seq'], 'last_source_seq': last['source_seq'],
                'status': 'OBSERVED_COUNTER_INTERVAL_NOT_EXCLUSIVE_REQUEST_COST', 'deltas': {},
                'elapsed_min_ns': None, 'elapsed_max_ns': None, 'execution_window_relation': 'NOT_BOUND_TO_TASK_WINDOW'}
            if not contiguous:
                issue('THREAD_NOT_OBSERVED_BETWEEN_ENDPOINTS', location, 'do not interpolate across missing source observations')
            if clock_valid:
                record['elapsed_min_ns'] = last['collection'][0] - first['collection'][1]
                record['elapsed_max_ns'] = last['collection'][1] - first['collection'][0]
                if window is not None:
                    record['execution_window_relation'] = ('FULLY_INSIDE_EXECUTION_WINDOW' if
                        first['collection'][0] >= window[0] and last['collection'][1] <= window[1]
                        else 'CROSSES_OR_OUTSIDE_EXECUTION_WINDOW_NOT_CLIPPED')
            for counter in COUNTERS:
                left, right = first['counters'][counter], last['counters'][counter]
                valid = contiguous and clock_valid and anchor_valid and integer(left) and integer(right) and right >= left
                if counter in ('wait_ns', 'timeslices'):
                    valid = valid and first['wait_enabled'] and last['wait_enabled']
                record['deltas'][counter] = right - left if valid else None
                if not integer(left) or not integer(right):
                    issue('MISSING_THREAD_COUNTER', location + '/' + counter, 'missing is unknown, not zero')
                elif right < left:
                    issue('THREAD_COUNTER_REGRESSION', location + '/' + counter, [left, right])
            if record['deltas']['run_ns'] is None or record['deltas']['wait_ns'] is None:
                record['status'] = 'INCOMPLETE_COUNTER_INTERVAL'
            else:
                observed_intervals += 1
                if record['execution_window_relation'] == 'FULLY_INSIDE_EXECUTION_WINDOW':
                    wait_intervals += 1
            item['intervals'].append(record)
        if not item['intervals']:
            issue('NO_TWO_ENDPOINT_THREAD_INTERVAL', 'thread/' + str(item['identity']), 'one observation cannot prove zero run or wait')
        item['observed_sample_count'] = len(item['observations'])
    if not instances:
        issue('NO_THREAD_INSTANCES_OBSERVED', 'load-processes.jsonl', 'short threads may run entirely between polls')
    return {'schema_version': 1, 'run_id': label, 'boot_id': boot,
        'status': 'PARTIAL_POLLING_WITH_GAPS' if issues else 'OBSERVED_PARTIAL_POLLING',
        'counter_status': 'OBSERVED_INTERVALS_WITH_LIMITATIONS' if observed_intervals else 'INCONCLUSIVE',
        'schedstats_enabled_at_ready': schedstats_at_start,
        'external_anchor_status': ('MATCHED_SAVED_METADATA' if anchor_valid else 'MISMATCH') if expectation is not None else 'NOT_PROVIDED',
        'execution_window': window, 'instance_count': len(instances),
        'observed_run_wait_interval_count': observed_intervals,
        'observed_run_wait_interval_fully_inside_execution_count': wait_intervals,
        'instances': list(instances.values()), 'issues': issues,
        'limitations': ['Polling does not cover complete thread lifecycle; no claim that all short-lived threads were observed.',
            'Counter points lie within non-atomic collection windows; use both endpoints, never nominal sampling periods.',
            'Thread run/wait intervals are not exclusive request cost, and waits cannot be added to wall time.',
            'Parent/child cgroup domains overlap; the same thread may appear in multiple domains, never sum across them.',
            'Disappearance may mean exit, scope change or sampling gap; it is not proof of a process leak.',
            'No interpolation, negative deltas, missing-as-zero, or clipping counters to execution boundaries.']}


def load_report(directory, expectation=None, window=None):
    directory = Path(directory)
    sources = {}
    for name in ('load-meta.json', 'load-sampler-stats.json', 'load-processes.jsonl'):
        path = directory / name
        if path.stat().st_size > 512 * 1024 * 1024:
            raise ValueError('thread artifact exceeds 512 MiB offline read budget')
        raw = path.read_bytes()
        sources[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        if name.endswith('.jsonl'):
            rows = [json.loads(line) for line in raw.splitlines()]
        elif name == 'load-meta.json':
            meta = json.loads(raw)
        else:
            stats = json.loads(raw)
    report = analyze(meta, stats, rows, expectation, window)
    report['sources'] = sources
    report['analyzer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--load-dir', type=Path, required=True)
    parser.add_argument('--expectation', type=Path, help='JSON {label,boot_id,cgroups}, supplied independently of sampler metadata')
    parser.add_argument('--execution-start-ns', type=int)
    parser.add_argument('--execution-end-ns', type=int)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (args.execution_start_ns is None) != (args.execution_end_ns is None):
        parser.error('both execution boundary timestamps are required together')
    expected = json.loads(args.expectation.read_text()) if args.expectation else None
    window = [args.execution_start_ns, args.execution_end_ns] if args.execution_start_ns is not None else None
    report = load_report(args.load_dir, expected, window)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({key: report[key] for key in ('status', 'counter_status', 'instance_count',
        'observed_run_wait_interval_count', 'observed_run_wait_interval_fully_inside_execution_count')}, sort_keys=True))


if __name__ == '__main__':
    main()
