#!/usr/bin/env python3
"""Offline Guest-wide virtual-disk/steal counters around one completed search.

No Guest APIs, workload execution, cache probing or gzip evidence reads. These
are global Guest clues, not exclusive Agent costs or physical SSD service time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


MAX_BYTES = 128 * 1024 * 1024
MAX_CAMPAIGNS = 4096
MAX_CASES = 4096
DISK_COUNTERS = {
    'read_completed': (0, 'operations'),
    'sectors_read': (2, '512_byte_sectors'),
    'read_ms': (3, 'milliseconds_cumulative_requests_may_overlap'),
    'io_busy_ms': (9, 'milliseconds_guest_virtual_device_io_accounting'),
    'weighted_ms': (10, 'milliseconds_weighted_guest_virtual_io_accounting'),
}


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def read_evidence(root, relative, sources, lines=False):
    path = root / relative
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError('bounded regular non-symlink evidence required: ' + relative)
    raw = path.read_bytes()
    sources[relative] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    if lines:
        return [json.loads(line) for line in raw.splitlines()]
    return json.loads(raw)


def identity(value):
    if not isinstance(value, dict):
        raise ValueError('CGROUP_IDENTITY_MISSING')
    path = value.get('path')
    if (not isinstance(path, str) or not path.startswith('/sys/fs/cgroup/')
            or str(PurePosixPath(path)) != path or '..' in PurePosixPath(path).parts
            or not all(integer(value.get(key), 1) for key in ('inode', 'device'))):
        raise ValueError('CGROUP_IDENTITY_INVALID')
    return {key: value[key] for key in ('path', 'inode', 'device')}


def delta(values, unit):
    if not values or any(not integer(value) for value in values):
        return {'status': 'UNKNOWN', 'delta': None, 'unit': unit, 'reason': 'MISSING_OR_INVALID_COUNTER'}
    if any(right < left for left, right in zip(values, values[1:])):
        return {'status': 'UNKNOWN', 'delta': None, 'unit': unit, 'reason': 'COUNTER_RESET_WITHIN_BRACKET'}
    return {'status': 'OBSERVED', 'delta': values[-1] - values[0], 'unit': unit}


def indexed(row, section, name, index):
    mapping = row.get(section)
    values = mapping.get(name) if isinstance(mapping, dict) else None
    return values[index] if isinstance(values, list) and len(values) > index else None


def summarize_trial(directory, device):
    """Return raw global deltas; unknown/missing counters never become zero."""
    if not isinstance(device, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', device):
        raise ValueError('explicit diskstats device name required, for example vda, not /dev/vda')
    root = Path(directory).resolve(strict=True)
    sources = {}
    report = {'schema_version': 1, 'tool': 'search-background-io', 'status': 'INCOMPLETE',
        'trial': str(root), 'device': device,
        'scope': 'GLOBAL_GUEST_VIRTUAL_DEVICE_NOT_AGENT_EXCLUSIVE_NOT_PHYSICAL_SSD_SERVICE',
        'diskstats_counters': {key: delta([], unit) for key, (_, unit) in DISK_COUNTERS.items()},
        'steal_ticks': delta([], 'USER_HZ_ticks_aggregated_across_guest_cpus'),
        'issues': [], 'sources': sources,
        'limits': ['Only nearest complete before/after samples enclose execution; source reads are not atomic and are not interpolated.',
            'Diskstats includes all Guest actors on this virtual device; it is not exclusive Agent I/O or physical-server SSD I/O.',
            'Cumulative request read_ms can overlap. Dividing by operations is not precise physical SSD service latency.',
            'io_busy_ms and weighted_ms are Guest virtual-device accounting, not proof of bandwidth saturation.',
            'in_flight is a gauge and is deliberately not differenced. No I/O/CPU/PSI quantities are added into wall time.',
            'Steal ticks are Guest-wide scheduler accounting, not per-Agent waiting or a complete Host scheduling diagnosis.',
            'No cache proof, Observer WAL, safety verification, bottleneck conclusion or causal attribution is performed.']}
    try:
        profile = read_evidence(root, 'profile-run.json', sources)
        meta = read_evidence(root, 'load/load-meta.json', sources)
        stats = read_evidence(root, 'load/load-sampler-stats.json', sources)
        rows = read_evidence(root, 'load/load-samples.jsonl', sources, lines=True)
        if (not isinstance(profile, dict) or profile.get('status') != 'COMPLETE' or profile.get('cleanup_errors') != []
                or not isinstance(profile.get('run_id'), str) or not profile['run_id']
                or not isinstance(profile.get('boot_id'), str) or not profile['boot_id']
                or not all(integer(profile.get(key)) for key in ('release_ns', 'end_ns', 'makespan_ns'))
                or profile['end_ns'] <= profile['release_ns']
                or profile['makespan_ns'] != profile['end_ns'] - profile['release_ns']):
            raise ValueError('COMPLETED_PROFILE_OR_EXACT_WINDOW_MISSING')
        expected = identity(profile.get('root_cgroup'))
        groups = meta.get('cgroups') if isinstance(meta, dict) else None
        if (not isinstance(groups, list) or meta.get('boot_id') != profile['boot_id'] or meta.get('label') != profile['run_id']
                or sum(identity(value) == expected for value in groups) != 1
                or PurePosixPath(expected['path']).name != profile['run_id']):
            raise ValueError('PROFILE_SAMPLER_BOOT_RUN_CGROUP_BINDING_MISMATCH')
        if not isinstance(rows, list) or not rows:
            raise ValueError('NO_SAMPLER_ROWS')
        if any(not isinstance(row, dict) or not integer(row.get('monotonic_ns'))
                or not integer(row.get('collection_end_ns')) or row['collection_end_ns'] < row['monotonic_ns']
                or not integer(row.get('seq')) or row['seq'] != index for index, row in enumerate(rows)):
            raise ValueError('SAMPLER_SEQUENCE_OR_COLLECTION_TIMESTAMPS_INVALID')
        if any(right['monotonic_ns'] <= left['monotonic_ns']
                or left['collection_end_ns'] > right['monotonic_ns'] for left, right in zip(rows, rows[1:])):
            raise ValueError('SAMPLER_TIMELINE_NONMONOTONIC_OR_COLLECTIONS_OVERLAP')
        before = [index for index, row in enumerate(rows) if row['collection_end_ns'] <= profile['release_ns']]
        after = [index for index, row in enumerate(rows) if row['monotonic_ns'] >= profile['end_ns']]
        if not before or not after:
            raise ValueError('COMPLETE_EXECUTION_BRACKET_MISSING')
        first, last = before[-1], after[0]
        selected = rows[first:last + 1]
        if len(selected) < 2:
            raise ValueError('EXECUTION_BRACKET_HAS_FEWER_THAN_TWO_SAMPLES')
        report.update(run_id=profile['run_id'], boot_id=profile['boot_id'], root_cgroup=expected,
            release_ns=profile['release_ns'], end_ns=profile['end_ns'], makespan_ns=profile['makespan_ns'],
            clk_tck=meta.get('clk_tck'), bracket={'first_seq': first, 'last_seq': last,
                'samples': len(selected), 'all_samples': len(rows),
                'before_monotonic_ns': rows[first]['monotonic_ns'], 'before_collection_end_ns': rows[first]['collection_end_ns'],
                'after_monotonic_ns': rows[last]['monotonic_ns'], 'after_collection_end_ns': rows[last]['collection_end_ns'],
                'before_uncertainty_ns': profile['release_ns'] - rows[first]['monotonic_ns'],
                'after_uncertainty_ns': rows[last]['monotonic_ns'] - profile['end_ns']})
        for name in ('read_errors', 'missed_ticks', 'truncated_process_sets', 'truncated_cgroup_traversals', 'cgroup_traversal_read_errors'):
            if not isinstance(stats, dict) or type(stats.get(name)) is not int or stats[name] != 0:
                report['issues'].append('SAMPLER_HEALTH:' + name)
        if not isinstance(stats, dict) or stats.get('samples') != len(rows):
            report['issues'].append('SAMPLER_FINAL_SAMPLE_COUNT_MISMATCH')
        if any(row.get('errors') for row in selected):
            report['issues'].append('COLLECTION_ERRORS_WITHIN_BRACKET')
        root_index = next(index for index, value in enumerate(groups) if identity(value) == expected)
        if any(not isinstance(row.get('cgroups'), list) or len(row['cgroups']) <= root_index
                or not isinstance(row['cgroups'][root_index], dict)
                or row['cgroups'][root_index].get('present') is not True for row in selected):
            report['issues'].append('REGISTERED_CGROUP_NOT_PRESENT_WITHIN_BRACKET')
        if not integer(meta.get('clk_tck'), 1):
            report['issues'].append('CLK_TCK_UNAVAILABLE')
        if not isinstance(meta.get('block_devices'), list) or device not in meta['block_devices']:
            report['issues'].append('DEVICE_NOT_ENROLLED_AT_SAMPLER_START')
        report['diskstats_counters'] = {name: delta([indexed(row, 'diskstats', device, index) for row in selected], unit)
            for name, (index, unit) in DISK_COUNTERS.items()}
        report['steal_ticks'] = delta([indexed(row, 'stat', 'cpu_total', 7) for row in selected],
            'USER_HZ_ticks_aggregated_across_guest_cpus')
        if all(value['status'] == 'OBSERVED' for value in list(report['diskstats_counters'].values()) + [report['steal_ticks']]) and not report['issues']:
            report['status'] = 'OBSERVED_GLOBAL_COUNTER_DELTAS_WITHIN_BRACKET'
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        report['issues'].append(type(error).__name__ + ':' + str(error))
    report['analyzer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return report


def safe_child(root, relative):
    """Canonical relative directories only; no symlink aliases or escapes."""
    if not isinstance(relative, str) or not relative:
        raise ValueError('safe relative evidence directory required')
    path = PurePosixPath(relative)
    if (path.is_absolute() or str(path) != relative or not path.parts
            or any(part in ('.', '..') for part in path.parts)):
        raise ValueError('unsafe or noncanonical relative evidence path')
    target = root
    for part in path.parts:
        target = target / part
        if target.is_symlink():
            raise ValueError('symlink evidence directory is not accepted')
    resolved = target.resolve(strict=True)
    resolved.relative_to(root)
    if not resolved.is_dir():
        raise ValueError('evidence directory required')
    return resolved


def same_json(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def summarize_matrix(path, device):
    """Batch only COMPLETE declared campaigns; retain each counter's UNKNOWN."""
    if not isinstance(device, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', device):
        raise ValueError('explicit diskstats device name required')
    path = Path(path).absolute()
    if path.is_symlink():
        raise ValueError('matrix file must not be a symlink')
    root = path.parent.resolve(strict=True)
    sources = {}
    matrix = read_evidence(root, path.name, sources)
    entries = matrix.get('campaigns') if isinstance(matrix, dict) else None
    if (not isinstance(matrix, dict) or type(matrix.get('schema_version')) is not int or matrix['schema_version'] != 1
            or matrix.get('status') != 'COMPLETE' or not isinstance(entries, list) or not 1 <= len(entries) <= MAX_CAMPAIGNS
            or not isinstance(matrix.get('boot_id'), str) or not matrix['boot_id']):
        raise ValueError('COMPLETE schema 1 matrix with a boot identity and bounded nonempty campaign entries required')
    seen_campaigns, seen_trials, seen_indices, seen_runs = set(), set(), set(), set()
    cases, status_counts = [], {}
    for ordinal, entry in enumerate(entries):
        if (not isinstance(entry, dict) or not integer(entry.get('block'))
                or not isinstance(entry.get('condition'), dict) or not 1 <= len(entry['condition']) <= 64
                or entry.get('stage') not in ('performance', 'warmup', 'diagnostic')):
            raise ValueError('matrix campaign requires block, stage and bounded declared condition')
        directory = safe_child(root, entry.get('path'))
        if directory in seen_campaigns:
            raise ValueError('matrix must not reuse a campaign path')
        seen_campaigns.add(directory)
        original_index = entry.get('original_schedule_index', entry.get('original_index', ordinal))
        if (not integer(original_index) or original_index in seen_indices
                or 'original_index' in entry and (not integer(entry['original_index']) or entry['original_index'] != original_index)):
            raise ValueError('original matrix indices must be nonnegative and unique')
        seen_indices.add(original_index)
        condition = entry['condition']
        if 'block' in condition and (not integer(condition['block']) or condition['block'] != entry['block']):
            raise ValueError('matrix condition block differs from entry block')
        relative_campaign = str(directory.relative_to(root))
        campaign = read_evidence(root, relative_campaign + '/campaign.json', sources)
        trials = campaign.get('trials') if isinstance(campaign, dict) else None
        if (not isinstance(campaign, dict) or type(campaign.get('schema_version')) is not int or campaign['schema_version'] != 1
                or campaign.get('status') != 'COMPLETE' or not isinstance(trials, list) or not 1 <= len(trials) <= 128
                or len(cases) + len(trials) > MAX_CASES):
            raise ValueError('COMPLETE schema 1 campaign with bounded nonempty trials required')
        for trial_index, trial_entry in enumerate(trials):
            if not isinstance(trial_entry, dict):
                raise ValueError('campaign trial entry must be an object')
            trial = safe_child(directory, trial_entry.get('path'))
            if trial in seen_trials:
                raise ValueError('matrix must not reuse a trial path')
            seen_trials.add(trial)
            relative_trial = str(trial.relative_to(root))
            profile_key = relative_trial + '/profile-run.json'
            profile = read_evidence(root, profile_key, sources)
            if (not isinstance(profile, dict) or type(profile.get('schema_version')) is not int or profile['schema_version'] != 1
                    or profile.get('status') != 'COMPLETE' or profile.get('cleanup_errors') != []
                    or not isinstance(profile.get('run_id'), str) or not profile['run_id'] or profile['run_id'] in seen_runs
                    or profile['run_id'] != trial_entry.get('run_id') or profile.get('boot_id') != matrix['boot_id']
                    or not integer(trial_entry.get('makespan_ns'), 1)
                    or not integer(profile.get('makespan_ns'), 1)
                    or profile.get('makespan_ns') != trial_entry['makespan_ns']
                    or not isinstance(profile.get('config'), dict)):
                raise ValueError('campaign trial/profile execution identity or timing mismatch')
            seen_runs.add(profile['run_id'])
            config = profile['config']
            if (not isinstance(config.get('mode'), str) or not config['mode'] or not integer(config.get('concurrency'), 1)
                    or not integer(config.get('repetition')) or type(config.get('warmup')) is not bool):
                raise ValueError('raw trial condition field types are invalid')
            if any(key not in config or key not in trial_entry or not same_json(config[key], trial_entry[key])
                    for key in ('mode', 'concurrency', 'repetition', 'warmup')):
                raise ValueError('campaign trial condition differs from raw profile')
            if any(key not in config or not same_json(config[key], value) for key, value in condition.items() if key != 'block'):
                raise ValueError('matrix condition differs from raw profile')
            expected_warmup = {'performance': False, 'warmup': True}.get(entry['stage'])
            if expected_warmup is not None and config.get('warmup') is not expected_warmup:
                raise ValueError('matrix stage differs from raw warmup flag')
            background = summarize_trial(trial, device)
            if background['sources'].get('profile-run.json') != sources[profile_key]:
                raise ValueError('raw profile changed during offline matrix analysis')
            cases.append({'original_index': original_index,
                'original_index_source': ('original_schedule_index' if 'original_schedule_index' in entry else
                    'original_index' if 'original_index' in entry else 'matrix_entry_order'),
                'block': entry['block'], 'stage': entry['stage'], 'condition': condition,
                'campaign_path': relative_campaign, 'trial_path': relative_trial, 'trial_index': trial_index,
                'run_id': profile['run_id'], 'background': background})
            status_counts[background['status']] = status_counts.get(background['status'], 0) + 1
    return {'schema_version': 1, 'tool': 'search-background-io-matrix',
        'status': ('OBSERVED_GLOBAL_COUNTER_DELTAS_WITHIN_DECLARED_MATRIX' if all(
            case['background']['status'] == 'OBSERVED_GLOBAL_COUNTER_DELTAS_WITHIN_BRACKET' for case in cases) else 'INCOMPLETE'),
        'matrix': str(root / path.name), 'device': device, 'boot_id': matrix['boot_id'],
        'scope': 'GLOBAL_GUEST_VIRTUAL_DEVICE_NOT_AGENT_EXCLUSIVE_NOT_PHYSICAL_SSD_SERVICE',
        'case_count': len(cases), 'background_status_counts': status_counts, 'cases': cases, 'sources': sources,
        'limits': ['Only raw saved global counters are differenced. No gzip/cache proof, workload, live Guest read or wallclock_report invocation.',
            'Individual UNKNOWN counters and incomplete sampler health remain in each case; matrix completion does not turn them green.',
            'No IO-ms-per-operation estimate, physical SSD service latency, causal attribution or automatic bottleneck conclusion.'],
        'analyzer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--trial', type=Path, help='completed directory containing profile-run.json and load/')
    source.add_argument('--matrix', type=Path, help='COMPLETE schema 1 combined matrix with safe relative campaign paths')
    parser.add_argument('--device', required=True, help='explicit Guest diskstats name, such as vda')
    parser.add_argument('--output', type=Path, required=True, help='fresh JSON outside the input trial; never overwritten')
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error('output must be fresh, not an existing path or symlink')
    root = args.matrix.parent.resolve(strict=True) if args.matrix else args.trial.resolve(strict=True)
    output = args.output.resolve()
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        parser.error('output must remain outside the raw input trial/matrix tree')
    report = summarize_matrix(args.matrix, args.device) if args.matrix else summarize_trial(root, args.device)
    with output.open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'status': report['status'], 'output': str(output)}))


if __name__ == '__main__':
    main()
