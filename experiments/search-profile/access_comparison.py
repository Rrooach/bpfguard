#!/usr/bin/env python3
"""Read-only, separate 2/4/6/8 wall time and selected file-access diagnostics.

Never pool the sampler and full-event modes. Probe overhead is a same-block
paired comparison, not the difference between unrelated old/new campaigns.
"""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import statistics

import wallclock_report as wall


_ARTIFACT_SPEC = importlib.util.spec_from_file_location('comparison_access_artifacts',
    Path(__file__).resolve().parent.parent / 'file-profile' / 'access_artifacts.py')
ARTIFACTS = importlib.util.module_from_spec(_ARTIFACT_SPEC)
_ARTIFACT_SPEC.loader.exec_module(ARTIFACTS)


def numeric(value):
    return type(value) in (int, float) and math.isfinite(value)


def metrics_summary(rows, getter):
    values = [getter(row) for row in rows]
    valid = [value for value in values if numeric(value)]
    result = wall.independent_mean_summary(valid, 'INDEPENDENT_RANDOMIZED_BLOCK')
    result['unknown_n'] = len(values) - len(valid)
    return result


def flatten_metrics(value, prefix=''):
    """Keep numeric observations/unknowns, not semantic strings as numbers."""
    result = {}
    for key, child in value.items():
        name = prefix + '.' + key if prefix else key
        if isinstance(child, dict):
            result.update(flatten_metrics(child, name))
        elif numeric(child) or child is None:
            result[name] = child
    return result


def signature(trial):
    return [(r['task_id'], r['query_index'], r['exit_code'], r['output_sha256'], r['output_bytes'])
            for r in trial['output_signature']]


def fixed_scope(config):
    return {key: config.get(key) for key in ('jobs', 'passes', 'corpus_sha256', 'permission_scope_sha256',
        'queries_sha256', 'repository_version', 'cpus', 'memory_max_mb', 'memory_high_mb',
        'cgroup_layout', 'interval_ms', 'process_interval_ms', 'timing_scope', 'cpu_time_scope',
        'file_access_backend', 'collector_ring_bytes')}


def collector_boundaries(capture, trial):
    """Actual saved boundaries, not an estimate from nominal collector timers."""
    result = {'status': 'UNKNOWN', 'startup_seconds': None,
        'post_exit_finalization_seconds': None, 'execution_to_raw_evidence_ready_seconds': None,
        'persisted_events': None, 'artifact_bytes': None,
        'ring_bytes': trial['config'].get('collector_ring_bytes'),
        'hash_scope': 'UNDECLARED_BY_COLLECTOR', 'issues': [],
        'scope': 'PRE_RELEASE_COLLECTOR_STARTUP_SEPARATE; END_TO_FINALIZED_INCLUDES_INNER_RUNNER_POST_EXIT_WORK_AND_COLLECTOR_DRAIN_FSYNC_HASH; OFFLINE_SQLITE_CSV_EXCLUDED'}
    if trial['config'].get('file_access_mode') == 'sampler':
        result['status'] = 'NOT_ENABLED'
        return result
    if not isinstance(capture, dict):
        result['issues'].append('CAPTURE_MISSING_OR_INVALID')
        return result
    if (capture.get('profile_run_id') != trial['run_id']
            or capture.get('profile_run_sha256') != wall.get(trial, 'sources', 'profile-run.json', 'sha256')
            or capture.get('boot_id') != trial['boot_id']):
        result['issues'].append('CAPTURE_PROFILE_BOOT_OR_SHA256_DIFFERS')
        return result
    result['hash_scope'] = capture.get('hash_scope', 'UNDECLARED_BY_COLLECTOR')
    started, ready, finalized = [capture.get(field) for field in
        ('started_monotonic_ns', 'ready_received_monotonic_ns', 'finalized_monotonic_ns')]
    release, end, duration = [capture.get(field) for field in ('release_ns', 'end_ns', 'makespan_ns')]
    if (not all(wall.integer(value, 1) for value in (release, end, duration))
            or end <= release or end - release != duration
            or duration / 1e9 != wall.get(trial, 'primary', 'seconds')
            or [release, end] != trial.get('execution_window')):
        result['issues'].append('CAPTURE_WINDOW_DIFFERS')
        return result
    if wall.integer(started, 1) and wall.integer(ready, 1) and started <= ready <= release:
        result['startup_seconds'] = (ready - started) / 1e9
    else:
        result['issues'].append('START_TO_READY_TIMING_UNKNOWN_OR_INVALID')
    if wall.integer(finalized, 1) and finalized >= end:
        result['post_exit_finalization_seconds'] = (finalized - end) / 1e9
        result['execution_to_raw_evidence_ready_seconds'] = (finalized - release) / 1e9
    else:
        result['issues'].append('POST_EXIT_FINALIZATION_TIMING_UNKNOWN_OR_INVALID')
    final = capture.get('final') if isinstance(capture.get('final'), dict) else {}
    for source, destination in (('bytes', 'artifact_bytes'), ('persisted_records', 'persisted_events')):
        value = final.get(source)
        if wall.integer(value):
            result[destination] = value
        else:
            result['issues'].append('COLLECTOR_' + source.upper() + '_UNKNOWN')
    if (capture.get('collector_ring_bytes') != result['ring_bytes']
            or final.get('ring_bytes') != result['ring_bytes']):
        result['issues'].append('COLLECTOR_RING_BUDGET_DIFFERS')
    result['status'] = 'OBSERVED_SAVED_BOUNDARIES' if not result['issues'] else 'PARTIAL_OR_UNKNOWN'
    return result


def aggregate(trials, data_device='253:0'):
    groups, issues, seen_runs, outputs = {}, [], set(), {}
    boot_ids = {trial.get('boot_id') for trial in trials}
    if len(boot_ids) != 1 or None in boot_ids:
        issues.append('MULTIPLE_OR_MISSING_BOOTS; NOT_SAME_BOOT_PAIRED_CAMPAIGN')
    for trial in trials:
        cfg = trial['config']
        mode = cfg.get('file_access_mode')
        block = wall.get(trial, 'matrix', 'block')
        if (mode not in ('sampler', 'access') or cfg.get('concurrency') not in (2, 4, 6, 8)
                or not wall.integer(block) or cfg.get('warmup') is not False
                or cfg.get('intervention') != 'none' or cfg.get('cache') not in ('warm', 'guest-cold')
                or cfg.get('workspace_layout') not in ('shared', 'independent')):
            issues.append('INVALID_EXPERIMENT_CONDITION:' + str(trial.get('run_id')))
            continue
        run_id = trial.get('run_id')
        if not isinstance(run_id, str) or run_id in seen_runs:
            issues.append('DUPLICATE_OR_MISSING_RUN_ID:' + str(run_id))
            continue
        seen_runs.add(run_id)
        fixed = json.dumps(fixed_scope(cfg), sort_keys=True)
        if fixed in outputs and outputs[fixed] != signature(trial):
            issues.append('CROSS_MODE_OR_CONDITION_OUTPUT_MISMATCH:' + run_id)
        outputs.setdefault(fixed, signature(trial))
        key = (fixed, cfg.get('cache'), cfg.get('workspace_layout'), cfg['concurrency'], mode)
        by_block = groups.setdefault(key, {})
        if block in by_block:
            issues.append('DUPLICATE_BLOCK_CONDITION:' + run_id)
            continue
        by_block[block] = trial
    if len(outputs) != 1:
        issues.append('FIXED_WORK_SCOPE_COUNT_IS_NOT_ONE')
    conditions, overhead = [], []
    for key, blocks in sorted(groups.items()):
        fixed, cache, layout, concurrency, mode = key
        rows = list(blocks.values())
        file_keys = sorted({field for row in rows for field in (row.get('file_metrics') or {})})
        resource_status = {state: sum(row['resources']['status'] == state for row in rows)
                           for state in sorted({row['resources']['status'] for row in rows})}
        analysis_status = {state: sum(row.get('file_analysis_status', 'NOT_ENABLED') == state for row in rows)
                           for state in sorted({row.get('file_analysis_status', 'NOT_ENABLED') for row in rows})}
        conditions.append({'cache': cache, 'workspace_layout': layout, 'concurrency': concurrency,
            'file_access_mode': mode, 'file_access_backend': json.loads(fixed).get('file_access_backend'),
            'collector_ring_bytes': json.loads(fixed).get('collector_ring_bytes'),
            'fixed_work': json.loads(fixed), 'blocks': sorted(blocks),
            'timing_eligible_n': sum(row['primary']['usable_for_comparison'] for row in rows),
            'cache_eligible_n': sum(row['cache_evidence']['cache_condition_eligible'] for row in rows),
            'makespan_seconds': metrics_summary(rows, lambda r: r['primary']['seconds']),
            'user_cpu_seconds': metrics_summary(rows, lambda r: r['task_cpu']['user_seconds']),
            'system_cpu_seconds': metrics_summary(rows, lambda r: r['task_cpu']['system_seconds']),
            'per_query_trial_median_seconds': metrics_summary(rows, lambda r: wall.get(r, 'per_query', 'duration_seconds', 'median')),
            'page_faults': metrics_summary(rows, lambda r: wall.get(r, 'extra_counters', 'pgfault')),
            'major_page_faults': metrics_summary(rows, lambda r: wall.get(r, 'resources', 'memory_counters', 'pgmajfault')),
            'refaults': metrics_summary(rows, lambda r: wall.get(r, 'resources', 'memory_counters', 'workingset_refault_file')),
            'data_device': data_device,
            'data_read_bytes': metrics_summary(rows, lambda r: wall.get(r, 'resources', 'io_by_device', data_device, 'rbytes')),
            'data_write_bytes': metrics_summary(rows, lambda r: wall.get(r, 'resources', 'io_by_device', data_device, 'wbytes')),
            'psi_stall_seconds': {resource: {kind: metrics_summary(rows,
                lambda r, res=resource, k=kind: wall.get(r, 'resources', 'psi_stall_us', res, k) / 1e6
                if numeric(wall.get(r, 'resources', 'psi_stall_us', res, k)) else None)
                for kind in ('some', 'full')} for resource in ('cpu', 'memory', 'io')},
            'file_cache_last_bytes': metrics_summary(rows, lambda r: wall.get(r, 'resources', 'file_cache_gauges', 'file', 'last_bytes')),
            'background': {field: metrics_summary(rows, lambda r, f=field: wall.get(r, 'extra_counters', f))
                for field in ('guest_context_switches', 'guest_tasks_created', 'guest_page_faults',
                    'guest_major_faults', 'guest_eth0_rx_bytes', 'guest_eth0_tx_bytes',
                    'guest_average_cpu_runqueue_waiting_tasks', 'guest_observed_max_d_state_tasks',
                    'target_observed_max_memory_bytes', 'target_observed_max_anon_bytes')},
            'resource_status_counts': resource_status, 'file_analysis_status_counts': analysis_status,
            'collector_cost': {field: metrics_summary(rows, lambda r, f=field: wall.get(r, 'collector_boundaries', f))
                for field in ('startup_seconds', 'post_exit_finalization_seconds',
                    'execution_to_raw_evidence_ready_seconds', 'persisted_events', 'artifact_bytes')},
            'collector_boundary_status_counts': {state: sum((wall.get(row, 'collector_boundaries', 'status') or 'UNKNOWN') == state for row in rows)
                for state in sorted({wall.get(row, 'collector_boundaries', 'status') or 'UNKNOWN' for row in rows})},
            'file_metrics': {field: metrics_summary(rows, lambda r, f=field: wall.get(r, 'file_metrics', f)) for field in file_keys},
            'run_ids': [row['run_id'] for row in rows]})
        if mode != 'access':
            continue
        control = groups.get((fixed, cache, layout, concurrency, 'sampler'), {})
        common = sorted(set(blocks) & set(control))
        pairs = []
        for block in common:
            baseline, traced = control[block], blocks[block]
            left, right = baseline['primary']['seconds'], traced['primary']['seconds']
            eligible = (baseline['primary']['usable_for_comparison'] and traced['primary']['usable_for_comparison']
                and baseline['cache_evidence']['cache_condition_eligible'] and traced['cache_evidence']['cache_condition_eligible']
                and baseline['boot_id'] == traced['boot_id'] and signature(baseline) == signature(traced))
            pairs.append({'block': block, 'sampler_seconds': left, 'access_seconds': right,
                'added_seconds': right - left if numeric(left) and numeric(right) else None,
                'added_percent': (right / left - 1) * 100 if numeric(left) and left > 0 and numeric(right) else None,
                'eligible': bool(eligible), 'sampler_run_id': baseline['run_id'], 'access_run_id': traced['run_id']})
        valid = [row for row in pairs if row['eligible']]
        overhead.append({'cache': cache, 'workspace_layout': layout, 'concurrency': concurrency,
            'file_access_backend': json.loads(fixed).get('file_access_backend'),
            'collector_ring_bytes': json.loads(fixed).get('collector_ring_bytes'),
            'pairs': pairs, 'paired_n': len(pairs), 'eligible_paired_n': len(valid),
            'added_seconds': metrics_summary(valid, lambda r: r['added_seconds']),
            'added_percent': metrics_summary(valid, lambda r: r['added_percent']),
            'missing_sampler_blocks': sorted(set(blocks) - set(control)),
            'missing_access_blocks': sorted(set(control) - set(blocks)),
            'scope': 'FULL_EVENT_COLLECTOR_INCREMENT_OVER_SAME_BOOT_SAMPLER; NOT_TOTAL_OBSERVER_OVERHEAD'})
    incomplete = any(row['timing_eligible_n'] != row['makespan_seconds']['n']
                     or row['cache_eligible_n'] != row['makespan_seconds']['n'] for row in conditions)
    quality = {'resource_incomplete_trials': sum(row['resources']['status'] != 'OBSERVED_ENCLOSING_INTERVAL' for row in trials),
        'access_analysis_incomplete_trials': sum(row['config'].get('file_access_mode') == 'access'
            and row.get('file_analysis_status') != 'COMPLETE_FOR_SELECTED_HOOKS' for row in trials),
        'access_boundary_incomplete_trials': sum(row['config'].get('file_access_mode') == 'access'
            and wall.get(row, 'collector_boundaries', 'status') != 'OBSERVED_SAVED_BOUNDARIES' for row in trials)}
    return {'schema_version': 1, 'status': 'INCOMPLETE' if issues or incomplete else 'DESCRIPTIVE_PAIRED_SEARCH_COMPARISON',
        'primary_metric': 'ALL_EIGHT_FIXED_WORK_TASKS_MAKESPAN_SECONDS', 'conditions': conditions,
        'collector_overhead': overhead, 'issues': issues, 'quality': quality, 'trials': trials,
        'limits': ['Sampler and access are not pooled. Every median is over independent randomized blocks.',
            'Per-read elapsed times can overlap across tasks and include blocking; they are not added into makespan.',
            'Resource counters use bracketing samples; missing/reset counters are unknown, not zero.',
            'File metrics cover only selected hooks and retained window events; unresolved paths/faults remain explicit.',
            'Guest data-cold/metadata-probed does not mean physical-server/SSD cache-cold.',
            'Collector startup is start-to-READY before release; end-to-finalized includes inner-runner post-exit work and collector detach/drain/fsync/hash. It is not pure syscall overhead.',
            'Execution-to-raw-evidence-ready is release-to-finalized, excluding pre-release cache preparation and later offline SQLite/CSV analysis. Artifact events/bytes include retained pre/post-window records.',
            'Shared warm preload may charge cache outside target cgroup; memory.file is not a total working-set comparison.']}


def extra_counters(directory, trial):
    """Extend the existing strict bracketing counter reader; no imputation."""
    boundary = wall.get(trial, 'resources', 'boundary')
    if not isinstance(boundary, dict):
        return {'pgfault': None, 'issues': ['NO_RESOURCE_BOUNDARY']}
    sources, issues = {}, []
    try:
        meta = wall._read(directory, 'load/load-meta.json', sources)
        rows = wall._read(directory, 'load/load-samples.jsonl', sources, lines=True)
        identity = wall._identity(trial['resources']['root_cgroup'])
        candidates = [i for i, group in enumerate(meta['cgroups']) if wall._identity(group) == identity]
        if len(candidates) != 1:
            raise ValueError('exact registered root group missing')
        index = candidates[0]
        start = boundary['first_collection'][0]
        end = boundary['last_collection'][0]
        selected_rows = [row for row in rows if start <= row['monotonic_ns'] <= end]
        selected = [row['cgroups'][index] for row in selected_rows]
        if len(selected_rows) < 2:
            raise ValueError('incomplete enclosing samples')
        result = {'pgfault': wall._delta(selected, ('memory_stat', 'pgfault'), issues),
            'issues': issues, 'scope': 'ENCLOSING_ROOT_CGROUP_INTERVAL; guest_* ARE WHOLE_GUEST_BACKGROUND'}
        for name, keys in (('guest_context_switches', ('stat', 'ctxt')),
                           ('guest_tasks_created', ('stat', 'processes')),
                           ('guest_page_faults', ('vmstat', 'pgfault')),
                           ('guest_major_faults', ('vmstat', 'pgmajfault'))):
            result[name] = wall._delta(selected_rows, keys, issues)
        for name, position in (('guest_eth0_rx_bytes', 0), ('guest_eth0_tx_bytes', 4)):
            converted = []
            for row in selected_rows:
                value = wall.get(row, 'net_dev', 'eth0')
                converted.append({'value': value[position] if isinstance(value, list) and len(value) > position else None})
            result[name] = wall._delta(converted, ('value',), issues)
        blocked = [wall.get(row, 'stat', 'procs_blocked') for row in selected_rows]
        result['guest_observed_max_d_state_tasks'] = max(blocked) if all(wall.integer(v) for v in blocked) else None
        for name, keys in (('target_observed_max_memory_bytes', ('memory_current',)),
                           ('target_observed_max_anon_bytes', ('memory_stat', 'anon'))):
            values = [wall.get(row, *keys) for row in selected]
            result[name] = max(values) if all(wall.integer(v) for v in values) else None
        schedules = [row.get('schedstat') for row in selected_rows]
        cpu_ids = [wall.get(row, 'stat', 'cpu_ids') for row in selected_rows]
        result['guest_average_cpu_runqueue_waiting_tasks'] = None
        if (wall.get(meta, 'thread_sampling', 'schedstats_runtime_enabled_at_start') is True
                and isinstance(cpu_ids[0], list) and cpu_ids[0] and all(ids == cpu_ids[0] for ids in cpu_ids)
                and all(isinstance(v, list) and len(v) == len(cpu_ids[0]) for v in schedules)):
            delays = []
            for cpu in range(len(cpu_ids[0])):
                converted = [{'value': row[cpu][1] if isinstance(row[cpu], list) and len(row[cpu]) > 1 else None}
                             for row in schedules]
                delays.append(wall._delta(converted, ('value',), issues))
            if all(wall.integer(v) for v in delays) and end > start:
                result['guest_average_cpu_runqueue_waiting_tasks'] = sum(delays) / (end - start)
        return result
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        return {'pgfault': None, 'issues': [str(error)]}


def load_analysis_receipt(path, expected_sha256=None):
    """Read one immutable final batch attempt; never guess the newest folder."""
    path = Path(path).resolve(strict=True)
    if path.stat().st_size > 32 * 1024 ** 2:
        raise ValueError('file analysis receipt exceeds bound')
    raw = path.read_bytes()
    if len(raw) > 32 * 1024 ** 2:
        raise ValueError('file analysis receipt exceeds bound')
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError('file analysis receipt SHA256 differs from expected digest')
    value = json.loads(raw)
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int or value['schema_version'] not in (1, 2)
            or not isinstance(value.get('attempt'), str) or not re.fullmatch(r'[0-9a-f]{32}', value['attempt'])
            or path.name != 'attempt-' + value['attempt'] + '.json'
            or value.get('status') not in ('COMPLETE_FOR_SELECTED_CASES', 'INCOMPLETE')
            or not isinstance(value.get('results'), dict) or not isinstance(value.get('failures'), dict)
            or not wall.integer(value.get('selected_cases'), 1)
            or value['selected_cases'] != len(value['results']) + len(value['failures'])
            or set(value['results']) & set(value['failures'])):
        raise ValueError('invalid final file-analysis batch attempt receipt')
    if value['schema_version'] == 2:
        settings = value.get('artifact_storage')
        if (not isinstance(settings, dict) or type(settings.get('schema_version')) is not int or settings.get('schema_version') != 1
                or settings.get('codec') != 'gzip'
                or settings.get('artifact_module_sha256') != hashlib.sha256(Path(ARTIFACTS.__file__).read_bytes()).hexdigest()):
            raise ValueError('archive receipt codec/schema/implementation binding differs')
    elif 'artifact_storage' in value or any(isinstance(row, dict) and (
            'artifact_storage_schema' in row or any('storage' in a for a in row.get('artifacts', {}).values()))
            for row in value['results'].values()):
        raise ValueError('archive artifacts require an explicit schema-2 batch receipt')
    for case_id, row in itertools_chain_items(value['results'], value['failures']):
        if (not isinstance(case_id, str) or not case_id or Path(case_id).name != case_id or case_id in ('.', '..')
                or not isinstance(row, dict) or row.get('case_id') != case_id):
            raise ValueError('batch receipt case identity differs')
    if value['status'] == 'COMPLETE_FOR_SELECTED_CASES' and (value['failures'] or any(
            row.get('analysis_status') != 'COMPLETE_FOR_SELECTED_HOOKS' for row in value['results'].values())):
        raise ValueError('batch receipt COMPLETE contradicts per-case status')
    return {'value': value, 'source': {'path': str(path), 'bytes': len(raw), 'sha256': digest,
        'attempt': value['attempt'], 'batch_status': value['status'], 'selected_cases': value['selected_cases']},
        'root': path.parent}


def itertools_chain_items(left, right):
    # Two bounded dictionaries, without allocating a duplicate receipt list.
    for item in left.items():
        yield item
    for item in right.items():
        yield item


def receipt_summary_path(receipt, case_id):
    row = receipt['value']['results'].get(case_id)
    if row is None:
        return None, None
    output = row.get('output')
    if (not isinstance(output, str) or not Path(output).is_absolute() or '..' in Path(output).parts
            or str(Path(output)) != output):
        raise ValueError('batch result output requires canonical absolute path')
    summary = (Path(output) / 'summary.json').resolve(strict=True)
    summary.relative_to(receipt['root'].resolve(strict=True))
    if not summary.is_file() or summary.stat().st_size > 32 * 1024 ** 2:
        raise ValueError('batch summary must be a bounded regular JSON artifact')
    artifact = wall.get(row, 'artifacts', 'summary.json')
    if (not isinstance(artifact, dict) or not wall._sha256(artifact.get('sha256'))
            or not wall.integer(artifact.get('bytes'), 1)
            or not isinstance(artifact.get('path'), str)
            or Path(artifact['path']).resolve(strict=True) != summary):
        raise ValueError('batch summary artifact path/SHA256/size declaration invalid')
    if 'storage' in artifact:
        raise ValueError('batch summary must remain a plain JSON artifact')
    return summary, row


def load_trials(matrix, analysis_root=None, analysis_receipt=None, expected_receipt_sha256=None):
    if analysis_root is not None and analysis_receipt is not None:
        raise ValueError('file-analysis-root and file-analysis-receipt are mutually exclusive')
    if expected_receipt_sha256 is not None and analysis_receipt is None:
        raise ValueError('expected file-analysis receipt SHA256 requires a receipt')
    receipt = load_analysis_receipt(analysis_receipt, expected_receipt_sha256) if analysis_receipt else None
    matrix = Path(matrix).resolve(strict=True)
    trials = wall.summarize_matrix(matrix)
    for trial in trials:
        directory = Path(trial['directory'])
        trial['extra_counters'] = extra_counters(directory, trial)
        profile_sources = {}
        profile = wall._read(directory, 'profile-run.json', profile_sources)
        if profile_sources['profile-run.json']['sha256'] != trial['sources']['profile-run.json']['sha256']:
            raise ValueError('profile changed during collector-boundary analysis')
        trial['execution_window'] = [profile['release_ns'], profile['end_ns']]
        target = matrix.parent / trial['matrix']['campaign']
        capture, capture_raw = None, None
        try:
            capture_raw = (target / 'capture.json').read_bytes()
            if len(capture_raw) > 32 * 1024 ** 2:
                raise ValueError('capture exceeds bound')
            capture = json.loads(capture_raw)
            trial['capture_source'] = {'path': str(target / 'capture.json'),
                'sha256': hashlib.sha256(capture_raw).hexdigest(), 'bytes': len(capture_raw)}
        except (OSError, ValueError) as error:
            trial['capture_issue'] = str(error)
        trial['collector_boundaries'] = collector_boundaries(capture, trial)
        if receipt:
            trial['file_analysis_receipt'] = receipt['source']
        if trial['config']['file_access_mode'] == 'sampler':
            trial.update(file_analysis_status='NOT_ENABLED', file_metrics={})
            continue
        try:
            selected = None
            if receipt:
                case_id = trial['matrix']['campaign']
                summary, selected = receipt_summary_path(receipt, case_id)
                if selected is None:
                    failure = receipt['value']['failures'].get(case_id)
                    trial.update(file_analysis_status='ANALYSIS_FAILED' if failure else 'NOT_SELECTED_IN_BATCH_RECEIPT',
                        file_metrics={}, file_analysis_issue=failure.get('error', 'batch analysis failed')
                        if failure else 'No result for this case in the explicitly selected batch receipt')
                    continue
            else:
                summary = ((Path(analysis_root) / trial['matrix']['campaign'] / 'summary.json')
                           if analysis_root else target / 'file-analysis' / 'summary.json')
            raw = summary.read_bytes()
            if len(raw) > 32 * 1024 ** 2:
                raise ValueError('file analysis summary exceeds bound')
            value = json.loads(raw)
            if not isinstance(value, dict) or not isinstance(value.get('metrics'), dict):
                raise ValueError('file summary metrics missing')
            if selected is not None:
                artifact = selected['artifacts']['summary.json']
                if (hashlib.sha256(raw).hexdigest() != artifact['sha256'] or len(raw) != artifact['bytes']
                        or value.get('status') != selected.get('analysis_status')
                        or any(wall.get(selected, 'sources', key, 'sha256') !=
                            wall.get(value, 'sources', key, 'sha256') for key in ('profile_run', 'capture'))):
                    raise ValueError('batch receipt summary digest/status/source binding differs')
            if (value.get('run_id') != trial['run_id']
                    or wall.get(value, 'sources', 'profile_run', 'sha256') !=
                    wall.get(trial, 'sources', 'profile-run.json', 'sha256')):
                raise ValueError('file summary profile identity/SHA256 differs')
            if (not isinstance(capture, dict) or capture_raw is None
                    or wall.get(value, 'sources', 'capture', 'sha256') != hashlib.sha256(capture_raw).hexdigest()
                    or capture.get('profile_run_id') != trial['run_id']
                    or value.get('collector_run_id') != capture.get('collector_run_id')):
                raise ValueError('file summary capture identity/SHA256 differs')
            trial.update(file_analysis_status=value.get('status', 'UNKNOWN'), file_metrics=flatten_metrics(value['metrics']),
                file_analysis={'path': str(summary), 'sha256': hashlib.sha256(raw).hexdigest(),
                               'summary': value})
        except (OSError, ValueError) as error:
            trial.update(file_analysis_status='MISSING_OR_INVALID', file_metrics={},
                         file_analysis_issue=str(error))
    return trials


def fmt(value, digits=3):
    return ('%.{}f'.format(digits) % value) if numeric(value) else '未知'


def markdown(report):
    lines = ['# 并发 2 / 4 / 6 / 8 文件搜索对照', '',
        '固定八个搜索任务、同一源码版本、相同查询及结果，四个工作负载 CPU。先看整批完成的墙钟秒数；下面的 CPU、缺页、I/O 和逐文件数据只解释现象，不相加分摊墙钟时间。', '',
        'sampler 仅采低频资源；access 同时逐条记录选定文件/缺页事件。两种模式分开显示，不能拿 access 的耗时当作未受探针影响的性能。', '']
    if report.get('file_analysis_receipt'):
        receipt = report['file_analysis_receipt']
        lines += ['离线分析按指定批处理回执取实际结果（包括重试目录），不会回退到旧结果。回执状态 `{}`，attempt `{}`，SHA256 `{}`。'.format(
            receipt['batch_status'], receipt['attempt'], receipt['sha256']), '']
    profiles = sorted({(row.get('file_access_backend') or 'UNDECLARED', row.get('collector_ring_bytes') or 0)
                       for row in report['conditions']})
    for backend, ring in profiles:
        for mode in ('sampler', 'access'):
            lines += ['## {} / {} / ring {} MiB：整批八个任务完成时间（秒）'.format(mode, backend, ring / 1024 ** 2), '',
                '| 缓存 / 仓库 | 并发 2 | 并发 4 | 并发 6 | 并发 8 |',
                '|---|---:|---:|---:|---:|']
            for cache in ('warm', 'guest-cold'):
                for layout in ('shared', 'independent'):
                    row = []
                    for concurrency in (2, 4, 6, 8):
                        found = [r for r in report['conditions'] if (r['file_access_mode'], r['cache'],
                            r['workspace_layout'], r['concurrency'], r.get('file_access_backend') or 'UNDECLARED',
                            r.get('collector_ring_bytes') or 0) == (mode, cache, layout, concurrency, backend, ring)]
                        row.append('{} (n={},有效{})'.format(fmt(found[0]['makespan_seconds']['median']),
                            found[0]['makespan_seconds']['n'], min(found[0]['timing_eligible_n'], found[0]['cache_eligible_n']))
                            if len(found) == 1 else '未测')
                    lines.append('| {} / {} | {} |'.format('热' if cache == 'warm' else '冷',
                        '共享' if layout == 'shared' else '独立', ' | '.join(row)))
            lines.append('')
    lines += ['## 资源指标（各轮中位数）', '',
        '| 缓存 / 仓库 / 并发 / 模式 | user CPU 秒 | system CPU 秒 | 总缺页 | major 缺页 | 数据盘读 MiB | CPU PSI some 秒 | I/O PSI some 秒 |',
        '|---|---:|---:|---:|---:|---:|---:|---:|']
    for row in report['conditions']:
        label = '{} / {} / {} / {}'.format(row['cache'], row['workspace_layout'], row['concurrency'], row['file_access_mode'])
        read_bytes = row['data_read_bytes']['median']
        lines.append('| {} | {} | {} | {} | {} | {} | {} | {} |'.format(label,
            fmt(row['user_cpu_seconds']['median']), fmt(row['system_cpu_seconds']['median']),
            fmt(row['page_faults']['median'], 0), fmt(row['major_page_faults']['median'], 0),
            fmt(read_bytes / 1024 ** 2 if numeric(read_bytes) else None),
            fmt(row['psi_stall_seconds']['cpu']['some']['median']),
            fmt(row['psi_stall_seconds']['io']['some']['median'])))
    lines += ['', '## 文件访问指标', '',
        '只对 access 模式显示，指标计数来自实际事件，而不是输入目录文件总数。每次 read 的字节数、耗时和每个文件的汇总请打开各轮 file-analysis 目录；没有采到或无法关联的事件不补成 0。', '']
    for row in report['conditions']:
        if row['file_access_mode'] != 'access':
            continue
        lines += ['### {} / {} / 并发 {}'.format(row['cache'], row['workspace_layout'], row['concurrency']), '',
            '解析状态：`{}`。'.format(json.dumps(row['file_analysis_status_counts'], ensure_ascii=False)), '',
            '| 指标 | 中位数 | 有效轮数 | 未知轮数 |', '|---|---:|---:|---:|']
        for key, metric in sorted(row['file_metrics'].items()):
            lines.append('| {} | {} | {} | {} |'.format(key, fmt(metric['median']), metric['n'], metric['unknown_n']))
        lines.append('')
    lines += ['## 全 Guest 背景指标', '',
        '这些包括采集器、SSH、系统服务等，不是 Agent 独占成本。CPU 等待任务数为各 CPU schedstat run-delay 总增量除以包围窗口时间；D-state 是采样看到的最大瞬时数量，不是累计等待秒数。', '',
        '| 缓存 / 仓库 / 并发 / 模式 | 上下文切换 | 新建 task | eth0 RX bytes | eth0 TX bytes | 平均 CPU 等待 task | 最大 D-state task |',
        '|---|---:|---:|---:|---:|---:|---:|']
    for row in report['conditions']:
        bg = row['background']
        lines.append('| {} / {} / {} / {} | {} | {} | {} | {} | {} | {} |'.format(
            row['cache'], row['workspace_layout'], row['concurrency'], row['file_access_mode'],
            fmt(bg['guest_context_switches']['median'], 0), fmt(bg['guest_tasks_created']['median'], 0),
            fmt(bg['guest_eth0_rx_bytes']['median'], 0), fmt(bg['guest_eth0_tx_bytes']['median'], 0),
            fmt(bg['guest_average_cpu_runqueue_waiting_tasks']['median']),
            fmt(bg['guest_observed_max_d_state_tasks']['median'], 0)))
    lines += ['## 逐事件探针的增量开销', '',
        '同一随机块中 access 减 sampler。正值表示采集增加了耗时；这不是 Observer 全功能相对完全关闭的总开销。', '',
        '| 缓存 / 仓库 / 并发 | 配对数 | 增加秒数中位数 | 增加百分比中位数 |', '|---|---:|---:|---:|']
    for row in report['collector_overhead']:
        lines.append('| {} / {} / {} | {} | {} | {}% |'.format(row['cache'], row['workspace_layout'],
            row['concurrency'], row['eligible_paired_n'], fmt(row['added_seconds']['median']), fmt(row['added_percent']['median'], 1)))
    lines += ['', '## 不能隐藏的边界成本：原始观测结果何时可用', '',
        '下面均是各独立轮次的中位数。加载准备是 collector 启动到 READY，在任务 release 之前。结束收尾是全部任务退出到 capture finalized，包含 sampler 包围采样、缓存证明保存/校验、runner 收尾以及 collector detach/drain/fsync/hash，不能称为纯 syscall 开销。', '',
        '“release→原始证据就绪”=任务墙钟+结束收尾，**不包含** release 前的缓存准备，也**不包含**随后 SQLite/CSV 离线解析。事件数和证据字节数是整个 collector artifact（包括保留的前后准备事件），不是窗口内 read 次数或读取的业务字节。sampler-only 没有该 collector，标为未启用，不补成 0 秒。', '',
        '| 缓存 / 仓库 / 并发 / 模式 / backend | ring MiB | 加载准备秒 | 任务墙钟秒 | 结束收尾秒 | release→原始证据就绪秒 | 证据 MiB | 保留事件数 |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for row in report['conditions']:
        cost = row['collector_cost']
        enabled = row['file_access_mode'] == 'access'
        cell = lambda field, divisor=1, digits=3: (fmt(cost[field]['median'] / divisor
            if numeric(cost[field]['median']) else None, digits) + ' (n={})'.format(cost[field]['n'])) if enabled else '未启用'
        lines.append('| {} / {} / {} / {} / {} | {} | {} | {} | {} | {} | {} | {} |'.format(
            row['cache'], row['workspace_layout'], row['concurrency'], row['file_access_mode'], row.get('file_access_backend'),
            fmt(row['collector_ring_bytes'] / 1024 ** 2 if numeric(row.get('collector_ring_bytes')) else None, 0),
            cell('startup_seconds'), fmt(row['makespan_seconds']['median']),
            cell('post_exit_finalization_seconds'), cell('execution_to_raw_evidence_ready_seconds'),
            cell('artifact_bytes', 1024 ** 2), cell('persisted_events', 1, 0)))
    lines += ['', '## 边界', ''] + ['- ' + value for value in report['limits']]
    lines += ['', '采集完整度：`{}`。这与真实墙钟耗时是否有效分开报告。'.format(json.dumps(report['quality'], ensure_ascii=False))]
    if report['issues']:
        lines += ['', '## 未通过的检查', ''] + ['- ' + value for value in report['issues']]
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', required=True, type=Path)
    analysis = parser.add_mutually_exclusive_group()
    analysis.add_argument('--file-analysis-root', type=Path)
    analysis.add_argument('--file-analysis-receipt', type=Path,
                          help='final access_batch attempt-UUID.json, including retry output mapping')
    parser.add_argument('--expected-file-analysis-receipt-sha256',
                        help='optional external SHA256 pin; actual receipt SHA256 is always saved')
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--data-device', default='253:0')
    args = parser.parse_args()
    report = aggregate(load_trials(args.matrix, args.file_analysis_root, args.file_analysis_receipt,
                                  args.expected_file_analysis_receipt_sha256), args.data_device)
    if args.file_analysis_receipt:
        references = [row['file_analysis_receipt'] for row in report['trials'] if 'file_analysis_receipt' in row]
        report['file_analysis_receipt'] = references[0] if references else None
    report['matrix_sha256'] = hashlib.sha256(args.matrix.read_bytes()).hexdigest()
    report['report_source_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.output_dir.mkdir(mode=0o700)
    with (args.output_dir / 'comparison.json').open('x') as out:
        json.dump(report, out, ensure_ascii=False, indent=2)
        out.write('\n')
    with (args.output_dir / 'comparison.md').open('x') as out:
        out.write(markdown(report))
    print(json.dumps({'status': report['status'], 'trials': len(report['trials']),
        'conditions': len(report['conditions']), 'output_dir': str(args.output_dir)}))


if __name__ == '__main__':
    main()
