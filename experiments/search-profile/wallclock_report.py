#!/usr/bin/env python3
"""Fixed-work search wall clock first; resource counters are separate clues.

Read-only analysis of saved search-profile campaigns. Does not enable probes,
drop caches, modify workloads, or add overlapping CPU/PSI/histogram times.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import random
import stat
import statistics


_SPEC = importlib.util.spec_from_file_location('wallclock_query_validator', Path(__file__).with_name('analyze.py'))
_ANALYZE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_ANALYZE)
COUNTERS = {'cpu_stat': ('usage_usec', 'user_usec', 'system_usec', 'throttled_usec'),
            'memory_stat': ('workingset_refault_file', 'pgscan', 'pgsteal', 'pgmajfault'),
            'memory_events': ('high', 'max', 'oom', 'oom_kill')}
GAUGES = ('file', 'shmem', 'active_file', 'inactive_file', 'file_dirty', 'file_writeback')
BOOTSTRAP_SEED = 20261015
BOOTSTRAP_RESAMPLES = 4000


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def get(value, *keys):
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def summary(values):
    values = list(values)
    values = [value for value in values if type(value) in (int, float) and math.isfinite(value)]
    ordered = sorted(values)
    return {'n': len(ordered), 'median': statistics.median(ordered) if ordered else None,
            'observed_p95': ordered[max(0, math.ceil(len(ordered) * .95) - 1)] if ordered else None}


def independent_mean_summary(values, sampling_unit, independent_values=None):
    """CI for a mean of independent units, never for pooled query samples.

    The existing median/p95/n summarize the original observations. A paired
    matrix block may contain multiple inner repetitions; their mean forms one
    independent value, with equal weight per block, for the mean and its CI.
    """
    values = list(values)
    independent_values = values if independent_values is None else list(independent_values)
    independent_values = sorted(value for value in independent_values
                                if type(value) in (int, float) and math.isfinite(value))
    result = summary(values)
    count, interval = len(independent_values), None
    if count >= 3:
        rng = random.Random(BOOTSTRAP_SEED)
        estimates = sorted(sum(rng.choice(independent_values) for _ in range(count)) / count
                           for _ in range(BOOTSTRAP_RESAMPLES))
        interval = [estimates[math.ceil(BOOTSTRAP_RESAMPLES * .025) - 1],
                    estimates[math.ceil(BOOTSTRAP_RESAMPLES * .975) - 1]]
    result.update(mean=statistics.mean(independent_values) if count else None,
                  mean_ci95_bootstrap=interval, independent_n=count,
                  mean_sampling_unit=sampling_unit,
                  mean_weighting='EQUAL_WEIGHT_PER_INDEPENDENT_UNIT')
    return result


def paired_change_summary(pairs, field):
    blocks = {}
    matrix = False
    for pair in pairs:
        block = pair['repetition']
        if isinstance(block, tuple):
            matrix = True
            block = block[0]
        blocks.setdefault(block, []).append(pair[field])
    return independent_mean_summary((pair[field] for pair in pairs),
        'PAIRED_MATRIX_BLOCK' if matrix else 'PAIRED_REPETITION_BLOCK',
        (statistics.mean(values) for values in blocks.values()))


def _read(root, name, sources, lines=False):
    path = (Path(root) / name).resolve()
    try:
        path.relative_to(Path(root).resolve())
        if not path.is_file() or path.stat().st_size > 512 * 1024 * 1024:
            raise ValueError('artifact missing/non-regular/over 512MiB budget')
        raw = path.read_bytes()
        value = [json.loads(line) for line in raw.splitlines()] if lines else json.loads(raw)
        if (not lines and not isinstance(value, dict)) or (lines and any(not isinstance(row, dict) for row in value)):
            raise ValueError('expected JSON object(s)')
    except (ValueError, OSError, UnicodeError) as error:
        raise ValueError('{}: {}'.format(name, error)) from error
    sources[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    return value


def _sha256(value):
    return isinstance(value, str) and len(value) == 64 and all(ch in '0123456789abcdef' for ch in value)


def _artifact_name(value):
    if (not isinstance(value, str) or not value or len(value) > 4096 or '\0' in value
            or Path(value).is_absolute() or '..' in Path(value).parts or str(Path(value)) != value):
        raise ValueError('cache artifact requires canonical relative path')
    return value


def _gzip_binding(directory, reference, sources):
    if not isinstance(reference, dict) or not _sha256(reference.get('sha256')):
        raise ValueError('missing/invalid gzip artifact reference')
    name = _artifact_name(reference.get('path'))
    path = (Path(directory) / name).resolve()
    path.relative_to(Path(directory).resolve())
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 18 <= before.st_size <= 512 * 1024 * 1024:
        raise ValueError('gzip artifact missing/nonregular/outside byte budget')
    digest, size, header = hashlib.sha256(), 0, b''
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            if not header:
                header = block[:3]
            size += len(block)
            digest.update(block)
        after = os.fstat(stream.fileno())
    if (size != before.st_size or any(getattr(before, key) != getattr(after, key)
            for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
        raise ValueError('gzip artifact changed while hashing')
    sources[name] = {'sha256': digest.hexdigest(), 'bytes': size}
    if digest.hexdigest() != reference['sha256'] or header != b'\x1f\x8b\x08':
        raise ValueError('gzip artifact SHA256/header mismatch')
    return {'path': name, **sources[name],
            'validation': 'GZIP_HEADER_AND_SHA256_ONLY; NO_DECOMPRESSION_OR_CRC_RECONSTRUCTION'}


def cache_evidence(directory, run, sources):
    """Bind compact cache observations without pretending to replay each file."""
    result = {'status': 'NOT_COLLECTED', 'cache_condition_eligible': False, 'issues': [], 'roots': [],
        'validation_scope': 'COMPACT_SUMMARY_AND_ARTIFACT_BINDING_ONLY',
        'per_file_reconstruction': 'FULL_PER_FILE_RECONSTRUCTION_NOT_PERFORMED',
        'identity_scope': 'PROFILE_RUN_BOOT_AND_TASK_JOB_WORKSPACE_BINDING; PROOF_HAS_NO_INDEPENDENT_RUN_BOOT_ATTESTATION',
        'scope': 'DATA_PAGE_RESIDENCY_NON_ATOMIC; METADATA_PROBED; NOT_DENTRY_INODE_OR_HOST_COLD'}
    if 'cache_residency' not in run:
        return result
    result['status'] = 'INVALID_OR_INCOMPLETE'
    try:
        reference = run['cache_residency']
        if not isinstance(reference, dict) or not _sha256(reference.get('sha256')):
            raise ValueError('invalid compact cache proof reference')
        if reference.get('scope') != 'DATA_PAGE_RESIDENCY; PROBING_TRAVERSES_METADATA; NOT_DENTRY_INODE_COLD_PROOF':
            raise ValueError('cache proof scope missing or unsupported')
        name = _artifact_name(reference.get('path'))
        proof = _read(directory, name, sources)
        if sources[name]['sha256'] != reference['sha256']:
            raise ValueError('compact cache proof SHA256 mismatch')
        if (type(proof.get('schema_version')) is not int or proof['schema_version'] != 1
                or proof.get('kind') != 'MINCORE_MULTIPLE_ROOT_RESIDENCY'
                or proof.get('status') != 'OBSERVED_NON_ATOMIC' or proof.get('errors', []) != []
                or proof.get('aggregation') != 'ROOTS_REPORTED_SEPARATELY_NO_PHYSICAL_CACHE_BYTES_SUMMED'):
            raise ValueError('unsupported/incomplete compact cache proof')
        for field in ('run_id', 'boot_id'):
            if not isinstance(run.get(field), str) or not run[field]:
                raise ValueError('profile cache run/boot identity missing')
            if field in proof and proof[field] != run[field]:
                raise ValueError('cache proof ' + field + ' differs from profile')
        result['profile_identity'] = {field: run[field] for field in ('run_id', 'boot_id')}
        release, config = run.get('release_ns'), run.get('config', {})
        if not integer(release) or not isinstance(config, dict) or not _sha256(config.get('corpus_sha256')):
            raise ValueError('cache release/inventory binding missing')
        mode, layout = config.get('cache'), config.get('workspace_layout')
        if mode not in ('warm', 'guest-cold') or layout not in ('shared', 'independent'):
            raise ValueError('cache mode/workspace layout unsupported')
        if (proof.get('independent_roots_required') is not (layout == 'independent')
                or proof.get('shared_dev_inode_identities') != []):
            raise ValueError('cache independent-root declaration inconsistent')
        tasks = run.get('tasks')
        if (not isinstance(tasks, list) or not tasks or not integer(config.get('jobs'), 1)
                or len(tasks) != config['jobs'] or len(tasks) > 128):
            raise ValueError('cache task/workspace scope missing')
        workspaces, prepared = [], []
        for task in tasks:
            task_id = task.get('task_id')
            if not isinstance(task_id, str) or Path(task_id).name != task_id or task_id in ('.', '..'):
                raise ValueError('invalid cache task identity')
            job = _read(directory, task_id + '-job.json', sources)
            workspace = job.get('corpus')
            if (not isinstance(workspace, str) or not workspace.startswith('/') or '..' in Path(workspace).parts
                    or str(Path(workspace)) != workspace):
                raise ValueError('cache task workspace requires exact canonical absolute path')
            if (get(job, 'query_identity', 'run_id') != run['run_id']
                    or get(job, 'query_identity', 'task_id') != task_id
                    or _identity(get(job, 'query_identity', 'cgroup')) != _identity(task.get('cgroup'))
                    or _identity(task.get('cgroup')) is None):
                raise ValueError('cache task job identity differs from profile')
            ready = task.get('preparation')
            if (not isinstance(ready, dict) or ready.get('boot_id') != run['boot_id']
                    or not integer(get(task, 'process', 'pid'), 1)
                    or not integer(get(task, 'process', 'start_ticks'), 1)
                    or ready.get('process') != task.get('process') or not integer(ready.get('monotonic_ns'))):
                raise ValueError('cache worker preflight identity/window missing')
            workspaces.append(workspace)
            prepared.append(ready['monotonic_ns'])
        if ((layout == 'shared' and len(set(workspaces)) != 1)
                or (layout == 'independent' and len(set(workspaces)) != len(workspaces))):
            raise ValueError('cache layout differs from task workspaces')
        roots = proof.get('roots')
        if not isinstance(roots, list) or not 1 <= len(roots) <= 16 or any(not isinstance(row, dict) for row in roots):
            raise ValueError('invalid bounded cache roots')
        names = [row.get('root') for row in roots]
        if any(not isinstance(value, str) for value in names) or len(set(names)) != len(names) or set(names) != set(workspaces):
            raise ValueError('cache roots do not match exact task workspaces')
        fixed, previous_end = None, None
        for row in roots:
            if (type(row.get('schema_version')) is not int or row['schema_version'] != 1
                    or row.get('kind') != 'MINCORE_FILE_DATA_RESIDENCY'
                    or row.get('status') != 'OBSERVED_NON_ATOMIC' or row.get('errors') != [] or 'files' in row
                    or row.get('inventory_sha256') != config['corpus_sha256'] or not _sha256(row.get('pin_sha256'))
                    or row.get('mincore_authority') != 'FILE_OWNER_FSUID_MATCH_REQUIRED_TO_EXCLUDE_LINUX_ALL_ONES_PERMISSION_MASKING'
                    or not integer(row.get('filesystem_uid'))):
                raise ValueError('cache root identity/status/inventory/authority invalid')
            if any(field in row and row[field] != run[field] for field in ('run_id', 'boot_id')):
                raise ValueError('cache root run/boot identity differs from profile')
            begin, end = row.get('start_monotonic_ns'), row.get('end_monotonic_ns')
            if (not integer(begin, 1) or not integer(end, 1) or end <= begin or end > release
                    or begin < max(prepared) or row.get('duration_ns') != end - begin
                    or type(row.get('duration_ns')) is not int
                    or (previous_end is not None and begin < previous_end)):
                raise ValueError('cache observation not in sequential worker-preflight/before-release window')
            previous_end = end
            fields = ('declared_file_count', 'observed_file_count', 'unknown_file_count', 'page_size', 'total_pages',
                'total_bytes', 'observed_total_pages', 'observed_total_bytes', 'observed_resident_pages',
                'observed_resident_bytes', 'resident_pages', 'resident_bytes')
            if any(not integer(row.get(field)) for field in fields):
                raise ValueError('cache counts/bytes/pages missing or noninteger')
            count, page, total, size = (row[field] for field in ('declared_file_count', 'page_size', 'total_pages', 'total_bytes'))
            resident, resident_size = row['resident_pages'], row['resident_bytes']
            if (not 1 <= count <= 200000 or not 512 <= page <= 1024 * 1024 or page & (page - 1)
                    or size > 64 * 1024 ** 3 or row['observed_file_count'] != count or row['unknown_file_count'] != 0
                    or any(row['observed_' + field] != row[field] for field in
                           ('total_pages', 'total_bytes', 'resident_pages', 'resident_bytes'))
                    or resident > total or resident_size > size):
                raise ValueError('cache summary counts or observed/declared totals inconsistent')
            for pages, byte_count in ((total, size), (resident, resident_size), (total - resident, size - resident_size)):
                minimum = pages * page - (page - 1) * min(count, pages)
                if not minimum <= byte_count <= pages * page:
                    raise ValueError('cache logical bytes inconsistent with page accounting')
            fraction = row.get('resident_fraction')
            if (total == 0 or type(fraction) not in (int, float) or not math.isfinite(fraction)
                    or not math.isclose(fraction, resident / total, rel_tol=1e-12, abs_tol=1e-12)):
                raise ValueError('cache residency fraction missing/inconsistent')
            state = ('ALL_NONRESIDENT_AT_EACH_FILE_PROBE' if resident == 0 else
                     'ALL_RESIDENT_AT_EACH_FILE_PROBE' if resident == total else 'MIXED_RESIDENCY')
            if row.get('data_page_state') != state:
                raise ValueError('cache data-page state inconsistent with totals')
            if (mode == 'guest-cold' and fraction > .001) or (mode == 'warm' and fraction < .999):
                raise ValueError('observed data-page residency violates declared cache condition')
            declaration = (count, page, total, size, row['inventory_sha256'])
            if fixed is not None and fixed != declaration:
                raise ValueError('cache independent roots do not declare identical fixed inventories')
            fixed = declaration
            result['roots'].append({field: row[field] for field in ('root', 'inventory_sha256', 'pin_sha256',
                'declared_file_count', 'observed_file_count', 'unknown_file_count', 'page_size', 'total_pages',
                'total_bytes', 'resident_pages', 'resident_bytes', 'resident_fraction', 'data_page_state',
                'start_monotonic_ns', 'end_monotonic_ns', 'duration_ns')})
            result['roots'][-1].update(start_to_release_ns=release - begin, end_to_release_ns=release - end)
        if (sum(row['declared_file_count'] for row in roots) > 1000000
                or sum(row['total_bytes'] for row in roots) > 256 * 1024 ** 3):
            raise ValueError('cache roots exceed collector global file/byte budgets')
        first, last = min(row['start_monotonic_ns'] for row in roots), max(row['end_monotonic_ns'] for row in roots)
        gap = run.get('cache_probe_end_to_release_ns')
        if not integer(gap) or gap != release - last:
            raise ValueError('profile last-root-end/release gap inconsistent')
        result['non_atomic_window'] = {'start_ns': first, 'end_ns': last, 'release_ns': release,
            'observation_span_ns': last - first, 'maximum_start_to_release_ns': release - first,
            'maximum_root_end_to_release_ns': release - min(row['end_monotonic_ns'] for row in roots),
            'last_root_end_to_release_ns': gap,
            'interpretation': 'Sequential per-file/root observations, not simultaneous residency at release.'}
        result['file_details'] = _gzip_binding(directory, proof.get('file_details'), sources)
        result.update(status='SUMMARY_AND_ARTIFACT_BINDING_VERIFIED', cache_condition_eligible=True)
    except (ValueError, OSError, TypeError, KeyError, OverflowError) as error:
        result['issues'].append({'code': 'CACHE_EVIDENCE_INVALID_OR_INCOMPLETE', 'detail': str(error)})
    return result


def _identity(value):
    if (not isinstance(value, dict) or not isinstance(value.get('path'), str) or not value['path'].startswith('/')
            or not integer(value.get('inode'), 1) or not integer(value.get('device'))):
        return None
    return value['path'], value['inode'], value['device']


def _delta(rows, keys, issues):
    values = [get(row, *keys) for row in rows]
    label = '/'.join(keys)
    if not values or any(not integer(value) for value in values):
        issues.append({'code': 'MISSING_COUNTER', 'field': label, 'detail': 'missing is unknown, not zero'})
        return None
    if any(last < first for first, last in zip(values, values[1:])):
        issues.append({'code': 'COUNTER_REGRESSION', 'field': label})
        return None
    return values[-1] - values[0]


def _resources(directory, run, start, end, sources, expected_root_cgroup=None):
    issues = []
    result = {'status': 'INCOMPLETE', 'issues': issues, 'boundary': None,
              'cpu_usec': {}, 'psi_stall_us': {}, 'memory_counters': {}, 'io_by_device': {},
              'file_cache_gauges': {}, 'system_background_file_cache': {}}
    if run.get('config', {}).get('mode') in ('baseline', 'observer'):
        result['status'] = 'NOT_COLLECTED'
        return result
    try:
        meta = _read(directory, 'load/load-meta.json', sources)
        stats = _read(directory, 'load/load-sampler-stats.json', sources)
        rows = _read(directory, 'load/load-samples.jsonl', sources, lines=True)
    except ValueError as error:
        issues.append({'code': 'RESOURCE_ARTIFACT_UNAVAILABLE', 'detail': str(error)})
        return result
    if meta.get('label') != run.get('run_id') or not run.get('boot_id') or meta.get('boot_id') != run['boot_id']:
        issues.append({'code': 'RESOURCE_RUN_OR_BOOT_MISMATCH'})
        return result
    groups = meta.get('cgroups')
    if not isinstance(groups, list) or any(_identity(group) is None for group in groups):
        issues.append({'code': 'INVALID_CGROUP_REGISTRY'})
        return result
    identities = [_identity(group) for group in groups]
    if len(set(identities)) != len(identities):
        issues.append({'code': 'DUPLICATE_CGROUP_REGISTRY'})
        return result
    task_groups = [_identity(task.get('cgroup')) for task in run.get('tasks', []) if isinstance(task, dict)]
    if not task_groups or any(identity is None or identity not in identities for identity in task_groups):
        issues.append({'code': 'TASK_CGROUP_NOT_BOUND_TO_REGISTRY'})
        return result
    if expected_root_cgroup is not None:
        selected = _identity(expected_root_cgroup)
        candidates = [index for index, identity in enumerate(identities) if identity == selected and selected is not None]
        basis = 'EXPLICIT_EXPECTED_ROOT_PATH_INODE_DEVICE'
    elif len(set(task_groups)) == 1:
        candidates = [identities.index(task_groups[0])]
        basis = 'EXACT_SHARED_TASK_CGROUP_IDENTITY'
    else:
        candidates = [index for index, identity in enumerate(identities)
                      if all(task[0].startswith(identity[0].rstrip('/') + '/') for task in task_groups)]
        basis = 'UNIQUE_SAMPLER_REGISTERED_COMMON_ANCESTOR_NOT_EXTERNAL_ROOT_ATTESTATION'
    if len(candidates) != 1:
        issues.append({'code': 'ROOT_CGROUP_AMBIGUOUS_OR_UNKNOWN'})
        return result
    index = candidates[0]
    result.update(root_cgroup={key: groups[index][key] for key in ('path', 'inode', 'device')}, root_binding_basis=basis)
    if any(not (task == identities[index] or task[0].startswith(identities[index][0].rstrip('/') + '/')) for task in task_groups):
        issues.append({'code': 'EXPECTED_ROOT_DOES_NOT_CONTAIN_TASKS'})
        return result
    previous = previous_end = None
    valid_rows = []
    for position, row in enumerate(rows):
        begin, finish = row.get('monotonic_ns'), row.get('collection_end_ns')
        if (not integer(row.get('seq')) or row['seq'] != position or not integer(begin) or not integer(finish)
                or finish < begin or (previous is not None and begin <= previous)
                or (previous_end is not None and begin < previous_end)):
            issues.append({'code': 'INVALID_SAMPLE_TIME_OR_SEQUENCE', 'row': position})
            return result
        previous = begin
        previous_end = finish
        if not isinstance(row.get('cgroups'), list) or len(row['cgroups']) != len(groups):
            issues.append({'code': 'CGROUP_SAMPLE_SHAPE_MISMATCH', 'row': position})
            return result
        valid_rows.append(row)
    left = [position for position, row in enumerate(valid_rows) if row['collection_end_ns'] <= start]
    right = [position for position, row in enumerate(valid_rows) if row['monotonic_ns'] >= end]
    if not left or not right or right[0] <= left[-1]:
        issues.append({'code': 'NO_BRACKETING_RESOURCE_SAMPLES', 'detail': 'no interpolation or nominal-period estimate'})
        return result
    selected_rows = valid_rows[left[-1]:right[0] + 1]
    first, last = selected_rows[0], selected_rows[-1]
    result['boundary'] = {'execution': [start, end],
        'first_collection': [first['monotonic_ns'], first['collection_end_ns']],
        'last_collection': [last['monotonic_ns'], last['collection_end_ns']],
        'before_uncertainty_ns': start - first['monotonic_ns'],
        'after_uncertainty_ns': last['collection_end_ns'] - end,
        'counter_interval_ns': last['monotonic_ns'] - first['monotonic_ns'],
        'interpolation': 'NONE', 'scope': 'ENCLOSING_ROOT_CGROUP_INTERVAL_NOT_EXACT_EXECUTION'}
    counters = []
    for row in selected_rows:
        group = row['cgroups'][index]
        if not isinstance(group, dict) or group.get('present') is not True:
            issues.append({'code': 'ROOT_CGROUP_SAMPLE_UNAVAILABLE', 'row': row['seq']})
            counters.append({})
        else:
            counters.append(group)
    for section, fields in COUNTERS.items():
        destination = result['cpu_usec'] if section == 'cpu_stat' else result['memory_counters']
        for field in fields:
            destination[field] = _delta(counters, (section, field), issues)
    for resource in ('cpu', 'memory', 'io'):
        result['psi_stall_us'][resource] = {kind: _delta(counters, ('psi', resource, kind + '_total_us'), issues)
                                          for kind in ('some', 'full')}
    io_maps = [row.get('io_stat_by_device') for row in counters]
    if any(not isinstance(value, dict) for value in io_maps):
        result['io_by_device'] = None
        issues.append({'code': 'MISSING_DEVICE_IO_MAP'})
    else:
        devices = sorted(set().union(*(set(value) for value in io_maps)))
        for device in devices:
            result['io_by_device'][device] = {field: _delta(counters, ('io_stat_by_device', device, field), issues)
                                              for field in ('rbytes', 'wbytes', 'rios', 'wios')}
        result['io_accounting_scope'] = 'PER_MAJOR_MINOR_ONLY; EMPTY_MAP_IS_NOT_PROOF_OF_NO_STORAGE_IO; NEVER_SUM_STACKED_DEVICES'
    for field in GAUGES:
        values = [get(row, 'memory_stat', field) for row in counters]
        observed = [value for value in values if integer(value)]
        result['file_cache_gauges'][field] = {'first_bytes': values[0] if integer(values[0]) else None,
            'last_bytes': values[-1] if integer(values[-1]) else None,
            'maximum_observed_bytes': max(observed) if observed else None,
            'status': 'OBSERVED_GAUGE' if len(observed) == len(values) else 'UNKNOWN_OR_PARTIAL'}
        if len(observed) != len(values):
            issues.append({'code': 'MISSING_FILE_CACHE_GAUGE', 'field': field})
    for field in ('Cached', 'Buffers', 'SReclaimable', 'MemAvailable'):
        values = [get(row, 'meminfo_kb', field) for row in selected_rows]
        result['system_background_file_cache'][field + '_kib'] = {
            'first': values[0] if integer(values[0]) else None, 'last': values[-1] if integer(values[-1]) else None}
    for field in ('read_errors', 'missed_ticks'):
        value = stats.get(field)
        if not integer(value) or value:
            issues.append({'code': 'RESOURCE_HEALTH_GAP_OR_UNKNOWN', 'field': field, 'value': value})
    if stats.get('samples') != len(rows):
        issues.append({'code': 'RESOURCE_SAMPLE_COUNT_MISMATCH'})
    result['status'] = 'OBSERVED_ENCLOSING_INTERVAL' if not issues else 'INCOMPLETE'
    return result


def summarize_trial(directory, expected_root_cgroup=None):
    directory = Path(directory)
    sources, issues = {}, []
    run = _read(directory, 'profile-run.json', sources)
    config = run.get('config') if isinstance(run.get('config'), dict) else {}
    start, end, duration = (run.get(key) for key in ('release_ns', 'end_ns', 'makespan_ns'))
    valid_timing = (run.get('status') == 'COMPLETE' and integer(start) and integer(end)
                    and integer(duration, 1) and end > start and duration == end - start)
    if not valid_timing:
        issues.append({'code': 'INVALID_OR_INCOMPLETE_EXECUTION_WINDOW'})
    if run.get('schema_version') != 1 or any(not isinstance(run.get(key), str) or not run[key] for key in ('run_id', 'boot_id')):
        issues.append({'code': 'MISSING_RUN_BOOT_OR_SCHEMA_BINDING'})
    rows = run.get('results') if isinstance(run.get('results'), list) else []
    jobs = config.get('jobs')
    ids = [row.get('task_id') for row in rows if isinstance(row, dict)]
    if not integer(jobs, 1) or len(rows) != jobs or len(ids) != jobs or any(not isinstance(value, str) for value in ids) or len(set(ids)) != len(ids):
        issues.append({'code': 'INCOMPLETE_FIXED_WORK_TASKS'})
    output = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if (row.get('exit_code') != 0 or type(row.get('exit_code')) is not int
                or not integer(row.get('queue_ns')) or not integer(row.get('wall_ns'))
                or not integer(row.get('completion_latency_ns'))
                or row.get('queue_ns', 0) + row.get('wall_ns', 0) != row.get('completion_latency_ns')):
            issues.append({'code': 'INVALID_TASK_RESULT', 'task': row.get('task_id')})
        digest, size = row.get('output_sha256'), row.get('output_bytes')
        if (not isinstance(digest, str) or len(digest) != 64 or any(ch not in '0123456789abcdef' for ch in digest)
                or not integer(size) or not integer(row.get('query_index'))):
            issues.append({'code': 'MISSING_OUTPUT_EQUIVALENCE_EVIDENCE', 'task': row.get('task_id')})
        output.append({key: row.get(key) for key in ('task_id', 'query_index', 'exit_code', 'output_sha256', 'output_bytes')})
    if rows and all(isinstance(row, dict) and integer(row.get('completion_latency_ns')) for row in rows):
        if max(row['completion_latency_ns'] for row in rows) != duration:
            issues.append({'code': 'MAKESPAN_DOES_NOT_RECONSTRUCT_FROM_TASK_COMPLETION'})
    event_problems = _ANALYZE.Problems()
    try:
        events = _read(directory, 'task-events.jsonl', sources, lines=True)
        tasks = _ANALYZE._task_events(events, run, event_problems)
        if (len(tasks) != jobs or any(not task['identity_valid'] for task in tasks)
                or any(not isinstance(value, str) for value in ids)
                or {task['task_id'] for task in tasks} != set(ids)):
            issues.append({'code': 'INVALID_TASK_EVENT_LIFECYCLE'})
        for task in tasks:
            matches = [row for row in rows if isinstance(row, dict) and row.get('task_id') == task['task_id']]
            if valid_timing and len(matches) == 1 and task['start'] and task['end']:
                row = matches[0]
                if (not integer(row.get('queue_ns')) or not integer(row.get('completion_latency_ns'))
                        or task['start'].get('monotonic_ns') != start + row['queue_ns']
                        or task['end'].get('monotonic_ns') != start + row['completion_latency_ns']
                        or any(task['end'].get(key) != row.get(key) for key in
                               ('exit_code', 'output_sha256', 'output_bytes', 'user_usec', 'system_usec'))):
                    issues.append({'code': 'TASK_EVENT_WINDOW_DIFFERS_FROM_RUN_RESULT', 'task': task['task_id']})
        for task in tasks:
            task_id = task['task_id']
            if Path(task_id).name == task_id and task_id not in ('.', '..'):
                for suffix in ('-job.json', '-statistics.json'):
                    try:
                        _read(directory, task_id + suffix, sources)
                    except ValueError:
                        pass  # strict query validator retains the missing raw-artifact issue
        queries = _ANALYZE._query_measurements(directory, run, tasks, event_problems)
    except (ValueError, TypeError, KeyError) as error:
        event_problems.add('RAW_QUERY_OR_EVENT_INVALID', str(directory), str(error))
        queries = {'status': 'INCOMPLETE', 'queries': []}
        issues.append({'code': 'RAW_TASK_LIFECYCLE_NOT_VALIDATED'})
    query_spans = [row for row in queries.get('queries', []) if row.get('measurement_status') == 'OBSERVED']
    cpu = {}
    for field in ('user_usec', 'system_usec'):
        values = [row.get(field) for row in rows if isinstance(row, dict)]
        cpu[field.replace('_usec', '_seconds')] = sum(values) / 1e6 if len(values) == jobs and all(integer(value) for value in values) else None
    expected_root_cgroup = expected_root_cgroup if expected_root_cgroup is not None else run.get('root_cgroup')
    resources = _resources(directory, run, start, end, sources, expected_root_cgroup) if valid_timing else {
        'status': 'INCOMPLETE', 'issues': [{'code': 'NO_VALID_EXECUTION_WINDOW'}]}
    cache = cache_evidence(directory, run, sources)
    return {'schema_version': 1, 'run_id': run.get('run_id'), 'boot_id': run.get('boot_id'),
        'directory': str(directory), 'config': config,
        'cache_semantics': {'memory_charge_scope': run.get('cache_memory_charge_scope', 'NOT_RECORDED_LEGACY'),
            'interpretation': 'Warm preload can charge page cache outside the workload cgroup; cold first reads charge inside. cgroup memory.file/current is not directly comparable as total working set.',
            'cold_scope': 'When residency probing is enabled it traverses file metadata: data-cold/metadata-probed, not directory/inode-cold or Host/storage-cold; legacy inputs do not retroactively prove a probe was performed.'},
        'primary': {'name': 'ALL_FIXED_WORK_TASKS_MAKESPAN_SECONDS',
                    'seconds': duration / 1e9 if integer(duration, 1) else None,
                    'usable_for_comparison': not issues, 'issues': issues},
        'task_cpu': {**cpu, 'scope': config.get('cpu_time_scope', 'LEGACY_UNSPECIFIED_COUNTER_SCOPE')},
        'per_query': {'status': queries.get('status'), 'duration_seconds': summary(row['duration_ns'] / 1e9 for row in query_spans),
            'by_kind': {kind: summary(row['duration_ns'] / 1e9 for row in query_spans if row.get('execution_kind') == kind)
                        for kind in ('SCAN', 'CACHE_HIT')}, 'issues': event_problems.items,
            'sampling_unit': 'Queries within a trial are correlated; no independent-query confidence interval.'},
        'resources': resources, 'cache_evidence': cache,
        'output_signature': sorted(output, key=lambda row: str(row['task_id'])),
        'sources': sources, 'query_validator_sha256': hashlib.sha256(Path(_ANALYZE.__file__).read_bytes()).hexdigest(),
        'limitations': ['Only all-fixed-work makespan is the primary performance metric; CPU/PSI/histograms are not a wall-clock partition.',
            'Enclosing samples include boundary uncertainty; unknown counters are not zero; stacked device byte counts are never summed.',
            'cgroup memory.stat file includes tmpfs/shared memory; page-cache charge may belong to the first-touch actor, not the current reader.',
            'In the formal matrix warm preload is performed by the coordinator outside the workload cgroup, while cold first reads occur inside; do not interpret cgroup memory.file/current differences as total working-set differences.',
            'Cache residency probing traverses metadata; cold means data-cold/metadata-probed, not directory/inode-cold.',
            'System Cached/Buffers are VM background, not Agent-exclusive memory; Guest-cold does not mean Host/storage caches are cold.']}


def _fixed_key(config):
    return json.dumps({key: config.get(key) for key in ('jobs', 'passes', 'corpus_sha256', 'queries_sha256',
        'permission_scope_sha256', 'repository_version', 'cpus', 'memory_max_mb', 'memory_high_mb',
        'mode', 'cgroup_layout', 'interval_ms', 'process_interval_ms', 'timing_scope', 'cpu_time_scope')}, sort_keys=True)


def aggregate(trials):
    groups, issues, outputs = {}, [], {}
    invalid_fixed, invalid_groups = set(), set()
    seen_runs = set()
    for trial in trials:
        config = trial['config']
        if trial.get('run_id') in seen_runs:
            issues.append({'code': 'DUPLICATE_RAW_RUN_ID', 'run_id': trial.get('run_id')})
            continue
        seen_runs.add(trial.get('run_id'))
        if config.get('warmup') is not False or get(trial, 'matrix', 'stage') in ('diagnostic', 'warmup'):
            continue
        if not trial['primary']['usable_for_comparison']:
            issues.append({'code': 'TRIAL_TIMING_INELIGIBLE', 'run_id': trial.get('run_id')})
            continue
        fixed = _fixed_key(config)
        if fixed in outputs and outputs[fixed] != trial['output_signature']:
            issues.append({'code': 'FIXED_WORK_OUTPUT_CHANGED', 'run_id': trial.get('run_id')})
            invalid_fixed.add(fixed)
        outputs.setdefault(fixed, trial['output_signature'])
        key = (fixed, config.get('cache'), config.get('workspace_layout'), config.get('intervention', 'none'), config.get('concurrency'))
        repetition = config.get('repetition')
        if not integer(repetition) or not integer(config.get('concurrency'), 1):
            issues.append({'code': 'INVALID_CONDITION_REPETITION', 'run_id': trial.get('run_id')})
            continue
        if 'matrix' in trial:
            block = get(trial, 'matrix', 'block')
            if not integer(block):
                issues.append({'code': 'INVALID_MATRIX_PAIR_BLOCK', 'run_id': trial.get('run_id')})
                continue
            repetition = (block, repetition)
        group = groups.setdefault(key, {})
        if repetition in group:
            issues.append({'code': 'DUPLICATE_CONDITION_REPETITION', 'run_id': trial.get('run_id')})
            invalid_groups.add(key)
            continue
        group[repetition] = trial
    conditions, comparisons = [], []
    for key, blocks in sorted(groups.items(), key=lambda row: str(row[0])):
        fixed, cache, layout, intervention, concurrency = key
        rows = list(blocks.values())
        devices = sorted({device for row in rows for device in (get(row, 'resources', 'io_by_device') or {})})
        timing_output_eligible = fixed not in invalid_fixed and key not in invalid_groups
        cache_eligible = all(get(row, 'cache_evidence', 'cache_condition_eligible') is True for row in rows)
        conditions.append({'fixed_work': json.loads(fixed), 'cache': cache, 'workspace_layout': layout,
            'intervention': intervention, 'concurrency': concurrency,
            'timing_output_eligible': timing_output_eligible, 'cache_condition_eligible': cache_eligible,
            'comparison_eligible': timing_output_eligible and cache_eligible,
            'cache_evidence_status_counts': {status: sum((get(row, 'cache_evidence', 'status') or 'NOT_COLLECTED') == status for row in rows)
                for status in sorted({get(row, 'cache_evidence', 'status') or 'NOT_COLLECTED' for row in rows})},
            'cache_maximum_start_to_release_ns': summary(
                get(row, 'cache_evidence', 'non_atomic_window', 'maximum_start_to_release_ns') for row in rows),
            'cache_maximum_root_end_to_release_ns': summary(
                get(row, 'cache_evidence', 'non_atomic_window', 'maximum_root_end_to_release_ns') for row in rows),
            'output_equivalence': 'FAIL' if fixed in invalid_fixed else 'PASS_WITHIN_FIXED_WORK_CONFIG',
            'makespan_seconds': independent_mean_summary(
                (row['primary']['seconds'] for row in rows), 'INDEPENDENT_TRIAL'),
            'total_user_cpu_seconds': summary(row['task_cpu']['user_seconds'] for row in rows),
            'total_system_cpu_seconds': summary(row['task_cpu']['system_seconds'] for row in rows),
            'per_query_trial_median_seconds': summary(row['per_query']['duration_seconds']['median'] for row in rows if row['per_query']['status'] == 'OBSERVED'),
            'per_query_trial_observed_p95_seconds': summary(row['per_query']['duration_seconds']['observed_p95'] for row in rows if row['per_query']['status'] == 'OBSERVED'),
            'query_status_counts': {status: sum(row['per_query']['status'] == status for row in rows)
                for status in sorted({row['per_query']['status'] for row in rows})},
            'root_psi_stall_us': {resource: {kind: summary(get(row, 'resources', 'psi_stall_us', resource, kind) for row in rows)
                for kind in ('some', 'full')} for resource in ('cpu', 'memory', 'io')},
            'root_io_by_device': {device: {field: summary(get(row, 'resources', 'io_by_device', device, field) for row in rows)
                for field in ('rbytes', 'wbytes', 'rios', 'wios')} for device in devices},
            'root_memory_counters': {field: summary(get(row, 'resources', 'memory_counters', field) for row in rows)
                for field in ('workingset_refault_file', 'pgscan', 'pgsteal', 'pgmajfault')},
            'root_file_cache_last_bytes': summary(get(row, 'resources', 'file_cache_gauges', 'file', 'last_bytes') for row in rows),
            'resource_status_counts': {status: sum(row['resources']['status'] == status for row in rows)
                for status in sorted({row['resources']['status'] for row in rows})}})
        if fixed in invalid_fixed or key in invalid_groups:
            continue
        for dimension, reference_value in ((4, 1), (1, 'guest-cold'), (2, 'independent'), (3, 'none')):
            if key[dimension] == reference_value:
                continue
            reference_key = list(key)
            reference_key[dimension] = reference_value
            reference = groups.get(tuple(reference_key))
            if reference is None or tuple(reference_key) in invalid_groups:
                continue
            common = sorted(set(blocks) & set(reference))
            pairs = [{'repetition': block, 'reference_seconds': reference[block]['primary']['seconds'],
                'changed_seconds': blocks[block]['primary']['seconds'],
                'change_seconds': blocks[block]['primary']['seconds'] - reference[block]['primary']['seconds'],
                'change_percent': (blocks[block]['primary']['seconds'] / reference[block]['primary']['seconds'] - 1) * 100}
                for block in common]
            paired_cache_eligible = bool(pairs) and all(
                get(trial, 'cache_evidence', 'cache_condition_eligible') is True
                for block in common for trial in (reference[block], blocks[block]))
            comparisons.append({'dimension': {1: 'cache', 2: 'workspace_layout', 3: 'intervention', 4: 'concurrency'}[dimension],
                'reference': reference_value, 'changed': key[dimension], 'cache': cache, 'workspace_layout': layout,
                'intervention': intervention, 'concurrency': concurrency, 'fixed_work': json.loads(fixed),
                'timing_output_eligible': bool(pairs), 'cache_condition_eligible': paired_cache_eligible,
                'comparison_eligible': bool(pairs) and paired_cache_eligible,
                'paired_change_seconds': paired_change_summary(pairs, 'change_seconds'),
                'paired_change_percent': paired_change_summary(pairs, 'change_percent'), 'pairs': pairs,
                'unpaired_reference_blocks': sorted(set(reference) - set(blocks)),
                'unpaired_changed_blocks': sorted(set(blocks) - set(reference)),
                'interpretation': 'negative means all fixed work finished sooner; pairing alone does not prove randomized/interleaved treatment assignment'})
    if not groups:
        issues.append({'code': 'NO_ELIGIBLE_FORMAL_PERFORMANCE_TRIALS'})
    return {'schema_version': 1, 'status': 'INCOMPLETE' if issues else 'DESCRIPTIVE_FIXED_WORK_COMPARISON',
        'primary_metric': 'ALL_FIXED_WORK_TASKS_MAKESPAN_SECONDS', 'conditions': conditions, 'comparisons': comparisons,
        'cache_condition_status': ('SUMMARY_AND_ARTIFACT_BINDING_VERIFIED'
            if conditions and all(row['cache_condition_eligible'] for row in conditions)
            else 'INVALID_OR_INCOMPLETE' if any(get(trial, 'cache_evidence', 'status') == 'INVALID_OR_INCOMPLETE' for trial in trials)
            else 'NOT_COLLECTED'),
        'cache_validation_scope': 'COMPACT_SUMMARY_AND_ARTIFACT_BINDING_ONLY; FULL_PER_FILE_RECONSTRUCTION_NOT_PERFORMED',
        'issues': issues, 'trials': trials,
        'confidence_interval_method': {'statistic': 'MEAN_NOT_MEDIAN', 'confidence_level': .95,
            'method': 'PERCENTILE_BOOTSTRAP', 'seed': BOOTSTRAP_SEED,
            'resamples': BOOTSTRAP_RESAMPLES, 'minimum_independent_units': 3,
            'sampling_unit': 'Condition: independent trial; paired change: matrix block (or standalone repetition block).',
            'nested_repetitions': 'For paired matrices, average within each outer block before resampling; equal block weight.',
            'pooled_queries': 'NO_CONFIDENCE_INTERVAL'},
        'diagnostic_trial_count': sum(get(row, 'matrix', 'stage') == 'diagnostic' for row in trials),
        'warmup_trial_count': sum(row['config'].get('warmup') is True or get(row, 'matrix', 'stage') == 'warmup' for row in trials),
        'limitations': ['No automatic causal bottleneck conclusion; compare wall clock first, then independent resource evidence.',
            'No total CPU/PSI/histogram sum or per-query confidence interval. Observed p95 is not a production SLA.',
            'Bootstrap intervals describe means, not medians, and are null below three independent trials/paired blocks; small-sample intervals remain exploratory.',
            'Timing/output eligibility is separate from cache-condition eligibility. Cache replay binds compact summaries and gzip SHA256 only, without reconstructing per-file observations or independently attesting run/boot identity.',
            'Warm/cold, shared/independent and concurrency contrasts require identical output and declared fixed work.']}


def summarize_campaign(directory):
    directory = Path(directory)
    sources = {}
    campaign = _read(directory, 'campaign.json', sources)
    if campaign.get('status') != 'COMPLETE' or not isinstance(campaign.get('trials'), list):
        raise ValueError('campaign must be COMPLETE with trial index')
    trials = []
    for entry in campaign['trials']:
        if not isinstance(entry, dict) or not isinstance(entry.get('path'), str) or Path(entry['path']).is_absolute() or '..' in Path(entry['path']).parts:
            raise ValueError('unsafe campaign trial path')
        path = (directory / entry['path']).resolve()
        path.relative_to(directory.resolve())
        trial = summarize_trial(path)
        for key in ('mode', 'concurrency', 'repetition', 'warmup'):
            if trial['config'].get(key) != entry.get(key):
                raise ValueError('trial condition differs from campaign: ' + key)
        if (trial['run_id'] != entry.get('run_id') or not integer(entry.get('makespan_ns'), 1)
                or trial['primary']['seconds'] != entry['makespan_ns'] / 1e9):
            raise ValueError('trial identity/timing differs from campaign index')
        trial['campaign_sources'] = sources
        trials.append(trial)
    return trials


def summarize_matrix(path):
    path = Path(path)
    sources = {}
    matrix = _read(path.parent, path.name, sources)
    if matrix.get('schema_version') != 1 or matrix.get('status') != 'COMPLETE' or not isinstance(matrix.get('campaigns'), list):
        raise ValueError('matrix must be COMPLETE schema 1 with campaign entries')
    seen, trials = set(), []
    for entry in matrix['campaigns']:
        if (not isinstance(entry, dict) or not isinstance(entry.get('path'), str)
                or Path(entry['path']).is_absolute() or '..' in Path(entry['path']).parts
                or not integer(entry.get('block')) or entry.get('stage') not in ('performance', 'diagnostic', 'warmup')
                or not isinstance(entry.get('condition'), dict)):
            raise ValueError('matrix entry requires safe relative campaign path, block, stage and condition')
        directory = (path.parent / entry['path']).resolve()
        directory.relative_to(path.parent.resolve())
        if directory in seen:
            raise ValueError('matrix must not reuse the same campaign as an independent repetition')
        seen.add(directory)
        condition = entry['condition']
        if 'block' in condition and (not integer(condition['block']) or condition['block'] != entry['block']):
            raise ValueError('matrix condition block differs from matrix entry block')
        for trial in summarize_campaign(directory):
            # block identifies the outer paired repetition, not the child run's
            # config. Every other declared plan field must be present in raw
            # config; even an unknown field set to null cannot be ignored.
            if any(key not in trial['config'] or
                   json.dumps(trial['config'][key], sort_keys=True, allow_nan=False) !=
                   json.dumps(value, sort_keys=True, allow_nan=False)
                   for key, value in condition.items() if key != 'block'):
                raise ValueError('matrix condition differs from raw trial configuration')
            expected_warmup = {'performance': False, 'warmup': True}.get(entry['stage'])
            if expected_warmup is not None and trial['config'].get('warmup') is not expected_warmup:
                raise ValueError('matrix stage differs from raw trial warmup flag')
            trial['matrix'] = {'block': entry['block'], 'stage': entry['stage'], 'condition': entry['condition'],
                               'campaign': entry['path'], 'source': sources}
            trials.append(trial)
    return trials


def _makespan_pivot(conditions, fmt):
    """Present condition medians without merging profiles or duplicate cells."""
    groups = {}
    for row in conditions:
        key = json.dumps({'fixed_work': row['fixed_work'], 'intervention': row['intervention']}, sort_keys=True)
        groups.setdefault(key, []).append(row)
    lines = ['## 先看整批任务完成时间', '',
        '每格为整批任务完成秒数的中位数，n 是正式重复轮数；并发列表示同时执行上限。未测不补成 0 秒。不同任务配置、资源档、CPU、内存限制或干预分别成表，不合并。', '',
        '“不合格”仍保留真实秒数，但不能用于合格的受控条件比较；没有缓存证明不等于没有实际耗时。']
    def escape(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    def cell(rows):
        if not rows:
            return '—（n=0，未测）'
        values = []
        for row in rows:
            value = '{}（n={}'.format(fmt(get(row, 'makespan_seconds', 'median')), get(row, 'makespan_seconds', 'n'))
            reasons = []
            if row.get('timing_output_eligible') is not True:
                reasons.append('输出不一致' if row.get('output_equivalence') == 'FAIL' else '时间／输出／重复块未合格')
            if row.get('cache_condition_eligible') is not True:
                reasons.append('缓存未验明')
            if row.get('comparison_eligible') is not True and not reasons:
                reasons.append('比较资格未通过')
            if reasons:
                value += '；不合格：' + '、'.join(reasons)
            values.append(value + '）')
        # Duplicate aggregated conditions are not new independent trials. Keep
        # both original medians/n, never average medians or add their n here.
        return ('不合格：重复条件，未合并：' if len(rows) > 1 else '') + '；'.join(values)
    for index, (key, rows) in enumerate(sorted(groups.items()), 1):
        fixed = rows[0]['fixed_work']
        digest = hashlib.sha256(key.encode()).hexdigest()[:12]
        lines += ['', '### 对照组 {}：{}／干预 {}（配置 {}）'.format(index,
            escape(fixed.get('mode')), escape(rows[0]['intervention']), digest), '',
            '固定任务数 {}；CPU {}；内存 high/max {} / {} MiB。完整 fixed_work 保留在 JSON。'.format(
                escape(fixed.get('jobs')), escape(fixed.get('cpus')),
                escape(fixed.get('memory_high_mb')), escape(fixed.get('memory_max_mb'))), '',
            '| 缓存 | 文件布局 | 并发 1：秒 | 并发 2：秒 | 并发 4：秒 | 并发 8：秒 |',
            '|---|---|---:|---:|---:|---:|']
        caches = sorted({row['cache'] for row in rows}, key=lambda value: (value not in ('guest-cold', 'warm'), str(value)))
        layouts = ['shared', 'independent'] + sorted({row['workspace_layout'] for row in rows} - {'shared', 'independent'}, key=str)
        for cache in caches:
            for layout in layouts:
                columns = [escape(cache), {'shared': '共享', 'independent': '独立'}.get(layout, escape(layout))]
                columns += [cell([row for row in rows if row['cache'] == cache
                    and row['workspace_layout'] == layout and type(row['concurrency']) is int
                    and row['concurrency'] == concurrency]) for concurrency in (1, 2, 4, 8)]
                lines.append('| ' + ' | '.join(columns) + ' |')
        other = [row['concurrency'] for row in rows if type(row['concurrency']) is not int or row['concurrency'] not in (1, 2, 4, 8)]
        if other:
            lines += ['', '其他并发值 {} 不在本主表四列中，仍逐条保留在下面的详细结果。'.format(escape(other))]
    return lines


def markdown(report):
    def fmt(value, digits=3):
        return '未知' if value is None else ('{:.%df}' % digits).format(value)
    def interval(value):
        return '未知' if value is None else '[{}, {}]'.format(fmt(value[0]), fmt(value[1]))
    def condition_label(row):
        return '{}/{}/{}/{}/c{}'.format(row['fixed_work'].get('mode'), row['cache'],
            row['workspace_layout'], row['intervention'], row['concurrency'])
    lines = ['# 多 Agent 大仓库搜索：先看全部任务多久完成', '',
        '主指标是 release 放行到本轮全部任务退出被回收所需秒数。不是单个任务耗时，也不是累计 CPU 时间。']
    lines += ['', *_makespan_pivot(report['conditions'], fmt), '', '## 详细结果', '',
        'CPU、PSI、缺页、文件缓存和逐设备读取量分别提供线索，不能加成“耗时分解”。', '',
        '| 资源档 | 缓存 | 文件布局 | 干预 | 并发 | 正式轮数 | 全部完成中位数 s | 观测 p95 s | user CPU s | system CPU s | 时间／输出 | 缓存条件 |',
        '|---|---|---|---|---:|---:|---:|---:|---:|---:|---|---|']
    for row in report['conditions']:
        values = [row['fixed_work'].get('mode'), row['cache'], row['workspace_layout'], row['intervention'], row['concurrency'], row['makespan_seconds']['n'],
                  fmt(row['makespan_seconds']['median']), fmt(row['makespan_seconds']['observed_p95']),
                  fmt(row['total_user_cpu_seconds']['median']), fmt(row['total_system_cpu_seconds']['median']),
                  '可比较' if row['timing_output_eligible'] else '否：输出或重复块有问题',
                  '摘要＋哈希绑定通过' if row['cache_condition_eligible'] else '未采集或未验明']
        lines.append('| ' + ' | '.join(str(value).replace('|', '\\|') for value in values) + ' |')
    lines += ['', '## 单因素配对比较', '',
              '95% bootstrap 区间只对应均值，不是中位数的区间。条件耗时以独立 trial 为单位；配对变化以外层矩阵 block（无矩阵时为配对 repetition）为单位。同一 block 内先求均值，再等权重采样；独立单位少于 3 个时区间为未知。每轮内的多次查询不作为独立样本。', '',
              '缓存未采集或未验明时，仍保留真实耗时及描述性差值，但不能据此声称已控制 warm/cold 条件。', '',
              '| 条件（改后） | 改变项目 | 参照 → 改后 | 配对数 | CI 独立块数 | 全部完成差值中位数 s | 配对变化中位数 % | 变化均值 % | 均值变化 95% CI % | 缓存条件 |',
              '|---|---|---|---:|---:|---:|---:|---:|---:|---|']
    for row in report['comparisons']:
        change = row['paired_change_percent']
        lines.append('| {} | {} | {} → {} | {} | {} | {} | {} | {} | {} | {} |'.format(
            condition_label(row), row['dimension'], row['reference'], row['changed'], change['n'], change['independent_n'],
            fmt(row['paired_change_seconds']['median']), fmt(change['median']),
            fmt(change['mean']), interval(change['mean_ci95_bootstrap']),
            '摘要绑定通过' if row['cache_condition_eligible'] else '未验明'))
    lines += ['', '### 缓存证明的边界', '',
        '这里只核对 compact 摘要、任务工作区／inventory 绑定、放行前时间窗与 gzip 文件 SHA256；没有解压并逐条独立重建文件观测（FULL_PER_FILE_RECONSTRUCTION_NOT_PERFORMED），也没有独立证明采集源可信。旧数据没有证明时为 NOT_COLLECTED，不补成通过。', '',
        '逐 root 的开始／结束到 release 年龄保存在 trials[].cache_evidence.roots；non_atomic_window 同时保留最早观测开始、最老 root 结束和最后 root 结束到放行的间隔。最后 root 间隔很短，不代表其他 root 的观测同样新；这些都是顺序观测，不是放行时的原子缓存快照。']
    lines += ['', '## 同一条件下的资源线索（独立指标，不能相加）', '',
        '下表每格是各轮原始包围区间增量的中位数；逐字段有效轮数和完整度见 JSON，缺项时仍保留其他已知指标。未知不补零。PSI 是 cgroup 受到资源压力的时间，不是任务精确损失。', '',
        '缓存记账口径：正式矩阵的 warm 预读由协调器在 workload cgroup 外完成，页面首次触碰可能记账到外部；cold 则由 workload 首次读取并在内部记账。因此 warm/cold 的 cgroup memory.file 和 memory.current 不能直接解释为全部工作集大小。每轮原始说明保存在 cache_semantics.memory_charge_scope（来自 profile-run.json 的 cache_memory_charge_scope）。', '',
        '冷缓存口径：缓存驻留 probe 会遍历文件 metadata，本轮应称 data-cold / metadata-probed，而不是目录项、inode、Guest、Host 与物理存储各层都完全冷。', '',
        '| 资源档／缓存／布局／干预／并发 | CPU PSI some ms | 内存 PSI some ms | I/O PSI some ms | file refault | pgscan | pgsteal | cgroup file 末值 MiB |',
        '|---|---:|---:|---:|---:|---:|---:|---:|']
    for row in report['conditions']:
        label = condition_label(row)
        psi = [get(row, 'root_psi_stall_us', kind, 'some', 'median') for kind in ('cpu', 'memory', 'io')]
        values = [fmt(value / 1000 if value is not None else None) for value in psi]
        values += [fmt(get(row, 'root_memory_counters', field, 'median')) for field in ('workingset_refault_file', 'pgscan', 'pgsteal')]
        file_bytes = row['root_file_cache_last_bytes']['median']
        values.append(fmt(file_bytes / 1024 ** 2 if file_bytes is not None else None))
        lines.append('| ' + label + ' | ' + ' | '.join(values) + ' |')
    lines += ['', '### 逐设备读取（不能跨层求和）', '',
        '| 条件 | major:minor | rbytes 增量中位数 MiB | 有效轮数 |', '|---|---|---:|---:|']
    devices_observed = False
    for row in report['conditions']:
        label = condition_label(row)
        for device, counters in row['root_io_by_device'].items():
            devices_observed = True
            value = counters['rbytes']['median']
            lines.append('| {} | {} | {} | {} |'.format(label, device,
                fmt(value / 1024 ** 2 if value is not None else None), counters['rbytes']['n']))
    if not devices_observed:
        lines.append('| 未记录可比较的逐设备计数；不是零 I/O 的证明 | — | 未知 | 0 |')
    lines += ['', '负值表示全部固定工作更早结束，不等于任意 Agent 的单次查询都更快；每轮查询相关，不能当作独立重复。', '',
        '## 怎样查原因', '', '打开 wallclock.json 的 trials：', '',
        '- primary：全部任务的真实 makespan；per_query：每次查询的中位数、观测 p95 与扫描／缓存命中区别。',
        '- task_cpu：所有任务累计 user/system CPU；不是墙钟时间百分比分账。',
        '- resources.psi_stall_us：根 cgroup 的 CPU／内存／I/O some/full 各自增量；它们可能重叠，不能相加。',
        '- resources.io_by_device：每个 major:minor 的读取量，不把虚拟设备与底层设备相加。新出现设备缺前值显示 null，不补零。',
        '- resources.memory_counters：refault、pgscan、pgsteal；file_cache_gauges 是 cgroup 记账缓存，system_background_file_cache 是全机背景，二者不是某个 Agent 独享工作集。',
        '- resources.boundary：实际最邻近包围采样的起止及边界误差。短任务不会被伪造出精确资源分解。', '',
        '即使任务时间可靠，资源采样仍可能不完整。Guest 清缓存不代表 Host 或物理设备缓存冷。真正的根因还需针对候选原因做单因素干预并验证整体完成时间。', '',
        '状态：' + report['status'] + '。缺项与全部原始来源摘要见 JSON。']
    if report.get('diagnostic_trial_count'):
        lines += ['', '另有 {} 轮独立 diagnostic：只用于查原因，不混入上表 performance 墙钟统计。'.format(report['diagnostic_trial_count'])]
    if report.get('warmup_trial_count'):
        lines += ['', '另有 {} 轮 warmup：仅用于预热，不混入上表 performance 墙钟统计。'.format(report['warmup_trial_count'])]
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--campaign', type=Path, action='append')
    inputs.add_argument('--matrix', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    trials = summarize_matrix(args.matrix) if args.matrix else [trial for directory in args.campaign for trial in summarize_campaign(directory)]
    report = aggregate(trials)
    report['analyzer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    for name, content in (('wallclock.json', json.dumps(report, ensure_ascii=False, indent=2) + '\n'),
                          ('wallclock.md', markdown(report))):
        with (args.output_dir / name).open('x', encoding='utf-8') as stream:
            stream.write(content)


if __name__ == '__main__':
    main()
