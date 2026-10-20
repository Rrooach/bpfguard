#!/usr/bin/env python3
"""Independently replay fixed search work and small collector bindings.

Reads every real stdout, job, query span and lifecycle record. Deliberately
does not read events.bin, cache-proof gzip contents or sampler time series.
Those require separate raw event/cache/resource analysis, not a green shortcut.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import random
import stat

import verify_large_matrix as core


_SPEC = importlib.util.spec_from_file_location('access_matrix_collector_contract',
    Path(__file__).resolve().parent.parent / 'file-profile' / 'access_analyze.py')
ACCESS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ACCESS)
PLAN_FIELDS = {'cache', 'workspace_layout', 'concurrency', 'file_access_mode',
               'block', 'warmup', 'intervention'}
BINARY_DIGESTS = core.BINARY_FIELDS | {'large_search_sha256', 'file_access_sha256', 'file_access_object_sha256'}
CONCURRENCIES = (2, 4, 6, 8)
CACHES = ('warm', 'guest-cold')
LAYOUTS = ('shared', 'independent')
MODES = ('sampler', 'access')
FIXED_QUERIES = ['EXPORT_SYMBOL_GPL', 'kmalloc(',
    'unlikely_profile_absent_20261015_93f712', 'spin_lock(']
RUNTIME_FILES = {'matrix_sha256': 'access_search.py', 'runner_sha256': 'run.py',
    'large_search_sha256': 'large_search.py', 'cache_probe_sha256': 'cache_probe.py',
    'sampler_sha256': 'allox-load-sampler', 'file_access_sha256': 'allox-file-access',
    'file_access_object_sha256': 'file_access_kprobe.bpf.o'}


def expected_schedule(seed, repetitions=5, concurrencies=CONCURRENCIES,
                      caches=CACHES, layouts=LAYOUTS, modes=MODES):
    rng, result = random.Random(seed), []
    for block in range(repetitions):
        rows = [dict(cache=c, workspace_layout=w, concurrency=n, file_access_mode=m,
                     block=block, warmup=False, intervention='none')
                for c, w, n, m in itertools.product(caches, layouts, concurrencies, modes)]
        rng.shuffle(rows)
        result.extend(rows)
    return result


def validate_manifest(matrix, expected_boot_id=None, expected_seed=101646):
    core.require(type(matrix.get('schema_version')) is int and matrix['schema_version'] == 1
        and matrix.get('status') == 'COMPLETE' and matrix.get('output_equivalence') == 'PASS',
        'one COMPLETE schema-1 campaign with PASS outputs required')
    core.require(type(matrix.get('seed')) is int and matrix['seed'] == expected_seed,
                 'campaign randomization seed differs')
    schedule = matrix.get('schedule')
    core.require(core.equal(schedule, expected_schedule(expected_seed)),
                 'full 160-case independently rebuilt randomized schedule differs')
    core.require(isinstance(matrix.get('campaigns'), list) and len(matrix['campaigns']) == 160,
                 'exactly 160 distinct completed campaigns required')
    core.require(core.equal(matrix.get('jobs'), 8) and core.equal(matrix.get('passes'), 1)
        and core.equal(matrix.get('queries'), FIXED_QUERIES) and core.equal(matrix.get('cpus'), [0, 1, 2, 3])
        and core.equal(matrix.get('measurement_coordinator_sampler_collector_cpus'), [4, 5])
        and core.equal(matrix.get('measurement_modes'), list(MODES)), 'fixed workload/CPU/mode scope differs')
    boot = matrix.get('boot_id')
    core.require(isinstance(boot, str) and bool(boot) and (expected_boot_id is None or boot == expected_boot_id),
                 'boot identity differs or is missing')
    source = matrix.get('source')
    core.require(isinstance(source, dict) and source.get('commit') == '519a81750493f6fb35ee282ba3ff5bafdd58b81b'
        and core.equal(source.get('regular_files'), 95989) and core.equal(source.get('regular_file_bytes'), 1641397655)
        and core.digest(source.get('archive_sha256')) and core.digest(matrix.get('source_inventory_sha256')),
        'fixed immutable source declaration differs')
    core.require(matrix.get('file_access_backend') == 'kprobe-tracefs'
        and core.equal(matrix.get('collector_budget'), {'ring_bytes': 268435456, 'max_bytes': 2147483648, 'max_seconds': 1200}),
        'formal collector backend/budget differs')
    binaries = matrix.get('binaries')
    core.require(isinstance(binaries, dict) and set(binaries) == BINARY_DIGESTS | {'file_access_backend'}
        and all(core.digest(binaries[key]) for key in BINARY_DIGESTS)
        and binaries['file_access_backend'] == matrix['file_access_backend'], 'binary/source digest declarations invalid')
    core.require(matrix.get('source_integrity') == 'PARTICIPATING_ROOTS_POST_CAMPAIGN_REHASHED_IDENTICAL'
        and isinstance(matrix.get('participating_source_roots'), list)
        and len(matrix['participating_source_roots']) == 9
        and len(set(matrix['participating_source_roots'])) == 9,
        'producer post-campaign nine-root source check claim missing')
    return schedule


def verify_work_details(reader, directory, profile, plan, binding):
    """Additional checks beyond the reused raw-output/query/lifecycle replay."""
    cfg = profile['config']
    for field, wanted in (('file_access_mode', plan['file_access_mode']),
        ('file_access_backend', binding['file_access_backend']),
        ('collector_ring_bytes', binding['collector_budget']['ring_bytes']),
        ('mode', 'sampler'), ('cgroup_layout', 'shared-leaf'), ('interval_ms', 100),
        ('process_interval_ms', 0), ('memory_max_mb', 0), ('memory_high_mb', 0),
        ('calibration_kind', None), ('sample_threads', False)):
        core.require(core.equal(cfg.get(field), wanted), 'formal raw configuration differs: ' + field)
    identities, windows = set(), []
    results = {row['task_id']: row for row in profile['results']}
    for task in profile['tasks']:
        task_id, identity = task['task_id'], task['process']
        pair = identity['pid'], identity['start_ticks']
        core.require(pair not in identities, 'duplicate worker process instance')
        identities.add(pair)
        prepared = task.get('preparation')
        ready = reader.json(core.child(directory, task_id + '-ready.json'))
        core.require(isinstance(prepared, dict) and core.equal(ready, prepared)
            and core.equal(prepared.get('process'), identity) and prepared.get('boot_id') == profile['boot_id']
            and core.integer(prepared.get('monotonic_ns'), 1) and prepared['monotonic_ns'] < profile['release_ns'],
            'worker stopped preflight/ready instance differs')
        row = results[task_id]
        for baseline, lifetime, measured in (('rusage_user_usec', 'lifetime_user_usec', 'user_usec'),
                                           ('rusage_system_usec', 'lifetime_system_usec', 'system_usec')):
            core.require(core.integer(prepared.get(baseline)) and core.integer(row.get(lifetime))
                and row[lifetime] - prepared[baseline] == row[measured], 'worker CPU preflight subtraction differs')
        stats = reader.json(core.child(directory, task_id + '-statistics.json'))
        core.require(core.equal(row.get('query_statistics'), stats), 'profile query-statistics copy differs from raw file')
        begin = profile['release_ns'] + row['queue_ns']
        end = profile['release_ns'] + row['completion_latency_ns']
        core.require(begin < end, 'nonpositive real task interval')
        windows += [(begin, 1), (end, -1)]
    active, maximum = 0, 0
    for _, change in sorted(windows, key=lambda item: (item[0], item[1])):
        active += change
        core.require(active >= 0, 'negative active task count')
        maximum = max(maximum, active)
    core.require(active == 0 and maximum <= plan['concurrency'], 'actual task intervals exceed concurrency cap')
    return {'maximum_overlapping_worker_intervals': maximum,
            'worker_process_instances': len(identities), 'raw_worker_ready_files_checked': len(identities)}


def metadata_health(meta, final):
    """Counter consistency only; deliberately not raw event-stream verification."""
    problems = Counter(ACCESS.tracefs_issues(meta, final))
    health = final.get('health')
    if (not isinstance(health, dict) or set(health) != ACCESS.HEALTH
            or any(not core.integer(value) for value in health.values())):
        problems['MISSING_OR_INVALID_HEALTH_COUNTERS'] += 1
    else:
        for key, value in health.items():
            if value and key != 'nested_hooks':
                problems['COLLECTOR_' + key] += value
    for field in ('pending_syscalls', 'pending_vfs_calls', 'pending_fault_calls', 'pending_mm_fault_calls',
                  'parser_errors', 'sequence_errors', 'cap_discarded', 'write_errors'):
        if not core.integer(final.get(field)) or final[field]:
            problems['NONZERO_OR_MISSING_' + field] += 1
    for field in ('write_error', 'flush_error', 'hash_error'):
        if field not in final or final[field] is not None:
            problems['ERROR_OR_MISSING_' + field] += 1
    if final.get('timed_out') is not False:
        problems['TIMEOUT_OR_UNKNOWN'] += 1
    if final.get('observation_health') != 'COMPLETE_FOR_SELECTED_HOOKS':
        problems['DECLARED_INCOMPLETE_OR_UNKNOWN'] += 1
    names, ids = set(), set()
    programs = final.get('programs')
    if not isinstance(programs, list):
        problems['PROGRAM_COUNTERS_MISSING'] += 1
        programs = []
    for program in programs:
        name, identifier = program.get('name'), program.get('id')
        if (name in names or identifier in ids or not isinstance(name, str)
                or not core.integer(identifier, 1) or not core.integer(program.get('recursion_misses'))):
            problems['PROGRAM_COUNTERS_INVALID'] += 1
            continue
        names.add(name)
        ids.add(identifier)
        if program['recursion_misses']:
            problems['PROGRAM_RECURSION_MISSES'] += program['recursion_misses']
    if names != ACCESS.PROGRAMS:
        problems['SELECTED_PROGRAM_SET_DIFFERS'] += 1
    cpus, seen, emitted = final.get('cpus'), set(), 0
    if not isinstance(cpus, list):
        problems['CPU_COUNTERS_MISSING'] += 1
        cpus = []
    for cpu in cpus:
        index = cpu.get('cpu')
        if (not core.integer(index) or index in seen
                or any(not core.integer(cpu.get(field)) for field in ('attempted', 'emitted', 'ring_drops'))):
            problems['CPU_COUNTERS_INVALID'] += 1
            continue
        seen.add(index)
        emitted += cpu['emitted']
        if cpu['attempted'] != cpu['emitted'] + cpu['ring_drops']:
            problems['CPU_ATTEMPTED_EMITTED_DROP_TOTAL_DIFFERS'] += 1
        if cpu['ring_drops']:
            problems['CPU_RING_DROPS'] += cpu['ring_drops']
    if (not core.integer(meta.get('possible_cpus'), 1) or seen != set(range(meta['possible_cpus']))
            or not core.integer(final.get('persisted_records')) or emitted != final['persisted_records']):
        problems['CPU_EMITTED_PERSISTED_TOTAL_DIFFERS'] += 1
    return {'status': 'INCOMPLETE' if problems else 'DECLARED_COMPLETE_METADATA_CONSISTENT',
        'issues': dict(problems), 'scope': 'SAVED_COUNTERS_AND_IDENTITIES_ONLY; RAW_EVENT_BYTES_NOT_READ'}


def verify_capture(reader, directory, profile_path, profile, plan, binding):
    capture_path = directory / 'capture.json'
    capture = reader.json(capture_path)
    core.require(capture.get('mode') == plan['file_access_mode'] and capture.get('boot_id') == profile['boot_id']
        and capture.get('profile_run_id') == profile['run_id']
        and capture.get('profile_run_sha256') == reader.sha(profile_path)
        and capture.get('profile_sha256') == reader.sha(profile_path)
        and capture.get('release_ns') == profile['release_ns'] and capture.get('end_ns') == profile['end_ns']
        and capture.get('makespan_ns') == profile['makespan_ns']
        and core.equal(capture.get('inner_root_cgroup'), profile['root_cgroup'])
        and capture.get('file_access_backend') == binding['file_access_backend']
        and capture.get('collector_ring_bytes') == binding['collector_budget']['ring_bytes'],
        'capture does not bind exact task run, profile SHA, mode, backend, ring and window')
    expected_profile = str(profile_path.relative_to(directory))
    core.require(capture.get('profile_path') == expected_profile, 'capture profile relative path differs')
    parent = capture.get('cgroup')
    core.require(core.cgroup(parent) and Path(profile['root_cgroup']['path']).parent == Path(parent['path'])
        and parent['device'] == profile['root_cgroup']['device']
        and parent['inode'] != profile['root_cgroup']['inode'], 'capture is not the execution cgroup direct parent')
    if plan['file_access_mode'] == 'sampler':
        core.require(capture.get('status') == 'NOT_ENABLED' and not (directory / 'file-access').exists(),
                     'sampler-only run unexpectedly has an enabled collector')
        return {'status': 'NOT_ENABLED', 'capture_sha256': reader.sha(capture_path)}
    collector = directory / 'file-access'
    meta, final = reader.json(collector / 'meta.json'), reader.json(collector / 'final.json')
    ACCESS.bind_collector(meta, final, profile, {'sha256': reader.sha(profile_path)}, capture)
    core.require(core.equal(capture.get('final'), final) and capture.get('final_sha256') == reader.sha(collector / 'final.json')
        and capture.get('binary_sha256') == binding['binaries']['file_access_sha256']
        and capture.get('bpf_sha256') == binding['binaries']['file_access_object_sha256']
        and meta.get('binary_sha256') == binding['binaries']['file_access_sha256']
        and meta.get('bpf_sha256') == binding['binaries']['file_access_object_sha256']
        and meta.get('backend') == binding['file_access_backend']
        and meta.get('ring_bytes') == binding['collector_budget']['ring_bytes']
        and meta.get('max_bytes') == binding['collector_budget']['max_bytes']
        and core.equal(capture.get('capture_budget'), binding['collector_budget'])
        and capture.get('returncode') == 0 and capture.get('finalized') is True
        and core.equal(capture.get('cpu_affinity'), [4, 5]), 'collector source/budget/capture binding differs')
    core.require(core.integer(capture.get('started_monotonic_ns'), 1)
        and capture['started_monotonic_ns'] <= capture['ready_received_monotonic_ns']
        and capture.get('hash_scope') == meta.get('hash_scope') == 'DETACHED_DRAINED_FSYNCED_FD_PASS',
        'collector startup or hash-scope binding differs')
    artifact = core.child(collector, 'events.bin')
    attrs = artifact.stat()
    core.require(stat.S_ISREG(attrs.st_mode) and core.integer(final.get('bytes'))
        and core.integer(final.get('persisted_records')) and attrs.st_size == final['bytes']
        and final['bytes'] == final['persisted_records'] * 192
        and final['bytes'] <= binding['collector_budget']['max_bytes'] and core.digest(final.get('events_sha256')),
        'opaque event artifact length/declared count/digest format differs')
    health = metadata_health(meta, final)
    core.require(capture.get('status') == ('COMPLETE_FOR_SELECTED_HOOKS'
        if final.get('observation_health') == 'COMPLETE_FOR_SELECTED_HOOKS' and capture.get('issues') == []
        else 'INCOMPLETE'), 'capture health does not preserve declared collector status')
    return {**health, 'producer_status': final.get('observation_health'),
        'capture_status': capture.get('status'), 'meta_sha256': reader.sha(collector / 'meta.json'),
        'final_sha256': reader.sha(collector / 'final.json'), 'capture_sha256': reader.sha(capture_path),
        'event_artifact': {'path': str(artifact), 'bytes': attrs.st_size,
            'declared_records': final['persisted_records'], 'declared_sha256': final['events_sha256'],
            'validation': 'STAT_LENGTH_ONLY; BYTES_SHA256_AND_RECORDS_NOT_REPLAYED'},
        'backend': meta['backend'], 'ring_bytes': meta['ring_bytes'], 'hash_scope': meta['hash_scope']}


def verify_entries(reader, root, matrix, plans):
    """Bounded reusable replay; caller enforces formal 160-case dimensions."""
    binding = {**matrix, 'measurement_mode': 'sampler'}
    core.require(len(matrix['campaigns']) == len(plans), 'schedule and campaign lengths differ')
    by_mode = {mode: {} for mode in MODES}
    seen, directories, runs, all_outputs, fixed = set(), set(), [], {}, None
    roots = set()
    for index, (entry, plan) in enumerate(zip(matrix['campaigns'], plans)):
        core.require(set(plan) == PLAN_FIELDS, 'plan shape differs')
        wanted_condition = {key: value for key, value in plan.items() if key != 'block'}
        wanted_condition.update(mode='sampler', repetition=0, file_access_backend=matrix['file_access_backend'],
                                collector_ring_bytes=matrix['collector_budget']['ring_bytes'])
        core.require(entry.get('path') == '%03d-r%d' % (index, plan['block'])
            and entry.get('stage') == 'performance' and core.equal(entry.get('block'), plan['block'])
            and core.equal(entry.get('condition'), wanted_condition), 'campaign index/order/condition differs')
        directory = core.child(root, entry['path'])
        core.require(directory not in directories, 'evidence directory counted twice')
        directories.add(directory)
        expected = by_mode[plan['file_access_mode']]
        record = core.verify_campaign(reader, directory, binding, plan, expected, seen)
        campaign = reader.json(directory / 'campaign.json')
        trial = core.child(directory, campaign['trials'][0]['path'])
        profile_path = trial / 'profile-run.json'
        profile = reader.json(profile_path)
        record['work_details'] = verify_work_details(reader, trial, profile, plan, binding)
        normalized_fixed = {key: value for key, value in expected['fixed'].items() if key != 'file_access_mode'}
        if fixed is None:
            fixed = normalized_fixed
        core.require(core.equal(fixed, normalized_fixed), 'sampler/access fixed scope differs')
        for query_index, output in expected['outputs'].items():
            all_outputs.setdefault(query_index, output)
            core.require(core.equal(all_outputs[query_index], output), 'actual stdout differs across sampler/access modes')
        for task in profile['tasks']:
            job = reader.json(trial / (task['task_id'] + '-job.json'))
            roots.add(job['corpus'])
        if runs:
            core.require(record['release_ns'] >= runs[-1]['end_ns'], 'task execution windows overlap or are reordered')
        stats = reader.json(trial / 'load/load-sampler-stats.json')
        gaps = {key: stats.get(key) for key in ('read_errors', 'missed_ticks')
                if not core.integer(stats.get(key)) or stats[key] != 0}
        record.update(index=index, block=plan['block'], condition=plan,
            sampler_health={'status': 'INCOMPLETE' if gaps else 'DECLARED_NO_READ_ERRORS_OR_MISSED_TICKS',
                'gaps': gaps, 'scope': 'SMALL_STATS_AND_REGISTRY_ONLY; TIME_SERIES_NOT_REPLAYED'},
            file_access=verify_capture(reader, directory, profile_path, profile, plan, binding))
        runs.append(record)
        # Real stdout bytes have been hashed and compared; retain receipts, not
        # all 1,280 payloads in RAM. No heavy artifact gets read by this tool.
        reader.cache.clear()
    core.require(set(matrix['participating_source_roots']) == roots, 'claimed input roots differ from actual raw jobs')
    return runs, fixed, all_outputs


def verify(matrix_path, expected_boot_id=None, expected_seed=101646, runtime_dir=None):
    reader = core.Evidence()
    result = {'schema_version': 1, 'verified': False, 'status': 'FAILED', 'issues': [], 'runs': [],
        'scope': {'verified': 'FORMAL_RANDOMIZED_SCHEDULE_FIXED_WORK_EIGHT_TASKS_QUERY_SPANS_LIFECYCLE_REAL_STDOUT_AND_COLLECTOR_METADATA_BINDINGS',
            'events_bin': 'STAT_LENGTH_ONLY; NO_BYTE_HASH_OR_RECORD_REPLAY',
            'cache_gzip': 'NOT_READ_OR_DECOMPRESSED; COMPACT_REFERENCES_ONLY',
            'sampler_time_series': 'NOT_READ_OR_REPLAYED; HEALTH_STATS_AND_REGISTRY_ONLY',
            'source_contents': 'PRODUCER_POST_CAMPAIGN_NINE_ROOT_REHASH_CLAIM_BOUND; NO_INDEPENDENT_SOURCE_REHASH',
            'binary_execution': 'NO_REEXECUTION_OR_ATTESTATION; OPTIONAL_BUNDLED_RUNTIME_BYTE_HASHES'},
        'external_bindings': {'expected_boot_id': expected_boot_id, 'expected_seed': expected_seed},
        'trust_boundary': 'Cooperative diagnostic artifacts; hashes bind bytes, not sensor truth or exclusive attribution.'}
    try:
        matrix_path = Path(matrix_path).resolve(strict=True)
        matrix = reader.json(matrix_path)
        plans = validate_manifest(matrix, expected_boot_id, expected_seed)
        if runtime_dir is not None:
            runtime_dir = Path(runtime_dir).resolve(strict=True)
            for field, name in RUNTIME_FILES.items():
                core.require(reader.sha(core.child(runtime_dir, name)) == matrix['binaries'][field],
                             'bundled frozen runtime SHA256 differs: ' + field)
            result['runtime_validation'] = 'BUNDLED_SEVEN_ARTIFACT_BYTE_HASHES_VERIFIED; GUEST_GREP_DECLARATION_ONLY'
        else:
            result['runtime_validation'] = 'PRODUCER_DIGEST_DECLARATIONS_ONLY; NO_RUNTIME_DIRECTORY_SUPPLIED'
        runs, fixed, outputs = verify_entries(reader, matrix_path.parent, matrix, plans)
        dimensions = {'sampler': dict(Counter(row['sampler_health']['status'] for row in runs)),
            'file_access_metadata': dict(Counter(row['file_access']['status'] for row in runs)),
            'event_stream_replay': 'NOT_PERFORMED_BY_THIS_VERIFIER'}
        incomplete = any(row['sampler_health']['status'] == 'INCOMPLETE' or
                         row['file_access']['status'] == 'INCOMPLETE' for row in runs)
        result.update(verified=True,
            status='VERIFIED_BINDINGS_WITH_INCOMPLETE_DIMENSIONS' if incomplete else 'VERIFIED_WITH_DECLARED_SCOPE',
            runs=runs, total_trials=len(runs), unique_runs=len({row['run_id'] for row in runs}),
            actual_stdout_files_hashed=len(runs) * 8, logical_queries_verified=len(runs) * 8,
            matrix_sha256=reader.sha(matrix_path), full_fixed_config=fixed, dimensions=dimensions,
            query_outputs={str(key): list(value) for key, value in sorted(outputs.items())})
    except (ValueError, OSError, TypeError, KeyError, IndexError, AttributeError, OverflowError) as error:
        result['issues'].append({'code': 'ACCESS_MATRIX_VERIFICATION_FAILED', 'detail': str(error)})
    result['read_artifacts'] = reader.receipts
    result['verifier_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result['dependencies'] = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
        for name, path in (('raw_search_contract', core.__file__), ('collector_metadata_contract', ACCESS.__file__))}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', required=True, type=Path)
    parser.add_argument('--expected-boot-id')
    parser.add_argument('--expected-seed', type=int, default=101646)
    parser.add_argument('--runtime-dir', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.absolute()
    core.require(not output.exists(), 'fresh verification receipt required')
    core.require(args.matrix.resolve().parent not in output.resolve().parents,
                 'verification receipt must be outside the raw campaign tree')
    if args.runtime_dir:
        core.require(args.runtime_dir.resolve() not in output.resolve().parents,
                     'verification receipt must be outside frozen runtime')
    result = verify(args.matrix, args.expected_boot_id, args.expected_seed, args.runtime_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'verified': result['verified'], 'status': result['status'], 'output': str(output)}))
    return 0 if result['verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
