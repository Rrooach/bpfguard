#!/usr/bin/env python3
"""Repeat complete randomized blocks after a recorded user pause.

The original evidence and frozen access_search.py are never rewritten.  This
new coordinator explicitly executes an original schedule suffix using the
frozen trial_with_collector/run_trial and cache preparation implementations.
It does not monkeypatch a schedule provider or pretend to be frozen execute().
"""
import argparse
import copy
import gc
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time
import uuid


def read(path):
    return json.loads(Path(path).read_bytes())


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def child(root, relative):
    path = Path(relative)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('unsafe relative evidence path')
    resolved = (root / path).resolve(strict=True)
    resolved.relative_to(root.resolve(strict=True))
    return resolved


def condition(plan, original):
    value = {key: item for key, item in plan.items() if key != 'block'}
    value.update(mode='sampler', repetition=0,
        file_access_backend=original['file_access_backend'],
        collector_ring_bytes=original['collector_budget']['ring_bytes'])
    return value


def validate_selection(original, pause, expected_completed, restart_block, frozen_schedule):
    plans, entries = original.get('schedule'), original.get('campaigns')
    if (original.get('schema_version') != 1 or original.get('status') not in ('FAILED', 'COMPLETE')
            or original.get('jobs') != 8 or original.get('passes') != 1
            or type(expected_completed) is not int or not isinstance(entries, list)
            or len(entries) != expected_completed or not isinstance(plans, list)
            or plans != frozen_schedule or len(plans) != 160
            or type(restart_block) is not int or restart_block not in (1, 2, 3, 4)):
        raise ValueError('terminal exact original fixed-eight 160-trial campaign required')
    if (pause.get('status') != 'PAUSED_AT_USER_REQUEST'
            or pause.get('vm_boot_id') != original.get('boot_id')
            or type(pause.get('completed_trials')) is not int
            or not 0 <= pause['completed_trials'] < len(plans)
            or pause['completed_trials'] > expected_completed
            or pause.get('last_completed_trial_index') != pause['completed_trials'] - 1
            or pause.get('in_progress_trial_index') != pause['completed_trials']
            or pause.get('in_progress_block') != restart_block
            or plans[pause['completed_trials']]['block'] != restart_block):
        raise ValueError('pause receipt does not bind the original split block/boot/prefix')
    start = next(index for index, plan in enumerate(plans) if plan['block'] == restart_block)
    if not 0 < start <= pause['completed_trials'] or start != restart_block * 32:
        raise ValueError('restart must retain complete uninterrupted original blocks')
    for index, entry in enumerate(entries):
        plan = plans[index]
        if (entry.get('path') != '%03d-r%d' % (index, plan['block'])
                or entry.get('block') != plan['block'] or type(entry.get('block')) is not int
                or entry.get('stage') != 'performance'
                or entry.get('condition') != condition(plan, original)):
            raise ValueError('original campaigns are not the exact completed schedule prefix')
    return start, copy.deepcopy(plans[start:])


def load_runtime(runtime):
    previous = list(sys.path)
    try:
        sys.path.insert(0, str(runtime))
        specification = importlib.util.spec_from_file_location('_frozen_access_resume', runtime / 'access_search.py')
        frozen = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(frozen)
    finally:
        sys.path[:] = previous
    for module, name in ((frozen.runner, 'run.py'), (frozen.large_search, 'large_search.py'),
                         (frozen.cache_probe, 'cache_probe.py'), (frozen.runner.analyze, 'analyze.py')):
        if Path(module.__file__).resolve() != runtime / name:
            raise ValueError('frozen runtime import resolved outside declared directory: ' + name)
    return frozen


def validate_runtime(frozen, runtime, original, args):
    paths = {'matrix_sha256': runtime / 'access_search.py', 'runner_sha256': runtime / 'run.py',
        'large_search_sha256': runtime / 'large_search.py', 'cache_probe_sha256': runtime / 'cache_probe.py',
        'sampler_sha256': args.sampler, 'file_access_sha256': args.file_access,
        'file_access_object_sha256': args.file_access_object,
        'grep_sha256': Path(shutil.which('grep')).resolve()}
    expected = original['binaries']
    if (set(expected) != set(paths) | {'file_access_backend'}
            or expected['file_access_backend'] != original['file_access_backend']
            or any(sha(path) != expected[key] for key, path in paths.items())):
        raise ValueError('frozen runtime or binary digest differs from original')
    return {str(path): sha(path) for path in list(paths.values()) + [runtime / 'analyze.py']}


def verify_preserved_campaign(directory, original, plan, expected, io_prime_devices=None):
    campaign = read(directory / 'campaign.json')
    if (campaign.get('status') != 'COMPLETE' or len(campaign.get('trials', [])) != 1
            or campaign.get('binaries') != original['binaries']
            or any(campaign.get(key) != original[key] for key in ('jobs', 'passes', 'queries'))):
        raise ValueError('preserved block campaign is incomplete or changed')
    item = campaign['trials'][0]
    trial = child(directory, item['path'])
    profile = read(trial / 'profile-run.json')
    if (profile.get('status') != 'COMPLETE' or profile.get('cleanup_errors')
            or profile.get('boot_id') != original['boot_id'] or profile.get('run_id') != item['run_id']
            or type(profile.get('release_ns')) is not int or type(profile.get('end_ns')) is not int
            or profile['end_ns'] <= profile['release_ns']
            or profile['end_ns'] - profile['release_ns'] != profile.get('makespan_ns')
            or item.get('makespan_ns') != profile.get('makespan_ns')):
        raise ValueError('preserved trial identity, wall time or cleanup differs')
    cfg = profile['config']
    if (any(cfg.get(key) != value for key, value in condition(plan, original).items())
            or any(cfg.get(key) != original[key] for key in ('jobs', 'passes', 'cpus'))):
        raise ValueError('preserved trial fixed-work configuration differs')
    if io_prime_devices is not None and [row.get('device') for row in profile.get('io_baseline_priming', [])] != io_prime_devices:
        raise ValueError('explicit pre-cache I/O baseline devices differ from original')
    capture = read(directory / 'capture.json')
    if (capture.get('profile_run_sha256') != sha(trial / 'profile-run.json')
            or capture.get('profile_run_id') != profile['run_id']
            or capture.get('boot_id') != original['boot_id']
            or capture.get('mode') != plan['file_access_mode']):
        raise ValueError('preserved capture/profile binding differs')
    tasks, results = profile.get('tasks', []), profile.get('results', [])
    if (len(tasks) != 8 or len(results) != 8
            or len({task['task_id'] for task in tasks}) != 8
            or {task['task_id'] for task in tasks} != {row['task_id'] for row in results}):
        raise ValueError('preserved fixed-eight outputs incomplete')
    for result in results:
        raw = child(trial, result['task_id'] + '.stdout').read_bytes()
        fields = raw.split(b'\0')
        if fields[-1] != b'':
            raise ValueError('malformed raw NUL search output')
        value = (result['exit_code'], hashlib.sha256(b'\0'.join(sorted(fields[:-1])) + b'\0').hexdigest(), len(raw))
        if value[0] != 0 or value[1:] != (result['output_sha256'], result['output_bytes']):
            raise ValueError('preserved raw search output differs')
        index = result['query_index']
        if index in expected and expected[index] != value:
            raise ValueError('query output differs across user pause')
        expected[index] = value
    return read(trial / 'report.json')['analysis']['source_sha256']


def readonly_roots(roots):
    mounts = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        columns = line.split()
        mounts[columns[4]] = columns[5].split(',')
    if any('ro' not in mounts.get(str(root), []) for root in roots):
        raise ValueError('all prepared source roots must retain exact read-only bind mounts')


def make_manifest(original, remaining, continuation):
    manifest = copy.deepcopy(original)
    for key in ('error', 'cleanup_errors', 'output_equivalence', 'source_integrity'):
        manifest.pop(key, None)
    manifest.update(status='RUNNING', campaigns=[], schedule=copy.deepcopy(remaining), continuation=continuation)
    return manifest


def execute(args):
    original, pause = read(args.original_matrix), read(args.pause_receipt)
    runtime = args.runtime.resolve(strict=True)
    frozen = load_runtime(runtime)
    plans = frozen.schedule(5, original['seed'])
    start, remaining = validate_selection(original, pause, args.expected_completed, args.restart_block, plans)
    frozen.cache_probe._ensure_guest()
    if os.geteuid() != 0 or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != original['boot_id']:
        raise ValueError('continuation requires original owned root Guest boot')
    runtime_digests = validate_runtime(frozen, runtime, original, args)
    if args.output.parent.resolve(strict=True) != args.original_matrix.parent.parent.resolve(strict=True) or args.output.exists():
        raise ValueError('fresh continuation directory beside original campaign required')
    preparation = read(args.prepared / 'preparation.json')
    inventory_path = args.prepared / 'corpus-inventory.json'
    inventory = read(inventory_path)
    roots = list(map(Path, preparation['independent_roots']))
    if (preparation.get('boot_id') != original['boot_id'] or len(roots) != 8
            or preparation.get('source') != original['source'] or read(args.source_manifest) != original['source']
            or preparation.get('inventory_sha256') != original['source_inventory_sha256']
            or sha(inventory_path) != original['source_inventory_sha256']
            or preparation.get('corpus') != str(args.corpus) or read(args.queries) != original['queries']):
        raise ValueError('boot-bound preparation, immutable input or queries differ')
    readonly_roots([args.corpus] + roots)
    expected = {}
    analyzer_hashes = {verify_preserved_campaign(child(args.original_matrix.parent, entry['path']),
        original, original['schedule'][index], expected, args.io_prime_devices)
        for index, entry in enumerate(original['campaigns'][:start])}
    if analyzer_hashes != {sha(runtime / 'analyze.py')}:
        raise ValueError('preserved block analyzer differs from frozen runtime')
    fresh = argparse.Namespace(**vars(args))
    fresh.jobs, fresh.passes = original['jobs'], original['passes']
    fresh.cpus = ','.join(map(str, original['cpus']))
    fresh.file_access_sha256 = original['binaries']['file_access_sha256']
    fresh.file_access_object_sha256 = original['binaries']['file_access_object_sha256']
    fresh.file_access_backend = original['file_access_backend']
    for key, source in (('collector_ring_bytes', 'ring_bytes'), ('collector_max_bytes', 'max_bytes'),
                        ('collector_timeout_seconds', 'max_seconds')):
        setattr(fresh, key, original['collector_budget'][source])
    common = frozen.large_search.arguments(fresh, inventory, roots)
    common.io_prime_devices = args.io_prime_devices
    available = os.sched_getaffinity(0)
    auxiliary = set(original['measurement_coordinator_sampler_collector_cpus'])
    if available != common.cpus | auxiliary or common.cpus & auxiliary or not auxiliary:
        raise ValueError('original fixed workload and separate measurement CPUs required')
    os.sched_setaffinity(0, auxiliary)
    continuation = {'schema_version': 1, 'adapter_sha256': sha(__file__),
        'original_matrix_sha256': sha(args.original_matrix), 'original_matrix': str(args.original_matrix),
        'pause_receipt_sha256': sha(args.pause_receipt), 'pause_receipt': str(args.pause_receipt),
        'source_start_index': start, 'original_schedule_indices': list(range(start, len(plans))),
        'original_completed_trials': len(original['campaigns']), 'original_raw_status': original['status'],
        'retained_original_schedule_indices': list(range(start)),
        'excluded_original_completed_indices': list(range(start, len(original['campaigns']))),
        'reason': 'REPEAT_ENTIRE_SPLIT_RANDOMIZED_BLOCK_AND_ALL_LATER_BLOCKS; NOT_RESULT_BASED_SELECTION',
        'coordination_implementation': 'NEW_EXPLICIT_LOOP_USING_FROZEN_TRIAL_WITH_COLLECTOR; NO_SCHEDULE_MONKEYPATCH',
        'frozen_runtime': str(runtime), 'frozen_runtime_sha256': runtime_digests,
        'original_evidence_modified': False, 'begin_monotonic_ns': time.monotonic_ns(),
        'io_prime_devices': args.io_prime_devices}
    manifest = make_manifest(original, remaining, continuation)
    args.output.mkdir(mode=0o700)
    frozen.runner.dump(args.output / 'matrix.json', manifest)
    base = Path('/sys/fs/cgroup') / ('search-access-resume-' + uuid.uuid4().hex)
    frozen.runner.ensure_cgroup_parent(base)
    base_identity = frozen.runner.cgroup_identity(base)
    pins = {}
    try:
        for layout in sorted({plan['workspace_layout'] for plan in remaining}):
            selected = [args.corpus] if layout == 'shared' else roots
            print(json.dumps({'pinning': layout, 'roots': len(selected)}), flush=True)
            pins[layout] = frozen.cache_probe.pin_roots(selected, inventory['files'], independent=layout == 'independent')
            if pins[layout]['status'] != 'PINNED':
                raise ValueError('exact source identities could not be pinned')
        for index, plan in enumerate(remaining, start):
            common.cache, common.workspace_layout = plan['cache'], plan['workspace_layout']
            common.workspaces = [args.corpus] * 8 if common.workspace_layout == 'shared' else roots
            common.cache_pins = pins[common.workspace_layout]
            target = args.output / ('%03d-r%d' % (index, plan['block']))
            target.mkdir()
            (target / 'trials').mkdir()
            selected_condition = condition(plan, original)
            campaign = {'schema_version': 1, 'status': 'RUNNING', 'trials': [], 'jobs': 8,
                'passes': fresh.passes, 'queries': original['queries'], 'cache': common.cache,
                'workspace_layout': common.workspace_layout, 'intervention': 'none',
                'repository_version': common.repository_version, 'grep_options': frozen.runner.GREP_OPTIONS,
                'cgroup_layout': common.cgroup_layout, 'memory_max_mb': 0, 'memory_high_mb': 0,
                'sample_threads': False, 'calibration_kind': None, 'corpus_sha256': inventory['sha256'],
                'permission_scope_sha256': inventory['permission_scope_sha256'], 'binaries': original['binaries'],
                'original_schedule_index': index, 'continuation_adapter_sha256': continuation['adapter_sha256']}
            print(json.dumps({'trial_index': index, 'continuation_local_index': index - start,
                'total': len(remaining), **plan}), flush=True)
            before = time.monotonic_ns()
            os.sync()
            campaign['pre_trial_writeback_drain'] = {
                'kind': 'OWNED_GUEST_SYNC_BEFORE_COLLECTOR_WORKER_AND_CACHE_PREPARATION',
                'start_monotonic_ns': before, 'end_monotonic_ns': time.monotonic_ns()}
            try:
                row = frozen.trial_with_collector(fresh, common, target, selected_condition,
                    inventory, original['queries'], base, original['boot_id'])
                for result in row['results']:
                    key = result['query_index']
                    value = result['exit_code'], result['output_sha256'], result['output_bytes']
                    if key not in expected or expected[key] != value:
                        raise ValueError('continued query output differs from retained pre-pause block')
                campaign.update(status='COMPLETE', trials=[row])
            finally:
                frozen.runner.dump(target / 'campaign.json', campaign)
            manifest['campaigns'].append({'path': target.name, 'block': plan['block'], 'stage': 'performance',
                'condition': selected_condition, 'original_schedule_index': index})
            frozen.update_owned_json(args.output / 'matrix.json', manifest)
            with (args.output / 'progress.jsonl').open('a') as stream:
                stream.write(json.dumps({'index': index, 'condition': plan, 'makespan_seconds': row['makespan_ns'] / 1e9,
                    'file_access_health': row['file_access_health']}) + '\n')
            print(json.dumps({'completed': index, 'wall_seconds': row['makespan_ns'] / 1e9,
                'file_access_health': row['file_access_health']}), flush=True)
            gc.collect()
        for root in frozen.participating_roots(args.corpus, roots, ('shared', 'independent')):
            if frozen.large_search.fingerprint(frozen.runner.corpus_inventory(root)) != frozen.large_search.fingerprint(inventory):
                raise ValueError('post-continuation immutable source integrity differs')
        manifest.update(status='COMPLETE', output_equivalence='PASS',
            source_integrity='PARTICIPATING_ROOTS_POST_CAMPAIGN_REHASHED_IDENTICAL')
    except BaseException as error:
        manifest.update(status='FAILED', error=type(error).__name__ + ':' + str(error))
        raise
    finally:
        errors = []
        frozen.runner.cleanup_owned_cgroup(base, base_identity, errors, kill_remaining=False)
        if errors:
            manifest.update(status='FAILED', cleanup_errors=errors)
        continuation['end_monotonic_ns'] = time.monotonic_ns()
        frozen.update_owned_json(args.output / 'matrix.json', manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original-matrix', 'pause-receipt', 'runtime', 'corpus', 'source-manifest',
                 'prepared', 'queries', 'sampler', 'file-access', 'file-access-object', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-completed', type=int, required=True)
    parser.add_argument('--restart-block', type=int, default=1)
    parser.add_argument('--io-prime-device', action='append', dest='io_prime_devices', required=True)
    args = parser.parse_args()
    for name in ('original_matrix', 'pause_receipt', 'runtime', 'corpus', 'source_manifest',
                 'prepared', 'queries', 'sampler', 'file_access', 'file_access_object'):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.output = args.output.absolute()
    execute(args)


if __name__ == '__main__':
    main()
