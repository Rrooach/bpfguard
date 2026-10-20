#!/usr/bin/env python3
"""Resume an explicitly interrupted matrix using its frozen timing implementation.

Never edits the original evidence. The original schedule prefix stays evidence,
not new repetitions. A long user pause is recorded, with a separate sensitivity
manifest omitting the outer block that straddled the pause.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time


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


def validate_prefix(original, expected_completed):
    plans, entries = original.get('schedule'), original.get('campaigns')
    if (original.get('schema_version') != 1 or original.get('status') != 'FAILED'
            or not isinstance(plans, list) or not isinstance(entries, list)
            or type(expected_completed) is not int or expected_completed != len(entries)
            or not 0 < len(entries) < len(plans)):
        raise ValueError('explicit interrupted schedule with exact completed prefix required')
    seen = set()
    for index, entry in enumerate(entries):
        plan = plans[index]
        if (entry.get('condition') != plan or entry.get('block') != plan.get('block')
                or type(plan.get('block')) is not int or plan['block'] < 0
                or entry.get('stage') != ('warmup' if plan.get('warmup') else 'performance')
                or entry.get('path') != '%03d-r%d' % (index, plan['block'])
                or entry['path'] in seen):
            raise ValueError('completed entries are not the exact original schedule prefix')
        seen.add(entry['path'])
    return copy.deepcopy(plans[len(entries):])


def verify_campaign(directory, binding, expected, plan):
    campaign = read(directory / 'campaign.json')
    if (campaign.get('status') != 'COMPLETE' or len(campaign.get('trials', [])) != 1
            or campaign.get('jobs') != binding['jobs'] or campaign.get('passes') != binding['passes']
            or campaign.get('queries') != binding['queries'] or campaign.get('binaries') != binding['binaries']):
        raise ValueError('incomplete or changed fixed-work campaign')
    item = campaign['trials'][0]
    trial = child(directory, item['path'])
    profile = read(trial / 'profile-run.json')
    if (profile.get('status') != 'COMPLETE' or profile.get('cleanup_errors')
            or profile.get('boot_id') != binding['boot_id'] or profile.get('run_id') != item['run_id']
            or profile.get('end_ns', 0) - profile.get('release_ns', 0) != profile.get('makespan_ns')
            or profile.get('makespan_ns') != item.get('makespan_ns')):
        raise ValueError('completed raw trial identity/timing/cleanup invalid')
    config = profile['config']
    if (config.get('cpus') != binding['cpus'] or config.get('mode') != binding['measurement_mode']
            or config.get('jobs') != binding['jobs'] or config.get('passes') != binding['passes']):
        raise ValueError('fixed CPU/mode/work differs')
    if any(config.get(key) != value for key, value in plan.items() if key != 'block'):
        raise ValueError('raw trial differs from original scheduled condition')
    tasks, results = profile.get('tasks', []), profile.get('results', [])
    if (len(tasks) != binding['jobs'] or len(results) != binding['jobs']
            or len({row['task_id'] for row in results}) != binding['jobs']):
        raise ValueError('fixed-work results incomplete')
    for result in results:
        task = next(task for task in tasks if task['task_id'] == result['task_id'])
        raw = child(trial, task['task_id'] + '.stdout').read_bytes()
        fields = raw.split(b'\0')
        if fields[-1] != b'':
            raise ValueError('malformed raw NUL filename output')
        digest = hashlib.sha256(b'\0'.join(sorted(fields[:-1])) + b'\0').hexdigest()
        value = result['exit_code'], digest, len(raw)
        if value != (0, result['output_sha256'], result['output_bytes']):
            raise ValueError('raw output differs from stored result')
        query = result['query_index']
        if query in expected and expected[query] != value:
            raise ValueError('cross-pause query output differs')
        expected[query] = value
    return read(trial / 'report.json')['analysis']['source_sha256']


def combine(original, resumed, original_name, resumed_name, provenance):
    count = len(original['campaigns'])
    if (resumed.get('status') != 'COMPLETE' or resumed.get('schedule') != original['schedule'][count:]
            or len(resumed.get('campaigns', [])) != len(resumed['schedule'])):
        raise ValueError('resume did not finish the exact remaining schedule')
    for key in ('source', 'source_inventory_sha256', 'jobs', 'passes', 'queries', 'cpus',
                'measurement_coordinator_and_sampler_cpus', 'boot_id', 'seed', 'binaries', 'measurement_mode'):
        if resumed.get(key) != original.get(key):
            raise ValueError('resume changed fixed input/config: ' + key)
    result = copy.deepcopy(original)
    result.pop('error', None)
    result.update(status='COMPLETE', output_equivalence='PASS', campaigns=[], resume_provenance=provenance)
    for prefix, source, offset in ((original_name, original, 0), (resumed_name, resumed, count)):
        for local, entry in enumerate(source['campaigns']):
            index = local + offset
            if entry['condition'] != original['schedule'][index] or entry['block'] != entry['condition']['block']:
                raise ValueError('resume entry reordered or block changed')
            record = copy.deepcopy(entry)
            record.update(path=prefix + '/' + entry['path'], original_schedule_index=index)
            result['campaigns'].append(record)
    return result


def readonly_roots(roots):
    mounts = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        columns = line.split()
        mounts[columns[4]] = columns[5].split(',')
    if any('ro' not in mounts.get(str(root), []) for root in roots):
        raise ValueError('prepared corpus/copies no longer have exact read-only bind mounts')


def execute(args):
    original = read(args.original_matrix)
    remaining = validate_prefix(original, args.expected_completed)
    runtime = args.runtime.resolve(strict=True)
    sys.path.insert(0, str(runtime))
    specification = importlib.util.spec_from_file_location('frozen_large_search_for_resume', runtime / 'large_search.py')
    frozen = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(frozen)
    frozen.cache_probe._ensure_guest()
    if os.geteuid() != 0 or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != original['boot_id']:
        raise ValueError('resume requires the original owned root Guest boot')
    binaries = {'matrix_sha256': runtime / 'large_search.py', 'runner_sha256': runtime / 'run.py',
                'cache_probe_sha256': runtime / 'cache_probe.py', 'sampler_sha256': args.sampler,
                'grep_sha256': Path(shutil.which('grep'))}
    if (Path(frozen.runner.__file__).resolve() != binaries['runner_sha256']
            or Path(frozen.cache_probe.__file__).resolve() != binaries['cache_probe_sha256']
            or set(binaries) != set(original['binaries'])
            or any(sha(path) != original['binaries'][key] for key, path in binaries.items())):
        raise ValueError('frozen runtime or binary digest changed')
    # The producer's default design is fixed; do not infer a new schedule from
    # just the missing conditions or randomize again after the user pause.
    if frozen.cases(5, original['seed']) != original['schedule']:
        raise ValueError('unexpected original design; explicit new adapter required')
    prepared = read(args.prepared / 'preparation.json')
    readonly_roots([args.corpus] + list(map(Path, prepared['independent_roots'])))
    common_parent = args.original_matrix.parent.parent.resolve(strict=True)
    if (args.output.parent.resolve(strict=True) != common_parent
            or args.combined.parent.resolve(strict=True) != common_parent):
        raise ValueError('fresh resume and combined manifests must share the original results parent')
    if args.output.exists() or args.combined.exists():
        raise ValueError('never overwrite original or previous resume evidence')
    if (read(args.queries) != original['queries'] or prepared['source'] != original['source']
            or prepared['inventory_sha256'] != original['source_inventory_sha256']):
        raise ValueError('resume queries or preparation differ from original scope')
    expected, analyzer_hashes = {}, set()
    for entry in original['campaigns']:
        analyzer_hashes.add(verify_campaign(child(args.original_matrix.parent, entry['path']),
            original, expected, entry['condition']))
    # original_matrix is matrix-001/matrix.json; combined paths are rooted in
    # results/, while each original campaign remains under matrix-001/.
    analyzer_path = Path(frozen.runner.analyze.__file__).resolve()
    if analyzer_path != runtime / 'analyze.py' or analyzer_hashes != {sha(analyzer_path)}:
        raise ValueError('frozen analyzer import differs from original trial analyzer')
    begin = time.monotonic_ns()
    frozen.cases = lambda *unused, **ignored: copy.deepcopy(remaining)
    fresh = argparse.Namespace(corpus=args.corpus, source_manifest=args.source_manifest,
        prepared=args.prepared, output=args.output, queries=args.queries, sampler=args.sampler,
        jobs=original['jobs'], passes=original['passes'], repetitions=5, seed=original['seed'],
        cpus=','.join(map(str, original['cpus'])), concurrency='1,2,4,8', caches='warm,guest-cold',
        layouts='shared,independent', warmups=0, mode=original['measurement_mode'], intervention='none')
    resumed = frozen.execute(fresh)
    for entry in resumed['campaigns']:
        if verify_campaign(child(args.output, entry['path']), original, expected, entry['condition']) not in analyzer_hashes:
            raise ValueError('resumed analyzer digest differs')
    provenance = {'adapter_sha256': sha(__file__), 'original_matrix_sha256': sha(args.original_matrix),
        'resumed_matrix_sha256': sha(args.output / 'matrix.json'), 'completed_prefix': len(original['campaigns']),
        'remaining_cases': len(remaining), 'begin_monotonic_ns': begin, 'end_monotonic_ns': time.monotonic_ns(),
        'frozen_analyzer_sha256': sha(analyzer_path),
        'original_raw_status': original['status'], 'original_evidence_modified': False,
        'timing_implementation': 'ORIGINAL_FROZEN_EXECUTE_AND_RUN_TRIAL; ONLY_SCHEDULE_PROVIDER_REPLACED_IN_MEMORY',
        'integrity': 'Frozen execute rechecked all source/copy contents and permissions after the remaining trials.',
        'pause': 'User pause with VM SIGSTOP; same boot retained; each next trial reestablishes cache condition.'}
    combined = combine(original, resumed, args.original_matrix.parent.name, args.output.name, provenance)
    frozen.runner.dump(args.combined, combined)
    left = original['schedule'][len(original['campaigns']) - 1]['block']
    right = remaining[0]['block']
    if left == right:
        sensitive = copy.deepcopy(combined)
        sensitive['campaigns'] = [entry for entry in combined['campaigns'] if entry['block'] != left]
        sensitive['schedule'] = [plan for plan in combined['schedule'] if plan['block'] != left]
        sensitive['sensitivity'] = {'excluded_split_block': left, 'reason': 'OUTER_BLOCK_SPANS_USER_PAUSE',
            'raw_evidence_retained': True, 'not_cherry_picked_by_observed_results': True}
        frozen.runner.dump(args.combined.with_name(args.combined.stem + '-continuous-blocks.json'), sensitive)
    print(json.dumps({'status': 'COMPLETE', 'total': len(combined['campaigns']), 'combined': str(args.combined)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('original-matrix', 'runtime', 'corpus', 'prepared', 'source-manifest', 'queries', 'sampler', 'output', 'combined'):
        parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--expected-completed', type=int, required=True)
    args = parser.parse_args()
    for name in ('original_matrix', 'runtime', 'corpus', 'prepared', 'source_manifest', 'queries', 'sampler'):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.output, args.combined = args.output.absolute(), args.combined.absolute()
    execute(args)


if __name__ == '__main__':
    main()
