#!/usr/bin/env python3
"""Run bounded, deterministic experiments INSIDE an owned disposable QEMU Guest.

Not a model benchmark. Guest-cold never means physical storage/Host-cold.
All paired blocks preserve logical queries and compare their actual outputs.
"""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def confidence(values, seed=73):
    if len(values) < 3:
        return None
    rng = random.Random(seed)
    samples = sorted(statistics.mean(rng.choices(values, k=len(values))) for _ in range(4000))
    return [samples[99], samples[3899]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=['matrix', 'overhead', 'pressure', 'diagnostic'], required=True)
    parser.add_argument('--root', type=Path, default=Path('/opt/profile-validation/search'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, default=Path('/opt/agent-benchmarks/artifacts-corrected.json'))
    parser.add_argument('--repetitions', type=int, default=5)
    parser.add_argument('--passes', type=int, default=8)
    parser.add_argument('--repository-version', required=True)
    parser.add_argument('--seed', type=int, default=7319)
    parser.add_argument('--hist-object', type=Path)
    parser.add_argument('--hist-sha256')
    parser.add_argument('--intervals', default='100,500,1000', help='overhead sampling periods in ms; e.g. 50 or 100,500,1000')
    args = parser.parse_args()
    if not 3 <= args.repetitions <= 20:
        parser.error('3..20 independent randomized repetition blocks required')
    intervals = [int(value) for value in args.intervals.split(',')]
    if not intervals or len(set(intervals)) != len(intervals) or any(not 10 <= value <= 60000 for value in intervals):
        parser.error('unique interval values in 10..60000 ms required')
    args.output.mkdir(mode=0o700)
    config = json.loads(args.artifacts.read_text())
    for kind in ('sampler', 'observer', 'verifier', 'recorder', 'lifecycle'):
        key = kind + ('_object' if kind in ('recorder', 'lifecycle') else '_binary')
        actual = hashlib.sha256(Path(config[key]).read_bytes()).hexdigest()
        if actual != config[kind + '_sha256']:
            raise RuntimeError('artifact digest mismatch: ' + key)
    cases = []
    if args.suite == 'matrix':
        for cache, workspace, intervention in itertools.product(('warm', 'guest-cold'), ('shared', 'independent'), ('none', 'exact-reuse')):
            cases.append({'cache': cache, 'workspace': workspace, 'intervention': intervention,
                          'modes': 'sampler', 'concurrency': '1,2,4,8', 'interval': 100})
    elif args.suite == 'overhead':
        for interval in intervals:
            cases.append({'cache': 'warm', 'workspace': 'shared', 'intervention': 'none',
                          'modes': 'baseline,observer,observer-sampler', 'concurrency': '1,8', 'interval': interval})
    elif args.suite == 'pressure':
        for limit in (0, 192):
            cases.append({'cache': 'guest-cold', 'workspace': 'shared', 'intervention': 'none',
                          'modes': 'sampler', 'concurrency': '1,2', 'interval': 100, 'memory_high_mb': limit})
    else:
        cases.append({'cache': 'warm', 'workspace': 'shared', 'intervention': 'none',
                      'modes': 'kernel-hist', 'concurrency': '1,8', 'interval': 100})
    rng, runs = random.Random(args.seed), []
    manifest = {'schema_version': 1, 'suite': args.suite, 'status': 'RUNNING', 'runs': runs,
                'seed': args.seed, 'repetitions': args.repetitions, 'artifacts': config,
                'repository_version': args.repository_version,
                'scope': 'deterministic GNU grep Linux lib corpus; 8 cooperative logical Agents; no model/API calls',
                'cache_scope': 'Guest page/dentry/inode caches; Host storage caches unknown',
                'confidence_unit': 'paired randomized trial block, not pooled Agent observations'}
    try:
        for repetition in range(args.repetitions):
            block = list(cases)
            rng.shuffle(block)
            for case in block:
                name = '%03d-r%d-%s' % (len(runs), repetition, args.suite)
                target = args.output / name
                command = [sys.executable, '-B', str(args.root / 'run.py'), '--corpus', str(args.root / ('pressure-corpus' if args.suite == 'pressure' else 'lib')),
                    '--queries-file', str(args.root / 'queries.json'), '--sampler', config['sampler_binary'],
                    '--output-dir', str(target), '--modes', case['modes'], '--concurrency', case['concurrency'],
                    '--jobs', '8', '--passes', str(args.passes), '--repetitions', '1', '--warmups', '0',
                    '--seed', str(args.seed + repetition * 117 + len(runs)), '--cache', case['cache'],
                    '--allow-guest-drop-caches', '--cpus', '0,1', '--cgroup-layout', ('per-task' if args.suite == 'diagnostic' else 'shared-leaf'),
                    '--workspace-layout', case['workspace'], '--intervention', case['intervention'],
                    '--repository-version', args.repository_version, '--interval-ms', str(case['interval']),
                    '--process-interval-ms', str(max(500, case['interval']))]
                if 'observer' in case['modes']:
                    for option, key in [('observer-binary', 'observer_binary'), ('verifier-binary', 'verifier_binary'),
                            ('recorder-object', 'recorder_object'), ('recorder-sha256', 'recorder_sha256'),
                            ('lifecycle-object', 'lifecycle_object'), ('lifecycle-sha256', 'lifecycle_sha256')]:
                        command += ['--' + option, config[key]]
                if args.suite == 'pressure':
                    command += ['--memory-max-mb', '512', '--memory-high-mb', str(case['memory_high_mb']), '--calibration-kind', 'read']
                if args.suite == 'diagnostic':
                    if not args.hist_object or not args.hist_sha256:
                        raise RuntimeError('diagnostic requires explicitly pinned BPF object')
                    command += ['--kernel-hist-object', str(args.hist_object), '--kernel-hist-sha256', args.hist_sha256,
                                '--kernel-hist-groups', 'sched,syscall,mem,lock,blk,irq', '--sample-threads']
                print(json.dumps({'run': name, 'repetition': repetition, **case}), flush=True)
                begin = time.monotonic_ns()
                with (args.output / (name + '.stdout')).open('xb') as out, (args.output / (name + '.stderr')).open('xb') as err:
                    result = subprocess.run(command, stdout=out, stderr=err, timeout=600)
                row = {'path': name, 'block': repetition, 'condition': case, 'returncode': result.returncode,
                       'orchestration_ns': time.monotonic_ns() - begin}
                runs.append(row)
                if result.returncode:
                    raise RuntimeError('actual trial failed; preserve evidence: ' + name)
        comparisons, equivalent, conditions = [], {}, []
        indexed = {}
        for run in runs:
            campaign = json.loads((args.output / run['path'] / 'campaign.json').read_text())
            for trial in campaign['trials']:
                if trial['warmup']:
                    continue
                case, c = run['condition'], trial['concurrency']
                key = (case['cache'], case['workspace'], case['interval'], case.get('memory_high_mb', 0), c, trial['mode'], case['intervention'])
                raw = json.loads((args.output / run['path'] / trial['path'] / 'profile-run.json').read_text())
                stats_path = args.output / run['path'] / trial['path'] / 'load/load-sampler-stats.json'
                stats = json.loads(stats_path.read_text()) if stats_path.exists() else None
                indexed.setdefault(key, {})[run['block']] = {'trial': trial, 'campaign_path': run['path'],
                    'raw': raw, 'sampler_stats': stats}
                for result in trial['results']:
                    output_key = result['query_index']
                    digest = (result['exit_code'], result['output_sha256'], result['output_bytes'])
                    if output_key in equivalent and equivalent[output_key] != digest:
                        raise RuntimeError('cross-condition logical output equivalence failed')
                    equivalent[output_key] = digest
        for key, values in sorted(indexed.items()):
            observations = list(values.values())
            durations = [row['trial']['makespan_ns'] / 1e9 for row in observations]
            conditions.append({'condition': list(key), 'samples': len(durations),
                'median_makespan_seconds': statistics.median(durations),
                'mean_makespan_seconds_ci95_bootstrap': confidence(durations),
                'sampler_usage': [row['raw'].get('sampler_usage') for row in observations],
                'observer_usage': [row['raw'].get('observer_result') for row in observations],
                'observer_prepare_ns': [row['raw'].get('observer_prepare_ns') for row in observations],
                'setup_ns': [row['raw'].get('setup_ns') for row in observations],
                'finalization_ns': [row['raw'].get('finalization_ns') for row in observations],
                'total_trial_ns': [row['raw'].get('total_trial_ns') for row in observations],
                'sampler_stats': [row['sampler_stats'] for row in observations],
                'physical_grep_executions': [sum(result.get('query_statistics', {}).get('physical_grep_executions', 0)
                    for result in row['trial']['results']) for row in observations],
                'logical_queries': [sum(result.get('query_statistics', {}).get('logical_queries', 0)
                    for result in row['trial']['results']) for row in observations],
                'analysis_statuses': [row['trial']['analysis_status'] for row in observations]})
            reference = None
            if key[-1] == 'exact-reuse':
                reference = key[:-1] + ('none',)
            elif key[-2] in ('observer', 'observer-sampler'):
                reference = key[:-2] + ('baseline', key[-1])
            elif args.suite == 'pressure' and key[3]:
                reference = key[:3] + (0,) + key[4:]
            if reference not in indexed:
                continue
            pairs = [value['trial']['makespan_ns'] / indexed[reference][block]['trial']['makespan_ns'] - 1
                     for block, value in values.items() if block in indexed[reference]]
            comparisons.append({'condition': list(key), 'reference': list(reference), 'pairs': len(pairs),
                'relative_makespan_changes': pairs, 'median_relative_change': statistics.median(pairs),
                'mean_relative_change_ci95_bootstrap': confidence(pairs),
                'benefit_supported': bool(confidence(pairs) and confidence(pairs)[1] < 0)})
            if key[-2] == 'observer-sampler':
                observer_reference = key[:-2] + ('observer', key[-1])
                if observer_reference in indexed:
                    increment = [value['trial']['makespan_ns'] / indexed[observer_reference][block]['trial']['makespan_ns'] - 1
                        for block, value in values.items() if block in indexed[observer_reference]]
                    comparisons.append({'condition': list(key), 'reference': list(observer_reference), 'pairs': len(increment),
                        'type': 'SAMPLER_INCREMENT_ON_SAME_OBSERVER', 'relative_makespan_changes': increment,
                        'median_relative_change': statistics.median(increment),
                        'mean_relative_change_ci95_bootstrap': confidence(increment)})
        manifest.update(status='COMPLETE', output_equivalence='PASS', comparisons=comparisons, conditions=conditions)
    except BaseException as error:
        manifest.update(status='FAILED', error=str(error))
        raise
    finally:
        save(args.output / 'validation-campaign.json', manifest)
    return 0


if __name__ == '__main__':
    sys.exit(main())
