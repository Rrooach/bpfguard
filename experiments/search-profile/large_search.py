#!/usr/bin/env python3
"""Owned-Guest, full-repository fixed-work wall-clock experiment, no models."""
import argparse
import gc
import gzip
import itertools
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import time

import cache_probe
import run as runner


def cases(repetitions, seed, intervention='none', concurrencies=(1, 2, 4, 8),
          caches=('warm', 'guest-cold'), layouts=('shared', 'independent'), warmups=0):
    rng, result = random.Random(seed), []
    for warmup, count in ((True, warmups), (False, repetitions)):
        for block in range(count):
            rows = [dict(cache=c, workspace_layout=w, concurrency=n, intervention=i,
                         block=block, warmup=warmup)
                    for c, w, n, i in itertools.product(caches, layouts, concurrencies,
                        ('none', 'exact-reuse') if intervention == 'paired' else (intervention,))]
            rng.shuffle(rows)
            result.extend(rows)
    return result


def verify_cache(proof, mode):
    if proof.get('status') != 'OBSERVED_NON_ATOMIC' or not proof.get('roots'):
        raise RuntimeError('cache residency could not be observed completely')
    for row in proof['roots']:
        fraction = row.get('resident_fraction')
        if not isinstance(fraction, (int, float)):
            raise RuntimeError('unknown data-page residency')
        if mode == 'guest-cold' and fraction > .001:
            raise RuntimeError('cold condition rejected: >0.1% data pages resident')
        if mode == 'warm' and fraction < .999:
            raise RuntimeError('warm condition rejected: <99.9% data pages resident')


def fingerprint(value):
    return value['sha256'], value['permission_scope_sha256'], value['bytes'], len(value['files'])


def prepare(args):
    source = json.loads(args.source_manifest.read_bytes())
    inventory = runner.corpus_inventory(args.corpus)
    if inventory['bytes'] != source['regular_file_bytes'] or len(inventory['files']) != source['regular_files']:
        raise ValueError('extracted regular-file scope differs from immutable source declaration')
    runner.dump(args.prepared / 'corpus-inventory.json', inventory)
    workspace_parent = args.prepared / 'workspaces'
    workspace_parent.mkdir()
    roots = []
    for index in range(args.jobs):
        target = workspace_parent / ('agent-%04d' % index)
        print(json.dumps({'prepare_copy': str(target)}), flush=True)
        shutil.copytree(args.corpus, target)
        if fingerprint(runner.corpus_inventory(target)) != fingerprint(inventory):
            raise ValueError('independent workspace content or permissions differ')
        roots.append(target)
    for root in [args.corpus] + roots:
        subprocess.run(['mount', '--bind', str(root), str(root)], check=True)
        subprocess.run(['mount', '-o', 'remount,bind,ro', str(root)], check=True)
    runner.dump(args.prepared / 'preparation.json', {'schema_version': 1, 'status': 'PREPARED',
        'source': source, 'corpus': str(args.corpus), 'independent_roots': list(map(str, roots)),
        'inventory_sha256': runner.sha_file(args.prepared / 'corpus-inventory.json'),
        'completed_monotonic_ns': time.monotonic_ns(), 'read_only_bind_mounts': True,
        'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
    return inventory, roots


def arguments(args, inventory, roots):
    return argparse.Namespace(cgroup_parent=Path('/sys/fs/cgroup/large-search-wallclock'),
        jobs=args.jobs, passes=args.passes, calibration_kind=None, calibration_seconds=.4,
        corpus=args.corpus, workspaces=[args.corpus] * args.jobs,
        repository_version=json.loads(args.source_manifest.read_bytes())['commit'],
        workspace_layout='shared', cgroup_layout='shared-leaf', intervention='none',
        memory_max_mb=0, memory_high_mb=0, sample_threads=False, cache='warm',
        cpus=set(map(int, args.cpus.split(','))), interval_ms=100, process_interval_ms=0,
        grep=str(Path(shutil.which('grep')).resolve()),
        grep_sha256=runner.sha_file(Path(shutil.which('grep')).resolve()),
        sampler=args.sampler.resolve(strict=True), allow_guest_drop_caches=True,
        timeout_seconds=300, verify_cache_residency=True, cache_proof_validator=verify_cache,
        io_prime_devices=['/dev/vda', '/dev/sda'],
        kernel_hist_object=None, kernel_hist_sha256=None, kernel_hist_groups='sched,syscall',
        kernel_hist_syscall_backend='kprobe', kernel_hist_memory_backend='kprobe-tracefs')


def execute(args):
    args.output.mkdir(mode=0o700)
    prep = json.loads((args.prepared / 'preparation.json').read_bytes())
    if json.loads(args.source_manifest.read_bytes()) != prep['source']:
        raise ValueError('source declaration differs from prepared immutable corpus')
    if prep['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise ValueError('preparation belongs to a different boot')
    inventory_path = args.prepared / 'corpus-inventory.json'
    if runner.sha_file(inventory_path) != prep['inventory_sha256']:
        raise ValueError('preparation inventory changed')
    inventory = json.loads(inventory_path.read_bytes())
    roots = list(map(Path, prep['independent_roots']))
    if str(args.corpus) != prep['corpus'] or len(roots) != args.jobs:
        raise ValueError('prepared root/jobs changed')
    queries = json.loads(args.queries.read_bytes())
    if not isinstance(queries, list) or not queries or len(queries) > args.jobs or any(
            not isinstance(query, str) or not query or '\n' in query or '\0' in query for query in queries):
        raise ValueError('bounded fixed query strings required')
    common = arguments(args, inventory, roots)
    if not common.cpus <= os.sched_getaffinity(0):
        raise ValueError('requested fixed CPUs unavailable')
    auxiliary_cpus = set(os.sched_getaffinity(0)) - common.cpus
    if not auxiliary_cpus:
        raise ValueError('reserve Guest CPUs outside fixed workload CPUs for measurement')
    os.sched_setaffinity(0, auxiliary_cpus)
    plans = cases(args.repetitions, args.seed, args.intervention,
        tuple(map(int, args.concurrency.split(','))), tuple(args.caches.split(',')),
        tuple(args.layouts.split(',')), args.warmups)
    manifest = {'schema_version': 1, 'status': 'RUNNING', 'campaigns': [],
        'purpose': 'FIXED_WORK_FULL_REPOSITORY_WALLCLOCK_AND_RESOURCE_CLUES_NOT_MODEL_SCORES',
        'primary_metric': 'WALL_SECONDS_FROM_COMMON_RELEASE_TO_ALL_WORKER_EXITS',
        'source': prep['source'], 'source_inventory_sha256': prep['inventory_sha256'],
        'jobs': args.jobs, 'passes': args.passes, 'queries': queries, 'cpus': sorted(common.cpus),
        'measurement_coordinator_and_sampler_cpus': sorted(auxiliary_cpus),
        'memory_configuration': 'Fixed Guest RAM; no per-condition memory limits',
        'boot_id': prep['boot_id'], 'seed': args.seed, 'schedule': plans,
        'measurement_mode': args.mode, 'mode_scope': 'Low-frequency cgroup sampling; no deep probes or final state snapshot inside timing',
        'cache_scope': 'Guest DATA pages verified per file, non-atomic. Residency probe traverses metadata, so not cold-dentry/inode proof. Host caches unknown.',
        'binaries': {'sampler_sha256': runner.sha_file(common.sampler),
            'grep_sha256': common.grep_sha256, 'runner_sha256': runner.sha_file(runner.__file__),
            'matrix_sha256': runner.sha_file(__file__), 'cache_probe_sha256': runner.sha_file(cache_probe.__file__)},
        'limits': ['CPU, PSI and histograms are separate clues; never added into wall seconds.',
            'Source/permission checks precede cache preparation; final integrity checks occur after the entire timed campaign.',
            'Warm/cold independent copies have distinct file inodes, but physical storage/Host cache independence is not asserted.']}
    expected = {}
    created_parent = runner.ensure_cgroup_parent(common.cgroup_parent)
    pins = {}
    try:
        for layout in sorted(set(plan['workspace_layout'] for plan in plans)):
            selected = [args.corpus] if layout == 'shared' else roots
            print(json.dumps({'pinning': layout, 'roots': len(selected)}), flush=True)
            pins[layout] = cache_probe.pin_roots(selected, inventory['files'], independent=layout == 'independent')
            if pins[layout]['status'] != 'PINNED':
                raise ValueError('could not pin exact independent source identities')
        for index, plan in enumerate(plans):
            common.cache, common.workspace_layout, common.intervention = plan['cache'], plan['workspace_layout'], plan['intervention']
            common.workspaces = [args.corpus] * args.jobs if plan['workspace_layout'] == 'shared' else roots
            common.cache_pins = pins[plan['workspace_layout']]
            target = args.output / ('%03d-r%d' % (index, plan['block']))
            target.mkdir()
            (target / 'trials').mkdir()
            campaign = {'schema_version': 1, 'status': 'RUNNING', 'trials': [],
                'jobs': args.jobs, 'passes': args.passes, 'queries': queries,
                'cache': common.cache, 'workspace_layout': common.workspace_layout,
                'intervention': common.intervention, 'repository_version': common.repository_version,
                'grep_options': runner.GREP_OPTIONS, 'cgroup_layout': common.cgroup_layout,
                'memory_max_mb': 0, 'memory_high_mb': 0, 'sample_threads': False,
                'calibration_kind': None,
                'corpus_sha256': inventory['sha256'], 'permission_scope_sha256': inventory['permission_scope_sha256'],
                'binaries': manifest['binaries']}
            condition = {'concurrency': plan['concurrency'], 'mode': args.mode,
                'repetition': 0, 'warmup': plan['warmup']}
            print(json.dumps({'trial_index': index, 'total': len(plans), **plan}), flush=True)
            try:
                row = runner.run_trial(common, target, condition, inventory, queries, 0)
                for result in row['results']:
                    identity = result['query_index']
                    value = (result['exit_code'], result['output_sha256'], result['output_bytes'])
                    if identity in expected and expected[identity] != value:
                        raise ValueError('cross-condition search output differs')
                    expected[identity] = value
                campaign['trials'].append(row)
                campaign['status'] = 'COMPLETE'
            finally:
                runner.dump(target / 'campaign.json', campaign)
            manifest['campaigns'].append({'path': target.name, 'block': plan['block'],
                'stage': 'warmup' if plan['warmup'] else 'performance', 'condition': plan})
            with (args.output / 'progress.jsonl').open('a') as stream:
                stream.write(json.dumps({'index': index, 'condition': plan, 'makespan_seconds': row['makespan_ns'] / 1e9}) + '\n')
            print(json.dumps({'completed': index, 'wall_seconds': row['makespan_ns'] / 1e9}), flush=True)
            gc.collect()
        for root in [args.corpus] + roots:
            if fingerprint(runner.corpus_inventory(root)) != fingerprint(inventory):
                raise ValueError('post-campaign immutable source integrity mismatch')
        manifest.update(status='COMPLETE', output_equivalence='PASS')
    except BaseException as error:
        manifest.update(status='FAILED', error=str(error))
        raise
    finally:
        if created_parent:
            common.cgroup_parent.rmdir()
        runner.dump(args.output / 'matrix.json', manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', required=True, type=Path)
    parser.add_argument('--source-manifest', required=True, type=Path)
    parser.add_argument('--prepared', required=True, type=Path)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--queries', type=Path)
    parser.add_argument('--sampler', type=Path)
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--passes', type=int, default=1)
    parser.add_argument('--repetitions', type=int, default=5)
    parser.add_argument('--warmups', type=int, default=0)
    parser.add_argument('--seed', type=int, default=101573)
    parser.add_argument('--cpus', default='0,1,2,3')
    parser.add_argument('--concurrency', default='1,2,4,8')
    parser.add_argument('--caches', default='warm,guest-cold')
    parser.add_argument('--layouts', default='shared,independent')
    parser.add_argument('--mode', choices=('baseline', 'sampler'), default='sampler')
    parser.add_argument('--intervention', choices=('none', 'exact-reuse', 'paired'), default='none')
    args = parser.parse_args()
    cache_probe._ensure_guest()
    if os.geteuid() != 0 or args.jobs != 8 or not 1 <= args.passes <= 8 or not 1 <= args.repetitions <= 20:
        parser.error('owned root Guest, fixed eight jobs and bounded repetitions/passes required')
    try:
        concurrent = runner.parse_ints(args.concurrency)
    except (ValueError, TypeError):
        parser.error('positive unique concurrency values required')
    if (max(concurrent) > args.jobs or not 0 <= args.warmups <= 2
            or not set(args.caches.split(',')) <= {'warm', 'guest-cold'}
            or not set(args.layouts.split(',')) <= {'shared', 'independent'}
            or len(set(args.caches.split(','))) != len(args.caches.split(','))
            or len(set(args.layouts.split(','))) != len(args.layouts.split(','))):
        parser.error('bounded unique concurrency/cache/layout/warmup settings required')
    args.corpus = args.corpus.resolve(strict=True)
    args.prepared = args.prepared.absolute()
    if args.prepare_only:
        args.prepared.mkdir(mode=0o700)
        inventory, _ = prepare(args)
        print(json.dumps({'prepared': str(args.prepared), 'files': len(inventory['files']), 'bytes': inventory['bytes']}))
    else:
        if args.output is None or args.queries is None or args.sampler is None:
            parser.error('execution requires fresh output, queries and sampler')
        args.output = args.output.absolute()
        execute(args)


if __name__ == '__main__':
    main()
