#!/usr/bin/env python3
"""Seal completed owned-Guest evidence before export; never edits raw trials."""
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

import paired_profiles


RUNTIME = Path('/opt/agent-benchmarks')
OBSERVER = Path('/opt/bpf-observer')
LEGACY_SEARCH = Path('/opt/search-profile')
TASKS = Path('/opt/terminal-bench-v4/tasks')
MARKERS = ('export-environment.json', 'export-inputs.json', 'export-inventory.json', 'executed-sources/final-runtime')
ASSETS = (('observer_binary', 'observer_sha256'), ('verifier_binary', 'verifier_sha256'),
    ('recorder_object', 'recorder_sha256'), ('lifecycle_object', 'lifecycle_sha256'),
    ('ip_binary', 'ip_sha256'), ('tc_binary', 'tc_sha256'), ('nft_binary', 'nft_sha256'),
    ('sampler_binary', 'sampler_sha256'))
DIAGNOSTIC_ASSETS = (('kernel_hist_object', 'kernel_hist_sha256'), ('file_profiler_binary', 'file_profiler_sha256'),
    ('file_profiler_object', 'file_profiler_object_sha256'), ('perf_binary', 'perf_sha256'))


def sha(path):
    path = Path(path)
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def regular(path):
    path = Path(path)
    if path != path.resolve(strict=True) or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('canonical regular file required, no symlink or special file: ' + str(path))
    return path


def below(path, root):
    try:
        Path(path).relative_to(Path(root))
        return True
    except ValueError:
        return False


def read(path):
    path = regular(path)
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('JSON exceeds seal read budget: ' + str(path))
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError('JSON object required: ' + str(path))
    return value


def inside(root, relative):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise ValueError('relative campaign path required')
    path = Path(root) / relative
    if path != path.resolve(strict=True) or not below(path, root):
        raise ValueError('campaign path escapes root or traverses symlink')
    return path


def tree_files(root):
    """Do not silently omit links or follow them outside the evidence scope."""
    root = Path(root)
    if root != root.resolve(strict=True) or not root.is_dir():
        raise ValueError('canonical existing directory required: ' + str(root))
    files = []
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(dirs + names):
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError('unknown symlink/special file in export scope: ' + str(path))
            if stat.S_ISREG(mode):
                files.append(path)
    return sorted(files, key=lambda path: str(path.relative_to(root)))


def fresh(root):
    for name in MARKERS:
        if (root / name).exists() or (root / name).is_symlink():
            raise ValueError('refusing existing seal output: ' + name)
    parent = root / 'executed-sources'
    if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
        raise ValueError('executed-sources must be a real directory')


def validate_query(directory, benchmark):
    campaign = read(directory / 'source-query-campaign.json')
    runs = campaign.get('runs')
    if (campaign.get('schema_version') != 1 or campaign.get('benchmark') != benchmark or not isinstance(runs, list)
            or len(runs) != 2 or {row.get('intervention') for row in runs} != {'none', 'exact-reuse'}
            or any(type(row.get('returncode')) is not int or row['returncode'] != 0 for row in runs)):
        raise ValueError('query interventions missing, duplicated or unfinished: ' + str(directory))
    expected = {(c, mode, rep, warm) for c in (1, 8) for mode in ('baseline', 'sampler')
        for warm in (False, True) for rep in (range(1) if warm else range(5))}
    for run in runs:
        intervention = run['intervention']
        child = directory / intervention
        if Path(run.get('path', '')) != child:
            raise ValueError('query manifest path differs from declared intervention')
        manifest = read(child / 'campaign.json')
        if (manifest.get('status') != 'COMPLETE' or manifest.get('intervention') != intervention
                or manifest.get('jobs') != 8 or manifest.get('passes') != 8
                or manifest.get('repository_version') != campaign.get('source', {}).get('image_id')):
            raise ValueError('raw query campaign fixed work/source/status incomplete')
        declarations, trials = manifest.get('conditions'), manifest.get('trials')
        if not isinstance(trials, list) or not isinstance(declarations, list) or len(trials) != 24 or len(declarations) != 24:
            raise ValueError('all 24 query trials including warmups required')
        keys = ('concurrency', 'mode', 'repetition', 'warmup')
        for records in (declarations, trials):
            identities = [tuple(item.get(key) for key in keys) for item in records]
            if (set(identities) != expected or len(set(identities)) != 24
                    or any(type(item.get('warmup')) is not bool or type(item.get('concurrency')) is not int
                        or type(item.get('repetition')) is not int for item in records)):
                raise ValueError('query block/condition duplicated or changed')
        seen_paths, seen_runs = set(), set()
        for item in trials:
            trial = inside(child, item.get('path'))
            if trial in seen_paths or item.get('run_id') in seen_runs:
                raise ValueError('query trial path/run duplicated')
            seen_paths.add(trial)
            seen_runs.add(item.get('run_id'))
            profile = read(trial / 'profile-run.json')
            if (profile.get('status') != 'COMPLETE' or profile.get('run_id') != item.get('run_id')
                    or any(profile.get('config', {}).get(key) != item.get(key) for key in keys)
                    or profile.get('config', {}).get('corpus_sha256') != manifest.get('corpus_sha256')):
                raise ValueError('query trial lifecycle/config not bound to declaration')
            results = profile.get('results')
            if not isinstance(results, list) or len(results) != 8 or len({row.get('task_id') for row in results}) != 8:
                raise ValueError('query task count/identity incomplete')
            for result in results:
                task = result.get('task_id')
                if not isinstance(task, str) or not re.fullmatch(r'task-[0-9]{4}', task):
                    raise ValueError('unsafe query task id')
                statistics = read(trial / (task + '-statistics.json'))
                spans = statistics.get('query_spans')
                if statistics.get('logical_queries') != 8 or not isinstance(spans, list) or len(spans) != 8:
                    raise ValueError('query task lacks eight raw spans')
                for ordinal, span in enumerate(spans):
                    if (span.get('run_id') != profile['run_id'] or span.get('task_id') != task
                            or span.get('query_ordinal') != ordinal or span.get('status') != 'COMPLETE'
                            or type(span.get('duration_ns')) is not int or span['duration_ns'] <= 0
                            or type(span.get('begin_ns')) is not int or type(span.get('end_ns')) is not int
                            or span['end_ns'] - span['begin_ns'] != span['duration_ns']):
                        raise ValueError('query raw timing/identity incomplete')
                raw = regular(trial / (task + '.stdout')).read_bytes()
                fields = raw.split(b'\0')
                digest = hashlib.sha256(b'\0'.join(sorted(fields[:-1])) + b'\0').hexdigest()
                if fields[-1] != b'' or digest != result.get('output_sha256') or len(raw) != result.get('output_bytes'):
                    raise ValueError('query raw output does not match receipt')
    return {'benchmark': benchmark, 'interventions': 2, 'trials_including_warmups': 48,
        'raw_logical_query_spans': 3072, 'scope': 'SEAL_SHAPE_AND_RAW_BINDING_CHECK_NOT_FULL_HOST_REPLAY'}


def validate_campaigns(root):
    reports = []
    for name, benchmark, tasks in (('paired-swe-001', 'swe', {'psf__requests-1142'}),
            ('paired-terminal-001', 'terminal', {'html-js-filter', 'bun-sourcemap-leak'})):
        manifest = read(root / name / 'campaign.json')
        if (manifest.get('status') != 'COMPLETE' or manifest.get('benchmark') != benchmark
                or set(manifest.get('tasks', [])) != tasks or len(manifest.get('tasks', [])) != len(tasks)
                or set(manifest.get('modes', [])) != {'baseline', 'threads', 'kernel', 'files', 'perf'}
                or len(manifest.get('modes', [])) != 5 or manifest.get('repetitions') != 5):
            raise ValueError('official campaign task/mode/repetition/status contract incomplete: ' + name)
        # Existing replay checks unique task/mode/block, exact raw trial paths,
        # official receipts and saved Observer bindings. Missing Guest offline
        # helpers only lower health; they are never converted into coverage.
        report = paired_profiles.replay(root / name)
        reports.append({'campaign': name, 'trial_count': report['trial_count'],
            'binding_replay_status': report['status'], 'measurement_health': report['measurement_health']})
    for name, benchmark in (('queries-swe-001', 'swe'), ('queries-terminal-001', 'terminal')):
        reports.append({'campaign': name, **validate_query(root / name, benchmark)})
    return reports


def input_plan(root):
    plans = []
    selected = [RUNTIME / name for name in ('diagnostics.py', 'paired_profiles.py', 'source_queries.py',
        'prepare_profiles.py', 'seal_profiles.py', 'terminal-bridge.py', 'swe/run.py', 'terminal/run.py',
        'terminal/prebuilt-images.example.json', 'swe-inputs/task.json', 'swe-inputs/provenance.json',
        'swe-inputs/harness.tar.gz', 'swe-image-requests-1142.tar.json')]
    selected += [OBSERVER / 'selected-tasks.json', LEGACY_SEARCH / 'analyze.py']
    for task in ('html-js-filter', 'bun-sourcemap-leak'):
        selected += tree_files(TASKS / task)
    for source in selected:
        source = regular(source)
        plans.append({'source': source, 'target': Path('external-sources') / str(source).lstrip('/'),
                      'sha256': sha(source), 'pin_source': 'EXECUTED_RUNTIME_OR_OFFICIAL_INPUT_CAPTURE'})
    for manifest_name, declarations in (('artifacts.json', ASSETS), ('diagnostic-assets.json', DIAGNOSTIC_ASSETS)):
        metadata = read(root / manifest_name)
        for path_key, digest_key in declarations:
            source = regular(Path(metadata[path_key]))
            allowed = below(source, root / 'bin') or below(source, RUNTIME) or below(source, OBSERVER)
            if path_key == 'perf_binary':
                allowed = source == Path('/usr/bin/perf').resolve(strict=True)
            digest = metadata.get(digest_key)
            if not allowed or not isinstance(digest, str) or not re.fullmatch(r'[a-fA-F0-9]{64}', digest) or sha(source) != digest.lower():
                raise ValueError('pinned asset scope/SHA256 mismatch: ' + path_key)
            plans.append({'source': source, 'target': Path('pinned-assets') / path_key,
                          'sha256': digest.lower(), 'pin_source': manifest_name + ':' + digest_key})
    targets = [str(row['target']) for row in plans]
    if len(set(targets)) != len(targets):
        raise ValueError('duplicate input archive target')
    return plans


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def seal(root):
    root = Path(root).resolve(strict=True)
    fresh(root)
    tree_files(root)
    checks = validate_campaigns(root)
    plans = input_plan(root)  # Validate every required source before mutation.
    containers = subprocess.check_output(['docker', 'ps', '-q'], text=True).split()
    if containers:
        raise RuntimeError('owned experiment Guest still has running containers; inspect exact owners before sealing')
    sources = root / 'executed-sources/final-runtime'
    sources.mkdir(parents=True, exist_ok=False)
    copied = []
    for item in plans:
        target = sources / item['target']
        target.parent.mkdir(parents=True, exist_ok=True)
        with item['source'].open('rb') as source, target.open('xb') as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        if sha(target) != item['sha256'] or sha(item['source']) != item['sha256']:
            raise ValueError('input changed during copy; preserve partial export: ' + str(item['source']))
        copied.append({**{key: str(value) for key, value in item.items()},
                       'target': str(target.relative_to(root)), 'bytes': target.stat().st_size})
    save(root / 'export-inputs.json', {'schema_version': 1, 'inputs': copied, 'campaign_preflight': checks,
        'scope': 'COPY_AND_SAVED_BINDING_COMPLETENESS_NOT_REPLACEMENT_FOR_HOST_WAL_OR_RESOURCE_REPLAY'})
    trace = Path('/sys/kernel/tracing/kprobe_events')
    receipt = {'schema_version': 1, 'scope': 'OWNED_QEMU_GUEST_COMPLETED_CAMPAIGN_EXPORT',
        'sealed_monotonic_ns': time.monotonic_ns(), 'sealed_wall_ns': time.time_ns(),
        'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'kernel': subprocess.check_output(['uname', '-a'], text=True).strip(),
        'kernel_command_line': Path('/proc/cmdline').read_text().strip(),
        'schedstats': Path('/proc/sys/kernel/sched_schedstats').read_text().strip(),
        'docker_version': subprocess.check_output(['docker', '--version'], text=True).strip(),
        'running_containers': containers, 'remaining_kprobe_events': trace.read_text() if trace.exists() else None,
        'gpu': 'EXCLUDED_BY_USER', 'new_model_api_requests': 0, 'inventory_excludes_its_own_file': True,
        'scope_note': 'Reference-control results are not autonomous model scores. Incomplete histories stay incomplete.'}
    save(root / 'export-environment.json', receipt)
    inventory = {}
    for path in tree_files(root):
        before = path.stat()
        digest = sha(path)
        after = path.stat()
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('raw evidence changed during inventory; preserve partial export: ' + str(path))
        inventory[str(path.relative_to(root))] = {'sha256': digest, 'bytes': after.st_size}
    save(root / 'export-inventory.json', inventory)
    return {'sealed': str(root), 'boot_id': receipt['boot_id'], 'running_containers': 0,
            'inventory_sha256': sha(root / 'export-inventory.json'), 'files': len(inventory)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    vendor = ' '.join(Path('/sys/class/dmi/id', name).read_text() for name in ('product_name', 'sys_vendor'))
    if (os.geteuid() != 0 or not any(word in vendor.lower() for word in ('qemu', 'kvm')) or root.parent != Path('/opt')
            or not re.fullmatch(r'benchmark-profile-[0-9]{8}[A-Za-z0-9_.-]*', root.name)):
        parser.error('explicit /opt experiment directory in the owned root Guest required')
    print(json.dumps(seal(root)))


if __name__ == '__main__':
    main()
