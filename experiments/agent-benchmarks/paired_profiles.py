#!/usr/bin/env python3
"""Paired diagnostic cost on pinned official task controls, not model scores.

All arms use the same Observer + 100ms sampler. Each additional diagnostic is
measured separately. Fresh containers, randomized repetition blocks, no API.
"""
import argparse
import hashlib
import importlib.util
import json
import random
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path


def save(path, data):
    with Path(path).open('x') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def interval(values):
    if not values:
        return None
    rng = random.Random(2751)
    estimates = sorted(statistics.mean(rng.choices(values, k=len(values))) for _ in range(4000))
    return {'n': len(values), 'median': statistics.median(values),
            'mean_ci95_bootstrap': [estimates[99], estimates[3899]] if len(values) >= 3 else None,
            'values': values}


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _safe(root, relative):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise ValueError('artifact path must remain inside its campaign')
    path = (Path(root) / relative).resolve()
    try:
        path.relative_to(Path(root).resolve())
    except ValueError:
        raise ValueError('artifact symlink escapes campaign') from None
    return path


def _load(root, relative, sources=None, lines=False):
    path = _safe(root, relative)
    try:
        if not path.is_file() or path.stat().st_size > (128 if lines else 16) * 1024 * 1024:
            raise ValueError('artifact missing, non-regular or over offline read budget: ' + relative)
        raw = path.read_bytes()
        value = [json.loads(line) for line in raw.splitlines()] if lines else json.loads(raw)
        if (lines and any(not isinstance(row, dict) for row in value)) or (not lines and not isinstance(value, dict)):
            raise ValueError('artifact must contain JSON object(s): ' + relative)
    except (OSError, json.JSONDecodeError, UnicodeError) as error:
        raise ValueError('invalid required artifact {}: {}'.format(relative, error)) from error
    if sources is not None:
        sources[relative] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    return value


def _timing(directory, benchmark, task, sources=None):
    if benchmark == 'swe':
        events = _load(directory, 'gold-control/observation/phase-events.jsonl', sources, lines=True)
        starts = [row for row in events if row.get('phase') == 'EXECUTION_START']
        ends = [row for row in events if row.get('phase') == 'EXECUTION_END']
        if len(starts) != 1 or len(ends) != 1:
            raise ValueError('exactly one execution start/end is required')
        left, right = starts[0], ends[0]
        start, end = left.get('monotonic_ns'), right.get('monotonic_ns')
        for key in ('run_id', 'boot_id', 'task_id', 'agent_id', 'container_id', 'target'):
            if key not in left or left[key] != right.get(key):
                raise ValueError('execution boundary identity changed: ' + key)
        if left.get('task_id') != task or any(not isinstance(left.get(key), str) or not left[key]
                for key in ('run_id', 'boot_id', 'agent_id', 'container_id')) or not isinstance(left.get('target'), dict):
            raise ValueError('execution boundary lacks bound task/run/environment identity')
        identity = left
    elif benchmark == 'terminal':
        row = _load(directory, task + '-summary.json', sources)
        if row.get('task') != task or not isinstance(row.get('interval'), dict):
            raise ValueError('Terminal timing task/interval mismatch')
        identity = row['interval']
        start, end = identity.get('agent_start_ns'), identity.get('agent_end_ns')
    else:
        raise ValueError('unsupported benchmark')
    if not _integer(start) or not _integer(end) or end <= start:
        raise ValueError('execution timestamps must be nonnegative integers with positive duration')
    return start, end, identity


def execution_ns(directory, benchmark, task):
    start, end, _ = _timing(Path(directory), benchmark, task)
    return end - start


def _cgroup(value):
    if (not isinstance(value, dict) or not isinstance(value.get('path'), str) or not value['path'].startswith('/')
            or not _integer(value.get('inode'), 1) or not _integer(value.get('device'))):
        raise ValueError('missing cgroup path/inode/device identity')
    return {key: value[key] for key in ('path', 'inode', 'device')}


def _terminal_selection(summary, item, task, harbor_name):
    """Normalize only the reviewed official namespace, never suffix matching."""
    allowed = {task, 'terminal-bench/' + task}
    if harbor_name not in allowed or summary.get('selected_tasks') != [task]:
        raise ValueError('Harbor task name/selected task differs from the exact official task')
    selection = summary.get('dataset_selection')
    entries = selection.get('tasks') if isinstance(selection, dict) else None
    if not isinstance(entries, list) or any(not isinstance(row, dict) or not isinstance(row.get('name'), str) for row in entries):
        raise ValueError('missing original Terminal selection task bindings')
    names = [row['name'] for row in entries]
    selected = [row for row in entries if row['name'] in allowed]
    if len(set(names)) != len(names) or len(selected) != 1:
        raise ValueError('ambiguous or missing exact Terminal selection task')
    source_digest = selected[0].get('source_input_manifest_sha256')
    selection_digest = selection.get('selection_manifest_sha256')
    if any(not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{64}', value) is None
            for value in (source_digest, selection_digest)):
        raise ValueError('Terminal selection/source input digest missing or malformed')
    command = item.get('command')
    if not isinstance(command, list) or command.count('--selection-sha256') != 1 or command.count('--task') != 1:
        raise ValueError('paired Terminal command must bind one selection digest and exact task')
    try:
        command_digest = command[command.index('--selection-sha256') + 1]
        command_task = command[command.index('--task') + 1]
    except IndexError:
        raise ValueError('paired Terminal command lacks selection/task values') from None
    if command_digest != selection_digest or command_task != task:
        raise ValueError('Terminal original selection/task differs from the recorded invocation')
    return {'canonical_task_name': 'terminal-bench/' + task,
        'original_selection_name': selected[0]['name'], 'harbor_task_name': harbor_name,
        'source_input_manifest_sha256': source_digest, 'selection_manifest_sha256': selection_digest,
        'dataset': selection.get('dataset')}


def _trial(root, item, manifest):
    sources = {}
    terminal_selection = None
    benchmark = manifest['benchmark']
    if benchmark == 'swe':
        summary = _load(root, 'benchmark-summary.json', sources)
        task = summary.get('instance_id')
        if task not in manifest['tasks'] or (item.get('task') is not None and item['task'] != task):
            raise ValueError('undeclared/mismatched SWE task')
        if summary.get('errors') != [] or summary.get('status') != 'COMPLETED':
            raise ValueError('SWE runtime did not complete')
        gold = summary.get('gold_control', {}).get(task, {})
        observed = summary.get('observations', {}).get('gold-control', {})
        if gold.get('resolved') is not True or observed.get('observer_verification_passed') is not True or observed.get('errors'):
            raise ValueError('official task or audit summary did not pass')
        official = _load(root, 'gold-control/official-result.json', sources)
        if official.get('instance_id') != task or official.get('report') != summary['gold_control']:
            raise ValueError('official SWE receipt differs from summary')
        prefix = 'gold-control/observation/'
        verification = _load(root, prefix + 'verification.json', sources)
        start, end, timing = _timing(root, benchmark, task, sources)
        label, boot = timing['run_id'], timing['boot_id']
        target = _load(root, prefix + 'target.json', sources)
        if target != timing['target'] or target != observed.get('target'):
            raise ValueError('SWE environment target binding differs')
        path = target.get('cgroup_path')
        if not isinstance(path, str) or not path.startswith('/'):
            raise ValueError('SWE target cgroup path missing')
        expected_group = {'path': '/sys/fs/cgroup' + path, 'inode': target.get('cgroup_inode'), 'device': target.get('cgroup_device')}
        load = prefix + 'load/'
        diag_path = prefix + 'diagnostics/diagnostics.json'
        post = _load(root, prefix + 'post-execution-sample.json', sources)
        if not _integer(post.get('monotonic_ns')) or post['monotonic_ns'] <= end:
            raise ValueError('SWE lacks a real post-execution sample')
    else:
        summary = _load(root, 'campaign-summary.json', sources)
        if not isinstance(summary.get('tasks'), list) or len(summary['tasks']) != 1:
            raise ValueError('one Terminal task per paired trial')
        row = summary['tasks'][0]
        task = row.get('task')
        if task not in manifest['tasks'] or (item.get('task') is not None and item['task'] != task):
            raise ValueError('undeclared/mismatched Terminal task')
        if row != _load(root, task + '-summary.json', sources):
            raise ValueError('Terminal task receipt differs from campaign summary')
        if row.get('task_reward_passed') is not True or any(row.get(key) for key in ('error', 'observer_error', 'sampler_error', 'harbor_exception')):
            raise ValueError('Terminal official task/runtime failed')
        start, end, timing = _timing(root, benchmark, task, sources)
        label, boot = timing.get('run_id'), timing.get('boot_id')
        if any(not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', value) for value in (label, boot)):
            raise ValueError('Terminal timing lacks safe run/boot identity')
        if timing.get('sampler_binding_validated') is not True or not _integer(timing.get('post_agent_sample_ns')) or timing['post_agent_sample_ns'] <= end:
            raise ValueError('Terminal lacks sampler binding/post-execution evidence')
        expected_group = {'path': timing.get('cgroup_path'), 'inode': timing.get('cgroup_inode'), 'device': timing.get('cgroup_device')}
        control = 'evidence/' + label + '/control/'
        verification = _load(root, control + 'offline-verification.json', sources)
        completion = _load(root, control + 'observer-summary.json', sources)
        if (completion.get('status') != 'OBSERVER_VERIFIED' or completion.get('task_label') != task
                or completion.get('run_id') != label or completion.get('container_id') != timing.get('container_id')
                or completion.get('observer', {}).get('offline_verification') != verification
                or row.get('observer_completed') != [completion]):
            raise ValueError('Terminal independent verifier/completion receipt binding failed')
        target = _load(root, control + 'target.json', sources)
        if (target.get('task_label') != task or target.get('container_id') != timing.get('container_id')
                or target.get('cgroup_id') != expected_group['inode']
                or '/sys/fs/cgroup' + str(target.get('cgroup_path')) != expected_group['path']):
            raise ValueError('Terminal container/cgroup target binding failed')
        result_path = row.get('harbor_result')
        if not isinstance(result_path, str) or 'harbor-trials' not in Path(result_path).parts:
            raise ValueError('missing original Harbor verifier result')
        parts = Path(result_path).parts
        harbor = _load(root, str(Path(*parts[parts.index('harbor-trials'):])), sources)
        terminal_selection = _terminal_selection(summary, item, task, harbor.get('task_name'))
        if (harbor.get('exception_info') is not None
                or harbor.get('verifier_result', {}).get('rewards') != row.get('harbor_rewards')
                or row.get('harbor_rewards') != {'reward': 1.0}
                or type(row.get('harbor_rewards', {}).get('reward')) not in (int, float)):
            raise ValueError('original Harbor verifier result did not pass')
        load = 'profiles/' + task + '/'
        diag_path = 'profiles/' + task + '-diagnostics/diagnostics.json'
    if verification.get('verified') is not True or verification.get('run_id') != label:
        raise ValueError('independent verifier receipt failed or belongs to another run')
    expected_group = _cgroup(expected_group)
    meta = _load(root, load + 'load-meta.json', sources)
    stats = _load(root, load + 'load-sampler-stats.json', sources)
    groups = meta.get('cgroups')
    if (meta.get('label') != label or meta.get('boot_id') != boot or meta.get('interval_ms') != 100
            or meta.get('process_interval_ms') != 100 or not isinstance(groups, list) or len(groups) != 1
            or _cgroup(groups[0]) != expected_group):
        raise ValueError('sampler run/boot/cgroup/100ms binding mismatch')
    detail = _load(root, diag_path, sources)
    if (detail.get('status') not in ('COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE', 'INCOMPLETE')
            or detail.get('mode') != item['mode'] or detail.get('label') != label
            or detail.get('boot_id') != boot or _cgroup(detail.get('cgroup')) != expected_group):
        raise ValueError('diagnostic mode/run/environment binding failed or did not finish')
    for name in ('start_boundary', 'ready_boundary', 'finish_boundary'):
        boundary = detail.get(name)
        if not isinstance(boundary, dict) or not _integer(boundary.get('monotonic_ns')):
            raise ValueError('diagnostic lifecycle boundary missing')
        if item['mode'] != 'baseline' and boundary.get('cgroup_events', {}).get('frozen') != '1':
            raise ValueError('diagnostic workload was not frozen at the boundary')
        if item['mode'] in ('threads', 'kernel') and boundary.get('schedstats') != '1':
            raise ValueError('thread diagnostic lacks schedstats=1 boundary evidence')
    if not (detail['start_boundary']['monotonic_ns'] <= detail['ready_boundary']['monotonic_ns'] <= start
            < end <= detail['finish_boundary']['monotonic_ns']):
        raise ValueError('diagnostic was not ready across the measured execution window')
    if item['mode'] in ('threads', 'kernel'):
        if (meta.get('thread_sampling', {}).get('enabled') is not True
                or meta.get('thread_sampling', {}).get('schedstats_runtime_enabled_at_start') is not True):
            raise ValueError('thread diagnostic was not enabled at sampler READY')
    if item['mode'] == 'kernel':
        kernel = meta.get('kernel_hist')
        expected_sha = manifest.get('diagnostic_assets', {}).get('kernel_hist_sha256')
        if (not isinstance(kernel, dict) or not isinstance(expected_sha, str) or len(expected_sha) != 64
                or kernel.get('object_sha256') != expected_sha.lower()
                or set(kernel.get('groups', [])) != {'sched', 'mem', 'lock', 'blk', 'irq', 'syscall'}):
            raise ValueError('kernel diagnostic lacks bound full probe set/object digest')
    if item['mode'] in ('files', 'perf'):
        code = detail.get('collector_usage', {}).get('returncode')
        expected_perf_sigint = (item['mode'] == 'perf' and type(code) is int and code == -2
            and detail.get('collector_termination') == 'EXPECTED_PERF_SIGINT_REQUIRES_VALID_REPORT'
            and detail.get('perf_acknowledged_commands') == ['enable', 'disable']
            and detail.get('perf_report_returncode') == 0)
        if type(code) is not int or (code != 0 and not expected_perf_sigint):
            raise ValueError('diagnostic collector did not exit successfully')
        if item['mode'] == 'files' and detail.get('file_metadata_binding_validated') is not True:
            raise ValueError('file diagnostic metadata was not bound')
        if item['mode'] == 'perf' and detail.get('perf_scope', {}).get('enable_ack_received') is not True:
            raise ValueError('perf never acknowledged enable')
        if item['mode'] == 'perf':
            diagnostic_dir = str(Path(diag_path).parent)
            controls = _load(root, diagnostic_dir + '/perf-control.jsonl', sources, lines=True)
            if ([row.get('command') for row in controls] != ['enable', 'disable']
                    or any(row.get('ack', '').strip('\0\r\n') != 'ack' for row in controls)
                    or type(detail.get('perf_report_returncode')) is not int or detail['perf_report_returncode'] != 0):
                raise ValueError('raw perf control/report did not finalize successfully')
            data = _safe(root, diagnostic_dir + '/perf.data')
            if not data.is_file() or data.stat().st_size <= 0:
                raise ValueError('perf did not preserve nonempty raw data')
            sources[diagnostic_dir + '/perf.data'] = {'sha256': sha(data), 'bytes': data.stat().st_size}
    health_issues = []
    if not isinstance(detail.get('issues'), list):
        raise ValueError('diagnostic health issue list is missing')
    for key in ('read_errors', 'missed_ticks', 'vanished_processes', 'truncated_process_sets',
            'truncated_cgroup_traversals', 'cgroup_traversal_read_errors', 'thread_read_errors',
            'vanished_threads_during_read', 'truncated_thread_samples', 'thread_identity_changes'):
        value = stats.get(key)
        if not _integer(value) or value:
            health_issues.append({'source': 'sampler/' + key, 'value': value})
    health_issues.extend({'source': 'diagnostics', 'value': value} for value in detail.get('issues', []))
    if detail.get('status') == 'INCOMPLETE' and not detail.get('issues'):
        health_issues.append({'source': 'diagnostics/status', 'value': 'INCOMPLETE_WITHOUT_DETAIL'})
    kernel_history = {'status': 'NOT_COLLECTED'}
    if item['mode'] == 'kernel':
        analyzer_path = Path(__file__).resolve().parents[1] / 'search-profile/analyze.py'
        if not analyzer_path.is_file():
            # Guest copies need not include the optional offline analyzer. Its
            # absence never upgrades raw collector finalization into coverage.
            kernel_history = {'status': 'NOT_EVALUATED', 'reason': 'offline kernel analyzer not shipped',
                              'raw_configuration': meta.get('kernel_hist'), 'raw_final_health': stats.get('kernel_hist')}
            health_issues.append({'source': 'kernel_history', 'value': 'NOT_EVALUATED'})
        else:
            try:
                spec = importlib.util.spec_from_file_location('paired_offline_kernel_analysis', analyzer_path)
                analyzer = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(analyzer)
                samples = _load(root, load + 'load-samples.jsonl', sources, lines=True)
                problems = analyzer.Problems()
                hist = analyzer._kernel_hist(meta, stats, samples, problems, requested=True)
                kernel_history = {key: hist.get(key) for key in ('status', 'issues', 'diagnostic_counters', 'programs',
                    'block_diagnostics', 'memory_return_probe_profiles', 'tracefs_cleanup')}
                kernel_history['issues'] = problems.items
                kernel_history['domains'] = [{key: domain.get(key) for key in ('domain_index', 'target_identity',
                    'status', 'issues', 'diagnostic_counters')} for domain in hist.get('domains', [])]
                kernel_history['analyzer_sha256'] = sha(analyzer_path)
                health_issues.extend({'source': 'kernel_history', 'value': issue} for issue in problems.items)
                if hist.get('status') != 'NO_REPORTED_LOSS_WITHIN_SELECTED_PROBES' and not problems.items:
                    health_issues.append({'source': 'kernel_history/status', 'value': hist.get('status')})
            except (ValueError, TypeError, KeyError, OSError) as error:
                kernel_history = {'status': 'INCONCLUSIVE', 'reason': str(error), 'analyzer_sha256': sha(analyzer_path)}
                health_issues.append({'source': 'kernel_history', 'value': str(error)})
    evidence_status = verification.get('evidence_status', 'UNKNOWN')
    if item['mode'] == 'perf':
        health_issues.append({'source': 'perf_history',
            'value': 'NOT_EVALUATED; acknowledged enable/disable and readable perf.data do not prove absence of lost samples, unwind errors or unresolved symbols'})
    return {**item, 'task': task, 'run_id': label, 'boot_id': boot,
        'hot_seconds': (end - start) / 1e9, 'execution_window': [start, end],
        'official_control_passed': True, 'audit_verified': True, 'audit_evidence_status': evidence_status,
        'diagnostic_collection_status': 'FINALIZED',
        'measurement_health': {'status': 'INCOMPLETE' if health_issues else 'NO_REPORTED_GAPS_WITHIN_SAVED_HEALTH_COUNTERS',
                               'issues': health_issues, 'not_complete_thread_lifecycle': True},
        'kernel_history': kernel_history,
        'perf_history_status': 'NOT_EVALUATED_SAMPLED_SYMBOL_CANDIDATES_ONLY' if item['mode'] == 'perf' else 'NOT_COLLECTED',
        'thread_history_status': 'PARTIAL_POLLING_NOT_FULL_LIFECYCLE' if item['mode'] in ('threads', 'kernel') else 'NOT_COLLECTED',
        'terminal_selection_binding': terminal_selection,
        'diagnostics': detail, 'sources': sources}


def replay(root):
    root = Path(root)
    manifest = _load(root, 'campaign.json')
    if type(manifest.get('schema_version')) is not int or manifest.get('schema_version') != 1 or manifest.get('status') != 'COMPLETE' or manifest.get('benchmark') not in ('swe', 'terminal'):
        raise ValueError('campaign must be a completed supported schema-1 benchmark')
    repetitions, tasks, modes, runs = (manifest.get(key) for key in ('repetitions', 'tasks', 'modes', 'runs'))
    if (not _integer(repetitions, 3) or repetitions > 10 or not isinstance(tasks, list) or not tasks
            or any(not isinstance(task, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', task) or task in ('.', '..') for task in tasks)
            or len(set(tasks)) != len(tasks) or not isinstance(modes, list) or not modes
            or any(mode not in ('baseline', 'threads', 'kernel', 'files', 'perf') for mode in modes)
            or len(set(modes)) != len(modes) or 'baseline' not in modes or not isinstance(runs, list)
            or len(runs) != repetitions * len(tasks) * len(modes)):
        raise ValueError('invalid/duplicate declarations or incomplete paired campaign')
    rows = []
    seen_paths, seen_pairs = set(), set()
    terminal_task_sources = {}
    terminal_selection_digest = None
    for item in runs:
        if (not isinstance(item, dict) or type(item.get('returncode')) is not int or item['returncode'] != 0
                or not _integer(item.get('block')) or item['block'] >= repetitions or item.get('mode') not in modes):
            raise ValueError('failed, malformed or undeclared paired trial')
        path = _safe(root, item.get('path'))
        if path == root.resolve() or path in seen_paths:
            raise ValueError('duplicate or root trial path')
        seen_paths.add(path)
        config = _load(root, item['path'] + '-artifacts.json')
        expected_config = {**manifest.get('artifacts', {}), 'diagnostics': {**manifest.get('diagnostic_assets', {}), 'mode': item['mode']}}
        if config != expected_config:
            raise ValueError('paired arm artifact configuration differs from campaign contract')
        row = _trial(path, item, manifest)
        binding = row.get('terminal_selection_binding')
        if binding is not None:
            source = (binding['source_input_manifest_sha256'], binding.get('dataset'))
            if row['task'] in terminal_task_sources and terminal_task_sources[row['task']] != source:
                raise ValueError('Terminal original source input/dataset changed between paired repetitions')
            terminal_task_sources[row['task']] = source
            if terminal_selection_digest is not None and terminal_selection_digest != binding['selection_manifest_sha256']:
                raise ValueError('Terminal selection manifest changed between paired repetitions')
            terminal_selection_digest = binding['selection_manifest_sha256']
        pair = (row['task'], row['mode'], row['block'])
        if pair in seen_pairs:
            raise ValueError('duplicate paired task/mode/block')
        seen_pairs.add(pair)
        row['artifact_config_sha256'] = sha(_safe(root, item['path'] + '-artifacts.json'))
        rows.append(row)
    expected_pairs = {(task, mode, block) for task in tasks for mode in modes for block in range(repetitions)}
    if seen_pairs != expected_pairs:
        raise ValueError('missing or extra paired task/mode/block')
    reports = []
    for task in manifest['tasks']:
        baseline = {row['block']: row for row in rows if row['task'] == task and row['mode'] == 'baseline'}
        for mode in manifest['modes']:
            selected = [row for row in rows if row['task'] == task and row['mode'] == mode]
            if len(selected) != manifest['repetitions']:
                raise ValueError('missing paired repetitions')
            reports.append({'task': task, 'mode': mode,
                'hot_seconds': interval([row['hot_seconds'] for row in selected]),
                'relative_to_same_observer_sampler_percent': interval([
                    (row['hot_seconds'] / baseline[row['block']]['hot_seconds'] - 1) * 100
                    for row in selected]) if mode != 'baseline' else None})
    kernel_incremental = []
    if 'kernel' in modes and 'threads' in modes:
        for task in tasks:
            reference = {row['block']: row for row in rows if row['task'] == task and row['mode'] == 'threads'}
            selected = [row for row in rows if row['task'] == task and row['mode'] == 'kernel']
            kernel_incremental.append({'task': task, 'reference': 'threads (same block, same 100ms thread polling)',
                'kernel_incremental_percent': interval([(row['hot_seconds'] / reference[row['block']]['hot_seconds'] - 1) * 100 for row in selected])})
    return {'schema_version': 1, 'status': 'PASS', 'benchmark': manifest['benchmark'],
            'scope': 'PINNED_OFFICIAL_REFERENCE_CONTROLS_NOT_AUTONOMOUS_MODEL_SCORE',
            'reference': 'same Observer + 100ms sampler; one extra diagnostic at a time',
            'small_sample_not_production_SLA': True, 'trial_count': len(rows), 'results': reports, 'runs': rows,
            'measurement_health': 'INCOMPLETE' if any(row['measurement_health']['status'] == 'INCOMPLETE' for row in rows) else 'NO_REPORTED_GAPS_WITHIN_SAVED_HEALTH_COUNTERS',
            'paired_kernel_over_threads': kernel_incremental, 'replay_source_sha256': sha(__file__),
            'limitations': ['confidence unit is randomized repetition block, not pooled processes',
                'task time includes command transport; short Oracle shell work can be below sampler resolution',
                'successful verifier replay does not imply complete syscall/object evidence',
                'kernel/baseline is a thread-polling plus kernel-probe bundle; paired_kernel_over_threads isolates the additional probes',
                'collector finalization and valid timing do not imply complete diagnostic history; health and audit evidence are retained independently',
                'independent verifier receipts are bound here; this parser is not itself a replacement for replaying raw Observer WAL',
                'no GPU and no model API cost; CPU inference scheduling is a separate augmented experiment']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--benchmark', choices=['swe', 'terminal'])
    parser.add_argument('--root', type=Path, default=Path('/opt/agent-benchmarks'))
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--diagnostic-assets', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repetitions', type=int, default=5)
    parser.add_argument('--modes', default='baseline,threads,kernel,files,perf')
    parser.add_argument('--task', action='append')
    parser.add_argument('--replay', action='store_true')
    args = parser.parse_args()
    if args.replay:
        print(json.dumps(replay(args.output), sort_keys=True))
        return
    if not args.benchmark or not args.artifacts or not args.diagnostic_assets or not 3 <= args.repetitions <= 10:
        parser.error('benchmark/artifacts/diagnostic-assets and 3..10 repetition blocks required')
    modes = args.modes.split(',')
    if len(modes) != len(set(modes)) or 'baseline' not in modes or not set(modes) <= {'baseline', 'threads', 'kernel', 'files', 'perf'}:
        parser.error('unique supported modes including baseline required')
    tasks = args.task or (['psf__requests-1142'] if args.benchmark == 'swe' else ['html-js-filter', 'bun-sourcemap-leak'])
    if args.benchmark == 'swe' and tasks != ['psf__requests-1142']:
        parser.error('only the pinned prepared SWE instance is admitted')
    args.output.mkdir(parents=True, exist_ok=False)
    base = json.loads(args.artifacts.read_text())
    extra = json.loads(args.diagnostic_assets.read_text())
    runs = []
    manifest = {'schema_version': 1, 'benchmark': args.benchmark, 'tasks': tasks, 'modes': modes,
        'repetitions': args.repetitions, 'seed': 2751, 'artifacts': base, 'diagnostic_assets': extra,
        'source_sha256': sha(__file__), 'runs': runs, 'status': 'RUNNING'}
    rng = random.Random(2751)
    try:
        for block in range(args.repetitions):
            conditions = [(task, mode) for task in tasks for mode in modes]
            rng.shuffle(conditions)
            for task, mode in conditions:
                name = '%03d-r%d-%s-%s' % (len(runs), block, task, mode)
                config = {**base, 'diagnostics': {**extra, 'mode': mode}}
                configpath = args.output / (name + '-artifacts.json')
                save(configpath, config)
                if args.benchmark == 'swe':
                    command = ['/opt/swe-venv/bin/python', '-B', str(args.root / 'swe/run.py'),
                        '--inputs', str(args.root / 'swe-inputs'), '--output-dir', str(args.output / name),
                        '--artifacts', str(configpath), '--bridge', str(args.root / 'terminal-bridge.py'),
                        '--image-import-provenance', str(args.root / 'swe-image-requests-1142.tar.json')]
                else:
                    command = ['/opt/harbor-venv/bin/python', '-B', str(args.root / 'terminal/run.py'),
                        '--bridge', str(args.root / 'terminal-bridge.py'), '--bridge-config', str(configpath),
                        '--selection', '/opt/bpf-observer/selected-tasks.json', '--selection-sha256',
                        sha('/opt/bpf-observer/selected-tasks.json'), '--tasks-dir', '/opt/terminal-bench-v4/tasks',
                        '--task', task, '--sampler', base['sampler_binary'], '--agent', 'oracle',
                        '--prebuilt-images', str(args.root / 'terminal/prebuilt-images.example.json'),
                        '--output', str(args.output / name)]
                print(json.dumps({'starting': name}), flush=True)
                start = time.monotonic_ns()
                with (args.output / (name + '.stdout')).open('xb') as out, (args.output / (name + '.stderr')).open('xb') as err:
                    completed = subprocess.run(command, stdout=out, stderr=err, timeout=900)
                runs.append({'path': name, 'block': block, 'mode': mode, 'returncode': completed.returncode,
                             'orchestration_ns': time.monotonic_ns() - start, 'command': command})
                if completed.returncode:
                    raise RuntimeError('task failed; preserve evidence: ' + name)
        manifest['status'] = 'COMPLETE'
    except BaseException as error:
        manifest.update(status='FAILED', error=str(error))
        raise
    finally:
        save(args.output / 'campaign.json', manifest)
    save(args.output / 'paired-report.json', replay(args.output))


if __name__ == '__main__':
    main()
