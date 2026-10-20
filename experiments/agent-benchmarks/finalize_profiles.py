#!/usr/bin/env python3
"""Read-only, dimension-preserving Host summary of the 2026-10-15 pilots.

This recomputes saved measurements; it never runs a workload, calls a model,
changes evidence, or turns a reference-control result into an Agent score.
"""
from collections import Counter
from contextlib import contextmanager
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import paired_profiles
import thread_wait_report


HERE = Path(__file__).resolve().parent
ERRORS = (OSError, ValueError, KeyError, TypeError)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def read(path):
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('offline JSON exceeds 128 MiB budget: ' + str(path))
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError('expected JSON object: ' + str(path))
    return value


def sha(path):
    return paired_profiles.sha(path)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


@contextmanager
def execution_tuner():
    # Legacy sibling imports use generic names. Isolate them from the search
    # analyzer and restore the embedding caller's modules after offline replay.
    names = ('analyze', 'run', 'semantic', 'local_inference', 'workloads')
    previous = {name: sys.modules.pop(name) for name in names if name in sys.modules}
    directory = HERE.parent / 'execution-profile'
    sys.path.insert(0, str(directory))
    try:
        yield module(directory / 'tune_static.py', 'finalize_execution_tuner')
    finally:
        sys.path.remove(str(directory))
        for name in names:
            sys.modules.pop(name, None)
        sys.modules.update(previous)


def compact_interval(value):
    return {key: item for key, item in value.items() if key != 'values'} if isinstance(value, dict) else value


def summarize_threads(load, row, output):
    meta = read(load / 'load-meta.json')
    group = row['diagnostics']['cgroup']
    groups = meta.get('cgroups')
    if not isinstance(groups, list) or len(groups) != 1:
        raise ValueError('paired thread report requires exactly one externally bound cgroup')
    # Identity fields come from phase/diagnostic evidence, not sampler self-
    # assertion. Other sampler configuration fields are retained, not vouched
    # for as independent identity anchors.
    expected = {'label': row['run_id'], 'boot_id': row['boot_id'],
                'cgroups': [{**groups[0], **{key: group[key] for key in ('path', 'inode', 'device')}}]}
    report = thread_wait_report.load_report(load, expected, row['execution_window'])
    report['anchor_basis'] = 'EXECUTION_PHASE_AND_DIAGNOSTIC_RUN_BOOT_CGROUP_IDENTITY; OTHER_META_FIELDS_NOT_EXTERNAL_ANCHORS'
    save(output, report)
    intervals = [interval for item in report['instances'] for interval in item['intervals']]
    inside = [interval for interval in intervals if interval['execution_window_relation'] == 'FULLY_INSIDE_EXECUTION_WINDOW']
    valid = [interval for interval in inside if interval['deltas']['run_ns'] is not None and interval['deltas']['wait_ns'] is not None]
    return {'report': str(output), 'status': report['status'], 'counter_status': report['counter_status'],
        'external_anchor_status': report['external_anchor_status'], 'instance_count': report['instance_count'],
        'observed_valid_interval_count': report['observed_run_wait_interval_count'],
        'valid_fully_inside_interval_count': len(valid),
        'fully_inside_wait_ns_sum_not_exclusive_request_cost': sum(interval['deltas']['wait_ns'] for interval in valid),
        'unknown_interval_count': sum(interval['deltas']['run_ns'] is None or interval['deltas']['wait_ns'] is None for interval in intervals),
        'outside_or_boundary_crossing_interval_count': sum(interval['execution_window_relation'] != 'FULLY_INSIDE_EXECUTION_WINDOW' for interval in intervals),
        'one_observation_thread_count': sum(not item['intervals'] for item in report['instances']),
        'issue_codes': dict(Counter(issue['code'] for issue in report['issues'])),
        'full_thread_lifecycle_claimed': False}


def paired_section(root, name, output):
    directory = root / name
    result = {'campaign': name, 'status': 'MISSING', 'issues': []}
    if not (directory / 'campaign.json').is_file():
        result['issues'].append('completed campaign.json not present')
        return result
    try:
        replay = paired_profiles.replay(directory)
        save(output / 'paired' / (name + '.json'), replay)
        expected_count = 25 if replay['benchmark'] == 'swe' else 50
        if replay['trial_count'] != expected_count:
            raise ValueError('expected {} trials, found {}'.format(expected_count, replay['trial_count']))
        expected_tasks = {'psf__requests-1142'} if replay['benchmark'] == 'swe' else {'html-js-filter', 'bun-sourcemap-leak'}
        if {row['task'] for row in replay['results']} != expected_tasks:
            raise ValueError('paired task identities differ from this pilot contract')
        result.update(status='REPLAYED', benchmark=replay['benchmark'], trial_count=replay['trial_count'],
            replay_report=str(output / 'paired' / (name + '.json')),
            measurement_health=replay['measurement_health'],
            audit_evidence_status_counts=dict(Counter(row['audit_evidence_status'] for row in replay['runs'])),
            costs=[{'task': row['task'], 'mode': row['mode'],
                'hot_seconds': compact_interval(row['hot_seconds']),
                'incremental_percent_vs_same_observer_sampler': compact_interval(row['relative_to_same_observer_sampler_percent'])}
                for row in replay['results']], kernel_over_threads=replay['paired_kernel_over_threads'],
            scope=replay['scope'], threads=[], diagnostic_health_counts=dict(Counter(row['measurement_health']['status'] for row in replay['runs'])))
        for cost in result['costs']:
            selected = [row for row in replay['runs'] if (row['task'], row['mode']) == (cost['task'], cost['mode'])]
            collector_cpu, collector_rss, sampler_cpu, sampler_rss, evidence = [], [], [], [], []
            for row in selected:
                detail = row['diagnostics']
                usage = detail.get('collector_usage') or {}
                if all(type(usage.get(key)) in (int, float) for key in ('user_cpu_seconds', 'system_cpu_seconds')):
                    collector_cpu.append(usage['user_cpu_seconds'] + usage['system_cpu_seconds'])
                if type(usage.get('max_rss_kib')) is int:
                    collector_rss.append(usage['max_rss_kib'])
                if type(detail.get('evidence_bytes_excluding_this_summary')) is int:
                    evidence.append(detail['evidence_bytes_excluding_this_summary'])
                trial_root = paired_profiles._safe(directory, row['path'])
                load = trial_root / ('gold-control/observation/load' if replay['benchmark'] == 'swe' else 'profiles/' + row['task'])
                usage = read(load / 'load-sampler-stats.json').get('self_rusage', {})
                if all(type(usage.get(key)) is int for key in ('user_usec', 'system_usec')):
                    sampler_cpu.append((usage['user_usec'] + usage['system_usec']) / 1e6)
                if type(usage.get('max_rss_kb')) is int:
                    sampler_rss.append(usage['max_rss_kb'])
            cost['sampler_cpu_seconds'] = compact_interval(paired_profiles.interval(sampler_cpu))
            cost['sampler_max_rss_kib'] = compact_interval(paired_profiles.interval(sampler_rss))
            cost['extra_collector_cpu_seconds'] = compact_interval(paired_profiles.interval(collector_cpu))
            cost['extra_collector_max_rss_kib'] = compact_interval(paired_profiles.interval(collector_rss))
            cost['diagnostic_evidence_bytes'] = compact_interval(paired_profiles.interval(evidence))
            cost['resource_counter_scope'] = 'WHOLE_COLLECTOR_LIFETIME_INCLUDES_LOAD_STARTUP_FINALIZATION_NOT_HOT_WINDOW_EXCLUSIVE'
        for index, row in enumerate(replay['runs']):
            if row['mode'] not in ('threads', 'kernel'):
                continue
            trial_root = paired_profiles._safe(directory, row['path'])
            load = trial_root / ('gold-control/observation/load' if replay['benchmark'] == 'swe' else 'profiles/' + row['task'])
            detail = summarize_threads(load, row, output / 'threads' / name / ('%03d-%s.json' % (index, row['mode'])))
            result['threads'].append({'task': row['task'], 'mode': row['mode'], 'block': row['block'], **detail})
    except ERRORS as error:
        result.update(status='INCOMPLETE', error=type(error).__name__ + ': ' + str(error))
    return result


def query_campaign(directory, intervention, provenance, analyzer, output):
    manifest = read(directory / 'campaign.json')
    if (manifest.get('status') != 'COMPLETE' or manifest.get('intervention') != intervention or
            manifest.get('repository_version') != provenance.get('image_id') or manifest.get('corpus') != provenance.get('copied_path') or
            manifest.get('jobs') != 8 or manifest.get('passes') != 8):
        raise ValueError('query campaign source/image/fixed work contract mismatch')
    declarations, trials = manifest.get('conditions'), manifest.get('trials')
    if not isinstance(declarations, list) or not isinstance(trials, list) or len(trials) != 24 or len(declarations) != 24:
        raise ValueError('query campaign requires all 24 trials, including four warmups')
    keys = ('concurrency', 'mode', 'repetition', 'warmup')
    for item in declarations + trials:
        if (not isinstance(item, dict) or type(item.get('concurrency')) is not int or type(item.get('repetition')) is not int
                or type(item.get('warmup')) is not bool):
            raise ValueError('query condition types are not explicit integer/bool declarations')
    expected = {(concurrency, mode, repeat, warmup) for concurrency in (1, 8) for mode in ('baseline', 'sampler')
                for warmup in (False, True) for repeat in (range(1) if warmup else range(5))}
    identities = [tuple(item.get(key) for key in keys) for item in trials]
    if len(set(identities)) != 24 or set(identities) != expected or set(tuple(item.get(key) for key in keys) for item in declarations) != expected:
        raise ValueError('query repetitions/conditions duplicated, missing or changed')
    seen_paths, seen_runs, summaries, signatures, issue_codes = set(), set(), [], [], Counter()
    raw_health = Counter()
    for index, item in enumerate(trials):
        trial = paired_profiles._safe(directory, item.get('path'))
        if trial == directory.resolve() or trial in seen_paths or item.get('run_id') in seen_runs:
            raise ValueError('query path or run_id duplicated')
        seen_paths.add(trial)
        seen_runs.add(item.get('run_id'))
        profile = read(trial / 'profile-run.json')
        config = profile.get('config', {})
        if (profile.get('run_id') != item.get('run_id') or any(config.get(key) != item.get(key) for key in keys)
                or config.get('corpus_sha256') != manifest.get('corpus_sha256')
                or config.get('repository_version') != provenance['image_id'] or config.get('intervention') != intervention):
            raise ValueError('raw query trial is not bound to declared campaign/source/condition')
        report = analyzer.analyze_trial(trial)
        measurement = report.get('query_measurements', {})
        if (measurement.get('status') != 'OBSERVED' or measurement.get('expected_queries') != 64 or
                measurement.get('observed_queries') != 64 or len(measurement.get('queries', [])) != 64
                or any(query.get('measurement_status') != 'OBSERVED' for query in measurement['queries'])):
            raise ValueError('strict per-query raw job/statistics replay is incomplete: ' + item['path'])
        if report.get('task_count') != 8 or any(not task.get('identity_valid') or task.get('status') != 'COMPLETE' for task in report['tasks']):
            raise ValueError('query task set/lifecycle incomplete')
        signature = sorted((task['task_id'], task['completion']['exit_code'], task['completion']['output_sha256'],
                            task['completion']['output_bytes']) for task in report['tasks'])
        if any(item[1] not in (0, 1) for item in signature):
            raise ValueError('query task failed')
        signatures.append(signature)
        raw_health[report['sampling_status']] += 1
        issue_codes.update(issue['code'] for issue in report.get('issues', []))
        target = output / ('trial-%03d.json' % index)
        save(target, report)
        summaries.append({'path': item['path'], 'run_id': item['run_id'], **{key: item[key] for key in keys},
            'query_count': 64, 'report': str(target), 'sampling_status': report['sampling_status'],
            'makespan_ns': report['execution_makespan_ns'], 'duration_seconds': measurement['duration_seconds']})
    if any(signature != signatures[0] for signature in signatures):
        raise ValueError('query output equality failed within intervention')
    result = {'status': 'RAW_PER_QUERY_TIMESTAMPS_VALIDATED', 'intervention': intervention,
        'campaign_sha256': sha(directory / 'campaign.json'), 'formal_trial_count': sum(not item['warmup'] for item in trials),
        'warmup_trial_count': sum(item['warmup'] for item in trials), 'formal_query_count': sum(row['query_count'] for row in summaries if not row['warmup']),
        'warmup_query_count': sum(row['query_count'] for row in summaries if row['warmup']),
        'output_signature': signatures[0], 'sampling_status_counts': dict(raw_health), 'raw_issue_codes': dict(issue_codes),
        'trials': summaries, 'scope': 'REAL_DOCKER_IMAGE_SOURCE_COPY_FIXED_GREP_NOT_AUTONOMOUS_BENCHMARK_SCORE'}
    save(output / 'summary.json', result)
    return result


def query_section(root, benchmark, output, analyzer):
    name = 'queries-' + benchmark + '-001'
    directory = root / name
    result = {'campaign': name, 'benchmark': benchmark, 'status': 'MISSING'}
    if not (directory / 'source-query-campaign.json').is_file():
        return result
    try:
        source = read(directory / 'source-query-campaign.json')
        provenance = read(root / 'corpus-provenance.json')[benchmark]
        if source.get('benchmark') != benchmark or source.get('source') != provenance:
            raise ValueError('query source provenance differs from independently copied corpus provenance')
        runs = source.get('runs', [])
        if (len(runs) != 2 or {row.get('intervention') for row in runs} != {'none', 'exact-reuse'}
                or any(type(row.get('returncode')) is not int or row['returncode'] != 0 for row in runs)):
            raise ValueError('both declared query interventions must have completed')
        interventions = {mode: query_campaign(directory / mode, mode, provenance, analyzer, output / 'queries' / name / mode)
                         for mode in ('none', 'exact-reuse')}
        if interventions['none']['output_signature'] != interventions['exact-reuse']['output_signature']:
            raise ValueError('output equality failed between none and exact reuse')
        contrasts = []
        for concurrency in (1, 8):
            for mode in ('baseline', 'sampler'):
                by_intervention = {name: {trial['repetition']: trial for trial in item['trials']
                    if not trial['warmup'] and trial['mode'] == mode and trial['concurrency'] == concurrency}
                    for name, item in interventions.items()}
                contrasts.append({'concurrency': concurrency, 'mode': mode,
                    'exact_reuse_vs_none_makespan_change_percent': compact_interval(paired_profiles.interval([
                        (by_intervention['exact-reuse'][repeat]['makespan_ns'] / by_intervention['none'][repeat]['makespan_ns'] - 1) * 100
                        for repeat in range(5)])),
                    'sampling_unit': 'matched repetition block, not 320 pooled queries'})
        result.update(status='VALIDATED_WITH_SEPARATE_RESOURCE_HEALTH', provenance=provenance,
            interventions={mode: {key: value for key, value in item.items() if key not in ('trials', 'output_signature')}
                           for mode, item in interventions.items()},
            paired_makespan_changes=contrasts, scope='SOURCE_MECHANISM_EXPERIMENT_NOT_TASK_SOLVE_SCORE')
    except ERRORS as error:
        result.update(status='INCOMPLETE', error=type(error).__name__ + ': ' + str(error))
    return result


def mixed_dimensions(report):
    """Separate replayed functionality from sampler quality, fail closed on unknown problems.

    The aggregate verdict and original problems are NEVER edited. A generic
    runtime_or_resource wrapper is resource-only here only when its underlying
    replay exposes exclusively recognized resource problems and every semantic
    and native trace remains verified. This is not a policy to ignore misses.
    """
    analyses = report.get('runtime_and_resources', {})
    blockers, resource_issues, resource_only_analyses = [], [], set()
    if not isinstance(analyses, dict) or not analyses or report.get('resource_replay_performed') is not True:
        blockers.append('RAW_RUNTIME_AND_RESOURCE_REPLAY_NOT_PERFORMED')
        analyses = {}
    for name, analysis in analyses.items():
        trials = analysis.get('trials', [])
        if not trials or any(row.get('semantic_complete') is not True or row.get('native_complete') is not True for row in trials):
            blockers.append(name + ':SEMANTIC_OR_NATIVE_PROOF_NOT_ESTABLISHED')
        problems = analysis.get('problems')
        if not isinstance(problems, list):
            blockers.append(name + ':MISSING_ANALYSIS_PROBLEM_LEDGER')
            continue
        known_resource_only = bool(problems)
        for problem in problems:
            known_resource = (isinstance(problem, dict) and
                ((set(problem) <= {'trial', 'kernel_history_incomplete'} and bool(problem.get('kernel_history_incomplete'))) or
                 (set(problem) <= {'trial', 'error'} and problem.get('error') in
                  ('PHASE_RESOURCE_COUNTERS_INCOMPLETE', 'THREAD_RESOURCE_COUNTERS_INCOMPLETE')) or
                 (set(problem) <= {'trial', 'semantic', 'native', 'load'} and problem.get('semantic') == 'COMPLETE'
                  and problem.get('native') == [] and isinstance(problem.get('load'), dict)
                  and problem['load'].get('status') == 'INCOMPLETE')))
            if known_resource:
                resource_issues.append({'analysis': name, 'problem': problem})
            else:
                known_resource_only = False
                blockers.append({'analysis': name, 'unclassified_or_functional_problem': problem})
        if known_resource_only and trials and all(row.get('semantic_complete') is True and row.get('native_complete') is True for row in trials):
            resource_only_analyses.add(name)
        if analysis.get('status') not in ('VALIDATED_WITH_DECLARED_SCOPE', 'INCOMPLETE_OR_INVALID'):
            blockers.append(name + ':UNKNOWN_ANALYSIS_STATUS')
        if analysis.get('status') == 'INCOMPLETE_OR_INVALID' and not problems:
            blockers.append(name + ':INCOMPLETE_WITHOUT_EXPLAINED_CAUSE')
    top_problems = report.get('problems')
    if not isinstance(top_problems, list):
        blockers.append('MISSING_TOP_LEVEL_PROBLEM_LEDGER')
        top_problems = []
    for problem in top_problems:
        explained_resource = any(problem == name + ':runtime_or_resource_replay_incomplete' for name in resource_only_analyses)
        selected_wait_gap = (isinstance(problem, str) and any(problem.startswith(name + ':') for name in analyses)
                             and problem.endswith(':selected_dispatch_thread_wait_not_measured'))
        if explained_resource or selected_wait_gap:
            resource_issues.append({'top_level_problem': problem})
        else:
            blockers.append({'top_level_problem': problem})
    if report.get('status') not in ('PASS_WITH_DECLARED_SCOPE', 'INCOMPLETE'):
        blockers.append('UNRECOGNIZED_SOURCE_AGGREGATE_STATUS')
    if report.get('status') == 'INCOMPLETE' and not top_problems:
        blockers.append('AGGREGATE_INCOMPLETE_WITHOUT_EXPLAINED_CAUSE')
    if report.get('fixed_work_and_outputs') != 'EXACT_EQUALITY':
        blockers.append('FIXED_WORK_AND_OUTPUT_EQUALITY_NOT_ESTABLISHED')
    core_verified = not blockers
    candidates = report.get('candidates', [])
    selection_verified = (core_verified and len(candidates) >= 2 and report.get('selected') in candidates and
        report.get('selection_claim') == 'BEST_MEDIAN_AMONG_PREDECLARED_CANDIDATES_NOT_GLOBAL_OPTIMUM')
    aggregates = report.get('evaluation_aggregates', {})
    fresh_evaluation_verified = (selection_verified and report.get('evaluation_trial_count') == 25 and
        all(aggregates.get(condition, {}).get(metric, {}).get('n') == 5 for condition in ('G0', 'G1', 'G2', 'G3', 'G4')
            for metric in ('a_seconds', 'makespan_seconds')))
    queued = report.get('G4_queued_competition_exercised_trials', [])
    order_verified = (fresh_evaluation_verified and len(queued) == 5 and len(set(queued)) == 5 and
                      report.get('priority_validation') == 'QUEUED_COMPETITION_OBSERVED_EVERY_G4_REPEAT')
    timing_verified = (fresh_evaluation_verified and all(report.get('paired_changes', {}).get(pair, {}).get(metric, {})
        .get('change_percent', {}).get('n') == 5 for pair in ('G1_to_G2', 'G2_to_G3', 'G3_to_G4', 'G2_to_G4')
        for metric in ('a_seconds', 'makespan_seconds', 'B_compile_units_per_second', 'B_total_seconds')))
    resource_clean = (bool(analyses) and not resource_issues and not blockers and
                      all(item.get('status') == 'VALIDATED_WITH_DECLARED_SCOPE' for item in analyses.values()))
    return {'classification_policy': 'MIXED_DIMENSION_SPLIT_V1_KNOWN_NESTED_RESOURCE_CAUSES_ONLY',
        'source_aggregate_status': report.get('status'), 'unclassified_or_functional_blockers': blockers,
        'execution_functionality': {'status': 'VERIFIED' if core_verified else 'INCONCLUSIVE'},
        'baseline_selection': {'status': 'VERIFIED_AMONG_PREDECLARED_CANDIDATES' if selection_verified else 'INCONCLUSIVE'},
        'frozen_fresh_evaluation': {'status': 'VERIFIED' if fresh_evaluation_verified else 'INCONCLUSIVE'},
        'G4_queue_order': {'status': 'VERIFIED_EACH_REPEAT' if order_verified else 'INCONCLUSIVE'},
        'paired_timing': {'status': 'RECOMPUTED_FIXED_WORK_N5' if timing_verified else 'INCONCLUSIVE', 'speedup_required': False},
        'resource_health': {'status': 'NO_REPORTED_GAPS_WITHIN_DECLARED_CONTRACT' if resource_clean else 'INCOMPLETE_OR_NOT_ESTABLISHED',
            'issues': resource_issues, 'original_statuses': {name: item.get('status') for name, item in analyses.items()},
            'limitations': 'Known probe/counter gaps remain findings; valid function/timing does not repair missing resource history.'}}


def mixed_section(root, name, tuner, output):
    result = {'campaign': name, 'status': 'MISSING'}
    directory = root / name
    if not (directory / 'experiment.json').is_file():
        return result
    try:
        benchmark = 'swe' if name.startswith('mixed-swe-') else 'terminal'
        provenance = read(root / 'corpus-provenance.json')[benchmark]
        manifest = read(directory / 'experiment.json')
        if manifest.get('external_search', {}).get('root') != provenance.get('copied_path'):
            raise ValueError('mixed search source is not bound to the benchmark corpus provenance')
        report = tuner.replay(directory, resource_replay=True)
        save(output / 'mixed' / (name + '.json'), report)
        result.update({key: report[key] for key in ('status', 'problems', 'selected', 'selection_objective', 'selection_claim',
            'evaluation_trial_count', 'evaluation_aggregates', 'paired_changes', 'priority_validation', 'fixed_work_and_outputs', 'scope')})
        result.update(replay_report=str(output / 'mixed' / (name + '.json')),
            dimensions=mixed_dimensions(report),
            tested_candidate_count=len(report['candidates']),
            G4_queued_competition_exercised_trial_count=len(report['G4_queued_competition_exercised_trials']),
            resource_status_counts=dict(Counter(item['status'] for item in report['runtime_and_resources'].values())))
    except ERRORS as error:
        result.update(status='INCOMPLETE', error=type(error).__name__ + ': ' + str(error))
    return result


def finalize(root, output):
    root, output = Path(root).resolve(strict=True), Path(output).absolute()
    if output.exists() or root == output.resolve():
        raise ValueError('summary output must be a new directory, separate from raw evidence')
    for directory in root.iterdir():
        if directory.is_dir() and directory.name.startswith(('paired-', 'queries-', 'mixed-')):
            try:
                output.resolve().relative_to(directory.resolve())
            except ValueError:
                continue
            raise ValueError('summary output must not modify a raw campaign directory')
    output.mkdir(parents=True, exist_ok=False)
    search_path = HERE.parent / 'search-profile/analyze.py'
    analyzer = module(search_path, 'finalize_search_analyzer')
    paired = [paired_section(root, name, output) for name in ('paired-swe-001', 'paired-terminal-001')]
    queries = [query_section(root, benchmark, output, analyzer) for benchmark in ('swe', 'terminal')]
    mixed_names = sorted(path.name for path in root.glob('mixed-*') if path.is_dir() and (path / 'experiment.json').is_file())
    mixed = []
    with execution_tuner() as tuner:
        for name in mixed_names:
            mixed.append(mixed_section(root, name, tuner, output))
    threads = [detail for item in paired for detail in item.get('threads', [])]
    paired_ready = len(paired) == 2 and all(item['status'] == 'REPLAYED' for item in paired)
    queries_ready = all(item['status'] == 'VALIDATED_WITH_SEPARATE_RESOURCE_HEALTH' for item in queries)
    mixed_coverage = {benchmark: [item for item in mixed if item['campaign'].startswith('mixed-' + benchmark + '-')]
                      for benchmark in ('swe', 'terminal')}
    # Keep every historical run. Primary means latest sequence with a manifest,
    # NOT "choose whichever result is green". An INCOMPLETE latest run stays so.
    primary = {benchmark: rows[-1]['campaign'] if rows else None for benchmark, rows in mixed_coverage.items()}
    primary_details = [next((item for item in mixed if item['campaign'] == name), {}) for name in primary.values()]
    selection_validated = all(item.get('dimensions', {}).get('baseline_selection', {}).get('status') == 'VERIFIED_AMONG_PREDECLARED_CANDIDATES'
        and item.get('dimensions', {}).get('frozen_fresh_evaluation', {}).get('status') == 'VERIFIED' for item in primary_details)
    priority_validated = all(item.get('dimensions', {}).get('G4_queue_order', {}).get('status') == 'VERIFIED_EACH_REPEAT'
        and item.get('dimensions', {}).get('paired_timing', {}).get('status') == 'RECOMPUTED_FIXED_WORK_N5' for item in primary_details)
    primary_resources = {benchmark: item.get('dimensions', {}).get('resource_health', {'status': 'NOT_ESTABLISHED'})
                         for benchmark, item in zip(('swe', 'terminal'), primary_details)}
    resource_limitations = any(item['status'] != 'NO_REPORTED_GAPS_WITHIN_DECLARED_CONTRACT' for item in primary_resources.values())
    summary = {'schema_version': 1, 'report_generation_status': 'GENERATED_NOT_A_GLOBAL_PASS', 'input_root': str(root),
        'GPU': 'EXCLUDED_BY_USER', 'model_api_calls_this_round': 0,
        'workload_scope': 'PINNED_OFFICIAL_REFERENCE_CONTROLS_PLUS_REAL_SOURCE_CPU_MECHANISM_EXPERIMENTS_NOT_AUTONOMOUS_AGENT_SCORES',
        'six_gaps': {
            'mixed_counter_correctness': {'status': 'IMPLEMENTED_REGRESSION_TEST_RESULTS_REPORTED_SEPARATELY',
                'unknown_policy': 'MISSING_RESET_INVALID_COUNTERS_REMAIN_UNKNOWN_NO_NEGATIVE_VALID_DELTAS'},
            'key_thread_wait': {'status': 'OBSERVED_PARTIAL_POLLING' if paired_ready and all(
                any(row['valid_fully_inside_interval_count'] and row['external_anchor_status'] == 'MATCHED_SAVED_METADATA'
                    for row in item.get('threads', [])) for item in paired) else 'INCOMPLETE',
                'valid_fully_inside_interval_count': sum(row['valid_fully_inside_interval_count'] for row in threads),
                'unknown_interval_count': sum(row['unknown_interval_count'] for row in threads),
                'one_observation_thread_count': sum(row['one_observation_thread_count'] for row in threads),
                'full_thread_lifecycle_claimed': False},
            'per_query_latency': {'status': 'RAW_PER_QUERY_REPLAY_VALIDATED' if queries_ready else 'INCOMPLETE'},
            'tuned_static_baseline': {'status': ('FROZEN_SELECTION_VERIFIED_WITH_RESOURCE_LIMITATIONS' if resource_limitations else
                'FROZEN_CANDIDATE_SELECTION_REPLAYED') if selection_validated else 'INCOMPLETE',
                'primary_campaigns': primary, 'resource_health': primary_resources},
            'phase_cpu_plus_request_priority': {'status': ('ORDER_AND_TIMING_VERIFIED_WITH_RESOURCE_LIMITATIONS' if resource_limitations else
                'ORDER_AND_TIMING_VERIFIED') if priority_validated else 'INCOMPLETE', 'resource_health': primary_resources},
            'detailed_diagnostic_overhead': {'status': 'PAIRED_N_AND_CI_RECOMPUTED' if paired_ready else 'INCOMPLETE',
                'reference': 'SAME_OBSERVER_PLUS_100MS_SAMPLER_NOT_TOTAL_OBSERVER_OVERHEAD',
                'confidence_note': 'paired randomized blocks; n=5 per task/arm; interval field mean_ci95_bootstrap is a mean CI, not a median CI'}},
        'paired': paired, 'queries': queries, 'mixed_primary': primary, 'mixed_all_history': mixed,
        'independent_wal_replay': {'status': 'SEPARATE_RECEIPT_REQUIRED', 'path': None},
        'source_sha256': {str(path.resolve().relative_to(HERE.parent)): sha(path) for path in
            (Path(__file__).resolve(), HERE / 'paired_profiles.py', HERE / 'thread_wait_report.py', search_path,
             HERE.parent / 'execution-profile/analyze.py', HERE.parent / 'execution-profile/tune_static.py')},
        'limitations': ['No aggregate safety/completeness boolean: valid timings can coexist with incomplete resource or object history.',
            'All paired arms shared kernel.sched_schedstats=1: measured thread-diagnostic increments do not include the kernel cost of enabling schedstats from zero.',
            'Original INCOMPLETE campaigns are retained; a clean repeat does not erase probe misses in earlier runs.',
            'Reference control scores are not autonomous model scores; mixed source search and synthetic compilation are not official benchmark solutions.',
            'Thread polling misses short tasks and is not exclusive per-request or complete lifecycle accounting.',
            'Source-query none/reuse treatments ran as separate campaigns: within-campaign mode/concurrency ordering was randomized, but treatment order was not interleaved. Their paired timing intervals are descriptive, not a fully randomized causal benefit estimate.',
            'Unknown counters and boundary-crossing intervals are never converted to zero or clipped into the execution window.',
            'Model API calls field describes this reference/local-CPU campaign, not prior historical paid model trials.']}
    save(output / 'summary.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    summary = finalize(args.root, args.output)
    print(json.dumps({'output': str(args.output / 'summary.json'), 'six_gaps': summary['six_gaps']}))


if __name__ == '__main__':
    main()
