#!/usr/bin/env python3
"""Final, read-only acceptance gate for the 160-case file-access experiment.

Requires 160 individual cache replay receipts and all 80 offline full-detail
analyses, rather than trusting comparison.json's descriptive top-level status.
This gate binds existing small receipts/summaries; it does not rehash huge raw
event/SQLite/gzip files or re-execute their preceding independent replay.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import stat

import access_comparison as compare
import verify_access_matrix as formal


core = formal.core
SUMMARY_ARTIFACTS = {'summary.json', 'events.sqlite', 'per-file.csv',
                     'read-samples.csv', 'source-read-samples.csv'}
RESOURCE_METRICS = ('makespan_seconds', 'user_cpu_seconds', 'system_cpu_seconds',
    'per_query_trial_median_seconds', 'page_faults', 'major_page_faults', 'refaults',
    'data_read_bytes', 'data_write_bytes', 'file_cache_last_bytes')
FILE_METRICS = ('source_unique_regular_files_read_attempted', 'source_read_calls',
    'source_read_returned_bytes', 'read_calls', 'read_duration_ns', 'read_mean_duration_ns',
    'read_max_duration_ns', 'mm_fault_attempts', 'mm_file_backed_fault_attempts',
    'mm_no_file_vma_fault_attempts', 'filemap_fault_attempts')
BACKGROUND_METRICS = ('guest_context_switches', 'guest_tasks_created', 'guest_page_faults',
    'guest_major_faults', 'guest_eth0_rx_bytes', 'guest_eth0_tx_bytes',
    'guest_average_cpu_runqueue_waiting_tasks', 'guest_observed_max_d_state_tasks',
    'target_observed_max_memory_bytes', 'target_observed_max_anon_bytes')


def write_new(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')


def document(reader, path, expected_sha256=None, limit=32 * 1024 ** 2):
    path = Path(path).resolve(strict=True)
    raw = reader.bytes(path, limit=limit)
    value = json.loads(raw)
    core.require(isinstance(value, dict), 'JSON object required: ' + str(path))
    if expected_sha256 is not None:
        core.require(core.digest(expected_sha256) and reader.sha(path) == expected_sha256,
                     'external SHA256 differs: ' + str(path))
    return value


def same_source(saved, reader, path):
    core.require(isinstance(saved, dict) and saved.get('sha256') == reader.sha(path)
        and saved.get('bytes') == len(reader.bytes(path)),
        'saved source SHA256/bytes differs: ' + str(path))


def five(metric, name):
    core.require(isinstance(metric, dict) and core.equal(metric.get('n'), 5)
        and core.equal(metric.get('unknown_n'), 0) and core.equal(metric.get('independent_n'), 5),
        'metric lacks five known independent blocks: ' + name)


def validate_report(report, matrix, matrix_sha):
    core.require(report.get('schema_version') == 1 and report.get('matrix_sha256') == matrix_sha
        and report.get('status') == 'DESCRIPTIVE_PAIRED_SEARCH_COMPARISON'
        and report.get('issues') == [] and report.get('primary_metric') ==
            'ALL_EIGHT_FIXED_WORK_TASKS_MAKESPAN_SECONDS', 'report identity/status/issue binding differs')
    trials = report.get('trials')
    core.require(isinstance(trials, list) and len(trials) == 160, 'exactly 160 report trials required')
    case_trials, seen_runs = {}, set()
    for trial, entry in zip(trials, matrix['campaigns']):
        case_id = entry['path']
        identity = trial.get('matrix', {})
        core.require(identity.get('campaign') == case_id and identity.get('block') == entry['block']
            and core.equal(identity.get('condition'), entry['condition'])
            and identity.get('stage') == entry['stage'] and case_id not in case_trials,
            'report trial order/condition differs from formal matrix')
        core.require(trial.get('boot_id') == matrix['boot_id'] and isinstance(trial.get('run_id'), str)
            and trial['run_id'] not in seen_runs, 'duplicate/mismatched report run or boot')
        seen_runs.add(trial['run_id'])
        core.require(trial.get('primary', {}).get('usable_for_comparison') is True
            and trial.get('cache_evidence', {}).get('cache_condition_eligible') is True
            and trial.get('resources', {}).get('status') == 'OBSERVED_ENCLOSING_INTERVAL',
            'timing/cache/resources incomplete for ' + case_id)
        mode = entry['condition']['file_access_mode']
        core.require(trial.get('file_analysis_status') ==
            ('COMPLETE_FOR_SELECTED_HOOKS' if mode == 'access' else 'NOT_ENABLED'),
            'file-analysis status missing/incomplete for ' + case_id)
        core.require(trial.get('collector_boundaries', {}).get('status') ==
            ('OBSERVED_SAVED_BOUNDARIES' if mode == 'access' else 'NOT_ENABLED'),
            'collector boundary cost incomplete for ' + case_id)
        case_trials[case_id] = trial
    quality = {'resource_incomplete_trials': 0, 'access_analysis_incomplete_trials': 0,
               'access_boundary_incomplete_trials': 0}
    core.require(core.equal(report.get('quality'), quality), 'report quality contains missing/incomplete diagnostics')
    conditions = report.get('conditions')
    core.require(isinstance(conditions, list) and len(conditions) == 32, 'exactly 32 report conditions required')
    cells = {}
    for row in conditions:
        key = tuple(row.get(field) for field in ('cache', 'workspace_layout', 'concurrency', 'file_access_mode'))
        core.require(key not in cells, 'duplicate report condition')
        cells[key] = row
        core.require(core.equal(row.get('blocks'), list(range(5)))
            and core.equal(row.get('timing_eligible_n'), 5) and core.equal(row.get('cache_eligible_n'), 5),
            'condition lacks five eligible intact blocks')
        wanted = [trial for trial in trials if tuple(trial['config'].get(field) for field in
            ('cache', 'workspace_layout', 'concurrency', 'file_access_mode')) == key]
        core.require(len(wanted) == 5 and set(row.get('run_ids', [])) == {trial['run_id'] for trial in wanted}
            and len(row['run_ids']) == 5, 'condition run identities differ')
        actual = compare.metrics_summary(wanted, lambda trial: trial['primary']['seconds'])
        core.require(core.equal(row.get('makespan_seconds'), actual), 'makespan aggregation differs from report trial seconds')
        for name in RESOURCE_METRICS:
            five(row.get(name), name)
        for resource in ('cpu', 'memory', 'io'):
            for kind in ('some', 'full'):
                five(compare.wall.get(row, 'psi_stall_seconds', resource, kind), 'PSI ' + resource + '/' + kind)
        for name in BACKGROUND_METRICS:
            five(row.get('background', {}).get(name), name)
        if key[-1] == 'access':
            core.require(row.get('file_analysis_status_counts') == {'COMPLETE_FOR_SELECTED_HOOKS': 5},
                         'condition hides incomplete file analyses')
            for name in FILE_METRICS:
                five(row.get('file_metrics', {}).get(name), name)
    wanted_cells = {(p['cache'], p['workspace_layout'], p['concurrency'], p['file_access_mode']) for p in matrix['schedule']}
    core.require(set(cells) == wanted_cells, 'report condition dimensions differ')
    overhead = report.get('collector_overhead')
    core.require(isinstance(overhead, list) and len(overhead) == 16, 'exactly 16 paired overhead cells required')
    pairs_seen = set()
    for row in overhead:
        key = tuple(row.get(field) for field in ('cache', 'workspace_layout', 'concurrency'))
        core.require(key not in pairs_seen and key + ('access',) in cells
            and core.equal(row.get('paired_n'), 5) and core.equal(row.get('eligible_paired_n'), 5)
            and row.get('missing_sampler_blocks') == [] and row.get('missing_access_blocks') == [],
            'overhead cell lacks five eligible same-block pairs')
        pairs_seen.add(key)
        pairs = row.get('pairs')
        core.require(isinstance(pairs, list) and [pair.get('block') for pair in pairs] == list(range(5)),
                     'overhead pair block identities differ')
        for pair in pairs:
            by_mode = {mode: next(trial for trial in trials if
                trial['matrix']['block'] == pair['block'] and
                tuple(trial['config'].get(field) for field in ('cache', 'workspace_layout', 'concurrency')) == key
                and trial['config']['file_access_mode'] == mode) for mode in ('sampler', 'access')}
            left, right = (by_mode[mode]['primary']['seconds'] for mode in ('sampler', 'access'))
            core.require(pair.get('eligible') is True and left > 0
                and pair.get('sampler_run_id') == by_mode['sampler']['run_id']
                and pair.get('access_run_id') == by_mode['access']['run_id']
                and pair.get('sampler_seconds') == left and pair.get('access_seconds') == right
                and pair.get('added_seconds') == right - left
                and pair.get('added_percent') == (right / left - 1) * 100,
                'paired overhead values or source run binding differs')
        for field in ('added_seconds', 'added_percent'):
            core.require(core.equal(row.get(field), compare.metrics_summary(pairs, lambda pair, f=field: pair[f])),
                         'paired overhead aggregate differs')
    return case_trials


def anchored_source(reader, path, replay_sources):
    same_source(replay_sources.get(str(Path(path).resolve(strict=True))), reader, path)


def raw_context(reader, root, entry, trial, replay_sources):
    case = core.child(root, entry['path'])
    capture = document(reader, case / 'capture.json')
    profile_path = core.child(case, capture['profile_path'])
    profile = document(reader, profile_path)
    anchored_source(reader, profile_path, replay_sources)
    anchored_source(reader, case / 'capture.json', replay_sources)
    core.require(profile.get('status') == 'COMPLETE' and profile.get('run_id') == trial['run_id']
        and profile.get('boot_id') == trial['boot_id'] and core.equal(profile.get('config'), trial.get('config'))
        and all(core.equal(profile['config'].get(key), value) for key, value in entry['condition'].items())
        and profile.get('makespan_ns') == profile['end_ns'] - profile['release_ns']
        and profile['makespan_ns'] / 1e9 == trial['primary']['seconds']
        and core.equal(trial.get('execution_window'), [profile['release_ns'], profile['end_ns']]),
        'report/raw profile identity, config or wall interval differs')
    same_source(trial.get('sources', {}).get('profile-run.json'), reader, profile_path)
    same_source(trial.get('capture_source'), reader, case / 'capture.json')
    core.require(capture.get('profile_run_sha256') == reader.sha(profile_path)
        and capture.get('profile_run_id') == profile['run_id'], 'capture/raw profile binding differs')
    core.require(core.equal(trial.get('collector_boundaries'), compare.collector_boundaries(capture, trial)),
                 'collector boundary cost differs from saved capture timestamps')
    return {'case': case, 'profile_path': profile_path, 'profile': profile, 'capture': capture}


def validate_cache(reader, index, index_path, matrix, matrix_path, contexts):
    same_source(index.get('matrix'), reader, matrix_path)
    core.require(index.get('schema_version') == 1 and index.get('status') == 'COMPLETE_FOR_SELECTED_CASES'
        and index.get('failures') == {}
        and isinstance(index.get('results'), dict) and set(index['results']) == set(contexts),
        'cache index must contain exactly all 160 cases without failure')
    pins, readonly = Counter(), Counter()
    for case_id, context in contexts.items():
        reference = index['results'][case_id]
        path = core.child(index_path.parent, reference['path'])
        proof = document(reader, path, reference.get('sha256'))
        same_source(reference, reader, path)
        profile, case = context['profile'], context['case']
        core.require(proof.get('status') == 'PASS' and proof.get('cache_condition_replay') == 'PASS'
            and proof.get('claim_scope') == 'SAVED_CACHE_RECORD_REPLAY_ONLY_NOT_LIVE_CACHE_TRUTH'
            and proof.get('run_id') == profile['run_id'] and proof.get('boot_id') == matrix['boot_id']
            and proof.get('cache') == profile['config']['cache']
            and proof.get('workspace_layout') == profile['config']['workspace_layout']
            and proof.get('release_ns') == profile['release_ns'] and proof.get('atomic_snapshot') is False,
            'cache replay PASS/identity binding differs for ' + case_id)
        same_source(proof.get('inputs', {}).get('profile'), reader, context['profile_path'])
        compact_path = context['profile_path'].parent / 'cache-residency.json'
        compact = document(reader, compact_path)
        same_source(proof.get('inputs', {}).get('summary'), reader, compact_path)
        details = proof.get('inputs', {}).get('file_details', {})
        gzip_path = compact_path.parent / 'cache-residency-files.json.gz'
        core.require(details.get('sha256') == compact.get('file_details', {}).get('sha256')
            and core.digest(details.get('sha256')) and details.get('bytes') == gzip_path.stat().st_size
            and proof.get('inputs', {}).get('inventory', {}).get('sha256') == matrix['source_inventory_sha256'],
            'cache proof gzip/inventory digest declaration differs')
        core.require(proof.get('pin_binding') in ('UNKNOWN', 'MATCHES_ORIGINAL_PIN_RECORDS'),
                     'cache pin-binding quality absent/invalid')
        pins[proof['pin_binding']] += 1
        readonly[proof.get('readonly_quality', 'UNKNOWN')] += 1
    return {'receipts': len(contexts), 'cache_condition_replay': 'PASS',
        'pin_binding_counts': dict(pins), 'readonly_quality_counts': dict(readonly),
        'scope': 'EXISTING_CACHE_REPLAY_RECEIPTS_AND_BOUND_SMALL_INPUTS; GZIP_BYTES_NOT_REPLAYED_AGAIN'}


def validate_analyses(reader, receipt, matrix_path, matrix, contexts, case_trials, replay_sources):
    value = receipt['value']
    wanted = {entry['path'] for entry in matrix['campaigns'] if entry['condition']['file_access_mode'] == 'access'}
    core.require(value.get('status') == 'COMPLETE_FOR_SELECTED_CASES'
        and value.get('selected_cases') == value.get('available_full_detail_cases') == 80
        and value.get('selected_prefix_limit') is None and value.get('failures') == {}
        and set(value['results']) == wanted, 'final batch must include every one of the 80 full-detail cases')
    plan = document(reader, receipt['root'] / 'plan.json')
    archived = value['schema_version'] == 2
    if archived:
        core.require(plan.get('schema_version') == 2
            and core.equal(plan.get('artifact_storage'), value.get('artifact_storage')),
            'archive plan and final receipt storage configuration differ')
    same_source(plan.get('matrix'), reader, matrix_path)
    core.require(plan.get('available_full_detail_cases') == 80 and plan.get('selected_prefix_limit') is None
        and isinstance(plan.get('cases'), list) and {row.get('case_id') for row in plan['cases']} == wanted
        and len(plan['cases']) == 80 and set(plan.get('omitted_sampler_cases', [])) == set(contexts) - wanted
        and plan.get('full_campaign_last_end_ns') == max(context['profile']['end_ns'] for context in contexts.values())
        and core.digest(plan.get('analyzer_sha256')), 'batch plan full-selection/matrix/source scope differs')
    plans = {row['case_id']: row for row in plan['cases']}
    for case_id in sorted(wanted):
        context, trial = contexts[case_id], case_trials[case_id]
        summary_path, row = compare.receipt_summary_path(receipt, case_id)
        summary = document(reader, summary_path, row['artifacts']['summary.json']['sha256'])
        same_source(row['artifacts']['summary.json'], reader, summary_path)
        core.require(row.get('analysis_status') == summary.get('status') == 'COMPLETE_FOR_SELECTED_HOOKS'
            and row.get('issues') == summary.get('issues') == {}
            and summary.get('run_id') == trial['run_id'] and summary.get('boot_id') == matrix['boot_id']
            and summary.get('collector_run_id') == context['capture'].get('collector_run_id')
            and summary.get('analyzer', {}).get('sha256') == plan['analyzer_sha256']
            and isinstance(summary.get('metrics'), dict)
            and core.equal(trial.get('file_metrics'), compare.flatten_metrics(summary['metrics'])),
            'batch/report/summary completeness, metric or identity differs for ' + case_id)
        core.require(core.equal(trial.get('file_analysis', {}).get('summary'), summary)
            and trial['file_analysis'].get('sha256') == reader.sha(summary_path),
            'report does not contain the exact selected batch summary')
        paths = {'profile_run': context['profile_path'], 'capture': context['case'] / 'capture.json',
                 'collector_meta': context['case'] / 'file-access/meta.json',
                 'collector_final': context['case'] / 'file-access/final.json'}
        for name, path in paths.items():
            document(reader, path)
            anchored_source(reader, path, replay_sources)
            for source in (row.get('sources', {}), summary.get('sources', {}), plans[case_id].get('sources', {})):
                same_source(source.get(name), reader, path)
        meta = document(reader, paths['collector_meta'])
        final = document(reader, paths['collector_final'])
        capture = context['capture']
        core.require(meta.get('binary_sha256') == matrix['binaries']['file_access_sha256']
            and meta.get('bpf_sha256') == matrix['binaries']['file_access_object_sha256']
            and meta.get('backend') == matrix['file_access_backend']
            and meta.get('ring_bytes') == matrix['collector_budget']['ring_bytes']
            and meta.get('max_bytes') == matrix['collector_budget']['max_bytes']
            and core.equal(capture.get('capture_budget'), matrix['collector_budget'])
            and capture.get('final_sha256') == reader.sha(paths['collector_final']),
            'actual collector binary/backend/budget/final binding differs from formal matrix')
        formal.ACCESS.bind_collector(meta, final, context['profile'],
            {'sha256': reader.sha(context['profile_path'])}, context['capture'])
        core.require(formal.metadata_health(meta, final)['status'] == 'DECLARED_COMPLETE_METADATA_CONSISTENT',
                     'collector metadata incomplete despite batch green status')
        raw = summary.get('raw_events', {})
        artifact = context['case'] / 'file-access/events.bin'
        core.require(raw.get('issues') == {} and raw.get('sha256') == row.get('raw', {}).get('sha256')
            == plans[case_id].get('raw', {}).get('sha256') == final.get('events_sha256')
            and core.digest(raw.get('sha256')) and raw.get('bytes') == row.get('raw', {}).get('bytes')
            == plans[case_id].get('raw', {}).get('bytes') == final.get('bytes') == artifact.stat().st_size
            and raw.get('records') == final.get('persisted_records')
            and raw['bytes'] == raw['records'] * 192, 'raw replay byte/count/digest declaration differs')
        inventory_sha = plan.get('inventory_database', {}).get('sha256')
        core.require(core.digest(inventory_sha)
            and summary.get('sources', {}).get('inventory_database', {}).get('sha256') == inventory_sha,
            'summary inventory index differs from full batch plan')
        core.require(set(row.get('artifacts', {})) == SUMMARY_ARTIFACTS, 'batch derived artifact set incomplete')
        if archived:
            core.require(row.get('artifact_storage_schema') == 2
                and core.equal(row.get('artifact_storage'), value['artifact_storage']),
                'archived case storage configuration differs')
        for name, saved in row['artifacts'].items():
            if archived:
                compare.ARTIFACTS.artifact_path(saved, summary_path.parent, name)
                if name in compare.ARTIFACTS.ARCHIVED_NAMES:
                    proof, storage = saved.get('verification', {}), saved.get('storage', {})
                    core.require(storage.get('codec') == 'gzip'
                        and proof.get('status') == 'VERIFIED_DECOMPRESSED_BYTES'
                        and proof.get('bytes') == saved['bytes'] and proof.get('sha256') == saved['sha256']
                        and proof.get('artifact_module_sha256') == value['artifact_storage']['artifact_module_sha256']
                        and core.equal(proof.get('storage'), {key: storage[key] for key in ('path', 'bytes', 'sha256')}),
                        'archive logical/compressed independent verification receipt differs: ' + name)
                else:
                    core.require('storage' not in saved, 'small artifacts must remain plain')
                continue
            path = summary_path.parent / name
            info = path.stat()
            core.require(stat.S_ISREG(info.st_mode) and info.st_size == saved.get('bytes')
                and core.digest(saved.get('sha256')) and Path(saved['path']).resolve(strict=True) == path,
                'batch derived artifact path/length/digest declaration differs: ' + name)
    return {'selected_cases': 80, 'analysis_status': 'COMPLETE_FOR_SELECTED_HOOKS',
        'scope': 'ACTUAL_SUMMARY_BYTE_HASHES_SOURCE_BINDINGS_AND_SAVED_RAW_REPLAY_RESULTS; RAW_AND_SQLITE_NOT_REHASHED_AGAIN'}


def verify(matrix_path, report_path, batch_path, cache_index_path, expected=None,
           selection_verification_path=None):
    expected, reader = expected or {}, core.Evidence()
    result = {'schema_version': 1, 'verified': False, 'status': 'REJECTED', 'issues': [], 'dimensions': {},
        'scope': 'FINAL_EXPERIMENT_RESULT_ACCEPTANCE_WITHIN_DECLARED_HOOKS_AND_SAVED_REPLAY_EVIDENCE',
        'not_reperformed': ['Raw events.bin record replay and byte hash', 'SQLite/CSV and inventory-index byte rehash',
            'Cache gzip decompression/replay', 'Sampler time-series resource recalculation',
            'Physical cache truth, kernel sensor attestation, malicious evidence authentication'],
        'trust_boundary': 'Cooperative local experiment receipts; external SHA pins bind bytes, not sensor truth.'}
    try:
        matrix_path = Path(matrix_path).resolve(strict=True)
        report_path, batch_path, cache_index_path = [Path(p).resolve(strict=True) for p in
            (report_path, batch_path, cache_index_path)]
        matrix = document(reader, matrix_path, expected.get('matrix'))
        formal.validate_manifest(matrix)
        core.require(selection_verification_path is not None,
                     'explicit pause-selection/strict fixed-work verification receipt required')
        selection = document(reader, selection_verification_path, expected.get('selection_verification'))
        paused = selection.get('status') == 'VERIFIED_PAUSE_SELECTION_WITH_DECLARED_SCOPE'
        core.require(paused or not any(key in matrix for key in ('composition', 'continuation')),
                     'composed or resumed matrix still requires its explicit pause-selection verification')
        strict = selection.get('fixed_work_verification', {}) if paused else selection
        core.require(selection.get('verified') is True
            and selection.get('matrix_sha256') == reader.sha(matrix_path)
            and strict.get('verified') is True and strict.get('status') == 'VERIFIED_WITH_DECLARED_SCOPE'
            and strict.get('matrix_sha256') == reader.sha(matrix_path)
            and strict.get('total_trials') == strict.get('unique_runs') == 160
            and strict.get('actual_stdout_files_hashed') == strict.get('logical_queries_verified') == 1280,
            'selection/strict-160 fixed-work verification missing, incomplete or bound to another matrix')
        replay_sources = strict.get('read_artifacts')
        core.require(isinstance(replay_sources, dict) and bool(replay_sources),
                     'strict replay source byte receipts missing')
        result['dimensions']['fixed_work_replay'] = {'trials': 160, 'stdout_byte_hashes': 1280,
            'pause_selection': ('VERIFIED_EXISTING_RECEIPT_BOUND_TO_EXACT_MATRIX' if paused else
                                'NOT_APPLICABLE; STRICT_COMPLETE_MATRIX_REPLAY_RECEIPT_BOUND')}
        report = document(reader, report_path, expected.get('report'), limit=128 * 1024 ** 2)
        trials = validate_report(report, matrix, reader.sha(matrix_path))
        contexts = {entry['path']: raw_context(reader, matrix_path.parent, entry, trials[entry['path']], replay_sources)
                    for entry in matrix['campaigns']}
        result['dimensions']['comparison'] = {'trials': 160, 'conditions': 32,
            'independent_blocks_per_condition': 5, 'paired_overhead_cells': 16, 'pairs_per_cell': 5}
        document(reader, batch_path, expected.get('batch'))
        receipt = compare.load_analysis_receipt(batch_path, reader.sha(batch_path))
        core.require(core.equal(report.get('file_analysis_receipt'), receipt['source'])
            and all(core.equal(trial.get('file_analysis_receipt'), receipt['source']) for trial in trials.values()),
            'report does not bind the explicitly supplied final batch attempt receipt')
        result['dimensions']['file_analyses'] = validate_analyses(reader, receipt, matrix_path, matrix,
                                                               contexts, trials, replay_sources)
        index = document(reader, cache_index_path, expected.get('cache_index'))
        result['dimensions']['cache_replay'] = validate_cache(reader, index, cache_index_path, matrix, matrix_path, contexts)
        result.update(verified=True, status='ACCEPTED_WITHIN_DECLARED_SCOPE')
    except (ValueError, OSError, TypeError, KeyError, IndexError, AttributeError, OverflowError, StopIteration) as error:
        result['issues'].append({'code': 'FINAL_ACCESS_RESULT_REJECTED', 'detail': str(error)})
    result['read_artifacts'] = reader.receipts
    result['verifier_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result['dependencies'] = {name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
        for name, module in (('comparison', compare), ('formal_matrix', formal),
                             ('collector_contract', formal.ACCESS), ('artifact_storage', compare.ARTIFACTS))}
    return result


def index_cache(matrix_path, receipts_directory, output):
    """Index completed individual proof receipts; do not run/decode proofs here."""
    reader = core.Evidence()
    matrix_path, receipts_directory = Path(matrix_path).resolve(strict=True), Path(receipts_directory).resolve(strict=True)
    matrix = document(reader, matrix_path)
    formal.validate_manifest(matrix)
    output = Path(output).absolute()
    core.require(output.parent.resolve(strict=True) == output.parent and not output.exists(), 'fresh cache-index path required')
    # Receipts are direct descendants so references remain safely relocatable.
    receipts_directory.relative_to(output.parent)
    rows, failures = {}, {}
    for entry in matrix['campaigns']:
        case_id = entry['path']
        path = receipts_directory / (case_id + '.json')
        try:
            value = document(reader, path)
            rows[case_id] = {'path': str(path.relative_to(output.parent)),
                'sha256': reader.sha(path), 'bytes': len(reader.bytes(path))}
            if value.get('status') != 'PASS' or value.get('cache_condition_replay') != 'PASS':
                failures[case_id] = 'CACHE_PROOF_DID_NOT_PASS'
        except (ValueError, OSError, TypeError, KeyError) as error:
            failures[case_id] = type(error).__name__ + ':' + str(error)
    receipt = {'schema_version': 1,
        'status': 'COMPLETE_FOR_SELECTED_CASES' if not failures and len(rows) == 160 else 'INCOMPLETE',
        'matrix': {'path': str(matrix_path), 'sha256': reader.sha(matrix_path), 'bytes': len(reader.bytes(matrix_path))},
        'results': rows, 'failures': failures,
        'scope': 'INDEX_OF_160_SEPARATELY_EXECUTED_SAVED_CACHE_REPLAY_RECEIPTS; NOT_LIVE_CACHE_TRUTH'}
    write_new(output, receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    check = sub.add_parser('verify')
    for name in ('matrix', 'report', 'batch-receipt', 'cache-index'):
        check.add_argument('--' + name, required=True, type=Path)
        check.add_argument('--expected-' + name + '-sha256')
    check.add_argument('--selection-verification', required=True, type=Path)
    check.add_argument('--expected-selection-verification-sha256')
    check.add_argument('--output', required=True, type=Path)
    index = sub.add_parser('index-cache')
    index.add_argument('--matrix', required=True, type=Path)
    index.add_argument('--receipts-dir', required=True, type=Path,
                       help='160 CASE_ID.json receipts, each from a separate serial verify_cache_proof process')
    index.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'index-cache':
        receipt = index_cache(args.matrix, args.receipts_dir, args.output)
        print(json.dumps({'status': receipt['status'], 'failures': len(receipt['failures']), 'output': str(args.output)}))
        return 0 if receipt['status'] == 'COMPLETE_FOR_SELECTED_CASES' else 1
    expected = {'matrix': args.expected_matrix_sha256, 'report': args.expected_report_sha256,
                'batch': args.expected_batch_receipt_sha256, 'cache_index': args.expected_cache_index_sha256,
                'selection_verification': args.expected_selection_verification_sha256}
    result = verify(args.matrix, args.report, args.batch_receipt, args.cache_index, expected,
                    args.selection_verification)
    output = args.output.absolute()
    for evidence in (args.matrix.parent, args.report.parent, args.batch_receipt.parent, args.cache_index.parent):
        core.require(evidence.resolve() not in output.resolve().parents,
                     'final acceptance receipt must be outside input evidence directories')
    output.parent.mkdir(parents=True, exist_ok=True)
    write_new(output, result)
    print(json.dumps({'verified': result['verified'], 'status': result['status'], 'issues': result['issues']}))
    return 0 if result['verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
