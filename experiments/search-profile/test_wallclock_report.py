#!/usr/bin/env python3
"""Raw-source, fixed-work wall-clock tests; no privilege or live sampling."""
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('test_search_wallclock', Path(__file__).with_name('wallclock_report.py'))
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class WallclockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cg = {'path': '/sys/fs/cgroup/search', 'inode': 10, 'device': 28}
        self.identity = {'schema_version': 1, 'run_id': 'run', 'boot_id': 'boot', 'task_id': 'task-0',
            'agent_id': 'agent-0', 'tool_call_id': 'call-0', 'attempt': 1, 'epoch': 1,
            'request_id': None, 'parent_task_id': None, 'dependencies': [], 'phase': 'search', 'priority': 0,
            'process': {'pid': 10, 'start_ticks': 50}, 'cgroup': self.cg}
        self.events = [{**self.identity, 'seq': 0, 'event': 'START', 'monotonic_ns': 1200000000},
            {**self.identity, 'seq': 1, 'event': 'COMPLETE', 'monotonic_ns': 2800000000,
             'wall_ns': 1600000000, 'exit_code': 0, 'output_sha256': 'a' * 64, 'output_bytes': 12,
             'user_usec': 10000, 'system_usec': 2000, 'max_rss_kb': 100}]
        query_identity = {key: self.identity[key] for key in ('run_id', 'task_id', 'agent_id', 'tool_call_id', 'attempt', 'epoch', 'cgroup')}
        self.job = {'query': 'needle', 'query_index': 0, 'passes': 2, 'query_identity': query_identity}
        self.query_stats = {'schema_version': 2, 'logical_queries': 2, 'physical_grep_executions': 2,
            'cache_hits': 0, 'intervention': 'none', 'query_timing_contract': 'WORKER_MONOTONIC_PER_LOGICAL_QUERY_V1',
            'query_spans': []}
        for ordinal, (begin, end) in enumerate(((1300000000, 1600000000), (1700000000, 2200000000))):
            self.query_stats['query_spans'].append({**query_identity, 'schema_version': 1,
                'boot_id': 'boot', 'process': self.identity['process'], 'query_ordinal': ordinal,
                'query_id': 'call-0:query-{:06d}'.format(ordinal), 'query_index': 0,
                'query_sha256': hashlib.sha256(b'needle').hexdigest(), 'mode': 'none',
                'execution_kind': 'SCAN', 'returncode': 0, 'status': 'COMPLETE', 'lock_wait_ns': 0,
                'begin_ns': begin, 'end_ns': end, 'duration_ns': end - begin,
                'timing_scope': 'WORKER_QUERY_CALL_INCLUDING_LOCK_CACHE_OUTPUT_AND_SUBPROCESS',
                'identity_scope': 'CALLING_WORKER; GREP_DESCENDANT_NOT_INDIVIDUALLY_RESOLVED'})
        self.run = {'schema_version': 1, 'run_id': 'run', 'boot_id': 'boot', 'status': 'COMPLETE',
            'release_ns': 1200000000, 'end_ns': 2800000000, 'makespan_ns': 1600000000, 'root_cgroup': self.cg,
            'config': {'jobs': 1, 'passes': 2, 'mode': 'sampler', 'concurrency': 1, 'repetition': 0,
                       'warmup': False, 'cache': 'warm', 'workspace_layout': 'shared', 'intervention': 'none',
                       'query_measurement_version': 1, 'cgroup_layout': 'shared-leaf', 'cpus': [0, 1],
                       'corpus_sha256': 'c' * 64, 'queries_sha256': 'd' * 64,
                       'cpu_time_scope': 'WAIT4_LIFETIME_MINUS_WORKER_PREFLIGHT_RUSAGE'},
            'tasks': [dict(self.identity)], 'results': [{
                'task_id': 'task-0', 'query_index': 0, 'exit_code': 0, 'wall_ns': 1600000000,
                'queue_ns': 0, 'completion_latency_ns': 1600000000, 'user_usec': 10000, 'system_usec': 2000,
                'output_sha256': 'a' * 64, 'output_bytes': 12, 'query_statistics': self.query_stats}]}
        self.meta = {'boot_id': 'boot', 'label': 'run', 'cgroups': [self.cg]}
        self.stats = {'samples': 5, 'read_errors': 0, 'missed_ticks': 0}
        self.samples = []
        for seq, begin in enumerate((1000000000, 1100000000, 2000000000, 2900000000, 3000000000)):
            self.samples.append({'seq': seq, 'monotonic_ns': begin, 'collection_end_ns': begin + 10000000,
                'meminfo_kb': {'Cached': 1024 + seq, 'Buffers': 10, 'SReclaimable': 100, 'MemAvailable': 9000},
                'cgroups': [{'present': True,
                    'cpu_stat': {field: seq * 100 for field in REPORT.COUNTERS['cpu_stat']},
                    'memory_stat': {**{field: seq * 5 for field in REPORT.COUNTERS['memory_stat']},
                                    **{field: seq * 4096 for field in REPORT.GAUGES}},
                    'memory_events': {field: 0 for field in REPORT.COUNTERS['memory_events']},
                    'psi': {kind: {'some_total_us': seq * 10, 'full_total_us': seq * 4} for kind in ('cpu', 'memory', 'io')},
                    'io_stat_by_device': {'8:0': {'rbytes': seq * 1000, 'wbytes': 0, 'rios': seq, 'wios': 0}}}]})

    def tearDown(self):
        self.temp.cleanup()

    def write(self, directory=None):
        root = directory or self.root
        for name, value in (('profile-run.json', self.run), ('task-0-job.json', self.job),
            ('task-0-statistics.json', self.query_stats), ('load/load-meta.json', self.meta),
            ('load/load-sampler-stats.json', self.stats)):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))
        for name, rows in (('task-events.jsonl', self.events), ('load/load-samples.jsonl', self.samples)):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows))

    def report(self):
        self.write()
        return REPORT.summarize_trial(self.root)

    def cache_fixture(self, mode='warm'):
        self.run['config'].update(cache=mode, workspace_layout='shared', jobs=1)
        self.job['corpus'] = '/fixture/corpus'
        self.run['tasks'] = [copy.deepcopy(self.identity)]
        self.run['tasks'][0]['preparation'] = {'boot_id': 'boot', 'process': self.identity['process'],
                                             'monotonic_ns': 1000000000}
        resident = mode == 'warm'
        row = {'schema_version': 1, 'kind': 'MINCORE_FILE_DATA_RESIDENCY', 'root': '/fixture/corpus',
            'inventory_sha256': self.run['config']['corpus_sha256'], 'pin_sha256': 'f' * 64,
            'status': 'OBSERVED_NON_ATOMIC', 'errors': [],
            'mincore_authority': 'FILE_OWNER_FSUID_MATCH_REQUIRED_TO_EXCLUDE_LINUX_ALL_ONES_PERMISSION_MASKING',
            'filesystem_uid': 0, 'declared_file_count': 2, 'observed_file_count': 2, 'unknown_file_count': 0,
            'page_size': 4096, 'total_pages': 3, 'total_bytes': 8193,
            'observed_total_pages': 3, 'observed_total_bytes': 8193,
            'observed_resident_pages': 3 if resident else 0, 'observed_resident_bytes': 8193 if resident else 0,
            'resident_pages': 3 if resident else 0, 'resident_bytes': 8193 if resident else 0,
            'resident_fraction': 1 if resident else 0,
            'data_page_state': 'ALL_RESIDENT_AT_EACH_FILE_PROBE' if resident else 'ALL_NONRESIDENT_AT_EACH_FILE_PROBE',
            'start_monotonic_ns': 1050000000, 'end_monotonic_ns': 1100000000, 'duration_ns': 50000000}
        # Deliberately opaque: only header+artifact SHA binding is requested,
        # not independent reconstruction of the gzip's per-file JSON contents.
        raw = gzip.compress(b'{"opaque_per_file_artifact": true}', mtime=0)
        (self.root / 'cache-files.json.gz').write_bytes(raw)
        proof = {'schema_version': 1, 'kind': 'MINCORE_MULTIPLE_ROOT_RESIDENCY',
            'status': 'OBSERVED_NON_ATOMIC', 'roots': [row], 'independent_roots_required': False,
            'shared_dev_inode_identities': [],
            'aggregation': 'ROOTS_REPORTED_SEPARATELY_NO_PHYSICAL_CACHE_BYTES_SUMMED',
            'file_details': {'path': 'cache-files.json.gz', 'sha256': hashlib.sha256(raw).hexdigest()}}
        self.run['cache_probe_end_to_release_ns'] = self.run['release_ns'] - row['end_monotonic_ns']
        self.save_cache(proof)
        return proof

    def save_cache(self, proof, refresh_digest=True):
        raw = json.dumps(proof).encode()
        (self.root / 'cache-residency.json').write_bytes(raw)
        if refresh_digest:
            self.run['cache_residency'] = {'path': 'cache-residency.json',
                'sha256': hashlib.sha256(raw).hexdigest(),
                'scope': 'DATA_PAGE_RESIDENCY; PROBING_TRAVERSES_METADATA; NOT_DENTRY_INODE_COLD_PROOF'}
        self.write()

    def test_actual_nearest_brackets_and_primary_total_wall_clock(self):
        result = self.report()
        self.assertEqual(result['primary']['seconds'], 1.6)
        self.assertTrue(result['primary']['usable_for_comparison'], result['primary']['issues'])
        self.assertEqual(result['task_cpu']['user_seconds'], .01)
        self.assertEqual(result['per_query']['status'], 'OBSERVED', result['per_query']['issues'])
        self.assertEqual(result['per_query']['duration_seconds'], {'n': 2, 'median': .4, 'observed_p95': .5})
        resources = result['resources']
        self.assertEqual(resources['status'], 'OBSERVED_ENCLOSING_INTERVAL', resources['issues'])
        self.assertEqual(resources['boundary']['first_collection'][0], 1100000000)
        self.assertEqual(resources['boundary']['last_collection'][0], 2900000000)
        self.assertEqual(resources['boundary']['before_uncertainty_ns'], 100000000)
        self.assertEqual(resources['boundary']['after_uncertainty_ns'], 110000000)
        self.assertEqual(resources['cpu_usec']['usage_usec'], 200)
        self.assertEqual(resources['io_by_device']['8:0']['rbytes'], 2000)
        self.assertEqual(resources['memory_counters']['pgscan'], 10)
        self.assertEqual(resources['file_cache_gauges']['file']['last_bytes'], 12288)
        self.assertNotIn('total_wait', resources)

    def test_missing_io_previous_value_is_unknown_and_devices_never_summed(self):
        self.samples[3]['cgroups'][0]['io_stat_by_device']['253:0'] = {'rbytes': 8000, 'wbytes': 0, 'rios': 1, 'wios': 0}
        result = self.report()
        self.assertIsNone(result['resources']['io_by_device']['253:0']['rbytes'])
        self.assertEqual(result['resources']['io_by_device']['8:0']['rbytes'], 2000)
        self.assertNotIn('total_rbytes', result['resources'])
        self.assertTrue(result['primary']['usable_for_comparison'])

    def test_intermediate_counter_regression_is_not_hidden_by_endpoints(self):
        self.samples[2]['cgroups'][0]['cpu_stat']['usage_usec'] = 99999
        result = self.report()
        self.assertIsNone(result['resources']['cpu_usec']['usage_usec'])
        self.assertEqual(result['resources']['status'], 'INCOMPLETE')

    def test_missing_psi_is_unknown_not_zero(self):
        del self.samples[1]['cgroups'][0]['psi']['memory']
        result = self.report()
        self.assertIsNone(result['resources']['psi_stall_us']['memory']['some'])
        self.assertEqual(result['resources']['psi_stall_us']['cpu']['some'], 20)

    def test_no_bracket_does_not_invent_resource_breakdown(self):
        self.samples = self.samples[2:]
        for seq, row in enumerate(self.samples): row['seq'] = seq
        self.stats['samples'] = len(self.samples)
        result = self.report()
        self.assertIsNone(result['resources']['boundary'])
        self.assertEqual(result['resources']['status'], 'INCOMPLETE')
        self.assertEqual(result['primary']['seconds'], 1.6)

    def test_wrong_root_identity_or_boot_prevents_resource_attribution(self):
        for key in ('root', 'boot'):
            with self.subTest(key=key):
                if key == 'root': self.run['root_cgroup'] = {**self.cg, 'inode': 99}
                else: self.run['root_cgroup'] = self.cg; self.meta['boot_id'] = 'other'
                result = self.report()
                self.assertIsNone(result['resources']['boundary'])

    def test_baseline_is_timing_only_and_does_not_invent_zero_sampling(self):
        self.run['config']['mode'] = 'baseline'
        result = self.report()
        self.assertEqual(result['resources']['status'], 'NOT_COLLECTED')
        self.assertEqual(result['resources']['cpu_usec'], {})

    def test_primary_timing_reconstructs_all_task_completion(self):
        self.run['results'][0]['completion_latency_ns'] += 1
        result = self.report()
        self.assertFalse(result['primary']['usable_for_comparison'])
        self.assertIn('MAKESPAN_DOES_NOT_RECONSTRUCT_FROM_TASK_COMPLETION', {row['code'] for row in result['primary']['issues']})

    def test_raw_task_assignment_or_completion_contradiction_blocks_comparison(self):
        self.run['results'][0]['task_id'] = 'foreign-task'
        self.assertFalse(self.report()['primary']['usable_for_comparison'])
        self.run['results'][0]['task_id'] = 'task-0'
        self.events[1]['output_sha256'] = 'b' * 64
        self.assertFalse(self.report()['primary']['usable_for_comparison'])

    def test_legacy_query_latency_is_unknown_not_task_time_divided_by_passes(self):
        del self.run['config']['query_measurement_version']
        result = self.report()
        self.assertEqual(result['per_query']['status'], 'NOT_COLLECTED_LEGACY')
        self.assertEqual(result['per_query']['duration_seconds']['n'], 0)

    def test_raw_query_tampering_is_not_overridden_by_profile_copy(self):
        self.write()
        self.query_stats['query_spans'][0]['duration_ns'] = -1
        (self.root / 'task-0-statistics.json').write_text(json.dumps(self.query_stats))
        result = REPORT.summarize_trial(self.root)
        self.assertEqual(result['per_query']['status'], 'INCOMPLETE')
        self.assertTrue(result['primary']['usable_for_comparison'])

    def test_cache_binding_validates_summary_and_artifact_without_claiming_full_reconstruction(self):
        for mode in ('warm', 'guest-cold'):
            with self.subTest(mode=mode):
                self.cache_fixture(mode)
                with patch.object(gzip, 'decompress', side_effect=AssertionError('full gzip reconstruction forbidden')):
                    result = REPORT.summarize_trial(self.root)
                cache = result['cache_evidence']
                self.assertEqual(cache['status'], 'SUMMARY_AND_ARTIFACT_BINDING_VERIFIED', cache['issues'])
                self.assertTrue(cache['cache_condition_eligible'])
                self.assertEqual(cache['validation_scope'], 'COMPACT_SUMMARY_AND_ARTIFACT_BINDING_ONLY')
                self.assertEqual(cache['per_file_reconstruction'], 'FULL_PER_FILE_RECONSTRUCTION_NOT_PERFORMED')
                self.assertIn('cache-residency.json', result['sources'])
                self.assertIn('cache-files.json.gz', result['sources'])
                self.assertEqual(cache['roots'][0]['start_to_release_ns'], 150000000)
                self.assertEqual(cache['roots'][0]['end_to_release_ns'], 100000000)
                condition = REPORT.aggregate([result])['conditions'][0]
                self.assertTrue(condition['timing_output_eligible'])
                self.assertTrue(condition['cache_condition_eligible'])
                self.assertTrue(condition['comparison_eligible'])

    def test_legacy_missing_cache_proof_is_not_collected_not_a_pass(self):
        result = self.report()
        self.assertEqual(result['cache_evidence']['status'], 'NOT_COLLECTED')
        condition = REPORT.aggregate([result])['conditions'][0]
        self.assertTrue(condition['timing_output_eligible'])
        self.assertFalse(condition['cache_condition_eligible'])
        self.assertFalse(condition['comparison_eligible'])
        self.assertEqual(condition['makespan_seconds']['median'], 1.6)

    def test_compact_proof_or_gzip_hash_tampering_does_not_remove_real_wall_time(self):
        proof = self.cache_fixture()
        proof['roots'][0]['resident_fraction'] = .5
        self.save_cache(proof, refresh_digest=False)
        result = REPORT.summarize_trial(self.root)
        self.assertIn('SHA256 mismatch', result['cache_evidence']['issues'][0]['detail'])
        self.assertEqual(result['primary']['seconds'], 1.6)
        self.assertTrue(result['primary']['usable_for_comparison'])
        self.cache_fixture()
        with (self.root / 'cache-files.json.gz').open('ab') as stream:
            stream.write(b'changed')
        result = REPORT.summarize_trial(self.root)
        self.assertIn('gzip artifact SHA256/header mismatch', result['cache_evidence']['issues'][0]['detail'])
        condition = REPORT.aggregate([result])['conditions'][0]
        self.assertTrue(condition['timing_output_eligible'])
        self.assertFalse(condition['cache_condition_eligible'])
        self.assertEqual(condition['makespan_seconds']['median'], 1.6)

    def test_cache_numeric_root_identity_window_and_unknown_tampering_is_rejected(self):
        mutations = [
            ('declared_file_count', True), ('observed_file_count', 1), ('unknown_file_count', 1),
            ('page_size', 4000), ('total_pages', True), ('observed_total_pages', 2),
            ('total_bytes', 20000), ('observed_total_bytes', 8192),
            ('resident_pages', 4), ('resident_bytes', 1), ('resident_fraction', .5),
            ('resident_fraction', float('nan')), ('resident_fraction', float('inf')),
            ('root', '/another/corpus'), ('inventory_sha256', 'e' * 64), ('pin_sha256', 'not-a-pin'),
            ('schema_version', True), ('status', 'INCOMPLETE'), ('errors', ['failed file']),
            ('mincore_authority', 'UNVERIFIED'), ('filesystem_uid', -1),
            ('start_monotonic_ns', 900000000), ('end_monotonic_ns', 1300000000),
            ('duration_ns', 1), ('data_page_state', 'MIXED_RESIDENCY'), ('boot_id', 'other-boot'),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                proof = self.cache_fixture()
                proof['roots'][0][field] = value
                self.save_cache(proof)  # Rebind digest, exercise semantic checks.
                result = REPORT.summarize_trial(self.root)
                self.assertEqual(result['cache_evidence']['status'], 'INVALID_OR_INCOMPLETE')
                self.assertFalse(result['cache_evidence']['cache_condition_eligible'])
                self.assertTrue(result['primary']['usable_for_comparison'])

    def test_cache_reference_escape_and_inconsistent_profile_gap_are_rejected(self):
        for path in ('../outside.json', '/outside.json', './cache-residency.json'):
            with self.subTest(path=path):
                self.cache_fixture()
                self.run['cache_residency']['path'] = path
                self.write()
                self.assertFalse(REPORT.summarize_trial(self.root)['cache_evidence']['cache_condition_eligible'])
        self.cache_fixture()
        self.run['cache_probe_end_to_release_ns'] += 1
        self.write()
        self.assertIn('gap inconsistent', REPORT.summarize_trial(self.root)['cache_evidence']['issues'][0]['detail'])

    def test_cache_top_identity_schema_layout_and_duplicate_roots_are_rejected(self):
        for key, value in (('run_id', 'foreign-run'), ('boot_id', 'foreign-boot'), ('schema_version', True),
                           ('independent_roots_required', True), ('shared_dev_inode_identities', [{}])):
            with self.subTest(field=key):
                proof = self.cache_fixture()
                proof[key] = value
                self.save_cache(proof)
                self.assertFalse(REPORT.summarize_trial(self.root)['cache_evidence']['cache_condition_eligible'])
        proof = self.cache_fixture()
        proof['roots'].append(copy.deepcopy(proof['roots'][0]))
        self.save_cache(proof)
        self.assertIn('exact task workspaces', REPORT.summarize_trial(self.root)['cache_evidence']['issues'][0]['detail'])

    def test_cache_gzip_reference_and_worker_workspace_identity_must_be_bound(self):
        for problem in ('missing_gzip', 'bad_header', 'job_root', 'job_run', 'preflight_boot'):
            with self.subTest(problem=problem):
                proof = self.cache_fixture()
                if problem == 'missing_gzip':
                    proof.pop('file_details')
                elif problem == 'bad_header':
                    raw = b'not really a gzip artifact'
                    (self.root / 'cache-files.json.gz').write_bytes(raw)
                    proof['file_details']['sha256'] = hashlib.sha256(raw).hexdigest()
                elif problem == 'job_root':
                    self.job['corpus'] = '/foreign/workspace'
                elif problem == 'job_run':
                    self.job['query_identity']['run_id'] = 'foreign-run'
                else:
                    self.run['tasks'][0]['preparation']['boot_id'] = 'foreign-boot'
                self.save_cache(proof)
                self.assertFalse(REPORT.summarize_trial(self.root)['cache_evidence']['cache_condition_eligible'])
                self.job['query_identity']['run_id'] = 'run'

    def test_cache_records_oldest_root_ages_not_only_last_probe_gap(self):
        proof = self.cache_fixture()
        self.run['config'].update(workspace_layout='independent', jobs=2)
        task = copy.deepcopy(self.run['tasks'][0])
        task['task_id'] = 'task-1'
        task['process'] = {'pid': 11, 'start_ticks': 51}
        task['preparation']['process'] = task['process']
        self.run['tasks'].append(task)
        second_job = copy.deepcopy(self.job)
        second_job['corpus'] = '/fixture/corpus-copy'
        second_job['query_identity']['task_id'] = 'task-1'
        (self.root / 'task-1-job.json').write_text(json.dumps(second_job))
        proof['independent_roots_required'] = True
        proof['roots'][0].update(start_monotonic_ns=1020000000, end_monotonic_ns=1050000000,
                                 duration_ns=30000000)
        second = copy.deepcopy(proof['roots'][0])
        second.update(root='/fixture/corpus-copy', start_monotonic_ns=1080000000,
                      end_monotonic_ns=1100000000, duration_ns=20000000)
        proof['roots'].append(second)
        self.save_cache(proof)
        result = REPORT.cache_evidence(self.root, self.run, {})
        self.assertTrue(result['cache_condition_eligible'], result['issues'])
        window = result['non_atomic_window']
        self.assertEqual(window['maximum_start_to_release_ns'], 180000000)
        self.assertEqual(window['maximum_root_end_to_release_ns'], 150000000)
        self.assertEqual(window['last_root_end_to_release_ns'], 100000000)
        self.assertGreater(window['maximum_root_end_to_release_ns'], window['last_root_end_to_release_ns'])
        proof['roots'][1]['start_monotonic_ns'] = 1040000000
        proof['roots'][1]['duration_ns'] = 60000000
        self.save_cache(proof)
        self.assertFalse(REPORT.cache_evidence(self.root, self.run, {})['cache_condition_eligible'])

    def trials(self):
        base = self.report()
        rows = []
        for repetition in range(3):
            for concurrency in (1, 8):
                value = copy.deepcopy(base)
                value['run_id'] = '{}-{}'.format(repetition, concurrency)
                value['config'].update(repetition=repetition, concurrency=concurrency)
                value['primary']['seconds'] = 10 if concurrency == 1 else 6
                rows.append(value)
        return rows

    def test_pairing_uses_independent_trial_blocks_not_pooled_queries(self):
        result = REPORT.aggregate(self.trials())
        comparison = next(row for row in result['comparisons'] if row['dimension'] == 'concurrency')
        self.assertEqual({key: comparison['paired_change_seconds'][key] for key in ('n', 'median', 'observed_p95')},
                         {'n': 3, 'median': -4, 'observed_p95': -4})
        self.assertEqual(comparison['paired_change_seconds']['mean'], -4)
        self.assertEqual(comparison['paired_change_seconds']['mean_ci95_bootstrap'], [-4, -4])
        self.assertEqual(comparison['paired_change_seconds']['independent_n'], 3)
        self.assertEqual(comparison['paired_change_seconds']['mean_sampling_unit'], 'PAIRED_REPETITION_BLOCK')
        self.assertEqual(comparison['paired_change_percent']['median'], -40)
        self.assertIn('release', REPORT.markdown(result))

    def test_readable_makespan_pivot_precedes_details_and_keeps_n_and_missing_unknown(self):
        report = REPORT.aggregate(self.trials())
        text = REPORT.markdown(report)
        pivot, details = text.split('## 详细结果', 1)
        self.assertIn('| 缓存 | 文件布局 | 并发 1：秒 | 并发 2：秒 | 并发 4：秒 | 并发 8：秒 |', pivot)
        shared = next(line for line in pivot.splitlines() if line.startswith('| warm | 共享 |'))
        self.assertIn('10.000（n=3', shared)
        self.assertIn('6.000（n=3', shared)
        self.assertEqual(shared.count('—（n=0，未测）'), 2)
        independent = next(line for line in pivot.splitlines() if line.startswith('| warm | 独立 |'))
        self.assertEqual(independent.count('—（n=0，未测）'), 4)
        self.assertNotIn('user CPU s', pivot)
        self.assertIn('user CPU s', details)
        self.assertIn('同一条件下的资源线索', details)

    def test_pivot_never_combines_different_fixed_configs_or_interventions(self):
        report = REPORT.aggregate(self.trials())
        original = copy.deepcopy(report['conditions'][0])
        rows = [original]
        for field, value in (('mode', 'baseline'), ('cpus', [2, 3]), ('memory_high_mb', 512)):
            row = copy.deepcopy(original)
            row['fixed_work'][field] = value
            rows.append(row)
        row = copy.deepcopy(original); row['intervention'] = 'reuse'; rows.append(row)
        # Same mapping with another insertion order remains the same exact
        # group, but its duplicate cell must not be averaged into that group.
        row = copy.deepcopy(original)
        row['fixed_work'] = dict(reversed(list(row['fixed_work'].items())))
        rows.append(row)
        report['conditions'] = rows
        pivot = REPORT.markdown(report).split('## 详细结果', 1)[0]
        self.assertEqual(pivot.count('### 对照组 '), 5)
        self.assertEqual(pivot.count('不合格：重复条件，未合并：'), 1)
        self.assertIn('CPU [2, 3]', pivot)

    def test_resource_and_pair_tables_identify_intervention_and_cache(self):
        report = REPORT.aggregate(self.trials())
        other = copy.deepcopy(report['conditions'][0])
        other['intervention'] = 'exact-reuse'
        report['conditions'].append(other)
        text = REPORT.markdown(report)
        self.assertIn('sampler/warm/shared/none/c1', text)
        self.assertIn('sampler/warm/shared/exact-reuse/c1', text)
        comparison = text.split('## 单因素配对比较', 1)[1].split('### 缓存证明', 1)[0]
        self.assertIn('sampler/warm/shared/none/c8', comparison)

    def test_pivot_preserves_original_values_for_duplicate_output_or_cache_ineligibility(self):
        report = REPORT.aggregate(self.trials())
        c1 = next(row for row in report['conditions'] if row['concurrency'] == 1)
        c1.update(timing_output_eligible=False, output_equivalence='FAIL', comparison_eligible=False)
        duplicate = copy.deepcopy(c1)
        duplicate['makespan_seconds'] = dict(duplicate['makespan_seconds'], median=77, n=7)
        report['conditions'].append(duplicate)
        pivot = REPORT.markdown(report).split('## 详细结果', 1)[0]
        self.assertIn('不合格：重复条件，未合并：', pivot)
        self.assertIn('10.000（n=3；不合格：输出不一致、缓存未验明）', pivot)
        self.assertIn('77.000（n=7；不合格：输出不一致、缓存未验明）', pivot)
        self.assertNotIn('43.500', pivot)
        self.assertIn('6.000（n=3；不合格：缓存未验明）', pivot)

    def test_pivot_full_cache_layout_matrix_has_four_rows_and_other_concurrency_not_hidden(self):
        report = REPORT.aggregate(self.trials())
        template = report['conditions'][0]
        rows = []
        for cache in ('guest-cold', 'warm'):
            for layout in ('shared', 'independent'):
                for concurrency in (1, 2, 4, 8):
                    row = copy.deepcopy(template)
                    row.update(cache=cache, workspace_layout=layout, concurrency=concurrency,
                               timing_output_eligible=True, cache_condition_eligible=True, comparison_eligible=True)
                    row['makespan_seconds'].update(median=concurrency, n=5)
                    rows.append(row)
        other = copy.deepcopy(rows[0]); other['concurrency'] = 3; rows.append(other)
        report['conditions'] = rows
        pivot = REPORT.markdown(report).split('## 详细结果', 1)[0]
        data = [line for line in pivot.splitlines() if line.startswith(('| guest-cold |', '| warm |'))]
        self.assertEqual(len(data), 4)
        self.assertEqual(pivot.count('（n=5）'), 16)
        self.assertNotIn('不合格：', pivot)
        self.assertIn('其他并发值 [3]', pivot)

    def test_mean_bootstrap_is_deterministic_permutation_invariant_and_not_median_ci(self):
        values = [1, 1, 10, 20, 60]
        result = REPORT.independent_mean_summary(values, 'INDEPENDENT_TRIAL')
        self.assertEqual(result, REPORT.independent_mean_summary(values, 'INDEPENDENT_TRIAL'))
        self.assertEqual(result, REPORT.independent_mean_summary(reversed(values), 'INDEPENDENT_TRIAL'))
        self.assertEqual(result['n'], 5)
        self.assertEqual(result['independent_n'], 5)
        self.assertEqual(result['median'], 10)
        self.assertEqual(result['observed_p95'], 60)
        self.assertEqual(result['mean'], 18.4)
        self.assertIsNotNone(result['mean_ci95_bootstrap'])
        self.assertLessEqual(result['mean_ci95_bootstrap'][0], result['mean'])
        self.assertGreaterEqual(result['mean_ci95_bootstrap'][1], result['mean'])

    def test_below_three_independent_trials_or_pairs_never_has_a_ci(self):
        for count in (0, 1, 2):
            with self.subTest(independent_trials=count):
                result = REPORT.independent_mean_summary([7] * count, 'INDEPENDENT_TRIAL')
                self.assertEqual(result['independent_n'], count)
                self.assertIsNone(result['mean_ci95_bootstrap'])
                self.assertEqual(result['mean'], 7 if count else None)
        rows = [row for row in self.trials() if row['config']['repetition'] < 2]
        report = REPORT.aggregate(rows)
        for condition in report['conditions']:
            self.assertEqual(condition['makespan_seconds']['independent_n'], 2)
            self.assertIsNone(condition['makespan_seconds']['mean_ci95_bootstrap'])
        for comparison in report['comparisons']:
            self.assertIsNone(comparison['paired_change_seconds']['mean_ci95_bootstrap'])
            self.assertIsNone(comparison['paired_change_percent']['mean_ci95_bootstrap'])

    def test_conditions_gain_trial_mean_ci_but_query_summaries_do_not(self):
        report = REPORT.aggregate(self.trials())
        for condition in report['conditions']:
            timing = condition['makespan_seconds']
            self.assertEqual(timing['n'], 3)
            self.assertEqual(timing['independent_n'], 3)
            self.assertEqual(timing['mean_sampling_unit'], 'INDEPENDENT_TRIAL')
            self.assertEqual(timing['mean_ci95_bootstrap'], [timing['mean'], timing['mean']])
            self.assertNotIn('mean_ci95_bootstrap', condition['per_query_trial_median_seconds'])
            self.assertNotIn('mean_ci95_bootstrap', condition['per_query_trial_observed_p95_seconds'])
        for trial in report['trials']:
            self.assertNotIn('mean_ci95_bootstrap', trial['per_query']['duration_seconds'])
            for query_summary in trial['per_query']['by_kind'].values():
                self.assertNotIn('mean_ci95_bootstrap', query_summary)
        method = report['confidence_interval_method']
        self.assertEqual(method['statistic'], 'MEAN_NOT_MEDIAN')
        self.assertEqual(method['minimum_independent_units'], 3)
        self.assertEqual(method['seed'], REPORT.BOOTSTRAP_SEED)

    def test_many_inner_repetitions_in_one_matrix_block_do_not_invent_independent_ci(self):
        rows = self.trials()
        for row in rows:
            row['matrix'] = {'stage': 'performance', 'block': 0}
        report = REPORT.aggregate(rows)
        comparison = next(row for row in report['comparisons'] if row['dimension'] == 'concurrency')
        for field in ('paired_change_seconds', 'paired_change_percent'):
            values = comparison[field]
            self.assertEqual(values['n'], 3)
            self.assertEqual(values['independent_n'], 1)
            self.assertEqual(values['mean_sampling_unit'], 'PAIRED_MATRIX_BLOCK')
            self.assertIsNone(values['mean_ci95_bootstrap'])

    def test_matrix_ci_uses_equal_weight_block_means_not_pooled_inner_pairs(self):
        template = self.trials()[0]
        rows = []
        for outer, inner, difference in ((0, 0, 0), (0, 1, 0), (0, 2, 9), (1, 0, 12), (2, 0, 15)):
            for concurrency in (1, 8):
                row = copy.deepcopy(template)
                row['run_id'] = '{}-{}-{}'.format(outer, inner, concurrency)
                row['config'].update(repetition=inner, concurrency=concurrency)
                row['matrix'] = {'stage': 'performance', 'block': outer}
                row['primary']['seconds'] = 10 if concurrency == 1 else 10 + difference
                rows.append(row)
        report = REPORT.aggregate(rows)
        comparison = next(row for row in report['comparisons'] if row['dimension'] == 'concurrency')
        change = comparison['paired_change_seconds']
        self.assertEqual(change['n'], 5)
        self.assertEqual(change['median'], 9)
        self.assertEqual(change['independent_n'], 3)
        self.assertEqual(change['mean'], 10)  # mean of [3, 12, 15], not of the five pairs
        self.assertEqual(change['mean_ci95_bootstrap'], [3, 15])
        text = REPORT.markdown(report)
        self.assertIn('变化均值 %', text)
        self.assertIn('均值变化 95% CI %', text)
        self.assertIn('不是中位数', text)

    def test_warmups_and_diagnostics_do_not_enter_performance_statistics(self):
        rows = self.trials()
        warmup = copy.deepcopy(rows[0]); warmup['config']['warmup'] = True; warmup['run_id'] = 'warmup'
        diagnostic = copy.deepcopy(rows[0]); diagnostic['matrix'] = {'stage': 'diagnostic', 'block': 5}; diagnostic['run_id'] = 'diagnostic'
        report = REPORT.aggregate(rows + [warmup, diagnostic])
        self.assertEqual(report['conditions'][0]['makespan_seconds']['n'], 3)
        self.assertEqual(report['diagnostic_trial_count'], 1)

    def test_output_changed_or_duplicate_blocks_forbid_paired_claim(self):
        rows = self.trials()
        rows[-1]['output_signature'][0]['output_sha256'] = 'e' * 64
        report = REPORT.aggregate(rows)
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertEqual(report['comparisons'], [])
        rows = self.trials()
        duplicate = copy.deepcopy(rows[0]); duplicate['run_id'] = 'different-run-same-block'
        report = REPORT.aggregate(rows + [duplicate])
        self.assertEqual(report['comparisons'], [])

    def test_matrix_block_and_inner_repetition_make_distinct_pairs(self):
        rows = self.trials()
        for row in rows:
            row['matrix'] = {'stage': 'performance', 'block': row['config']['repetition']}
            row['config']['repetition'] = 0
        report = REPORT.aggregate(rows)
        self.assertEqual(report['status'], 'DESCRIPTIVE_FIXED_WORK_COMPARISON')
        self.assertEqual(report['comparisons'][0]['paired_change_percent']['n'], 3)

    def test_copying_same_raw_run_does_not_create_independent_repetitions(self):
        rows = self.trials()
        duplicate = copy.deepcopy(rows[0]); duplicate['config']['repetition'] = 99
        report = REPORT.aggregate(rows + [duplicate])
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertIn('DUPLICATE_RAW_RUN_ID', {row['code'] for row in report['issues']})

    def write_campaign(self, directory, label):
        self.run['run_id'] = label
        self.meta['label'] = label
        self.job['query_identity']['run_id'] = label
        for event in self.events: event['run_id'] = label
        for query in self.query_stats['query_spans']: query['run_id'] = label
        self.run['tasks'][0]['run_id'] = label
        self.write(directory / 'trials/trial-0')
        entry = {key: self.run['config'][key] for key in ('mode', 'concurrency', 'repetition', 'warmup')}
        entry.update(path='trials/trial-0', run_id=label, makespan_ns=self.run['makespan_ns'])
        (directory / 'campaign.json').write_text(json.dumps({'status': 'COMPLETE', 'trials': [entry]}))

    def test_matrix_reads_raw_children_binds_conditions_and_external_blocks(self):
        self.write_campaign(self.root / 'block0', 'run-block0')
        self.write_campaign(self.root / 'block1', 'run-block1')
        matrix = {'schema_version': 1, 'status': 'COMPLETE', 'campaigns': [
            {'path': 'block0', 'block': 0, 'stage': 'performance', 'condition': {'cache': 'warm', 'concurrency': 1}},
            {'path': 'block1', 'block': 1, 'stage': 'performance', 'condition': {'cache': 'warm', 'concurrency': 1}}]}
        path = self.root / 'matrix.json'; path.write_text(json.dumps(matrix))
        trials = REPORT.summarize_matrix(path)
        self.assertEqual(len(trials), 2)
        self.assertEqual(REPORT.aggregate(trials)['conditions'][0]['makespan_seconds']['n'], 2)
        matrix['campaigns'][0]['condition']['cache'] = 'guest-cold'
        path.write_text(json.dumps(matrix))
        with self.assertRaisesRegex(ValueError, 'condition differs'):
            REPORT.summarize_matrix(path)

    def test_matrix_duplicate_source_and_path_escape_are_rejected(self):
        self.write_campaign(self.root / 'block0', 'run-block0')
        entry = {'path': 'block0', 'block': 0, 'stage': 'performance', 'condition': {'cache': 'warm'}}
        matrix = {'schema_version': 1, 'status': 'COMPLETE', 'campaigns': [entry, dict(entry, block=1)]}
        path = self.root / 'matrix.json'; path.write_text(json.dumps(matrix))
        with self.assertRaisesRegex(ValueError, 'reuse'):
            REPORT.summarize_matrix(path)
        matrix['campaigns'] = [dict(entry, path='../foreign')]
        path.write_text(json.dumps(matrix))
        with self.assertRaises(ValueError):
            REPORT.summarize_matrix(path)

    def test_matrix_complete_plan_block_is_bound_to_outer_block_not_raw_config(self):
        self.write_campaign(self.root / 'block0', 'run-block0')
        condition = {'cache': 'warm', 'workspace_layout': 'shared', 'concurrency': 1,
                     'intervention': 'none', 'block': 0, 'warmup': False}
        entry = {'path': 'block0', 'block': 0, 'stage': 'performance', 'condition': condition}
        matrix = {'schema_version': 1, 'status': 'COMPLETE', 'campaigns': [entry]}
        path = self.root / 'matrix.json'
        path.write_text(json.dumps(matrix))
        self.assertEqual(len(REPORT.summarize_matrix(path)), 1)
        for invalid in (1, False, -1, None):
            with self.subTest(block=invalid):
                condition['block'] = invalid
                path.write_text(json.dumps(matrix))
                with self.assertRaisesRegex(ValueError, 'condition block differs'):
                    REPORT.summarize_matrix(path)

    def test_matrix_unknown_null_key_and_boolean_integer_alias_are_rejected(self):
        self.write_campaign(self.root / 'block0', 'run-block0')
        entry = {'path': 'block0', 'block': 0, 'stage': 'performance', 'condition': {}}
        matrix = {'schema_version': 1, 'status': 'COMPLETE', 'campaigns': [entry]}
        path = self.root / 'matrix.json'
        for condition in ({'unknown_plan_field': None}, {'concurrency': True}, {'warmup': 0}):
            with self.subTest(condition=condition):
                entry['condition'] = condition
                path.write_text(json.dumps(matrix))
                with self.assertRaisesRegex(ValueError, 'condition differs'):
                    REPORT.summarize_matrix(path)

    def test_matrix_warmup_stage_binds_raw_flag_and_never_enters_performance(self):
        self.write_campaign(self.root / 'formal', 'run-formal')
        self.run['config']['warmup'] = True
        self.write_campaign(self.root / 'warmup', 'run-warmup')
        formal = {'path': 'formal', 'block': 0, 'stage': 'performance', 'condition': {'warmup': False}}
        warmup = {'path': 'warmup', 'block': 0, 'stage': 'warmup', 'condition': {'warmup': True}}
        matrix = {'schema_version': 1, 'status': 'COMPLETE', 'campaigns': [formal, warmup]}
        path = self.root / 'matrix.json'; path.write_text(json.dumps(matrix))
        result = REPORT.aggregate(REPORT.summarize_matrix(path))
        self.assertEqual(result['conditions'][0]['makespan_seconds']['n'], 1)
        self.assertEqual(result['warmup_trial_count'], 1)
        self.assertIn('1 轮 warmup', REPORT.markdown(result))
        for entry, invalid_stage in ((formal, 'warmup'), (warmup, 'performance')):
            with self.subTest(path=entry['path']):
                old_stage = entry['stage']; entry['stage'] = invalid_stage
                path.write_text(json.dumps(matrix))
                with self.assertRaisesRegex(ValueError, 'stage differs'):
                    REPORT.summarize_matrix(path)
                entry['stage'] = old_stage


if __name__ == '__main__':
    unittest.main()
