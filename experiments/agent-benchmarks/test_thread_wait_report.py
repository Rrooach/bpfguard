#!/usr/bin/env python3
"""Offline thread identity, clock, missing-data and counter-reset regression tests."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location('benchmark_thread_wait_report', Path(__file__).with_name('thread_wait_report.py'))
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class ThreadWaitTests(unittest.TestCase):
    def setUp(self):
        self.cg = {'path': '/sys/fs/cgroup/test', 'inode': 42, 'device': 28}
        self.meta = {'boot_id': 'boot', 'label': 'run', 'cgroups': [self.cg],
            'thread_sampling': {'enabled': True, 'schedstats_runtime_enabled_at_start': True}}
        self.stats = {key: 0 for key in ('read_errors', 'vanished_processes', 'truncated_process_sets',
            'truncated_cgroup_traversals', 'cgroup_traversal_read_errors', 'thread_read_errors',
            'vanished_threads_during_read', 'truncated_thread_samples', 'thread_identity_changes', 'missed_ticks')}
        self.stats['process_samples'] = 2
        self.identity = {'boot_id': 'boot', 'pid': 10, 'process_start_ticks': 20, 'tid': 11, 'thread_start_ticks': 25}
        self.rows = []
        for seq, begin, run, wait in ((0, 1000, 10, 50), (1, 2000, 40, 130)):
            thread = {'identity': dict(self.identity), 'comm': 'worker', 'run_ns': run, 'wait_ns': wait,
                'timeslices': seq + 1, 'utime': seq + 2, 'stime': seq + 3,
                'collection_start_ns': begin + 10, 'collection_end_ns': begin + 20,
                'wait_counter_status': 'ENABLED', 'lifecycle_status': 'POLLED_INSTANCE_NOT_FULL_LIFECYCLE'}
            self.rows.append({'seq': seq, 'monotonic_ns': begin, 'collection_end_ns': begin + 100,
                'schedstats_runtime_enabled': True, 'cgroups': [{'present': True,
                    'thread_sampling': 'PARTIAL_POLLED_NOT_FULL_LIFECYCLE', 'truncated_cgroup_dirs': False,
                    'truncated_process_set': False, 'traversal_errors': [], 'disappeared_threads': [],
                    'processes': [{'pid': 10, 'start_ticks': 20, 'boot_id': 'boot',
                        'tid_sampling_issues': [], 'tid_samples': [thread]}]}]})

    def report(self, **kwargs):
        return REPORT.analyze(self.meta, self.stats, self.rows, **kwargs)

    def thread(self, index):
        return self.rows[index]['cgroups'][0]['processes'][0]['tid_samples'][0]

    def codes(self, report):
        return {row['code'] for row in report['issues']}

    def interval(self, report):
        return report['instances'][0]['intervals'][0]

    def test_two_identity_bound_endpoints_use_actual_collection_windows(self):
        report = self.report(window=[900, 2200])
        self.assertEqual(report['status'], 'OBSERVED_PARTIAL_POLLING')
        self.assertEqual(report['observed_run_wait_interval_fully_inside_execution_count'], 1)
        interval = self.interval(report)
        self.assertEqual(interval['deltas']['run_ns'], 30)
        self.assertEqual(interval['deltas']['wait_ns'], 80)
        self.assertEqual(interval['elapsed_min_ns'], 990)
        self.assertEqual(interval['elapsed_max_ns'], 1010)
        self.assertNotIn('COMPLETE', report['status'])

    def test_schedstats_disabled_at_ready_cannot_turn_zero_into_success(self):
        self.meta['thread_sampling']['schedstats_runtime_enabled_at_start'] = False
        report = self.report()
        self.assertIsNone(self.interval(report)['deltas']['wait_ns'])
        self.assertEqual(report['counter_status'], 'INCONCLUSIVE')
        self.assertIn('SCHEDSTATS_NOT_ENABLED_AT_READY', self.codes(report))

    def test_process_sampling_cadence_can_skip_system_sample_sequence_numbers(self):
        self.rows[0]['seq'] = 0
        self.rows[1]['seq'] = 5
        report = self.report()
        self.assertEqual(report['status'], 'OBSERVED_PARTIAL_POLLING')
        self.assertEqual(self.interval(report)['deltas']['wait_ns'], 80)
        self.assertEqual(self.interval(report)['last_source_seq'], 5)

    def test_runtime_schedstats_change_or_missing_flag_is_unknown(self):
        for enabled in (False, None, 1):
            with self.subTest(enabled=enabled):
                self.rows[1]['schedstats_runtime_enabled'] = enabled
                report = self.report()
                self.assertIsNone(self.interval(report)['deltas']['wait_ns'])
                self.assertIn('SCHEDSTATS_DISABLED_OR_UNKNOWN', self.codes(report))

    def test_counter_regression_never_produces_negative_delta(self):
        self.thread(1)['wait_ns'] = 40
        report = self.report()
        interval = self.interval(report)
        self.assertIsNone(interval['deltas']['wait_ns'])
        self.assertEqual(interval['deltas']['run_ns'], 30)
        self.assertEqual(interval['status'], 'INCOMPLETE_COUNTER_INTERVAL')
        self.assertIn('THREAD_COUNTER_REGRESSION', self.codes(report))

    def test_missing_thread_counter_is_not_zero(self):
        del self.thread(0)['wait_ns']
        report = self.report()
        self.assertIsNone(self.interval(report)['deltas']['wait_ns'])
        self.assertIn('MISSING_THREAD_COUNTER', self.codes(report))

    def test_pid_or_tid_reuse_never_joins_different_birth_instances(self):
        self.thread(1)['identity']['thread_start_ticks'] += 1
        report = self.report()
        self.assertEqual(report['instance_count'], 2)
        self.assertTrue(all(not row['intervals'] for row in report['instances']))
        self.assertEqual(report['counter_status'], 'INCONCLUSIVE')

    def test_foreign_boot_or_wrong_process_birth_is_rejected(self):
        self.thread(1)['identity']['boot_id'] = 'other'
        report = self.report()
        self.assertIn('THREAD_IDENTITY_MISMATCH', self.codes(report))
        self.assertEqual(report['observed_run_wait_interval_count'], 0)

    def test_gap_between_same_identity_endpoints_is_not_interpolated(self):
        gap = copy.deepcopy(self.rows[0])
        gap.update(seq=1, monotonic_ns=1500, collection_end_ns=1600)
        gap['cgroups'][0]['processes'] = []
        self.rows[1]['seq'] = 2
        self.rows.insert(1, gap)
        self.stats['process_samples'] = 3
        report = self.report()
        self.assertIsNone(self.interval(report)['deltas']['run_ns'])
        self.assertIn('THREAD_NOT_OBSERVED_BETWEEN_ENDPOINTS', self.codes(report))

    def test_collection_time_outside_source_row_or_nonmonotonic_is_rejected(self):
        self.thread(1)['collection_end_ns'] = 9000
        report = self.report()
        self.assertIn('INVALID_THREAD_COLLECTION_WINDOW', self.codes(report))
        self.assertIsNone(self.interval(report)['deltas']['run_ns'])

    def test_task_boundary_crossing_is_retained_without_clipping(self):
        report = self.report(window=[1500, 2050])
        interval = self.interval(report)
        self.assertEqual(interval['deltas']['wait_ns'], 80)
        self.assertEqual(interval['execution_window_relation'], 'CROSSES_OR_OUTSIDE_EXECUTION_WINDOW_NOT_CLIPPED')
        self.assertEqual(report['observed_run_wait_interval_fully_inside_execution_count'], 0)

    def test_external_identity_anchor_mismatch_suppresses_deltas(self):
        expected = {'boot_id': 'other', 'label': 'run', 'cgroups': [self.cg]}
        report = self.report(expectation=expected)
        self.assertEqual(report['external_anchor_status'], 'MISMATCH')
        self.assertIsNone(self.interval(report)['deltas']['run_ns'])

    def test_external_anchor_compares_cgroup_identity_not_ancillary_availability(self):
        self.meta['cgroups'][0]['available'] = {'pressure': True}
        expected = {'boot_id': 'boot', 'label': 'run', 'cgroups': [
            {key: self.cg[key] for key in ('path', 'inode', 'device')}]}
        report = self.report(expectation=expected)
        self.assertEqual(report['external_anchor_status'], 'MATCHED_SAVED_METADATA')
        self.assertEqual(self.interval(report)['deltas']['wait_ns'], 80)

    def test_overlapping_domains_remain_separate_never_globally_summed(self):
        self.meta['cgroups'].append({**self.cg, 'path': '/sys/fs/cgroup/test/child', 'inode': 43})
        for row in self.rows:
            row['cgroups'].append(copy.deepcopy(row['cgroups'][0]))
        report = self.report()
        self.assertEqual(report['instance_count'], 2)
        self.assertNotIn('total_wait_ns', report)
        self.assertEqual([row['domain_index'] for row in report['instances']], [0, 1])

    def test_missing_final_health_counters_stay_unknown(self):
        del self.stats['thread_identity_changes']
        self.assertIn('MISSING_HEALTH_COUNTER', self.codes(self.report()))

    def test_json_artifact_loader_retains_source_fingerprints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (('load-meta.json', self.meta), ('load-sampler-stats.json', self.stats)):
                (root / name).write_text(json.dumps(value))
            (root / 'load-processes.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in self.rows))
            report = REPORT.load_report(root)
            self.assertEqual(len(report['sources']), 3)
            self.assertEqual(len(report['sources']['load-processes.jsonl']['sha256']), 64)
            self.assertEqual(report['observed_run_wait_interval_count'], 1)


if __name__ == '__main__':
    unittest.main()
