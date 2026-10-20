import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import access_comparison as compare


def trial(block=0, mode='sampler', concurrency=2, seconds=2.0):
    return {'run_id': '%s-%s-%s' % (block, mode, concurrency), 'boot_id': 'boot',
        'config': {'file_access_mode': mode, 'concurrency': concurrency, 'warmup': False,
            'file_access_backend': 'fentry',
            'collector_ring_bytes': 64 * 1024 ** 2,
            'intervention': 'none', 'cache': 'warm', 'workspace_layout': 'shared',
            'jobs': 8, 'passes': 1, 'cpus': [0, 1, 2, 3]}, 'matrix': {'block': block},
        'primary': {'usable_for_comparison': True, 'seconds': seconds},
        'cache_evidence': {'cache_condition_eligible': True},
        'output_signature': [{'task_id': 't', 'query_index': 0, 'exit_code': 0,
                              'output_sha256': 'a' * 64, 'output_bytes': 16}],
        'task_cpu': {'user_seconds': 1.0, 'system_seconds': .5},
        'per_query': {'duration_seconds': {'median': .3}},
        'resources': {'status': 'OBSERVED_ENCLOSING_INTERVAL', 'memory_counters': {'pgmajfault': 0},
                      'io_by_device': {'253:0': {'rbytes': 0}},
                      'psi_stall_us': {'cpu': {'some': 1000000}, 'io': {'some': 0}}},
        'extra_counters': {'pgfault': 40}, 'file_metrics': {'read_calls': 100} if mode == 'access' else {},
        'file_analysis_status': 'COMPLETE_FOR_SELECTED_HOOKS' if mode == 'access' else 'NOT_ENABLED'}


class ComparisonTests(unittest.TestCase):
    def boundary_fixture(self):
        row = trial(0, 'access', seconds=2.0)
        row['sources'] = {'profile-run.json': {'sha256': 'a' * 64}}
        row['execution_window'] = [1000000000, 3000000000]
        capture = {'profile_run_id': row['run_id'], 'profile_run_sha256': 'a' * 64, 'boot_id': row['boot_id'],
            'release_ns': 1000000000, 'end_ns': 3000000000, 'makespan_ns': 2000000000,
            'started_monotonic_ns': 100000000, 'ready_received_monotonic_ns': 300000000,
            'finalized_monotonic_ns': 3600000000, 'collector_ring_bytes': 64 * 1024 ** 2,
            'hash_scope': 'DETACHED_DRAINED_FSYNCED_FD_PASS',
            'final': {'ring_bytes': 64 * 1024 ** 2, 'bytes': 1920, 'persisted_records': 10}}
        return row, capture

    def test_real_collector_boundaries_keep_startup_and_completion_gap_separate(self):
        row, capture = self.boundary_fixture()
        result = compare.collector_boundaries(capture, row)
        self.assertEqual(result['status'], 'OBSERVED_SAVED_BOUNDARIES')
        self.assertEqual(result['startup_seconds'], .2)
        self.assertEqual(result['post_exit_finalization_seconds'], .6)
        self.assertEqual(result['execution_to_raw_evidence_ready_seconds'], 2.6)
        self.assertEqual(result['artifact_bytes'], 1920)
        self.assertEqual(result['persisted_events'], 10)

    def test_sampler_collector_boundary_is_not_enabled_never_zero(self):
        row, capture = self.boundary_fixture()
        row['config']['file_access_mode'] = 'sampler'
        result = compare.collector_boundaries(capture, row)
        self.assertEqual(result['status'], 'NOT_ENABLED')
        self.assertIsNone(result['startup_seconds'])
        self.assertIsNone(result['post_exit_finalization_seconds'])
        self.assertIsNone(result['artifact_bytes'])

    def test_missing_timer_is_unknown_and_other_real_fields_survive(self):
        row, capture = self.boundary_fixture()
        capture.pop('started_monotonic_ns')
        result = compare.collector_boundaries(capture, row)
        self.assertEqual(result['status'], 'PARTIAL_OR_UNKNOWN')
        self.assertIsNone(result['startup_seconds'])
        self.assertEqual(result['post_exit_finalization_seconds'], .6)
        self.assertEqual(result['artifact_bytes'], 1920)

    def test_shifted_or_wrong_profile_boundary_is_rejected(self):
        row, capture = self.boundary_fixture()
        capture['release_ns'] += 100
        capture['end_ns'] += 100
        result = compare.collector_boundaries(capture, row)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIsNone(result['execution_to_raw_evidence_ready_seconds'])
        row, capture = self.boundary_fixture()
        capture['profile_run_sha256'] = 'b' * 64
        self.assertEqual(compare.collector_boundaries(capture, row)['status'], 'UNKNOWN')

    def extra_fixture(self, path, sched_enabled=True):
        (path / 'load').mkdir()
        identity = {'path': '/sys/fs/cgroup/test', 'inode': 13, 'device': 28}
        meta = {'cgroups': [identity], 'thread_sampling': {'schedstats_runtime_enabled_at_start': sched_enabled}}
        rows = []
        for i in range(3):
            rows.append({'monotonic_ns': 1000000000 + i * 100000000,
                'cgroups': [{'memory_stat': {'pgfault': 100 + 4 * i, 'anon': 20 + i}, 'memory_current': 40 + i}],
                'stat': {'ctxt': 50 + 2 * i, 'processes': 10 + i, 'procs_blocked': i, 'cpu_ids': [0]},
                'vmstat': {'pgfault': 200 + i, 'pgmajfault': 4},
                'net_dev': {'eth0': [40 + i, 0, 0, 0, 80 + i, 0, 0, 0]},
                'schedstat': [[100000000 + i, 10000000 + i * 20000000, 5 + i]]})
        (path / 'load/load-meta.json').write_text(json.dumps(meta))
        (path / 'load/load-samples.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return {'resources': {'root_cgroup': identity, 'boundary': {'first_collection': [1000000000],
                                                                   'last_collection': [1200000000]}}}

    def test_extra_whole_guest_counters_and_run_delay_are_separate(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            fixture = self.extra_fixture(path)
            result = compare.extra_counters(path, fixture)
            self.assertEqual(result['pgfault'], 8)
            self.assertEqual(result['guest_context_switches'], 4)
            self.assertEqual(result['guest_eth0_rx_bytes'], 2)
            self.assertEqual(result['guest_average_cpu_runqueue_waiting_tasks'], .2)
            self.assertEqual(result['guest_observed_max_d_state_tasks'], 2)
            self.assertEqual(result['target_observed_max_memory_bytes'], 42)

    def test_schedstats_disabled_must_not_be_reported_zero_wait(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            fixture = self.extra_fixture(path, False)
            result = compare.extra_counters(path, fixture)
            self.assertIsNone(result['guest_average_cpu_runqueue_waiting_tasks'])

    def test_numeric_metrics_flatten_without_counting_definitions(self):
        self.assertEqual(compare.flatten_metrics({'read_calls': 3, 'definition': 'selected hooks',
            'faults': {'RETRY': 2, 'unknown': None}, 'disabled': False}),
            {'read_calls': 3, 'faults.RETRY': 2, 'faults.unknown': None})

    def test_modes_never_pool_and_pair_same_block(self):
        rows = [trial(block, mode, seconds=2 if mode == 'sampler' else 3)
                for block in range(5) for mode in ('sampler', 'access')]
        report = compare.aggregate(rows)
        self.assertEqual(report['status'], 'DESCRIPTIVE_PAIRED_SEARCH_COMPARISON')
        self.assertEqual(len(report['conditions']), 2)
        self.assertEqual({r['makespan_seconds']['median'] for r in report['conditions']}, {2, 3})
        overhead = report['collector_overhead'][0]
        self.assertEqual(overhead['eligible_paired_n'], 5)
        self.assertEqual(overhead['added_seconds']['median'], 1)
        self.assertEqual(overhead['added_percent']['median'], 50)

    def test_2_4_6_8_output_and_complete_count(self):
        rows = [trial(block, mode, n, seconds=8 / n + (.1 if mode == 'access' else 0))
                for block in range(5) for n in (2, 4, 6, 8) for mode in ('sampler', 'access')]
        report = compare.aggregate(rows)
        self.assertEqual(len(report['conditions']), 8)
        self.assertEqual(len(report['collector_overhead']), 4)
        text = compare.markdown(report)
        self.assertIn('并发 6', text)
        self.assertIn('n=5', text)
        self.assertNotIn('nan', text)

    def test_missing_metrics_are_not_zero(self):
        rows = [trial(0, 'sampler'), trial(0, 'access')]
        rows[1]['resources']['io_by_device'] = {}
        report = compare.aggregate(rows)
        accessed = next(r for r in report['conditions'] if r['file_access_mode'] == 'access')
        self.assertIsNone(accessed['data_read_bytes']['median'])
        self.assertEqual(accessed['data_read_bytes']['unknown_n'], 1)
        self.assertEqual(accessed['major_page_faults']['median'], 0)

    def test_bad_output_and_duplicate_block_rejected(self):
        rows = [trial(0, 'sampler'), trial(0, 'access')]
        rows[1]['output_signature'][0]['output_bytes'] = 17
        report = compare.aggregate(rows + [copy.deepcopy(rows[1])])
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertTrue(any('OUTPUT_MISMATCH' in issue for issue in report['issues']))
        self.assertTrue(any('DUPLICATE' in issue for issue in report['issues']))
        self.assertEqual(report['collector_overhead'][0]['eligible_paired_n'], 0)

    def test_boot_change_cannot_be_paired(self):
        rows = [trial(0, 'sampler'), trial(0, 'access')]
        rows[1]['boot_id'] = 'other'
        report = compare.aggregate(rows)
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertEqual(report['collector_overhead'][0]['eligible_paired_n'], 0)

    def test_backend_changes_are_never_pooled_or_paired(self):
        rows = [trial(0, 'sampler'), trial(0, 'access')]
        rows[1]['config']['file_access_backend'] = 'kprobe-tracefs'
        report = compare.aggregate(rows)
        self.assertEqual(len(report['conditions']), 2)
        self.assertEqual(report['collector_overhead'][0]['paired_n'], 0)
        self.assertEqual({r['file_access_backend'] for r in report['conditions']}, {'fentry', 'kprobe-tracefs'})

    def test_ring_budget_changes_are_never_paired(self):
        rows = [trial(0, 'sampler'), trial(0, 'access')]
        rows[1]['config']['collector_ring_bytes'] = 256 * 1024 ** 2
        report = compare.aggregate(rows)
        self.assertEqual(len(report['conditions']), 2)
        self.assertEqual(report['collector_overhead'][0]['paired_n'], 0)
        text = compare.markdown(report)
        self.assertIn('ring 64.0 MiB', text)
        self.assertIn('ring 256.0 MiB', text)

    def test_unpaired_blocks_not_paired_by_position(self):
        report = compare.aggregate([trial(0, 'sampler'), trial(1, 'access')])
        overhead = report['collector_overhead'][0]
        self.assertEqual(overhead['paired_n'], 0)
        self.assertEqual(overhead['missing_sampler_blocks'], [1])
        self.assertEqual(overhead['missing_access_blocks'], [0])


class ReceiptMappingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.matrix = self.root / 'main/matrix.json'
        self.matrix.parent.mkdir()
        self.matrix.write_text('{}')
        self.case_id = '001-r0'
        self.target = self.matrix.parent / self.case_id
        self.directory = self.target / 'trials/one'
        self.directory.mkdir(parents=True)
        self.row = trial(0, 'access')
        profile = {'release_ns': 1000000000, 'end_ns': 3000000000, 'makespan_ns': 2000000000}
        (self.directory / 'profile-run.json').write_text(json.dumps(profile))
        self.profile_sha = self.sha(self.directory / 'profile-run.json')
        capture = {'profile_run_id': self.row['run_id'], 'profile_run_sha256': self.profile_sha,
            'boot_id': 'boot', 'collector_run_id': 'collector', 'release_ns': 1000000000,
            'end_ns': 3000000000, 'makespan_ns': 2000000000}
        (self.target / 'capture.json').write_text(json.dumps(capture))
        self.capture_sha = self.sha(self.target / 'capture.json')
        self.row.update(directory=str(self.directory), sources={'profile-run.json': {'sha256': self.profile_sha}},
                        matrix={'block': 0, 'campaign': self.case_id})
        self.base = self.root / 'analysis'
        self.retry = self.base / 'retries' / (self.case_id + '-retry')
        self.retry.mkdir(parents=True)
        self.summary = {'status': 'INCOMPLETE', 'run_id': self.row['run_id'], 'collector_run_id': 'collector',
            'metrics': {'read_calls': 17}, 'sources': {'profile_run': {'sha256': self.profile_sha},
            'capture': {'sha256': self.capture_sha}}}
        self.summary_path = self.retry / 'summary.json'
        self.summary_path.write_text(json.dumps(self.summary))
        stale = self.base / self.case_id
        stale.mkdir()
        (stale / 'summary.json').write_text(json.dumps(dict(self.summary, metrics={'read_calls': 999})))
        self.attempt = 'a' * 32
        self.receipt_path = self.base / ('attempt-' + self.attempt + '.json')
        self.receipt = {'schema_version': 1, 'attempt': self.attempt, 'status': 'INCOMPLETE',
            'selected_cases': 1, 'results': {self.case_id: self.result_row()}, 'failures': {}}
        self.save_receipt()

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def result_row(self):
        return {'case_id': self.case_id, 'output': str(self.retry), 'analysis_status': 'INCOMPLETE',
            'sources': self.summary['sources'], 'artifacts': {'summary.json': {'path': str(self.summary_path),
                'sha256': self.sha(self.summary_path), 'bytes': self.summary_path.stat().st_size}}}

    def save_receipt(self):
        self.receipt_path.write_text(json.dumps(self.receipt))

    def load(self, **kwargs):
        with mock.patch.object(compare.wall, 'summarize_matrix', return_value=[copy.deepcopy(self.row)]):
            return compare.load_trials(self.matrix, **kwargs)[0]

    def test_retry_mapping_binds_summary_digest_and_keeps_incomplete(self):
        row = self.load(analysis_receipt=self.receipt_path, expected_receipt_sha256=self.sha(self.receipt_path))
        self.assertEqual(row['file_metrics']['read_calls'], 17)
        self.assertEqual(row['file_analysis_status'], 'INCOMPLETE')
        self.assertEqual(row['file_analysis']['path'], str(self.summary_path))
        self.assertEqual(row['file_analysis_receipt']['sha256'], self.sha(self.receipt_path))

    def test_without_receipt_old_root_behavior_is_unchanged(self):
        row = self.load(analysis_root=self.base)
        self.assertEqual(row['file_metrics']['read_calls'], 999)
        self.assertNotIn('file_analysis_receipt', row)

    def test_root_and_receipt_are_mutually_exclusive(self):
        with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
            self.load(analysis_root=self.base, analysis_receipt=self.receipt_path)

    def test_changed_summary_is_unknown_and_does_not_fall_back_to_stale_output(self):
        self.summary_path.write_text(json.dumps(dict(self.summary, metrics={'read_calls': 18})))
        row = self.load(analysis_receipt=self.receipt_path)
        self.assertEqual(row['file_analysis_status'], 'MISSING_OR_INVALID')
        self.assertEqual(row['file_metrics'], {})

    def test_failed_case_does_not_pick_existing_stale_summary(self):
        self.receipt.update(results={}, failures={self.case_id: {'case_id': self.case_id, 'error': 'worker failed'}})
        self.save_receipt()
        row = self.load(analysis_receipt=self.receipt_path)
        self.assertEqual(row['file_analysis_status'], 'ANALYSIS_FAILED')
        self.assertEqual(row['file_metrics'], {})
        self.assertIn('worker failed', row['file_analysis_issue'])

    def test_unselected_case_stays_unknown(self):
        result = self.receipt['results'].pop(self.case_id)
        result['case_id'] = '002-r0'
        self.receipt['results']['002-r0'] = result
        self.save_receipt()
        row = self.load(analysis_receipt=self.receipt_path)
        self.assertEqual(row['file_analysis_status'], 'NOT_SELECTED_IN_BATCH_RECEIPT')
        self.assertEqual(row['file_metrics'], {})

    def test_receipt_case_key_and_result_identity_must_match(self):
        self.receipt['results'][self.case_id]['case_id'] = 'wrong-case'
        self.save_receipt()
        with self.assertRaisesRegex(ValueError, 'case identity'):
            self.load(analysis_receipt=self.receipt_path)

    def test_wrong_receipt_sha_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.load(analysis_receipt=self.receipt_path, expected_receipt_sha256='0' * 64)

    def test_profile_and_capture_source_bindings_are_rechecked(self):
        self.receipt['results'][self.case_id]['sources']['capture']['sha256'] = '0' * 64
        self.save_receipt()
        row = self.load(analysis_receipt=self.receipt_path)
        self.assertEqual(row['file_analysis_status'], 'MISSING_OR_INVALID')
        self.assertEqual(row['file_metrics'], {})

    def test_wrong_run_cannot_be_hidden_by_matching_summary_sha(self):
        self.summary['run_id'] = 'another-run'
        self.summary_path.write_text(json.dumps(self.summary))
        self.receipt['results'][self.case_id] = self.result_row()
        self.save_receipt()
        row = self.load(analysis_receipt=self.receipt_path)
        self.assertEqual(row['file_analysis_status'], 'MISSING_OR_INVALID')

    def test_complete_batch_cannot_contradict_incomplete_case(self):
        self.receipt['status'] = 'COMPLETE_FOR_SELECTED_CASES'
        self.save_receipt()
        with self.assertRaisesRegex(ValueError, 'contradicts'):
            self.load(analysis_receipt=self.receipt_path)

    def test_schema_two_plain_summary_remains_usable_and_binds_storage_module(self):
        self.receipt.update(schema_version=2, artifact_storage={'schema_version': 1, 'codec': 'gzip',
            'artifact_module_sha256': self.sha(Path(compare.ARTIFACTS.__file__))})
        self.save_receipt()
        row = self.load(analysis_receipt=self.receipt_path)
        self.assertEqual(row['file_metrics']['read_calls'], 17)
        self.receipt['artifact_storage']['artifact_module_sha256'] = '0' * 64
        self.save_receipt()
        with self.assertRaisesRegex(ValueError, 'implementation binding'):
            self.load(analysis_receipt=self.receipt_path)

    def test_archive_requires_explicit_schema_and_unknown_codec_is_rejected(self):
        self.receipt['results'][self.case_id]['artifact_storage_schema'] = 2
        self.save_receipt()
        with self.assertRaisesRegex(ValueError, 'schema-2'):
            self.load(analysis_receipt=self.receipt_path)
        self.receipt.update(schema_version=2, artifact_storage={'schema_version': 1, 'codec': 'zstd',
            'artifact_module_sha256': self.sha(Path(compare.ARTIFACTS.__file__))})
        self.save_receipt()
        with self.assertRaisesRegex(ValueError, 'codec/schema'):
            self.load(analysis_receipt=self.receipt_path)


if __name__ == '__main__':
    unittest.main()
