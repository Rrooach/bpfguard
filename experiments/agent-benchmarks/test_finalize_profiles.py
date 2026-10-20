import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import finalize_profiles as final


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class FinalizeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'raw'
        self.root.mkdir()
        self.output = Path(self.temp.name) / 'new-output'

    def tearDown(self):
        self.temp.cleanup()

    def query_fixture(self):
        directory = self.root / 'query'
        directory.mkdir()
        provenance = {'image_id': 'sha256:actual-image', 'copied_path': '/guest/copied-source'}
        manifest = {'status': 'COMPLETE', 'intervention': 'none', 'repository_version': provenance['image_id'],
            'corpus': provenance['copied_path'], 'jobs': 8, 'passes': 8, 'corpus_sha256': 'c' * 64,
            'conditions': [], 'trials': []}
        for concurrency in (1, 8):
            for mode in ('baseline', 'sampler'):
                for warmup in (False, True):
                    for repeat in (range(1) if warmup else range(5)):
                        condition = {'concurrency': concurrency, 'mode': mode, 'repetition': repeat, 'warmup': warmup}
                        index = len(manifest['trials'])
                        item = {'path': 'trials/trial-%02d' % index, 'run_id': 'query-run-' + str(index), **condition}
                        manifest['conditions'].append(condition)
                        manifest['trials'].append(item)
                        write(directory / item['path'] / 'profile-run.json', {'run_id': item['run_id'], 'config': {
                            **condition, 'corpus_sha256': manifest['corpus_sha256'],
                            'repository_version': provenance['image_id'], 'intervention': 'none'}})
        write(directory / 'campaign.json', manifest)
        self.query_calls = []

        def analyze_trial(path):
            self.query_calls.append(path)
            return {'query_measurements': {'status': 'OBSERVED', 'expected_queries': 64, 'observed_queries': 64,
                'queries': [{'measurement_status': 'OBSERVED'} for _ in range(64)], 'duration_seconds': {'n': 64, 'median': .1}},
                'task_count': 8, 'tasks': [{'task_id': 'task-' + str(index), 'identity_valid': True, 'status': 'COMPLETE',
                    'completion': {'exit_code': 0, 'output_sha256': 'o' * 64, 'output_bytes': 10}} for index in range(8)],
                'sampling_status': 'INCOMPLETE', 'issues': [{'code': 'SHORT_WINDOW_NO_SAMPLE'}], 'execution_makespan_ns': 100}

        return directory, provenance, manifest, SimpleNamespace(analyze_trial=analyze_trial)

    def test_queries_replay_every_trial_and_keep_warmups_and_resource_unknown(self):
        directory, provenance, _, analyzer = self.query_fixture()
        before = {str(path): path.read_bytes() for path in directory.rglob('*') if path.is_file()}
        report = final.query_campaign(directory, 'none', provenance, analyzer, self.output)
        self.assertEqual(len(self.query_calls), 24)
        self.assertEqual(report['formal_trial_count'], 20)
        self.assertEqual(report['warmup_trial_count'], 4)
        self.assertEqual(report['formal_query_count'], 1280)
        self.assertEqual(report['warmup_query_count'], 256)
        self.assertEqual(report['sampling_status_counts'], {'INCOMPLETE': 24})
        self.assertEqual(before, {str(path): path.read_bytes() for path in directory.rglob('*') if path.is_file()})
        self.assertEqual(len(list(self.output.glob('trial-*.json'))), 24)

    def test_query_missing_or_duplicate_condition_not_counted_as_complete(self):
        directory, provenance, manifest, analyzer = self.query_fixture()
        manifest['trials'][-1] = copy.deepcopy(manifest['trials'][0])
        write(directory / 'campaign.json', manifest)
        with self.assertRaisesRegex(ValueError, 'duplicated, missing or changed'):
            final.query_campaign(directory, 'none', provenance, analyzer, self.output)

    def test_query_same_path_under_different_block_is_not_replayed_twice(self):
        directory, provenance, manifest, analyzer = self.query_fixture()
        manifest['trials'][-1]['path'] = manifest['trials'][0]['path']
        write(directory / 'campaign.json', manifest)
        with self.assertRaisesRegex(ValueError, 'path or run_id duplicated'):
            final.query_campaign(directory, 'none', provenance, analyzer, self.output)

    def test_query_image_provenance_cannot_be_replaced_by_source_label(self):
        directory, provenance, _, analyzer = self.query_fixture()
        with self.assertRaisesRegex(ValueError, 'source/image/fixed work'):
            final.query_campaign(directory, 'none', {**provenance, 'image_id': 'another-image'}, analyzer, self.output)

    def test_query_incomplete_raw_timing_is_not_inferred_from_task_total(self):
        directory, provenance, _, analyzer = self.query_fixture()
        original = analyzer.analyze_trial

        def forged(path):
            report = original(path)
            report['query_measurements']['status'] = 'NOT_COLLECTED_LEGACY'
            return report

        analyzer.analyze_trial = forged
        with self.assertRaisesRegex(ValueError, 'per-query raw job/statistics replay is incomplete'):
            final.query_campaign(directory, 'none', provenance, analyzer, self.output)

    def test_query_one_unknown_measurement_is_not_hidden_in_complete_task(self):
        directory, provenance, _, analyzer = self.query_fixture()
        original = analyzer.analyze_trial

        def forged(path):
            report = original(path)
            report['query_measurements']['queries'][0]['measurement_status'] = 'UNKNOWN'
            return report

        analyzer.analyze_trial = forged
        with self.assertRaises(ValueError):
            final.query_campaign(directory, 'none', provenance, analyzer, self.output)

    def thread_fixture(self):
        directory = self.root / 'load'
        cg = {'path': '/sys/fs/cgroup/pilot', 'inode': 10, 'device': 28}
        meta = {'boot_id': 'boot', 'label': 'run', 'cgroups': [{**cg, 'availability': 'retained-meta-not-external'}],
            'thread_sampling': {'enabled': True, 'schedstats_runtime_enabled_at_start': True}}
        stats = {key: 0 for key in ('read_errors', 'vanished_processes', 'truncated_process_sets',
            'truncated_cgroup_traversals', 'cgroup_traversal_read_errors', 'thread_read_errors',
            'vanished_threads_during_read', 'truncated_thread_samples', 'thread_identity_changes', 'missed_ticks')}
        stats['process_samples'] = 2
        identity = {'boot_id': 'boot', 'pid': 10, 'process_start_ticks': 20, 'tid': 11, 'thread_start_ticks': 21}
        rows = []
        for index, stamp in enumerate((100, 200)):
            rows.append({'seq': index, 'monotonic_ns': stamp, 'collection_end_ns': stamp + 10,
                'schedstats_runtime_enabled': True, 'cgroups': [{'present': True,
                    'thread_sampling': 'PARTIAL_POLLED_NOT_FULL_LIFECYCLE', 'truncated_cgroup_dirs': False,
                    'truncated_process_set': False, 'traversal_errors': [], 'processes': [{'pid': 10,
                        'start_ticks': 20, 'boot_id': 'boot', 'tid_sampling_issues': [], 'tid_samples': [{
                            'identity': identity, 'collection_start_ns': stamp + 1, 'collection_end_ns': stamp + 2,
                            'wait_counter_status': 'ENABLED', 'lifecycle_status': 'POLLED_INSTANCE_NOT_FULL_LIFECYCLE',
                            'run_ns': index * 20, 'wait_ns': index * 5, 'timeslices': index + 1,
                            'utime': index + 1, 'stime': index + 1}]}]}]})
        write(directory / 'load-meta.json', meta)
        write(directory / 'load-sampler-stats.json', stats)
        (directory / 'load-processes.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        row = {'run_id': 'run', 'boot_id': 'boot', 'execution_window': [50, 250], 'diagnostics': {'cgroup': cg}}
        return directory, row

    def test_thread_wait_uses_external_identity_and_full_inside_endpoints(self):
        directory, row = self.thread_fixture()
        result = final.summarize_threads(directory, row, self.output / 'thread.json')
        self.assertEqual(result['valid_fully_inside_interval_count'], 1)
        self.assertEqual(result['fully_inside_wait_ns_sum_not_exclusive_request_cost'], 5)
        self.assertEqual(result['unknown_interval_count'], 0)
        self.assertEqual(result['external_anchor_status'], 'MATCHED_SAVED_METADATA')
        self.assertNotIn('instances', result)
        self.assertFalse(result['full_thread_lifecycle_claimed'])

    def test_thread_forged_self_metadata_cannot_reanchor_external_phase(self):
        directory, row = self.thread_fixture()
        meta = json.loads((directory / 'load-meta.json').read_text())
        meta['cgroups'][0]['inode'] += 1
        write(directory / 'load-meta.json', meta)
        result = final.summarize_threads(directory, row, self.output / 'thread.json')
        self.assertEqual(result['external_anchor_status'], 'MISMATCH')
        self.assertEqual(result['valid_fully_inside_interval_count'], 0)
        self.assertEqual(result['unknown_interval_count'], 1)

    def test_thread_cross_boundary_intervals_not_clipped_into_execution(self):
        directory, row = self.thread_fixture()
        row['execution_window'] = [150, 250]
        result = final.summarize_threads(directory, row, self.output / 'thread.json')
        self.assertEqual(result['valid_fully_inside_interval_count'], 0)
        self.assertEqual(result['outside_or_boundary_crossing_interval_count'], 1)

    def test_missing_real_campaigns_never_get_passing_status(self):
        summary = final.finalize(self.root, self.output)
        self.assertEqual([row['status'] for row in summary['paired']], ['MISSING', 'MISSING'])
        self.assertEqual(summary['six_gaps']['per_query_latency']['status'], 'INCOMPLETE')
        self.assertEqual(summary['six_gaps']['tuned_static_baseline']['status'], 'INCOMPLETE')
        self.assertEqual(summary['six_gaps']['detailed_diagnostic_overhead']['status'], 'INCOMPLETE')
        self.assertNotIn('all_pass', summary)
        self.assertEqual(summary['GPU'], 'EXCLUDED_BY_USER')

    def test_latest_incomplete_mixed_not_replaced_with_older_green_run(self):
        for name in ('mixed-swe-003', 'mixed-terminal-001', 'mixed-terminal-002'):
            write(self.root / name / 'experiment.json', {})

        def mixed(root, name, tuner, output):
            return {'campaign': name, 'status': 'INCOMPLETE' if name.endswith('002') else 'PASS_WITH_DECLARED_SCOPE'}

        with patch.object(final, 'mixed_section', side_effect=mixed):
            summary = final.finalize(self.root, self.output)
        self.assertEqual(summary['mixed_primary']['terminal'], 'mixed-terminal-002')
        self.assertEqual(len(summary['mixed_all_history']), 3)
        self.assertEqual(summary['six_gaps']['tuned_static_baseline']['status'], 'INCOMPLETE')

    def test_existing_output_never_overwritten(self):
        self.output.mkdir()
        with self.assertRaises(ValueError):
            final.finalize(self.root, self.output)

    def mixed_fixture(self):
        candidates = [{'reserved_cpus': 2, 'compile_workers': 2}, {'reserved_cpus': 3, 'compile_workers': 4}]
        aggregate = {condition: {metric: {'n': 5, 'median': 1} for metric in ('a_seconds', 'makespan_seconds')}
                     for condition in ('G0', 'G1', 'G2', 'G3', 'G4')}
        pairs = {pair: {metric: {'change_percent': {'n': 5, 'median': 10}} for metric in
                       ('a_seconds', 'makespan_seconds', 'B_compile_units_per_second', 'B_total_seconds')}
                 for pair in ('G1_to_G2', 'G2_to_G3', 'G3_to_G4', 'G2_to_G4')}
        return {'status': 'PASS_WITH_DECLARED_SCOPE', 'problems': [], 'resource_replay_performed': True,
            'runtime_and_resources': {'tune-c2-w2': {'status': 'VALIDATED_WITH_DECLARED_SCOPE', 'problems': [],
                'trials': [{'semantic_complete': True, 'native_complete': True}]},
                'evaluation': {'status': 'VALIDATED_WITH_DECLARED_SCOPE', 'problems': [],
                'trials': [{'semantic_complete': True, 'native_complete': True}]}},
            'fixed_work_and_outputs': 'EXACT_EQUALITY', 'candidates': candidates, 'selected': candidates[0],
            'selection_claim': 'BEST_MEDIAN_AMONG_PREDECLARED_CANDIDATES_NOT_GLOBAL_OPTIMUM',
            'evaluation_trial_count': 25, 'evaluation_aggregates': aggregate, 'paired_changes': pairs,
            'priority_validation': 'QUEUED_COMPETITION_OBSERVED_EVERY_G4_REPEAT',
            'G4_queued_competition_exercised_trials': ['g4-' + str(i) for i in range(5)]}

    def test_known_probe_miss_does_not_erase_verified_selection_order_or_timing(self):
        report = self.mixed_fixture()
        report.update(status='INCOMPLETE', problems=['evaluation:runtime_or_resource_replay_incomplete'])
        probe_problem = {'trial': 'trial-12-G1-r2', 'kernel_history_incomplete': [{
            'code': 'KERNEL_HIST_RECURSION_MISSES', 'location': 'kh_sched_exit', 'detail': 'delta=1'}]}
        report['runtime_and_resources']['evaluation'].update(status='INCOMPLETE_OR_INVALID', problems=[probe_problem])
        original = copy.deepcopy(report)
        dimensions = final.mixed_dimensions(report)
        self.assertEqual(report, original)
        self.assertEqual(dimensions['source_aggregate_status'], 'INCOMPLETE')
        self.assertEqual(dimensions['baseline_selection']['status'], 'VERIFIED_AMONG_PREDECLARED_CANDIDATES')
        self.assertEqual(dimensions['frozen_fresh_evaluation']['status'], 'VERIFIED')
        self.assertEqual(dimensions['G4_queue_order']['status'], 'VERIFIED_EACH_REPEAT')
        self.assertEqual(dimensions['paired_timing']['status'], 'RECOMPUTED_FIXED_WORK_N5')
        self.assertEqual(dimensions['resource_health']['status'], 'INCOMPLETE_OR_NOT_ESTABLISHED')
        self.assertIn(probe_problem, [item.get('problem') for item in dimensions['resource_health']['issues']])

    def test_unknown_top_problem_is_not_arbitrarily_ignored(self):
        report = self.mixed_fixture()
        report.update(status='INCOMPLETE', problems=['evaluation:some_new_unclassified_failure'])
        dimensions = final.mixed_dimensions(report)
        self.assertEqual(dimensions['execution_functionality']['status'], 'INCONCLUSIVE')
        self.assertEqual(dimensions['baseline_selection']['status'], 'INCONCLUSIVE')
        self.assertEqual(dimensions['G4_queue_order']['status'], 'INCONCLUSIVE')
        self.assertTrue(dimensions['unclassified_or_functional_blockers'])

    def test_generic_runtime_wrapper_requires_nested_known_resource_cause(self):
        report = self.mixed_fixture()
        report.update(status='INCOMPLETE', problems=['evaluation:runtime_or_resource_replay_incomplete'])
        report['runtime_and_resources']['evaluation']['status'] = 'INCOMPLETE_OR_INVALID'
        dimensions = final.mixed_dimensions(report)
        self.assertEqual(dimensions['paired_timing']['status'], 'INCONCLUSIVE')
        self.assertEqual(dimensions['baseline_selection']['status'], 'INCONCLUSIVE')

    def test_semantic_native_or_output_failure_cannot_be_relabeled_as_probe_loss(self):
        for kind in ('semantic_complete', 'native_complete'):
            with self.subTest(kind=kind):
                report = self.mixed_fixture()
                report['runtime_and_resources']['evaluation']['trials'][0][kind] = False
                dimensions = final.mixed_dimensions(report)
                self.assertEqual(dimensions['execution_functionality']['status'], 'INCONCLUSIVE')
        report = self.mixed_fixture()
        report['fixed_work_and_outputs'] = 'MISMATCH'
        self.assertEqual(final.mixed_dimensions(report)['paired_timing']['status'], 'INCONCLUSIVE')

    def test_frozen_selection_failure_blocks_functional_acceptance(self):
        report = self.mixed_fixture()
        report.update(status='INCOMPLETE', problems=['evaluation_not_bound_to_prior_frozen_selection'])
        self.assertEqual(final.mixed_dimensions(report)['baseline_selection']['status'], 'INCONCLUSIVE')
        self.assertEqual(final.mixed_dimensions(report)['frozen_fresh_evaluation']['status'], 'INCONCLUSIVE')

    def test_unknown_nested_problem_does_not_escape_via_generic_resource_wrapper(self):
        report = self.mixed_fixture()
        report.update(status='INCOMPLETE', problems=['evaluation:runtime_or_resource_replay_incomplete'])
        report['runtime_and_resources']['evaluation'].update(status='INCOMPLETE_OR_INVALID',
            problems=[{'trial': 'trial-1', 'error': 'NEW_UNCLASSIFIED_FAILURE'}])
        self.assertEqual(final.mixed_dimensions(report)['baseline_selection']['status'], 'INCONCLUSIVE')

    def test_negative_speedup_is_valid_timing_not_a_failed_experiment(self):
        report = self.mixed_fixture()
        # Positive change_percent means slower. No condition is required to win.
        dimensions = final.mixed_dimensions(report)
        self.assertEqual(dimensions['paired_timing']['status'], 'RECOMPUTED_FIXED_WORK_N5')
        self.assertFalse(dimensions['paired_timing']['speedup_required'])


if __name__ == '__main__':
    unittest.main()
