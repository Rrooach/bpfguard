"""Pure saved-evidence tests; no Guest, perf, or workload execution."""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import background_io as B


class BackgroundIoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.trial = self.root / 'trial'
        (self.trial / 'load').mkdir(parents=True)
        self.identity = {'path': '/sys/fs/cgroup/search-profile/search-fixture', 'inode': 9, 'device': 28}
        self.profile = {'status': 'COMPLETE', 'cleanup_errors': [], 'run_id': 'search-fixture', 'boot_id': 'boot',
            'root_cgroup': self.identity, 'release_ns': 25, 'end_ns': 75, 'makespan_ns': 50}
        self.meta = {'boot_id': 'boot', 'label': 'search-fixture', 'cgroups': [self.identity], 'clk_tck': 100,
            'block_devices': ['vda', 'sda']}
        self.rows = []
        for index, stamp in enumerate((0, 20, 40, 60, 80, 100)):
            self.rows.append({'seq': index, 'monotonic_ns': stamp, 'collection_end_ns': stamp + 5,
                'diskstats': {'vda': [100 + index, 0, 1000 + 2 * index, 2000 + 3 * index,
                    0, 0, 0, 0, 9 - index, 3000 + 4 * index, 4000 + 5 * index]},
                'stat': {'cpu_total': [0, 0, 0, 0, 0, 0, 0, 50 + 2 * index]}, 'cgroups': [{'present': True}]})
        self.stats = {'samples': len(self.rows), **{name: 0 for name in ('read_errors', 'missed_ticks',
            'truncated_process_sets', 'truncated_cgroup_traversals', 'cgroup_traversal_read_errors')}}
        self.persist()

    def tearDown(self):
        self.temp.cleanup()

    def persist(self):
        for relative, value in (('profile-run.json', self.profile), ('load/load-meta.json', self.meta),
                                ('load/load-sampler-stats.json', self.stats)):
            (self.trial / relative).write_text(json.dumps(value))
        (self.trial / 'load/load-samples.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in self.rows))

    def report(self):
        self.persist()
        return B.summarize_trial(self.trial, 'vda')

    def test_nearest_complete_bracket_and_raw_global_deltas(self):
        result = self.report()
        self.assertEqual(result['status'], 'OBSERVED_GLOBAL_COUNTER_DELTAS_WITHIN_BRACKET')
        self.assertEqual(result['bracket']['first_seq'], 1)
        self.assertEqual(result['bracket']['last_seq'], 4)
        self.assertEqual({name: value['delta'] for name, value in result['diskstats_counters'].items()},
            {'read_completed': 3, 'sectors_read': 6, 'read_ms': 9, 'io_busy_ms': 12, 'weighted_ms': 15})
        self.assertEqual(result['steal_ticks']['delta'], 6)
        self.assertEqual(len(result['sources']), 4)
        self.assertIn('NOT_PHYSICAL_SSD_SERVICE', result['scope'])
        self.assertNotIn('in_flight', result['diskstats_counters'])
        self.assertNotIn('service_latency', result)

    def test_before_sample_must_end_before_release_not_merely_begin(self):
        self.rows[1]['collection_end_ns'] = 26
        result = self.report()
        self.assertEqual(result['bracket']['first_seq'], 0)
        self.assertEqual(result['bracket']['last_seq'], 4)

    def test_missing_end_bracket_retains_unknown_not_zero(self):
        self.profile.update(end_ns=110, makespan_ns=85)
        result = self.report()
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertTrue(all(value['delta'] is None for value in result['diskstats_counters'].values()))
        self.assertIsNone(result['steal_ticks']['delta'])

    def test_new_or_interior_missing_device_never_assumes_zero_baseline(self):
        del self.rows[1]['diskstats']['vda']
        result = self.report()
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertTrue(all(value['status'] == 'UNKNOWN' for value in result['diskstats_counters'].values()))
        self.assertEqual(result['steal_ticks']['status'], 'OBSERVED')

    def test_interior_counter_reset_cannot_be_hidden_by_positive_endpoint_delta(self):
        self.rows[2]['diskstats']['vda'][0] = 100
        self.rows[2]['stat']['cpu_total'][7] = 1
        result = self.report()
        self.assertEqual(result['diskstats_counters']['read_completed']['reason'], 'COUNTER_RESET_WITHIN_BRACKET')
        self.assertEqual(result['steal_ticks']['reason'], 'COUNTER_RESET_WITHIN_BRACKET')
        self.assertEqual(result['diskstats_counters']['read_ms']['status'], 'OBSERVED')

    def test_short_counter_array_and_boolean_counter_are_unknown(self):
        self.rows[2]['stat']['cpu_total'] = [0, 0]
        self.rows[2]['diskstats']['vda'][2] = True
        result = self.report()
        self.assertEqual(result['steal_ticks']['status'], 'UNKNOWN')
        self.assertEqual(result['diskstats_counters']['sectors_read']['status'], 'UNKNOWN')

    def test_gauge_may_decrease_and_is_not_differenced(self):
        for row, gauge in zip(self.rows, (0, 100, 10, 999, 0, 2)):
            row['diskstats']['vda'][8] = gauge
        self.assertEqual(self.report()['status'], 'OBSERVED_GLOBAL_COUNTER_DELTAS_WITHIN_BRACKET')

    def test_boot_run_and_cgroup_identity_mismatches_reject_derivation(self):
        for field in ('boot_id', 'label'):
            original = self.meta[field]
            self.meta[field] = 'other'
            result = self.report()
            self.assertEqual(result['status'], 'INCOMPLETE')
            self.assertIsNone(result['steal_ticks']['delta'])
            self.meta[field] = original
        self.meta['cgroups'] = [dict(self.identity, inode=999)]
        self.assertIsNone(self.report()['steal_ticks']['delta'])

    def test_nonmonotonic_samples_boolean_sequences_and_unfinished_trials_reject(self):
        self.rows[2]['seq'] = True
        self.assertIsNone(self.report()['steal_ticks']['delta'])
        self.rows[2]['seq'] = 2
        self.rows[2]['monotonic_ns'] = 19
        self.assertIsNone(self.report()['steal_ticks']['delta'])
        self.rows[2]['monotonic_ns'] = 40
        self.profile['status'] = 'RUNNING'
        self.assertIsNone(self.report()['steal_ticks']['delta'])

    def test_sampler_health_and_missing_cgroup_do_not_erase_known_global_findings(self):
        self.stats['read_errors'] = 1
        self.rows[2]['cgroups'][0]['present'] = False
        result = self.report()
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['diskstats_counters']['read_completed']['delta'], 3)
        self.assertIn('SAMPLER_HEALTH:read_errors', result['issues'])
        self.assertIn('REGISTERED_CGROUP_NOT_PRESENT_WITHIN_BRACKET', result['issues'])

    def test_explicit_device_and_regular_bounded_inputs_required(self):
        for device in ('', '/dev/vda', '../vda'):
            with self.assertRaises(ValueError):
                B.summarize_trial(self.trial, device)
        path = self.trial / 'load/load-meta.json'
        original = self.root / 'original-meta.json'
        path.rename(original)
        path.symlink_to(original)
        result = B.summarize_trial(self.trial, 'vda')
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertIsNone(result['steal_ticks']['delta'])

    def test_cli_fresh_output_and_raw_evidence_never_overwritten(self):
        output = self.root / 'derived.json'
        command = ['background_io.py', '--trial', str(self.trial), '--device', 'vda', '--output', str(output)]
        with mock.patch('sys.argv', command), contextlib.redirect_stdout(io.StringIO()):
            B.main()
        before = output.read_bytes()
        with mock.patch('sys.argv', command), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            B.main()
        self.assertEqual(output.read_bytes(), before)
        command[-1] = str(self.trial / 'forbidden.json')
        with mock.patch('sys.argv', command), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            B.main()
        self.assertFalse((self.trial / 'forbidden.json').exists())
        dangling = self.root / 'dangling.json'
        target = self.root / 'unrequested.json'
        dangling.symlink_to(target)
        command[-1] = str(dangling)
        with mock.patch('sys.argv', command), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            B.main()
        self.assertFalse(target.exists())

    def matrix_fixture(self, count=1):
        source = self.root / 'matrix-input'
        source.mkdir()
        matrix = {'schema_version': 1, 'status': 'COMPLETE', 'boot_id': 'boot', 'campaigns': []}
        for index in range(count):
            directory = source / ('campaign-%d' % index)
            trial = directory / 'trials' / ('search-fixture-%d' % index)
            shutil.copytree(self.trial, trial)
            run_id = 'search-fixture-%d' % index
            config = dict(cache='warm', workspace_layout='shared', concurrency=8, intervention='none',
                warmup=False, repetition=0, mode='sampler')
            profile = copy.deepcopy(self.profile)
            profile.update(schema_version=1, run_id=run_id, config=config)
            profile['root_cgroup']['path'] = '/sys/fs/cgroup/search-profile/' + run_id
            (trial / 'profile-run.json').write_text(json.dumps(profile))
            meta = copy.deepcopy(self.meta)
            meta.update(label=run_id, cgroups=[profile['root_cgroup']])
            (trial / 'load/load-meta.json').write_text(json.dumps(meta))
            entry = dict(path=str(trial.relative_to(directory)), run_id=run_id, makespan_ns=50,
                **{key: config[key] for key in ('mode', 'concurrency', 'repetition', 'warmup')})
            campaign = {'schema_version': 1, 'status': 'COMPLETE', 'trials': [entry]}
            (directory / 'campaign.json').write_text(json.dumps(campaign))
            condition = {key: value for key, value in config.items() if key not in ('mode', 'repetition')}
            matrix['campaigns'].append({'path': directory.name, 'original_schedule_index': 7 + index,
                'block': 2, 'stage': 'performance', 'condition': dict(condition, block=2)})
        path = source / 'combined.json'
        path.write_text(json.dumps(matrix))
        return path, matrix

    def test_matrix_preserves_indices_conditions_each_unknown_and_known_counter(self):
        path, matrix = self.matrix_fixture(2)
        missing = path.parent / 'campaign-1/trials/search-fixture-1/load/load-samples.jsonl'
        rows = [json.loads(line) for line in missing.read_text().splitlines()]
        del rows[2]['diskstats']['vda']
        missing.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        result = B.summarize_matrix(path, 'vda')
        self.assertEqual(result['case_count'], 2)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual([row['original_index'] for row in result['cases']], [7, 8])
        self.assertEqual(result['cases'][0]['condition'], matrix['campaigns'][0]['condition'])
        self.assertEqual(result['cases'][0]['background']['status'], 'OBSERVED_GLOBAL_COUNTER_DELTAS_WITHIN_BRACKET')
        second = result['cases'][1]['background']
        self.assertEqual(second['diskstats_counters']['read_ms']['status'], 'UNKNOWN')
        self.assertIsNone(second['diskstats_counters']['read_ms']['delta'])
        self.assertEqual(second['steal_ticks']['delta'], 6)
        self.assertNotIn('service_latency', result)

    def test_matrix_duplicate_campaign_path_original_index_or_trial_rejected(self):
        path, matrix = self.matrix_fixture(2)
        original = copy.deepcopy(matrix)
        for kind in ('path', 'index'):
            matrix = copy.deepcopy(original)
            if kind == 'path':
                matrix['campaigns'][1]['path'] = matrix['campaigns'][0]['path']
            else:
                matrix['campaigns'][1]['original_schedule_index'] = matrix['campaigns'][0]['original_schedule_index']
            path.write_text(json.dumps(matrix))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                B.summarize_matrix(path, 'vda')
        path.write_text(json.dumps(original))
        campaign_path = path.parent / 'campaign-0/campaign.json'
        campaign = json.loads(campaign_path.read_text())
        campaign['trials'].append(dict(campaign['trials'][0]))
        campaign_path.write_text(json.dumps(campaign))
        with self.assertRaisesRegex(ValueError, 'reuse a trial'):
            B.summarize_matrix(path, 'vda')

    def test_matrix_paths_are_safe_canonical_relative_non_symlink_directories(self):
        path, matrix = self.matrix_fixture()
        original = copy.deepcopy(matrix)
        for value in ('../campaign-0', '/absolute', '.', 'campaign-0/../campaign-0', 'campaign-0//trials'):
            matrix = copy.deepcopy(original)
            matrix['campaigns'][0]['path'] = value
            path.write_text(json.dumps(matrix))
            with self.subTest(value=value), self.assertRaises(ValueError):
                B.summarize_matrix(path, 'vda')
        alias = path.parent / 'alias'
        alias.symlink_to(path.parent / 'campaign-0', target_is_directory=True)
        matrix['campaigns'][0]['path'] = 'alias'
        path.write_text(json.dumps(matrix))
        with self.assertRaisesRegex(ValueError, 'symlink'):
            B.summarize_matrix(path, 'vda')
        path.write_text(json.dumps(original))
        campaign_path = path.parent / 'campaign-0/campaign.json'
        campaign = json.loads(campaign_path.read_text())
        campaign['trials'][0]['path'] = '../trials'
        campaign_path.write_text(json.dumps(campaign))
        with self.assertRaises(ValueError):
            B.summarize_matrix(path, 'vda')

    def test_matrix_and_campaign_must_be_complete_bounded_schema_one(self):
        path, matrix = self.matrix_fixture()
        original = copy.deepcopy(matrix)
        for field, value in (('status', 'RUNNING'), ('schema_version', True), ('campaigns', []),
                             ('campaigns', matrix['campaigns'] * (B.MAX_CAMPAIGNS + 1))):
            matrix = copy.deepcopy(original)
            matrix[field] = value
            path.write_text(json.dumps(matrix))
            with self.subTest(field=field), self.assertRaises(ValueError):
                B.summarize_matrix(path, 'vda')
        path.write_text(json.dumps(original))
        campaign_path = path.parent / 'campaign-0/campaign.json'
        campaign = json.loads(campaign_path.read_text())
        campaign['status'] = 'FAILED'
        campaign_path.write_text(json.dumps(campaign))
        with self.assertRaisesRegex(ValueError, 'COMPLETE schema 1 campaign'):
            B.summarize_matrix(path, 'vda')

    def test_matrix_campaign_run_timing_boot_and_typed_condition_bind_to_profile(self):
        path, matrix = self.matrix_fixture()
        campaign_path = path.parent / 'campaign-0/campaign.json'
        profile_path = path.parent / 'campaign-0/trials/search-fixture-0/profile-run.json'
        original_campaign = json.loads(campaign_path.read_text())
        original_profile = json.loads(profile_path.read_text())
        for target, field, value in (('entry', 'run_id', 'wrong'), ('entry', 'makespan_ns', 51),
                ('profile', 'boot_id', 'other-boot'), ('config', 'concurrency', True),
                ('config', 'cache', 'guest-cold')):
            campaign, profile = copy.deepcopy(original_campaign), copy.deepcopy(original_profile)
            mapping = campaign['trials'][0] if target == 'entry' else profile['config'] if target == 'config' else profile
            mapping[field] = value
            campaign_path.write_text(json.dumps(campaign))
            profile_path.write_text(json.dumps(profile))
            with self.subTest(target=target, field=field), self.assertRaises(ValueError):
                B.summarize_matrix(path, 'vda')

    def test_matrix_cli_mutually_exclusive_fresh_and_outside_raw_tree(self):
        path, matrix = self.matrix_fixture()
        output = self.root / 'matrix-derived.json'
        command = ['background_io.py', '--matrix', str(path), '--device', 'vda', '--output', str(output)]
        with mock.patch('sys.argv', command), contextlib.redirect_stdout(io.StringIO()):
            B.main()
        self.assertEqual(json.loads(output.read_text())['case_count'], 1)
        command[-1] = str(path.parent / 'forbidden.json')
        with mock.patch('sys.argv', command), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            B.main()
        self.assertFalse((path.parent / 'forbidden.json').exists())
        command += ['--trial', str(self.trial)]
        with mock.patch('sys.argv', command), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            B.main()


if __name__ == '__main__':
    unittest.main()
