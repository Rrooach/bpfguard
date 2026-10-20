#!/usr/bin/env python3
"""Paired benchmark parser contracts; fixtures are not benchmark evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location('benchmark_paired_profiles', Path(__file__).with_name('paired_profiles.py'))
PAIR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PAIR)


def write(path, value, lines=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(row) + '\n' for row in value) if lines else json.dumps(value))


class PairedReplayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.task = 'psf__requests-1142'
        self.cg = {'path': '/sys/fs/cgroup/docker-fixture', 'inode': 200, 'device': 28}
        self.manifest = {'schema_version': 1, 'status': 'COMPLETE', 'benchmark': 'swe',
            'tasks': [self.task], 'modes': ['baseline', 'threads'], 'repetitions': 3,
            'seed': 2751, 'artifacts': {}, 'diagnostic_assets': {},
            'source_sha256': hashlib.sha256(Path(PAIR.__file__).read_bytes()).hexdigest(), 'runs': []}
        for block in range(3):
            for mode in self.manifest['modes']:
                name = 'r{}-{}'.format(block, mode)
                item = {'path': name, 'task': self.task, 'block': block, 'mode': mode,
                        'returncode': 0, 'orchestration_ns': 5000000000}
                self.manifest['runs'].append(item)
                self.make_swe_trial(item)
                write(self.root / (name + '-artifacts.json'), {'diagnostics': {'mode': mode}})
        self.save_manifest()

    def tearDown(self):
        self.temporary.cleanup()

    def save_manifest(self):
        write(self.root / 'campaign.json', self.manifest)

    def observation(self, item=None):
        return self.root / (item or self.manifest['runs'][0])['path'] / 'gold-control/observation'

    def make_swe_trial(self, item):
        directory = self.observation(item)
        label = item['path'] + '-gold-control'
        start, end = 1000000000, 2000000000 + (100000000 if item['mode'] != 'baseline' else 0)
        target = {'process': {'pid': 90, 'start_ticks': 100}, 'cgroup_path': '/docker-fixture',
            'cgroup_inode': self.cg['inode'], 'cgroup_device': self.cg['device'],
            'mount_namespace_inode': 300, 'network_namespace_inode': 301, 'image_id': 'sha256:' + 'a' * 64}
        summary = {'instance_id': self.task, 'status': 'COMPLETED', 'errors': [],
            'gold_control': {self.task: {'resolved': True}},
            'observations': {'gold-control': {'observer_verification_passed': True, 'errors': [],
                'sampler': {'samples': 20, 'process_samples': 20, 'read_errors': 0, 'missed_ticks': 0},
                'target': target, 'post_execution_sample': {'seq': 21, 'monotonic_ns': end + 1,
                                                         'collection_end_ns': end + 2}}}}
        write(directory.parents[1] / 'benchmark-summary.json', summary)
        write(directory.parent / 'official-result.json', {'instance_id': self.task, 'report': summary['gold_control']})
        event = {'schema_version': 1, 'run_id': label, 'task_id': self.task, 'agent_id': 'gold-control',
            'boot_id': 'boot', 'container_id': 'd' * 64, 'target': target}
        write(directory / 'phase-events.jsonl', [{**event, 'phase': 'EXECUTION_START', 'monotonic_ns': start},
            {**event, 'phase': 'EXECUTION_END', 'monotonic_ns': end}], lines=True)
        write(directory / 'target.json', target)
        write(directory / 'verification.json', {'verified': True, 'run_id': label, 'evidence_status': 'INCOMPLETE'})
        write(directory / 'post-execution-sample.json', {'seq': 21, 'monotonic_ns': end + 1, 'collection_end_ns': end + 2})
        write(directory / 'load/load-meta.json', {'schema_version': 1, 'label': label, 'boot_id': 'boot',
            'interval_ms': 100, 'process_interval_ms': 100, 'cgroups': [self.cg],
            'thread_sampling': {'enabled': item['mode'] in ('threads', 'kernel'),
                                'schedstats_runtime_enabled_at_start': True}})
        write(directory / 'load/load-sampler-stats.json', {'samples': 20, 'process_samples': 20,
            'read_errors': 0, 'missed_ticks': 0, 'thread_read_errors': 0,
            'thread_identity_changes': 0, 'truncated_process_sets': 0,
            'truncated_cgroup_traversals': 0, 'cgroup_traversal_read_errors': 0})
        write(directory / 'sampler-ready.json', {'status': 'READY', 'binding_validated': True})
        write(directory / 'diagnostics/diagnostics.json', {'schema_version': 1,
            'status': 'COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE', 'mode': item['mode'], 'label': label,
            'boot_id': 'boot', 'cgroup': self.cg, 'issues': [],
            'start_boundary': {'monotonic_ns': start - 100, 'cgroup_events': {'frozen': '1'},
                               'schedstats': '1' if item['mode'] in ('threads', 'kernel') else None},
            'ready_boundary': {'monotonic_ns': start - 50, 'cgroup_events': {'frozen': '1'},
                               'schedstats': '1' if item['mode'] in ('threads', 'kernel') else None},
            'finish_boundary': {'monotonic_ns': end + 10, 'cgroup_events': {'frozen': '1'},
                                'schedstats': '1' if item['mode'] in ('threads', 'kernel') else None}})

    def require_valid_fixture(self):
        report = PAIR.replay(self.root)
        self.assertEqual(report['status'], 'PASS')
        return report

    def mutate_json(self, path, change):
        value = json.loads(path.read_text())
        change(value)
        write(path, value)

    def test_complete_actual_diagnostic_status_pairs_same_blocks(self):
        report = self.require_valid_fixture()
        self.assertEqual(report['trial_count'], 6)
        threads = next(row for row in report['results'] if row['mode'] == 'threads')
        relative = threads['relative_to_same_observer_sampler_percent']
        self.assertEqual(relative['n'], 3)
        self.assertAlmostEqual(relative['median'], 10)

    def test_manifest_not_complete_is_rejected(self):
        self.require_valid_fixture()
        for status in ('RUNNING', 'FAILED', None):
            with self.subTest(status=status):
                self.manifest['status'] = status
                self.save_manifest()
                with self.assertRaises(ValueError):
                    PAIR.replay(self.root)

    def test_duplicate_paired_blocks_do_not_count_as_three_repetitions(self):
        self.require_valid_fixture()
        for item in self.manifest['runs']:
            if item['block'] == 0:
                item['block'] = 1
        self.save_manifest()
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)

    def test_out_of_range_or_boolean_block_ids_are_rejected(self):
        self.require_valid_fixture()
        original = copy.deepcopy(self.manifest)
        for replacement in (99, True, -1):
            with self.subTest(replacement=replacement):
                self.manifest = copy.deepcopy(original)
                for item in self.manifest['runs']:
                    if item['block'] == 1:
                        item['block'] = replacement
                self.save_manifest()
                with self.assertRaises(ValueError):
                    PAIR.replay(self.root)

    def test_duplicate_paths_are_rejected_even_when_blocks_are_unique(self):
        self.require_valid_fixture()
        self.manifest['runs'][2]['path'] = self.manifest['runs'][0]['path']
        self.save_manifest()
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)

    def test_trial_path_escape_is_rejected_before_opening(self):
        self.require_valid_fixture()
        self.manifest['runs'][0]['path'] = '../foreign'
        self.save_manifest()
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)

    def test_undeclared_extra_mode_is_not_ignored(self):
        self.require_valid_fixture()
        extra = dict(self.manifest['runs'][0], path='extra', mode='unknown')
        self.make_swe_trial(extra)
        self.manifest['runs'].append(extra)
        self.save_manifest()
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)

    def test_duplicate_mode_declarations_are_rejected(self):
        self.require_valid_fixture()
        self.manifest['modes'].append('threads')
        self.save_manifest()
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)

    def test_independent_verification_artifact_not_summary_boolean_is_required(self):
        self.require_valid_fixture()
        write(self.observation() / 'verification.json', {'verified': False})
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)

    def test_official_pass_and_verifier_fields_must_be_actual_booleans(self):
        self.require_valid_fixture()
        summary_path = self.observation().parents[1] / 'benchmark-summary.json'
        self.mutate_json(summary_path, lambda value: value['gold_control'][self.task].update(resolved='false'))
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)

    def test_diagnostic_mode_label_boot_and_domain_are_bound(self):
        self.require_valid_fixture()
        path = self.observation() / 'diagnostics/diagnostics.json'
        original = json.loads(path.read_text())
        for key, value in (('mode', 'threads'), ('label', 'foreign'), ('boot_id', 'foreign'),
                           ('cgroup', {**self.cg, 'inode': 201})):
            with self.subTest(key=key):
                write(path, {**original, key: value})
                with self.assertRaises(ValueError):
                    PAIR.replay(self.root)
        write(path, original)

    def test_diagnostic_health_gaps_preserve_valid_timing_without_claiming_complete_history(self):
        self.require_valid_fixture()
        path = self.observation() / 'diagnostics/diagnostics.json'
        self.mutate_json(path, lambda value: value.update(issues=['collector_timeout']))
        report = PAIR.replay(self.root)
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['measurement_health'], 'INCOMPLETE')
        self.assertEqual(report['runs'][0]['measurement_health']['status'], 'INCOMPLETE')
        self.assertEqual(report['runs'][0]['audit_evidence_status'], 'INCOMPLETE')

    def test_kernel_increment_is_paired_against_same_thread_polling(self):
        self.manifest['modes'].append('kernel')
        self.manifest['diagnostic_assets'] = {'kernel_hist_sha256': 'f' * 64}
        for block in range(3):
            item = {'path': 'r{}-kernel'.format(block), 'task': self.task,
                    'block': block, 'mode': 'kernel', 'returncode': 0}
            self.make_swe_trial(item)
            path = self.observation(item) / 'load/load-meta.json'
            self.mutate_json(path, lambda value: value.update(kernel_hist={
                'object_sha256': 'f' * 64, 'groups': ['sched', 'mem', 'lock', 'blk', 'irq', 'syscall']}))
            self.manifest['runs'].append(item)
        for item in self.manifest['runs']:
            write(self.root / (item['path'] + '-artifacts.json'),
                  {'diagnostics': {**self.manifest['diagnostic_assets'], 'mode': item['mode']}})
        self.save_manifest()
        report = PAIR.replay(self.root)
        self.assertEqual(report['trial_count'], 9)
        incremental = report['paired_kernel_over_threads'][0]['kernel_incremental_percent']
        self.assertEqual(incremental['n'], 3)
        self.assertEqual(incremental['median'], 0)

    def test_perf_sigint_raw_status_requires_real_nul_padded_control_acks(self):
        self.manifest['modes'].append('perf')
        for block in range(3):
            item = {'path': 'r{}-perf'.format(block), 'task': self.task,
                    'block': block, 'mode': 'perf', 'returncode': 0}
            self.make_swe_trial(item)
            directory = self.observation(item) / 'diagnostics'
            self.mutate_json(directory / 'diagnostics.json', lambda value: value.update(
                collector_usage={'returncode': -2, 'usage_status': 'COMPLETE'},
                collector_termination='EXPECTED_PERF_SIGINT_REQUIRES_VALID_REPORT',
                perf_acknowledged_commands=['enable', 'disable'], perf_report_returncode=0,
                perf_scope={'enable_ack_received': True}))
            write(directory / 'perf-control.jsonl', [{'command': 'enable', 'ack': 'ack\n\0', 'monotonic_ns': 999999925},
                {'command': 'disable', 'ack': 'ack\n\0', 'monotonic_ns': 2100000020}], lines=True)
            (directory / 'perf.data').write_bytes(b'PERFILE2-fixture-not-real-perf-data')
            write(self.root / (item['path'] + '-artifacts.json'), {'diagnostics': {'mode': 'perf'}})
            self.manifest['runs'].append(item)
        self.save_manifest()
        report = PAIR.replay(self.root)
        perf = [row for row in report['runs'] if row['mode'] == 'perf']
        self.assertEqual(len(perf), 3)
        self.assertTrue(all(row['diagnostics']['collector_usage']['returncode'] == -2 for row in perf))
        directory = self.observation(self.manifest['runs'][-1]) / 'diagnostics'
        write(directory / 'perf-control.jsonl', [{'command': 'enable', 'ack': 'ack\n\0'},
                                               {'command': 'disable', 'ack': 'not-an-ack\n\0'}], lines=True)
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)


class TerminalReplayTests(unittest.TestCase):
    """Fixture follows saved Harbor + bridge evidence layout, not a fake bool."""
    def setUp(self):
        self.fixture = PairedReplayTests()
        self.fixture.setUp()
        self.root, self.cg = self.fixture.root, self.fixture.cg
        self.manifest = self.fixture.manifest
        self.manifest.update(benchmark='terminal', tasks=['html-js-filter'])
        self.task = 'html-js-filter'
        for item in self.manifest['runs']:
            item['task'] = self.task
            item['command'] = ['python', 'terminal/run.py', '--selection-sha256', 'b' * 64, '--task', self.task]
            path = self.root / item['path']
            label = 'tbench-html-js-filter-' + item['path']
            verifier = {'verified': True, 'run_id': label, 'evidence_status': 'INCOMPLETE'}
            completion = {'schema_version': 1, 'status': 'OBSERVER_VERIFIED', 'run_id': label,
                'task_label': self.task, 'container_id': 'c' * 64,
                'observer': {'offline_verification': verifier, 'overall_evidence_status': 'INCOMPLETE'}}
            end = 2100000000 if item['mode'] == 'threads' else 2000000000
            interval = {'agent_start_ns': 1000000000, 'agent_end_ns': end, 'post_agent_sample_ns': end + 1,
                'run_id': label, 'boot_id': 'boot', 'container_id': 'c' * 64, 'init_pid': 90,
                'cgroup_path': self.cg['path'], 'cgroup_inode': self.cg['inode'],
                'cgroup_device': self.cg['device'], 'sampler_binding_validated': True}
            row = {'task': self.task, 'agent': 'oracle', 'task_reward_passed': True,
                'harbor_rewards': {'reward': 1.0}, 'observer_completed': [completion],
                'observer_error': None, 'sampler_error': None, 'error': None, 'harbor_exception': None,
                'interval': interval, 'harbor_result': '/opt/results/' + item['path'] + '/harbor-trials/fixture/result.json'}
            write(path / 'campaign-summary.json', {'benchmark': 'Terminal-Bench', 'tasks': [row],
                'selected_tasks': [self.task], 'dataset_selection': {'dataset': {
                    'name': 'terminal-bench/terminal-bench', 'version': '4.0.0'},
                    'selection_manifest_sha256': 'b' * 64,
                    'tasks': [{'name': 'terminal-bench/' + self.task, 'source_input_manifest_sha256': 'a' * 64}]}})
            write(path / (self.task + '-summary.json'), row)
            write(path / 'harbor-trials/fixture/result.json', {'task_name': self.task, 'exception_info': None,
                'verifier_result': {'rewards': {'reward': 1.0}}})
            control = path / 'evidence' / label / 'control'
            write(control / 'offline-verification.json', verifier)
            write(control / 'observer-summary.json', completion)
            write(control / 'target.json', {'task_label': self.task, 'container_id': 'c' * 64,
                'cgroup_id': self.cg['inode'], 'cgroup_path': '/docker-fixture', 'init_pid': 90})
            original_load = self.fixture.observation(item) / 'load'
            meta = json.loads((original_load / 'load-meta.json').read_text())
            meta['label'] = label
            meta['cgroups'][0]['available'] = {'cpu.stat': True, 'pressure': True}
            write(path / 'profiles' / self.task / 'load-meta.json', meta)
            write(path / 'profiles' / self.task / 'load-sampler-stats.json',
                  json.loads((original_load / 'load-sampler-stats.json').read_text()))
            detail = json.loads((self.fixture.observation(item) / 'diagnostics/diagnostics.json').read_text())
            detail['label'] = label
            write(path / 'profiles' / (self.task + '-diagnostics') / 'diagnostics.json', detail)
        self.fixture.save_manifest()

    def tearDown(self):
        self.fixture.tearDown()

    def test_terminal_uses_independent_bridge_and_original_harbor_receipts(self):
        report = PAIR.replay(self.root)
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['trial_count'], 6)
        self.assertTrue(all(row['audit_evidence_status'] == 'INCOMPLETE' for row in report['runs']))
        self.assertAlmostEqual(report['results'][1]['relative_to_same_observer_sampler_percent']['median'], 10)

    def test_terminal_false_independent_verifier_is_not_overridden_by_summary(self):
        self.assertEqual(PAIR.replay(self.root)['status'], 'PASS')
        item = self.manifest['runs'][0]
        write(self.root / item['path'] / 'evidence' / ('tbench-html-js-filter-' + item['path']) /
              'control/offline-verification.json', {'verified': False})
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)

    def test_terminal_original_reward_mismatch_is_not_overridden_by_summary(self):
        self.assertEqual(PAIR.replay(self.root)['status'], 'PASS')
        item = self.manifest['runs'][0]
        write(self.root / item['path'] / 'harbor-trials/fixture/result.json', {
            'task_name': self.task, 'exception_info': None, 'verifier_result': {'rewards': {'reward': 0}}})
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)

    def test_terminal_exact_official_qualified_name_is_accepted(self):
        for item in self.manifest['runs']:
            path = self.root / item['path'] / 'harbor-trials/fixture/result.json'
            self.fixture.mutate_json(path, lambda value: value.update(task_name='terminal-bench/' + self.task))
        report = PAIR.replay(self.root)
        self.assertEqual(report['status'], 'PASS')
        self.assertTrue(all(row['terminal_selection_binding']['canonical_task_name'] == 'terminal-bench/' + self.task
                            for row in report['runs']))

    def test_terminal_wrong_prefix_or_suffix_lookalike_is_rejected(self):
        self.assertEqual(PAIR.replay(self.root)['status'], 'PASS')
        path = self.root / self.manifest['runs'][0]['path'] / 'harbor-trials/fixture/result.json'
        original = json.loads(path.read_text())
        for name in ('other-dataset/' + self.task, 'nested/terminal-bench/' + self.task,
                     'terminal-bench/' + self.task + '/extra', 'terminal-bench/not-' + self.task):
            with self.subTest(name=name):
                write(path, {**original, 'task_name': name})
                with self.assertRaises(ValueError):
                    PAIR.replay(self.root)

    def test_terminal_qualified_name_must_match_original_selection_and_command(self):
        self.assertEqual(PAIR.replay(self.root)['status'], 'PASS')
        path = self.root / self.manifest['runs'][0]['path'] / 'campaign-summary.json'
        self.fixture.mutate_json(path, lambda value: value['dataset_selection']['tasks'][0].update(name='other/' + self.task))
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)

    def test_terminal_selection_digest_is_bound_to_invocation(self):
        self.assertEqual(PAIR.replay(self.root)['status'], 'PASS')
        self.manifest['runs'][0]['command'][3] = 'c' * 64
        self.fixture.save_manifest()
        with self.assertRaises(ValueError):
            PAIR.replay(self.root)


class ExecutionBoundaryTests(unittest.TestCase):
    def test_terminal_negative_zero_float_boolean_boundaries_are_rejected(self):
        for start, end in ((20, 10), (10, 10), (1.5, 9), (True, 9), (None, 9)):
            with self.subTest(start=start, end=end), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write(root / 'task-summary.json', {'task': 'task', 'interval': {'agent_start_ns': start, 'agent_end_ns': end}})
                with self.assertRaises(ValueError):
                    PAIR.execution_ns(root, 'terminal', 'task')

    def test_swe_duplicate_wrong_identity_or_nonpositive_boundaries_are_rejected(self):
        event = {'run_id': 'run', 'boot_id': 'boot', 'task_id': 'task', 'agent_id': 'agent',
                 'container_id': 'container', 'target': {'cgroup_inode': 2}}
        valid = [{**event, 'phase': 'EXECUTION_START', 'monotonic_ns': 10},
                 {**event, 'phase': 'EXECUTION_END', 'monotonic_ns': 20}]
        mutations = [lambda rows: rows.append(dict(rows[0])),
                     lambda rows: rows[1].update(boot_id='other'),
                     lambda rows: rows[1].update(run_id='other'),
                     lambda rows: rows[1].update(monotonic_ns=10),
                     lambda rows: rows[1].update(monotonic_ns=True)]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as directory:
                rows = copy.deepcopy(valid)
                mutate(rows)
                root = Path(directory)
                write(root / 'gold-control/observation/phase-events.jsonl', rows, lines=True)
                with self.assertRaises(ValueError):
                    PAIR.execution_ns(root, 'swe', 'task')


if __name__ == '__main__':
    unittest.main()
