import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import access_search as access


class ScheduleTests(unittest.TestCase):
    def test_ring_budget_requires_bounded_power_of_two(self):
        for value in (16, 32, 64, 128, 256, 512):
            self.assertTrue(access.valid_ring_bytes(value * 1024 ** 2))
        for value in (0, 8 * 1024 ** 2, 100 * 1024 ** 2, 1024 * 1024 ** 2, True):
            self.assertFalse(access.valid_ring_bytes(value))

    def test_only_participating_roots_hashed_and_deduplicated(self):
        corpus = Path('/corpus')
        independent = [Path('/agent-%d' % i) for i in range(8)]
        self.assertEqual(access.participating_roots(corpus, independent, ['shared']), [corpus])
        self.assertEqual(access.participating_roots(corpus, independent, ['independent']), independent)
        self.assertEqual(access.participating_roots(corpus, independent, ['shared', 'independent']),
                         [corpus] + independent)
        self.assertEqual(access.participating_roots(corpus, independent + independent, ['independent']), independent)

    def test_five_complete_paired_blocks_no_old_concurrency_one(self):
        rows = access.schedule(5, 101646)
        self.assertEqual(len(rows), 160)
        self.assertEqual(rows, access.schedule(5, 101646))
        for block in range(5):
            selected = [row for row in rows if row['block'] == block]
            self.assertEqual(len(selected), 32)
            self.assertEqual(len({(r['cache'], r['workspace_layout'], r['concurrency'], r['file_access_mode'])
                                  for r in selected}), 32)
            self.assertEqual({r['concurrency'] for r in selected}, {2, 4, 6, 8})
            self.assertEqual({r['file_access_mode'] for r in selected}, {'sampler', 'access'})
        self.assertNotEqual(access.schedule(1, 1), access.schedule(1, 2))

    def test_two_round_calibration(self):
        rows = access.schedule(1, 1, (2,), ('warm',), ('shared',))
        self.assertEqual(len(rows), 2)
        self.assertEqual({r['file_access_mode'] for r in rows}, {'sampler', 'access'})

    def test_unique_supported_values(self):
        self.assertEqual(access.bounded_list('2,4,6,8', ('2', '4', '6', '8'), 'n'), ['2', '4', '6', '8'])
        for value in ('2,2', '', '1', '2,3', '2, 4'):
            with self.assertRaises(ValueError):
                access.bounded_list(value, ('2', '4', '6', '8'), 'n')


class ReadyTests(unittest.TestCase):
    def setUp(self):
        self.group = {'path': '/sys/fs/cgroup/test', 'inode': 8, 'device': 28}
        self.ready = {'type': 'READY', 'run_id': 'run', 'boot_id': 'boot',
            'bpf_sha256': 'a' * 64, 'backend': 'fentry', 'ring_bytes': 64 * 1024 ** 2,
            'start_monotonic_ns': 123, 'domains': [self.group]}

    def test_exact_ready_bound(self):
        access.validate_ready(self.ready, 'run', 'boot', 'a' * 64, self.group)

    def test_ready_rejects_each_identity_mismatch(self):
        for field, value in (('run_id', 'wrong'), ('boot_id', 'wrong'), ('bpf_sha256', 'b' * 64),
                             ('backend', 'kprobe-tracefs'), ('ring_bytes', 256 * 1024 ** 2),
                             ('start_monotonic_ns', True), ('domains', [])):
            row = dict(self.ready)
            row[field] = value
            with self.assertRaises(RuntimeError):
                access.validate_ready(row, 'run', 'boot', 'a' * 64, self.group)
        for field in ('path', 'inode', 'device'):
            row = dict(self.ready, domains=[dict(self.group)])
            row['domains'][0][field] = 'wrong'
            with self.assertRaises(RuntimeError):
                access.validate_ready(row, 'run', 'boot', 'a' * 64, self.group)

    def test_bounded_single_json_line(self):
        code = 'import sys; sys.stdout.write(%r); sys.stdout.flush()' % (json.dumps(self.ready) + '\n')
        process = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE)
        try:
            self.assertEqual(access.read_ready(process, 3), self.ready)
            self.assertEqual(process.wait(timeout=3), 0)
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
                process.wait()

    def test_premature_exit_fail_closed(self):
        process = subprocess.Popen([sys.executable, '-c', 'pass'], stdout=subprocess.PIPE)
        try:
            with self.assertRaises(RuntimeError):
                access.read_ready(process, 3)
        finally:
            process.wait(timeout=3)
            process.stdout.close()


class LifecycleTests(unittest.TestCase):
    def test_owned_manifest_updates_are_atomic_and_leave_no_temporary(self):
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / 'matrix.json'
            access.update_owned_json(target, {'status': 'RUNNING'})
            access.update_owned_json(target, {'status': 'COMPLETE'})
            self.assertEqual(json.loads(target.read_text()), {'status': 'COMPLETE'})
            self.assertEqual(list(Path(name).iterdir()), [target])

    def test_sampler_wraps_unchanged_trial_then_removes_only_created_empty_parent(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            base, target = root / 'base', root / 'trial'
            base.mkdir()
            target.mkdir()
            (target / 'trials').mkdir()
            common = SimpleNamespace()
            profile = {'run_id': 'search-run', 'release_ns': 30, 'end_ns': 90, 'makespan_ns': 60,
                       'root_cgroup': {'path': '/inner', 'inode': 6, 'device': 28}}
            def fake_trial(*unused):
                trial = target / 'trials' / 'inner'
                trial.mkdir()
                access.runner.dump(trial / 'profile-run.json', profile)
                return {'path': 'trials/inner', 'results': []}
            def cleanup(path, identity, errors, kill_remaining):
                self.assertFalse(kill_remaining)
                self.assertEqual(access.runner.cgroup_identity(path), identity)
                path.rmdir()
            with mock.patch.object(access.runner, 'ensure_cgroup_parent', side_effect=lambda p: p.mkdir()), \
                    mock.patch.object(access.runner, 'run_trial', side_effect=fake_trial), \
                    mock.patch.object(access.runner, 'cleanup_owned_cgroup', side_effect=cleanup):
                row = access.trial_with_collector(SimpleNamespace(file_access_backend='fentry', collector_ring_bytes=64 * 1024 ** 2), common, target,
                    {'file_access_mode': 'sampler'}, {}, [], base, 'boot')
            self.assertEqual(row['file_access_health'], 'NOT_ENABLED')
            capture = json.loads((target / 'capture.json').read_text())
            self.assertEqual(capture['profile_run_id'], 'search-run')
            self.assertEqual(capture['profile_run_sha256'], access.runner.sha_file(target / 'trials/inner/profile-run.json'))
            self.assertEqual(list(base.iterdir()), [])

    def test_trial_failure_keeps_capture_and_still_cleans_own_parent(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            base, target = root / 'base', root / 'trial'
            base.mkdir()
            target.mkdir()
            def cleanup(path, identity, errors, kill_remaining):
                path.rmdir()
            with mock.patch.object(access.runner, 'ensure_cgroup_parent', side_effect=lambda p: p.mkdir()), \
                    mock.patch.object(access.runner, 'run_trial', side_effect=RuntimeError('failed trial')), \
                    mock.patch.object(access.runner, 'cleanup_owned_cgroup', side_effect=cleanup):
                with self.assertRaisesRegex(RuntimeError, 'failed trial'):
                    access.trial_with_collector(SimpleNamespace(file_access_backend='fentry', collector_ring_bytes=64 * 1024 ** 2), SimpleNamespace(), target,
                        {'file_access_mode': 'sampler'}, {}, [], base, 'boot')
            self.assertEqual(json.loads((target / 'capture.json').read_text())['status'], 'NOT_ENABLED')
            self.assertEqual(list(base.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
