import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import access_resume as resume
import access_search


def fixture():
    plans = access_search.schedule(5, 101646)
    original = {'schema_version': 1, 'status': 'FAILED', 'schedule': plans, 'campaigns': [],
        'jobs': 8, 'passes': 1, 'seed': 101646, 'boot_id': 'boot', 'file_access_backend': 'kprobe-tracefs',
        'collector_budget': {'ring_bytes': 256 * 1024 ** 2}, 'binaries': {'frozen': 'same'},
        'queries': ['needle'], 'cpus': [0, 1, 2, 3]}
    original['campaigns'] = [{'path': '%03d-r%d' % (index, plan['block']), 'block': plan['block'],
        'stage': 'performance', 'condition': resume.condition(plan, original)}
        for index, plan in enumerate(plans[:54])]
    pause = {'status': 'PAUSED_AT_USER_REQUEST', 'vm_boot_id': 'boot', 'completed_trials': 54,
        'last_completed_trial_index': 53, 'in_progress_trial_index': 54, 'in_progress_block': 1}
    return original, pause


class ScheduleContracts(unittest.TestCase):
    def test_whole_split_block_repeated_not_just_failed_trial(self):
        original, pause = fixture()
        before = copy.deepcopy(original)
        start, remaining = resume.validate_selection(original, pause, 54, 1, original['schedule'])
        self.assertEqual(start, 32)
        self.assertEqual(remaining, original['schedule'][32:])
        self.assertEqual(len(remaining), 128)
        self.assertEqual([r['block'] for r in remaining].count(1), 32)
        remaining[0]['cache'] = 'changed'
        self.assertEqual(original, before)

    def test_completed_original_can_also_repeat_pause_split_block(self):
        original, pause = fixture()
        original['campaigns'] = [{'path': '%03d-r%d' % (i, p['block']), 'block': p['block'],
            'stage': 'performance', 'condition': resume.condition(p, original)}
            for i, p in enumerate(original['schedule'])]
        original['status'] = 'COMPLETE'
        self.assertEqual(resume.validate_selection(original, pause, 160, 1, original['schedule'])[0], 32)

    def test_changed_schedule_prefix_and_conditions_rejected(self):
        for operation in ('count', 'hole', 'condition', 'block_bool', 'live', 'jobs', 'passes', 'schedule'):
            original, pause = fixture()
            frozen = copy.deepcopy(original['schedule'])
            expected = 54
            if operation == 'count': expected = 53
            elif operation == 'hole': original['campaigns'][1]['path'] = '002-r0'
            elif operation == 'condition': original['campaigns'][1]['condition']['file_access_mode'] = 'changed'
            elif operation == 'block_bool': original['campaigns'][1]['block'] = False
            elif operation == 'live': original['status'] = 'RUNNING'
            elif operation == 'jobs': original['jobs'] = 4
            elif operation == 'passes': original['passes'] = 2
            else: original['schedule'][33]['cache'] = 'changed'
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                resume.validate_selection(original, pause, expected, 1, frozen)

    def test_pause_must_bind_original_boot_and_split_position(self):
        for field, value in (('status', 'RUNNING'), ('vm_boot_id', 'other'), ('completed_trials', True),
                             ('completed_trials', 160), ('last_completed_trial_index', 52),
                             ('in_progress_trial_index', 55), ('in_progress_block', 2)):
            original, pause = fixture()
            pause[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                resume.validate_selection(original, pause, 54, 1, original['schedule'])

    def test_manifest_never_changes_original_or_hides_raw_failure(self):
        original, pause = fixture()
        original.update(error='pause exceeded collector deadline', source_integrity='old', cleanup_errors=['old'])
        before = copy.deepcopy(original)
        provenance = {'adapter_sha256': 'new', 'original_raw_status': original['status']}
        value = resume.make_manifest(original, original['schedule'][32:], provenance)
        self.assertEqual(value['status'], 'RUNNING')
        self.assertEqual(value['binaries'], original['binaries'])
        self.assertEqual(value['campaigns'], [])
        self.assertEqual(value['continuation']['original_raw_status'], 'FAILED')
        self.assertNotIn('source_integrity', value)
        self.assertNotIn('cleanup_errors', value)
        self.assertEqual(original, before)


class EvidenceContracts(unittest.TestCase):
    def test_preserved_outputs_are_independently_read_and_rehashed(self):
        original, _ = fixture()
        plan = original['schedule'][0]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            trial = root / 'trials' / 'one'
            trial.mkdir(parents=True)
            raw, results, tasks = b'b\0a\0', [], []
            digest = hashlib.sha256(b'a\0b\0').hexdigest()
            for index in range(8):
                task = 'task-%04d' % index
                (trial / (task + '.stdout')).write_bytes(raw)
                tasks.append({'task_id': task})
                results.append({'task_id': task, 'query_index': 0, 'exit_code': 0,
                    'output_sha256': digest, 'output_bytes': len(raw)})
            profile = {'status': 'COMPLETE', 'cleanup_errors': [], 'boot_id': 'boot', 'run_id': 'run',
                'release_ns': 10, 'end_ns': 30, 'makespan_ns': 20, 'tasks': tasks, 'results': results,
                'config': dict(resume.condition(plan, original), jobs=8, passes=1, cpus=[0, 1, 2, 3])}
            (trial / 'profile-run.json').write_text(json.dumps(profile))
            (trial / 'report.json').write_text(json.dumps({'analysis': {'source_sha256': 'analyzer'}}))
            campaign = {'status': 'COMPLETE', 'jobs': 8, 'passes': 1, 'queries': ['needle'],
                'binaries': original['binaries'], 'trials': [{'path': 'trials/one', 'run_id': 'run', 'makespan_ns': 20}]}
            (root / 'campaign.json').write_text(json.dumps(campaign))
            capture = {'profile_run_sha256': resume.sha(trial / 'profile-run.json'), 'profile_run_id': 'run',
                'boot_id': 'boot', 'mode': plan['file_access_mode']}
            (root / 'capture.json').write_text(json.dumps(capture))
            self.assertEqual(resume.verify_preserved_campaign(root, original, plan, {}), 'analyzer')
            (trial / 'task-0003.stdout').write_bytes(b'tampered\0')
            with self.assertRaisesRegex(ValueError, 'raw search output'):
                resume.verify_preserved_campaign(root, original, plan, {})

    def test_artifact_paths_cannot_escape(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for path in ('../elsewhere', '/absolute', ''):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    resume.child(root, path)


class ExplicitLoopContracts(unittest.TestCase):
    def test_loop_preserves_logical_indices_and_original_sources_without_monkeypatch(self):
        original, pause = fixture()
        original['boot_id'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        pause['vm_boot_id'] = original['boot_id']
        original['measurement_coordinator_sampler_collector_cpus'] = [4, 5]
        original['binaries'].update(file_access_sha256='binary', file_access_object_sha256='object')
        original['collector_budget'].update(max_bytes=2147483648, max_seconds=1200)
        original['source'] = {'commit': 'fixed'}
        raw_runner = access_search.runner
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            old, prepared, runtime = root / 'main-001', root / 'prepared', root / 'runtime'
            for path in (old, prepared, runtime):
                path.mkdir()
            for entry in original['campaigns'][:32]:
                (old / entry['path']).mkdir()
            (runtime / 'analyze.py').write_text('frozen analyzer')
            inventory = {'files': ['file'], 'sha256': 'content', 'permission_scope_sha256': 'permissions'}
            raw_runner.dump(prepared / 'corpus-inventory.json', inventory)
            original['source_inventory_sha256'] = resume.sha(prepared / 'corpus-inventory.json')
            corpus = root / 'corpus'
            roots = [root / ('agent-%d' % i) for i in range(8)]
            prep = {'boot_id': original['boot_id'], 'source': original['source'], 'corpus': str(corpus),
                'inventory_sha256': original['source_inventory_sha256'], 'independent_roots': list(map(str, roots))}
            raw_runner.dump(prepared / 'preparation.json', prep)
            raw_runner.dump(old / 'matrix.json', original)
            raw_runner.dump(root / 'pause.json', pause)
            raw_runner.dump(root / 'source.json', original['source'])
            raw_runner.dump(root / 'queries.json', original['queries'])
            args = SimpleNamespace(original_matrix=old / 'matrix.json', pause_receipt=root / 'pause.json',
                runtime=runtime, expected_completed=54, restart_block=1, prepared=prepared, corpus=corpus,
                source_manifest=root / 'source.json', queries=root / 'queries.json', sampler=root / 'sampler',
                file_access=root / 'collector', file_access_object=root / 'object', output=root / 'resume-001',
                io_prime_devices=['/dev/vda', '/dev/vdb', '/dev/sda'])
            analyzer_sha = resume.sha(runtime / 'analyze.py')
            common = SimpleNamespace(cpus={0, 1, 2, 3}, repository_version='fixed', cgroup_layout='shared-leaf')
            calls = []
            def trial(fresh, actual_common, target, condition, inventory, queries, base, boot):
                calls.append((target.name, copy.deepcopy(condition), fresh.collector_ring_bytes))
                return {'results': [{'query_index': 0, 'exit_code': 0, 'output_sha256': 'same', 'output_bytes': 1}],
                    'makespan_ns': 1000000, 'file_access_health': 'COMPLETE_FOR_SELECTED_HOOKS'}
            def verify(directory, binding, plan, expected, devices):
                expected[0] = 0, 'same', 1
                self.assertEqual(devices, args.io_prime_devices)
                return analyzer_sha
            fake_runner = SimpleNamespace(dump=raw_runner.dump, GREP_OPTIONS=raw_runner.GREP_OPTIONS,
                ensure_cgroup_parent=mock.Mock(), cgroup_identity=lambda unused: {'inode': 1},
                cleanup_owned_cgroup=mock.Mock(), corpus_inventory=mock.Mock(return_value=inventory))
            fake = SimpleNamespace(schedule=access_search.schedule, runner=fake_runner,
                cache_probe=SimpleNamespace(_ensure_guest=mock.Mock(), pin_roots=mock.Mock(return_value={'status': 'PINNED'})),
                large_search=SimpleNamespace(arguments=lambda *unused: common, fingerprint=lambda value: value['sha256']),
                participating_roots=access_search.participating_roots, trial_with_collector=trial,
                update_owned_json=access_search.update_owned_json)
            with mock.patch.object(resume, 'load_runtime', return_value=fake), \
                    mock.patch.object(resume, 'validate_runtime', return_value={'frozen': 'same'}), \
                    mock.patch.object(resume, 'readonly_roots'), \
                    mock.patch.object(resume, 'verify_preserved_campaign', side_effect=verify) as verified, \
                    mock.patch.object(resume.os, 'geteuid', return_value=0), \
                    mock.patch.object(resume.os, 'sched_getaffinity', return_value=set(range(6))), \
                    mock.patch.object(resume.os, 'sched_setaffinity') as affinity, \
                    mock.patch.object(resume.os, 'sync') as sync, \
                    mock.patch('builtins.print'), mock.patch.object(resume.gc, 'collect'):
                result = resume.execute(args)
            self.assertEqual(result['status'], 'COMPLETE')
            self.assertEqual(len(calls), 128)
            self.assertEqual((calls[0][0], calls[-1][0]), ('032-r1', '159-r4'))
            self.assertEqual(verified.call_count, 32)
            self.assertEqual(sync.call_count, 128)
            affinity.assert_called_once_with(0, {4, 5})
            self.assertEqual(fake_runner.corpus_inventory.call_count, 9)
            self.assertEqual(read(old / 'matrix.json'), original)
            self.assertEqual([entry['original_schedule_index'] for entry in result['campaigns']], list(range(32, 160)))
            self.assertEqual(result['continuation']['adapter_sha256'], resume.sha(resume.__file__))
            self.assertEqual(result['source_integrity'], 'PARTICIPATING_ROOTS_POST_CAMPAIGN_REHASHED_IDENTICAL')


def read(path):
    return json.loads(path.read_bytes())


if __name__ == '__main__':
    unittest.main()
