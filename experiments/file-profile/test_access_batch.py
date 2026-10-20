import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('access_batch_tests_subject', HERE / 'access_batch.py')
BATCH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BATCH
SPEC.loader.exec_module(BATCH)
FIXTURE_SPEC = importlib.util.spec_from_file_location('access_batch_fixtures', HERE / 'test_access_analyze.py')
FIXTURES = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(FIXTURES)


class BatchTests(unittest.TestCase):
    def inputs(self, root, post_started=400):
        case = root / 'campaign' / '001-r0'
        case.mkdir(parents=True)
        fixture = FIXTURES.AccessAnalyzeTests()
        meta, final, capture = fixture.bundle(case, label='001-r0')
        (case / 'collector').rename(case / 'file-access')
        condition = {'file_access_mode': 'access', 'file_access_backend': 'fentry',
            'collector_ring_bytes': meta['ring_bytes'], 'cache': 'warm',
            'workspace_layout': 'shared', 'concurrency': 2, 'warmup': False,
            'intervention': 'none', 'mode': 'sampler', 'repetition': 0}
        profile = json.loads((case / 'profile-run.json').read_text())
        profile['config'] = condition
        profile_raw = json.dumps(profile).encode()
        (case / 'profile-run.json').write_bytes(profile_raw)
        capture.update(profile_path='profile-run.json', mode='access',
            profile_run_sha256=hashlib.sha256(profile_raw).hexdigest(),
            collector_ring_bytes=meta['ring_bytes'], capture_budget={'ring_bytes': meta['ring_bytes'],
                'max_bytes': meta['max_bytes'], 'max_seconds': 1200})
        (case / 'capture.json').write_text(json.dumps(capture))
        matrix = {'schema_version': 1, 'status': 'COMPLETE', 'boot_id': 'boot',
            'file_access_backend': 'fentry', 'collector_budget': capture['capture_budget'],
            'campaigns': [{'path': '001-r0', 'block': 0, 'condition': condition}],
            'schedule': [{'file_access_mode': 'access', 'cache': 'warm', 'workspace_layout': 'shared',
                'concurrency': 2, 'warmup': False, 'intervention': 'none', 'block': 0}]}
        matrix_path = case.parent / 'matrix.json'
        matrix_path.write_text(json.dumps(matrix))
        inventory = fixture.inventory()
        inventory['objects'][0]['scope_kind'] = 'SOURCE_CORPUS'
        inventory['post_verification'] = {'status': 'IDENTICAL_READONLY_METADATA_WITHIN_DECLARED_SCOPE',
            'started_ns': post_started, 'ended_ns': post_started + 10}
        inventory_path = root / 'verified-final.json'
        inventory_path.write_text(json.dumps(inventory))
        index = root / 'inventory.sqlite'
        receipt = BATCH.ANALYZER.build_inventory_index([inventory_path], index, 'boot')
        return matrix_path, index, receipt['artifact']['sha256']

    def plan(self, root, **kwargs):
        args = self.inputs(root, **kwargs)
        return BATCH.plan_batch(*args)

    def test_plan_binds_matrix_capture_profile_and_post_final_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan = self.plan(Path(temporary))
            self.assertEqual(len(plan['cases']), 1)
            self.assertEqual(plan['full_campaign_last_end_ns'], 200)
            self.assertEqual(plan['available_full_detail_cases'], 1)
            self.assertEqual(plan['cases'][0]['case_id'], '001-r0')

    def test_same_boot_preflight_receipt_cannot_replace_formal_post(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.inputs(Path(temporary), post_started=150)
            with self.assertRaisesRegex(ValueError, 'AFTER'):
                BATCH.plan_batch(*args)

    def test_required_inventory_external_digest_cannot_be_guessed(self):
        with tempfile.TemporaryDirectory() as temporary:
            matrix, index, _ = self.inputs(Path(temporary))
            with self.assertRaises(ValueError):
                BATCH.plan_batch(matrix, index, '0' * 64)

    def test_budget_and_schedule_cannot_silently_differ(self):
        for kind in ('ring', 'schedule', 'rawconfig'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                matrix_path, index, digest = self.inputs(Path(temporary))
                matrix = json.loads(matrix_path.read_text())
                if kind == 'ring':
                    matrix['collector_budget']['ring_bytes'] *= 2
                elif kind == 'schedule':
                    matrix['schedule'][0]['concurrency'] = 8
                else:
                    matrix['campaigns'][0]['condition']['collector_ring_bytes'] *= 2
                matrix_path.write_text(json.dumps(matrix))
                with self.assertRaises(ValueError):
                    BATCH.plan_batch(matrix_path, index, digest)

    def test_limit_is_explicit_subset_not_a_full_80_case_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.inputs(Path(temporary))
            plan = BATCH.plan_batch(*args, limit=1)
            self.assertEqual(plan['selected_prefix_limit'], 1)
            for limit in (0, 2, True):
                with self.subTest(limit=limit), self.assertRaises(ValueError):
                    BATCH.plan_batch(*args, limit=limit)

    def test_one_small_case_end_to_end_and_verified_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            output = root / 'analysis'
            first = BATCH.run_batch(plan, output, workers=1)
            self.assertEqual(first['status'], 'COMPLETE_FOR_SELECTED_CASES')
            first_output = first['results']['001-r0']['output']
            self.assertEqual(first['results']['001-r0']['observed_metrics']['source_read_returned_bytes'], 10)
            again = BATCH.run_batch(plan, output, workers=1, resume=True)
            self.assertEqual(again['resume_verified_cases'], ['001-r0'])
            self.assertEqual(again['results']['001-r0']['output'], first_output)
            self.assertEqual(len(list(output.glob('attempt-*.json'))), 2)

    def test_modified_saved_artifact_is_not_blindly_skipped_or_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            output = root / 'analysis'
            first = BATCH.run_batch(plan, output, workers=1)
            old = Path(first['results']['001-r0']['output']) / 'read-samples.csv'
            old.write_text('bad retained evidence\n')
            again = BATCH.run_batch(plan, output, workers=1, resume=True)
            self.assertEqual(again['resume_verified_cases'], [])
            self.assertEqual(old.read_text(), 'bad retained evidence\n')
            self.assertIn('/retries/', again['results']['001-r0']['output'])
            events = [json.loads(line) for line in (output / 'progress.jsonl').read_text().splitlines()]
            self.assertIn('RESUME_REJECTED', [row['event'] for row in events])

    def test_failure_receipt_and_partial_output_survive_fresh_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            output = root / 'analysis'
            def fail(case, target, inventory, digest):
                target.mkdir(parents=True)
                (target / 'partial.txt').write_text('retained')
                raise RuntimeError('fixture failure')
            first = BATCH.run_batch(plan, output, workers=1, worker=fail)
            self.assertEqual(first['status'], 'INCOMPLETE')
            self.assertIn('001-r0', first['failures'])
            again = BATCH.run_batch(plan, output, workers=1, resume=True)
            self.assertEqual(again['status'], 'COMPLETE_FOR_SELECTED_CASES')
            self.assertEqual((output / '001-r0' / 'partial.txt').read_text(), 'retained')

    def test_existing_output_and_changed_plan_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            output = root / 'analysis'
            BATCH.run_batch(plan, output, workers=1)
            with self.assertRaises(FileExistsError):
                BATCH.run_batch(plan, output, workers=1)
            changed = copy.deepcopy(plan)
            changed['matrix']['sha256'] = '0' * 64
            with self.assertRaises(ValueError):
                BATCH.run_batch(changed, output, workers=1, resume=True)

    def test_invalid_workers_and_journal_corruption_fail_explicitly(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            for count in (0, 9, True):
                with self.subTest(count=count), self.assertRaises(ValueError):
                    BATCH.run_batch(plan, root / 'bad', workers=count)
            journal = root / 'broken.jsonl'
            journal.write_text('{')
            with self.assertRaisesRegex(ValueError, 'preserve'):
                BATCH.journal_completed(journal)

    def test_real_process_pool_handles_tiny_fixture_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            result = BATCH.run_batch(plan, root / 'analysis', workers=2)
            self.assertEqual(result['status'], 'COMPLETE_FOR_SELECTED_CASES')

    def test_resume_cannot_shrink_the_required_artifact_verification_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            output = root / 'analysis'
            result = BATCH.run_batch(plan, output, workers=1)
            receipt = copy.deepcopy(result['results']['001-r0'])
            receipt['artifacts'] = {}
            valid, reason = BATCH.verify_completed(plan['cases'][0], receipt,
                plan['inventory_database']['sha256'], output, plan['analyzer_sha256'])
            self.assertFalse(valid)
            self.assertIn('ARTIFACT_SET', reason)

    def test_verified_incomplete_history_stays_incomplete_on_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.inputs(root)
            case = root / 'campaign' / '001-r0'
            final_path = case / 'file-access' / 'final.json'
            final = json.loads(final_path.read_text())
            final['health']['ring_drops'] = 1
            final['cpus'][0].update(attempted=2, ring_drops=1)
            final['observation_health'] = 'INCOMPLETE'
            raw = json.dumps(final).encode()
            final_path.write_bytes(raw)
            capture_path = case / 'capture.json'
            capture = json.loads(capture_path.read_text())
            capture['final_sha256'] = hashlib.sha256(raw).hexdigest()
            capture_path.write_text(json.dumps(capture))
            plan = BATCH.plan_batch(*args)
            output = root / 'analysis'
            first = BATCH.run_batch(plan, output, workers=1)
            self.assertEqual(first['status'], 'INCOMPLETE')
            again = BATCH.run_batch(plan, output, workers=1, resume=True)
            self.assertEqual(again['status'], 'INCOMPLETE')
            self.assertEqual(again['resume_verified_cases'], ['001-r0'])

    def archive_plan(self, root):
        args = self.inputs(root)
        scratch = root / 'scratch'
        scratch.mkdir(mode=0o700)
        settings = {'codec': 'gzip', 'scratch_root': str(scratch),
            'scratch_per_case_bytes': 8 * 1024 ** 2, 'min_output_free_bytes': 0}
        return BATCH.plan_batch(*args, archive_settings=settings)

    def test_archive_is_opt_in_and_plain_schema_one_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.plan(root)
            result = BATCH.run_batch(plan, root / 'analysis', workers=1)
            self.assertEqual(plan['schema_version'], 1)
            self.assertEqual(result['schema_version'], 1)
            self.assertNotIn('artifact_storage', plan)
            row = result['results']['001-r0']
            self.assertNotIn('artifact_storage_schema', row)
            for record in row['artifacts'].values():
                self.assertEqual(set(record), {'path', 'bytes', 'sha256'})

    def test_archive_case_restores_exact_logical_bytes_and_removes_only_own_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.archive_plan(root)
            scratch = Path(plan['artifact_storage']['scratch_root'])
            sentinel = scratch / 'unrelated-user-file'
            sentinel.write_text('do not remove')
            old_env = {name: os.environ.get(name) for name in ('TMPDIR', 'SQLITE_TMPDIR')}
            old_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
            result = BATCH.run_batch(plan, root / 'analysis', workers=1)
            self.assertEqual(result['schema_version'], 2)
            self.assertEqual(result['status'], 'COMPLETE_FOR_SELECTED_CASES')
            row = result['results']['001-r0']
            self.assertEqual(row['artifact_storage_schema'], 2)
            output = Path(row['output'])
            for name in BATCH.ARTIFACTS.ARTIFACT_NAMES:
                proof = BATCH.ARTIFACTS.verify_artifact(row['artifacts'][name], output, name)
                self.assertEqual(proof['bytes'], row['artifacts'][name]['bytes'])
                self.assertEqual(proof['sha256'], row['artifacts'][name]['sha256'])
                if name in BATCH.ARTIFACTS.ARCHIVED_NAMES:
                    self.assertFalse((output / name).exists())
                    self.assertNotIn('path', row['artifacts'][name])
                    restored = root / ('restored-' + name)
                    BATCH.ARTIFACTS.restore_artifact(row['artifacts'][name], output, name, restored)
                    self.assertEqual(BATCH.artifact_digest(restored)['sha256'], row['artifacts'][name]['sha256'])
                else:
                    self.assertTrue((output / name).is_file())
            self.assertFalse(Path(row['scratch']['path']).exists())
            self.assertEqual(list(scratch.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_text(), 'do not remove')
            self.assertEqual({name: os.environ.get(name) for name in old_env}, old_env)
            self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE), old_limit)
            self.assertTrue(Path(plan['cases'][0]['raw']['path']).is_file())

    def test_archive_verified_resume_rechecks_five_logical_artifacts_and_raw(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.archive_plan(root)
            output = root / 'analysis'
            first = BATCH.run_batch(plan, output, workers=1)
            with patch.object(BATCH.ARTIFACTS, 'verify_artifact', wraps=BATCH.ARTIFACTS.verify_artifact) as verify:
                second = BATCH.run_batch(plan, output, workers=1, resume=True)
            self.assertEqual(second['resume_verified_cases'], ['001-r0'])
            self.assertEqual(second['results'], json.loads(json.dumps(first['results'])))
            self.assertEqual({call.args[2] for call in verify.call_args_list}, BATCH.ARTIFACTS.ARTIFACT_NAMES)
            self.assertEqual(verify.call_count, 5)
            raw = Path(plan['cases'][0]['raw']['path'])
            with raw.open('ab') as stream:
                stream.write(b'bad')
            valid, reason = BATCH.verify_completed(plan['cases'][0], first['results']['001-r0'],
                plan['inventory_database']['sha256'], output, plan['analyzer_sha256'])
            self.assertFalse(valid)
            self.assertEqual(reason, 'SAVED_RAW_SOURCE_CHANGED')

    def test_archive_tamper_is_retained_and_retried_under_fresh_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.archive_plan(root)
            output = root / 'analysis'
            first = BATCH.run_batch(plan, output, workers=1)
            path = Path(first['results']['001-r0']['artifacts']['events.sqlite']['storage']['path'])
            damaged = bytearray(path.read_bytes())
            damaged[len(damaged) // 2] ^= 1
            path.write_bytes(damaged)
            second = BATCH.run_batch(plan, output, workers=1, resume=True)
            self.assertEqual(second['status'], 'COMPLETE_FOR_SELECTED_CASES')
            self.assertEqual(second['resume_verified_cases'], [])
            self.assertIn('/retries/', second['results']['001-r0']['output'])
            self.assertEqual(path.read_bytes(), bytes(damaged))

    def test_archive_failure_retains_scratch_and_never_journals_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.archive_plan(root)
            output = root / 'analysis'
            with patch.object(BATCH.ARTIFACTS, 'store_gzip', side_effect=OSError('fixture archive failure')):
                result = BATCH.run_batch(plan, output, workers=1)
            self.assertEqual(result['status'], 'INCOMPLETE')
            self.assertEqual(result['results'], {})
            self.assertIn('001-r0', result['failures'])
            journal = [json.loads(row) for row in (output / 'progress.jsonl').read_text().splitlines()]
            self.assertNotIn('RESULT', [row['event'] for row in journal])
            scratch = Path(plan['artifact_storage']['scratch_root'])
            self.assertEqual(len(list(scratch.glob('access-*/analysis/events.sqlite'))), 1)

    def test_archive_scratch_env_is_private_and_failures_restore_process_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.archive_plan(root)
            before = {key: os.environ.get(key) for key in ('TMPDIR', 'SQLITE_TMPDIR')}
            limits = resource.getrlimit(resource.RLIMIT_FSIZE)
            def fail(case, target, inventory, digest):
                self.assertEqual(os.environ['TMPDIR'], os.environ['SQLITE_TMPDIR'])
                self.assertTrue(Path(os.environ['TMPDIR']).relative_to(Path(plan['artifact_storage']['scratch_root'])).parts)
                self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE)[0], plan['artifact_storage']['scratch_per_case_bytes'])
                raise RuntimeError('fixture analyzer failure')
            result = BATCH.run_batch(plan, root / 'analysis', workers=1, worker=fail)
            self.assertEqual(result['status'], 'INCOMPLETE')
            self.assertEqual({key: os.environ.get(key) for key in before}, before)
            self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE), limits)

    def test_archive_preflight_enforces_workers_space_and_real_memory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.archive_plan(root)
            settings = plan['artifact_storage']
            little_space = type('Usage', (), {'free': settings['scratch_per_case_bytes']})()
            with patch.object(BATCH.shutil, 'disk_usage', return_value=little_space), self.assertRaisesRegex(ValueError, 'workers times'):
                BATCH.run_batch(plan, root / 'analysis', workers=2)
            original = Path.read_text
            def low_memory(path, *args, **kwargs):
                return 'MemAvailable: 1 kB\n' if str(path) == '/proc/meminfo' else original(path, *args, **kwargs)
            with patch.object(Path, 'read_text', low_memory), self.assertRaisesRegex(ValueError, 'MemAvailable'):
                BATCH.run_batch(plan, root / 'analysis', workers=1)

    def test_archive_rejects_unsafe_scratch_codec_and_changed_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.archive_plan(root)
            for change in ({'codec': 'guess'}, {'artifact_module_sha256': '0' * 64}, {'scratch_per_case_bytes': True}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    BATCH.validate_archive_settings(dict(plan['artifact_storage'], **change))
            scratch = Path(plan['artifact_storage']['scratch_root'])
            scratch.chmod(0o777)
            with self.assertRaisesRegex(ValueError, 'private owned'):
                BATCH.validate_archive_settings(plan['artifact_storage'])

    def test_archive_real_pool_uses_tiny_fixture_and_no_final_plain_db(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.archive_plan(root)
            result = BATCH.run_batch(plan, root / 'analysis', workers=2)
            self.assertEqual(result['status'], 'COMPLETE_FOR_SELECTED_CASES')
            self.assertTrue((root / 'analysis/001-r0/events.sqlite.gz').is_file())
            self.assertFalse((root / 'analysis/001-r0/events.sqlite').exists())

    def test_archive_verified_incomplete_history_is_not_relabelled_on_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = self.archive_plan(root)
            case = Path(plan['cases'][0]['root'])
            final_path, capture_path = case / 'file-access/final.json', case / 'capture.json'
            final = json.loads(final_path.read_bytes())
            final['health']['ring_drops'] = 1
            final['cpus'][0].update(attempted=2, ring_drops=1)
            final['observation_health'] = 'INCOMPLETE'
            final_raw = json.dumps(final).encode()
            final_path.write_bytes(final_raw)
            capture = json.loads(capture_path.read_bytes())
            capture['final_sha256'] = hashlib.sha256(final_raw).hexdigest()
            capture_path.write_text(json.dumps(capture))
            plan = BATCH.plan_batch(plan['matrix']['path'], plan['inventory_database']['path'],
                plan['inventory_database']['sha256'], archive_settings=plan['artifact_storage'])
            output = root / 'analysis'
            first = BATCH.run_batch(plan, output, workers=1)
            second = BATCH.run_batch(plan, output, workers=1, resume=True)
            self.assertEqual(first['status'], second['status'])
            self.assertEqual(second['status'], 'INCOMPLETE')
            self.assertEqual(second['resume_verified_cases'], ['001-r0'])


if __name__ == '__main__':
    unittest.main()
