import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import resume_large_search as resume


def fixture():
    plans = [dict(cache='warm', workspace_layout='shared', concurrency=n,
                  intervention='none', block=block, warmup=False)
             for block in (0, 1) for n in (1, 2)]
    original = dict(schema_version=1, status='FAILED', schedule=plans,
        campaigns=[dict(path='%03d-r0' % index, block=0, stage='performance', condition=plan)
                   for index, plan in enumerate(plans[:2])],
        source={'commit': 'fixed'}, source_inventory_sha256='inventory-file', jobs=1,
        passes=1, queries=['needle'], cpus=[0], measurement_coordinator_and_sampler_cpus=[1],
        boot_id='boot', seed=1, binaries={'runner': 'fixed'}, measurement_mode='sampler')
    return original


class ResumeContracts(unittest.TestCase):
    def test_exact_suffix_is_copied_not_reordered_or_rewritten(self):
        old = fixture()
        before = copy.deepcopy(old)
        plans = resume.validate_prefix(old, 2)
        self.assertEqual(plans, old['schedule'][2:])
        plans[0]['cache'] = 'changed'
        self.assertEqual(old, before)

    def test_holes_duplicates_and_wrong_count_rejected(self):
        old = fixture()
        for operation in ('count', 'hole', 'condition', 'block', 'status'):
            changed = copy.deepcopy(old)
            expected = 2
            if operation == 'count': expected = 1
            elif operation == 'hole': changed['campaigns'][1]['path'] = '003-r0'
            elif operation == 'condition': changed['campaigns'][1]['condition'] = changed['schedule'][2]
            elif operation == 'block': changed['campaigns'][1]['block'] = True
            else: changed['status'] = 'COMPLETE'
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                resume.validate_prefix(changed, expected)

    def test_combined_retains_original_indices_blocks_and_failed_source(self):
        old = fixture()
        new = copy.deepcopy(old)
        new.update(status='COMPLETE', schedule=old['schedule'][2:], campaigns=[
            dict(path='%03d-r1' % i, block=1, stage='performance', condition=plan)
            for i, plan in enumerate(old['schedule'][2:])])
        result = resume.combine(old, new, 'old', 'new', {'adapter': 'sha'})
        self.assertEqual([r['original_schedule_index'] for r in result['campaigns']], list(range(4)))
        self.assertEqual([r['block'] for r in result['campaigns']], [0, 0, 1, 1])
        self.assertEqual([r['path'] for r in result['campaigns']],
                         ['old/000-r0', 'old/001-r0', 'new/000-r1', 'new/001-r1'])
        self.assertEqual(result['status'], 'COMPLETE')
        self.assertEqual(old['status'], 'FAILED')
        for field in ('boot_id', 'binaries', 'cpus', 'source_inventory_sha256'):
            wrong = copy.deepcopy(new)
            wrong[field] = 'changed'
            with self.subTest(field=field), self.assertRaises(ValueError):
                resume.combine(old, wrong, 'old', 'new', {})

    def test_raw_output_not_just_stored_digest_is_checked(self):
        binding = fixture()
        plan = binding['schedule'][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trial = root / 'trials' / 'one'
            trial.mkdir(parents=True)
            raw = b'z\0a\0'
            (trial / 'task-0000.stdout').write_bytes(raw)
            digest = hashlib.sha256(b'a\0z\0').hexdigest()
            campaign = dict(status='COMPLETE', jobs=1, passes=1, queries=['needle'],
                binaries=binding['binaries'], trials=[dict(path='trials/one', run_id='r', makespan_ns=20)])
            profile = dict(status='COMPLETE', cleanup_errors=[], boot_id='boot', run_id='r',
                release_ns=10, end_ns=30, makespan_ns=20, config=dict(
                    cpus=[0], mode='sampler', jobs=1, passes=1, **{k: v for k, v in plan.items() if k != 'block'}),
                tasks=[dict(task_id='task-0000')], results=[dict(task_id='task-0000', query_index=0,
                    exit_code=0, output_bytes=len(raw), output_sha256=digest)])
            (root / 'campaign.json').write_text(json.dumps(campaign))
            (trial / 'profile-run.json').write_text(json.dumps(profile))
            (trial / 'report.json').write_text(json.dumps({'analysis': {'source_sha256': 'analyzer'}}))
            expected = {}
            self.assertEqual(resume.verify_campaign(root, binding, expected, plan), 'analyzer')
            self.assertEqual(expected[0], (0, digest, len(raw)))
            (trial / 'task-0000.stdout').write_bytes(b'tampered\0')
            with self.assertRaises(ValueError):
                resume.verify_campaign(root, binding, expected, plan)

    def test_artifact_paths_cannot_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in ('../elsewhere', '/absolute'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    resume.child(Path(directory), path)


if __name__ == '__main__':
    unittest.main()
