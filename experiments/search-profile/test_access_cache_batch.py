import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import access_cache_batch as batch


CHECKER = '''import argparse,json,os,sys
from pathlib import Path
p=argparse.ArgumentParser()
for n in ('trial','inventory','expected-inventory-sha256','preparation','output'): p.add_argument('--'+n,required=True)
a=p.parse_args()
ok=not Path(a.trial).name.startswith('fail')
Path(a.output).write_text(json.dumps({'status':'PASS' if ok else 'FAIL','cache_condition_replay':'PASS' if ok else 'FAIL','fixture_pid':os.getpid()}))
print('tiny fixture only')
print('fixture stderr retained',file=sys.stderr)
sys.exit(0 if ok else 1)
'''

INDEXER = '''import argparse,json,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('command')
for n in ('matrix','receipts-dir','output'): p.add_argument('--'+n,required=True)
a=p.parse_args();rows={};failed={}
for f in Path(a.receipts_dir).glob('*.json'):
 v=json.loads(f.read_text()); rows[f.stem]={'path':'receipts/'+f.name}
 if v.get('status')!='PASS': failed[f.stem]='fixture fail'
Path(a.output).write_text(json.dumps({'status':'COMPLETE_FOR_SELECTED_CASES' if not failed else 'INCOMPLETE','results':rows,'failures':failed}))
sys.exit(1 if failed else 0)
'''


def fixture(root):
    inputs, raw = root / 'inputs', root / 'raw'
    inputs.mkdir()
    raw.mkdir()
    for path, value in ((inputs / 'inventory.json', {'files': []}),
                        (inputs / 'preparation.json', {}), (raw / 'matrix.json', {})):
        batch.write_new(path, value)
    checker, indexer = root / 'checker.py', root / 'indexer.py'
    checker.write_text(CHECKER)
    indexer.write_text(INDEXER)
    plan = {'matrix': batch.fingerprint(raw / 'matrix.json'),
        'inventory': batch.fingerprint(inputs / 'inventory.json'),
        'preparation': batch.fingerprint(inputs / 'preparation.json'),
        'cases': [{'case_id': '%03d-r0' % i, 'trial': str(root / ('trial-%d' % i))} for i in range(2)]}
    return plan, checker, indexer


class BatchContracts(unittest.TestCase):
    def test_each_proof_has_own_serial_process_and_small_index(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            plan, checker, indexer = fixture(root)
            with mock.patch('builtins.print'):
                receipt = batch.run_batch(plan, root / 'batch', checker, indexer)
            self.assertEqual(receipt['status'], 'COMPLETE_FOR_SELECTED_CASES')
            self.assertEqual(receipt['failures'], {})
            values = [batch.document(root / 'batch' / 'receipts' / (case['case_id'] + '.json')) for case in plan['cases']]
            self.assertNotEqual(values[0]['fixture_pid'], values[1]['fixture_pid'])
            self.assertEqual(len(receipt['results']), 2)
            for row in receipt['results'].values():
                self.assertEqual(row['returncode'], 0)
                self.assertEqual(row['command'][1], '-B')
                self.assertIn('--preparation', row['command'])
            self.assertIn('fixture stderr retained', (root / 'batch' / 'logs' / '000-r0.stderr').read_text())
            self.assertEqual(batch.document(root / 'batch' / 'batch.json')['status'], receipt['status'])
            self.assertEqual(batch.document(root / 'batch' / 'index.json')['status'], 'COMPLETE_FOR_SELECTED_CASES')

    def test_failed_proof_preserved_and_next_child_still_runs(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            plan, checker, indexer = fixture(root)
            plan['cases'][0]['trial'] = str(root / 'fail-first')
            with mock.patch('builtins.print'):
                receipt = batch.run_batch(plan, root / 'batch', checker, indexer)
            self.assertEqual(receipt['status'], 'INCOMPLETE')
            self.assertIn('000-r0', receipt['failures'])
            self.assertIn('__index__', receipt['failures'])
            self.assertEqual(receipt['results']['001-r0']['returncode'], 0)
            self.assertEqual(batch.document(root / 'batch' / 'receipts' / '000-r0.json')['status'], 'FAIL')
            self.assertEqual(len((root / 'batch' / 'progress.jsonl').read_text().splitlines()), 2)

    def test_fresh_output_and_outside_raw_scope_required(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            plan, checker, indexer = fixture(root)
            for output in (root / 'inputs', root / 'raw' / 'batch'):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    batch.run_batch(plan, output, checker, indexer)

    def test_timeout_and_missing_child_are_failure_not_pass(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with mock.patch.object(batch.subprocess, 'run', side_effect=batch.subprocess.TimeoutExpired(['fixture'], 1)):
                result = batch.invoke(['fixture'], root / 'out', root / 'err', 1)
            self.assertIsNone(result['returncode'])
            self.assertIn('TimeoutExpired', result['error'])

    def test_indexer_cannot_turn_missing_receipts_into_success(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            plan, checker, indexer = fixture(root)
            checker.write_text('raise SystemExit(1)')
            with mock.patch('builtins.print'):
                receipt = batch.run_batch(plan, root / 'batch', checker, indexer)
            self.assertEqual(receipt['status'], 'INCOMPLETE')
            self.assertIn('000-r0', receipt['failures'])
            self.assertIn('001-r0', receipt['failures'])
            self.assertIn('__index__', receipt['failures'])

    def test_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            for path in ('', '../elsewhere', '/absolute'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    batch.child(Path(name), path)


class PlanContracts(unittest.TestCase):
    def test_plan_only_follows_bound_direct_cases_and_hashes_inventory(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            plan, _, _ = fixture(root)
            inventory = plan['inventory']
            preparation = {'inventory_sha256': inventory['sha256'], 'source': {'commit': 'same'}, 'boot_id': 'boot'}
            (root / 'inputs' / 'preparation.json').unlink()
            batch.write_new(root / 'inputs' / 'preparation.json', preparation)
            schedule = [{'block': 0, 'cache': 'warm', 'file_access_mode': 'sampler'},
                        {'block': 0, 'cache': 'guest-cold', 'file_access_mode': 'access'}]
            matrix = {'source_inventory_sha256': inventory['sha256'], 'boot_id': 'boot', 'source': preparation['source'],
                'campaigns': [{'path': '%03d-r0' % i, 'block': 0,
                              'condition': {k: v for k, v in item.items() if k != 'block'}} for i, item in enumerate(schedule)]}
            for entry in matrix['campaigns']:
                case = root / 'raw' / entry['path']
                trial = case / 'trials' / 'one'
                trial.mkdir(parents=True)
                batch.write_new(trial / 'profile-run.json', {})
                batch.write_new(case / 'capture.json', {'profile_path': 'trials/one/profile-run.json'})
            (root / 'raw' / 'matrix.json').unlink()
            batch.write_new(root / 'raw' / 'matrix.json', matrix)
            with mock.patch.object(batch.formal, 'validate_manifest', return_value=schedule):
                actual = batch.plan_batch(root / 'raw' / 'matrix.json', root / 'inputs' / 'inventory.json',
                                          root / 'inputs' / 'preparation.json')
            self.assertEqual(len(actual['cases']), 2)
            self.assertEqual(actual['inventory']['sha256'], inventory['sha256'])
            self.assertEqual(actual['cases'][0]['trial'], str(root / 'raw' / '000-r0' / 'trials' / 'one'))


if __name__ == '__main__':
    unittest.main()
