import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from benchmark_replay import MARKER, discover, replay


class BenchmarkReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'input'
        self.root.mkdir()
        self.output = self.base / 'host-receipts'
        self.verifier = self.base / 'pinned-verifier'
        self.verifier.write_text('#!' + sys.executable + '\n' + '''
import argparse,json,pathlib,sys,time
p=argparse.ArgumentParser();p.add_argument('--artifacts');p.add_argument('--expectation');a=p.parse_args()
e=json.loads(pathlib.Path(a.expectation).read_text())
if e.get('fixture_sleep'): time.sleep(5)
sys.stderr.write('retained verifier diagnostic\\n')
if e.get('fixture_rc'): sys.exit(e['fixture_rc'])
if e.get('fixture_bad_json'): print('not-json');sys.exit(0)
r={'verified':not e.get('fixture_unverified',False),'run_id':e['expected_config']['run_id'],
   'epoch':e['expected_config']['epoch'],'evidence_status':e.get('fixture_evidence','INCOMPLETE'),
   'system_effect_wal_event_count':10,'system_effect_jsonl_event_count':10,
   'process_lifecycle_wal_event_count':3,'process_lifecycle_jsonl_event_count':3,
   'socket_state_event_count':2,'retained_field':{'reason':'coverage gap remains'}}
if e.get('fixture_forged_count'): r['system_effect_wal_event_count']=-1
if e.get('fixture_bool_count'): r['system_effect_wal_event_count']=True
if e.get('fixture_count_mismatch'): r['system_effect_jsonl_event_count']=9
if e.get('fixture_wrong_run'): r['run_id']='another-run'
if e.get('fixture_modify_input'):
 pathlib.Path(a.expectation).write_text(json.dumps({**e,'changed_during_replay':True}))
print(json.dumps(r))
''')
        self.verifier.chmod(0o700)
        self.digest = hashlib.sha256(self.verifier.read_bytes()).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def add(self, name, terminal=False, **fields):
        session = self.root / name
        observer = session / 'observer'
        observer.mkdir(parents=True)
        (observer / 'artifact-manifest.json').write_text('{"fixture":"manifest"}')
        (observer / 'deployment-observation-report.json').write_text('{"overall_evidence_status":"INCOMPLETE"}')
        (observer / 'system-effects.raw.bin').write_bytes(b'read-only WAL fixture')
        parent = session / 'control' if terminal else session
        parent.mkdir(exist_ok=True)
        expectation = parent / 'verification-expectation.json'
        expectation.write_text(json.dumps({'expected_config': {'run_id': name, 'epoch': 1},
            'expected_artifact_manifest_sha256': '0' * 64, 'expected_report_sha256': '0' * 64, **fields}))
        return expectation, observer

    def run_replay(self, **kwargs):
        return replay(self.root, self.verifier, self.digest, self.output, **kwargs)

    def test_swe_terminal_and_single_run_layouts_discovered_and_replayed(self):
        self.add('paired-swe/block-0/files/observation')
        self.add('paired-terminal/block-0/perf/evidence/task-123', terminal=True)
        self.add('official-swe/gold-control/observation')
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        result = self.run_replay()
        self.assertTrue(result['all_replays_passed'])
        self.assertFalse(result['all_evidence_complete'])
        self.assertEqual(result['independent_verification_count'], 3)
        self.assertEqual(result['event_totals'], {'system_effect_wal_event_count': 30,
            'process_lifecycle_wal_event_count': 9, 'socket_state_event_count': 6,
            'total_verified_wal_events': 45})
        self.assertEqual(result['evidence_status_counts'], {'INCOMPLETE': 3})
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        for check in result['checks']:
            self.assertEqual(check['result']['retained_field'], {'reason': 'coverage gap remains'})
            receipt = Path(check['receipt_directory'])
            self.assertIn('retained verifier diagnostic', (receipt / 'verifier.stderr').read_text())
            self.assertEqual(check['input_digests_before'], check['input_digests_after'])

    def test_existing_and_nested_replay_outputs_not_reinterpreted_as_input(self):
        self.add('real/observation')
        old = self.root / 'old-host-replay'
        old.mkdir()
        (old / MARKER).write_text('{}')
        (old / 'verification-expectation.json').write_text('untrusted old receipt')
        self.output = self.root / 'new-host-replay'
        self.assertEqual(self.run_replay()['independent_verification_count'], 1)
        inputs, issues = discover(self.root)
        self.assertEqual(len(inputs), 1)
        self.assertEqual(issues, [])

    def test_empty_input_is_not_vacuous_success(self):
        result = self.run_replay()
        self.assertFalse(result['all_replays_passed'])
        self.assertEqual(result['independent_verification_count'], 0)
        self.assertIn('NO_VERIFICATION_EXPECTATIONS_FOUND', [row['error'] for row in result['discovery_issues']])

    def test_orphan_observer_is_not_silently_omitted(self):
        expectation, _ = self.add('orphan')
        expectation.unlink()
        self.add('good')
        result = self.run_replay()
        self.assertFalse(result['all_replays_passed'])
        self.assertEqual(result['independent_verification_count'], 1)
        self.assertIn('OBSERVER_WITHOUT_VERIFICATION_EXPECTATION', [row['error'] for row in result['discovery_issues']])

    def test_missing_observer_produces_failure_receipt(self):
        expectation = self.root / 'verification-expectation.json'
        expectation.write_text('{}')
        result = self.run_replay()
        self.assertEqual(result['failed_count'], 1)
        self.assertFalse(result['all_replays_passed'])
        self.assertIn('DIRECTORY_MISSING', result['checks'][0]['error'])

    def test_duplicate_expectations_do_not_double_count_one_wal(self):
        expectation, observer = self.add('duplicate')
        control = observer.parent / 'control'
        control.mkdir()
        (control / expectation.name).write_bytes(expectation.read_bytes())
        result = self.run_replay()
        self.assertEqual(result['failed_count'], 2)
        self.assertEqual(result['independent_verification_count'], 0)
        self.assertEqual(result['event_totals']['total_verified_wal_events'], 0)

    def test_symlink_expectation_rejected(self):
        expectation, _ = self.add('linked')
        outside = self.base / 'outside.json'
        expectation.rename(outside)
        expectation.symlink_to(outside)
        result = self.run_replay()
        self.assertEqual(result['failed_count'], 1)
        self.assertFalse(result['all_replays_passed'])

    def test_symlink_observer_not_traversed_or_trusted(self):
        _, observer = self.add('linked')
        outside = self.base / 'outside-observer'
        observer.rename(outside)
        observer.symlink_to(outside)
        result = self.run_replay()
        self.assertFalse(result['all_replays_passed'])
        self.assertEqual(result['independent_verification_count'], 0)

    def test_wrong_verifier_pin_fails_before_creating_output(self):
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            replay(self.root, self.verifier, 'f' * 64, self.output)
        self.assertFalse(self.output.exists())

    def test_output_cannot_overwrite_input_or_previous_receipts(self):
        self.add('good')
        with self.assertRaises(FileExistsError):
            replay(self.root, self.verifier, self.digest, self.root)
        self.run_replay()
        with self.assertRaises(FileExistsError):
            self.run_replay()

    def test_output_inside_artifact_is_rejected_without_modification(self):
        _, observer = self.add('good')
        self.output = observer / 'not-allowed-receipts'
        with self.assertRaisesRegex(ValueError, 'must not modify an artifact'):
            self.run_replay()
        self.assertFalse(self.output.exists())

    def test_nonzero_return_preserves_raw_stderr_and_returncode(self):
        self.add('rejected', fixture_rc=8)
        result = self.run_replay()
        check = result['checks'][0]
        self.assertEqual(check['return_code'], 8)
        self.assertFalse(check['verified'])
        self.assertIn('retained verifier diagnostic', (Path(check['receipt_directory']) / 'verifier.stderr').read_text())

    def test_timeout_is_explicit_not_success(self):
        self.add('timed-out', fixture_sleep=True)
        result = self.run_replay(timeout=.03)
        self.assertEqual(result['checks'][0]['status'], 'TIMEOUT')
        self.assertEqual(result['independent_verification_count'], 0)

    def test_bad_json_unverified_wrong_run_and_invalid_counts_rejected(self):
        for index, field in enumerate(('fixture_bad_json', 'fixture_unverified', 'fixture_wrong_run',
                                        'fixture_forged_count', 'fixture_bool_count', 'fixture_count_mismatch')):
            self.add('bad-' + str(index), **{field: True})
        result = self.run_replay()
        self.assertEqual(result['failed_count'], 6)
        self.assertFalse(result['all_replays_passed'])
        self.assertEqual(result['event_totals']['total_verified_wal_events'], 0)

    def test_input_modification_during_verifier_is_detected(self):
        self.add('changing', fixture_modify_input=True)
        result = self.run_replay()
        self.assertFalse(result['all_replays_passed'])
        self.assertIn('binding changed during Host replay', result['checks'][0]['error'])


if __name__ == '__main__':
    unittest.main()
