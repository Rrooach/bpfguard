import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location('audit_replay', Path(__file__).with_name('audit_replay.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class ReplayTests(unittest.TestCase):
    def test_verifier_hash_must_match_before_running(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            verifier = root / 'verifier'
            verifier.write_bytes(b'fixed-binary')
            with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                audit.verify([], verifier, '0' * 64, root / 'result')
            self.assertFalse((root / 'result').exists())

    def test_verified_incomplete_stays_incomplete(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            verifier = root / 'verifier'
            verifier.write_bytes(b'fixed-binary')
            trial = root / 'trial'
            trial.mkdir()
            receipt = {'verified': True, 'evidence_status': 'INCOMPLETE', 'system_effect_wal_event_count': 17}
            run = subprocess.CompletedProcess([], 0, json.dumps(receipt).encode(), b'')
            with mock.patch.object(audit, 'observer_trials', return_value=iter([trial])), mock.patch.object(audit.subprocess, 'run', return_value=run):
                result = audit.verify([root], verifier, hashlib.sha256(verifier.read_bytes()).hexdigest(), root / 'result')
            self.assertEqual(result['independent_host_wal_replay'], 'PASS')
            self.assertEqual(result['evidence_statuses'], {'INCOMPLETE': 1})

    def test_parse_or_exit_failure_is_not_green(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            verifier = root / 'verifier'
            verifier.write_bytes(b'fixed-binary')
            trial = root / 'trial'
            trial.mkdir()
            run = subprocess.CompletedProcess([], 1, b'{"verified":true}', b'rejected')
            with mock.patch.object(audit, 'observer_trials', return_value=iter([trial])), mock.patch.object(audit.subprocess, 'run', return_value=run):
                result = audit.verify([root], verifier, hashlib.sha256(verifier.read_bytes()).hexdigest(), root / 'result')
            self.assertEqual(result['independent_host_wal_replay'], 'FAIL')
            self.assertEqual(result['statuses'], {'FAIL': 1})
            self.assertEqual(result['evidence_statuses'], {})

    def test_timeout_is_a_preserved_failure_receipt(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            verifier = root / 'verifier'
            verifier.write_bytes(b'fixed-binary')
            trial = root / 'trial'
            trial.mkdir()
            error = subprocess.TimeoutExpired([], 120, output=b'partial', stderr=b'slow')
            with mock.patch.object(audit, 'observer_trials', return_value=iter([trial])), mock.patch.object(audit.subprocess, 'run', side_effect=error):
                result = audit.verify([root], verifier, hashlib.sha256(verifier.read_bytes()).hexdigest(), root / 'result')
            self.assertEqual(result['independent_host_wal_replay'], 'FAIL')
            self.assertIn(b'INDEPENDENT_VERIFIER_TIMEOUT', (root / 'result' / '0000.stderr').read_bytes())


if __name__ == '__main__':
    unittest.main()
