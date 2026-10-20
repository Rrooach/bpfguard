#!/usr/bin/env python3
"""Evidence binding and protocol failure checks; no Docker or paid model calls."""

import importlib.util
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


runner = module("swe_pilot_runner", "run.py")
prepare = module("swe_pilot_prepare", "prepare.py")


class EvidenceTests(unittest.TestCase):
    def test_task_identity_and_dataset_binding(self):
        provenance = {"instance_id": "psf__requests-1142", "dataset": prepare.DATASET,
                      "harness_revision": runner.HARNESS_REVISION}
        task = [{"instance_id": provenance["instance_id"]}]
        self.assertEqual(runner.validate_task(task, provenance), task[0])
        with self.assertRaises(ValueError):
            runner.validate_task([{"instance_id": "other"}], provenance)
        with self.assertRaises(ValueError):
            runner.validate_task(task * 2, provenance)
        with self.assertRaises(ValueError):
            runner.validate_task(task, {**provenance, "dataset": "custom-fixture"})

    def test_dataset_must_have_complete_failure_tests(self):
        row = {"instance_id": "psf__requests-1142", "repo": "psf/requests", "base_commit": "a" * 40,
               "patch": "patch", "test_patch": "test", "problem_statement": "issue", "version": "1",
               "FAIL_TO_PASS": '["one"]', "PASS_TO_PASS": '[]'}
        self.assertEqual(prepare.validate_instance(row, row["instance_id"]), row)
        with self.assertRaises(ValueError):
            prepare.validate_instance({**row, "FAIL_TO_PASS": "[]"}, row["instance_id"])
        with self.assertRaises(ValueError):
            prepare.validate_instance({**row, "base_commit": "short"}, row["instance_id"])

    def test_installed_harness_forgery_is_rejected_and_auxiliary_exclusion_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installed = root / "installed"
            installed.mkdir()
            sources = {"__init__.py": b"version = '3.0.17'\n", "harness/__init__.py": b"",
                       "harness/run_evaluation.py": b"evaluation = True\n",
                       "harness/grading.py": b"grading = True\n", "scripts/auxiliary.py": b"auxiliary = True\n"}
            archive_path = root / "harness.tar.gz"
            prefix = "SWE-bench-" + runner.HARNESS_REVISION + "/swebench/"
            with tarfile.open(archive_path, "w:gz") as archive:
                for relative, content in sources.items():
                    entry = tarfile.TarInfo(prefix + relative)
                    entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content))
                    if not relative.startswith("scripts/"):
                        path = installed / relative
                        path.parent.mkdir(exist_ok=True)
                        path.write_bytes(content)
            provenance = {"harness_source": {"sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest()}}
            with mock.patch.object(runner.importlib.util, "find_spec",
                                   return_value=SimpleNamespace(submodule_search_locations=[str(installed)])):
                checked = runner.validate_installed_harness(root, provenance)
                self.assertEqual(checked["auxiliary_scripts_not_packaged"], ["scripts/auxiliary.py"])
                (installed / "harness/grading.py").write_text("forged = True\n")
                with self.assertRaisesRegex(ValueError, "differs from pinned source"):
                    runner.validate_installed_harness(root, provenance)

    def test_model_output_is_not_silently_treated_as_shell(self):
        self.assertEqual(runner.validate_agent_command('{"command":"pwd"}'), "pwd")
        for invalid in ('pwd', '{"command":""}', '{"command":"pwd","extra":true}', '{"command":42}'):
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                runner.validate_agent_command(invalid)

    def test_protocol_partial_line_timeout(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; print('{',end='',flush=True); time.sleep(2)"],
                                  stdout=subprocess.PIPE)
        try:
            with self.assertRaises(TimeoutError):
                runner.read_line(child, .05)
        finally:
            runner.terminate(child)
            child.stdout.close()

    def test_protocol_bounded_and_single_response(self):
        for output in ('{}\n{}\n', 'x' * 500):
            child = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdout.write(" + repr(output) + "); sys.stdout.flush()"],
                                      stdout=subprocess.PIPE)
            try:
                with self.assertRaises((RuntimeError, json.JSONDecodeError)):
                    runner.read_line(child, 1, maximum=128)
            finally:
                runner.terminate(child)
                child.stdout.close()

    def test_plain_sampler_ready(self):
        child = subprocess.Popen([sys.executable, "-c", "print('READY')"], stdout=subprocess.PIPE)
        try:
            self.assertEqual(runner.read_line(child, 1, decode_json=False), b"READY\n")
        finally:
            runner.terminate(child)
            child.stdout.close()

    def test_failed_ready_cleanup_keeps_phase_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            container = mock.Mock()
            container.id = "a" * 64
            session = runner.Session(container, Path(directory) / "session", "run", {}, None)
            session.finish()
            self.assertTrue((session.root / "phase-events.jsonl").is_file())
            self.assertEqual(len(session.events), 1)
            session.finish()
            self.assertEqual(len(session.events), 1)

    def test_verification_pass_does_not_promote_incomplete_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "observer").mkdir()
            (root / "verification.json").write_text('{"verified":true}')
            (root / "observer/deployment-observation-report.json").write_text(
                '{"overall_evidence_status":"INCOMPLETE","aggregate_health":{"event_dropped":0}}')
            result = runner.summarize_observation(root)
            self.assertTrue(result["observer_verification_passed"])
            self.assertEqual(result["state"], "INCOMPLETE")
            self.assertEqual(result["aggregate_health"]["event_dropped"], 0)


if __name__ == "__main__":
    unittest.main()
