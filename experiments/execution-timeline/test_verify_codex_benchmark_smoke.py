"""Collector-path portability tests; native replay is mocked only here."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from common import bind_artifacts
from verify_codex_benchmark_smoke import verify


class PortableCollectorTests(unittest.TestCase):
    def fixture(self,root):
        app=root/"app";app.mkdir()
        names=[]
        for name in ("rpc.jsonl","tool-events.jsonl","function-bindings.jsonl"):
            (app/name).write_bytes(b"");names.append("app/"+name)
        (app/"steps.json").write_text(json.dumps({"tool_calls":[],"function_bindings":[]}))
        names.append("app/steps.json")
        (root/"manifest.json").write_text(json.dumps({"artifacts":bind_artifacts(root,names),"tools":[]}))

    def test_local_collector_is_forwarded_without_removing_manifest_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root);collector=root/"pinned-collector"
            with patch("verify_codex_benchmark_smoke.verify_run",return_value={"health":{},"critical_path":{}}) as native:
                with patch("verify_codex_benchmark_smoke.verify_codex_tool_sources",return_value={"status":"UNIT_TEST_ONLY"}):
                    result=verify(root,"app",collector=collector)
            self.assertEqual(result["status"],"REPLAY_PASSED")
            self.assertEqual(native.call_args.kwargs["collector"],collector)
            self.assertEqual(len(native.call_args.kwargs["expected_manifest_sha256"]),64)

    def test_collector_override_does_not_bypass_application_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root)
            (root/"app/rpc.jsonl").write_bytes(b"tampered\n")
            with patch("verify_codex_benchmark_smoke.verify_run") as native:
                with self.assertRaisesRegex(ValueError,"digest differs"):
                    verify(root,"app",collector=root/"local")
            native.assert_not_called()
