#!/usr/bin/env python3
"""The integration tests use Go's independent canonical pprof reader."""
import copy
from contextlib import redirect_stderr, redirect_stdout
import gzip
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from pprof_export import MAX_INT64, encode_pprof, main, write_pprof
from semantic_profile import VIEW_DEFINITIONS


class PprofExportTests(unittest.TestCase):
    def profile(self, measure="wall_ms", unit="ms", weights=(1.25, 0)):
        return {"agent_id": "agent-a", "run_id": "run-1", "task_id": "task-1",
            "semantic_quality": "EXPLICIT_LABELS_NOT_INFERRED_INTENT", "views": [{
            "name": measure, "unit": unit, "status": "AVAILABLE", "total": sum(weights),
            "sample_count": len(weights)}], "operations": [{
            "kind": "tool", "stack": [{"kind": "task", "label": "fix parser"},
                {"kind": "tool", "label": "search", "call_id": "call-1"}],
            "measures": {measure: weight}, "evidence": {"tool_call_id": "tool-1",
                "evidence_chain_id": "chain-1", "path": "/private/secret.log",
                "command": "curl --header 'Bearer do-not-copy-this'", "result": 0}}
            for weight in weights]}

    def raw(self, path):
        result = subprocess.run([shutil.which("go"), "tool", "pprof", "-raw", str(path)],
            text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_standard_gzip_and_deterministic_encoding(self):
        first, metadata = encode_pprof(self.profile(), "wall_ms")
        second, _ = encode_pprof(self.profile(), "wall_ms")
        self.assertEqual(first, second)
        raw = gzip.decompress(first)
        self.assertGreater(len(raw), 100)
        self.assertEqual(metadata["unit"], "nanoseconds")
        self.assertEqual(metadata["exported_total"], 1_250_000)
        self.assertEqual(metadata["zero_sample_count"], 1)
        self.assertNotIn(b"secret.log", raw)
        self.assertNotIn(b"do-not-copy-this", raw)
        self.assertIn(b"evidence_ref_sha256", raw)
        self.assertIn(b"chain-1", raw)

    @unittest.skipUnless(shutil.which("go"), "Go pprof independent reader unavailable")
    def test_go_pprof_accepts_leaf_first_samples_labels_units_and_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.pb.gz"
            write_pprof(self.profile(), "wall_ms", path)
            raw = self.raw(path)
            self.assertIn("wall_ms/nanoseconds", raw)
            self.assertRegex(raw, r"1250000:\s+2\s+1")
            self.assertRegex(raw, r"\n\s+0:\s+2\s+1")
            self.assertIn("call_id:[call-1]", raw)
            self.assertIn("tool_call_id:[tool-1]", raw)
            self.assertIn("evidence_chain_id:[chain-1]", raw)
            self.assertIn("agent_id:[agent-a]", raw)
            self.assertIn("run_id:[run-1]", raw)
            self.assertIn("tool:[search]", raw)
            self.assertIn("task: fix parser", raw)
            self.assertIn("tool: search", raw)

    @unittest.skipUnless(shutil.which("go"), "Go pprof independent reader unavailable")
    def test_go_pprof_accepts_memory_custom_unit_and_semantic_flamegraph(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.pb.gz"
            receipt = write_pprof(self.profile("memory_rss_byte_ms", "byte_ms", (12345.5, 0)),
                "memory_rss_byte_ms", path)
            self.assertEqual(receipt["unit"], "byte_milliseconds")
            self.assertEqual(receipt["exported_total"], 12346)
            self.assertEqual(receipt["quantization_delta_source_units"], "0.5")
            self.assertIn("memory_rss_byte_ms/byte_milliseconds", self.raw(path))
            # Exercise a real consumer's graph generation, not only its parser.
            result = subprocess.run([shutil.which("go"), "tool", "pprof", "-dot", str(path)],
                text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("digraph", result.stdout)
            self.assertIn("fix parser", result.stdout)

    def test_not_collected_is_not_exported_as_zero(self):
        profile = self.profile()
        profile["views"][0]["status"] = "NOT_COLLECTED"
        with self.assertRaisesRegex(ValueError, "refusing invented samples"):
            encode_pprof(profile, "wall_ms")

    def test_all_zero_available_still_has_samples(self):
        _, receipt = encode_pprof(self.profile(weights=(0, 0)), "wall_ms")
        self.assertEqual(receipt["sample_count"], 2)
        self.assertEqual(receipt["zero_sample_count"], 2)

    def test_refuses_absent_operations_corrupt_totals_and_duplicate_views(self):
        for change in ("no_operations", "bad_total", "bad_count", "duplicate"):
            with self.subTest(change=change):
                profile = self.profile()
                if change == "no_operations": profile.pop("operations")
                if change == "bad_total": profile["views"][0]["total"] = 99
                if change == "bad_count": profile["views"][0]["sample_count"] = 999
                if change == "duplicate": profile["views"].append(copy.deepcopy(profile["views"][0]))
                with self.assertRaises(ValueError): encode_pprof(profile, "wall_ms")

    def test_rejects_negative_nonfinite_bool_fractional_count_and_overflow(self):
        for value in (-1, float("nan"), float("inf"), True, MAX_INT64 + 1):
            with self.subTest(value=value):
                profile = self.profile()
                profile["operations"][0]["measures"]["wall_ms"] = value
                with self.assertRaises(ValueError): encode_pprof(profile, "wall_ms")
        with self.assertRaisesRegex(ValueError, "fractional count"):
            encode_pprof(self.profile("syscall_count", "次", (0.5, 0)), "syscall_count")

    def test_bounded_redacted_labels_and_frames(self):
        profile = self.profile()
        for operation in profile["operations"]:
            operation["stack"][1]["call_id"] = "x" * 3000
            operation["stack"][0]["label"] = "Authorization Bearer do-not-leak"
            operation["evidence"]["request_id"] = "api_key=should-not-copy"
        encoded, _ = encode_pprof(profile, "wall_ms")
        raw = gzip.decompress(encoded)
        self.assertNotIn(b"do-not-leak", raw)
        self.assertNotIn(b"should-not-copy", raw)
        self.assertNotIn(b"x" * 500, raw)
        self.assertIn(b"[redacted]", raw)

    @unittest.skipUnless(shutil.which("go"), "Go pprof independent reader unavailable")
    def test_stable_function_location_and_string_ids_when_operations_reordered(self):
        original = self.profile()
        original["operations"][0]["stack"][1]["label"] = "write"
        reversed_profile = copy.deepcopy(original)
        reversed_profile["operations"].reverse()
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "a.pb.gz"; second = Path(directory) / "b.pb.gz"
            write_pprof(original, "wall_ms", first); write_pprof(reversed_profile, "wall_ms", second)
            self.assertEqual(self.raw(first).split("Locations", 1)[1], self.raw(second).split("Locations", 1)[1])

    @unittest.skipUnless(shutil.which("go"), "Go pprof independent reader unavailable")
    def test_all_current_view_units_parse_in_canonical_go_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, _label, unit, _quality in VIEW_DEFINITIONS:
                with self.subTest(view=name):
                    path = Path(directory) / (name + ".pb.gz")
                    weights = (1.25, 0) if unit in ("ms", "byte_ms") else (3, 0)
                    write_pprof(self.profile(name, unit, weights), name, path)
                    self.assertIn("Samples:", self.raw(path))

    def test_cli_and_missing_measure_are_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"; output = Path(directory) / "profile.pb.gz"
            source.write_text(json.dumps(self.profile()))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--profile", str(source), "--view", "wall_ms", "--output", str(output)]), 0)
            self.assertEqual(output.read_bytes()[:2], b"\x1f\x8b")
            source.write_text('{"views": [], "views": []}')
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["--profile", str(source), "--view", "wall_ms", "--output", str(output)])
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
