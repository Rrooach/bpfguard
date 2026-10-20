#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from code_mode_timing import (SCHEMA, app_server_code_mode_timing, load_code_mode_events,
                              replay_code_mode_events, replay_runtime_events)


class CodeModeTimingTests(unittest.TestCase):
    def run_node(self, callback):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "code-mode.jsonl"
            script = ("import {runObservedCodeMode,closeCodeModeLedgers} from "
                + json.dumps(Path(__file__).with_name("observer-code-mode.mjs").resolve().as_uri())
                + ";try { await runObservedCodeMode({run_id:'r',agent_id:'a',task_id:'t',call_id:'c',"
                + "ledgerPath:process.argv[1]}, " + callback + "); } catch (error) {"
                + "if (error.message !== 'expected fixture failure') throw error; } finally { closeCodeModeLedgers(); }")
            subprocess.run(["node", "--input-type=module", "-e", script, str(ledger)],
                           text=True, capture_output=True, check=True, timeout=15)
            return replay_runtime_events(load_code_mode_events(ledger))["invocations"][0]

    def events(self):
        identity = {"schema": SCHEMA, "clock": "NODE_HRTIME_MONOTONIC", "run_id": "r", "agent_id": "a",
            "task_id": "t", "call_id": "c", "runtime_id": "runtime", "pid": 12, "boot_id": "boot"}
        raw = [
            (0, "CODE_MODE_STARTED", {"memory": {"rss_bytes": 100, "heap_used_bytes": 10}}),
            (1, "JS_STARTED", {"span_id": "j1", "name": "prepare"}),
            (3, "JS_COMPLETED", {"span_id": "j1", "name": "prepare", "status": "SUCCEEDED", "thread_cpu_usec": 1}),
            (4, "TOOL_WAIT_STARTED", {"span_id": "w1", "name": "search"}),
            (5, "TOOL_WAIT_STARTED", {"span_id": "w2", "name": "read"}),
            (9, "TOOL_WAIT_COMPLETED", {"span_id": "w2", "name": "read", "status": "SUCCEEDED"}),
            (10, "TOOL_WAIT_COMPLETED", {"span_id": "w1", "name": "search", "status": "SUCCEEDED"}),
            (12, "CODE_MODE_COMPLETED", {"status": "SUCCEEDED", "memory": {"rss_bytes": 90, "heap_used_bytes": 9}}),
        ]
        return [{**identity, "sequence": i + 1, "occurred_ns": timestamp, "event": kind, **fields}
                for i, (timestamp, kind, fields) in enumerate(raw)]

    def test_parallel_waits_are_unioned_and_js_is_independent(self):
        result = replay_code_mode_events(self.events())["invocations"][0]
        self.assertEqual(result["wall_ns"], 12)
        self.assertEqual(result["tool_wait_union_ns"], 6)
        self.assertEqual(result["tool_wait_sum_ns"], 10)
        self.assertEqual(result["no_tool_outstanding_wall_ns"], 6)
        self.assertEqual(result["instrumented_js_dispatch_wall_ns"], 2)
        self.assertEqual(result["instrumented_js_thread_cpu_usec"], 1)
        self.assertEqual(result["memory"]["rss_bytes"], {"start": 100, "end": 90, "max_observed": 100})

    def test_mismatch_duplicate_regression_and_unawaited_tools_are_rejected(self):
        for mutate in (
            lambda rows: rows[3].update(runtime_id="different"),
            lambda rows: rows[4].update(span_id="w1"),
            lambda rows: rows[5].update(occurred_ns=2),
            lambda rows: rows.pop(6),
            lambda rows: rows[7].update(memory={"rss_bytes": -1}),
            lambda rows: rows[2].update(name="different"),
        ):
            rows = copy.deepcopy(self.events()); mutate(rows)
            for i, row in enumerate(rows):
                row["sequence"] = i + 1
            with self.assertRaises(ValueError):
                replay_code_mode_events(rows)

    def test_partial_ledger_retains_missing_completion(self):
        with self.assertRaises(ValueError):
            replay_code_mode_events(self.events()[:-1])
        self.assertEqual(replay_code_mode_events(self.events()[:-1], require_complete=False)["status"], "INCOMPLETE")

    def test_presentation_partition_does_not_double_count_js_during_tool_wait(self):
        rows = self.events()
        # JS runs while both tools are outstanding: those two units are JS,
        # four units are tool-pending only, and six are not instrumented.
        rows[1]["occurred_ns"], rows[2]["occurred_ns"] = 6, 8
        rows = sorted(rows, key=lambda row: row["occurred_ns"])
        for i, row in enumerate(rows):
            row["sequence"] = i + 1
        call = replay_runtime_events(rows)["invocations"][0]
        self.assertEqual(call["wall_ms"], 12 / 1e6)
        self.assertEqual(call["js_ms"], 2 / 1e6)
        self.assertEqual(call["tool_wait_ms"], 4 / 1e6)
        self.assertEqual(call["other_ms"], 6 / 1e6)
        self.assertEqual(sum(x["end_ns"] - x["begin_ns"] for x in call["segments"]), 12)

    def test_bigint_timestamps_preserve_nanoseconds_after_104_days_uptime(self):
        rows = self.events()
        for row in rows:
            row["occurred_ns"] = str(100_000_000_000_000_000 + row["occurred_ns"])
        self.assertEqual(replay_runtime_events(rows)["invocations"][0]["wall_ns"], 12)

    def test_js_body_excludes_capture_and_ledger_overhead(self):
        rows = self.events()
        rows[2].update(dispatch_begin_ns="2", dispatch_end_ns="3")
        call = replay_runtime_events(rows)["invocations"][0]
        self.assertEqual(call["instrumented_js_dispatch_wall_ns"], 1)
        self.assertEqual(call["js_slices"][0]["timing_basis"],
                         "SYNCHRONOUS_BODY_EXCLUDING_LEDGER_AND_MEMORY_CAPTURE")
        rows[2]["dispatch_begin_ns"] = "0"
        with self.assertRaises(ValueError):
            replay_runtime_events(rows)

    def test_no_js_instrumentation_is_not_a_measured_zero(self):
        rows = [row for row in self.events() if not row["event"].startswith("JS_")]
        for i, row in enumerate(rows):
            row["sequence"] = i + 1
        call = replay_runtime_events(rows)["invocations"][0]
        self.assertIsNone(call["js_ms"])
        self.assertIsNone(call["instrumented_js_dispatch_wall_ns"])
        self.assertIsNone(call["thread_cpu_ms"])
        self.assertEqual(call["js_execution_status"], "NOT_COLLECTED")

    def test_explicit_zero_duration_js_slice_is_measured(self):
        rows = self.events()
        rows[2].update(dispatch_begin_ns=2, dispatch_end_ns=2, thread_cpu_usec=0)
        call = replay_runtime_events(rows)["invocations"][0]
        self.assertEqual(call["js_ms"], 0)
        self.assertEqual(call["thread_cpu_ms"], 0)
        self.assertEqual(call["js_execution_status"], "MEASURED_SLICES")

    def test_jsonl_duplicate_keys_and_truncated_tail_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            path.write_text('{"event":"first","event":"second"}\n')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_code_mode_events(path)
            path.write_text('{"event":"complete-json-without-newline"}')
            with self.assertRaisesRegex(ValueError, "truncated"):
                load_code_mode_events(path)

    def test_app_server_timing_requires_explicit_gateway_and_is_not_js_self_time(self):
        rows = []
        for method, timestamp in (("item/started", 100), ("item/completed", 200)):
            rows.append({"direction": "CODEX_TO_CLIENT", "receipt_ns": timestamp,
                "message": {"method": method, "params": {"threadId": "th", "turnId": "tu",
                    "item": {"id": "c", "type": "dynamicToolCall", "namespace": "functions", "tool": "exec"}}}})
        self.assertEqual(app_server_code_mode_timing(rows)["status"], "NOT_COLLECTED")
        result = app_server_code_mode_timing(rows, selectors=[("dynamicToolCall", "functions", "exec")])
        self.assertEqual(result["invocations"][0]["receipt_duration_ns"], 100)
        self.assertIsNone(result["invocations"][0]["js_execution_ns"])
        self.assertEqual(app_server_code_mode_timing([], enabled=False)["status"], "NOT_ENABLED")
        with self.assertRaises(ValueError):
            app_server_code_mode_timing(rows, selectors=[("dynamicToolCall", "functions", "exec")], enabled=False)

    @unittest.skipUnless(shutil.which("node"), "Node/V8 unavailable")
    def test_actual_node_v8_dispatcher_smoke(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "code-mode.jsonl"
            completed = subprocess.run(["node", str(Path(__file__).with_name("observer-code-mode.mjs")),
                "--ledger", str(ledger)], text=True, capture_output=True, check=True, timeout=15)
            self.assertEqual(json.loads(completed.stdout)["status"], "SUCCEEDED")
            result = replay_code_mode_events(load_code_mode_events(ledger))
            self.assertEqual(result["status"], "COMPLETE")
            call = result["invocations"][0]
            self.assertGreater(call["tool_wait_union_ns"], 10_000_000)
            self.assertGreater(call["tool_wait_sum_ns"], call["tool_wait_union_ns"])
            self.assertGreater(call["instrumented_js_dispatch_wall_ns"], 0)
            self.assertGreater(call["memory"]["rss_bytes"]["max_observed"], 0)
            self.assertEqual(len(call["js_slices"]), 4)
            self.assertEqual(sum(x["purpose"] == "TOOL_DISPATCH" for x in call["js_slices"]), 2)
            self.assertTrue(all(x["timing_basis"] == "SYNCHRONOUS_BODY_EXCLUDING_LEDGER_AND_MEMORY_CAPTURE"
                                for x in call["js_slices"]))
            self.assertEqual(call["runtime"]["engine"], "V8")

    @unittest.skipUnless(shutil.which("node"), "Node/V8 unavailable")
    def test_synchronous_tool_dispatch_is_js_with_no_wait(self):
        call = self.run_node("async ({awaitTool}) => await awaitTool('sync gateway', () => {"
            "const end=performance.now()+20;while(performance.now()<end){};return 7;}, {call_id:'child-sync'})")
        self.assertGreater(call["js_ms"], 15)
        self.assertEqual(call["tool_wait_ms"], 0)
        self.assertEqual(call["tool_waits"], [])
        self.assertEqual(call["js_slices"][0]["purpose"], "TOOL_DISPATCH")
        self.assertEqual(call["js_slices"][0]["child_call_id"], "child-sync")
        self.assertAlmostEqual(call["wall_ms"], call["js_ms"] + call["tool_wait_ms"] + call["other_ms"])

    @unittest.skipUnless(shutil.which("node"), "Node/V8 unavailable")
    def test_async_gateway_sync_prefix_is_js_before_await(self):
        call = self.run_node("async ({awaitTool}) => await awaitTool('async gateway', async () => {"
            "const end=performance.now()+20;while(performance.now()<end){};"
            "await new Promise(resolve=>setTimeout(resolve,25));return 7;}, {call_id:'child-async'})")
        self.assertGreater(call["js_ms"], 15)
        self.assertGreater(call["tool_wait_ms"], 15)
        self.assertLessEqual(call["js_slices"][0]["end_ns"], call["tool_waits"][0]["start_ns"])
        self.assertAlmostEqual(call["wall_ms"], call["js_ms"] + call["tool_wait_ms"] + call["other_ms"])

    @unittest.skipUnless(shutil.which("node"), "Node/V8 unavailable")
    def test_sync_gateway_throw_preserves_failed_js_boundary(self):
        call = self.run_node("async ({awaitTool}) => await awaitTool('throws gateway', () => {"
            "throw new Error('expected fixture failure');}, {call_id:'child-fail'})")
        self.assertEqual(call["status"], "FAILED")
        self.assertEqual(call["js_slices"][0]["status"], "FAILED")
        self.assertEqual(call["tool_wait_ms"], 0)
        self.assertEqual(call["tool_waits"], [])


if __name__ == "__main__":
    unittest.main()
