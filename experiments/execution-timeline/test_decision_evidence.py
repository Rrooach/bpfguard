#!/usr/bin/env python3
import copy
import unittest
from unittest.mock import patch

from decision_evidence import build_decision_evidence


class DecisionEvidenceTests(unittest.TestCase):
    def fixture(self):
        root = {"tid": 20, "start_ticks": 100, "clock_ticks": 100}
        binding = {"thread_id": "thread", "turn_id": "turn", "call_id": "call",
            "agent_id": "agent", "task_id": "task",
            "observer_tool_call_id": "tool", "tool_call_id": "tool", "boot_id": "boot",
            "root": root, "cgroup_id": 12, "begin_ns": 1_010_000_000,
            "end_ns": 1_300_000_000, "command": "cat file"}
        call = {"thread_id": "thread", "turn_id": "turn", "call_id": "call", "tool_name": "shell",
            "agent_id": "agent", "task_id": "task", "execution_begin_ns": 1_010_000_000,
            "execution_end_ns": 1_300_000_000, "execution_tool_call_id": "tool", "root": root, "cgroup_id": 12}
        application = {"thread_id": "thread", "turn_id": "turn", "function_bindings": [binding],
            "tool_calls": [call], "steps": [
                {"kind": "AGENT_MESSAGE", "thread_id": "thread", "turn_id": "turn", "item_id": "plan",
                 "text": "Inspect the file"},
                {"kind": "TOOL_CALL", "thread_id": "thread", "turn_id": "turn", "call_id": "call"}]}
        report = {"run": {"boot_id": "boot"}, "tools": [{"tool_call_id": "tool", **{
            key: value for key, value in binding.items() if key not in
            ("observer_tool_call_id", "tool_call_id", "thread_id", "turn_id", "call_id")}}],
            "threads": [{"tool_call_id": "tool", "key": "boot:20:1001000000", "tid": 20, "tgid": 20,
                "birth_ns": 1_001_000_000, "process_birth_ns": 1_001_000_000,
                "calls": [{"name": "read", "nr": 0, "call_id": 1_030_000_000,
                    "start_ns": 1_030_000_000, "end_ns": 1_050_000_000, "pairing": "PAIRED",
                    "result": 20, "files": [{"path": "/src/file", "mount_id": 2,
                        "device": 3, "inode": 4, "generation": 0}]}]}],
            "health": {"status": "INCOMPLETE"}, "critical_path": {"status": "INCOMPLETE"}}
        return application, report

    def test_exact_ids_and_object_references_do_not_become_causal_intent(self):
        app, report = self.fixture()
        evidence = build_decision_evidence(app, report)
        self.assertEqual(evidence["status"], "PARTIAL")  # raw RPC not replayed
        chain = evidence["chains"][0]
        self.assertEqual(chain["edges"][0]["status"], "ORDERED_CONTEXT_ONLY")
        self.assertEqual(chain["edges"][2]["status"], "MATCHED")
        self.assertEqual(chain["edges"][3]["status"], "MATCHED")
        call = chain["observations"][0]
        self.assertEqual(call["evidence_ref"], "report#/threads/0/calls/0")
        self.assertEqual(call["objects"][0]["status"], "KERNEL_OBJECT_FIELDS")
        self.assertEqual(evidence["operation_history_status"], "INCOMPLETE")

    def test_protocol_demo_with_zero_kernel_events_never_claims_full_chain(self):
        app, report = self.fixture(); report["threads"] = []
        evidence = build_decision_evidence(app, report, verification={"status": "PROTOCOL_VALIDATION_PASSED"})
        self.assertEqual(evidence["status"], "PARTIAL")
        self.assertEqual(evidence["summary"]["kernel_syscall_observations"], 0)
        self.assertEqual(evidence["chains"][0]["edges"][3]["status"], "MISSING")
        self.assertIn("不能声称", evidence["chains"][0]["summary"])

    def test_pid_reuse_cannot_bind_by_tid_alone(self):
        app, report = self.fixture(); report["threads"][0].update(
            birth_ns=2_001_000_000, key="boot:20:2001000000")
        evidence = build_decision_evidence(app, report)
        self.assertEqual(evidence["chains"][0]["edges"][3]["status"], "MISSING")

    def test_boot_or_cgroup_mismatch_is_explicit_conflict(self):
        for field, value in (("boot_id", "another-boot"), ("cgroup_id", 55)):
            app, report = self.fixture(); app["function_bindings"][0][field] = value
            self.assertEqual(build_decision_evidence(app, report)["status"], "CONFLICT")

    def test_same_timestamp_or_text_in_other_turn_cannot_supply_context(self):
        app, report = self.fixture(); app["steps"][0]["turn_id"] = "other-turn"
        chain = build_decision_evidence(app, report)["chains"][0]
        self.assertIsNone(chain["context"])
        self.assertEqual(chain["edges"][0]["status"], "MISSING")

    def test_no_later_message_can_backfill_missing_intent(self):
        app, report = self.fixture(); app["steps"].reverse()
        self.assertIsNone(build_decision_evidence(app, report)["chains"][0]["context"])

    def test_duplicate_native_mapping_is_rejected(self):
        app, report = self.fixture(); extra = copy.deepcopy(app["function_bindings"][0]); extra["call_id"] = "second"
        app["function_bindings"].append(extra)
        with self.assertRaisesRegex(ValueError, "multiple application calls"):
            build_decision_evidence(app, report)

    def test_large_evidence_keeps_explicit_truncation_not_green(self):
        app, report = self.fixture(); report["threads"][0]["calls"] *= 2
        result = build_decision_evidence(app, report, max_observations=1)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["chains"][0]["edges"][-1]["status"], "TRUNCATED")
        self.assertEqual(result["chains"][0]["edges"][-1]["omitted_observations"], 1)

    def test_supplied_replay_status_is_not_a_replay_execution(self):
        app, report = self.fixture()
        result = build_decision_evidence(app, report, verification={"status": "REPLAY_PASSED"})
        self.assertEqual(result["application_source_replay"]["status"], "NOT_REPLAYED")
        self.assertEqual(result["native_replay"]["status"], "REPLAY_RECEIPT_PROVIDED")
        self.assertEqual(result["status"], "PARTIAL")

    def test_raw_projection_failure_is_visible_not_suppressed(self):
        app, report = self.fixture()
        result = build_decision_evidence(app, report, rpc_rows=[], tool_events=[])
        self.assertEqual(result["status"], "CONFLICT")
        self.assertEqual(result["application_source_replay"]["status"], "FAILED")

    def test_full_links_still_keep_incomplete_history_independent(self):
        app, report = self.fixture()
        with patch("decision_evidence._source_replay", return_value={"status": "RAW_APPLICATION_REPLAY_PASSED"}):
            result = build_decision_evidence(app, report)
        self.assertEqual(result["status"], "LINKED_WITHIN_SELECTED_EVIDENCE")
        self.assertEqual(result["operation_history_status"], "INCOMPLETE")

    def test_application_message_cannot_impersonate_raw_codex_message(self):
        app, report = self.fixture()
        rpc = [{"direction": "CODEX_TO_CLIENT", "message": {"method": "item/completed", "params": {
            "threadId": "thread", "turnId": "turn", "item": {"id": "plan", "type": "agentMessage",
            "text": "A different message"}}}}]
        result = build_decision_evidence(app, report, rpc_rows=rpc)
        self.assertEqual(result["chains"][0]["edges"][0]["status"], "CONFLICT")
        self.assertEqual(result["status"], "CONFLICT")

    def test_agent_identity_cannot_be_borrowed_from_another_call(self):
        app, report = self.fixture(); app["function_bindings"][0]["agent_id"] = "someone-else"
        result = build_decision_evidence(app, report)
        self.assertEqual(result["status"], "CONFLICT")


if __name__ == "__main__":
    unittest.main()
