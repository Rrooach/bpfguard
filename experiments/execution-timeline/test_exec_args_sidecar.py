#!/usr/bin/env python3
from copy import deepcopy
import json
from pathlib import Path
import struct
import tempfile
import unittest
import uuid

from exec_args_sidecar import (ARG_BYTES, ENTRY_BYTES, HEADER, HEADER_BYTES, HEALTH,
    HEALTH_MAGIC, MAGIC, codex_snapshot_contract, correlate_commands, correlate_core_scopes, decode_record, verify_capture)

BOOT = uuid.UUID("11111111-2222-3333-4444-555555555555")


def record(kind=1, seq=1, flags=0, args=None, filename="/bin/bash", result=0, timestamp=None):
    args = args if args is not None else ["/bin/bash", "-lc", "printf hello"]
    lengths, statuses, slots = [0]*8, [0]*8, []
    if kind != 1: args = []; filename = ""
    for index in range(8):
        data = args[index].encode() + b"\0" if index < len(args) else b""
        slots.append(data.ljust(ARG_BYTES, b"\0"))
        if data:
            lengths[index] = len(data); statuses[index] = 2 if len(data) == ARG_BYTES else 1
    name = filename.encode() + b"\0" if kind == 1 else b""
    values = [MAGIC, 1, kind, ENTRY_BYTES if kind == 1 else HEADER_BYTES, flags, BOOT.bytes,
        timestamp or (200 if kind == 1 else 300), seq, 42, 180, 100, 100, 42, result,
        10, 10, 0, 10 if kind == 2 else 0, 59, len(args), len(name), 0,
        *lengths, *statuses, b"bash\0".ljust(16, b"\0"), name.ljust(256, b"\0")]
    return HEADER.pack(*values) + (b"".join(slots) if kind == 1 else b"")


class ExecArgSidecarTests(unittest.TestCase):
    def capture(self, directory, records=None, counters=None, pending=0):
        root = Path(directory)
        data = b"".join(records or [record(), record(2, seq=2)])
        (root / "events.bin").write_bytes(data)
        values = [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
        if counters:
            for index, value in counters.items(): values[index] = value
        (root / "health.bin").write_bytes(HEALTH.pack(HEALTH_MAGIC, 1, HEALTH.size, BOOT.bytes,
            42, 100, 400, len(records) if records is not None else 2, len(data), 256*1024*1024,
            0, 0, 0, pending, *values))
        (root / "ready.json").write_text(json.dumps({"status": "READY", "cgroup_id": 42,
            "scope": "EXACT_CGROUP_ID_NOT_DESCENDANTS"}))
        return root

    def test_binary_layout_and_successful_entry_reconstruction(self):
        self.assertEqual(len(record()), 33200)
        self.assertEqual(len(record(2)), 432)
        row = decode_record(record())
        self.assertEqual(row["argv"], ["/bin/bash", "-lc", "printf hello"])
        self.assertEqual(row["argv_quality"], "COMPLETE_USER_ENTRY_STRINGS")
        with tempfile.TemporaryDirectory() as directory:
            replay = verify_capture(self.capture(directory))
            self.assertEqual(replay["history_status"], "COMPLETE_FOR_SELECTED_EXACT_CGROUP_EXEC_HOOKS")
            self.assertEqual(len(replay["executions"]), 1)
            self.assertEqual(replay["core_syscall_count_increment"], 0)

    def test_exact_unique_command_correlates_but_is_not_strong_causality(self):
        with tempfile.TemporaryDirectory() as directory:
            replay = verify_capture(self.capture(directory))
            result = correlate_commands([{"call_id": "a", "arguments": {
                "command": "/bin/bash -lc 'printf hello'"}}], replay)
            self.assertEqual(result["calls"][0]["status"], "KERNEL_ARGV_EXACT_CORRELATED")
            self.assertIn("not TOCTOU", result["calls"][0]["meaning"])
            result = correlate_commands([{"call_id": "a", "command": "printf hello"}], replay)
            self.assertEqual(result["calls"][0]["status"], "NO_EXACT_ARGV_MATCH")

    def test_argv_truncation_or_read_failure_never_establishes_binding(self):
        long = record(flags=64, args=["x" * (ARG_BYTES - 1)])
        row = decode_record(long)
        self.assertEqual(row["argv_flags"], [2])
        self.assertNotEqual(row["argv_quality"], "COMPLETE_USER_ENTRY_STRINGS")
        failed = bytearray(record(flags=16, args=["abc"]))
        # Exact header argv length/status offsets: first length 128, status 144.
        struct.pack_into("<H", failed, 128, 0); struct.pack_into("<H", failed, 144, 3)
        row = decode_record(bytes(failed))
        self.assertEqual(row["argv"], [""])
        self.assertNotEqual(row["argv_quality"], "COMPLETE_USER_ENTRY_STRINGS")

    def test_negative_exec_syscall_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            replay = verify_capture(self.capture(directory, [record(), record(3, seq=2, result=-2)], {2: 0, 3: 1}))
            self.assertEqual(replay["executions"], [])
            self.assertEqual(replay["record_counts"]["FAILED"], 1)

    def test_open_capture_is_incomplete_not_a_proof_of_no_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            replay = verify_capture(self.capture(directory, [record()], {2: 0, 13: 1}, pending=1))
            self.assertEqual(replay["history_status"], "INCOMPLETE")
            self.assertIn("unclosed_entry_records", replay["reason_flags"])

    def test_drop_sequence_is_retained_and_restricts_correlation(self):
        with tempfile.TemporaryDirectory() as directory:
            replay = verify_capture(self.capture(directory, [record(seq=2), record(2, seq=3)], {6: 1, 13: 3}))
            self.assertEqual(replay["sequence_gaps"], 1)
            self.assertEqual(replay["history_status"], "INCOMPLETE")
            result = correlate_commands([{"call_id": "a", "command": "/bin/bash -lc 'printf hello'"}], replay)
            self.assertEqual(result["calls"][0]["status"], "EXACT_ARGV_CANDIDATE_CAPTURE_INCOMPLETE")

    def test_duplicate_application_claims_are_not_unique(self):
        with tempfile.TemporaryDirectory() as directory:
            replay = verify_capture(self.capture(directory))
            calls = [{"call_id": value, "command": "/bin/bash -lc 'printf hello'"} for value in ("a", "b")]
            result = correlate_commands(calls, replay)
            self.assertTrue(all(row["status"] == "AMBIGUOUS_APPLICATION_CALLS_CLAIM_SAME_EXEC" for row in result["calls"]))

    def test_incomplete_other_exec_cannot_be_silently_excluded_from_uniqueness(self):
        with tempfile.TemporaryDirectory() as directory:
            replay = verify_capture(self.capture(directory))
            unknown = deepcopy(replay["executions"][0])
            unknown["entry"].update(flags=8, argv_quality="INCOMPLETE_OR_NOT_AN_ENTRY")
            replay["executions"].append(unknown)
            calls = [{"call_id": "a", "command": "/bin/bash -lc 'printf hello'"}]
            result = correlate_commands(calls, replay)
            self.assertEqual(result["calls"][0]["status"], "EXACT_ARGV_CANDIDATE_OTHER_EXEC_ARGV_INCOMPLETE")
            unknown["entry"]["argv_hex"][0] = b"/different/program".hex()
            result = correlate_commands(calls, replay)
            self.assertEqual(result["calls"][0]["status"], "KERNEL_ARGV_EXACT_CORRELATED")

    def test_corrupted_padding_flags_sequence_and_manifest_fail(self):
        for mutation in ("padding", "flag", "sequence", "tail", "health", "boot"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = self.capture(directory)
                data = bytearray((root / "events.bin").read_bytes())
                if mutation == "padding": data[HEADER_BYTES + 200] = 1
                if mutation == "flag": struct.pack_into("<I", data, 12, 128)
                if mutation == "sequence": struct.pack_into("<Q", data, ENTRY_BYTES + 40, 1)
                if mutation == "tail": data.pop()
                if mutation == "boot": data[16] ^= 1
                if mutation == "health":
                    health = bytearray((root / "health.bin").read_bytes()); health[56] ^= 1
                    (root / "health.bin").write_bytes(health)
                (root / "events.bin").write_bytes(data)
                with self.assertRaises(ValueError): verify_capture(root)
        with tempfile.TemporaryDirectory() as directory:
            root = self.capture(directory)
            with self.assertRaises(ValueError): verify_capture(root, {"events.bin": {"sha256": "wrong", "size_bytes": 0}})

    def test_projected_json_cannot_override_binary_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.capture(directory)
            (root / "events.jsonl").write_text('{"argv":["invented"]}\n')
            replay = verify_capture(root)
            self.assertEqual(replay["executions"][0]["entry"]["argv"][0], "/bin/bash")

    def core(self):
        root_key = str(BOOT) + ":10:100"
        child_key = str(BOOT) + ":11:260"
        root = {"key": root_key, "tid": 10, "tgid": 10, "birth_ns": 100, "process_birth_ns": 100,
            "end_ns": 390, "execs": [{"timestamp_ns": 250, "old_tid": 10,
                "evidence": "KERNEL_SCHED_PROCESS_EXEC_SUCCESS"}],
            "calls": [{"start_ns": 180, "end_ns": 245}, {"start_ns": 251, "end_ns": 255}]}
        child = {"key": child_key, "tid": 11, "tgid": 11, "birth_ns": 260, "process_birth_ns": 260,
            "end_ns": 380, "parent_key": root_key, "execs": [],
            "fork_event": {"event": "FORK", "timestamp_ns": 265, "peer_quality": "STABLE_TASK_IDENTITY",
                "peer": {"tid": 10, "tgid": 10, "thread_birth_ns": 100, "process_birth_ns": 100, "cgroup_id": 42},
                "task": {"tid": 11, "tgid": 11, "thread_birth_ns": 260, "process_birth_ns": 260, "cgroup_id": 42}},
            "calls": [{"start_ns": 270, "end_ns": 280}]}
        unrelated = {"key": str(BOOT) + ":99:100", "tid": 99, "tgid": 99, "birth_ns": 100,
            "process_birth_ns": 100, "end_ns": 380, "execs": [],
            "calls": [{"start_ns": 270, "end_ns": 280}]}
        return {"run": {"boot_id": str(BOOT), "end_ns": 400},
            "health": {"status": "COMPLETE_FOR_SELECTED_HOOKS", "counters": {"ring_drops": 0}},
            "threads": [root, child, unrelated]}

    def test_core_scope_uses_exec_lifetime_and_fork_graph_not_shared_group(self):
        with tempfile.TemporaryDirectory() as directory:
            replay = verify_capture(self.capture(directory))
            calls = correlate_commands([{"call_id": "a", "command": "/bin/bash -lc 'printf hello'"}], replay)
            core = self.core(); before = deepcopy(core)
            joined = correlate_core_scopes(calls, replay, core, {"status": "REPLAY_PASSED"})
            row = joined["calls"][0]
            self.assertEqual(row["status"], "KERNEL_ARGV_AND_CORE_EXEC_IDENTITY_CORRELATED")
            self.assertEqual(row["syscall_count"], 2)
            self.assertEqual([scope["call_indices"] for scope in row["thread_ranges"]], [[1], [0]])
            self.assertEqual(len(row["thread_ranges"]), 2)
            self.assertEqual(joined["core_syscall_count_increment"], 0)
            self.assertEqual(core, before)

    def test_core_scope_rejects_forged_candidate_multiple_exec_and_bad_fork(self):
        with tempfile.TemporaryDirectory() as directory:
            replay = verify_capture(self.capture(directory))
            calls = correlate_commands([{"call_id": "a", "command": "/bin/bash -lc 'printf hello'"}], replay)
            forged = deepcopy(calls); forged["calls"][0]["candidates"][0]["tid"] = 99
            result = correlate_core_scopes(forged, replay, self.core(), {"status": "REPLAY_PASSED"})
            self.assertEqual(result["calls"][0]["status"], "ARGV_CORRELATION_NOT_BOUND_TO_REPLAY")
            core = self.core(); core["threads"][0]["execs"].append(deepcopy(core["threads"][0]["execs"][0]))
            result = correlate_core_scopes(calls, replay, core, {"status": "REPLAY_PASSED"})
            self.assertEqual(result["calls"][0]["status"], "CORE_SIDECAR_SUCCESSFUL_EXEC_SEQUENCE_COUNT_MISMATCH")
            core = self.core(); core["threads"][1]["fork_event"]["peer"]["thread_birth_ns"] = 999
            result = correlate_core_scopes(calls, replay, core, {"status": "REPLAY_PASSED"})
            self.assertEqual(result["calls"][0]["syscall_count"], 1)
            result = correlate_core_scopes(calls, replay, self.core())
            self.assertEqual(result["calls"][0]["status"], "CORE_INDEPENDENT_REPLAY_RECEIPT_REQUIRED")

    def test_codex_snapshot_projection_is_opt_in_versioned_and_script_exact(self):
        app = {"thread_id": "thread-a"}
        rpc = [{"message": {"result": {"thread": {"id": "thread-a", "cliVersion": "0.154.0"}}}}]
        config = {"native_shell": "ENABLED", "dynamic_tools": "NONE"}
        contract = codex_snapshot_contract(app, rpc, config)
        with self.assertRaises(ValueError): codex_snapshot_contract(app, [], config)
        with tempfile.TemporaryDirectory() as directory:
            replay = verify_capture(self.capture(directory, [record(args=["/bin/bash", "-c", "printf hello"]), record(2, seq=2)]))
            call = {"call_id": "a", "tool_name": "commandExecution", "arguments": {
                "source": "unifiedExecStartup", "command": "/bin/bash -lc 'printf hello'"}}
            self.assertEqual(correlate_commands([call], replay)["calls"][0]["status"], "NO_EXACT_ARGV_MATCH")
            adapted = correlate_commands([call], replay, contract)["calls"][0]
            self.assertEqual(adapted["status"], "KERNEL_ARGV_CODEX_SNAPSHOT_PROJECTED_CORRELATED")
            self.assertEqual(adapted["argv_projection"]["script_comparison"], "EXACT_BYTES")
            changed = deepcopy(call); changed["arguments"]["command"] += "x"
            self.assertEqual(correlate_commands([changed], replay, contract)["calls"][0]["status"], "NO_EXACT_ARGV_MATCH")
            changed = deepcopy(call); changed["arguments"]["source"] = "unknown"
            self.assertEqual(correlate_commands([changed], replay, contract)["calls"][0]["status"], "NO_EXACT_ARGV_MATCH")
            malformed = deepcopy(call); malformed["arguments"]["command"] = '/bin/bash -lc "'
            self.assertEqual(correlate_commands([malformed], replay, contract)["calls"][0]["status"], "NO_PARSEABLE_NATIVE_COMMAND")
            malformed["arguments"]["command"] = ["/bin/bash", "-lc", None]
            self.assertEqual(correlate_commands([malformed], replay, contract)["calls"][0]["status"], "NO_PARSEABLE_NATIVE_COMMAND")

    def test_multi_exec_scope_requires_equal_complete_sequence_and_closed_lifetime(self):
        with tempfile.TemporaryDirectory() as directory:
            replay = verify_capture(self.capture(directory))
            initial = deepcopy(replay["executions"][0])
            initial["entry"]["wal_offset"] = 999; initial["success"]["wal_offset"] = 1000
            initial["success"]["timestamp_ns"] = 220
            initial["entry"]["argv_hex"] = [b"different".hex()]
            replay["executions"].insert(0, initial)
            calls = correlate_commands([{"call_id": "a", "command": "/bin/bash -lc 'printf hello'",
                "result_delivered_ns": 395}], replay)
            core = self.core()
            core["threads"][0]["execs"].insert(0, {"timestamp_ns": 210, "old_tid": 10,
                "evidence": "KERNEL_SCHED_PROCESS_EXEC_SUCCESS"})
            joined = correlate_core_scopes(calls, replay, core, {"status": "REPLAY_PASSED"})
            self.assertEqual(joined["calls"][0]["status"], "MULTI_EXEC_SCOPE_REQUIRES_KERNEL_EXIT_BEFORE_APP_COMPLETION")
            core["threads"][0]["exit_ns"] = 390
            joined = correlate_core_scopes(calls, replay, core, {"status": "REPLAY_PASSED"})
            self.assertEqual(joined["calls"][0]["status"], "KERNEL_ARGV_AND_CORE_EXEC_IDENTITY_CORRELATED")
            self.assertEqual(joined["calls"][0]["exec_sequence_alignment"]["matched_position"], 1)
            self.assertEqual(joined["calls"][0]["syscall_count"], 2)


if __name__ == "__main__": unittest.main()
