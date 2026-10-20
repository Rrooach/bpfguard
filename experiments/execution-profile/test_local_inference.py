import dataclasses
import json
import tempfile
import unittest
from pathlib import Path

from local_inference import validate_logical_kv, verify_native
from semantic import Context, identity


class NativeFixtureTests(unittest.TestCase):
    def kv(self):
        return {"schema_version": 1, "status": "OBSERVED_LOGICAL_KV",
            "scope": "SHARED_LLAMA_CONTEXT_LOGICAL_NOT_REQUEST_ALLOCATION", "captured_at": "ENGINE_COMPLETE_HANDLER_ENTRY",
            "token_sequence_associations": 4, "used_cells": 2, "context_capacity_tokens": 512,
            "capacity_cells": 512, "capacity_cells_basis": "PUBLIC_CONTEXT_CAPACITY_NONRECURRENT_MODEL",
            "sequence_capacity": 2, "batch_capacity_tokens": 128, "microbatch_capacity_tokens": 128,
            "model_recurrent": False, "allocated_bytes": None, "allocated_bytes_status": "UNKNOWN_PUBLIC_API_NOT_EXPOSED",
            "gpu_memory": {"status": "UNKNOWN_NO_GPU_BACKEND", "framework_allocated_bytes": None,
                           "framework_reserved_bytes": None, "device_used_bytes": None},
            "source_apis": ["llama_get_kv_cache_token_count", "llama_get_kv_cache_used_cells", "llama_n_ctx", "llama_n_seq_max",
                            "llama_n_batch", "llama_n_ubatch", "llama_model_is_recurrent"],
            "collection_start_ns": 7, "collection_end_ns": 8}

    def test_kv_logical_counts_not_unique_tokens_or_rss_bytes(self):
        value = self.kv()
        self.assertEqual(validate_logical_kv(value, 9)["token_sequence_associations"], 4)
        self.assertEqual(value["used_cells"], 2)
        events, expected = self.fixture()
        events[-1]["details"]["logical_kv"] = value
        result = self.replay(events, expected)
        self.assertTrue(result["verified"], result)
        self.assertEqual(result["logical_kv_by_request_completion"]["request"]["allocated_bytes"], None)

    def test_kv_missing_is_unknown_and_gpu_rss_capacity_forgeries_rejected(self):
        self.assertEqual(validate_logical_kv(None, 9)["status"], "UNKNOWN_LEGACY_NATIVE_TRACE_DID_NOT_COLLECT")
        for kind in ("GPU", "RSS", "CAPACITY", "CLOCK"):
            value = self.kv()
            if kind == "GPU":
                value["gpu_memory"]["device_used_bytes"] = 1048576
            elif kind == "RSS":
                value["allocated_bytes"] = 1048576
            elif kind == "CAPACITY":
                value["used_cells"] = 513
            else:
                value["collection_end_ns"] = 100
            with self.assertRaises(ValueError, msg=kind):
                validate_logical_kv(value, 9)

    def fixture(self):
        context = json.loads(json.dumps(dataclasses.asdict(Context("run", "A", "agent-A", request_id="request"))))
        actor = identity()
        member = {"context": context, "native_task_id": 1, "slot_id": 0}
        batch = {"batch_id": "batch", "members": [member], "tokens": 1}
        events = []
        def emit(kind, ctx=context, details=None):
            events.append({"schema_version": 1, "seq": len(events) + 1, "monotonic_ns": len(events) + 1,
                           "kind": kind, "context": ctx, "details": details or {}, "backend": "CPU", "actor": actor})
        for state in ("ACCEPTED", "QUEUED", "SCHEDULED"):
            emit("ENGINE_" + state, details={"native_task_id": 1, "slot_id": 0})
        emit("ENGINE_BATCH_BEGIN", {}, batch)
        emit("ENGINE_WORKER_BEGIN", {}, {**batch, "worker_index": 0})
        emit("ENGINE_WORKER_END", {}, {**batch, "worker_index": 0})
        emit("ENGINE_BATCH_END", {}, {**batch, "return_code": 0})
        emit("ENGINE_FIRST_TOKEN")
        emit("ENGINE_COMPLETE", details={"output_tokens": 1})
        return events, {"request": context}

    def replay(self, events, expected):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "native.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in events))
            return verify_native(path, expected)

    def test_explicit_native_worker_batch_interval(self):
        events, expected = self.fixture()
        result = self.replay(events, expected)
        self.assertTrue(result["verified"], result)
        self.assertEqual(len(result["ggml_worker_processing_intervals"]), 1)
        self.assertEqual(result["gpu_status"], "NOT_AVAILABLE")

    def test_native_zero_tid_forged_owner_and_early_batch_end_rejected(self):
        events, expected = self.fixture()
        forged = json.loads(json.dumps(events))
        forged[4]["actor"]["tid"] = 0
        self.assertFalse(self.replay(forged, expected)["verified"])
        forged = json.loads(json.dumps(events))
        forged[4]["details"]["members"][0]["context"]["agent_id"] = "wrong"
        self.assertFalse(self.replay(forged, expected)["verified"])
        forged = json.loads(json.dumps(events))
        forged[5], forged[6] = forged[6], forged[5]
        for seq, row in enumerate(forged, 1):
            row["seq"], row["monotonic_ns"] = seq, seq
        self.assertFalse(self.replay(forged, expected)["verified"])

    def test_two_request_actual_batch_and_wrong_slot_rejection(self):
        events, expected = self.fixture()
        events = json.loads(json.dumps(events))
        other = {**expected["request"], "task_id": "B", "agent_id": "agent-B", "request_id": "request-B"}
        expected["request-B"] = other
        actor = events[0]["actor"]
        admission = [{"schema_version": 1, "kind": "ENGINE_" + state, "context": other,
                      "details": {"native_task_id": 2, "slot_id": 1}, "backend": "CPU", "actor": actor}
                     for state in ("ACCEPTED", "QUEUED", "SCHEDULED")]
        events[3:3] = admission
        for event in events:
            if event["kind"].startswith(("ENGINE_BATCH_", "ENGINE_WORKER_")):
                event["details"]["members"].append({"context": other, "native_task_id": 2, "slot_id": 1})
        events += [{"schema_version": 1, "kind": "ENGINE_" + state, "context": other,
                    "details": {"output_tokens": 1}, "backend": "CPU", "actor": actor}
                   for state in ("FIRST_TOKEN", "COMPLETE")]
        for sequence, event in enumerate(events, 1):
            event["seq"], event["monotonic_ns"] = sequence, sequence
        result = self.replay(events, expected)
        self.assertTrue(result["verified"], result)
        self.assertEqual(result["maximum_observed_batch_members"], 2)
        self.assertEqual(result["dynamic_multi_member_batch_e2e"], "OBSERVED_REAL_MULTI_MEMBER_DECODE")
        forged = json.loads(json.dumps(events))
        forged[6]["details"]["members"][1]["slot_id"] = 0
        self.assertFalse(self.replay(forged, expected)["verified"])
        forged = json.loads(json.dumps(events))
        forged[7]["details"]["members"][1]["slot_id"] = 0
        self.assertFalse(self.replay(forged, expected)["verified"])

    def test_light_declares_uncollected_workers_and_selected_batches(self):
        events, expected = self.fixture()
        events = [event for event in events if not event["kind"].startswith("ENGINE_WORKER_")]
        for sequence, event in enumerate(events, 1):
            event["seq"], event["monotonic_ns"], event["native_profile"] = sequence, sequence, "LIGHT"
        result = self.replay(events, expected)
        self.assertTrue(result["verified"], result)
        self.assertEqual(result["worker_coverage"], "NOT_COLLECTED_LIGHT")
        self.assertEqual(result["batch_coverage"], "MEMBERSHIP_CHANGE_BATCHES_ONLY_NOT_FULL_GRAPH_HISTORY")
        self.assertIsNone(result["total_actual_batch_count"])
        self.assertEqual(result["selected_membership_change_batch_count"], 1)
        self.assertEqual(result["thread_processing_intervals"][0]["interval_kind"], "SINGLE_ACTUAL_LLAMA_DECODE_CALL")
        forged = json.loads(json.dumps(events))
        forged[4]["details"]["members"][0]["context"]["agent_id"] = "wrong"
        self.assertFalse(self.replay(forged, expected)["verified"])

    def test_empty_or_missing_native_is_not_zero_work_success(self):
        self.assertFalse(self.replay([], {})["verified"])
        events, expected = self.fixture()
        self.assertFalse(self.replay([], expected)["verified"])


if __name__ == "__main__":
    unittest.main()
