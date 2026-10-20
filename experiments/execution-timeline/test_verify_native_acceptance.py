import copy
import json
from pathlib import Path
import tempfile
import unittest

from native_raw_tools import replay_native_raw_tools
from verify_native_acceptance import completed_sse, reconcile_projection, verify_provider


class AcceptanceTests(unittest.TestCase):
    def projection(self):
        rows = []
        for ns, item in ((10, {"type": "custom_tool_call", "call_id": "call-a", "name": "exec", "input": "text(1)"}),
                         (30, {"type": "custom_tool_call_output", "call_id": "call-a", "output": "1"})):
            rows.append({"direction": "CODEX_TO_CLIENT", "receipt_ns": ns, "message": {
                "method": "rawResponseItem/completed", "params": {"threadId": "t", "turnId": "r", "item": item}}})
        return replay_native_raw_tools(rows, thread_id="t", turn_id="r")

    def test_handler_receipt_is_not_raw_rpc_receipt(self):
        projection = self.projection()
        app = copy.deepcopy(projection)
        call = app["native_model_tool_calls"][0]
        call["request_received_ns"] += 3
        call["output_received_ns"] += 5
        call["source_request"]["receipt_ns"] += 3
        call["source_output"]["receipt_ns"] += 5
        call["request_to_output_ms"] += 2 / 1000000
        result = reconcile_projection(app, projection)
        self.assertEqual(result[0]["handler_after_raw_ns"], {"request_received_ns": 3, "output_received_ns": 5})
        self.assertEqual(projection["native_model_tool_calls"][0]["request_received_ns"], 10)

    def test_content_change_is_not_accepted_as_clock_difference(self):
        projection = self.projection()
        app = copy.deepcopy(projection)
        app["native_model_tool_calls"][0]["request"]["text"] = "other command"
        with self.assertRaisesRegex(ValueError, "content/identity"):
            reconcile_projection(app, projection)

    def test_source_cannot_predate_raw_receipt(self):
        projection = self.projection()
        app = copy.deepcopy(projection)
        app["native_model_tool_calls"][0]["source_request"]["receipt_ns"] -= 1
        with self.assertRaisesRegex(ValueError, "predates raw"):
            reconcile_projection(app, projection)

    def test_ambiguous_completed_sse_rejected(self):
        block = b'data: {"type":"response.completed","response":{"id":"a"}}\n\n'
        self.assertEqual(completed_sse(block)["id"], "a")
        with self.assertRaises(ValueError):
            completed_sse(block + block)

    def test_provider_mapping_and_usage_replayed_not_trusted(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent-benchmarks"))
        from native_provider_wire import prepare_request, restore_response
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = {"model": "test-model", "tools": [{"type": "custom", "name": "exec"}], "input": []}
            provider, receipt = prepare_request(native)
            usage = {"input_tokens": 5, "output_tokens": 2, "total_tokens": 7}
            response = {"type": "response.completed", "response": {"id": "response-a", "usage": usage, "output": []}}
            upstream = b'data: ' + json.dumps(response).encode() + b'\n\n'
            delivered = restore_response(upstream, receipt)
            values = {"-native-request.json": native, "-request.json": provider, "-wire-adapter.json": receipt}
            for suffix, value in values.items():
                (root / ("label-step-0" + suffix)).write_text(json.dumps(value))
            (root / "label-step-0-upstream.sse").write_bytes(upstream)
            (root / "label-step-0-delivered.sse").write_bytes(delivered)
            projection = {"native_model_responses": [{"response_id": "response-a", "usage": {
                "inputTokens": 5, "outputTokens": 2, "totalTokens": 7}}]}
            timing = [{"provider_response_id": "response-a", "request_id": "request-a", "boot_id": "boot-a"}]
            result = verify_provider(root, "label", projection, timing, "boot-a")
            self.assertEqual(len(result), 1)
            self.assertNotIn("input", result[0])
            projection["native_model_responses"][0]["usage"]["totalTokens"] = 8
            with self.assertRaisesRegex(ValueError, "usage differ"):
                verify_provider(root, "label", projection, timing, "boot-a")


if __name__ == "__main__":
    unittest.main()
