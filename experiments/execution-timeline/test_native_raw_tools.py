#!/usr/bin/env python3
"""Synthetic protocol fixtures only; no model or external API calls."""
from copy import deepcopy
import unittest

from native_raw_tools import NativeRawTools,replay_native_raw_tools


def item(value):
    return {"method":"rawResponseItem/completed","params":{"threadId":"t","turnId":"u","item":value}}


class NativeRawToolTests(unittest.TestCase):
    def request(self,call_id="model-call"):
        return item({"type":"custom_tool_call","call_id":call_id,"name":"exec","input":"const r=await tools.exec_command({cmd:'grep x a'});text(r.output);"})

    def test_original_exec_js_and_matching_output_wall_not_js_cpu(self):
        replay=NativeRawTools("t","u")
        replay.accept(self.request(),1000000000)
        replay.accept({"method":"rawResponse/completed","params":{"threadId":"t","turnId":"u","responseId":"resp",
            "usage":{"inputTokens":100,"outputTokens":20,"totalTokens":120}}},1100000000)
        replay.accept(item({"type":"custom_tool_call_output","call_id":"model-call","output":"actual output"}),2000000000)
        result=replay.projection();call=result["native_model_tool_calls"][0]
        self.assertEqual(call["runtime"],"NATIVE_CODE_MODE")
        self.assertEqual(call["request_to_output_ms"],1000)
        self.assertEqual(call["response_id"],"resp")
        self.assertIsNone(call["v8_cpu_ms"]);self.assertIsNone(call["v8_js_ms"])
        self.assertEqual(call["child_call_ids"],[])
        self.assertEqual(call["output"]["text"],"actual output")
        self.assertEqual(result["native_model_responses"][0]["output_tool_call_ids"],["model-call"])
        self.assertEqual(result["native_model_responses"][0]["usage"]["inputTokens"],100)

    def test_exact_call_id_pairing_with_parallel_outputs(self):
        replay=NativeRawTools("t","u")
        replay.accept(self.request("a"),10);replay.accept(self.request("b"),11)
        replay.accept(item({"type":"custom_tool_call_output","call_id":"b","output":"b-out"}),20)
        replay.accept(item({"type":"custom_tool_call_output","call_id":"a","output":"a-out"}),30)
        self.assertEqual([x["output"]["text"] for x in replay.projection()["native_model_tool_calls"]],["a-out","b-out"])

    def test_missing_output_is_kept_incomplete_not_invented_success(self):
        replay=NativeRawTools("t","u");replay.accept(self.request(),10)
        self.assertEqual(replay.projection()["native_model_tool_calls"][0]["status"],"OUTPUT_NOT_OBSERVED")

    def test_unknown_output_duplicate_request_wrong_turn_or_negative_usage_rejected(self):
        values=[item({"type":"custom_tool_call_output","call_id":"unknown","output":"x"}),
            {"method":"rawResponse/completed","params":{"threadId":"t","turnId":"u","responseId":"r","usage":{"totalTokens":-1}}}]
        for value in values:
            with self.subTest(value=value),self.assertRaises(ValueError):NativeRawTools("t","u").accept(value,10)
        replay=NativeRawTools("t","u");replay.accept(self.request(),10)
        with self.assertRaises(ValueError):replay.accept(self.request(),11)
        value=self.request();value["params"]["turnId"]="other"
        with self.assertRaises(ValueError):NativeRawTools("t","u").accept(value,1)

    def test_offline_replay_reuses_original_rpc_receipts_without_writing(self):
        rows=[{"direction":"CODEX_TO_CLIENT","receipt_ns":10,"message":self.request()},
            {"direction":"CODEX_TO_CLIENT","receipt_ns":20,"message":item({"type":"custom_tool_call_output",
                "call_id":"model-call","output":"done"})}]
        original=deepcopy(rows)
        result=replay_native_raw_tools(rows,thread_id="t",turn_id="u")
        self.assertEqual(result["native_model_tool_calls"][0]["request_received_ns"],10)
        self.assertEqual(rows,original)


if __name__=="__main__":unittest.main()
