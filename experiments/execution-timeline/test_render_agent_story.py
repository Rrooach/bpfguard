#!/usr/bin/env python3
import unittest

from render_agent_story import build_story, read_rpc_usage, render


class AgentStoryTests(unittest.TestCase):
    def fixture(self):
        tool = {"tool_call_id":"linux-1","agent_id":"agent","task_id":"task","begin_ns":130,
            "end_ns":180,"command":"echo x","result":{"return_code":0},"root":{"tid":10}}
        report = {"schema_version":1,"run":{"run_id":"r","boot_id":"b","begin_ns":90,"end_ns":220},
            "tools":[tool,{**tool,"tool_call_id":"grader"}],"threads":[{"tool_call_id":"linux-1",
                "tid":10,"tgid":10,"process_birth_ns":100,"comm":"sh","execs":[{"timestamp_ns":140,
                    "filename":"/bin/sh","comm":"sh"}],"calls":[{"nr":0,"name":"read","start_ns":145,
                    "end_ns":150,"pairing":"PAIRED","result":3,"files":[{"path":"/work/a","read":{
                        "start_ns":146,"end_ns":149,"requested_bytes":8,"returned_bytes":3}}]}]}],
            "critical_path":{"status":"RECONSTRUCTED_WITHIN_SELECTED_MODEL","tools":[{
                "tool_call_id":"linux-1","status":"RECONSTRUCTED_WITHIN_SELECTED_MODEL"}]},
            "totals":{"events":9},"health":{"status":"COMPLETE_FOR_SELECTED_HOOKS","counters":{"ring_drops":0}}}
        call = {"call_id":"app-1","tool_name":"observer_bash","status":"SUCCEEDED","exit_code":0,
            "requested_ns":120,"result_delivered_ns":190}
        binding = {"call_id":"app-1","observer_tool_call_id":"linux-1","task_id":"task","agent_id":"agent",
            "command":"echo x","begin_ns":130,"end_ns":180,"root_pid":10,"gate_result":{"return_code":0,
                "stdout_bytes":2,"stderr_bytes":0}}
        app = {"begin_ns":100,"end_ns":200,"model":"deepseek","status":"completed",
            "function_bindings":[binding],"tool_calls":[call],"errors":[]}
        return report, app

    def test_application_tool_maps_to_process_syscall_and_file(self):
        report, app = self.fixture()
        story = build_story(report, app, {"resolved":True}, {"status":"REPLAY_PASSED"})
        self.assertEqual(story["tool_count"], 1)
        self.assertEqual(story["total_syscalls"], 1)
        self.assertEqual(story["total_read_bytes"], 3)
        self.assertEqual(story["tools"][0]["syscall_rows"][0]["name"], "read")
        self.assertEqual(story["tools"][0]["syscall_rows"][0]["paths"], ["/work/a"])
        self.assertNotIn("grader", [tool["tool_call_id"] for tool in story["tools"]])

    def test_html_is_human_hierarchy_and_escapes_embedded_content(self):
        report, app = self.fixture()
        app["function_bindings"][0]["command"] = "echo </script>"
        html = render(build_story(report, app))
        self.assertIn("Agent 端到端执行记录", html)
        self.assertIn("Agent 语义火焰图", html)
        self.assertIn("syscall_count", html)
        self.assertIn("token_count", html)
        self.assertIn("逐次 syscall", html)
        self.assertNotIn("echo </script>", html)
        self.assertIn("echo \\u003c/script\\u003e", html)

    def test_missing_linux_binding_is_rejected(self):
        report, app = self.fixture()
        app["function_bindings"][0]["observer_tool_call_id"] = "absent"
        with self.assertRaisesRegex(ValueError, "report binding"):
            build_story(report, app)

    def test_provider_token_usage_is_explicit_and_order_association_is_disclosed(self):
        report, app = self.fixture()
        usage = [{"receipt_ns": 195, "totalTokens": 12, "inputTokens": 10,
                  "outputTokens": 2, "cachedInputTokens": 0,
                  "cacheWriteInputTokens": 0, "reasoningOutputTokens": 0,
                  "source": "CODEX_PROVIDER_REPORTED_LAST_USAGE"}]
        story = build_story(report, app, rpc_usage=usage)
        self.assertEqual(story["total_tokens"], 12)
        self.assertEqual(story["model_usage"][0]["associated_tool_call_id"], "linux-1")
        self.assertIn("NOT_CAUSAL", story["model_usage"][0]["attribution"])

    def test_code_mode_cannot_be_borrowed_from_another_run(self):
        report,app=self.fixture()
        mode={"status":"COMPLETE","invocations":[{"run_id":"another-run",
            "agent_id":"agent","task_id":"task","call_id":"app-1","boot_id":"b"}]}
        with self.assertRaisesRegex(ValueError,"run identity differs"):
            build_story(report,app,code_mode=mode)
        mode["invocations"][0].update(run_id="r",begin_ns=90,end_ns=210)
        with self.assertRaisesRegex(ValueError,"outside Agent interval"):
            build_story(report,app,code_mode=mode)

    def test_page_does_not_duplicate_full_operations_or_mutate_source(self):
        report,app=self.fixture();story=build_story(report,app)
        from semantic_profile import build_profile
        profile=build_profile(story)
        profile["operations"][0]["evidence"]["unit_test_private_marker"]="ONLY_IN_FULL_PROFILE"
        chain=story["decision_evidence"]["chains"][0]
        chain["observations"]=[{"syscall":"read","result":1} for _ in range(9)]
        chain["observations"][8]["unit_test_marker"]="ONLY_IN_FULL_CHAIN"
        html=render(story,profile)
        self.assertNotIn("ONLY_IN_FULL_PROFILE",html)
        self.assertNotIn("ONLY_IN_FULL_CHAIN",html)
        self.assertEqual(len(chain["observations"]),9)
        self.assertIn("ONLY_IN_FULL_PROFILE",str(profile))


if __name__ == "__main__":
    unittest.main()
