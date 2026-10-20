#!/usr/bin/env python3
import unittest

from semantic_profile import build_profile, operations_from_story


class SemanticProfileTests(unittest.TestCase):
    def story(self):
        return {"agent_id": "a", "task_id": "fix bug", "agent_wall_ms": 20,
                "trailing_agent_ms": 2, "model_usage": [{"number": 1,
                    "semantic_path": ["检查代码"], "attribution": "ORDERED_NOT_CAUSAL",
                    "totalTokens": 123, "inputTokens": 100, "outputTokens": 23,
                    "cachedInputTokens": 0, "reasoningOutputTokens": 0,
                    "source": "CODEX_PROVIDER_REPORTED_LAST_USAGE", "at_ms": 4}],
                "tools": [{"number": 1, "call_id": "c1",
                "tool_call_id": "t1", "tool_name": "shell", "command": "cat a",
                "status": "SUCCEEDED", "agent_gap_before_ms": 5,
                "request_to_execution_ms": 1, "execution_ms": 10,
                "result_delivery_ms": 2, "semantic_path": ["检查代码"],
                "semantic_quality": "AGENT_REPORTED_PLAN_STEP_ORDER",
                "process_profiles": [{"tgid": 10, "process_birth_ns": 1, "comm": "cat",
                    "threads": [{"tid": 10, "comm": "cat", "state_totals_ns": {
                        "ONCPU": 2_000_000, "RUNNABLE": 1_000_000, "SLEEP": 3_000_000}}]}],
                "syscall_rows": [{"tgid": 10, "process_birth_ns": 1, "tid": 10,
                    "comm": "cat", "name": "read", "category": "filesystem",
                    "duration_us": 50, "paths": ["/src/a"], "additional_paths": 0,
                    "returned_bytes": 100, "result": 100, "errno": None, "at_ms": 7}],
                "resources": {"scope": "FRESH_EPHEMERAL_TOOL_CGROUP_BOUNDARIES; test",
                    "status": "COMPLETE", "memory_peak_bytes": 4096,
                    "cpu_usage_usec": 3000, "minor_faults": 4, "major_faults": 1,
                    "io_read_bytes": 512, "io_write_bytes": 8}}]}

    def test_same_semantic_prefix_projects_multiple_measures(self):
        story = self.story(); story["run_id"] = "run"
        profile = build_profile(story)
        self.assertEqual({key: profile[key] for key in ("agent_id", "task_id", "run_id")},
                         {"agent_id": "a", "task_id": "fix bug", "run_id": "run"})
        views = {view["name"]: view for view in profile["views"]}
        self.assertEqual(views["wall_ms"]["total"], 20)
        self.assertEqual(views["oncpu_ms"]["total"], 2)
        self.assertEqual(views["file_read_bytes"]["total"], 100)
        self.assertEqual(views["memory_peak_bytes"]["total"], 4096)
        self.assertEqual(views["token_count"]["total"], 123)
        self.assertEqual(views["file_read_bytes"]["tree"]["label"], "Agent a")
        labels = [child["label"] for child in views["file_read_bytes"]["tree"]["children"]]
        self.assertIn("fix bug", labels)

    def test_missing_resource_data_is_not_invented(self):
        story = self.story(); story["tools"][0]["resources"] = None
        views = {view["name"]: view for view in build_profile(story)["views"]}
        self.assertEqual(views["memory_peak_bytes"]["status"], "NOT_COLLECTED")
        self.assertEqual(views["cgroup_cpu_ms"]["total"], 0)

    def test_measured_zero_is_available_and_observer_memory_has_its_own_view(self):
        story=self.story();story["tools"][0]["resources"]["cpu_usage_usec"]=0
        story["memory"]={"interval_ms":100,"series":[
            {"name":"agent","role":"AGENT_RUNTIME","at_ms":0,"rss_bytes":100},
            {"name":"observer","role":"OBSERVER_CONTROL","at_ms":0,"rss_bytes":500},
            {"name":"agent","role":"AGENT_RUNTIME","at_ms":100,"rss_bytes":200},
            {"name":"observer","role":"OBSERVER_CONTROL","at_ms":100,"rss_bytes":700}]}
        views={view["name"]:view for view in build_profile(story)["views"]}
        self.assertEqual(views["cgroup_cpu_ms"]["status"],"AVAILABLE")
        self.assertEqual(views["cgroup_cpu_ms"]["total"],0)
        self.assertEqual(views["memory_rss_byte_ms"]["total"],15000)
        self.assertEqual(views["observer_rss_byte_ms"]["total"],60000)

    def test_explicit_wall_partition_replaces_overlapping_tool_durations(self):
        story=self.story();story["wall_partition"]={"segments":[{"label":"model wait","duration_ns":10000000,
            "begin_ns":0,"end_ns":10000000,"active_ids":[],"semantic_path":[]}]}
        views={view["name"]:view for view in build_profile(story)["views"]}
        self.assertEqual(views["wall_ms"]["total"],10)

    def test_evidence_links_annotate_only_exact_call_identity_without_reparenting(self):
        story = self.story()
        story["decision_evidence"] = {"status": "PARTIAL", "summary": {"partial_calls": 1},
            "chains": [{"call_id": "c1", "chain_id": "tool:c1", "status": "PARTIAL"},
                       {"call_id": "unrelated", "chain_id": "wrong", "status": "LINKED"}]}
        operations = operations_from_story(story)
        linked = [row for row in operations if row["evidence"].get("evidence_chain_id")]
        self.assertTrue(linked)
        self.assertTrue(all(row["evidence"]["evidence_chain_id"] == "tool:c1" for row in linked))
        profile = build_profile(story)
        self.assertEqual(profile["evidence_links"]["status"], "PARTIAL")
        self.assertEqual(profile["operation_count"], len(profile["operations"]))
        self.assertEqual(profile["operations"], operations)
        self.assertEqual(next(view for view in profile["views"] if view["name"] == "syscall_count")["total"], 1)

    def invocation(self, call_id="c1"):
        return {"run_id": "run", "agent_id": "a", "task_id": "fix bug", "call_id": call_id,
            "runtime_id": "runtime", "pid": 88, "boot_id": "boot", "begin_ns": 0, "end_ns": 10_000_000,
            "js_ms": 3, "tool_wait_ms": 5, "thread_cpu_ms": 1.2,
            "segments": [
                {"kind": "JS", "begin_ns": 0, "end_ns": 2_000_000,
                 "name": "prepare query", "span_ids": ["j1"]},
                {"kind": "AWAIT", "begin_ns": 2_000_000, "end_ns": 4_000_000,
                 "name": "search", "span_ids": ["w1"], "child_call_ids": ["child-search"]},
                {"kind": "AWAIT", "begin_ns": 4_000_000, "end_ns": 7_000_000,
                 "name": "search / read", "span_ids": ["w1", "w2"],
                 "child_call_ids": ["child-search", "child-read"]},
                {"kind": "JS", "begin_ns": 7_000_000, "end_ns": 8_000_000,
                 "name": "consume results", "span_ids": ["j2"]},
                {"kind": "OTHER", "begin_ns": 8_000_000, "end_ns": 10_000_000,
                 "name": "unmeasured continuation", "span_ids": []}]}

    def test_v8_segments_share_exact_tool_hierarchy_and_conserve_nonoverlapping_weights(self):
        story = self.story(); story["code_mode"] = {"invocations": [self.invocation()]}
        story["decision_evidence"] = {"chains": [{"call_id": "c1", "chain_id": "tool:c1", "status": "PARTIAL"}]}
        profile = build_profile(story); views = {row["name"]: row for row in profile["views"]}
        self.assertEqual(views["v8_js_ms"]["total"], 3)
        self.assertEqual(views["v8_tool_wait_ms"]["total"], 5)  # Parallel w1+w2 is a union, not 8ms.
        self.assertEqual(views["v8_thread_cpu_ms"]["total"], 1.2)
        segments = [row for row in profile["operations"] if row["kind"] == "code_mode_segment"]
        self.assertEqual(len(segments), 4)
        self.assertEqual([frame["kind"] for frame in segments[0]["stack"]],
                         ["task", "semantic", "tool", "v8", "code_mode_phase"])
        self.assertEqual(segments[0]["stack"][-1]["label"], "执行 JavaScript · prepare query")
        self.assertEqual(segments[0]["evidence"]["evidence_chain_id"], "tool:c1")
        self.assertEqual(segments[0]["evidence"]["span_id"], "j1")
        self.assertEqual(segments[2]["evidence"]["span_ids"], ["w1", "w2"])
        self.assertEqual(segments[2]["evidence"]["boot_id"], "boot")
        self.assertEqual(segments[2]["evidence"]["runtime_id"], "runtime")
        cpu = [row for row in profile["operations"] if "v8_thread_cpu_ms" in row["measures"]]
        self.assertEqual(len(cpu), 1)

    def test_parallel_unknown_v8_call_is_not_assigned_to_an_overlapping_tool(self):
        story = self.story(); story["code_mode"] = {"invocations": [self.invocation(), self.invocation("unrelated")]}
        operations = operations_from_story(story)
        unrelated = [row for row in operations if row["kind"].startswith("code_mode")
                     and row["evidence"].get("call_id") == "unrelated"]
        self.assertTrue(unrelated)
        self.assertTrue(all(not any(frame["kind"] == "tool" for frame in row["stack"]) for row in unrelated))
        views = {row["name"]: row for row in build_profile(story)["views"]}
        self.assertEqual(views["v8_js_ms"]["total"], 6)  # Explicit invocations may overlap.
        self.assertEqual(views["v8_thread_cpu_ms"]["total"], 2.4)

    def test_zero_v8_measurements_remain_available_without_segments(self):
        story = self.story(); invocation = self.invocation(); invocation.update(
            segments=[], js_ms=0, tool_wait_ms=0, thread_cpu_ms=0)
        story["code_mode"] = {"invocations": [invocation]}
        views = {row["name"]: row for row in build_profile(story)["views"]}
        for measure in ("v8_js_ms", "v8_tool_wait_ms", "v8_thread_cpu_ms"):
            self.assertEqual(views[measure]["status"], "AVAILABLE")
            self.assertEqual(views[measure]["total"], 0)

    def test_uninstrumented_v8_intervals_are_not_inferred_as_js_or_zero(self):
        story = self.story(); invocation = self.invocation(); invocation.update(
            segments=[{"kind": "OTHER", "begin_ns": 0, "end_ns": 10_000_000}],
            js_ms=None, tool_wait_ms=None, thread_cpu_ms=None)
        story["code_mode"] = {"invocations": [invocation]}
        views = {row["name"]: row for row in build_profile(story)["views"]}
        for measure in ("v8_js_ms", "v8_tool_wait_ms", "v8_thread_cpu_ms"):
            self.assertEqual(views[measure]["status"], "NOT_COLLECTED")

    def test_overlapping_or_inconsistent_v8_partition_is_rejected(self):
        for change in (lambda invocation: invocation["segments"][1].update(begin_ns=1_000_000),
                       lambda invocation: invocation.update(js_ms=9)):
            story = self.story(); invocation = self.invocation(); change(invocation)
            story["code_mode"] = {"invocations": [invocation]}
            with self.assertRaisesRegex(ValueError, "Code Mode"):
                build_profile(story)

    def test_memory_uses_only_exact_native_tool_id_and_keeps_runtime_observer_separate(self):
        story = self.story(); points = []
        for name, role, tool_id in (("tool", "TOOL_ROOT", "t1"),
                                    ("wrong namespace", "TOOL_ROOT", "c1"),
                                    ("runtime", "AGENT_RUNTIME", None),
                                    ("observer", "OBSERVER_CONTROL", "t1")):
            for at, rss in ((0, 100), (100, 200)):
                points.append({"name": name, "role": role, "tool_call_id": tool_id,
                               "at_ms": at, "rss_bytes": rss})
        story["memory"] = {"interval_ms": 100, "series": points}
        operations = [row for row in operations_from_story(story) if row["kind"] == "memory_sample"]
        exact = [row for row in operations if row["evidence"]["attribution"] == "EXPLICIT_NATIVE_TOOL_CALL_ID"]
        self.assertEqual(len(exact), 1)
        self.assertEqual([frame["kind"] for frame in exact[0]["stack"]], ["task", "semantic", "tool", "resource"])
        self.assertEqual(exact[0]["stack"][2]["call_id"], "c1")
        for row in operations:
            if row not in exact:
                self.assertFalse(any(frame["kind"] == "tool" for frame in row["stack"]))
        views = {row["name"]: row for row in build_profile(story)["views"]}
        self.assertEqual(views["memory_rss_byte_ms"]["total"], 45000)
        self.assertEqual(views["observer_rss_byte_ms"]["total"], 15000)

    def test_memory_does_not_interpolate_across_changed_tool_identity(self):
        story = self.story(); story["memory"] = {"interval_ms": 100, "series": [
            {"name": "reused", "role": "TOOL_ROOT", "tool_call_id": "t1", "at_ms": 0, "rss_bytes": 100},
            {"name": "reused", "role": "TOOL_ROOT", "tool_call_id": "other", "at_ms": 100, "rss_bytes": 200}]}
        views = {row["name"]: row for row in build_profile(story)["views"]}
        self.assertEqual(views["memory_rss_byte_ms"]["status"], "NOT_COLLECTED")

    def test_missing_semantic_annotation_does_not_say_task_is_unknown(self):
        story = self.story(); story["tools"][0]["semantic_path"] = []
        operation = next(row for row in operations_from_story(story) if row["kind"] == "tool_call")
        self.assertEqual(operation["stack"][1]["label"], "未提供步骤标签（任务与命令已知）")
        self.assertEqual(operation["stack"][0]["label"], "fix bug")


if __name__ == "__main__":
    unittest.main()
