#!/usr/bin/env python3
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from profile_query import compare_profiles, operation_fields, query_profiles


class ProfileQueryTests(unittest.TestCase):
    def profile(self, run="r1", amount=3, pid=10, ordinal=1):
        return {"run_id": run, "agent_id": "agent-" + run, "task_id": "same-controlled-task",
            "semantic_quality": "DETERMINISTIC_COMMAND_RULE_INFERENCE_NOT_INTENT_PROOF",
            "views": [{"name": "wall_ms", "label": "墙钟", "unit": "ms", "status": "AVAILABLE", "total": amount + 2},
                      {"name": "token_count", "label": "Tokens", "unit": "tokens", "status": "AVAILABLE", "total": 10}],
            "operations": [
                {"kind": "tool_phase", "stack": [{"kind": "task", "label": "same-controlled-task"},
                    {"kind": "semantic", "label": "完成任务"}, {"kind": "semantic", "label": "运行测试"},
                    {"kind": "tool", "label": "工具 {} · observer_bash".format(ordinal), "call_id": "call-" + run},
                    {"kind": "process", "label": "pytest [pid {}]".format(pid)}],
                 "measures": {"wall_ms": amount, "token_count": 10}, "evidence": {"call_id": "call-" + run}},
                {"kind": "syscall", "stack": [{"kind": "semantic", "label": "完成任务"},
                    {"kind": "semantic", "label": "检查实现"}, {"kind": "syscall", "label": "read"},
                    {"kind": "file", "label": "a.py", "path": "/repo/src/a.py"}],
                 "measures": {"wall_ms": 2}, "evidence": {"result": 10}},
                {"kind": "unmeasured", "stack": [{"kind": "phase", "label": "unknown"}],
                 "measures": {}, "evidence": {}}]}

    def test_cross_run_fold_omits_pid_and_tool_ordinal_but_keeps_evidence(self):
        output = query_profiles([self.profile(), self.profile("r2", pid=999, ordinal=5)], "wall_ms")
        self.assertEqual(output["views"][0]["total"], 10)
        self.assertEqual(output["conservation"]["source_total"], 10)
        self.assertEqual(output["views"][0]["tree"]["children"][0]["label"], "完成任务")
        test = next(node for node in output["views"][0]["tree"]["children"][0]["children"] if node["label"] == "运行测试")
        self.assertEqual(test["value"], 6)
        self.assertEqual({row["evidence"]["run_id"] for row in output["operations"]}, {"r1", "r2"})
        self.assertNotIn("pid", str([row["stack"] for row in output["operations"]]))
        self.assertIn("pid 999", str(output["operations"][-2]["evidence"]["source_stack"]))

    def test_filters_preserve_conservation_and_do_not_change_sources(self):
        profile = self.profile(); before = deepcopy(profile)
        output = query_profiles([profile], "wall_ms", stack="semantic,action", filters=["semantic=测试"])
        self.assertEqual(output["conservation"], {"status": "PASSED", "source_total": 5,
            "excluded_total": 2, "selected_total": 3, "missing_measure_operations": 1,
            "meaning": "selected+excluded=source; missing is not zero"})
        self.assertEqual(profile, before)
        output = query_profiles([profile], "wall_ms", filters=["semantic!=测试"])
        self.assertEqual(output["views"][0]["total"], 2)

    def test_changing_field_order_changes_projection_not_total(self):
        first = query_profiles([self.profile()], "wall_ms", stack="semantic,action,object")
        second = query_profiles([self.profile()], "wall_ms", stack="action,semantic")
        self.assertEqual(first["views"][0]["total"], second["views"][0]["total"])
        self.assertNotEqual(first["operations"][0]["stack"], second["operations"][0]["stack"])

    def test_mapping_is_explicit_first_match_per_field_before_filter(self):
        rules = [{"field": "semantic", "source_field": "action", "pattern": "read", "label": "读取源码"},
                 {"field": "semantic", "source_field": "action", "pattern": ".", "label": "所有操作"}]
        result = query_profiles([self.profile()], "wall_ms", mappings=rules, filters=["semantic=读取源码"])
        self.assertEqual(result["views"][0]["total"], 2)
        self.assertEqual(result["operations"][0]["fields"]["semantic"], ["读取源码"])

    def test_token_projection_uses_same_semantic_prefix_and_actual_usage(self):
        output = query_profiles([self.profile()], "token_count", stack="semantic")
        self.assertEqual(output["views"][0]["total"], 10)
        self.assertEqual(output["operations"][0]["stack"], [{"kind": "semantic", "label": "完成任务"},
            {"kind": "semantic", "label": "运行测试"}])
        self.assertEqual(output["conservation"]["missing_measure_operations"], 2)

    def test_zero_measured_is_kept_and_missing_not_zero(self):
        profile = self.profile(amount=0)
        result = query_profiles([profile], "wall_ms", filters=["semantic=运行测试"])
        self.assertEqual(result["views"][0]["status"], "AVAILABLE")
        self.assertEqual(result["views"][0]["total"], 0)
        self.assertEqual(result["views"][0]["sample_count"], 1)
        missing = query_profiles([profile], "wall_ms", filters=["semantic=does-not-exist"])
        self.assertEqual(missing["views"][0]["status"], "NO_SELECTED_SAMPLES")

    def test_source_identity_total_units_and_nonfinite_are_rejected(self):
        for mutation in ("run", "total", "nan", "negative", "availability"):
            profile = self.profile()
            if mutation == "run": profile.pop("run_id")
            if mutation == "total": profile["views"][0]["total"] = 99
            if mutation == "nan": profile["operations"][0]["measures"]["wall_ms"] = float("nan")
            if mutation == "negative": profile["operations"][0]["measures"]["wall_ms"] = -1
            if mutation == "availability": profile["views"][0]["status"] = "NOT_COLLECTED"
            with self.assertRaises(ValueError, msg=mutation): query_profiles([profile], "wall_ms")
        with self.assertRaises(ValueError): query_profiles([self.profile(), self.profile()], "wall_ms")
        other = self.profile("r2"); other["views"][0]["unit"] = "seconds"
        with self.assertRaises(ValueError): query_profiles([self.profile(), other], "wall_ms")

    def test_versioned_vocabularies_cannot_be_silently_merged_or_compared(self):
        first, other = self.profile(), self.profile("r2")
        first["semantic_annotations"] = {"taxonomy_version": "v1", "taxonomy_digest": "hash1"}
        other["semantic_annotations"] = {"taxonomy_version": "v2", "taxonomy_digest": "hash2"}
        with self.assertRaisesRegex(ValueError, "taxonomy"):
            query_profiles([first, other], "wall_ms")
        with self.assertRaisesRegex(ValueError, "taxonomy"):
            compare_profiles([first], [other], "wall_ms")
        other["semantic_annotations"] = deepcopy(first["semantic_annotations"])
        merged = query_profiles([first, other], "wall_ms")
        self.assertEqual(merged["semantic_registry"]["status"], "SAME_VERSIONED_TAXONOMY")

    def test_default_difference_is_per_run_not_unequal_cohort_mass(self):
        result = compare_profiles([self.profile("b1")], [self.profile("c1"), self.profile("c2")], "wall_ms")
        self.assertEqual(result["baseline_total"], 5)
        self.assertEqual(result["comparison_total"], 5)
        self.assertEqual(result["delta_total"], 0)
        self.assertTrue(all(row["direction"] == "EQUAL" for row in result["rows"]))

    def test_signed_difference_retains_improvement_and_regression(self):
        result = compare_profiles([self.profile("good", amount=6)], [self.profile("bad", amount=2)], "wall_ms")
        row = result["rows"][0]
        self.assertEqual(row["delta"], -4)
        self.assertEqual(row["display_width"], 8)
        self.assertEqual(row["direction"], "DECREASE")
        self.assertEqual(sum(row["delta"] for row in result["rows"]), result["delta_total"])

    def test_outcome_must_be_explicit_not_shell_success(self):
        output = query_profiles([self.profile()], "wall_ms", stack="outcome,semantic", outcomes={"r1": "OFFICIAL_PASS"})
        self.assertEqual(output["operations"][0]["stack"][0]["label"], "OFFICIAL_PASS")
        unknown = query_profiles([self.profile()], "wall_ms", stack="outcome")
        self.assertEqual(unknown["operations"][0]["stack"][0]["label"], "UNKNOWN")

    def test_invalid_stack_and_filter_rejected(self):
        for stack in ("pid,semantic", "semantic,semantic", ""):
            with self.assertRaises(ValueError): query_profiles([self.profile()], "wall_ms", stack=stack)
        with self.assertRaises(ValueError): query_profiles([self.profile()], "wall_ms", filters=["not-a-filter"])
        with self.assertRaises(ValueError): query_profiles([self.profile()], "wall_ms", filters=["semantic=["])

    def test_syscall_result_overrides_enclosing_tool_success(self):
        profile = self.profile()
        row = profile["operations"][1]
        row["stack"].insert(0, {"kind": "tool", "label": "工具 1 · shell", "status": "SUCCEEDED"})
        row["evidence"].update(result=-13, errno="EACCES")
        fields = operation_fields(row, profile)
        self.assertEqual(fields["result"], ["EACCES"])

    def test_cli_projects_multiple_runs_with_auditable_totals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.json").write_text(json.dumps(self.profile()))
            (root / "b.json").write_text(json.dumps(self.profile("r2")))
            command = [sys.executable, str(Path(__file__).with_name("profile_query.py")),
                "--profile", str(root / "a.json"), "--profile", str(root / "b.json"),
                "--measure", "wall_ms", "--stack", "semantic,action", "--where", "semantic=测试",
                "--output", str(root / "output.json")]
            subprocess.run(command, check=True, capture_output=True)
            output = json.loads((root / "output.json").read_text())
            self.assertEqual(output["conservation"]["selected_total"], 6)
            self.assertEqual(output["conservation"]["excluded_total"], 4)


if __name__ == "__main__":
    unittest.main()
