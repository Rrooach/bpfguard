#!/usr/bin/env python3
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from semantic_annotations import (TAXONOMY_VERSION, apply_annotations, build_annotations,
    build_trajectory, classify_tool, validate_annotations, validate_trajectory)


class SemanticAnnotationTests(unittest.TestCase):
    def fixture(self):
        commands = ["rg -n 'broken' src", "sed -n '1,80p' src/a.py",
                    "apply_patch '<patch>'", "python3 -m pytest -q"]
        steps, calls = [], []
        for index, command in enumerate(commands):
            row = {"kind": "TOOL_CALL", "call_id": "c" + str(index),
                   "observer_tool_call_id": "native" + str(index), "command": command,
                   "requested_ns": 10 + 10 * index, "result_delivered_ns": 15 + 10 * index,
                   "status": "SUCCEEDED", "exit_code": 0, "stdout": "actual result " + str(index)}
            steps.append(row); calls.append(row)
        app = {"agent_id": "a", "task_id": "fix-fixture", "begin_ns": 0, "end_ns": 100,
               "prompt": "Fix the parser and run its tests", "steps": steps, "tool_calls": calls}
        story = {"run_id": "r", "agent_id": "a", "task_id": "fix-fixture", "tools": [
            {"call_id": row["call_id"], "tool_call_id": row["observer_tool_call_id"],
             "semantic_path": ["old prior message"]} for row in calls],
            "wall_partition": {"segments": [{"active_ids": ["c0"], "duration_ns": 10}]},
            "model_requests": [{"request_id": "m", "begin_ns": 2, "end_ns": 9,
                                "bound_tool_call_ids": ["native0"]}]}
        return app, story

    def test_rules_use_tool_syntax_not_previous_message(self):
        app, story = self.fixture()
        app["steps"].insert(0, {"kind": "AGENT_MESSAGE", "receipt_ns": 1,
                                "text": "Everything is a test, pytest test pytest"})
        trajectory = build_trajectory(app, story)
        annotations = build_annotations(trajectory)
        self.assertEqual(annotations["call_paths"], {
            "c0": ["task", "locate"], "c1": ["task", "inspect"],
            "c2": ["task", "edit"], "c3": ["task", "test"]})
        self.assertIn("INFERENCE", annotations["method"])
        message = next(row for row in annotations["assignments"] if row["kind"] == "AGENT_MESSAGE")
        self.assertEqual(message["path"], ["task", "unassigned"])
        self.assertEqual(validate_annotations(trajectory, annotations)["status"], "STRUCTURE_AND_SOURCE_BINDING_VALID")

    def test_source_records_results_and_user_task_are_retained(self):
        app, story = self.fixture()
        trajectory = build_trajectory(app, story)
        kinds = [step["kind"] for step in trajectory["steps"]]
        self.assertEqual(kinds.count("TOOL_REQUEST"), 4)
        self.assertEqual(kinds.count("TOOL_RESULT"), 4)
        self.assertIn("USER_TASK", kinds); self.assertIn("MODEL_REQUEST", kinds)
        result = next(step for step in trajectory["steps"] if step["kind"] == "TOOL_RESULT")
        self.assertIn("actual result", result["source"]["stdout"])
        self.assertTrue(result["source_sha256"])
        self.assertEqual(trajectory, build_trajectory(app, story))

    def test_raw_turn_task_not_agent_message_is_used(self):
        app, story = self.fixture(); del app["prompt"]
        rpc = [{"direction": "CLIENT_TO_CODEX", "receipt_ns": 0,
                "message": {"method": "turn/start", "params": {"input": [
                    {"type": "text", "text": "Fix the actual user request"}]}}}]
        trajectory = build_trajectory(app, story, rpc)
        task = next(step for step in trajectory["steps"] if step["kind"] == "USER_TASK")
        self.assertEqual(task["source_ref"], "rpc#/0")
        self.assertEqual(task["source"], rpc[0])

    def test_model_output_binding_is_exact_not_nearest_tool(self):
        app, story = self.fixture()
        trajectory = build_trajectory(app, story)
        result = build_annotations(trajectory)
        model = next(row for row in result["assignments"] if row["kind"] == "MODEL_REQUEST")
        self.assertEqual(model["path"], ["task", "locate"])
        story["model_requests"][0]["bound_tool_call_ids"] = ["native0", "not-registered"]
        result = build_annotations(build_trajectory(app, story))
        model = next(row for row in result["assignments"] if row["kind"] == "MODEL_REQUEST")
        self.assertEqual(model["path"], ["task", "unassigned"])

    def test_foreign_boot_model_duration_does_not_establish_trajectory_order(self):
        app, story = self.fixture(); story["boot_id"] = "guest"
        story["model_requests"][0].update(source_boot_id="host", clock_alignment="DIFFERENT_BOOT_DURATION_ONLY")
        trajectory = build_trajectory(app, story)
        model = next(step for step in trajectory["steps"] if step["kind"] == "MODEL_REQUEST")
        self.assertIsNone(model["at_ns"])
        self.assertIn("UNORDERED_SUPPLEMENTS", trajectory["ordering"])

    def test_search_pattern_does_not_become_test_execution(self):
        self.assertEqual(classify_tool({"command": "rg 'pytest test broken' src"})[0], "locate")
        self.assertEqual(classify_tool({"command": "cat src/pytest.py"})[0], "inspect")
        self.assertEqual(classify_tool({"command": "echo pytest"})[0], "unassigned")

    def test_mixed_and_unknown_commands_remain_unassigned(self):
        for command in ("custom_solver --fix", "python3 app.py", "cat '", "rg foo src && custom_solver"):
            self.assertEqual(classify_tool({"command": command})[0], "unassigned", command)
        self.assertEqual(classify_tool({"command": "cd repo && sed -n '1,5p' a.py | head"})[0], "inspect")
        self.assertEqual(classify_tool({"command": "env ABC=1 exec pytest -q"})[0], "test")
        self.assertEqual(classify_tool({"command": "bash -c 'pytest -q'"})[0], "test")

    def test_composite_known_work_gets_a_broader_responsibility_not_time_split(self):
        stage, evidence = classify_tool({"command": "rg foo src && pytest"})
        self.assertEqual(stage, "inspect_test")
        self.assertEqual(evidence[-1]["rule"], "broader-composite-responsibility-no-time-splitting")
        self.assertEqual(classify_tool({"command": "apply_patch fix.diff && pytest -q"})[0], "edit_test")
        self.assertEqual(classify_tool({"command": "cat a.py\npytest -q"})[0], "inspect_test")
        self.assertEqual(classify_tool({"command": "for f in a b; do cat \"$f\"; done; bun --version"})[0], "inspect")
        self.assertEqual(classify_tool({"command": "rg foo src; cat a.py | sort"})[0], "inspect")

    def test_explicit_mutation_not_stdout_read(self):
        for command in ("sed -i s/old/new/ a.py", "echo text > a.py", "cat > a.py", "apply_patch patch.diff"):
            self.assertEqual(classify_tool({"command": command})[0], "edit", command)
        self.assertEqual(classify_tool({"command": "sed -n '1,10p' a.py"})[0], "inspect")
        self.assertEqual(classify_tool({"command": "cat > run.sh <<true\npytest\ntrue"})[0], "unassigned")

    def test_sparse_reviewed_nested_paths_cover_every_step(self):
        app, story = self.fixture(); trajectory = build_trajectory(app, story)
        first, third = trajectory["steps"][0], trajectory["steps"][3]
        marks = {"trajectory_digest": trajectory["trajectory_digest"], "taxonomy_version": TAXONOMY_VERSION,
                 "marks": [{"step_id": first["step_id"], "path": ["task", "locate"]},
                           {"step_id": third["step_id"], "path": ["task", "locate", "inspect"]}]}
        output = build_annotations(trajectory, marks)
        self.assertIn("EXPLICIT_OFFLINE", output["method"])
        self.assertEqual(output["assignments"][2]["labels"], ["完成任务", "定位问题"])
        self.assertEqual(output["assignments"][3]["labels"], ["完成任务", "定位问题", "检查实现"])
        self.assertEqual(output["intervals"][0]["end_step_exclusive"], len(trajectory["steps"]))
        self.assertEqual(output["intervals"][1]["taxonomy_key"], "locate")
        self.assertEqual(output["intervals"][1]["end_step_exclusive"], len(trajectory["steps"]))

    def test_bad_marks_cannot_use_offsets_unknown_taxonomy_or_missing_root(self):
        app, story = self.fixture(); trajectory = build_trajectory(app, story)
        base = {"trajectory_digest": trajectory["trajectory_digest"], "taxonomy_version": TAXONOMY_VERSION}
        for marks in ([{"step_id": trajectory["steps"][1]["step_id"], "path": ["task", "test"]}],
                      [{"step_id": "unknown", "path": ["task"]}],
                      [{"step_id": trajectory["steps"][0]["step_id"], "path": ["task", "made-up"]}],
                      [{"step_id": trajectory["steps"][0]["step_id"], "path": ["test"]}]):
            with self.assertRaises(ValueError):
                build_annotations(trajectory, {**base, "marks": marks})

    def test_offline_observer_review_uses_frozen_business_task_vocabulary(self):
        app, story = self.fixture(); trajectory = build_trajectory(app, story)
        explicit = {"trajectory_digest": trajectory["trajectory_digest"],
            "taxonomy_version": "http-header-repair-v1", "method": "OFFLINE_OBSERVER_REVIEW",
            "taxonomy": {"task": "修复 HTTP 头处理", "inspect": "定位头合并行为", "repair": "实现并验证修复",
                         "verify": "检查回归结果", "unassigned": "未分配阶段"},
            "review_basis": "Observed command, output and task input; not hidden reasoning",
            "marks": [{"step_id": trajectory["steps"][0]["step_id"], "path": ["task", "inspect"]},
                      {"step_id": trajectory["steps"][-1]["step_id"], "path": ["task", "verify"]}]}
        result = build_annotations(trajectory, explicit)
        self.assertEqual(result["method"], "OFFLINE_OBSERVER_REVIEW_NOT_RUNTIME_INTENT_PROOF")
        self.assertEqual(result["source_marks"], explicit)
        self.assertEqual(result["assignments"][0]["labels"], ["修复 HTTP 头处理", "定位头合并行为"])
        self.assertEqual(result["call_paths"]["c3"], ["task", "unassigned"])
        # c3 request/result cross a reviewed boundary, so native events do not
        # inherit whichever stage happens to be encountered last.
        self.assertEqual(apply_annotations(story, result)["tools"][-1]["semantic_path"],
                         ["修复 HTTP 头处理", "未分配阶段"])

    def test_changed_sources_crossing_or_forged_native_paths_are_rejected(self):
        app, story = self.fixture(); trajectory = build_trajectory(app, story)
        original = build_annotations(trajectory)
        for mutation in ("interval", "source", "callpath", "label", "missing", "identity"):
            output = deepcopy(original)
            if mutation == "interval": output["intervals"][1]["end_step_exclusive"] += 2
            if mutation == "source": output["assignments"][0]["source_sha256"] = "wrong"
            if mutation == "callpath": output["call_paths"]["c0"] = ["task", "test"]
            if mutation == "label": output["assignments"][0]["labels"] = ["invented"]
            if mutation == "missing": output["assignments"].pop()
            if mutation == "identity": output["assignments"][0]["call_id"] = "other-tool"
            with self.assertRaises(ValueError, msg=mutation):
                validate_annotations(trajectory, output)
        changed = deepcopy(trajectory); changed["steps"][0]["source"]["text"] = "different"
        with self.assertRaises(ValueError): validate_trajectory(changed)

    def test_apply_copy_paths_by_exact_ids_and_keep_old_context(self):
        app, story = self.fixture(); before = deepcopy(story)
        annotations = build_annotations(build_trajectory(app, story))
        output = apply_annotations(story, annotations)
        self.assertEqual(story, before)
        self.assertEqual(output["tools"][0]["semantic_path"], ["完成任务", "定位问题"])
        self.assertEqual(output["tools"][0]["semantic_original_path"], ["old prior message"])
        self.assertEqual(output["model_requests"][0]["semantic_path"], ["完成任务", "定位问题"])
        self.assertEqual(output["wall_partition"]["segments"][0]["semantic_path"], ["完成任务", "定位问题"])
        wrong = deepcopy(story); wrong["run_id"] = "different"
        with self.assertRaises(ValueError): apply_annotations(wrong, annotations)

    def test_cli_persists_trajectory_and_annotations_without_overwriting(self):
        app, story = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.json").write_text(json.dumps(app))
            (root / "story.json").write_text(json.dumps(story))
            command = [sys.executable, str(Path(__file__).with_name("semantic_annotations.py")),
                "--application", str(root / "app.json"), "--story", str(root / "story.json"),
                "--trajectory-output", str(root / "trajectory.json"), "--output", str(root / "annotations.json")]
            subprocess.run(command, check=True, capture_output=True)
            trajectory = json.loads((root / "trajectory.json").read_text())
            annotations = json.loads((root / "annotations.json").read_text())
            self.assertEqual(validate_annotations(trajectory, annotations)["steps"], 10)
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_unknown_concurrent_actor_does_not_inherit_known_tools_stage(self):
        app, story = self.fixture()
        story["wall_partition"]["segments"][0]["active_ids"] = ["c0", "unknown-shared-service"]
        annotations = build_annotations(build_trajectory(app, story))
        output = apply_annotations(story, annotations)
        self.assertEqual(output["wall_partition"]["segments"][0]["semantic_path"], ["完成任务", "未分配阶段"])


if __name__ == "__main__":
    unittest.main()
