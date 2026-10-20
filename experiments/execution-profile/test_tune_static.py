import copy
import concurrent.futures
import contextlib
import dataclasses
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from local_inference import SharedInference
from run import cpu_policy, sha, submit_with_queue_context
from semantic import Context, Recorder
import tune_static
from tune_static import candidates, choose, metrics, paired, priority_problems, replay, summarize, work_signature
from workloads import corpus_inventory, work


def trial(mode="G2", repetition=0, duration=10):
    inference = {"request-A": {"output_sha256": "a", "input_tokens": 8, "output_tokens": 16,
        "queue_wait_ns": 1_000_000_000, "admitted_ns": 101_000_000_000,
        "completed_ns": 105_000_000_000}}
    compiles = []
    if mode != "G0":
        inference["request-B"] = {"output_sha256": "b", "input_tokens": 7, "output_tokens": 16,
            "queue_wait_ns": 2_000_000_000, "admitted_ns": 106_000_000_000,
            "completed_ns": 108_000_000_000}
        compiles = [{"unit": "one", "object_sha256": "obj", "end_ns": 108_000_000_000,
            "release_wait_ns": 3_000_000_000}]
    return {"condition": mode, "repetition": repetition, "run_id": mode + str(repetition),
        "released_ns": 100_000_000_000, "a_latency_ns": 5_000_000_000,
        "makespan_ns": duration * 1_000_000_000, "compile_units": compiles, "inference": inference,
        "tools": {"search": {"stdout_sha256": "search", "end_ns": 3}},
        "fixed_workload": {"tokens_per_request": 16, "B_compile_count": len(compiles),
            "B_request_count": int(mode != "G0"), "inventory_sha256": "inventory"},
        "scheduling_configuration": {"request_priority_enabled": mode == "G4"},
        "a_admission_context": {"queued_request_ids_before_A": ["request-B"] if mode == "G4" else []}}


class StaticTuningTests(unittest.TestCase):
    def test_legacy_policies_unchanged_and_nonzero_cpu_ids_supported(self):
        self.assertEqual(cpu_policy("G2", "SEARCH"), ({0, 1}, {0, 1}, {2, 3}))
        self.assertEqual(cpu_policy("G3", "SEARCH"), ({0}, {0, 1}, {1, 2, 3}))
        self.assertEqual(cpu_policy("G4", "INFERENCE", [4, 5, 6, 7], 3), ({4, 5, 6}, {4, 5, 6}, {7}))
        self.assertEqual(cpu_policy("G2", "A_COMPLETE")[2], {0, 1, 2, 3})
        with self.assertRaises(ValueError):
            cpu_policy("G2", "SEARCH", static_cpus=4)

    def test_candidate_bounds_unique_and_more_than_one(self):
        self.assertEqual(candidates("1:2,2:4,3:2"), [(1, 2), (2, 4), (3, 2)])
        for invalid in ("2:4", "2:4,2:4", "0:4,2:4", "1:9,2:4", "2,3:4"):
            with self.assertRaises(ValueError):
                candidates(invalid)

    def test_tuning_family_rejects_one_cpu_before_starting_any_experiment(self):
        arguments = ["tune_static.py", "--engine", "unused", "--model", "unused", "--sampler", "unused",
            "--output", "unused-output", "--cgroup-parent", "unused-cgroup", "--candidates", "1:2,2:4"]
        errors = io.StringIO()
        with mock.patch("sys.argv", arguments), contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as caught:
            tune_static.main()
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("requires >=2 engine CPUs", errors.getvalue())

    def test_selection_only_uses_predeclared_objective(self):
        rows = [{"reserved_cpus": 2, "compile_workers": 4,
                 "medians": {"makespan_seconds": 5, "a_seconds": 3}},
                {"reserved_cpus": 3, "compile_workers": 2,
                 "medians": {"makespan_seconds": 6, "a_seconds": 1}}]
        self.assertIs(choose(rows), rows[0])
        self.assertIs(choose(rows, "a_seconds"), rows[1])
        with self.assertRaises(ValueError):
            choose(rows, "evaluation_a_seconds")

    def test_fixed_work_signature_excludes_policy_not_objects(self):
        left, right = trial(), trial()
        right["scheduling_configuration"]["compile_workers"] = 1
        right["tools"]["search"]["end_ns"] = 999
        self.assertEqual(work_signature(left), work_signature(right))
        right["compile_units"][0]["object_sha256"] = "different"
        self.assertNotEqual(work_signature(left), work_signature(right))
        self.assertEqual(work_signature(left, a_only=True), work_signature(trial("G0"), a_only=True))

    def test_B_max_wait_and_throughput_not_discarded(self):
        values = metrics(trial())
        self.assertEqual(values["B_max_compile_wait_seconds"], 3)
        self.assertEqual(values["B_max_request_wait_seconds"], 2)
        self.assertEqual(values["B_compile_units_per_second"], 1 / 8)
        self.assertEqual(summarize([values])["B_max_compile_wait_seconds"]["median"], 3)

    def test_negative_performance_result_is_not_hidden(self):
        result = paired([trial("G3", duration=10), trial("G4", duration=12)], "G3", "G4")
        self.assertAlmostEqual(result["makespan_seconds"]["change_percent"]["median"], 20)
        self.assertEqual(result["makespan_seconds"]["absolute_change"]["median"], 2)
        slower = trial("G4", duration=99)
        slower["a_admission_context"]["running_request_ids_before_A"] = ["B-already-running"]
        slower["inference"]["B-already-running"] = {"admitted_ns": 100_000_000_000}
        self.assertEqual(priority_problems(slower), [])
        slower["a_admission_context"]["queued_request_ids_before_A"] = []
        self.assertTrue(all("no_queued_competition" in value for value in priority_problems(slower)))

    def test_already_popped_B_is_not_a_queued_priority_rival(self):
        """Synchronization fixture, not simulated inference performance data."""
        with tempfile.TemporaryDirectory() as temporary:
            recorder = Recorder(Path(temporary) / "semantic.jsonl", "priority-race-fixture")
            a = recorder.declare(Context("priority-race-fixture", "task-A", "agent-A"))
            b = recorder.declare(Context("priority-race-fixture", "task-B", "agent-B"))
            recorder.update_policy(a, 10, {"fixture": "EXPLICIT_PRIORITY"})
            popped, allow_scheduled, allow_running_complete = threading.Event(), threading.Event(), threading.Event()
            original_request = recorder.request

            def controlled_request(context, state, details=None):
                if context.request_id == "B-popped" and state == "SCHEDULED":
                    popped.set()
                    if not allow_scheduled.wait(5):
                        raise TimeoutError("fixture SCHEDULED barrier")
                return original_request(context, state, details)

            recorder.request = controlled_request

            def fixture_infer(service, context, prompt, tokens):
                recorder.request(context, "FIRST_TOKEN", {"fixture": True})
                if context.request_id == "B-popped" and not allow_running_complete.wait(5):
                    raise TimeoutError("fixture running barrier")
                recorder.request(context, "COMPLETE", {"fixture": True})
                return {"fixture": True}

            service = None
            try:
                with mock.patch.object(SharedInference, "_infer", fixture_infer):
                    service = SharedInference(recorder, "unused-fixture://", priority_scheduling=True)
                    with service.condition:
                        running = service.submit(dataclasses.replace(b, request_id="B-popped", tool_call_id="B1"), "fixture", 1)
                        queued = service.submit(dataclasses.replace(b, request_id="B-queued", tool_call_id="B2"), "fixture", 1)
                    self.assertTrue(popped.wait(5))
                    # Worker already removed B1, but has not yet recorded its
                    # SCHEDULED marker. A competes only with still-queued B2.
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        submission = pool.submit(submit_with_queue_context, service, recorder,
                            dataclasses.replace(a, request_id="request-A", tool_call_id="A"), "fixture", 1)
                        allow_scheduled.set()
                        a_future, admission = submission.result(timeout=5)
                    self.assertEqual(admission["queued_request_ids_before_A"], ["B-queued"])
                    self.assertNotIn("B-popped", admission["queued_request_ids_before_A"])
                    allow_running_complete.set()
                    results = [future.result(timeout=5) for future in (running, a_future, queued)]
                    order = [result["request_id"] for result in sorted(results, key=lambda value: value["admitted_ns"])]
                    self.assertEqual(order, ["B-popped", "request-A", "B-queued"])
                    self.assertEqual(priority_problems({"condition": "G4", "run_id": "fixture",
                        "a_admission_context": admission,
                        "inference": {value["request_id"]: value for value in results}}), [])
            finally:
                allow_scheduled.set()
                allow_running_complete.set()
                if service:
                    service.close()
                recorder.close()

    def test_real_corpus_scope_no_git_or_symlink_target_and_each_query_timed(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            (source / "main.py").write_text("needle literal\nnormal\n")
            (source / ".git").mkdir()
            (source / ".git/hidden").write_text("needle hidden\n")
            (base / "outside").write_text("needle outside\n")
            (source / "link").symlink_to(base / "outside")
            before = corpus_inventory(source)
            self.assertEqual(set(before["inventory"]), {"main.py", "link"})
            self.assertEqual(before["inventory"]["link"]["kind"], "SYMLINK_NOT_FOLLOWED")
            result = work("search", base, 3, source, "needle")
            self.assertEqual(result["matches"], 1)
            self.assertEqual(len(result["queries"]), 3)
            for index, query in enumerate(result["queries"]):
                self.assertEqual(query["query_index"], index)
                self.assertGreater(query["duration_ns"], 0)
                self.assertEqual(query["duration_ns"], query["end_ns"] - query["begin_ns"])
                self.assertEqual(query["stdout_sha256"], result["stdout_sha256"])
            self.assertEqual(before, corpus_inventory(source))
            empty = work("search", base, 1, source, "no-such-literal")
            self.assertEqual(empty["matches"], 0)
            self.assertEqual(empty["queries"][0]["returncode"], 1)
            (source / "main.py").write_text("changed\n")
            self.assertNotEqual(before["inventory_sha256"], corpus_inventory(source)["inventory_sha256"])

    def test_replay_freezes_baseline_and_checks_equal_work_and_priority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def write(path, value):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
            binding = {"engine_sha256": "engine", "model_sha256": "model", "sampler_sha256": "sampler"}
            manifest = {**binding, "candidate_order": [[1, 2], [2, 4]], "tuning_repetitions": 2,
                "evaluation_repetitions": 3, "evaluation_conditions": ["G0", "G1", "G2", "G3", "G4"],
                "objective": "makespan_seconds"}
            write(root / "experiment.json", manifest)
            rows = []
            for reserved, workers in manifest["candidate_order"]:
                directory = root / ("tune-c%d-w%d" % (reserved, workers))
                write(directory / "campaign.json", {**binding, "args": {"static_cpus": reserved, "compile_workers": workers}})
                trials = [trial(repetition=rep, duration=10 + reserved) for rep in range(2)]
                for rep, value in enumerate(trials):
                    write(directory / ("trial-%d" % rep) / "trial.json", value)
                measures = summarize([metrics(value) for value in trials])
                rows.append({"reserved_cpus": reserved, "compile_workers": workers,
                    "medians": {key: value["median"] if value else None for key, value in measures.items()},
                    "statistics": measures, "campaign_sha256": sha(directory / "campaign.json")})
            selected = choose(rows)
            write(root / "selection.json", {"selected": selected, "frozen_wall_ns": 100})
            write(root / "evaluation-start.json", {"selection_sha256": sha(root / "selection.json"), "started_wall_ns": 101})
            write(root / "evaluation/campaign.json", {**binding, "args": {"static_cpus": 1, "compile_workers": 2}})
            for mode in manifest["evaluation_conditions"]:
                for rep in range(3):
                    write(root / "evaluation" / ("trial-%s-%d" % (mode, rep)) / "trial.json", trial(mode, rep))
            result = replay(root, resource_replay=False)
            self.assertEqual(result["problems"], [])
            self.assertEqual(result["status"], "INCOMPLETE")  # No resource replay is never a full pass.
            self.assertEqual(result["evaluation_trial_count"], 15)
            self.assertEqual(len(result["G4_queued_competition_exercised_trials"]), 3)
            path = root / "evaluation/trial-G4-0/trial.json"
            changed = json.loads(path.read_text())
            changed["inference"]["request-B"]["admitted_ns"] = 100_000_000_000
            write(path, changed)
            self.assertTrue(any("priority_not_applied" in problem for problem in replay(root, resource_replay=False)["problems"]))
            changed["compile_units"][0]["object_sha256"] = "tampered"
            write(path, changed)
            self.assertTrue(any("outputs_changed" in problem for problem in replay(root, resource_replay=False)["problems"]))
            write(root / "evaluation-start.json", {"selection_sha256": "wrong", "started_wall_ns": 99})
            self.assertIn("evaluation_not_bound_to_prior_frozen_selection", replay(root, resource_replay=False)["problems"])


if __name__ == "__main__":
    unittest.main()
