#!/usr/bin/env python3
"""Bounded static-baseline tuning, frozen selection, then fresh G0..G4 repeats.

CPU-only mechanism experiment, not a Terminal/SWE score or GPU experiment.
All evidence is append-only. Evaluation never participates in baseline selection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
import time
from pathlib import Path

from analyze import analyze, interval
from run import sha, write_json
from workloads import corpus_inventory, prepare_assets

HERE = Path(__file__).resolve().parent
METRICS = ("a_seconds", "makespan_seconds", "B_compile_units_per_second", "B_total_seconds",
           "B_max_compile_wait_seconds", "B_max_request_wait_seconds", "a_request_wait_seconds")


def candidates(value):
    result = []
    for pair in value.split(","):
        fields = pair.split(":")
        if len(fields) != 2:
            raise ValueError("candidate syntax is reserved_CPUs:compiler_workers")
        reserved, workers = map(int, fields)
        if not 1 <= reserved <= 3 or not 1 <= workers <= 8 or (reserved, workers) in result:
            raise ValueError("unique bounded CPU/worker candidates required")
        result.append((reserved, workers))
    if len(result) < 2 or len(result) > 12:
        raise ValueError("compare 2..12 predeclared candidates")
    return result


def metrics(trial):
    units = trial["compile_units"]
    requests = [value for key, value in trial["inference"].items() if key != "request-A"]
    release = trial["released_ns"]
    compile_seconds = (max(unit["end_ns"] for unit in units) - release) / 1e9 if units else None
    all_ends = [unit["end_ns"] for unit in units] + [value["completed_ns"] for value in requests]
    return {"a_seconds": trial["a_latency_ns"] / 1e9, "makespan_seconds": trial["makespan_ns"] / 1e9,
        "B_compile_units_per_second": len(units) / compile_seconds if compile_seconds else None,
        "B_total_seconds": (max(all_ends) - release) / 1e9 if all_ends else None,
        "B_max_compile_wait_seconds": max((unit["release_wait_ns"] / 1e9 for unit in units), default=None),
        "B_max_request_wait_seconds": max((value["queue_wait_ns"] / 1e9 for value in requests), default=None),
        "a_request_wait_seconds": trial["inference"]["request-A"]["queue_wait_ns"] / 1e9}


def work_signature(trial, a_only=False):
    """No scheduling/policy field belongs in the exact-work signature."""
    fixed = dict(trial["fixed_workload"])
    if a_only:
        fixed.pop("B_request_count")
        fixed.pop("B_compile_count")
    return {"fixed": fixed,
        "objects": {} if a_only else {unit["unit"]: unit["object_sha256"] for unit in trial["compile_units"]},
        "models": {key: {field: value[field] for field in ("output_sha256", "input_tokens", "output_tokens")}
            for key, value in trial["inference"].items() if not a_only or key == "request-A"},
        "tools": {name: {key: value[key] for key in ("stdout_sha256", "output_sha256") if key in value}
            for name, value in trial["tools"].items()}}


def load_trials(directory):
    return [json.loads(path.read_text()) for path in sorted(Path(directory).glob("trial-*/trial.json"))]


def choose(rows, objective="makespan_seconds"):
    """Best among tested candidates, not a claim of a globally optimal policy."""
    if objective not in ("makespan_seconds", "a_seconds") or not rows:
        raise ValueError("predeclare a recognized objective and nonempty candidates")
    return min(rows, key=lambda row: (row["medians"][objective], row["reserved_cpus"], row["compile_workers"]))


def summarize(rows):
    return {metric: interval([row[metric] for row in rows if row[metric] is not None]) for metric in METRICS}


def paired(trials, baseline, intervention):
    lookup = {(trial["condition"], trial["repetition"]): metrics(trial) for trial in trials}
    repetitions = sorted(rep for condition, rep in lookup if condition == baseline and (intervention, rep) in lookup)
    return {metric: {"absolute_change": interval([lookup[(intervention, rep)][metric] - lookup[(baseline, rep)][metric]
            for rep in repetitions if lookup[(baseline, rep)][metric] is not None and lookup[(intervention, rep)][metric] is not None]),
        "change_percent": interval([(lookup[(intervention, rep)][metric] / lookup[(baseline, rep)][metric] - 1) * 100
            for rep in repetitions if lookup[(baseline, rep)][metric] is not None and lookup[(baseline, rep)][metric] > 0
            and lookup[(intervention, rep)][metric] is not None])} for metric in METRICS}


def priority_problems(trial):
    """Check application admission order only, never require a speedup.

    Running/already-popped requests are not eligible for nonpreemptive priority.
    Only queue members observed under the same lock as A enqueue are checked.
    """
    if trial["condition"] != "G4":
        return []
    queued = trial.get("a_admission_context", {}).get("queued_request_ids_before_A")
    if not queued:
        return [trial["run_id"] + ":G4_no_queued_competition_opportunity_observed"]
    a_admitted = trial["inference"]["request-A"]["admitted_ns"]
    return [trial["run_id"] + ":priority_not_applied_to_preexisting_queue:" + request
        for request in queued if request not in trial["inference"]
        or trial["inference"][request]["admitted_ns"] <= a_admitted]


def replay(root, resource_replay=True):
    """Rebuild selection and evaluation from raw trial/runtime/resource records."""
    root = Path(root)
    manifest = json.loads((root / "experiment.json").read_text())
    selection = json.loads((root / "selection.json").read_text())
    start = json.loads((root / "evaluation-start.json").read_text())
    problems, candidate_rows, all_mixed, analyses = [], [], [], {}

    def check_search_scope(name, path, campaign):
        expected = manifest.get("external_search")
        if campaign["args"].get("external_search_config") != expected:
            problems.append(name + ":external_search_scope_or_query_changed")
        if expected and "inventory_sha256" in expected:
            if sha(path / "external-search-inventory.json") != expected["manifest_sha256"]:
                problems.append(name + ":external_search_inventory_binding_mismatch")
            after = json.loads((path / "external-search-postcheck.json").read_text())
            if (after.get("unchanged") is not True or after.get("before_inventory_sha256") != expected["inventory_sha256"]
                    or after.get("after_inventory_sha256") != expected["inventory_sha256"]):
                problems.append(name + ":external_search_corpus_changed")

    for candidate in manifest["candidate_order"]:
        name = "tune-c%d-w%d" % tuple(candidate)
        path = root / name
        trials = load_trials(path)
        campaign = json.loads((path / "campaign.json").read_text())
        check_search_scope(name, path, campaign)
        if (len(trials) != manifest["tuning_repetitions"] or any(trial["condition"] != "G2" for trial in trials)
                or {trial["repetition"] for trial in trials} != set(range(manifest["tuning_repetitions"]))):
            problems.append(name + ":tuning_trials_missing_or_wrong_condition")
        if (campaign["args"]["static_cpus"], campaign["args"]["compile_workers"]) != tuple(candidate):
            problems.append(name + ":candidate_configuration_changed")
        for field in ("engine_sha256", "model_sha256", "sampler_sha256"):
            if campaign[field] != manifest[field]:
                problems.append(name + ":binary_binding_mismatch:" + field)
        if not trials:
            continue
        measures = summarize([metrics(trial) for trial in trials])
        candidate_rows.append({"reserved_cpus": candidate[0], "compile_workers": candidate[1],
            "medians": {key: value["median"] if value else None for key, value in measures.items()},
            "statistics": measures, "campaign_sha256": sha(path / "campaign.json")})
        all_mixed.extend(trials)
        if resource_replay:
            analyses[name] = analyze(path)
    if not candidate_rows or choose(candidate_rows, manifest["objective"]) != selection["selected"]:
        problems.append("baseline_selection_does_not_replay")
    if start["selection_sha256"] != sha(root / "selection.json") or start["started_wall_ns"] <= selection["frozen_wall_ns"]:
        problems.append("evaluation_not_bound_to_prior_frozen_selection")
    evaluation = root / "evaluation"
    evaluation_manifest = json.loads((evaluation / "campaign.json").read_text())
    check_search_scope("evaluation", evaluation, evaluation_manifest)
    evaluation_trials = load_trials(evaluation)
    args = evaluation_manifest["args"]
    for field in ("engine_sha256", "model_sha256", "sampler_sha256"):
        if evaluation_manifest[field] != manifest[field]:
            problems.append("evaluation_binary_binding_mismatch:" + field)
    if (args["static_cpus"], args["compile_workers"]) != (
            selection["selected"]["reserved_cpus"], selection["selected"]["compile_workers"]):
        problems.append("evaluation_changed_frozen_baseline")
    expected_keys = {(condition, rep) for condition in manifest["evaluation_conditions"]
                     for rep in range(manifest["evaluation_repetitions"])}
    keys = [(trial["condition"], trial["repetition"]) for trial in evaluation_trials]
    if len(keys) != len(expected_keys) or set(keys) != expected_keys:
        problems.append("evaluation_incomplete_or_duplicate")
    all_mixed += [trial for trial in evaluation_trials if trial["condition"] != "G0"]
    if all_mixed:
        reference = work_signature(all_mixed[0])
        a_reference = work_signature(all_mixed[0], a_only=True)
        for trial in all_mixed:
            if work_signature(trial) != reference:
                problems.append(trial["run_id"] + ":fixed_B_work_or_outputs_changed")
        for trial in evaluation_trials:
            if work_signature(trial, a_only=True) != a_reference:
                problems.append(trial["run_id"] + ":A_work_or_outputs_changed")
    for trial in all_mixed:
        configuration = trial.get("scheduling_configuration", {})
        if configuration.get("request_priority_enabled") != (trial["condition"] == "G4"):
            problems.append(trial["run_id"] + ":priority_configuration_not_bound")
    if resource_replay:
        analyses["evaluation"] = analyze(evaluation)
        for name, result in analyses.items():
            if result["status"] != "VALIDATED_WITH_DECLARED_SCOPE":
                problems.append(name + ":runtime_or_resource_replay_incomplete")
            for trial in result["trials"]:
                dispatch = [row for row in trial["thread_resources"].get("intervals", [])
                    if row.get("native_scope") == "REQUEST_SCOPED_NATIVE_DISPATCH_INTERVAL_NOT_EXCLUSIVE_ONCPU"]
                if not dispatch or any(row.get("wait_ns") is None or row.get("counter_status") != "COMPLETE" for row in dispatch):
                    problems.append(name + ":" + trial["trial"] + ":selected_dispatch_thread_wait_not_measured")
    aggregates = {condition: summarize([metrics(trial) for trial in evaluation_trials if trial["condition"] == condition])
                  for condition in manifest["evaluation_conditions"]}
    comparisons = {left + "_to_" + right: paired(evaluation_trials, left, right)
                  for left, right in (("G1", "G2"), ("G2", "G3"), ("G3", "G4"), ("G2", "G4"))}
    priority_exercised = [trial["run_id"] for trial in evaluation_trials if trial["condition"] == "G4"
                         and trial.get("a_admission_context", {}).get("queued_request_ids_before_A")]
    for trial in evaluation_trials:
        problems.extend(priority_problems(trial))
    return {"schema_version": 1, "status": "PASS_WITH_DECLARED_SCOPE" if not problems and resource_replay else "INCOMPLETE",
        "problems": problems, "resource_replay_performed": resource_replay, "candidates": candidate_rows,
        "selected": selection["selected"], "selection_objective": manifest["objective"],
        "selection_claim": "BEST_MEDIAN_AMONG_PREDECLARED_CANDIDATES_NOT_GLOBAL_OPTIMUM",
        "evaluation_trial_count": len(evaluation_trials), "evaluation_aggregates": aggregates,
        "paired_changes": comparisons, "G4_queued_competition_exercised_trials": priority_exercised,
        "priority_validation": "QUEUED_COMPETITION_OBSERVED_EVERY_G4_REPEAT"
            if len(priority_exercised) == manifest["evaluation_repetitions"] else "SOME_OR_ALL_G4_REPEATS_WITHOUT_PRIORITY_OPPORTUNITY_NOT_FULLY_VALIDATED",
        "fixed_work_and_outputs": "EXACT_EQUALITY" if not any("outputs_changed" in value for value in problems) else "MISMATCH",
        "GPU": "EXCLUDED_BY_REQUEST", "negative_results_allowed": True,
        "scope": "CPU_ONLY_FIXED_MECHANISM_NOT_BENCHMARK_SCORE_OR_PRODUCTION_MODEL_SLA",
        "runtime_and_resources": analyses}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--sampler", type=Path, required=True)
    parser.add_argument("--kernel-hist-object", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cgroup-parent", type=Path, required=True)
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--search-corpus", type=Path, help="fixed real benchmark source snapshot; does not replace fixed B compilation work")
    parser.add_argument("--search-query", default="TARGET_731")
    parser.add_argument("--candidates", default="2:2,2:4,3:2,3:4")
    parser.add_argument("--objective", choices=["makespan_seconds", "a_seconds"], default="makespan_seconds")
    parser.add_argument("--tuning-repetitions", type=int, default=3)
    parser.add_argument("--evaluation-repetitions", type=int, default=5)
    parser.add_argument("--seed", type=int, default=1731)
    parser.add_argument("--native-profile", choices=["LIGHT", "FORENSIC"], default="LIGHT")
    parser.add_argument("--tokens", type=int, default=256)
    parser.add_argument("--b-requests", type=int, default=4)
    parser.add_argument("--compile-units", type=int, default=8)
    parser.add_argument("--functions-per-unit", type=int, default=96)
    parser.add_argument("--search-repeats", type=int, default=1)
    parser.add_argument("--prepare-rounds", type=int, default=128)
    args = parser.parse_args()
    try:
        candidate_order = candidates(args.candidates)
    except ValueError as error:
        parser.error(str(error))
    if any(reserved < 2 for reserved, _ in candidate_order):
        parser.error("this two-GGML-worker candidate family requires >=2 engine CPUs; use run.py explicitly for oversubscription failure diagnostics")
    if not 2 <= args.tuning_repetitions <= 10 or not 3 <= args.evaluation_repetitions <= 10:
        parser.error("need 2..10 tuning and 3..10 fresh evaluation repeats")
    if Path("/proc/sys/kernel/sched_schedstats").read_text().strip() != "1":
        parser.error("enable kernel.sched_schedstats=1 in the cooperative Guest before this experiment")
    args.output.mkdir(parents=True, exist_ok=False)
    args.cgroup_parent.mkdir(exist_ok=False)
    (args.cgroup_parent / "cgroup.subtree_control").write_text("+cpuset +cpu +memory +io +pids")
    assets = args.assets.resolve() if args.assets else args.output / "assets"
    if not args.assets:
        prepare_assets(assets, units=args.compile_units, functions=args.functions_per_unit)
    external_search = None
    if args.search_corpus:
        args.search_corpus = args.search_corpus.resolve(strict=True)
        external_inventory = corpus_inventory(args.search_corpus)
        write_json(args.output / "external-search-inventory.json", external_inventory)
        external_search = {key: value for key, value in external_inventory.items() if key != "inventory"}
        external_search["manifest_sha256"] = sha(args.output / "external-search-inventory.json")
    if external_search is not None or args.search_query != "TARGET_731":
        external_search = external_search or {}
        external_search["query_sha256"] = hashlib.sha256(args.search_query.encode()).hexdigest()
    random.Random(args.seed).shuffle(candidate_order)
    manifest = {"schema_version": 1, "candidate_order": candidate_order, "objective": args.objective,
        "tuning_repetitions": args.tuning_repetitions, "evaluation_repetitions": args.evaluation_repetitions,
        "evaluation_conditions": ["G0", "G1", "G2", "G3", "G4"],
        "engine_sha256": sha(args.engine), "model_sha256": sha(args.model),
        "sampler_sha256": sha(args.sampler), "runner_sha256": sha(HERE / "run.py"),
        "external_search": external_search,
        "selection_rule": "LOWEST_MEDIAN_PREDECLARED_OBJECTIVE_THEN_CPU_COUNT_THEN_WORKER_COUNT",
        "candidate_family": "FIXED_TWO_GGML_WORKERS_AT_LEAST_TWO_RESERVED_ENGINE_CPUS",
        "seed": args.seed, "GPU": "EXCLUDED_BY_REQUEST"}
    write_json(args.output / "experiment.json", manifest)

    def launch_campaign(name, cpu_count, workers, conditions, repetitions, seed):
        command = [sys.executable, str(HERE / "run.py"), "--engine", str(args.engine.resolve()),
            "--model", str(args.model.resolve()), "--sampler", str(args.sampler.resolve()),
            "--output", str((args.output / name).resolve()), "--cgroup-parent", str(args.cgroup_parent / name),
            "--assets", str(assets.resolve()), "--static-cpus", str(cpu_count), "--compile-workers", str(workers),
            "--conditions", conditions, "--repetitions", str(repetitions), "--seed", str(seed),
            "--tokens", str(args.tokens), "--b-requests", str(args.b_requests), "--compile-units", str(args.compile_units),
            "--functions-per-unit", str(args.functions_per_unit), "--search-repeats", str(args.search_repeats),
            "--prepare-rounds", str(args.prepare_rounds), "--sample-threads", "--require-thread-wait",
            "--native-profile", args.native_profile]
        if args.search_corpus:
            command += ["--search-corpus", str(args.search_corpus)]
        command += ["--search-query", args.search_query]
        if args.kernel_hist_object:
            command += ["--kernel-hist-object", str(args.kernel_hist_object.resolve()), "--kernel-hist-groups", "sched"]
        subprocess.run(command, check=True)

    try:
        rows = []
        for index, (cpu_count, workers) in enumerate(candidate_order):
            name = "tune-c%d-w%d" % (cpu_count, workers)
            launch_campaign(name, cpu_count, workers, "G2", args.tuning_repetitions, args.seed + index)
            measures = summarize([metrics(trial) for trial in load_trials(args.output / name)])
            rows.append({"reserved_cpus": cpu_count, "compile_workers": workers,
                "medians": {key: value["median"] if value else None for key, value in measures.items()},
                "statistics": measures, "campaign_sha256": sha(args.output / name / "campaign.json")})
        selected = choose(rows, args.objective)
        write_json(args.output / "selection.json", {"schema_version": 1, "selected": selected,
            "candidate_results": rows, "objective": args.objective, "frozen_wall_ns": time.time_ns(),
            "evaluation_used_for_selection": False})
        write_json(args.output / "evaluation-start.json", {"selection_sha256": sha(args.output / "selection.json"),
            "started_wall_ns": time.time_ns(), "seed": args.seed + 100_000})
        launch_campaign("evaluation", selected["reserved_cpus"], selected["compile_workers"],
                        "G0,G1,G2,G3,G4", args.evaluation_repetitions, args.seed + 100_000)
        result = replay(args.output)
        write_json(args.output / "verdict.json", result)
        print(json.dumps({key: result[key] for key in ("status", "selected", "evaluation_trial_count", "problems")}), flush=True)
        if result["status"] != "PASS_WITH_DECLARED_SCOPE":
            raise SystemExit(1)
    finally:
        if "populated 0" in (args.cgroup_parent / "cgroup.events").read_text().splitlines():
            args.cgroup_parent.rmdir()


if __name__ == "__main__":
    main()
