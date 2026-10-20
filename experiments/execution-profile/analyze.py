#!/usr/bin/env python3
"""Offline semantic/native replay, fixed-work checks and paired uncertainty."""
import argparse
import hashlib
import importlib.util
import json
import random
import statistics
import dataclasses
from pathlib import Path

from local_inference import verify_native
from semantic import Context, verify


def interval(values, seed=731, samples=4000):
    if not values:
        return None
    rng = random.Random(seed)
    estimates = sorted(statistics.median(rng.choices(values, k=len(values))) for _ in range(samples))
    return {"n": len(values), "median": statistics.median(values),
            "bootstrap_median_ci95": [estimates[int(samples * .025)], estimates[int(samples * .975)]],
            "maximum": max(values), "method": "PAIRED_BLOCK_RESAMPLE_MEDIAN_FIXED_SEED"}


def counter_delta(first, last, location, issues):
    """Missing/reset cumulative counters are unknown, never zero or negative work."""
    if type(first) is not int or type(last) is not int:
        issues.append("counter_missing_or_invalid:" + location)
        return None
    if first < 0 or last < first:
        issues.append("counter_regression:" + location)
        return None
    return last - first


def io_delta(first, last, issues):
    if not isinstance(first, dict) or not isinstance(last, dict):
        issues.append("counter_missing_or_invalid:io_stat_by_device")
        return None
    result = {}
    for device in sorted(set(first) | set(last)):
        before, after = first.get(device), last.get(device)
        if not isinstance(before, dict) or not isinstance(after, dict):
            issues.append("counter_missing_or_invalid:io_stat_by_device." + device)
        before = before if isinstance(before, dict) else {}
        after = after if isinstance(after, dict) else {}
        result[device] = {key: counter_delta(before.get(key), after.get(key),
            "io_stat_by_device." + device + "." + key, issues)
            for key in sorted(set(before) | set(after))}
    return result


def load_health(path, begin, end, groups, boot_id=None, expected_label=None):
    if not path.exists():
        return {"status": "NOT_ENABLED", "attribution": "NO_RESOURCE_EVIDENCE"}
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    errors = []
    try:
        meta = json.loads((path.parent / "load-meta.json").read_text())
        stats = json.loads((path.parent / "load-sampler-stats.json").read_text())
    except (OSError, ValueError):
        return {"status": "INCOMPLETE", "errors": ["missing_or_invalid_sampler_meta_stats"]}
    if boot_id and meta.get("boot_id") != boot_id:
        errors.append("sampler_boot_identity_mismatch")
    if expected_label and meta.get("label") != expected_label:
        errors.append("sampler_run_label_mismatch")
    expected = list(groups.values())
    if len(meta.get("cgroups", [])) != len(expected):
        errors.append("sampler_group_count_mismatch")
    for index, identity in enumerate(meta.get("cgroups", [])):
        if index >= len(expected) or any(identity.get(field) != expected[index][field] for field in ("path", "inode", "device")):
            errors.append("sampler_group_identity_mismatch")
        for source in ("cpu.stat", "memory.stat", "io.stat", "pressure"):
            if not identity.get("available", {}).get(source):
                errors.append("cgroup_source_unavailable:" + source)
    for counter in ("read_errors", "missed_ticks", "truncated_process_sets", "truncated_cgroup_traversals", "cgroup_traversal_read_errors"):
        if type(stats.get(counter)) is not int or stats[counter] != 0:
            errors.append("sampler_quality_counter:" + counter)
    if not rows or rows[0]["monotonic_ns"] >= begin or rows[-1]["monotonic_ns"] <= end:
        errors.append("missing_before_after_execution_brackets")
    last = 0
    for index, row in enumerate(rows):
        if row["seq"] != index or row["monotonic_ns"] <= last:
            errors.append("sample_sequence_or_time_invalid")
        last = row["monotonic_ns"]
        if row.get("errors") or row.get("collection_end_ns", 0) < row["monotonic_ns"]:
            errors.append("sampler_collection_error_or_time_invalid")
        if len(row.get("cgroups", [])) != len(expected):
            errors.append("sample_cgroup_count_mismatch")
        for resource in ("cpu", "memory", "io"):
            if not isinstance(row.get("psi", {}).get(resource), dict):
                errors.append("system_PSI_missing:" + resource)
        for group_index, group in enumerate(row.get("cgroups", [])):
            if group.get("present") is not True:
                errors.append("cgroup_missing")
            for resource in ("cpu", "memory", "io"):
                if not isinstance(group.get("psi", {}).get(resource), dict):
                    errors.append("cgroup_PSI_missing:" + resource)
            if index and group_index < len(rows[index - 1].get("cgroups", [])):
                before = rows[index - 1]["cgroups"][group_index]
                for category in ("cpu_stat", "memory_events", "psi"):
                    def flattened(data, prefix=""):
                        for key, value in data.items():
                            if isinstance(value, dict):
                                yield from flattened(value, prefix + key + ".")
                            else:
                                yield prefix + key, value
                    previous = dict(flattened(before.get(category, {})))
                    current = dict(flattened(group.get(category, {})))
                    for key in sorted(set(previous) | set(current)):
                        counter_delta(previous.get(key), current.get(key), category + "." + key, errors)
                for key in ("pgfault", "pgmajfault"):
                    counter_delta(before.get("memory_stat", {}).get(key),
                                  group.get("memory_stat", {}).get(key), "memory_stat." + key, errors)
                io_delta(before.get("io_stat_by_device"), group.get("io_stat_by_device"), errors)
    # Keep raw schema intact and raw resources reviewable. Counters are cgroup
    # totals, not request costs of a resident shared service.
    return {"status": "COMPLETE" if not errors else "INCOMPLETE", "errors": sorted(set(errors)),
            "sample_count": len(rows), "first_ns": rows[0]["monotonic_ns"] if rows else None,
            "last_ns": rows[-1]["monotonic_ns"] if rows else None,
            "group_identities": groups, "shared_engine_cost": "SERVICE_TOTAL_NOT_PER_AGENT_CPU_COST",
            "thread_sampling_status": stats.get("thread_sampling_status", "DISABLED"),
            "stats": stats, "attribution": "TEMPORAL_PHASE_ASSOCIATION_NOT_CAUSAL_PROOF"}


def resource_windows(path, intervals, groups):
    if not path.exists():
        return {"status": "NOT_ENABLED", "windows": []}
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    meta = json.loads((path.parent / "load-meta.json").read_text())
    stats = json.loads((path.parent / "load-sampler-stats.json").read_text())
    # Reuse the already strict kernel diagnostic health contract, not a weaker
    # second interpretation. The source digest binds this helper version.
    helper_path = Path(__file__).resolve().parent.parent / "search-profile/analyze.py"
    if not helper_path.is_file():
        helper_path = Path(__file__).resolve().parent.parent / "search/analyze.py"
    kernel_health = {"status": "NOT_COLLECTED"}
    if meta.get("kernel_hist"):
        if helper_path.is_file():
            specification = importlib.util.spec_from_file_location("execution_shared_search_health", helper_path)
            helper = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(helper)
            problems = helper.Problems()
            kernel_health = helper._kernel_hist(meta, stats, rows, problems, requested=True)
            kernel_health["helper_sha256"] = hashlib.sha256(helper_path.read_bytes()).hexdigest()
        else:
            kernel_health = {"status": "INCOMPLETE", "issues": ["STRICT_KERNEL_HEALTH_HELPER_MISSING"]}
    configuration = meta.get("kernel_hist") or {}
    metrics = {metric["name"]: index for index, metric in enumerate(configuration.get("metrics", []))
               if metric.get("subsystem") in configuration.get("groups", []) and metric.get("scope") == "target"}
    windows = []
    for label, begin, end, actor in intervals:
        before = [row for row in rows if row["monotonic_ns"] <= begin]
        after = [row for row in rows if row["monotonic_ns"] >= end]
        if not before or not after:
            windows.append({"phase": label, "status": "UNBRACKETED", "begin_ns": begin, "end_ns": end})
            continue
        left, right = before[-1], after[0]
        domains = {}
        for index, name in enumerate(groups):
            a, b = left["cgroups"][index], right["cgroups"][index]
            issues = []
            delta = lambda category, key: counter_delta(a.get(category, {}).get(key),
                b.get(category, {}).get(key), category + "." + key, issues)
            psi = {}
            for resource in ("cpu", "memory", "io"):
                before_psi = a.get("psi", {}).get(resource, {})
                after_psi = b.get("psi", {}).get(resource, {})
                if not before_psi or not after_psi:
                    issues.append("counter_missing_or_invalid:psi." + resource)
                psi[resource] = {key: counter_delta(before_psi.get(key), after_psi.get(key),
                    "psi." + resource + "." + key, issues) for key in sorted(set(before_psi) | set(after_psi))}
            domain = {"cpu_usage_usec": delta("cpu_stat", "usage_usec"),
                      "cpu_throttled_usec": delta("cpu_stat", "throttled_usec"),
                      "psi_delta_us_by_resource_not_additive": psi,
                      "memory_current_before": a.get("memory_current"), "memory_current_after": b.get("memory_current"),
                      "pgmajfault": delta("memory_stat", "pgmajfault"), "pgfault": delta("memory_stat", "pgfault"),
                      "io_by_device": io_delta(a.get("io_stat_by_device"), b.get("io_stat_by_device"), issues),
                      "attribution": "SHARED_SERVICE_TOTAL_NOT_REQUEST_COST" if name == "shared-engine" else "DECLARED_CGROUP_WINDOW"}
            kh_left, kh_right = left.get("khist", {}).get("domains", []), right.get("khist", {}).get("domains", [])
            if index < len(kh_left) and index < len(kh_right):
                hist = {}
                for metric, metric_index in metrics.items():
                    first, last = kh_left[index]["m"][metric_index], kh_right[index]["m"][metric_index]
                    hist[metric] = {"completed_count": counter_delta(first[0], last[0], "kernel_hist." + metric + ".count", issues),
                                    "completed_sum_ns": counter_delta(first[1], last[1], "kernel_hist." + metric + ".sum_ns", issues)}
                domain["kernel_completed_spans_not_disjoint_wall_time"] = hist
                domain["kernel_groups_selected"] = configuration.get("groups", [])
            domain["counter_status"] = "COMPLETE" if not issues else "INCOMPLETE"
            domain["counter_issues"] = sorted(set(issues))
            domains[name] = domain
        windows.append({"phase": label, "begin_ns": begin, "end_ns": end, "actor": actor,
            "sample_envelope_start_ns": left["monotonic_ns"], "sample_envelope_end_ns": right["monotonic_ns"],
            "before_uncertainty_ns": begin - left["monotonic_ns"], "after_uncertainty_ns": right["monotonic_ns"] - end,
            "scope": "BRACKETED_NON_ATOMIC_SAMPLE_ENVELOPE_CAN_INCLUDE_NEIGHBORING_PHASE_WORK",
            "not_additive_between_phases": True, "domains": domains})
    return {"status": "PHASE_RESOURCE_ENVELOPES_WITH_EXPLICIT_RESOLUTION", "windows": windows,
            "quality_status": "INCOMPLETE" if any(window.get("status") == "UNBRACKETED" or
                any(domain["counter_status"] != "COMPLETE" for domain in window.get("domains", {}).values())
                for window in windows) else "COMPLETE",
            "kernel_health": kernel_health,
            "interpretation": "Compare slow phase envelopes across fixed-work conditions; PSI resources and overlapping completed spans are never summed into wall time."}


def thread_associations(path, intervals):
    if not path.exists():
        return {"status": "NOT_ENABLED", "intervals": []}
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    by_instance = {}
    fields = ("boot_id", "pid", "process_start_ticks", "tid", "thread_start_ticks")
    for sample in rows:
        for group in sample.get("cgroups", []):
            for process in group.get("processes", []):
                for thread in process.get("tid_samples", []):
                    key = tuple(thread["identity"][field] for field in fields)
                    by_instance.setdefault(key, []).append(thread)
    result = []
    for interval in intervals:
        actor = interval["actor"]
        matching = by_instance.get(tuple(actor[field] for field in fields), [])
        left = [sample for sample in matching if sample["collection_end_ns"] <= interval["start_ns"]]
        right = [sample for sample in matching if sample["collection_start_ns"] >= interval["end_ns"]]
        record = {"actor": actor, "start_ns": interval["start_ns"], "end_ns": interval["end_ns"],
                  "request_id": interval.get("request_id"), "requests": interval.get("requests"),
                  "native_scope": interval["scope"], "status": "NO_BRACKETING_TID_SAMPLES_SHORT_THREAD_OR_POLLING_GAP",
                  "sample_bracketed": False, "counter_status": "INCOMPLETE", "run_ns": None, "wait_ns": None}
        if left and right:
            first, last = left[-1], right[0]
            issues = []
            envelope = [sample for sample in matching if
                first["collection_start_ns"] <= sample["collection_start_ns"] <= last["collection_start_ns"]]
            counters = {}
            for field in ("run_ns", "wait_ns"):
                counter_issues = []
                for before, after in zip(envelope, envelope[1:]):
                    counter_delta(before.get(field), after.get(field), "tid." + field, counter_issues)
                value = counter_delta(first.get(field), last.get(field), "tid." + field, counter_issues)
                if field == "wait_ns" and any(sample.get("wait_counter_status") != "ENABLED" for sample in envelope):
                    counter_issues.append("counter_disabled_or_unknown:tid.wait_ns")
                counters[field] = None if counter_issues else value
                issues.extend(counter_issues)
            record.update(status="UNRESOLVED_THREAD_COUNTER_ENVELOPE" if issues else
                          "BRACKETED_THREAD_COUNTER_ENVELOPE_NOT_EXCLUSIVE_REQUEST_COST",
                          sample_bracketed=True, counter_status="INCOMPLETE" if issues else "COMPLETE",
                          counter_issues=sorted(set(issues)),
                          before_uncertainty_ns=interval["start_ns"] - first["collection_end_ns"],
                          after_uncertainty_ns=last["collection_start_ns"] - interval["end_ns"],
                          **counters)
        result.append(record)
    return {"status": "PARTIAL_POLLING_NEVER_FULL_THREAD_LIFECYCLE", "intervals": result,
            "quality_status": "INCOMPLETE" if any(not record["status"].startswith("BRACKETED") for record in result) else "COMPLETE",
            "sample_bracketed_intervals": sum(record.get("sample_bracketed", False) for record in result),
            "bracketed_intervals": sum(record["status"].startswith("BRACKETED") for record in result),
            "unresolved_intervals": sum(not record["status"].startswith("BRACKETED") for record in result),
            "binding": "BOOT_PID_START_TID_START_AND_NATIVE_PROCESSING_WINDOW_NOT_PERMANENT_AGENT_OWNER"}


def analyze(directory):
    directory = Path(directory)
    campaign = json.loads((directory / "campaign.json").read_text())
    trials, problems = [], []
    for path in sorted(directory.glob("trial-*/trial.json")):
        trial = json.loads(path.read_text())
        folder = path.parent
        semantic = verify(folder / "semantic-events.jsonl")
        expected = json.loads((folder / "expected-requests.json").read_text())
        scheduled = {}
        for event in map(json.loads, (folder / "semantic-events.jsonl").read_text().splitlines()):
            if event["kind"] == "REQUEST_SCHEDULED":
                scheduled[event["request_id"]] = {field.name: event[field.name] for field in dataclasses.fields(Context)}
        if scheduled != expected:
            problems.append({"trial": folder.name, "error": "NATIVE_CONTEXT_NOT_BOUND_TO_SEMANTIC_ADMISSION"})
        native = verify_native(folder / "native-events.jsonl", expected) if trial.get("native_trace", "on") == "on" else {
            "verified": None, "status": "NOT_ENABLED_EXPLICIT_OVERHEAD_CONTROL", "errors": [], "event_count": 0,
            "batch_count": 0, "ggml_worker_processing_intervals": [], "request_dispatch_processing_intervals": []}
        load = load_health(folder / "load/load-samples.jsonl", trial["released_ns"], trial["completed_ns"], trial["cgroups"], campaign["boot_id"], trial["run_id"])
        if semantic["status"] != "COMPLETE" or (trial.get("native_trace", "on") == "on" and not native["verified"]) or load["status"] == "INCOMPLETE":
            problems.append({"trial": folder.name, "semantic": semantic["status"], "native": native["errors"], "load": load})
        phases, phase_intervals = {}, []
        starts = {}
        for event in map(json.loads, (folder / "semantic-events.jsonl").read_text().splitlines()):
            if event["task_id"] == "task-A" and event["kind"] == "BEGIN" and event["phase"] in {"SEARCH", "PREPARE", "INFERENCE"}:
                starts[event["span_id"]] = (event["monotonic_ns"], event["actor"])
            elif event["kind"] == "END" and event["span_id"] in starts:
                phase_start, actor = starts[event["span_id"]]
                phases[event["phase"]] = (event["monotonic_ns"] - phase_start) / 1e9
                phase_intervals.append((event["phase"], phase_start, event["monotonic_ns"], actor))
        resources = resource_windows(folder / "load/load-samples.jsonl", phase_intervals, trial["cgroups"])
        threads = thread_associations(folder / "load/load-processes.jsonl",
            native["request_dispatch_processing_intervals"] + native["ggml_worker_processing_intervals"])
        if resources.get("kernel_health", {}).get("status") == "INCOMPLETE":
            problems.append({"trial": folder.name, "kernel_history_incomplete": resources["kernel_health"].get("issues")})
        if resources.get("quality_status") == "INCOMPLETE":
            problems.append({"trial": folder.name, "error": "PHASE_RESOURCE_COUNTERS_INCOMPLETE"})
        if any(record.get("counter_issues") for record in threads.get("intervals", [])):
            problems.append({"trial": folder.name, "error": "THREAD_RESOURCE_COUNTERS_INCOMPLETE"})
        compilation = trial["compile_units"]
        for request_id, output in trial["inference"].items():
            if hashlib.sha256(output["output"].encode()).hexdigest() != output["output_sha256"] or output["output_tokens"] != trial["fixed_workload"]["tokens_per_request"]:
                problems.append({"trial": folder.name, "request": request_id, "error": "MODEL_OUTPUT_HASH_OR_WORK_COUNT_FORGED"})
            if native["verified"] is True and (native["completed"][request_id]["output_tokens"], native["completed"][request_id]["input_tokens"]) != (output["output_tokens"], output["input_tokens"]):
                problems.append({"trial": folder.name, "request": request_id, "error": "NATIVE_MODEL_WORK_COUNT_MISMATCH"})
        b_duration = (max(unit["end_ns"] for unit in compilation) - trial["released_ns"]) / 1e9 if compilation else None
        b_ends = [unit["end_ns"] for unit in compilation] + [value["completed_ns"] for key, value in trial["inference"].items() if key != "request-A"]
        b_total = (max(b_ends) - trial["released_ns"]) / 1e9 if b_ends else None
        trials.append({"trial": folder.name, "condition": trial["condition"], "repetition": trial["repetition"],
            "a_seconds": trial["a_latency_ns"] / 1e9, "makespan_seconds": trial["makespan_ns"] / 1e9,
            "a_phases_seconds": phases, "a_queue_seconds": trial["inference"]["request-A"]["queue_wait_ns"] / 1e9,
            "B_compile_seconds": b_duration, "B_compile_units_per_second": len(compilation) / b_duration if b_duration else None,
            "B_total_completion_seconds": b_total,
            "B_max_compile_queue_wait_seconds": max((unit["release_wait_ns"] / 1e9 for unit in compilation), default=None),
            "B_inference_queue_seconds": [value["queue_wait_ns"] / 1e9 for key, value in trial["inference"].items() if key != "request-A"],
            "fixed_workload": trial["fixed_workload"], "object_outputs": {unit["unit"]: unit["object_sha256"] for unit in compilation},
            "inference_outputs": {key: (value["output_sha256"], value["output_tokens"]) for key, value in trial["inference"].items()},
            "semantic_events": semantic["event_count"], "native_events": native["event_count"],
            "semantic_complete": semantic["status"] == "COMPLETE", "native_complete": native["verified"] is True,
            "native_profile": native.get("native_profile"), "native_batch_coverage": native.get("batch_coverage"),
            "native_worker_coverage": native.get("worker_coverage"),
            "observed_actual_batch_count": native.get("observed_actual_batch_count", native["batch_count"]),
            "total_actual_batch_count": native.get("total_actual_batch_count"),
            "selected_membership_change_batch_count": native.get("selected_membership_change_batch_count"),
            "actual_worker_intervals": len(native["ggml_worker_processing_intervals"]),
            "resource_health": load, "phase_resources": resources, "thread_resources": threads,
            "resource_complete_independent_of_semantic": load["status"] == "COMPLETE" and
                resources.get("quality_status") != "INCOMPLETE" and threads.get("quality_status") != "INCOMPLETE" and
                resources.get("kernel_health", {}).get("status") != "INCOMPLETE"})
    expected_trials = len(campaign["order"])
    if len(trials) != expected_trials:
        problems.append({"missing_trials": expected_trials - len(trials)})
    mixed = [trial for trial in trials if trial["condition"] != "G0"]
    if mixed:
        reference = mixed[0]
        for trial in mixed[1:]:
            if any(trial[name] != reference[name] for name in ("fixed_workload", "object_outputs", "inference_outputs")):
                problems.append({"trial": trial["trial"], "error": "fixed_B_work_or_model_output_changed"})
    for trial in trials:
        if mixed and trial["inference_outputs"]["request-A"] != mixed[0]["inference_outputs"]["request-A"]:
            problems.append({"trial": trial["trial"], "error": "A_model_output_changed"})
    conditions = sorted({trial["condition"] for trial in trials})
    aggregate = {condition: {metric: interval([trial[metric] for trial in trials if trial["condition"] == condition and trial[metric] is not None])
                            for metric in ("a_seconds", "makespan_seconds", "a_queue_seconds", "B_compile_units_per_second", "B_total_completion_seconds")}
                 for condition in conditions}
    pairs = {}
    for baseline, intervention in (("G0", "G1"), ("G1", "G2"), ("G2", "G3"), ("G3", "G4")):
        lookup = {(trial["condition"], trial["repetition"]): trial for trial in trials}
        pair = [(lookup[(baseline, repetition)], lookup[(intervention, repetition)])
                for repetition in range(campaign["args"]["repetitions"])
                if (baseline, repetition) in lookup and (intervention, repetition) in lookup]
        if not pair:
            continue
        metrics = ["a_seconds"] if baseline == "G0" else ["a_seconds", "makespan_seconds", "B_compile_units_per_second", "B_total_completion_seconds"]
        pairs[baseline + "_to_" + intervention] = {
            metric: interval([(right[metric] / left[metric] - 1) * 100 for left, right in pair]) for metric in metrics}
    phase_summary = {condition: {phase: interval([trial["a_phases_seconds"][phase] for trial in trials
                    if trial["condition"] == condition and phase in trial["a_phases_seconds"]])
                    for phase in ("SEARCH", "PREPARE", "INFERENCE")} for condition in conditions}
    findings = []
    comparison = pairs.get("G1_to_G2", {})
    if comparison and comparison["a_seconds"]["bootstrap_median_ci95"][1] < 0:
        findings.append({"kind": "CPU_RESERVATION_IMPROVES_A_WITH_FIXED_B_WORK",
            "explanation": "相同编译和推理工作量下，给 A/共享引擎静态保留 CPU 后，A 更早完成。",
            "evidence": comparison, "not_claimed": "不是 GPU 调度收益，不代表所有 Agent 工作负载。"})
    phase_change = pairs.get("G2_to_G3", {})
    if phase_change and phase_change["a_seconds"]["median"] > 0:
        findings.append({"kind": "KNOWN_A_PHASE_POLICY_NOT_BETTER_THAN_STATIC_RESERVATION",
            "explanation": "A 搜索时，共享服务仍在处理 B 的真实推理；仅按 A 的阶段分配 CPU 没有优于静态保留。",
            "evidence": phase_change, "limitation": "这是本固定场景的阴性结果，不是所有阶段调度策略都无效。"})
    if "G1" in aggregate and "G2" in aggregate:
        findings.append({"kind": "DIRECTLY_MEASURED_ADMISSION_QUEUE",
            "explanation": "客户端共享队列等待是明确记录的时间段，不能把它当 GPU 等待，也不按 service CPU 猜测。",
            "G1_queue_seconds": aggregate["G1"]["a_queue_seconds"], "G2_queue_seconds": aggregate["G2"]["a_queue_seconds"]})
    return {"schema_version": 1, "status": "VALIDATED_WITH_DECLARED_SCOPE" if not problems else "INCOMPLETE_OR_INVALID",
            "problems": problems, "trial_count": len(trials), "aggregates": aggregate, "paired_change_percent": pairs,
            "trials": trials, "workload_checks": "EXACT_COMPILE_OBJECT_AND_REAL_MODEL_OUTPUT_HASH_EQUALITY",
            "phase_summary": phase_summary, "findings": findings,
            "scope": campaign["scope"], "gpu": "NOT_AVAILABLE_HARDWARE_UNVALIDATED",
            "G0_makespan_not_fixed_AB_work_comparable": True,
            "shared_service_attribution": "REQUEST_QUEUE_AND_NATIVE_BATCH_THREAD_INTERVALS_NO_UTILIZATION_GUESS",
            "hypothesis": "G3_BETTER_THAN_G2_NOT_GUARANTEED_REPORT_NEGATIVE_RESULTS",
            "evidence_digest": hashlib.sha256(json.dumps(campaign, sort_keys=True).encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = analyze(args.directory)
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(encoded)
    else:
        print(encoded)


if __name__ == "__main__":
    main()
