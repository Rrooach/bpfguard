#!/usr/bin/env python3
"""Reproducible offline replay and cross-version exact-work/output checks."""
import argparse
import hashlib
import json
from pathlib import Path

from analyze import analyze
from local_inference import verify_native
from semantic import verify


def signature(trial):
    return {"workload": trial["fixed_workload"],
            "objects": {unit["unit"]: unit["object_sha256"] for unit in trial["compile_units"]},
            "model": {key: {field: value[field] for field in ("output_sha256", "input_tokens", "output_tokens")}
                      for key, value in trial["inference"].items()}}


def replay(root):
    root = Path(root)
    matrices, other, problems = {}, [], []
    for name in ("mixed-20261014", "sched-diagnostic-20261014", "mixed-light-v3-20261014"):
        if not (root / name).exists():
            problems.append({"campaign": name, "error": "REQUIRED_MATRIX_CAMPAIGN_MISSING"})
            continue
        result = analyze(root / name)
        matrices[name] = result
        if result["status"] != "VALIDATED_WITH_DECLARED_SCOPE":
            problems.append({"campaign": name, "issues": result["problems"]})
    old, new = root / "mixed-20261014", root / "mixed-light-v3-20261014"
    matched = None
    if old.exists() and new.exists():
        reference = {}
        for path in old.glob("trial-*/trial.json"):
            trial = json.loads(path.read_text())
            reference[(trial["condition"], trial["repetition"])] = signature(trial)
        matched = 0
        for path in new.glob("trial-*/trial.json"):
            trial = json.loads(path.read_text())
            if reference.get((trial["condition"], trial["repetition"])) != signature(trial):
                problems.append({"trial": str(path), "error": "CROSS_VERSION_WORKLOAD_OR_OUTPUT_CHANGED"})
            else:
                matched += 1
        if matched != len(reference):
            problems.append({"error": "CROSS_VERSION_PAIR_COUNT_MISMATCH"})
    for name in ("overhead-20261014", "overhead-light-v3-20261014", "overhead-forensic-v3-20261014"):
        if not (root / name).exists():
            problems.append({"campaign": name, "error": "REQUIRED_OVERHEAD_CAMPAIGN_MISSING"})
            continue
        for path in sorted((root / name).glob("pair-*/trial.json")):
            trial = json.loads(path.read_text())
            semantic = verify(path.parent / "semantic-events.jsonl")
            expected = json.loads((path.parent / "expected-requests.json").read_text())
            native = verify_native(path.parent / "native-events.jsonl", expected) if trial["native_trace"] == "on" else {
                "verified": None, "status": "EXPLICITLY_DISABLED_CONTROL"}
            if semantic["status"] != "COMPLETE" or (trial["native_trace"] == "on" and not native["verified"]):
                problems.append({"trial": str(path), "error": "REPLAY_FAILED"})
            other.append({"campaign": name, "trial": path.parent.name, "semantic": semantic, "native": native})
    for name in ("queue2-20261014", "queue-v3-20261014"):
        path = root / name / "queue-control"
        if not path.exists():
            problems.append({"campaign": name, "error": "REQUIRED_QUEUE_CAMPAIGN_MISSING"})
            continue
        semantic = verify(path / "semantic-events.jsonl")
        native = verify_native(path / "native-events.jsonl", json.loads((path / "expected-requests.json").read_text()))
        if semantic["status"] != "COMPLETE" or not native["verified"]:
            problems.append({"trial": str(path), "error": "QUEUE_REPLAY_FAILED"})
        other.append({"campaign": name, "trial": path.name, "semantic": semantic, "native": native})
    return {"schema_version": 1, "status": "PASS_WITH_DECLARED_SCOPE" if not problems else "FAILED",
            "problems": problems, "matrix_trial_count": sum(matrix["trial_count"] for matrix in matrices.values()),
            "other_trial_count": len(other), "cross_version_exact_work_model_and_compiler_output_pairs": matched,
            "matrices": matrices, "other": other,
            "gpu": "HARDWARE_NOT_AVAILABLE_FIXTURES_NOT_E2E", "authority": "RUNTIME_AND_RESOURCE_REPLAY_NOT_OBSERVER_AUDIT_WAL"}


def summary(root, result, receipt):
    root, receipt = Path(root), Path(receipt)
    def digest(path):
        value = hashlib.sha256()
        with Path(path).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(chunk)
        return value.hexdigest()
    campaigns = []
    for name, matrix in result["matrices"].items():
        path = root / name
        manifest = path / "campaign.json"
        configuration = json.loads(manifest.read_text())
        campaigns.append({"name": name, "path": str(path), "manifest_sha256": digest(manifest),
            "status": matrix["status"], "trial_count": matrix["trial_count"],
            "engine_sha256": configuration["engine_sha256"], "model_sha256": configuration["model_sha256"],
            "native_header_sha256": configuration["native_header_sha256"], "native_patch_sha256": configuration["native_patch_sha256"],
            "native_profile": configuration["args"].get("native_profile", "FORENSIC_LEGACY"),
            "sampler_sha256": configuration["sampler_sha256"],
            "paired_change_percent": matrix["paired_change_percent"],
            "medians_seconds": {condition: {metric: statistics["median"] if statistics else None
                for metric, statistics in measures.items()} for condition, measures in matrix["aggregates"].items()},
            "resource_issues": sum(trial["resource_health"]["status"] == "INCOMPLETE" for trial in matrix["trials"]),
            "thread_lifecycle": "PARTIAL_POLLED_NOT_FULL", "gpu": "NOT_AVAILABLE"})
    for name in ("overhead-20261014", "overhead-light-v3-20261014", "overhead-forensic-v3-20261014",
                 "queue2-20261014", "queue-v3-20261014"):
        path = root / name / "verdict.json"
        if not path.exists():
            continue
        verdict = json.loads(path.read_text())
        entry = {"name": name, "path": str(path.parent), "verdict_path": str(path), "verdict_sha256": digest(path),
                 "status": verdict["status"], "engine_sha256": verdict["engine_sha256"], "model_sha256": verdict["model_sha256"]}
        if "tracing_incremental_slowdown_percent" in verdict:
            entry.update(native_profile=verdict.get("native_profile", "FORENSIC_LEGACY"),
                         paired_slowdown_percent=verdict["tracing_incremental_slowdown_percent"],
                         cost_scope=verdict["scope"], repetitions=verdict["repetitions"])
        else:
            entry.update(actual_order=verdict["order"], cancelled_before_native_admission=verdict["cancelled_before_native_admission"])
        campaigns.append(entry)
    return {"schema_version": 1, "status": result["status"], "problems": result["problems"],
            "counts": {"matrix_trials": result["matrix_trial_count"], "overhead_queue_trials": result["other_trial_count"],
                       "cross_version_exact_output_pairs": result["cross_version_exact_work_model_and_compiler_output_pairs"]},
            "detailed_receipt": {"path": str(receipt), "sha256": digest(receipt), "bytes": receipt.stat().st_size},
            "campaigns": campaigns, "batch_coverage": {
                "FORENSIC": "EVERY_ACTUAL_LLAMA_DECODE_CALL_AND_SCOPED_WORKER_INTERVALS",
                "LIGHT": "SINGLE_ACTUAL_DECODE_CALL_SELECTED_AT_MEMBERSHIP_CHANGE_NOT_EPOCH_OR_TOTAL_HISTORY",
                "LIGHT_total_actual_batch_count": None, "dynamic_multi_member_actual": "NOT_RUN_SINGLE_SLOT"},
            "gpu": "HARDWARE_NOT_AVAILABLE_NVTX_NSYS_KERNEL_MEMCPY_FIXTURES_ONLY",
            "native_default": "OFF_WITHOUT_OBSERVER_NATIVE_EVENTS", "authority": result["authority"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary-only", type=Path, help="Summarize an existing immutable detailed receipt without replaying or overwriting it")
    parser.add_argument("--tuned-static", action="store_true",
                        help="replay a tune_static.py selection and fresh G0..G4 evaluation, not the historical named campaigns")
    args = parser.parse_args()
    if args.tuned_static and args.summary_only:
        parser.error("tuned-static replay and historical summary-only are separate formats")
    if args.tuned_static:
        from tune_static import replay as replay_tuned_static
        result = replay_tuned_static(args.root)
    elif args.summary_only:
        result = summary(args.root, json.loads(args.summary_only.read_text()), args.summary_only)
    else:
        result = replay(args.root)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({key: result[key] for key in ("status", "counts", "matrix_trial_count", "other_trial_count", "evaluation_trial_count", "cross_version_exact_work_model_and_compiler_output_pairs", "problems") if key in result}))
    if result["problems"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
