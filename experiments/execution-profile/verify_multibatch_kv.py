#!/usr/bin/env python3
"""Independent raw semantic/native replay for the bounded two-slot KV control."""
import argparse
import dataclasses
import hashlib
import json
from pathlib import Path

from local_inference import verify_native
from run import sha, write_json
from semantic import Context, verify


def replay(directory, engine_directory):
    manifest = json.loads((directory / "manifest.json").read_text())
    problems = []
    for filename, expected_digest in manifest["artifacts"].items():
        if sha(directory / filename) != expected_digest:
            problems.append("artifact digest changed: " + filename)
    for name, field in (("llama-server", "engine_sha256"), ("native_events-v4.hpp", "native_header_sha256"),
                        ("llama-runtime-hooks-v4.patch", "native_patch_sha256")):
        if sha(engine_directory / name) != manifest[field]:
            problems.append("compiled engine/source digest mismatch: " + name)
    semantic = verify(directory / "semantic-events.jsonl")
    expected, semantic_outputs = {}, {}
    for raw in (directory / "semantic-events.jsonl").read_text().splitlines():
        event = json.loads(raw)
        if event["kind"] == "REQUEST_SCHEDULED":
            expected[event["request_id"]] = {field.name: event[field.name] for field in dataclasses.fields(Context)}
        if event["kind"] == "REQUEST_COMPLETE":
            semantic_outputs[event["request_id"]] = event["details"]
    if expected != json.loads((directory / "expected-requests.json").read_text()):
        problems.append("declared request table not independently matched to raw admission")
    native = verify_native(directory / "native-events.jsonl", expected)
    if semantic["status"] != "COMPLETE" or not native["verified"]:
        problems.append("raw semantic/native replay invalid")
    registered = manifest["registered_actor"]
    if native["process_instance"] != (registered["boot_id"], registered["pid"], registered["process_start_ticks"],
                                      registered["cgroup_inode"], registered["cgroup_device"]):
        problems.append("native process differs from registered stopped-launch instance")
    outputs = json.loads((directory / "results.json").read_text())
    if len(expected) != 2 or len(outputs) != 2 or {value["slot_id"] for value in native["completed"].values()} != {0, 1}:
        problems.append("two explicit real request/slot identities not established")
    for output in outputs:
        request_id = output["request_id"]
        if (hashlib.sha256(output["output"].encode()).hexdigest() != output["output_sha256"] or
            output["wire_context"] != expected[request_id] or
            output["output_sha256"] != semantic_outputs[request_id]["output_sha256"] or
            output["output_tokens"] != native["completed"][request_id]["output_tokens"] or
            output["input_tokens"] != native["completed"][request_id]["input_tokens"] or
            output["output_tokens"] != manifest.get("fixed_output_token_limit", 32)):
            problems.append("raw admission/native token/output content binding mismatch: " + request_id)
    if native["multi_member_actual_batch_count"] < 1:
        problems.append("no genuine multi-member decode call")
    kv = native["logical_kv_by_request_completion"]
    if len(kv) != 2 or any(value["status"] != "OBSERVED_LOGICAL_KV" for value in kv.values()):
        problems.append("shared context logical KV not collected")
    return {"schema_version": 1, "status": "INVALID" if problems else "PASS_REAL_CPU_MULTIBATCH_LOGICAL_KV",
            "verifier_source_sha256": {name: sha(Path(__file__).parent / name)
                                       for name in ("verify_multibatch_kv.py", "local_inference.py", "semantic.py", "run.py")},
            "problems": problems, "path": str(directory), "manifest_sha256": sha(directory / "manifest.json"),
            "engine_sha256": manifest["engine_sha256"], "header_sha256": manifest["native_header_sha256"],
            "patch_sha256": manifest["native_patch_sha256"], "native_event_count": native["event_count"],
            "native_request_count": native["request_count"], "observed_actual_batch_count": native["observed_actual_batch_count"],
            "multi_member_actual_batch_count": native["multi_member_actual_batch_count"],
            "maximum_observed_batch_members": native["maximum_observed_batch_members"],
            "actual_worker_interval_count": len(native["ggml_worker_processing_intervals"]),
            "logical_kv_by_request_completion": kv, "logical_kv_scope": native["logical_kv_scope"],
            "logical_kv_collection_ns": {key: value["collection_end_ns"] - value["collection_start_ns"] for key, value in kv.items()},
            "cpu_cost_split": "NOT_ESTABLISHED_NOT_ESTIMATED", "gpu": "UNKNOWN_NO_COMPUTE_DEVICE",
            "historical_performance": "FROZEN_V3_AND_78_TRIALS_NOT_CHANGED_OR_POOLED",
            "artifact_digests": manifest["artifacts"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--engine-directory", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    result = replay(options.directory, options.engine_directory)
    write_json(options.output, result)
    print(json.dumps({"status": result["status"], "problems": result["problems"]}))
    if result["problems"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
