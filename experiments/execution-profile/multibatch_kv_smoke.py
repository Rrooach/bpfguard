#!/usr/bin/env python3
"""Two real simultaneous CPU requests: native batch membership and logical KV.

This is a functional calibration, not an overhead or scheduling benchmark.
Unlike SharedInference's one-slot admission queue, two bounded client threads
submit directly to a real two-slot continuous-batching llama.cpp server.
"""
import argparse
import concurrent.futures
import dataclasses
import json
import os
import threading
import time
import urllib.request
from pathlib import Path

from local_inference import SharedInference, verify_native
from run import group_create, group_empty, launch, sha, terminate, write_json
from semantic import Context, Recorder, verify


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--native-header", required=True, type=Path)
    parser.add_argument("--native-patch", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cgroup-parent", required=True, type=Path)
    parser.add_argument("--port", type=int, default=18454)
    parser.add_argument("--tokens", type=int, default=32)
    options = parser.parse_args()
    if not 8 <= options.tokens <= 128:
        parser.error("bounded real output tokens must be 8..128")
    options.output.mkdir(parents=True, exist_ok=False)
    options.cgroup_parent.mkdir()
    (options.cgroup_parent / "cgroup.subtree_control").write_text("+cpuset +cpu +memory +io +pids")
    group = group_create(options.cgroup_parent, "shared-real-two-slot-engine", {0, 1})
    recorder = Recorder(options.output / "semantic-events.jsonl", options.output.name)
    native_path = options.output / "native-events.jsonl"
    endpoint = "http://127.0.0.1:%d" % options.port
    contexts = [recorder.declare(Context(options.output.name, "task-" + suffix, "agent-" + suffix,
                   tool_call_id="infer-" + suffix, request_id="request-" + suffix)) for suffix in ("A", "B")]
    # Reuse only the actual streaming HTTP implementation; no single-worker
    # admission queue is created or misrepresented as dynamic server batching.
    client = object.__new__(SharedInference)
    client.recorder, client.endpoint = recorder, endpoint
    engine = None
    log = (options.output / "engine.log").open("xb")
    try:
        env = dict(os.environ, OBSERVER_NATIVE_EVENTS=str(native_path), OBSERVER_NATIVE_PROFILE="FORENSIC")
        command = [str(options.engine), "-m", str(options.model), "--host", "127.0.0.1", "--port", str(options.port),
                   "--parallel", "2", "-c", "1024", "-b", "128", "-ub", "128", "-t", "2", "-tb", "2",
                   "-ngl", "0", "--no-warmup", "--poll", "0"]
        engine, registered_actor = launch(command, group, log, log, env)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if engine.poll() is not None:
                raise RuntimeError("real two-slot engine exited before READY")
            try:
                with urllib.request.urlopen(endpoint + "/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(.01)
        else:
            raise TimeoutError("real two-slot engine READY")
        barrier = threading.Barrier(2)
        prompts = {context.request_id: ("Once upon a time a little " + ("bird" if context.agent_id == "agent-A" else "cat") +
                   " lived in a forest. The sun was bright and the friends played near the river. " * 12)
                   for context in contexts}
        def request(context):
            recorder.request(context, "ACCEPTED", {"calibration": "REAL_DIRECT_TWO_CLIENT_ADMISSION"})
            recorder.request(context, "QUEUED", {"queue": "CLIENT_START_BARRIER_NOT_ENGINE_QUEUE"})
            barrier.wait(timeout=15)
            recorder.request(context, "SCHEDULED", {"queue": "DIRECT_HTTP_ADMISSION",
                "engine_actual_scheduling": "RECORDED_SEPARATELY_BY_NATIVE_HOOK"})
            with recorder.thread_processing(context, "client-handler-" + context.request_id):
                result = client._infer(context, prompts[context.request_id], options.tokens)
            result["request_id"] = context.request_id
            return result
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(request, context) for context in contexts]
            results = [future.result(timeout=120) for future in futures]
        terminate(engine)
        recorder.close()
        expected = {result["request_id"]: result["wire_context"] for result in results}
        native = verify_native(native_path, expected)
        semantic = verify(options.output / "semantic-events.jsonl")
        problems = []
        if not native["verified"] or semantic["status"] != "COMPLETE":
            problems.append("raw semantic/native replay failed")
        instance = native["process_instance"]
        if instance != (registered_actor["boot_id"], registered_actor["pid"], registered_actor["process_start_ticks"],
                        registered_actor["cgroup_inode"], registered_actor["cgroup_device"]):
            problems.append("native service identity differs from stopped-launch cgroup registration")
        if native["multi_member_actual_batch_count"] == 0:
            problems.append("no actual two-member llama_decode batch observed")
        if any(value["status"] != "OBSERVED_LOGICAL_KV" or value["sequence_capacity"] < 2
               for value in native["logical_kv_by_request_completion"].values()):
            problems.append("actual shared-context logical KV collection not observed")
        if {value["slot_id"] for value in native["completed"].values()} != {0, 1}:
            problems.append("two real server slots did not both execute")
        write_json(options.output / "expected-requests.json", expected)
        write_json(options.output / "results.json", results)
        write_json(options.output / "native-verdict.json", native)
        write_json(options.output / "semantic-verdict.json", semantic)
        write_json(options.output / "manifest.json", {"schema_version": 1, "status": "INVALID" if problems else "PASS",
            "calibration": "REAL_CPU_TWO_SLOT_BATCH_AND_LOGICAL_KV_NOT_PERFORMANCE", "problems": problems,
            "engine_sha256": sha(options.engine), "model_sha256": sha(options.model),
            "native_header_sha256": sha(options.native_header), "native_patch_sha256": sha(options.native_patch),
            "native_profile": "FORENSIC", "engine_command": command, "registered_actor": registered_actor,
            "fixed_output_token_limit": options.tokens,
            "maximum_observed_batch_members": native["maximum_observed_batch_members"],
            "multi_member_actual_batch_count": native["multi_member_actual_batch_count"],
            "observed_actual_batch_count": native["observed_actual_batch_count"],
            "server_parallel_slots": 2,
            "sequence_capacity_meaning": "LLAMA_PUBLIC_API_KV_SEQUENCE_ID_CAPACITY_NOT_SERVER_SLOT_COUNT",
            "actual_worker_intervals": len(native["ggml_worker_processing_intervals"]),
            "logical_kv_by_request_completion": native["logical_kv_by_request_completion"],
            "logical_kv_scope": native["logical_kv_scope"], "cpu_cost_split": "NOT_ESTABLISHED_NOT_ESTIMATED",
            "gpu": "UNKNOWN_NO_COMPUTE_DEVICE", "event_count": native["event_count"],
            "performance_data": "FUNCTIONAL_ONLY_NOT_POOLED_WITH_FROZEN_V3_78_TRIALS",
            "artifacts": {name: sha(options.output / name) for name in ("native-events.jsonl", "semantic-events.jsonl",
                          "expected-requests.json", "results.json", "native-verdict.json", "semantic-verdict.json")}})
        print(json.dumps({"status": "INVALID" if problems else "PASS", "problems": problems,
                          "multi_member_actual_batch_count": native["multi_member_actual_batch_count"]}), flush=True)
        if problems:
            raise RuntimeError("; ".join(problems))
    finally:
        terminate(engine)
        recorder.close()
        log.close()
        if not group_empty(group):
            raise RuntimeError("unexpected residual process in own calibration cgroup")
        group.rmdir()
        options.cgroup_parent.rmdir()


if __name__ == "__main__":
    main()
