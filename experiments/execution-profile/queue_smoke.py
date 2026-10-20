#!/usr/bin/env python3
"""Real-engine acceptance of scoped reuse, queued cancellation and priority update."""
import argparse
import dataclasses
import json
import time
from pathlib import Path
from types import SimpleNamespace

from local_inference import verify_native
from run import Trial, group_empty, sha, terminate, write_json
from semantic import verify
from workloads import prepare_assets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cgroup-parent", type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=False)
    options.cgroup_parent.mkdir()
    (options.cgroup_parent / "cgroup.subtree_control").write_text("+cpuset +cpu +memory +io +pids")
    assets = options.output / "assets"
    prepare_assets(assets, files=1, lines=1, units=1, functions=1)
    args = SimpleNamespace(**vars(options), port=18451, sampler=None, kernel_hist_object=None,
                           sample_threads=False, native_trace="on")
    args.native_profile = "FORENSIC"
    trial = Trial(args, options.output / "queue-control", "G4", 0, assets)
    try:
        trial.start_engine()
        service, recorder = trial.service, trial.recorder
        first = dataclasses.replace(trial.b, request_id="B-running", tool_call_id="infer-B-running")
        queued = dataclasses.replace(trial.b, request_id="B-queued", tool_call_id="infer-B-queued")
        cancelled = dataclasses.replace(trial.a, request_id="A-cancelled", tool_call_id="infer-A-cancelled")
        priority = dataclasses.replace(trial.a, request_id="A-priority", tool_call_id="infer-A-priority")
        running = service.submit(first, "Once upon a time a little bird lived in a forest.", 256)
        deadline = time.monotonic() + 15
        while recorder.requests.get(first.request_id, (None, None))[1] != "FIRST_TOKEN":
            if running.done() or time.monotonic() > deadline:
                raise RuntimeError("first real request finished before queue control barrier")
            time.sleep(.001)
        background = service.submit(queued, "Once upon a time a little bird lived in a forest.", 256)
        recorder.update_policy(trial.a, -10, {"controller": "SHARED_ADMISSION_PRIORITY", "basis": "INITIAL_LOW_PRIORITY"})
        cancelled_future = service.submit(cancelled, "Once upon a time there was a cat.", 256)
        high = service.submit(priority, "Once upon a time there was a dog.", 256)
        if not service.cancel(cancelled.request_id) or not cancelled_future.cancelled():
            raise RuntimeError("queued cancellation was not enforced")
        recorder.update_policy(trial.a, 20, {"controller": "SHARED_ADMISSION_PRIORITY",
            "basis": "EXPLICIT_RUNTIME_POLICY_VERSION", "running_request_preemption": "NOT_SUPPORTED"})
        service.reprioritize()
        results = [future.result(timeout=120) for future in (running, high, background)]
        service.close()
        terminate(trial.engine)
        recorder.close()
        expected = {result["request_id"]: result["wire_context"] for result in results}
        native = verify_native(trial.native_path, expected)
        semantic = verify(trial.directory / "semantic-events.jsonl")
        order = [result["request_id"] for result in sorted(results, key=lambda result: result["admitted_ns"])]
        if order != ["B-running", "A-priority", "B-queued"] or not native["verified"] or semantic["status"] != "COMPLETE":
            raise RuntimeError("real queue/identity replay failed: " + json.dumps({"order": order,
                "native_errors": native["errors"], "semantic": semantic}))
        write_json(trial.directory / "expected-requests.json", expected)
        write_json(trial.directory / "native-verdict.json", native)
        write_json(trial.directory / "semantic-verdict.json", semantic)
        write_json(options.output / "verdict.json", {"status": "PASS_REAL_CPU_ENGINE", "order": order,
            "cancelled_before_native_admission": "A-cancelled", "effective_priority_version": recorder.current(trial.a).effective_version,
            "same_shared_client_worker_scoped_per_request": True, "native_request_count": native["request_count"],
            "native_batch_count": native["batch_count"], "actual_ggml_worker_intervals": len(native["ggml_worker_processing_intervals"]),
            "results": results, "engine_sha256": sha(options.engine), "model_sha256": sha(options.model),
            "gpu": "NOT_AVAILABLE", "running_decode_preemption": "NOT_SUPPORTED_NOT_CLAIMED",
            "dynamic_multi_member_batch": "NOT_RUN_ACTUAL_SINGLETON_BATCHES_ONLY"})
        print(json.dumps({"status": "PASS_REAL_CPU_ENGINE", "order": order}), flush=True)
    finally:
        terminate(trial.engine)
        if trial.service and trial.service.worker.is_alive():
            trial.service.close()
        trial.recorder.close()
        for group in reversed(trial.groups):
            if not group_empty(group):
                raise RuntimeError("queue smoke has unexpected residual processes")
            group.rmdir()
        trial.root.rmdir()
        options.cgroup_parent.rmdir()


if __name__ == "__main__":
    main()
