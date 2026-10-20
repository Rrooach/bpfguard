#!/usr/bin/env python3
"""Paired actual-model tracing on/off cost, same patched binary and fixed input."""
import argparse
import dataclasses
import json
import random
from pathlib import Path
from types import SimpleNamespace

from analyze import interval
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
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--tokens", type=int, default=256)
    parser.add_argument("--native-profile", choices=["LIGHT", "FORENSIC"], default="LIGHT")
    options = parser.parse_args()
    if not 2 <= options.repetitions <= 10 or not 1 <= options.tokens <= 256:
        parser.error("bounded repeats and real tokens required")
    options.output.mkdir(parents=True, exist_ok=False)
    options.cgroup_parent.mkdir()
    (options.cgroup_parent / "cgroup.subtree_control").write_text("+cpuset +cpu +memory +io +pids")
    assets = options.output / "assets"
    prepare_assets(assets, files=1, lines=1, units=1, functions=1)
    rng, results, output_signature = random.Random(731), [], None
    try:
        for repetition in range(options.repetitions):
            order = ["on", "off"]
            rng.shuffle(order)
            for enabled in order:
                args = SimpleNamespace(**vars(options), port=18451, sampler=None, kernel_hist_object=None,
                                       sample_threads=False, native_trace=enabled)
                directory = options.output / ("pair-%d-%s" % (repetition, enabled))
                trial = Trial(args, directory, "G0", repetition, assets)
                try:
                    trial.start_engine()
                    context = dataclasses.replace(trial.a, request_id="request-A", tool_call_id="infer-A")
                    result = trial.service.submit(context, "Once upon a time a little bird lived in a forest.", options.tokens).result(timeout=120)
                    trial.service.close()
                    terminate(trial.engine)
                    trial.recorder.close()
                    semantic = verify(directory / "semantic-events.jsonl")
                    if semantic["status"] != "COMPLETE":
                        raise RuntimeError("overhead semantic replay failed")
                    expected = {result["request_id"]: result["wire_context"]}
                    native = verify_native(trial.native_path, expected) if enabled == "on" else {
                        "verified": None, "status": "NOT_ENABLED_EXPLICIT_CONTROL"}
                    if enabled == "on" and not native["verified"]:
                        raise RuntimeError("overhead native replay failed")
                    signature = (result["output_sha256"], result["input_tokens"], result["output_tokens"])
                    if output_signature is not None and signature != output_signature:
                        raise RuntimeError("on/off performed unequal real model work")
                    output_signature = signature
                    receipt = {"repetition": repetition, "native_trace": enabled,
                        "native_profile": options.native_profile,
                        "real_inference_seconds": (result["completed_ns"] - result["admitted_ns"]) / 1e9,
                        "time_to_first_token_seconds": (result["first_token_ns"] - result["admitted_ns"]) / 1e9,
                        "result": result, "semantic": semantic, "native": native}
                    write_json(directory / "trial.json", receipt)
                    write_json(directory / "expected-requests.json", expected)
                    results.append(receipt)
                    print(json.dumps({key: receipt[key] for key in ("repetition", "native_trace", "real_inference_seconds")}), flush=True)
                finally:
                    terminate(trial.engine)
                    if trial.service and trial.service.worker.is_alive():
                        trial.service.close()
                    trial.recorder.close()
                    for group in reversed(trial.groups):
                        if not group_empty(group):
                            raise RuntimeError("overhead control has residual process")
                        group.rmdir()
                    trial.root.rmdir()
        lookup = {(result["repetition"], result["native_trace"]): result for result in results}
        slowdown = [(lookup[(rep, "on")]["real_inference_seconds"] / lookup[(rep, "off")]["real_inference_seconds"] - 1) * 100
                    for rep in range(options.repetitions)]
        write_json(options.output / "verdict.json", {"status": "PASS_REAL_MODEL_EQUAL_OUTPUT_PAIRED_CONTROL",
            "engine_sha256": sha(options.engine), "model_sha256": sha(options.model), "tokens": options.tokens,
            "repetitions": options.repetitions, "random_seed": 731, "results": results,
            "native_profile": options.native_profile,
            "tracing_incremental_slowdown_percent": interval(slowdown),
            "scope": "SAME_PATCHED_BINARY_LOGGING_ON_VS_OFF_NOT_UNPATCHED_ENGINE_OR_OBSERVER_TOTAL_OVERHEAD",
            "default": "NATIVE_EVENT_ENV_ABSENT_MEANS_LOGGING_DISABLED", "gpu": "NOT_AVAILABLE",
            "warning": "TINY_15M_CPU_MODEL_NOT_PRODUCTION_LLM_SLA"})
    finally:
        options.cgroup_parent.rmdir()


if __name__ == "__main__":
    main()
