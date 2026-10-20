#!/usr/bin/env python3
"""Genuine CPU llama.cpp + fixed compiler interference, cooperative Guest only."""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import os
import random
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

from local_inference import SharedInference, verify_native
from semantic import Context, Recorder, identity, verify
from workloads import corpus_inventory, prepare_assets

HERE = Path(__file__).resolve().parent


def write_json(path, data):
    path = Path(path)
    with path.open("x") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def affinity(group, cpus):
    # Set every current TID, not just leader. Repeated scans include newly created
    # descendants; a cpuset controller also constrains future forks/threads.
    value = ",".join(str(cpu) for cpu in sorted(cpus))
    (group / "cpuset.cpus").write_text(value)
    if (group / "cpuset.cpus.effective").read_text().strip() != value:
        # Linux compresses ranges: compare expanded sets instead.
        actual = set()
        for interval in (group / "cpuset.cpus.effective").read_text().strip().split(","):
            bounds = interval.split("-")
            actual.update(range(int(bounds[0]), int(bounds[-1]) + 1))
        if actual != set(cpus):
            raise RuntimeError("requested cpuset is not effective")
    for pid in (group / "cgroup.procs").read_text().split():
        try:
            for tid in (Path("/proc") / pid / "task").iterdir():
                os.sched_setaffinity(int(tid.name), set(cpus))
        except (ProcessLookupError, FileNotFoundError):
            pass


def group_create(parent, name, cpus):
    group = parent / name
    group.mkdir()
    (group / "cpuset.mems").write_text((parent / "cpuset.mems.effective").read_text().strip())
    affinity(group, cpus)
    return group


def launch(command, group, stdout, stderr, env=None, resume=True):
    process = subprocess.Popen([sys.executable, str(HERE / "child.py"), *map(str, command)],
                               stdout=stdout, stderr=stderr, env=env)
    deadline = time.monotonic() + 15
    while True:
        if process.poll() is not None:
            raise RuntimeError("stopped launcher exited early")
        status = Path("/proc", str(process.pid), "status").read_text()
        if "\nState:\tT" in status:
            break
        if time.monotonic() > deadline:
            raise TimeoutError("workload failed to stop before registration")
        time.sleep(0.002)
    (group / "cgroup.procs").write_text(str(process.pid))
    actor = identity(process.pid, process.pid)
    if actor["cgroup_inode"] != group.stat().st_ino:
        raise RuntimeError("workload cgroup assignment failed")
    if resume:
        os.kill(process.pid, signal.SIGCONT)
    return process, actor


def group_empty(group):
    return "populated 0" in (group / "cgroup.events").read_text().splitlines()


def terminate(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def await_sampler(process, path, after=None, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("sampler exited before barrier")
        if path.exists():
            for row in reversed(path.read_text().splitlines()):
                try:
                    sample = json.loads(row)
                except json.JSONDecodeError:
                    continue
                if after is None or sample["monotonic_ns"] > after:
                    return sample
                break
        time.sleep(0.01)
    raise TimeoutError("no flushed sampler bracket after execution")


def cpu_policy(mode, phase, cpus=(0, 1, 2, 3), static_cpus=2):
    """Pure, recorded policy; changing parallelism never reduces fixed B work."""
    cpus = tuple(cpus)
    if len(cpus) != 4 or len(set(cpus)) != 4 or not 1 <= static_cpus < 4:
        raise ValueError("four distinct CPUs and 1..3 reserved CPUs required")
    all_cpus, reserved = set(cpus), set(cpus[:static_cpus])
    background = all_cpus - reserved
    if mode in ("G0", "G1"):
        return all_cpus, all_cpus, all_cpus
    if mode == "G2":
        return reserved, reserved, all_cpus if phase == "A_COMPLETE" else background
    if mode in ("G3", "G4"):
        if phase in ("SEARCH", "PREPARE"):
            # Shared inference is not idle merely because A is preparing.
            return {cpus[0]}, reserved, all_cpus - {cpus[0]}
        return reserved, reserved, all_cpus if phase == "A_COMPLETE" else background
    raise ValueError("unknown condition")


def submit_with_queue_context(service, recorder, context, prompt, tokens):
    """Queue membership and A enqueue share the worker's pop lock.

    A request already popped by the worker is deliberately not a queued rival:
    its inference cannot be preempted even if SCHEDULED is not emitted yet.
    """
    with service.condition:
        with recorder.lock:
            admission = {"queued_request_ids_before_A": [item[2].request_id for item in service.queue],
                "running_request_ids_before_A": [request for request, state in recorder.requests.items()
                    if state[1] in ("SCHEDULED", "FIRST_TOKEN")],
                "scope": "APPLICATION_ADMISSION_QUEUE_NOT_ENGINE_PREEMPTION"}
        future = service.submit(context, prompt, tokens)
        return future, admission


class Trial:
    def __init__(self, args, directory, mode, repetition, assets):
        self.args, self.directory, self.mode, self.repetition, self.assets = args, directory, mode, repetition, assets
        self.cpu_ids = tuple(getattr(args, "cpu_ids", (0, 1, 2, 3)))
        self.static_cpus = getattr(args, "static_cpus", 2)
        self.compile_workers = getattr(args, "compile_workers", 4)
        directory.mkdir()
        self.run_id = directory.name
        self.recorder = Recorder(directory / "semantic-events.jsonl", self.run_id)
        self.a = self.recorder.declare(Context(self.run_id, "task-A", "agent-A"))
        self.b = self.recorder.declare(Context(self.run_id, "task-B", "agent-B"))
        self.lock = threading.RLock()
        self.processes, self.groups = [], []
        self.root = args.cgroup_parent / self.run_id
        self.root.mkdir()
        (self.root / "cgroup.subtree_control").write_text("+cpuset +cpu +memory +io +pids")
        self.cg_a = group_create(self.root, "agent-A", self.cpu_ids)
        self.cg_b = group_create(self.root, "agent-B", self.cpu_ids)
        self.cg_engine = group_create(self.root, "shared-engine", self.cpu_ids)
        self.groups = [self.cg_a, self.cg_b, self.cg_engine]
        self.engine, self.sampler, self.service = None, None, None
        self.object_results = []
        self.native_path = directory / "native-events.jsonl"
        self.cg_identities = {group.name: {"path": str(group), "inode": group.stat().st_ino,
                                              "device": group.stat().st_dev} for group in self.groups}

    def policy(self, phase):
        with self.lock:
            a_cpus, engine_cpus, b_cpus = cpu_policy(self.mode, phase, self.cpu_ids, self.static_cpus)
            for context, group, cpus in ((self.a, self.cg_a, a_cpus), (self.b, self.cg_b, b_cpus)):
                affinity(group, cpus)
                self.recorder.update_policy(context, 10 if self.mode == "G4" and context.task_id == "task-A" else 0,
                    {"phase_trigger": phase, "requested_cpus": sorted(cpus),
                     "effective_cpus": (group / "cpuset.cpus.effective").read_text().strip(),
                     "controller": "CGROUP_CPUSET_AND_EXISTING_TID_AFFINITY",
                     "workload_change": "NONE"})
            affinity(self.cg_engine, engine_cpus)
            if self.service:
                self.service.reprioritize()

    def start_engine(self):
        self.policy("SEARCH")
        log = (self.directory / "engine.log").open("xb")
        env = dict(os.environ)
        env.pop("OBSERVER_NATIVE_EVENTS", None)
        if self.args.native_trace == "on":
            env["OBSERVER_NATIVE_EVENTS"] = str(self.native_path)
            env["OBSERVER_NATIVE_PROFILE"] = self.args.native_profile
        self.engine, actor = launch([self.args.engine, "-m", self.args.model, "--host", "127.0.0.1",
            "--port", str(self.args.port), "--parallel", "1", "-c", "512", "-b", "128", "-ub", "128",
            "-t", "2", "-tb", "2", "-ngl", "0", "--no-warmup", "--poll", "0"],
            self.cg_engine, log, log, env)
        self.processes.append(self.engine)
        self.engine_actor = actor
        endpoint = "http://127.0.0.1:%d" % self.args.port
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.engine.poll() is not None:
                raise RuntimeError("actual llama-server failed; inspect engine.log")
            try:
                with urllib.request.urlopen(endpoint + "/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.02)
        else:
            raise TimeoutError("llama-server readiness")
        # No synthetic tokens: warmup uses actual inference without registered
        # task context and is explicitly outside the measured native stream.
        request = urllib.request.Request(endpoint + "/completion", data=json.dumps({
            "prompt": "Once upon a time", "n_predict": 8, "temperature": 0, "seed": 1234,
            "ignore_eos": True, "cache_prompt": False}).encode(), headers={"Content-Type": "application/json"})
        urllib.request.urlopen(request, timeout=30).read()
        self.service = SharedInference(self.recorder, endpoint, priority_scheduling=self.mode == "G4")
        if self.args.sampler:
            log = (self.directory / "sampler.stderr").open("xb")
            command = [str(self.args.sampler), "--output-dir", str(self.directory / "load"),
                       "--label", self.run_id, "--interval-ms", "50", "--process-interval-ms", "50"]
            for group in self.groups:
                command += ["--cgroup", str(group)]
            if self.args.sample_threads or self.args.kernel_hist_object:
                command += ["--sample-threads"]
            if self.args.kernel_hist_object:
                command += ["--kernel-hist-object", str(self.args.kernel_hist_object),
                            "--kernel-hist-sha256", sha(self.args.kernel_hist_object),
                            "--kernel-hist-groups", self.args.kernel_hist_groups]
                for group in self.groups:
                    command += ["--kernel-hist-cgroup", str(group)]
            self.sampler = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log)
            self.processes.append(self.sampler)
            await_sampler(self.sampler, self.directory / "load/load-samples.jsonl")
            if self.args.sample_threads or self.args.kernel_hist_object:
                # System JSONL is flushed before TID JSONL in each sampler tick.
                # Seeing the former alone is not proof the latter is ready.
                await_sampler(self.sampler, self.directory / "load/load-processes.jsonl")

    def tool(self, context, phase, span_id, command, dependency=()):
        stdout = (self.directory / (span_id + ".stdout")).open("xb")
        stderr = (self.directory / (span_id + ".stderr")).open("xb")
        process, actor = launch(command, self.cg_a, stdout, stderr, resume=False)
        self.processes.append(process)
        self.recorder.begin(context, phase, span_id, dependency_spans=dependency, actor=actor)
        os.kill(process.pid, signal.SIGCONT)
        returncode = process.wait(timeout=120)
        stdout.close()
        stderr.close()
        self.recorder.end(span_id, "END" if returncode == 0 else "FAIL", {"returncode": returncode,
                          "actor_capture": "STOPPED_LAUNCH_INSTANCE_NOT_POST_EXIT_PROCFS"}, actor=actor)
        if returncode:
            raise RuntimeError("real tool failed: " + span_id)
        return json.loads((self.directory / (span_id + ".stdout")).read_text())

    def compiler(self, source, released_ns):
        name = source.stem
        obj = self.directory / (name + ".o")
        log = (self.directory / (name + ".stderr")).open("xb")
        process, actor = launch(["g++", "-std=c++17", "-O2", "-frandom-seed=731", "-c", source, "-o", obj],
                                self.cg_b, subprocess.DEVNULL, log, resume=False)
        self.processes.append(process)
        context = dataclasses.replace(self.b, tool_call_id="compile-" + name)
        start = time.monotonic_ns()
        self.recorder.begin(context, "COMPILE", name, actor=actor)
        os.kill(process.pid, signal.SIGCONT)
        code = process.wait(timeout=120)
        end = time.monotonic_ns()
        self.recorder.end(name, "END" if code == 0 else "FAIL", {"returncode": code}, actor=actor)
        log.close()
        if code:
            raise RuntimeError("fixed compiler work failed")
        result = {"unit": name, "start_ns": start, "end_ns": end, "release_wait_ns": start - released_ns,
                  "object_sha256": sha(obj), "object_bytes": obj.stat().st_size,
                  "process_instance": actor}
        with self.lock:
            self.object_results.append(result)
        return result

    def execute(self):
        begin = time.monotonic_ns()
        self.start_engine()
        native_expected, inference_results, tool_results = {}, {}, {}
        released = time.monotonic_ns()
        compile_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.compile_workers)
        compiles, background = [], []
        try:
            if self.mode != "G0":
                compiles = [compile_pool.submit(self.compiler, source, released)
                            for source in sorted((self.assets / "source").glob("*.cpp"))]
                for index in range(self.args.b_requests):
                    context = dataclasses.replace(self.b, tool_call_id="infer-B-%d" % index, request_id="request-B-%d" % index)
                    background.append(self.service.submit(context, "Once upon a time a little bird lived in a forest.", self.args.tokens))
            search_context = dataclasses.replace(self.a, tool_call_id="search-A")
            search_command = [sys.executable, HERE / "workloads.py", "search", self.assets, self.args.search_repeats]
            if getattr(self.args, "search_corpus", None):
                search_command += ["--search-corpus", self.args.search_corpus]
            if getattr(self.args, "search_query", "TARGET_731") != "TARGET_731":
                search_command += ["--search-query", self.args.search_query]
            tool_results["search"] = self.tool(search_context, "SEARCH", "search-A",
                     search_command)
            self.policy("PREPARE")
            prep_context = dataclasses.replace(self.a, tool_call_id="prepare-A")
            tool_results["prepare"] = self.tool(prep_context, "PREPARE", "prepare-A",
                     [sys.executable, HERE / "workloads.py", "prepare", self.assets, self.args.prepare_rounds], ["search-A"])
            self.policy("INFERENCE")
            context = dataclasses.replace(self.a, tool_call_id="infer-A", request_id="request-A")
            self.recorder.begin(context, "INFERENCE", "inference-A", dependency_spans=["prepare-A"])
            prompt = ("Once upon a time a small child found a magic stone.\nSearch evidence: " +
                      tool_results["search"]["stdout_sha256"] + "\nPrepared input: " +
                      tool_results["prepare"]["output_sha256"] + "\nThe story continued:")
            future, admission_context = submit_with_queue_context(
                self.service, self.recorder, context, prompt, self.args.tokens)
            a_result = future.result(timeout=120)
            self.recorder.end("inference-A")
            a_complete = time.monotonic_ns()
            inference_results["request-A"] = a_result
            self.policy("A_COMPLETE")
            for future in background:
                result = future.result(timeout=120)
                inference_results[result["request_id"]] = result
            for future in compiles:
                future.result(timeout=180)
            completed = time.monotonic_ns()
            self.service.close()
            native_expected = {key: result["wire_context"] for key, result in inference_results.items()}
            thread_barrier_started = time.monotonic_ns()
            if self.sampler and (self.args.sample_threads or self.args.kernel_hist_object):
                # Keep the resident engine/TIDs alive through the post-request
                # process sample. Killing it first made the last request's wait
                # envelope fundamentally unbracketable, even with schedstats on.
                await_sampler(self.sampler, self.directory / "load/load-processes.jsonl", completed)
            thread_barrier_ns = time.monotonic_ns() - thread_barrier_started
            terminate(self.engine)
            if self.sampler:
                await_sampler(self.sampler, self.directory / "load/load-samples.jsonl", time.monotonic_ns())
                terminate(self.sampler)
                if self.sampler.returncode != 0:
                    raise RuntimeError("sampler finalization failed")
            for group in self.groups:
                if not group_empty(group):
                    raise RuntimeError("unmanaged process survives in " + group.name)
            self.recorder.close()
            semantic_result = verify(self.directory / "semantic-events.jsonl")
            native_result = verify_native(self.native_path, native_expected) if self.args.native_trace == "on" else {
                "verified": None, "status": "NOT_ENABLED_EXPLICIT_OVERHEAD_CONTROL", "errors": []}
            if semantic_result["status"] != "COMPLETE" or (self.args.native_trace == "on" and not native_result["verified"]):
                raise RuntimeError("runtime semantic/native evidence replay failed: " +
                                   json.dumps({"semantic": semantic_result, "native_errors": native_result["errors"]}))
            write_json(self.directory / "semantic-verdict.json", semantic_result)
            write_json(self.directory / "native-verdict.json", native_result)
            write_json(self.directory / "expected-requests.json", native_expected)
            report = {"schema_version": 1, "status": "COMPLETE", "condition": self.mode,
                      "repetition": self.repetition, "run_id": self.run_id,
                      "released_ns": released, "completed_ns": completed, "makespan_ns": completed - released,
                      "a_latency_ns": a_complete - released, "setup_ns": released - begin,
                      "post_execution_thread_bracket_ns": thread_barrier_ns,
                      "compile_units": self.object_results, "inference": inference_results, "tools": tool_results,
                      "fixed_workload": {"inventory_sha256": json.loads((self.assets / "inventory.json").read_text())["inventory_sha256"],
                          "tokens_per_request": self.args.tokens, "B_request_count": self.args.b_requests if self.mode != "G0" else 0,
                          "B_compile_count": len(compiles), "search_repeats": self.args.search_repeats,
                          "prepare_rounds": self.args.prepare_rounds},
                      "cgroups": self.cg_identities, "engine_process": self.engine_actor,
                      "cpu_backend": "GGML_CPU_REAL_GGUF", "gpu_validation": "UNAVAILABLE_NO_COMPUTE_DEVICE",
                      "native_trace": self.args.native_trace,
                      "native_profile": self.args.native_profile,
                      "a_admission_context": admission_context,
                      "scheduling_configuration": {"cpu_ids": list(self.cpu_ids),
                          "static_reserved_cpus": self.static_cpus, "compile_workers": self.compile_workers,
                          "request_priority_enabled": self.mode == "G4",
                          "running_request_preemption": "NOT_SUPPORTED"},
                      "semantic_authority": "SOURCE_RUNTIME_DECLARED_NOT_KERNEL_CAUSAL_PROOF",
                      "B_work_not_reduced": True, "dynamic_batch_validation": "SINGLE_SLOT_SINGLETON_ACTUAL_MEMBERS"}
            report["G2_policy_name"] = "STATIC_RESERVATION_UNTIL_A_DONE_RELEASE_B_AFTER_A_COMPLETES"
            if getattr(self.args, "external_search_config", None):
                report["fixed_workload"]["external_search"] = self.args.external_search_config
            write_json(self.directory / "trial.json", report)
            return report
        finally:
            compile_pool.shutdown(wait=True)
            for process in self.processes:
                terminate(process)
            if self.service and self.service.worker.is_alive():
                self.service.close()
            self.recorder.close()
            for group in reversed(self.groups):
                if not group_empty(group):
                    expected = self.cg_identities[group.name]
                    if (group.stat().st_ino, group.stat().st_dev) != (expected["inode"], expected["device"]):
                        raise RuntimeError("refusing cleanup after cgroup identity changed")
                    (group / "cgroup.kill").write_text("1")
                    deadline = time.monotonic() + 10
                    while not group_empty(group) and time.monotonic() < deadline:
                        time.sleep(.01)
                if group_empty(group):
                    group.rmdir()
            if self.root.exists() and not any(self.root.iterdir()):
                self.root.rmdir()
            elif self.root.exists() and all(group_empty(group) for group in self.groups if group.exists()):
                self.root.rmdir()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--assets", type=Path, help="Reuse immutable corpus/source to preserve byte-identical input across collector versions")
    parser.add_argument("--search-corpus", type=Path,
                        help="fixed real benchmark source snapshot for A search only; B compiler assets remain unchanged")
    parser.add_argument("--search-query", default="TARGET_731", help="bounded literal query; same query/path in every condition")
    parser.add_argument("--sampler", type=Path)
    parser.add_argument("--kernel-hist-object", type=Path)
    parser.add_argument("--kernel-hist-groups", default="sched")
    parser.add_argument("--sample-threads", action="store_true")
    parser.add_argument("--require-thread-wait", action="store_true",
                        help="fail before execution unless schedstats runtime is enabled and thread sampling selected")
    parser.add_argument("--native-trace", choices=["on", "off"], default="on")
    parser.add_argument("--native-profile", choices=["LIGHT", "FORENSIC"], default="LIGHT")
    parser.add_argument("--cgroup-parent", type=Path, default=Path("/sys/fs/cgroup/execution-profile"))
    parser.add_argument("--port", type=int, default=18451)
    parser.add_argument("--conditions", default="G0,G1,G2,G3")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--seed", type=int, default=731)
    parser.add_argument("--tokens", type=int, default=128)
    parser.add_argument("--b-requests", type=int, default=2)
    parser.add_argument("--compile-units", type=int, default=16)
    parser.add_argument("--functions-per-unit", type=int, default=192)
    parser.add_argument("--search-repeats", type=int, default=6)
    parser.add_argument("--prepare-rounds", type=int, default=8192)
    parser.add_argument("--static-cpus", type=int, default=2,
                        help="G2 reserved CPUs and G3/G4 inference CPUs (1..3 of four); default preserves historical two-core policy")
    parser.add_argument("--compile-workers", type=int, default=4,
                        help="compiler concurrency only; all fixed compilation units still execute")
    args = parser.parse_args()
    if os.geteuid() != 0 or len(os.sched_getaffinity(0)) < 4:
        parser.error("requires privileged cooperative experiment Guest with four CPUs")
    if not 1 <= args.repetitions <= 10 or not 1 <= args.tokens <= 256 or not 0 <= args.b_requests <= 4:
        parser.error("bounded repetitions/tokens/requests required")
    if not 1 <= args.compile_units <= 64 or not 1 <= args.functions_per_unit <= 512 or not 1 <= args.search_repeats <= 64 or not 1 <= args.prepare_rounds <= 32768:
        parser.error("bounded fixed search/preparation/compiler work required")
    if not 1 <= args.static_cpus <= 3 or not 1 <= args.compile_workers <= 8:
        parser.error("static-cpus must be 1..3 and compile-workers 1..8")
    if not args.search_query or "\x00" in args.search_query or len(args.search_query.encode()) > 4096:
        parser.error("nonempty bounded literal search query required")
    if args.search_corpus:
        args.search_corpus = args.search_corpus.resolve(strict=True)
    if args.require_thread_wait and (not args.sampler or not (args.sample_threads or args.kernel_hist_object) or
            Path("/proc/sys/kernel/sched_schedstats").read_text().strip() != "1"):
        parser.error("thread-wait acceptance requires sampler, thread sampling and kernel.sched_schedstats=1")
    args.cpu_ids = sorted(os.sched_getaffinity(0))[:4]
    args.output.mkdir(parents=True, exist_ok=False)
    args.cgroup_parent.mkdir(exist_ok=False)
    (args.cgroup_parent / "cgroup.subtree_control").write_text("+cpuset +cpu +memory +io +pids")
    assets = args.assets.resolve() if args.assets else args.output / "assets"
    if args.assets:
        inventory = json.loads((assets / "inventory.json").read_text())
        actual = {str(path.relative_to(assets)): sha(path) for path in sorted(assets.rglob("*"))
                  if path.is_file() and path.name != "inventory.json"}
        if actual != inventory["inventory"] or (inventory["compile_units"], inventory["functions_per_unit"]) != (
                args.compile_units, args.functions_per_unit):
            raise RuntimeError("reused workload assets changed or fixed-work parameters differ")
    else:
        inventory = prepare_assets(assets, units=args.compile_units, functions=args.functions_per_unit)
    external_inventory = corpus_inventory(args.search_corpus) if args.search_corpus else None
    args.external_search_config = None
    if external_inventory or args.search_query != "TARGET_731":
        args.external_search_config = {key: value for key, value in (external_inventory or {}).items() if key != "inventory"}
        args.external_search_config["query_sha256"] = hashlib.sha256(args.search_query.encode()).hexdigest()
    if external_inventory:
        write_json(args.output / "external-search-inventory.json", external_inventory)
        args.external_search_config["manifest_sha256"] = sha(args.output / "external-search-inventory.json")
    conditions = args.conditions.split(",")
    if not set(conditions) <= {"G0", "G1", "G2", "G3", "G4"} or len(set(conditions)) != len(conditions):
        parser.error("unique recognized conditions required")
    ordering = []
    rng = random.Random(args.seed)
    for repetition in range(args.repetitions):
        order = list(conditions)
        rng.shuffle(order)
        ordering += [(mode, repetition) for mode in order]
    write_json(args.output / "campaign.json", {"schema_version": 1, "engine_sha256": sha(args.engine),
        "model_sha256": sha(args.model), "sampler_sha256": sha(args.sampler) if args.sampler else None,
        "source_commit": "ec7f3ac9ab33e46b136eb5ab6a76c4d81f57c7f1", "model_revision": "499bc8821c6b12b4e53c5bffcb21ec206f212d81",
        "native_header_sha256": sha(HERE / "native_events.hpp"), "native_patch_sha256": sha(HERE / "llama-runtime-hooks.patch"),
        "boot_id": identity()["boot_id"], "available_cpus": sorted(os.sched_getaffinity(0)), "order": ordering,
        "random_seed": args.seed, "inventory": inventory, "args": {key: str(value) if isinstance(value, Path) else value
                                                                   for key, value in vars(args).items()},
        "scope": "COOPERATIVE_EXCLUSIVE_QEMU_CPU_BACKEND_NOT_GPU_PRODUCTION_PERFORMANCE"})
    try:
        for index, (mode, repetition) in enumerate(ordering):
            directory = args.output / ("trial-%02d-%s-r%d" % (index, mode, repetition))
            try:
                result = Trial(args, directory, mode, repetition, assets).execute()
            except BaseException as error:
                write_json(directory / "failure.json", {"status": "FAILED_NOT_COUNTED_AS_VALIDATED",
                    "error_type": type(error).__name__, "error": str(error), "condition": mode,
                    "repetition": repetition, "monotonic_ns": time.monotonic_ns()})
                raise
            print(json.dumps({"trial": directory.name, "A_seconds": result["a_latency_ns"] / 1e9,
                              "makespan_seconds": result["makespan_ns"] / 1e9}), flush=True)
        if external_inventory:
            after = corpus_inventory(args.search_corpus)
            unchanged = after["inventory_sha256"] == external_inventory["inventory_sha256"]
            write_json(args.output / "external-search-postcheck.json", {"unchanged": unchanged,
                "before_inventory_sha256": external_inventory["inventory_sha256"],
                "after_inventory_sha256": after["inventory_sha256"], "checked_after_all_trials": True})
            if not unchanged:
                raise RuntimeError("fixed benchmark search corpus changed during campaign")
    finally:
        if args.cgroup_parent.exists() and "populated 0" in (args.cgroup_parent / "cgroup.events").read_text().splitlines():
            args.cgroup_parent.rmdir()


if __name__ == "__main__":
    main()
