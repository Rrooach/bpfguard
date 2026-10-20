#!/usr/bin/env python3
"""Sequential, fail-closed fixed-eight-job benchmark matrix in an owned Guest.

This is an Oracle/reference transport experiment, not a model benchmark score.
No provider API, image pull, cleanup, replay, or result rewriting is performed.
An unsuccessful group stops the matrix and retains all partial evidence.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from common import digest, write_new
from kprobe_contract import validate_receipt
from parallel_run import load_plan
from replay import health_issues


HERE = Path(__file__).resolve().parent
LABEL = re.compile(r"[a-z][a-z0-9_-]{0,47}")
BENCHMARKS = {"terminal": "Terminal-Bench", "swe": "SWE-bench Verified"}
WORKER_NAMES = {"parallel_run.py", "parallel_terminal.py", "parallel_swe.py", "terminal_validate.py"}
FILE_ARGUMENTS = ("--collector", "--object", "--bridge", "--selection", "--prebuilt-images",
                  "--image-import-provenance", "--swe-adapter")
COMMON_RESOURCE_FIELDS = ("vcpus", "memory_mib", "total_preloaded_collectors", "ring_bytes_per_collector",
    "inference_api_calls", "sampler_interval_ms", "sampler_process_polling", "read_hook_backend",
    "collector_identity", "bpf_object_identity", "source_identities")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_json(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "expected regular non-symlink JSON: " + str(path))
    return json.loads(path.read_bytes())


def argument(command, option, required=True):
    positions = [i for i, value in enumerate(command) if value == option]
    require(len(positions) <= 1, "duplicate worker option: " + option)
    if not positions:
        require(not required, "missing worker option: " + option)
        return None
    index = positions[0]
    require(index + 1 < len(command), "missing worker option value: " + option)
    return command[index + 1]


def pin_file(pins, path, expected=None):
    path = Path(path)
    require(path.is_absolute(), "pinned input must be absolute: " + str(path))
    resolved = path.resolve(strict=True)
    require(resolved.is_file(), "pinned input is not a regular file: " + str(path))
    identity = digest(resolved)
    require(expected is None or identity == expected, "input digest differs: " + str(path))
    previous = pins.setdefault(str(path), {"resolved": str(resolved), "identity": identity})
    require(previous == {"resolved": str(resolved), "identity": identity}, "inconsistent input pin: " + str(path))


def prepare_plans(values, source_directory=HERE):
    """Pin the exact plans, runtime files, native files, and explicit inputs."""
    plans, pins, common_resources, benchmark_resources = [], {}, None, {}
    for value in values:
        label, separator, raw_path = value.partition("=")
        require(separator and label in BENCHMARKS, "--plans entries must be terminal=PATH or swe=PATH")
        require(label not in {entry["label"] for entry in plans}, "duplicate benchmark label")
        path = Path(raw_path).resolve(strict=True)
        plan = load_plan(path)
        require(plan.get("benchmark") == BENCHMARKS[label], "plan benchmark differs from label")
        config = plan.get("resource_configuration")
        require(isinstance(config, dict) and config.get("inference_api_calls") == 0
                and config.get("total_preloaded_collectors") == 8
                and config.get("ring_bytes_per_collector") == 67108864
                and config.get("vcpus") == 16 and config.get("memory_mib") == 65536
                and config.get("sampler_interval_ms") == 100 and config.get("sampler_process_polling") is False
                and config.get("read_hook_backend") == "OWNED_TRACEFS_KPROBE_KRETPROBE",
                "plan must declare the fixed 16-vCPU/64-GiB, eight-collector, zero-API experiment")
        require("ORACLE_REFERENCE" in plan.get("scope", "") and "NOT_MODEL_SCORE" in plan.get("scope", ""),
                "only explicitly labelled Oracle reference plans are admitted")
        if label == "terminal":
            require(config.get("original_task_cpu_memory_quotas_preserved") is True,
                    "Terminal task CPU/memory quotas must be preserved")
        shared = {name: config.get(name) for name in COMMON_RESOURCE_FIELDS}
        if common_resources is None:
            common_resources = shared
        require(shared == common_resources, "benchmark plans have different common resource/source configurations")
        # Different benchmarks have different official timing/evaluation and
        # collector-affinity contracts. Preserve each exact declaration; only
        # a given benchmark's concurrency changes between its groups.
        benchmark_resources[label] = config
        sources = config.get("source_identities")
        require(isinstance(sources, dict) and {"parallel_run.py", "phase_control.py", "common.py", "parallel_terminal.py",
                "parallel_swe.py", "terminal_validate.py"} <= set(sources), "plan omits required source pins")
        for name, identity in sources.items():
            require(Path(name).name == name and LABEL.fullmatch(name.replace(".", "_")), "unsafe source basename")
            pin_file(pins, Path(source_directory) / name, identity)
        pin_file(pins, path)
        for job in plan["jobs"]:
            command = job["command"]
            worker = "parallel_terminal.py" if label == "terminal" else "parallel_swe.py"
            require(str(Path(source_directory) / worker) in command, "worker is not the pinned benchmark adapter")
            require("--capture-only" in command and "--model" not in command and "--search-probe" not in command,
                    "matrix must use capture-only official reference tasks, not a model or search probe")
            pin_file(pins, command[0])
            for option in FILE_ARGUMENTS:
                path_value = argument(command, option, required=option in ("--collector", "--object"))
                if path_value:
                    expected = config.get("collector_identity" if option == "--collector" else "bpf_object_identity") \
                        if option in ("--collector", "--object") else None
                    require(expected is not None or option not in ("--collector", "--object"), "missing native identity")
                    pin_file(pins, path_value, expected)
            if label == "swe":
                inputs = Path(argument(command, "--inputs"))
                for name in ("task.json", "provenance.json"):
                    pin_file(pins, inputs / name)
            selection_sha = argument(command, "--selection-sha256", required=False)
            if selection_sha:
                require(digest(argument(command, "--selection"))["sha256"] == selection_sha,
                        "selected task identity differs")
        plans.append({"label": label, "path": str(path), "identity": digest(path),
                      "benchmark": plan["benchmark"], "scope": plan["scope"], "plan": plan})
    require(plans, "at least one benchmark plan is required")
    return plans, pins, {"common": common_resources, "by_benchmark": benchmark_resources}


def check_pins(pins):
    for path, pinned in pins.items():
        require(str(Path(path).resolve(strict=True)) == pinned["resolved"]
                and digest(path) == pinned["identity"], "pinned source/input changed: " + path)


def docker_value(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30, check=True)
    return result.stdout.strip()


def cgroup_limits(root, hierarchy_root=Path("/sys/fs/cgroup")):
    """Pin actual hierarchical controls; absent is never guessed to be 'max'."""
    root, hierarchy_root = Path(root).resolve(strict=True), Path(hierarchy_root).resolve(strict=True)
    require(root == hierarchy_root or hierarchy_root in root.parents, "driver cgroup escapes hierarchy")
    chain, current = [], root
    while True:
        parent_controls = None if current == hierarchy_root else (current.parent / "cgroup.subtree_control").read_text().strip()
        entry = {"path": str(current), "cgroup_id": current.stat().st_ino,
                 "controllers": (current / "cgroup.controllers").read_text().strip(),
                 "subtree_control": (current / "cgroup.subtree_control").read_text().strip(),
                 "parent_subtree_control": parent_controls, "limits": {}}
        for name in ("cpu.max", "cpuset.cpus.effective", "cpuset.mems.effective", "memory.max", "memory.swap.max", "pids.max"):
            try:
                item = {"status": "EXPOSED", "value": (current / name).read_text().strip()}
            except FileNotFoundError:
                if current == hierarchy_root:
                    require(name in ("cpu.max", "memory.max", "memory.swap.max", "pids.max"),
                            "required root effective cgroup control unavailable: " + name)
                    item = {"status": "NOT_EXPOSED_AT_CGROUP_ROOT", "value": None}
                else:
                    require(name.partition(".")[0] not in parent_controls.split(),
                            "enabled parent controller lacks expected child interface: " + name)
                    item = {"status": "NOT_EXPOSED_CONTROLLER_DISABLED_IN_PARENT", "value": None}
            entry["limits"][name] = item
        chain.append(entry)
        if current == hierarchy_root:
            break
        current = current.parent
    return {"scope": "ACTUAL_DRIVER_CGROUP_AND_ALL_ANCESTORS; NOT_WORKER_CONTAINER_QUOTAS", "hierarchy": chain}


def guest_identity():
    """Only stable configuration, not fluctuating availability or counters."""
    require(os.geteuid() == 0, "matrix must run as root inside the owned experiment Guest")
    vendor = " ".join(Path("/sys/class/dmi/id", name).read_text().strip()
                      for name in ("sys_vendor", "product_name"))
    require(any(word in vendor.lower() for word in ("qemu", "kvm", "bochs")), "not an experimental QEMU Guest")
    memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    total_kib = int(memory["MemTotal"].split()[0])
    require(total_kib >= 60 * 1024 * 1024, "Guest has less than 60 GiB usable memory")
    online = Path("/sys/devices/system/cpu/online").read_text().strip()
    require(os.cpu_count() == 16 and len(os.sched_getaffinity(0)) == 16, "Guest/driver must retain all sixteen CPUs")
    cgroups = Path("/proc/self/cgroup").read_text().splitlines()
    roots = [line[3:] for line in cgroups if line.startswith("0::")]
    require(len(roots) == 1, "a unified cgroup v2 identity is required")
    root = (Path("/sys/fs/cgroup") / roots[0].lstrip("/")).resolve(strict=True)
    require(root == Path("/sys/fs/cgroup") or Path("/sys/fs/cgroup") in root.parents, "unsafe driver cgroup")
    limits = cgroup_limits(root)
    daemon = json.loads(docker_value("info", "--format", "{{json .ID}}"))
    require(isinstance(daemon, str) and bool(daemon), "Docker daemon identity unavailable")
    return {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "uname": list(os.uname()), "dmi": vendor, "online_cpus": online,
            "cpu_affinity": sorted(os.sched_getaffinity(0)), "memory_total_kib": total_kib,
            "swap_total": memory["SwapTotal"].strip(), "driver_cgroup": str(root),
            "driver_cgroup_id": root.stat().st_ino, "driver_limits": limits, "docker_daemon_id": daemon}


def assert_quiet(proc_root=Path("/proc"), trace_root=Path("/sys/kernel/tracing")):
    """Read-only: never kill a process, remove a container, or delete a hook."""
    conflicts = []
    for path in proc_root.glob("[0-9]*/cmdline"):
        try:
            argv = [part.decode(errors="surrogateescape") for part in path.read_bytes().split(b"\0") if part]
        except FileNotFoundError:
            continue  # A process exited during a read-only scan.
        pid = int(path.parent.name)
        if pid == os.getpid() or not argv:
            continue
        names = {Path(value).name for value in argv if not value.startswith("-")}
        collector = Path(argv[0]).name == "collect" and "--object" in argv and "--cgroup" in argv
        if names & WORKER_NAMES or collector:
            conflicts.append({"pid": pid, "roles": sorted(names & WORKER_NAMES), "collector": collector})
    require(not conflicts, "active benchmark worker/controller/collector conflict: " + json.dumps(conflicts))
    require(not docker_value("ps", "--all", "--quiet", "--no-trunc"),
            "Docker containers remain; manual scoped inspection/cleanup is required, not automatic deletion")
    require(trace_root.is_dir(), "tracefs must already be mounted in the Guest")
    hooks = (trace_root / "kprobe_events").read_text()
    require("allox_execution_timeline/" not in hooks, "owned timeline kprobes remain; do not delete without identity review")
    return {"checked_ns": time.monotonic_ns(), "benchmark_processes": [], "docker_containers": [],
            "owned_kprobe_events": [], "method": "READ_ONLY_PROC_DOCKER_TRACEFS_NO_CLEANUP"}


def relative_directory(root, value):
    require(isinstance(value, str) and value and not Path(value).is_absolute() and ".." not in Path(value).parts,
            "unsafe worker timeline directory")
    path = (root / value).resolve(strict=True)
    require(root.resolve() in path.parents and path.is_dir(), "timeline directory escapes job output")
    return path


def await_next(directory, index, group, completed, boot_id, timeout):
    """A private explicit ACK creates a safe raw-export gap, never an auto retry."""
    stem = f"{index:02d}-{group}"
    acknowledgment = directory / (stem + "-next.json")
    expected = {"schema_version": 1, "event": "NEXT", "boot_id": boot_id,
                "group_name": group, "completed_receipt_identity": digest(completed)}
    write_new(directory / (stem + "-awaiting-next.json"), {
        "schema_version": 1, "event": "AWAITING_NEXT_AFTER_QUIET_VALIDATION", "boot_id": boot_id,
        "group_name": group, "begin_ns": time.monotonic_ns(), "acknowledgment_path": acknowledgment.name,
        "expected_acknowledgment": expected, "timeout_seconds": timeout,
        "scope": "NO_NEXT_GROUP_STARTED; EXTERNAL_RAW_EXPORT_ALLOWED_IN_THIS_GAP"})
    deadline = time.monotonic() + timeout
    while True:
        if acknowledgment.exists() or acknowledgment.is_symlink():
            value = load_json(acknowledgment)
            require(all(value.get(key) == item for key, item in expected.items()),
                    "NEXT acknowledgment does not bind this boot/group/completed receipt")
            return {"status": "EXPLICIT_NEXT_OBSERVED", "observed_ns": time.monotonic_ns(),
                    "acknowledgment_identity": digest(acknowledgment)}
        if time.monotonic() >= deadline:
            raise TimeoutError("explicit NEXT acknowledgment timed out; no subsequent group started")
        time.sleep(0.1)


def validate_group(directory, plan, concurrency, expected_boot):
    campaign = load_json(directory / "campaign.json")
    require(campaign.get("status") == "WORKERS_COMPLETED" and campaign.get("total_jobs") == 8
            and campaign.get("concurrency") == concurrency and campaign.get("boot_id") == expected_boot,
            "group controller did not complete the declared eight jobs")
    require(campaign.get("plan_identity") == plan["identity"]
            and campaign.get("resource_configuration") == plan["plan"]["resource_configuration"], "group plan/resources differ")
    require(len(campaign.get("jobs", [])) == 8
            and {row.get("job_id") for row in campaign["jobs"]} == {row["job_id"] for row in plan["plan"]["jobs"]},
            "group jobs differ from fixed work plan")
    jobs = []
    for spec in plan["plan"]["jobs"]:
        job_root = directory / "jobs" / spec["job_id"]
        worker = load_json(job_root / "worker-result.json")
        require(worker.get("job_id") == spec["job_id"] and worker.get("mode") == "ORACLE_REFERENCE"
                and worker.get("official_passed") is True, "official reference worker did not pass: " + spec["job_id"])
        require(worker.get("benchmark") == plan["benchmark"] and worker.get("task_id") == spec["task_id"], "worker task identity differs")
        require(not worker.get("error") and not worker.get("errors"), "worker retained an infrastructure error")
        timeline = relative_directory(job_root, worker.get("timeline_directory"))
        manifest = load_json(timeline / "manifest.json")
        require(manifest.get("boot_id") == expected_boot, "worker boot differs")
        configuration = plan["plan"]["resource_configuration"]
        require(manifest.get("collector_identity") == configuration["collector_identity"]
                and manifest.get("bpf_object_identity") == configuration["bpf_object_identity"], "worker native identity differs")
        capture = relative_directory(timeline, manifest.get("capture_directory", "capture"))
        for name in ("health.json", "meta.json", "kprobe-hooks.json"):
            path = capture / name
            require(manifest.get("artifacts", {}).get(str(path.relative_to(timeline))) == digest(path),
                    "group health/receipt is not bound to its run manifest: " + name)
        health, meta = load_json(capture / "health.json"), load_json(capture / "meta.json")
        require(health.get("status") == "COMPLETE_FOR_SELECTED_HOOKS" and not health_issues(health, []),
                "native transport history incomplete: " + spec["job_id"])
        receipt = validate_receipt(load_json(capture / "kprobe-hooks.json"), meta, health)
        require(receipt["status"] == "VALIDATED_BOUND_RECEIPT", "native hook receipt is incomplete")
        jobs.append({"job_id": spec["job_id"], "official_passed": True,
            "worker_result_identity": digest(job_root / "worker-result.json"),
            "manifest_identity": digest(timeline / "manifest.json"), "health_identity": digest(capture / "health.json"),
            "hook_receipt_identity": digest(capture / "kprobe-hooks.json"), "records": health["records"],
            "independent_raw_replay": "PENDING_SEPARATE_VERIFICATION"})
    return {"campaign_identity": digest(directory / "campaign.json"), "jobs": jobs,
            "batch_wall_ns": campaign.get("batch_wall_ns"),
            "agent_return_batch_wall_ns": campaign.get("agent_return_batch_wall_ns")}


def run(args):
    require(len(args.concurrencies) == len(set(args.concurrencies)) and all(value in (2, 4, 6, 8) for value in args.concurrencies),
            "concurrencies must be distinct members of 2/4/6/8")
    require(LABEL.fullmatch(args.output_prefix), "unsafe output prefix")
    for timeout in (args.group_timeout, args.setup_timeout, args.task_timeout, args.finalize_timeout,
                    getattr(args, "pause_timeout", 1800)):
        require(math.isfinite(timeout) and 0 < timeout <= 14400, "timeout must be within (0,14400]")
    root = args.output.absolute()
    require(not root.exists() and not root.is_symlink(), "matrix output must be fresh")
    root.mkdir(mode=0o700, parents=True)
    result = {"schema_version": 1, "mode": "ORACLE_REFERENCE", "paid_api_calls": 0,
              "status": "STARTING", "begin_ns": time.monotonic_ns(), "groups": [],
              "scope": "FIXED_EIGHT_TRIALS_PER_BENCHMARK; ONE_GROUP_AT_A_TIME; NOT_A_MODEL_SCORE",
              "independent_raw_replay": "PENDING_SEPARATE_VERIFICATION", "automatic_cleanup": False}
    child = None
    try:
        plans, pins, resources = prepare_plans(args.plans)
        pin_file(pins, args.sampler.resolve(strict=True))
        pin_file(pins, Path(__file__).resolve())
        identity = guest_identity()
        require(identity["boot_id"] == args.expected_boot_id, "Guest boot differs from explicitly expected identity")
        check_pins(pins)
        result.update(guest_identity=identity, input_pins=pins, resource_configuration=resources,
                      plans=[{key: entry[key] for key in ("label", "path", "identity", "benchmark", "scope")} for entry in plans],
                      concurrency_order=args.concurrencies)
        write_new(root / "matrix-inputs.json", result)
        for concurrency in args.concurrencies:
            for plan in plans:
                index = len(result["groups"])
                name = f"{plan['label']}-c{concurrency}-{args.output_prefix}"
                row = {"name": name, "benchmark": plan["benchmark"], "concurrency": concurrency,
                       "output": str(root / name), "status": "CHECKING_PRECONDITIONS"}
                result["groups"].append(row)
                check_pins(pins)
                require(guest_identity() == identity, "Guest/resource/daemon identity changed before group")
                before = assert_quiet()
                write_new(root / f"{index:02d}-{name}-before.json", before)
                command = [sys.executable, "-B", str(HERE / "parallel_run.py"), "--plan", plan["path"],
                    "--output", row["output"], "--concurrency", str(concurrency), "--sampler", str(args.sampler.resolve()),
                    "--setup-timeout", str(args.setup_timeout), "--task-timeout", str(args.task_timeout),
                    "--finalize-timeout", str(args.finalize_timeout)]
                row.update(command=command, begin_ns=time.monotonic_ns(), status="RUNNING")
                with (root / (name + ".stdout")).open("xb") as stdout, (root / (name + ".stderr")).open("xb") as stderr:
                    child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
                    row["controller_pid"] = child.pid
                    try:
                        code = child.wait(timeout=args.group_timeout)
                    except subprocess.TimeoutExpired:
                        # Interrupt only our controller. Its reviewed exception
                        # path publishes ABORT and joins its own worker children.
                        child.send_signal(signal.SIGINT)
                        try:
                            child.wait(timeout=120)
                        except subprocess.TimeoutExpired:
                            row["controller_still_running"] = True
                        raise TimeoutError("group exceeded deadline; interrupted only the owned controller, inspect retained evidence")
                row.update(end_ns=time.monotonic_ns(), return_code=code)
                child = None
                check_pins(pins)
                require(guest_identity() == identity, "Guest/resource/daemon identity changed after group")
                row["quiet_after"] = assert_quiet()
                require(code == 0, "group failed; no subsequent group will start")
                row.update(validate_group(root / name, plan, concurrency, args.expected_boot_id))
                row["status"] = "REFERENCE_AND_TRANSPORT_PASSED_PENDING_INDEPENDENT_REPLAY"
                completed = root / f"{index:02d}-{name}-completed.json"
                write_new(completed, row)
                if getattr(args, "pause_between_groups", False) and len(result["groups"]) < len(plans) * len(args.concurrencies):
                    row["next_barrier"] = await_next(root, index, name, completed, args.expected_boot_id, args.pause_timeout)
        result["status"] = "REFERENCE_AND_TRANSPORT_PASSED_PENDING_INDEPENDENT_REPLAY"
    except BaseException as error:
        result.update(status="STOPPED_ON_FAILURE", error=type(error).__name__ + ": " + str(error))
        if child is not None and child.poll() is None:
            # Never silently leave a matrix to continue after its caller exits.
            child.send_signal(signal.SIGINT)
            try:
                child.wait(timeout=120)
            except subprocess.TimeoutExpired:
                result["owned_controller_requires_manual_inspection"] = child.pid
        if result["groups"] and result["groups"][-1]["status"] != "REFERENCE_AND_TRANSPORT_PASSED_PENDING_INDEPENDENT_REPLAY":
            result["groups"][-1]["status"] = "FAILED_OR_INCOMPLETE_RETAINED"
    finally:
        result["end_ns"] = time.monotonic_ns()
        write_new(root / "matrix.json", result)
    print(json.dumps({key: result.get(key) for key in ("status", "error", "paid_api_calls")}, sort_keys=True))
    return int(result["status"] == "STOPPED_ON_FAILURE")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plans", nargs="+", required=True, help="terminal=/absolute/plan.json swe=/absolute/plan.json")
    parser.add_argument("--concurrencies", nargs="+", type=int, default=[6, 8, 4])
    parser.add_argument("--output", type=Path, required=True, help="fresh matrix receipt and group output root")
    parser.add_argument("--output-prefix", default="r001", help="safe per-group suffix; never overwrites an attempt")
    parser.add_argument("--sampler", type=Path, required=True)
    parser.add_argument("--expected-boot-id", required=True)
    parser.add_argument("--pause-between-groups", action="store_true", help="await boot/group/digest-bound private NEXT ACK after each nonfinal group")
    parser.add_argument("--pause-timeout", type=float, default=1800)
    parser.add_argument("--group-timeout", type=float, default=7200)
    parser.add_argument("--setup-timeout", type=float, default=1800)
    parser.add_argument("--task-timeout", type=float, default=900)
    parser.add_argument("--finalize-timeout", type=float, default=1800)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
