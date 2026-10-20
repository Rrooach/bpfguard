#!/usr/bin/env python3
"""Run cooperative Linux tools under an opt-in, stopped-launch timeline trace.

No Allox dependency, no host-global sysctl changes, no GPU/API calls. Each tool
gets a distinct cgroup. The recorder is READY before a child enters that group
and stops itself; the application span starts immediately before SIGCONT.
"""
from __future__ import annotations

import argparse
import json
import os
import select
import signal
import subprocess
import time
import uuid
from pathlib import Path

from common import bind_artifacts, digest, proc_identity, write_new
from replay import verify_run
from resource_accounting import capture as capture_resources, tool_accounting


def wait_stopped(pid, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found, status = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
        if found:
            if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP:
                return
            raise RuntimeError(f"tool exited before startup gate: wait status {status}")
        time.sleep(.002)
    raise TimeoutError("stopped launch gate timed out")


def start_tool(spec, cgroup, directory):
    stdout = os.open(directory / "stdout", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    stderr = os.open(directory / "stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        pid = os.fork()
        if pid == 0:
            try:
                os.setsid()
                os.dup2(stdout, 1)
                os.dup2(stderr, 2)
                os.close(stdout)
                os.close(stderr)
                (cgroup / "cgroup.procs").write_text(str(os.getpid()))
                if spec.get("cwd"):
                    os.chdir(spec["cwd"])
                os.kill(os.getpid(), signal.SIGSTOP)
                os.execvpe(spec["command"][0], spec["command"], {**os.environ, **spec.get("env", {})})
            except BaseException as error:
                os.write(2, (repr(error) + "\n").encode())
                os._exit(127)
    finally:
        os.close(stdout)
        os.close(stderr)
    wait_stopped(pid, 10)
    return pid


def populated(cgroup):
    values = dict(line.split() for line in (cgroup / "cgroup.events").read_text().splitlines())
    return values.get("populated") != "0"


def kill_group(cgroup):
    # Only a fresh, explicitly created task cgroup may reach this function.
    kill = cgroup / "cgroup.kill"
    if kill.exists():
        kill.write_text("1")
    else:
        for value in (cgroup / "cgroup.procs").read_text().split():
            try:
                os.kill(int(value), signal.SIGKILL)
            except ProcessLookupError:
                pass


def ready_line(process, timeout=20):
    readable, _, _ = select.select([process.stdout], [], [], timeout)
    if not readable:
        raise TimeoutError("native collector READY timed out")
    line = process.stdout.readline(128 * 1024)
    if not line.endswith(b"\n"):
        raise RuntimeError("native collector exited or malformed READY")
    ready = json.loads(line)
    if ready.get("status", ready.get("event")) != "READY":
        raise RuntimeError(f"native collector not READY: {ready}")
    return ready


def collect_run(args):
    if os.geteuid() != 0 or not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        raise RuntimeError("Linux root and writable cgroup v2 are required")
    specs = json.loads(args.tools.read_bytes()) if args.tools else [{
        "agent_id": args.agent_id, "task_id": "task-1", "tool_call_id": "tool-1", "command": args.command}]
    if not isinstance(specs, list) or not specs:
        raise ValueError("non-empty tool list required")
    seen = set()
    for spec in specs:
        for name in ("agent_id", "task_id", "tool_call_id"):
            if not isinstance(spec.get(name), str) or not spec[name]:
                raise ValueError(f"tool {name} required")
        if spec["tool_call_id"] in seen or not isinstance(spec.get("command"), list) or not spec["command"]:
            raise ValueError("tool IDs must be unique and commands must be argv arrays")
        seen.add(spec["tool_call_id"])
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    collector, object_path = args.collector.resolve(strict=True), args.object.resolve(strict=True)
    run_id = args.run_id or "timeline-" + uuid.uuid4().hex
    parent = args.cgroup_parent.resolve(strict=True)
    if parent == Path("/") or not (parent / "cgroup.controllers").exists():
        raise ValueError("explicit cgroup-v2 parent required")
    group = parent / ("observer-timeline-" + uuid.uuid4().hex)
    group.mkdir()
    write_new(root / "tools.input.json", specs)
    # Kernel symbols are captured before the measured window and outside the
    # workload cgroup; zero-address kernels simply yield unresolved symbols.
    if not args.no_trace:
        with Path("/proc/kallsyms").open("rb") as source:
            write_new(root / "kallsyms.txt", source.read(32 * 1024 * 1024))
    command = [str(collector), "--object", str(object_path), "--cgroup", str(group),
               "--output-dir", str(root / "capture"), "--max-records", str(args.max_records),
               "--max-bytes", str(args.max_bytes)]
    if not args.no_kernel_stacks:
        command.append("--kernel-stacks")
    command.extend(["--ring-bytes", str(args.ring_bytes)])
    if args.live_json:
        command.append("--live-json")
    process, children, groups, tools = None, {}, [], []
    collector_stderr = (root / "collector.stderr").open("xb")
    begin = time.monotonic_ns()
    try:
        if not args.no_trace:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=collector_stderr)
            if callable(getattr(args, "collector_started", None)):
                args.collector_started(process.pid)
            ready = ready_line(process)
        else:
            ready = {"status": "NO_OBSERVER_BASELINE_EXPLICITLY_REQUESTED", "observer_enabled": False}
        write_new(root / "ready.json", ready)
        begin = time.monotonic_ns()
        for index, spec in enumerate(specs):
            cg = group / f"tool-{index:04d}"
            cg.mkdir()
            groups.append(cg)
            target = root / f"tool-{index:04d}"
            target.mkdir()
            invocation_ns = time.monotonic_ns()
            pid = start_tool(spec, cg, target)
            children[pid] = (spec, cg, target)
            identity = proc_identity(pid)
            tool = {k: spec[k] for k in ("agent_id", "task_id", "tool_call_id")}
            tool.update(root=identity, cgroup_id=cg.stat().st_ino, cgroup_path=str(cg), command=spec["command"],
                        invocation_ns=invocation_ns,
                        gate="SIGSTOP_AFTER_CGROUP_ENTRY_BEFORE_EXEC", begin_ns=None, end_ns=None)
            tool["resources_before"] = capture_resources(cg)
            tools.append(tool)
        # All children are enrolled and stopped before any measured tool runs.
        write_new(root / "enrollment.json", tools)
        for tool in tools:
            tool["begin_ns"] = time.monotonic_ns()
            os.kill(tool["root"]["tid"], signal.SIGCONT)
        deadline = time.monotonic() + args.timeout
        while children:
            for pid, (spec, cg, target) in list(children.items()):
                found, status, usage = os.wait4(pid, os.WNOHANG)
                if not found:
                    continue
                tool = next(t for t in tools if t["root"]["tid"] == pid)
                tool.update(root_exit_observed_ns=time.monotonic_ns(), result=os.waitstatus_to_exitcode(status))
                tool["rusage"] = {"user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
                                  "minor_faults": usage.ru_minflt, "major_faults": usage.ru_majflt,
                                  "voluntary_switches": usage.ru_nvcsw, "involuntary_switches": usage.ru_nivcsw,
                                  "scope": "WAIT4_ROOT_AND_ITS_REAPED_CHILDREN_NOT_ARBITRARY_CGROUP_TOTAL"}
                # Root exit alone does not prove the command's whole tree ended.
                while populated(cg) and time.monotonic() < deadline:
                    time.sleep(.002)
                if populated(cg):
                    tool["cleanup"] = "TIMEOUT_KILLED_REMAINING_CGROUP"
                    kill_group(cg)
                    settle = time.monotonic() + 5
                    while populated(cg) and time.monotonic() < settle:
                        time.sleep(.002)
                tool["cgroup_empty"] = not populated(cg)
                tool["termination"] = "FORCED_CGROUP_CLEANUP" if tool.get("cleanup") else "NATURAL_CGROUP_EMPTY"
                tool["end_ns"] = time.monotonic_ns()
                resources_after = capture_resources(cg)
                tool["resources"] = tool_accounting(tool.pop("resources_before"), resources_after)
                del children[pid]
            if time.monotonic() > deadline and children:
                for _, cg, _ in children.values():
                    kill_group(cg)
                raise TimeoutError("tool runtime timed out; evidence retained, no completed manifest")
            time.sleep(.001)
        end = time.monotonic_ns()
        if args.no_trace:
            baseline = {"schema_version": 1, "run_id": run_id, "observer_enabled": False,
                        "mode": "NO_OBSERVER_BASELINE", "begin_ns": begin, "end_ns": end, "tools": tools,
                        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                        "verification_status": "NOT_APPLICABLE_NO_TRACE_RECORDED",
                        "artifacts": bind_artifacts(root, ["tools.input.json", "enrollment.json", "ready.json"])}
            write_new(root / "baseline.json", baseline)
            print(json.dumps({"output": str(root), "observer_enabled": False, "verification": "NOT_APPLICABLE_NO_TRACE"}))
            return baseline
        process.stdin.write(b"STOP\n")
        process.stdin.flush()
        process.stdin.close()
        collector_return_code = process.wait(timeout=20)
        if not (root / "capture/health.json").is_file():
            raise RuntimeError("native collector did not commit terminal health evidence")
        collector_stderr.close()
        names = ["capture/events.bin", "capture/events.jsonl", "capture/health.json", "capture/meta.json",
                 "kallsyms.txt", "enrollment.json", "tools.input.json", "ready.json", "collector.stderr"]
        if (root / "capture/censored-contexts.json").exists():
            names.append("capture/censored-contexts.json")
        if (root / "capture/censored-wakes.json").exists():
            names.append("capture/censored-wakes.json")
        if (root / "capture/kprobe-hooks.json").exists():
            names.append("capture/kprobe-hooks.json")
        for index, _ in enumerate(tools):
            names.extend([f"tool-{index:04d}/stdout", f"tool-{index:04d}/stderr"])
        manifest = {"schema_version": 1, "run_id": run_id,
                    "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                    "kernel_release": os.uname().release,
                    "begin_ns": begin, "end_ns": end, "clock": "CLOCK_MONOTONIC",
                    "capture_directory": "capture", "tools": tools,
                    "collector_binary": str(collector), "collector_identity": digest(collector),
                    "collector_return_code": collector_return_code,
                    "bpf_object": str(object_path), "bpf_identity": digest(object_path),
                    "scope": {"kind": "COOPERATIVE_DIRECT_CGROUP_DESCENDANTS", "root_cgroup": str(group),
                              "root_cgroup_id": group.stat().st_ino, "kernel_stacks": not args.no_kernel_stacks,
                              "gpu": "NOT_SELECTED"}, "artifacts": bind_artifacts(root, names)}
        write_new(root / "manifest.json", manifest)
        report = verify_run(root)
        write_new(root / "report.json", report)
        from render import render_report
        write_new(root / "timeline.html", render_report(report).encode())
        write_new(root / "verification.json", {"status": "REPLAY_PASSED", "manifest": digest(root / "manifest.json"),
                                               "report": digest(root / "report.json"),
                                               "timeline_status": report["critical_path"]["status"]})
        print(json.dumps({"output": str(root), "verification": "REPLAY_PASSED",
                          "timeline_status": report["critical_path"]["status"], "totals": report["totals"]}))
        return report
    finally:
        for pid, (_, cg, _) in children.items():
            kill_group(cg)
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        collector_stderr.close()
        for cg in reversed(groups):
            if not populated(cg):
                cg.rmdir()
        if not populated(group):
            group.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collector", required=True, type=Path)
    parser.add_argument("--object", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tools", type=Path, help="JSON list of commands, run concurrently")
    parser.add_argument("--agent-id", default="agent-1")
    parser.add_argument("--run-id")
    parser.add_argument("--cgroup-parent", type=Path, default=Path("/sys/fs/cgroup"))
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--max-records", type=int, default=1_000_000)
    parser.add_argument("--max-bytes", type=int, default=1024 * 1024 * 1024)
    parser.add_argument("--ring-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--no-kernel-stacks", action="store_true")
    parser.add_argument("--live-json", action="store_true", help="diagnostic comparison; serialize JSON during workload")
    parser.add_argument("--no-trace", action="store_true", help="explicit Observer-OFF timing baseline, no timeline claims")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.tools and not args.command:
        parser.error("provide --tools or -- COMMAND")
    collect_run(args)


if __name__ == "__main__":
    main()
