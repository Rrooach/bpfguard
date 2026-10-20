#!/usr/bin/env python3
"""Observe the real Codex app-server and its explicitly dispatched shell tools.

This is a cooperative, single-Agent Linux demo, not a benchmark or sandbox.
The official Codex binary owns the agent loop. Its dynamic shell requests are
executed in stopped, sibling cgroups, with exact request/root bindings. No
model API key enters the Guest: only a local budget-proxy credential is read.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time
from urllib.parse import urlsplit
import uuid

from codex_client import CodexRPC, append_record, run_agent
from common import bind_artifacts, digest, proc_identity, write_new
import run as linux_run
from resource_accounting import capture as capture_resources, tool_accounting
from runtime_resources import RuntimeResourceSampler
from model_transport_timing import ModelTransportProxy


def proxy_token(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("proxy credential must not be a symlink")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "r") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= 512:
            raise ValueError("proxy credential must be an owned0600 small regular file")
        value = stream.read().strip()
    if not value or any(c.isspace() for c in value):
        raise ValueError("malformed proxy credential")
    return value


def codex_command(args, catalog, *, transport_base_url=None):
    broker_base_url=transport_base_url or args.broker_base_url
    endpoint = urlsplit(broker_base_url)
    if (endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1" or endpoint.port is None
            or endpoint.path != "/v1" or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment):
        raise ValueError("only an explicit local IPv4 budget broker /v1 endpoint is admitted")
    if args.budget_label != "codex-smoke-001" or args.model != "deepseek-flash":
        raise ValueError("this demo admits only its fixed shared-budget label/model")
    config = {
        "model": args.model, "model_provider": "observer_proxy", "forced_login_method": "api",
        "model_reasoning_effort": "low", "model_catalog_json": str(catalog),
        "model_providers.observer_proxy.name": "DeepSeek via bounded local broker",
        "model_providers.observer_proxy.base_url": broker_base_url,
        "model_providers.observer_proxy.env_key": "OBSERVER_BROKER_TOKEN",
        "model_providers.observer_proxy.wire_api": "responses",
        "model_providers.observer_proxy.requires_openai_auth": False,
        "model_providers.observer_proxy.request_max_retries": 0,
        "model_providers.observer_proxy.stream_max_retries": 0,
        "model_providers.observer_proxy.stream_idle_timeout_ms": 180000,
        "model_providers.observer_proxy.supports_websockets": False,
        "web_search": "disabled", "otel.exporter": "none",
        "shell_environment_policy.inherit": "none",
    }
    disabled = ("shell_tool", "unified_exec", "shell_snapshot", "code_mode", "code_mode_host",
                "multi_agent", "multi_agent_v2", "view_image", "hooks", "tool_search",
                "apply_patch_freeform", "responses_websockets", "responses_websockets_v2")
    config.update({"features." + feature: False for feature in disabled})
    command = [str(args.codex), "app-server", "--listen", "stdio://", "--strict-config"]
    for key, value in config.items():
        command += ["-c", key + "=" + json.dumps(value)]
    command += ["-c", 'model_providers.observer_proxy.http_headers={"X-Benchmark-Task"="codex-smoke-001"}']
    return command, config


def start_runtime(command, cgroup, directory, cwd, environment):
    """Fork/stop before actual exec, retaining a private stdin/stdout transport."""
    input_read, input_write = os.pipe()
    output_read, output_write = os.pipe()
    err = os.open(directory / "stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        pid = os.fork()
        if pid == 0:
            try:
                os.setsid()
                os.dup2(input_read, 0); os.dup2(output_write, 1); os.dup2(err, 2)
                for fd in (input_read, input_write, output_read, output_write, err):
                    if fd > 2:
                        os.close(fd)
                (cgroup / "cgroup.procs").write_text(str(os.getpid()))
                os.chdir(cwd)
                os.kill(os.getpid(), signal.SIGSTOP)
                os.execvpe(command[0], command, environment)
            except BaseException as error:
                os.write(2, (repr(error) + "\n").encode()); os._exit(127)
    finally:
        os.close(input_read); os.close(output_write); os.close(err)
    try:
        linux_run.wait_stopped(pid, 10)
    except BaseException:
        os.close(input_write); os.close(output_read)
        raise
    return pid, output_read, input_write


def usage_record(usage):
    return {"user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
        "minor_faults": usage.ru_minflt, "major_faults": usage.ru_majflt,
        "voluntary_switches": usage.ru_nvcsw, "involuntary_switches": usage.ru_nivcsw,
        "scope": "WAIT4_ROOT_AND_ITS_REAPED_CHILDREN_NOT_ARBITRARY_CGROUP_TOTAL"}


def finalize_replay(root):
    """A display failure must not relabel a successful independent raw replay."""
    from replay import verify_run
    try:
        report = verify_run(root)
        write_new(root / "report.json", report)
        verification = {"status": "REPLAY_PASSED", "manifest": digest(root / "manifest.json"), "report": digest(root / "report.json")}
    except Exception as failure:
        return {"status": "REPLAY_FAILED_OR_INCOMPLETE", "error": type(failure).__name__ + ": " + str(failure)[:4096],
                "manifest": digest(root / "manifest.json"), "original_health_preserved": True}
    try:
        from render import render_report
        write_new(root / "timeline.html", render_report(report).encode())
        verification["render_status"] = "GENERATED"
    except Exception as failure:
        verification.update(render_status="FAILED_SEPARATE_FROM_RAW_REPLAY",
                            render_error=type(failure).__name__ + ": " + str(failure)[:4096])
    return verification


class Tools:
    def __init__(self, root, group, agent_id, workspace, timeout, resource_sampler=None):
        self.root, self.group, self.agent_id = root, group, agent_id
        self.workspace, self.timeout = workspace, timeout
        self.tools, self.groups, self.children = [], [], {}
        self.resource_sampler = resource_sampler
        write_new(root / "tool-spans.jsonl", b"")

    def allocate(self):
        index = len(self.tools); cg = self.group / f"tool-{index:04d}"
        cg.mkdir(); self.groups.append(cg)
        target = self.root / f"tool-{index:04d}"; target.mkdir()
        return index, cg, target

    def enrolled(self, index, cg, pid, argv, invocation_ns, kind, call_id=None):
        tool = {"agent_id": self.agent_id, "task_id": "codex-local-demo",
            "tool_call_id": "codex-runtime" if index == 0 else f"codex-shell-{index:04d}",
            "root": proc_identity(pid), "cgroup_id": cg.stat().st_ino, "cgroup_path": str(cg),
            "command": argv, "invocation_ns": invocation_ns,
            "gate": "SIGSTOP_AFTER_CGROUP_ENTRY_BEFORE_EXEC", "begin_ns": None, "end_ns": None,
            "kind": kind, "codex_call_id": call_id}
        self.tools.append(tool); self.children[pid] = (tool, cg)
        if self.resource_sampler is not None:
            self.resource_sampler.register(tool["tool_call_id"], pid=pid,
                role="AGENT_RUNTIME" if kind == "OFFICIAL_CODEX_RUNTIME" else "TOOL_PROCESS",
                tool_call_id=tool["tool_call_id"], cgroup=cg,
                cgroup_scope="FRESH_EXCLUSIVE_TOOL_CGROUP_INCLUDES_DESCENDANTS")
        append_record(self.root / "tool-spans.jsonl", {"event": "TOOL_ENROLLED", **tool})
        return tool

    def release(self, tool):
        _, cg = self.children[tool["root"]["tid"]]
        tool["resources_before"] = capture_resources(cg)
        tool["begin_ns"] = time.monotonic_ns()
        append_record(self.root / "tool-spans.jsonl", {"event": "TOOL_START", **tool})
        os.kill(tool["root"]["tid"], signal.SIGCONT)

    def reap(self, tool, cg, graceful_seconds=0):
        pid = tool["root"]["tid"]; deadline = time.monotonic() + graceful_seconds
        while True:
            found, status, usage = os.wait4(pid, os.WNOHANG)
            if found:
                break
            if time.monotonic() >= deadline:
                tool["cleanup"] = "SUPERVISOR_TERMINATED_REMAINING_CGROUP"
                linux_run.kill_group(cg)
                _, status, usage = os.wait4(pid, 0)
                break
            time.sleep(.002)
        tool.update(root_exit_observed_ns=time.monotonic_ns(), result=os.waitstatus_to_exitcode(status), rusage=usage_record(usage))
        settle = time.monotonic() + 5
        if linux_run.populated(cg):
            tool["cleanup"] = "SUPERVISOR_TERMINATED_REMAINING_CGROUP"
            linux_run.kill_group(cg)
        while linux_run.populated(cg) and time.monotonic() < settle:
            time.sleep(.002)
        tool["cgroup_empty"] = not linux_run.populated(cg)
        tool["termination"] = "FORCED_CGROUP_CLEANUP" if tool.get("cleanup") else "NATURAL_CGROUP_EMPTY"
        tool["end_ns"] = time.monotonic_ns()
        resources_after = capture_resources(cg)
        tool["resources"] = tool_accounting(tool.pop("resources_before"), resources_after)
        if self.resource_sampler is not None:
            self.resource_sampler.finish(tool["tool_call_id"],reason="ROOT_WAIT4_AND_CGROUP_CLOSURE",
                confirmed_exit=tool["result"],exit_source="OS_WAIT4")
        append_record(self.root / "tool-spans.jsonl", {"event": "TOOL_END", **tool})
        del self.children[pid]
        if not tool["cgroup_empty"]:
            raise RuntimeError("tool cgroup did not become empty")

    def execute(self, command, call_id, rpc_request_id):
        index, cg, target = self.allocate()
        argv = ["/bin/bash", "--noprofile", "--norc", "-c", command]
        spec = {"command": argv, "cwd": str(self.workspace), "env": {"BASH_ENV": "", "ENV": ""}}
        invocation = time.monotonic_ns(); pid = linux_run.start_tool(spec, cg, target)
        tool = self.enrolled(index, cg, pid, argv, invocation, "CODEX_DYNAMIC_SHELL", call_id)
        self.release(tool)
        # Polling is only a supervisor bound and cannot identify a kernel wait.
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            # waitid(WNOWAIT) observes exit without consuming wait4's rusage.
            if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                break
            if sum((target / name).stat().st_size for name in ("stdout", "stderr")) > 1024 * 1024:
                tool["output_limit_triggered"] = True
                break
            time.sleep(.002)
        self.reap(tool, cg)
        stdout, stderr = (target / "stdout").read_bytes(), (target / "stderr").read_bytes()
        return {"exit_code": tool["result"], "stdout": stdout[:8192].decode(errors="replace"),
            "stderr": stderr[:4096].decode(errors="replace"), "output_truncated": len(stdout) > 8192 or len(stderr) > 4096,
            "binding": {"tool_call_id": tool["tool_call_id"], "root_pid": pid, "root": tool["root"],
                "cgroup_id": tool["cgroup_id"], "cgroup_path": str(cg), "begin_ns": tool["begin_ns"],
                "end_ns": tool["end_ns"], "cgroup_empty": tool["cgroup_empty"],
                "stdout_artifact": str((target / "stdout").relative_to(self.root)),
                "stderr_artifact": str((target / "stderr").relative_to(self.root))}}


def collect(args):
    if os.geteuid() != 0 or not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        raise RuntimeError("owned Linux root with writable cgroup v2 required")
    if not 1 <= args.max_calls <= 8 or not 1 <= args.tool_timeout <= 60 or not 10 <= args.timeout <= 600:
        raise ValueError("bounded local demo time/call limits required")
    for name in ("collector", "object", "codex", "catalog", "workspace"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    root = args.output.resolve(); root.mkdir(parents=True, exist_ok=False, mode=0o700)
    app = root / "app"; app.mkdir()
    home = root / "private-codex-home"; home.mkdir(mode=0o700)
    write_new(app / "model-catalog.json", args.catalog.read_bytes())
    prompt = args.prompt.read_text()
    if not 1 <= len(prompt.encode()) <= 32768:
        raise ValueError("bounded public task prompt required")
    write_new(app / "prompt.txt", prompt.encode())
    command, config = codex_command(args, app / "model-catalog.json")
    write_new(app / "config.public.json", {"config": config, "budget_label": args.budget_label,
        "http_headers": {"X-Benchmark-Task": args.budget_label}, "credentials": "LOCAL_PROXY_TOKEN_ONLY_NOT_BOUND_OR_LOGGED",
        "agent_loop": "OFFICIAL_CODEX_APP_SERVER", "scope": "COOPERATIVE_WORKLOAD_NOT_AN_ISOLATION_BOUNDARY",
        "tool_mode": "CODEX_CONTROLLED_COMMAND_TOOL_MODE_NOT_DEFAULT_ALL_BUILTINS",
        "provider_tool_policy": {"expected": "ADVERTISE_AND_DELIVER_ONLY_EXACT_FUNCTION_OBSERVER_BASH",
            "enforced_by": "EXTERNAL_RESPONSES_BROKER_NOT_CODEX_FEATURE_FLAGS",
            "verification": "REQUIRES_BOUND_BROKER_POLICY_RECEIPT_NOT_ESTABLISHED_BY_THIS_CONFIG",
            "client_defense": "SUPPORTED_BUILTIN_ITEMS_RECORDED_APPLICATION_ONLY; UNEXPECTED_SERVER_REQUEST_FAILS_CLOSED",
            "feature_flag_limit": "CODEX_CATALOG_CAN_STILL_ADVERTISE_BUILTINS_DESPITE_DISABLED_FEATURE_FLAGS"}})
    environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "CODEX_HOME": str(home), "OBSERVER_BROKER_TOKEN": proxy_token(args.broker_token_file)}
    parent = args.cgroup_parent.resolve(strict=True)
    if not (parent / "cgroup.controllers").is_file() or parent == Path("/"):
        raise ValueError("explicit cgroup v2 parent required")
    group = parent / ("observer-codex-" + uuid.uuid4().hex); group.mkdir()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    lifecycle = Tools(root, group, args.agent_id, args.workspace, args.tool_timeout)
    process, rpc, runtime, raw_stdout, resource_sampler, transport = None, None, None, None, None, None
    stderr = (root / "collector.stderr").open("xb")
    outcome, error, begin, end, partial = None, None, None, None, {}
    try:
        transport=ModelTransportProxy(app,args.broker_base_url,environment["OBSERVER_BROKER_TOKEN"],args.budget_label).start()
        # Preserve the validated config policy; only insert the local timing
        # transport between Codex and the existing bounded model broker.
        original='model_providers.observer_proxy.base_url='+json.dumps(config["model_providers.observer_proxy.base_url"])
        config["model_providers.observer_proxy.base_url"]=transport.base_url
        command=[('model_providers.observer_proxy.base_url='+json.dumps(transport.base_url)) if value==original else value
                 for value in command]
        write_new(app/"model-transport-config.json",{"clock":"CLOCK_MONOTONIC", "boot_id":boot,
            "base_url":transport.base_url,"upstream_base_url":args.broker_base_url,
            "scope":"AGENT_LOCAL_REQUEST_BOUNDARIES; ORIGINAL_BUDGET_POLICY_REMAINS_UPSTREAM"})
        resource_sampler = RuntimeResourceSampler(root / "resources", agent_id=args.agent_id)
        resource_sampler.register("agent-total", role="AGENT", cgroup=group,
            cgroup_scope="FRESH_EXCLUSIVE_AGENT_CGROUP_INCLUDES_RUNTIME_AND_TOOLS")
        resource_sampler.register("observer-supervisor", pid=os.getpid(), role="OBSERVER_CONTROL")
        resource_sampler.start()
        lifecycle.resource_sampler = resource_sampler
        with Path("/proc/kallsyms").open("rb") as source:
            write_new(root / "kallsyms.txt", source.read(32 * 1024 * 1024))
        collector_command = [str(args.collector), "--object", str(args.object), "--cgroup", str(group),
            "--output-dir", str(root / "capture"), "--max-records", str(args.max_records),
            "--max-bytes", str(args.max_bytes), "--ring-bytes", str(args.ring_bytes), "--kernel-stacks"]
        process = subprocess.Popen(collector_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr)
        resource_sampler.register("observer-collector", pid=process.pid, role="OBSERVER_COLLECTOR")
        ready = linux_run.ready_line(process); write_new(root / "ready.json", ready)
        begin = time.monotonic_ns()
        index, cg, target = lifecycle.allocate(); invocation = time.monotonic_ns()
        pid, read_fd, write_fd = start_runtime(command, cg, target, args.workspace, environment)
        runtime = lifecycle.enrolled(index, cg, pid, command, invocation, "OFFICIAL_CODEX_RUNTIME")
        raw_stdout = (target / "stdout").open("xb")
        rpc = CodexRPC(read_fd, write_fd, app, boot, raw_stdout)
        lifecycle.release(runtime)
        try:
            def progress(value):
                nonlocal partial
                partial = json.loads(json.dumps(value))
            outcome = run_agent(rpc, prompt, args.workspace, lifecycle.execute, app, model=args.model,
                                max_calls=args.max_calls, timeout=args.timeout,
                                agent_id=args.agent_id, task_id="codex-local-demo", progress=progress,
                                budget_label=args.budget_label)
        except BaseException as failure:
            error = type(failure).__name__ + ": " + str(failure)[:4096]
            outcome = {"schema_version": 2, "mode": "REAL_CODEX_APP_SERVER_DYNAMIC_TOOLS",
                **partial, "status": "CLIENT_OR_RUNTIME_FAILURE", "error": error,
                "tool_event_schema": "APPLICATION_TOOL_LIFECYCLE_V1",
                "tool_event_source_scope": "RAW_CODEX_RPC_REPLAY_REQUIRED; LINUX_BINDING_SEPARATE",
                "tool_calls": partial.get("tool_calls", []),
                "agent_loop": "OFFICIAL_CODEX_NOT_IMPLEMENTED_BY_THIS_CLIENT"}
        finally:
            rpc.close_input()
            lifecycle.reap(runtime, cg, graceful_seconds=5)
            # The entire runtime cgroup is now empty, so every stdout writer
            # is closed. Preserve any final protocol bytes even after the
            # completed turn; these are not reinterpreted as model output.
            while True:
                tail = os.read(read_fd, 64 * 1024)
                if not tail:
                    break
                raw_stdout.write(tail)
            os.close(read_fd); raw_stdout.flush(); os.fsync(raw_stdout.fileno()); raw_stdout.close(); raw_stdout = None
        end = time.monotonic_ns()
        transport.stop()
        if linux_run.populated(group):
            raise RuntimeError("run root remains populated; no completed evidence claim")
        write_new(app / "codex-result.json", outcome)
        write_new(root / "tools.input.json", [{k: tool[k] for k in ("agent_id", "task_id", "tool_call_id", "command")} for tool in lifecycle.tools])
        process.stdin.write(b"STOP\n"); process.stdin.flush(); process.stdin.close()
        collector_code = process.wait(timeout=30); stderr.close()
        resource_summary = resource_sampler.stop()
        if not (root / "capture/health.json").is_file():
            raise RuntimeError("native collector did not finalize health")
        names = [str(path.relative_to(root)) for path in root.rglob("*")
                 if path.is_file() and home not in path.parents and path.name not in ("manifest.json", "report.json", "timeline.html", "verification.json")]
        manifest = {"schema_version": 1, "run_id": args.run_id or "codex-" + uuid.uuid4().hex,
            "boot_id": boot, "kernel_release": os.uname().release, "clock": "CLOCK_MONOTONIC", "begin_ns": begin, "end_ns": end,
            "mode": "REAL_CODEX_APP_SERVER_DYNAMIC_TOOLS", "agent_id": args.agent_id, "budget_label": args.budget_label,
            "capture_directory": "capture", "tools": lifecycle.tools,
            "collector_binary": str(args.collector), "collector_identity": digest(args.collector), "collector_return_code": collector_code,
            "bpf_object": str(args.object), "bpf_identity": digest(args.object),
            "codex_binary": str(args.codex), "codex_identity": digest(args.codex), "agent_outcome": outcome.get("status"),
            "resource_sampling": {"summary": "resources/resource-summary.json",
                                  "samples": "resources/resource-samples.jsonl",
                                  "interval_ms": resource_summary["interval_ms"],
                                  "coverage": resource_summary["status"]},
            "scope": {"kind": "COOPERATIVE_DIRECT_CGROUP_DESCENDANTS", "root_cgroup": str(group),
                      "root_cgroup_id": group.stat().st_ino, "kernel_stacks": True, "gpu": "NOT_SELECTED",
                      "tool_binding": "EXPLICIT_CODEX_DYNAMIC_REQUEST_TO_STOPPED_SIBLING_CGROUP",
                      "application_receipt_times": "NOT_KERNEL_OR_MODEL_GENERATION_TIMESTAMPS",
                      "security": "CONTROLLED_COOPERATIVE_DEMO_NOT_HOSTILE_AGENT_CONTAINMENT"},
            "artifacts": bind_artifacts(root, sorted(names))}
        write_new(root / "manifest.json", manifest)
        verification = finalize_replay(root)
        write_new(root / "verification.json", verification)
        return {"output": str(root), "agent_outcome": outcome.get("status"), "error": error, "verification": verification["status"],
                "tools": len(lifecycle.tools), "api_budget_authority": "HOST_SHARED_RESPONSES_BROKER"}
    finally:
        if transport is not None:transport.stop()
        if resource_sampler is not None:
            resource_sampler.stop()
        if rpc is not None:
            rpc.close_input()
        for pid, (tool, cg) in list(lifecycle.children.items()):
            linux_run.kill_group(cg)
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        if process is not None and process.poll() is None:
            if not linux_run.populated(group) and process.stdin is not None and not process.stdin.closed:
                try:
                    process.stdin.write(b"STOP\n"); process.stdin.flush(); process.stdin.close(); process.wait(timeout=20)
                except (OSError, subprocess.TimeoutExpired):
                    process.terminate()
            else:
                process.terminate()
            if process.poll() is None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
        if raw_stdout is not None:
            raw_stdout.close()
        stderr.close()
        for cg in reversed(lifecycle.groups):
            if not linux_run.populated(cg):
                cg.rmdir()
        if not linux_run.populated(group):
            group.rmdir()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("collector", "object", "codex", "catalog", "workspace", "prompt", "output", "broker-token-file"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--broker-base-url", default="http://127.0.0.1:10091/v1")
    parser.add_argument("--budget-label", default="codex-smoke-001")
    parser.add_argument("--model", default="deepseek-flash")
    parser.add_argument("--agent-id", default="codex-agent-1")
    parser.add_argument("--run-id")
    parser.add_argument("--cgroup-parent", type=Path, default=Path("/sys/fs/cgroup"))
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--tool-timeout", type=float, default=30)
    parser.add_argument("--max-calls", type=int, default=8)
    parser.add_argument("--max-records", type=int, default=2_000_000)
    parser.add_argument("--max-bytes", type=int, default=2 * 1024 ** 3)
    parser.add_argument("--ring-bytes", type=int, default=64 * 1024 ** 2)
    result = collect(parser.parse_args(argv)); print(json.dumps(result), flush=True)
    return 0 if result["agent_outcome"] == "completed" and result["verification"] == "REPLAY_PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
