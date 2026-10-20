"""Official Codex app-server Agent; only its shell tools enter observed Docker.

The client below does not implement an inference/Agent loop. Codex owns that
loop and its final answer. The controlled dynamic tool crosses one explicit
Docker Exec gate; the Codex runtime itself is outside that container and is
not mislabelled as kernel-observed container activity.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

try:
    from harbor.agents.base import BaseAgent
except ModuleNotFoundError:
    # The SWE-bench worker reuses the app-server transport without importing
    # or pretending to run Harbor.  Terminal-Bench still supplies the real
    # Harbor BaseAgent before CodexObserverAgent is instantiated.
    class BaseAgent:  # pragma: no cover - exercised in the SWE Guest venv
        pass

from codex_client import CodexRPC, append_record, run_agent
from codex_run import proxy_token
from common import digest, write_new
from runtime_resources import RuntimeResourceSampler
from resource_accounting import capture as capture_cgroup
from model_transport_timing import ModelTransportProxy

ACTIVE = ContextVar("timeline_codex_terminal_settings", default=None)
LABEL = re.compile(r"(?:codex-terminal-c(2|4|6|8)-0[0-7]|codex-(?:terminal|swe)-smoke-00[12])\Z")
MODE = "MODEL_AGENT"
IMPLEMENTATION = "OFFICIAL_CODEX_APP_SERVER_DYNAMIC_TOOLS"
BINDING = "EXPLICIT_CODEX_REQUEST_TO_DOCKER_EXEC_STOPPED_ROOT_NOT_TIMESTAMP_MATCHING"
SCOPE = "OFFICIAL_CODEX_PUBLIC_TASK_AND_GATED_DOCKER_TOOLS; CODEX_RUNTIME_OUTSIDE_CONTAINER_CAPTURE"
CGROUP_ROOT = Path("/sys/fs/cgroup")
OWNED_RUNTIME_PARENT = re.compile(r"observer-runtime-fixture-[0-9a-f]{32}\Z")
INSTRUCTIONS = (
    "You are Codex, a coding agent solving a Terminal-Bench task in a Linux container. "
    "Use only observer_bash to inspect or change task files; commands execute in the actual task container, "
    "not in the Codex runtime host. Do not use any other tool. Do not read /solution, /tests, verifier "
    "artifacts, Docker control sockets, host files or credentials. No reference solution is supplied. "
    "There are at most 8 shell tool calls, 12 model requests and 4096 output tokens per model response; "
    "each command is at most 32768 bytes and has a 45-second timeout. Solve the public task efficiently, then give a brief final "
    "answer to submit the current state for unchanged official grading."
)


class ObserverBindingError(RuntimeError):
    """Capture/identity failures must not be hidden as ordinary task failures."""


def expected_max_calls(budget_label):
    """Keep campaign limits label-bound instead of accepting an arbitrary CLI value."""
    return 10 if budget_label.endswith("-002") else 8


def app_server_command(settings, catalog):
    """Pinned official configuration, with no retries and no direct API secret."""
    endpoint = urlsplit(settings.base_url)
    if (endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1" or endpoint.port is None
            or endpoint.path != "/v1" or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment):
        raise ValueError("only an explicit local IPv4 budget broker /v1 endpoint is admitted")
    if not LABEL.fullmatch(settings.budget_label):
        raise ValueError("explicit Codex Terminal concurrency/job budget label required")
    config = {
        "model": "deepseek-flash", "model_provider": "observer_proxy", "forced_login_method": "api",
        "model_reasoning_effort": "none", "model_catalog_json": str(catalog),
        "model_providers.observer_proxy.name": "DeepSeek via bounded local broker",
        "model_providers.observer_proxy.base_url": settings.base_url,
        "model_providers.observer_proxy.env_key": "OBSERVER_BROKER_TOKEN",
        "model_providers.observer_proxy.wire_api": "responses",
        "model_providers.observer_proxy.requires_openai_auth": False,
        "model_providers.observer_proxy.request_max_retries": 0,
        "model_providers.observer_proxy.stream_max_retries": 0,
        "model_providers.observer_proxy.stream_idle_timeout_ms": 180000,
        "model_providers.observer_proxy.supports_websockets": False,
        "web_search": "disabled", "otel.exporter": "none", "shell_environment_policy.inherit": "none",
    }
    disabled = ("shell_tool", "unified_exec", "shell_snapshot", "code_mode", "code_mode_host",
                "multi_agent", "multi_agent_v2", "view_image", "hooks", "tool_search",
                "apply_patch_freeform", "responses_websockets", "responses_websockets_v2")
    config.update({"features." + feature: False for feature in disabled})
    command = [str(settings.codex), "app-server", "--listen", "stdio://", "--strict-config"]
    for key, value in config.items():
        command += ["-c", key + "=" + json.dumps(value)]
    command += ["-c", "model_providers.observer_proxy.http_headers="
                + '{"X-Benchmark-Task"=' + json.dumps(settings.budget_label) + "}"]
    return command, config


@dataclass
class CodexSettings:
    base_url: str
    token_file: Path
    budget_label: str
    evidence_directory: Path
    agent_id: str
    task_id: str
    boot_id: str
    codex: Path
    catalog: Path
    max_calls: int = 8
    max_requests: int = 12
    max_output: int = 4096
    tool_timeout: int = 45
    timeout: int = 1800
    gate: object = None
    termination: str = "NOT_STARTED"
    function_bindings: list = field(default_factory=list)
    outcome: object = None
    runtime: dict = field(default_factory=dict)
    partial: dict = field(default_factory=dict)
    runner: object = None
    base_instructions: str = INSTRUCTIONS
    thread_cwd: Path = Path("/app")
    benchmark_kind: str = "TERMINAL_BENCH"
    runtime_cgroup: object = None
    runtime_cgroup_owned: bool = False

    def persist(self):
        self.evidence_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        value = {"schema_version": 2, "mode": MODE, "agent_implementation": IMPLEMENTATION,
            "agent_id": self.agent_id, "task_id": self.task_id, "budget_label": self.budget_label,
            "boot_id": self.boot_id, "clock": "CLOCK_MONOTONIC", "agent_scope": SCOPE,
            "model": "deepseek-flash", "max_calls": self.max_calls,
            "max_requests_enforced_by_external_broker": self.max_requests,
            "max_output_tokens_enforced_by_external_broker": self.max_output,
            "reasoning_effort": "none", "max_command_bytes": 32768,
            "tool_timeout_seconds": self.tool_timeout, "termination": self.termination,
            "function_bindings": self.function_bindings, "runtime": self.runtime,
            "tool_event_schema": "APPLICATION_TOOL_LIFECYCLE_V1",
            "tool_event_source_scope": "RAW_CODEX_RPC_REPLAY_REQUIRED; LINUX_BINDING_SEPARATE",
            "reported_tool_adapter": ["commandExecution", "fileChange", "mcpToolCall",
                "collabAgentToolCall", "webSearch", "imageView", "imageGeneration", "sleep"],
            "paid_api_calls": None, "cost_authority": "SHARED_HOST_RESPONSES_BROKER_LEDGER",
            "runtime_kernel_scope": "CODEX_RUNTIME_NOT_CAPTURED; ONLY_TASK_CONTAINER_GATED_TOOL_TREES",
            "benchmark_kind": self.benchmark_kind, "thread_cwd": str(self.thread_cwd)}
        path = self.evidence_directory / "codex-agent.json"
        from terminal_validate import write_json
        write_json(path, value, replace=path.exists())
        return value


@contextmanager
def configured(settings):
    token = ACTIVE.set(settings)
    try:
        yield settings
    finally:
        ACTIVE.reset(token)


def _runtime_cgroup_identity(path):
    stat = path.stat()
    return {"path": str(path), "inode": stat.st_ino, "device": stat.st_dev}


def _runtime_group_state(plan):
    """Read an identity-bound cgroup boundary; population is not PID RSS."""
    path = Path(plan["path"])
    if _runtime_cgroup_identity(path) != plan["identity"]:
        raise ObserverBindingError("runtime cgroup lifetime identity changed")
    accounting = capture_cgroup(path)
    events = dict(line.split() for line in (path / "cgroup.events").read_text().splitlines())
    raw_pids = (path / "cgroup.procs").read_text().split()
    if events.get("populated") not in ("0", "1") or any(not pid.isdecimal() for pid in raw_pids):
        raise ObserverBindingError("runtime cgroup population evidence malformed")
    if accounting.get("identity") != plan["identity"] or _runtime_cgroup_identity(path) != plan["identity"]:
        raise ObserverBindingError("runtime cgroup identity changed during boundary capture")
    return {"monotonic_ns": time.monotonic_ns(), "populated": events["populated"] == "1",
            "pids": sorted(set(map(int, raw_pids))), "accounting": accounting,
            "pid_enumeration_scope": "DECLARED_LEAF_CGROUP_PROCS; POPULATION_INCLUDES_DESCENDANT_CGROUPS",
            "scope": plan["scope"]}


def _prepare_runtime_cgroup(settings):
    declared = getattr(settings, "runtime_cgroup", None)
    owned = getattr(settings, "runtime_cgroup_owned", False)
    if owned is not True and owned is not False:
        raise ValueError("runtime_cgroup_owned must be an explicit boolean")
    if declared is None:
        if owned:
            raise ValueError("owned runtime cgroup requires an explicit path")
        return None
    path = Path(declared).resolve(strict=True)
    if CGROUP_ROOT.resolve(strict=True) not in path.parents:
        raise ValueError("runtime cgroup must be an explicit cgroup-v2 child")
    if owned and (path.name != "runtime" or path.parent.parent != CGROUP_ROOT.resolve(strict=True)
                  or not OWNED_RUNTIME_PARENT.fullmatch(path.parent.name)):
        raise ValueError("owned cleanup only admits this fixture's fresh UUID runtime leaf")
    plan = {"path": str(path), "identity": _runtime_cgroup_identity(path), "owned": owned,
        "scope": "FRESH_EXCLUSIVE_RUNTIME_CGROUP_INCLUDES_DESCENDANTS" if owned else
            "EXPLICIT_RUNTIME_CGROUP_NOT_PROVEN_EXCLUSIVE_NO_AUTOMATIC_CLEANUP"}
    initial = _runtime_group_state(plan)
    if owned and (initial["populated"] or initial["pids"] or any(child.is_dir() for child in path.iterdir())):
        raise ObserverBindingError("owned runtime cgroup must start empty with no nested groups")
    plan["initial_state"] = initial
    return plan


def _runtime_process_fact(pid):
    """Retain process identity for cleanup evidence, never argv or environment."""
    root = Path("/proc") / str(pid)
    try:
        first = (root / "stat").read_text()
        first_ticks = int(first[first.rfind(")") + 2:].split()[19])
        comm = (root / "comm").read_text().rstrip("\n")[:256]
        try:
            executable = os.readlink(root / "exe")
        except OSError as error:
            executable = None
            executable_error = type(error).__name__
        else:
            executable_error = None
        last = (root / "stat").read_text()
        last_ticks = int(last[last.rfind(")") + 2:].split()[19])
        if first_ticks != last_ticks:
            return {"pid": pid, "status": "PID_IDENTITY_CHANGED_DURING_ENUMERATION"}
        return {"pid": pid, "start_ticks": first_ticks, "comm": comm, "exe": executable,
                "exe_error": executable_error, "status": "IDENTITY_OBSERVED"}
    except (OSError, ValueError, IndexError) as error:
        return {"pid": pid, "status": "UNAVAILABLE_DURING_ENUMERATION", "error": type(error).__name__}


def _kill_owned_runtime_cgroup(plan):
    """Only a validated fresh fixture leaf can reach the cgroup.kill write."""
    if plan.get("owned") is not True:
        raise ObserverBindingError("automatic cleanup is forbidden for a non-owned runtime cgroup")
    path = Path(plan["path"])
    if path.name != "runtime" or path.parent.parent != CGROUP_ROOT.resolve(strict=True) or \
            not OWNED_RUNTIME_PARENT.fullmatch(path.parent.name):
        raise ObserverBindingError("automatic cleanup target is not a fresh fixture runtime leaf")
    initial = plan.get("initial_state", {})
    if initial.get("populated") is not False or initial.get("pids") != [] or \
            initial.get("accounting", {}).get("identity") != plan["identity"]:
        raise ObserverBindingError("automatic cleanup lacks initially-empty identity-bound ownership evidence")
    directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        stat = os.fstat(directory_fd)
        if {"path": str(path), "inode": stat.st_ino, "device": stat.st_dev} != plan["identity"]:
            raise ObserverBindingError("runtime cgroup identity changed before cleanup")
        # No PID-based kill fallback: PID reuse must never target another task.
        kill_fd = os.open("cgroup.kill", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            os.write(kill_fd, b"1")
        finally:
            os.close(kill_fd)
    finally:
        os.close(directory_fd)


def _close_runtime_cgroup(plan, app, root_pid, returncode, root_wait_ns):
    if plan is None:
        return None
    receipt = {"schema_version": 1, "clock": "CLOCK_MONOTONIC",
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "root_pid": root_pid, "root_returncode": returncode,
        "root_wait_confirmed_ns": root_wait_ns, "owned": plan["owned"],
        "identity": plan["identity"], "scope": plan["scope"],
        "initial_state": plan["initial_state"], "forced_cleanup": False,
        "command_arguments_collected": False, "environment_collected": False}
    try:
        before = _runtime_group_state(plan)
        receipt["before"] = before
        receipt["residual_processes_before_cleanup"] = [_runtime_process_fact(pid) for pid in before["pids"]]
        receipt["had_residual_processes_after_root_exit"] = before["populated"] or bool(before["pids"])
        if not plan["owned"]:
            receipt.update(status="NOT_CLEANED_NONOWNED_SCOPE", after=before)
        else:
            if receipt["had_residual_processes_after_root_exit"]:
                receipt["forced_cleanup"] = True
                receipt["cleanup_started_ns"] = time.monotonic_ns()
                _kill_owned_runtime_cgroup(plan)
            deadline = time.monotonic() + 5
            after = _runtime_group_state(plan)
            while (after["populated"] or after["pids"]) and time.monotonic() < deadline:
                time.sleep(.01)
                after = _runtime_group_state(plan)
            receipt["after"] = after
            receipt["finished_ns"] = time.monotonic_ns()
            if after["populated"] or after["pids"]:
                raise ObserverBindingError("owned runtime cgroup remained populated after bounded cleanup")
            receipt["status"] = "OWNED_CGROUP_EMPTY_AFTER_FORCED_CLEANUP" if receipt["forced_cleanup"] else \
                "OWNED_CGROUP_ALREADY_EMPTY_NO_KILL"
    except BaseException as error:
        receipt.update(status="CLEANUP_FAILED_OR_IDENTITY_UNCONFIRMED",
                       error=type(error).__name__ + ": " + str(error))
        write_new(Path(app) / "runtime-cgroup-cleanup.json", receipt)
        raise
    write_new(Path(app) / "runtime-cgroup-cleanup.json", receipt)
    return receipt


async def bound_tool(settings, environment, command, call_id, rpc_request_id):
    gate = settings.gate
    if gate is None or environment.exec is not gate:
        raise ObserverBindingError("Codex tool is not the registered Docker Exec gate")
    before = len(gate.manifest["tools"])
    error, executed = None, None
    try:
        executed = await environment.exec(command=command, timeout_sec=settings.tool_timeout)
    except BaseException as failure:
        error = failure
    added = gate.manifest["tools"][before:]
    if (len(added) != 1 or added[0].get("command") != command
            or added[0].get("agent_id") != settings.agent_id
            or not isinstance(added[0].get("root"), dict)
            or type(added[0].get("begin_ns")) is not int or type(added[0].get("end_ns")) is not int):
        raise ObserverBindingError("one Codex dynamic request must bind exactly one stopped Docker root") from error
    span = added[0]
    stdout, stderr = (executed.stdout or "", executed.stderr or "") if executed is not None else ("", "")
    code = executed.return_code if executed is not None else 124 if isinstance(error, TimeoutError) else None
    if type(code) is not int:
        raise ObserverBindingError("Docker transport failed without a bounded tool timeout") from error
    if error is not None:
        stderr = "Tool timed out; its registered Docker Exec root was terminated."
    index = len(settings.function_bindings) + 1
    stdout_name, stderr_name = f"tool-{index:04d}.stdout", f"tool-{index:04d}.stderr"
    write_new(settings.evidence_directory / stdout_name, stdout.encode())
    write_new(settings.evidence_directory / stderr_name, stderr.encode())
    binding = {"tool_call_id": span["tool_call_id"], "observer_tool_call_id": span["tool_call_id"],
        "agent_id": settings.agent_id, "task_id": settings.task_id, "boot_id": settings.boot_id,
        "budget_label": settings.budget_label, "root_pid": span["root"]["tid"], "root": dict(span["root"]),
        "cgroup_id": span["cgroup_id"], "begin_ns": span["begin_ns"], "end_ns": span["end_ns"],
        "gate_binding_basis": BINDING, "cgroup_empty": None,
        "quiescence_scope": "PER_TOOL_ROOT_FINISHED; FULL_CONTAINER_CLOSURE_ONLY_AT_AGENT_END",
        "stdout_artifact": "app/" + stdout_name, "stderr_artifact": "app/" + stderr_name,
        "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
        "docker_exec_id": span.get("docker_exec_id"), "gate_result": span.get("result")}
    # GatedExec has already fsynced TOOL_END. Its final span is immutable and
    # must remain byte-for-byte equal to that journal for independent replay.
    # Codex IDs therefore live in a separately manifest-bound application
    # ledger, never in an after-the-fact mutation of the gate span.
    row = {"thread_id": None, "turn_id": None, "call_id": call_id, "rpc_request_id": rpc_request_id,
           "command": command, **binding}
    settings.function_bindings.append(row)
    append_record(settings.evidence_directory / "docker-function-bindings.jsonl", row)
    settings.persist()
    return {"exit_code": code, "stdout": stdout[:3500], "stderr": stderr[:1000],
            "output_truncated": len(stdout) > 3500 or len(stderr) > 1000, "binding": binding}


def _run_runtime(settings, instruction, executor):
    """Blocking JSON-RPC transport run in a worker thread; no paid call loop here."""
    app = settings.evidence_directory
    app.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not 1 <= len(instruction.encode()) <= 32768:
        raise ValueError("bounded public Terminal-Bench instruction required")
    expected = expected_max_calls(settings.budget_label)
    if (settings.max_calls, settings.max_requests, settings.max_output, settings.tool_timeout, settings.timeout) != (expected, 12, 4096, 45, 1800):
        raise ValueError(f"Codex campaign fixes {expected} calls, 12 model requests, 4096 output tokens, 45s tools and 1800s turns")
    write_new(app / "prompt.txt", instruction.encode())
    write_new(app / "model-catalog.json", Path(settings.catalog).read_bytes())
    command_settings = replace(settings,base_url=getattr(settings,"_observer_timed_base_url",settings.base_url))
    command, config = app_server_command(command_settings, app / "model-catalog.json")
    runtime_plan = _prepare_runtime_cgroup(settings)
    write_new(app / "config.public.json", {"config": config, "budget_label": settings.budget_label,
        "codex_identity": digest(settings.codex), "model_catalog_identity": digest(settings.catalog),
        "http_headers": {"X-Benchmark-Task": settings.budget_label}, "credentials": "LOCAL_PROXY_TOKEN_ONLY_NOT_LOGGED",
        "agent_loop": IMPLEMENTATION, "base_instructions": settings.base_instructions,
        "provider_tool_policy": "EXTERNAL_BROKER_MUST_ADVERTISE_AND_DELIVER_ONLY_EXACT_OBSERVER_BASH",
        "application_tool_event_policy": "RECORD_SUPPORTED_CODEX_ITEMS_IF_REPORTED; DO_NOT_INFER_LINUX_BINDING",
        "runtime_kernel_scope": "NOT_CAPTURED; ONLY_DOCKER_TASK_CONTAINER_IS_CAPTURED"})
    with tempfile.TemporaryDirectory(prefix="observer-codex-terminal-private-") as private:
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "CODEX_HOME": private, "OBSERVER_BROKER_TOKEN": proxy_token(settings.token_file)}
        with (app / "runtime.stderr").open("xb") as err, (app / "runtime.stdout").open("xb") as raw:
            runtime_cgroup=Path(runtime_plan["path"]) if runtime_plan else None
            enroll_runtime=bool(runtime_plan and runtime_plan["owned"])
            launch_command=(["/bin/sh","-c",'kill -STOP $$; exec "$@"',"observer-codex-runtime",*command]
                if enroll_runtime else command)
            proc = subprocess.Popen(launch_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err,
                                    env=environment, cwd=private, start_new_session=True)
            old_sampler = getattr(settings.gate, "resource_sampler", None)
            sampler = None
            try:
                if enroll_runtime:
                    from run import wait_stopped
                    wait_stopped(proc.pid,5)
                    ready_group = _runtime_group_state(runtime_plan)
                    if ready_group["populated"] or ready_group["pids"]:
                        raise ObserverBindingError("owned runtime group became populated before enrollment")
                    (Path(runtime_cgroup)/"cgroup.procs").write_text(str(proc.pid))
                settings.runtime = {"pid": proc.pid, "begin_ns": time.monotonic_ns(), "kernel_observed": False,
                    "actual_binary": str(settings.codex), "binary_identity": digest(settings.codex),
                    "application_only_clock": "CLOCK_MONOTONIC", "runtime_directory": "PRIVATE_TEMPORARY_NOT_EXPORTED"}
                if runtime_plan:
                    settings.runtime["resource_cgroup"] = {"path":runtime_plan["path"],
                        "identity":runtime_plan["identity"],"scope":runtime_plan["scope"],
                        "owned":runtime_plan["owned"],"enrollment":"STOPPED_CHILD_ENROLLED_BEFORE_EXEC" if enroll_runtime else
                            "NONOWNED_READ_ONLY_NO_ENROLLMENT"}
                settings.persist()
                sampler = RuntimeResourceSampler(app, interval_ms=100, agent_id=settings.agent_id)
                sampler.register("codex-runtime", pid=proc.pid, role="AGENT_RUNTIME",cgroup=runtime_cgroup,
                    cgroup_scope=runtime_plan["scope"] if runtime_plan else "NO_CGROUP_REGISTERED")
                sampler.register("observer-supervisor", pid=os.getpid(), role="OBSERVER_SUPERVISOR",
                    cgroup=getattr(settings,"observer_cgroup",None),cgroup_scope="FRESH_EXCLUSIVE_OBSERVER_FIXTURE_CGROUP")
                sampler.start()
                if settings.gate is not None:
                    settings.gate.resource_sampler = sampler
                    settings.gate._resource_container_registered = False
                rpc = CodexRPC(proc.stdout.fileno(), proc.stdin.fileno(), app, settings.boot_id, raw)
                if enroll_runtime:os.kill(proc.pid,signal.SIGCONT)
            except BaseException:
                if settings.gate is not None:
                    settings.gate.resource_sampler = old_sampler
                os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=5)
                proc.stdin.close();proc.stdout.close()
                if sampler is not None:sampler.stop()
                raise
            def progress(value):
                settings.partial = json.loads(json.dumps(value))
            try:
                result = run_agent(rpc, instruction, settings.thread_cwd, executor, app, max_calls=settings.max_calls,
                    timeout=settings.timeout, base_instructions=settings.base_instructions, progress=progress, binding_basis=BINDING,
                    tool_timing_scope="SUPERVISOR_SIGCONT_THROUGH_DOCKER_EXEC_ROOT_RETURN; FULL_CGROUP_CLOSURE_AT_AGENT_END",
                    max_command_bytes=32768, agent_id=settings.agent_id, task_id=settings.task_id,
                    budget_label=settings.budget_label)
                settings.termination = "CODEX_" + result["status"].upper()
            except (TimeoutError, EOFError) as failure:
                settings.termination = "CODEX_RUNTIME_TIMEOUT_OR_EOF"
                result = {"schema_version": 2, "mode": "REAL_CODEX_APP_SERVER_DYNAMIC_TOOLS",
                    "model": "deepseek-flash", **settings.partial, "status": "failed",
                    "error": type(failure).__name__ + ": " + str(failure),
                    "tool_event_schema": "APPLICATION_TOOL_LIFECYCLE_V1",
                    "tool_event_source_scope": "RAW_CODEX_RPC_REPLAY_REQUIRED; LINUX_BINDING_SEPARATE",
                    "tool_calls": settings.partial.get("tool_calls", []),
                    "agent_loop": "OFFICIAL_CODEX_NOT_IMPLEMENTED_BY_THIS_CLIENT"}
                if not (app / "steps.json").exists():
                    write_new(app / "steps.json", result)
            except RuntimeError as failure:
                if "dynamic tool call limit reached" not in str(failure):
                    raise
                settings.termination = "CODEX_TOOL_CALL_LIMIT"
                result = {"schema_version": 2, "mode": "REAL_CODEX_APP_SERVER_DYNAMIC_TOOLS", "model": "deepseek-flash",
                    **settings.partial, "status": "interrupted", "error": str(failure),
                    "tool_event_schema": "APPLICATION_TOOL_LIFECYCLE_V1",
                    "tool_event_source_scope": "RAW_CODEX_RPC_REPLAY_REQUIRED; LINUX_BINDING_SEPARATE",
                    "tool_calls": settings.partial.get("tool_calls", []),
                    "agent_loop": "OFFICIAL_CODEX_NOT_IMPLEMENTED_BY_THIS_CLIENT"}
                write_new(app / "steps.json", result)
            finally:
                proc.stdin.close()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL); proc.wait(timeout=5)
                root_wait_ns = time.monotonic_ns()
                cleanup_error = None
                try:
                    cleanup = _close_runtime_cgroup(runtime_plan,app,proc.pid,proc.returncode,root_wait_ns)
                    if cleanup is not None:
                        settings.runtime["cgroup_cleanup"] = cleanup
                except BaseException as failure:
                    cleanup_error = failure
                try:
                    sampler.finish("codex-runtime",reason="CODEX_RUNTIME_WAIT_CONFIRMED",
                        confirmed_exit=proc.returncode,exit_source="SUBPROCESS_WAIT")
                finally:
                    try:
                        settings.runtime["resource_summary"] = sampler.stop()
                    finally:
                        if settings.gate is not None:
                            settings.gate.resource_sampler = old_sampler
                # Drain only after all normal stdout writers have exited.
                # Bound tail prevents a broken child from growing evidence indefinitely.
                tail, deadline = bytearray(), time.monotonic() + 5
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([proc.stdout.fileno()], [], [], remaining)[0]:
                        raise ObserverBindingError("Codex stdout writer survived runtime exit")
                    block = os.read(proc.stdout.fileno(), 65536)
                    if not block:
                        break
                    tail.extend(block)
                    if len(tail) > 4 * 1024 * 1024:
                        raise ObserverBindingError("oversized Codex post-turn stdout")
                raw.write(tail); raw.flush(); os.fsync(raw.fileno()); proc.stdout.close()
                settings.runtime.update(end_ns=time.monotonic_ns(), return_code=proc.returncode)
                settings.runtime["model_timing"] = {"artifact":"model-request-timing.jsonl",
                    "clock":"CLOCK_MONOTONIC","scope":"AGENT_LOCAL_HTTP_BOUNDARY"}
                settings.persist()
                if cleanup_error is not None:
                    raise cleanup_error
    write_new(app / "codex-result.json", result)
    settings.outcome = result
    settings.persist()
    return result


def run_runtime(settings, instruction, executor):
    """Keep request timing on the same Linux clock as the Agent/tool events."""
    app=settings.evidence_directory
    app.mkdir(mode=0o700,parents=True,exist_ok=True)
    with ModelTransportProxy(app,settings.base_url,proxy_token(settings.token_file),
                             settings.budget_label) as transport:
        settings._observer_timed_base_url=transport.base_url
        try:
            return _run_runtime(settings,instruction,executor)
        finally:
            del settings._observer_timed_base_url


class CodexObserverAgent(BaseAgent):
    @staticmethod
    def name():
        return "observer-timeline-codex"

    def version(self):
        return "1.0"

    async def setup(self, environment):
        return

    async def run(self, instruction, environment, context):
        settings = ACTIVE.get()
        if not isinstance(settings, CodexSettings) or settings.gate is None:
            raise ObserverBindingError("Codex requires one released instrumented worker settings object")
        loop = asyncio.get_running_loop()
        def execute(command, call_id, rpc_id):
            future = asyncio.run_coroutine_threadsafe(bound_tool(settings, environment, command, call_id, rpc_id), loop)
            return future.result(timeout=settings.tool_timeout + 90)
        try:
            await loop.run_in_executor(None, settings.runner or run_runtime, settings, instruction, execute)
        finally:
            settings.persist()
            context.metadata = {"termination": settings.termination, "mode": MODE,
                "agent_implementation": IMPLEMENTATION, "budget_label": settings.budget_label,
                "model_usage_authority": "SHARED_HOST_RESPONSES_BROKER_LEDGER"}
