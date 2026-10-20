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
from dataclasses import dataclass, field
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

from harbor.agents.base import BaseAgent

from codex_client import CodexRPC, append_record, run_agent
from codex_run import proxy_token
from common import digest, write_new

ACTIVE = ContextVar("timeline_codex_terminal_settings", default=None)
LABEL = re.compile(r"codex-terminal-c(2|4|6|8)-0[0-7]\Z")
MODE = "MODEL_AGENT"
IMPLEMENTATION = "OFFICIAL_CODEX_APP_SERVER_DYNAMIC_TOOLS"
BINDING = "EXPLICIT_CODEX_REQUEST_TO_DOCKER_EXEC_STOPPED_ROOT_NOT_TIMESTAMP_MATCHING"
SCOPE = "OFFICIAL_CODEX_PUBLIC_TASK_AND_GATED_DOCKER_TOOLS; CODEX_RUNTIME_OUTSIDE_CONTAINER_CAPTURE"
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

    def persist(self):
        self.evidence_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        value = {"schema_version": 1, "mode": MODE, "agent_implementation": IMPLEMENTATION,
            "agent_id": self.agent_id, "task_id": self.task_id, "budget_label": self.budget_label,
            "boot_id": self.boot_id, "clock": "CLOCK_MONOTONIC", "agent_scope": SCOPE,
            "model": "deepseek-flash", "max_calls": self.max_calls,
            "max_requests_enforced_by_external_broker": self.max_requests,
            "max_output_tokens_enforced_by_external_broker": self.max_output,
            "reasoning_effort": "none", "max_command_bytes": 32768,
            "tool_timeout_seconds": self.tool_timeout, "termination": self.termination,
            "function_bindings": self.function_bindings, "runtime": self.runtime,
            "paid_api_calls": None, "cost_authority": "SHARED_HOST_RESPONSES_BROKER_LEDGER",
            "runtime_kernel_scope": "CODEX_RUNTIME_NOT_CAPTURED; ONLY_TASK_CONTAINER_GATED_TOOL_TREES"}
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


def run_runtime(settings, instruction, executor):
    """Blocking JSON-RPC transport run in a worker thread; no paid call loop here."""
    app = settings.evidence_directory
    app.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not 1 <= len(instruction.encode()) <= 32768:
        raise ValueError("bounded public Terminal-Bench instruction required")
    if (settings.max_calls, settings.max_requests, settings.max_output, settings.tool_timeout, settings.timeout) != (8, 12, 4096, 45, 1800):
        raise ValueError("Codex campaign fixes 8 calls, 12 model requests, 4096 output tokens, 45s tools and 1800s turns")
    write_new(app / "prompt.txt", instruction.encode())
    write_new(app / "model-catalog.json", Path(settings.catalog).read_bytes())
    command, config = app_server_command(settings, app / "model-catalog.json")
    write_new(app / "config.public.json", {"config": config, "budget_label": settings.budget_label,
        "codex_identity": digest(settings.codex), "model_catalog_identity": digest(settings.catalog),
        "http_headers": {"X-Benchmark-Task": settings.budget_label}, "credentials": "LOCAL_PROXY_TOKEN_ONLY_NOT_LOGGED",
        "agent_loop": IMPLEMENTATION, "base_instructions": INSTRUCTIONS,
        "provider_tool_policy": "EXTERNAL_BROKER_MUST_ADVERTISE_AND_DELIVER_ONLY_EXACT_OBSERVER_BASH",
        "runtime_kernel_scope": "NOT_CAPTURED; ONLY_DOCKER_TASK_CONTAINER_IS_CAPTURED"})
    with tempfile.TemporaryDirectory(prefix="observer-codex-terminal-private-") as private:
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "CODEX_HOME": private, "OBSERVER_BROKER_TOKEN": proxy_token(settings.token_file)}
        with (app / "runtime.stderr").open("xb") as err, (app / "runtime.stdout").open("xb") as raw:
            proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err,
                                    env=environment, cwd=private, start_new_session=True)
            settings.runtime = {"pid": proc.pid, "begin_ns": time.monotonic_ns(), "kernel_observed": False,
                "actual_binary": str(settings.codex), "binary_identity": digest(settings.codex),
                "application_only_clock": "CLOCK_MONOTONIC", "runtime_directory": "PRIVATE_TEMPORARY_NOT_EXPORTED"}
            settings.persist()
            rpc = CodexRPC(proc.stdout.fileno(), proc.stdin.fileno(), app, settings.boot_id, raw)
            def progress(value):
                settings.partial = json.loads(json.dumps(value))
            try:
                result = run_agent(rpc, instruction, Path(private), executor, app, max_calls=settings.max_calls,
                    timeout=settings.timeout, base_instructions=INSTRUCTIONS, progress=progress, binding_basis=BINDING,
                    tool_timing_scope="SUPERVISOR_SIGCONT_THROUGH_DOCKER_EXEC_ROOT_RETURN; FULL_CGROUP_CLOSURE_AT_AGENT_END",
                    max_command_bytes=32768)
                settings.termination = "CODEX_" + result["status"].upper()
            except (TimeoutError, EOFError) as failure:
                settings.termination = "CODEX_RUNTIME_TIMEOUT_OR_EOF"
                result = {"schema_version": 1, "mode": "REAL_CODEX_APP_SERVER_DYNAMIC_TOOLS",
                    "model": "deepseek-flash", **settings.partial, "status": "failed",
                    "error": type(failure).__name__ + ": " + str(failure),
                    "agent_loop": "OFFICIAL_CODEX_NOT_IMPLEMENTED_BY_THIS_CLIENT"}
                if not (app / "steps.json").exists():
                    write_new(app / "steps.json", result)
            except RuntimeError as failure:
                if "dynamic tool call limit reached" not in str(failure):
                    raise
                settings.termination = "CODEX_TOOL_CALL_LIMIT"
                result = {"schema_version": 1, "mode": "REAL_CODEX_APP_SERVER_DYNAMIC_TOOLS", "model": "deepseek-flash",
                    **settings.partial, "status": "interrupted", "error": str(failure),
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
                settings.persist()
    write_new(app / "codex-result.json", result)
    settings.outcome = result
    settings.persist()
    return result


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
