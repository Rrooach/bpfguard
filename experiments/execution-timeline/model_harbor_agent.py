"""Bounded real model agent; public instruction only, no Oracle invocation."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import time

from harbor.agents.base import BaseAgent
from model_client import ModelClient, ModelRequestError

ACTIVE = ContextVar("timeline_model_agent_settings", default=None)
MODEL_SCOPE = "REAL_MODEL_AGENT_PUBLIC_INSTRUCTION_AND_GATED_TOOLS_NOT_ORACLE"


class ObserverBindingError(RuntimeError):
    """Instrumentation/identity failures are not model-score failures."""


def append(path, value):
    with path.open("ab") as stream:
        stream.write(json.dumps(value, sort_keys=True, allow_nan=False).encode() + b"\n")
        stream.flush(); os.fsync(stream.fileno())


@dataclass
class ModelSettings:
    base_url: str
    token_file: Path
    budget_label: str
    evidence_directory: Path
    agent_id: str
    task_id: str
    boot_id: str
    max_rounds: int = 4
    max_output: int = 1024
    request_timeout: int = 180
    tool_timeout: int = 45
    gate: object = None
    client: object = None
    termination: str = "NOT_STARTED"
    function_bindings: list = field(default_factory=list)
    client_factory: object = ModelClient

    def persist(self):
        self.evidence_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        value = {"schema_version": 1, "mode": "MODEL_AGENT", "agent_scope": MODEL_SCOPE,
                 "agent_id": self.agent_id, "task_id": self.task_id, "budget_label": self.budget_label,
                 "boot_id": self.boot_id, "model": "deepseek-flash", "clock": "CLOCK_MONOTONIC",
                 "max_rounds": self.max_rounds, "max_output_tokens": self.max_output,
                 "tool_timeout_sec": self.tool_timeout, "request_timeout_sec": self.request_timeout,
                 "termination": self.termination,
                 "paid_api_calls": None, "paid_api_call_count_authority": "SHARED_HOST_BROKER_LEDGER",
                 "client_request_attempts": len(self.client.events) if self.client else 0,
                 "usage": dict(self.client.usage) if self.client else {"prompt_tokens": 0, "completion_tokens": 0},
                 "function_bindings": self.function_bindings,
                 "meaning": "APPLICATION_EVIDENCE; API_WAIT_IS_NOT_REMOTE_GPU_OR_CONTAINER_KERNEL_ACTIVITY"}
        path = self.evidence_directory / "model-agent.json"
        temporary = path.with_name(".model-agent.pending")
        with temporary.open("xb") as stream:
            stream.write(json.dumps(value, sort_keys=True, indent=2).encode() + b"\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        return value


@contextmanager
def configured(settings):
    token = ACTIVE.set(settings)
    try:
        yield settings
    finally:
        ACTIVE.reset(token)


TOOLS = [{"type": "function", "function": {
    "name": "bash", "description": "Run a bounded shell command in the task workspace.",
    "parameters": {"type": "object", "properties": {"command": {"type": "string"}},
                   "required": ["command"], "additionalProperties": False}}},
    {"type": "function", "function": {"name": "finish", "description": "Submit current changes for official grading.",
    "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}}]


async def bound_tool(settings, environment, command, provider_call_id, request_id):
    gate = settings.gate
    if gate is None or environment.exec is not gate:
        raise ObserverBindingError("model tool is not the registered Docker Exec gate")
    before = len(gate.manifest["tools"])
    execution_error, executed = None, None
    try:
        executed = await environment.exec(command=command, timeout_sec=settings.tool_timeout)
    except BaseException as error:
        execution_error = error
    added = gate.manifest["tools"][before:]
    if (len(added) != 1 or added[0].get("command") != command
            or added[0].get("agent_id") != settings.agent_id
            or not isinstance(added[0].get("root"), dict)
            or type(added[0].get("begin_ns")) is not int or type(added[0].get("end_ns")) is not int):
        raise ObserverBindingError("one provider bash call must bind to exactly one enrolled root") from execution_error
    span = added[0]
    binding = {"schema_version": 1, "event": "MODEL_FUNCTION_BOUND", "boot_id": settings.boot_id,
               "agent_id": settings.agent_id, "task_id": settings.task_id, "budget_label": settings.budget_label,
               "request_id": request_id, "provider_function_call_id": provider_call_id,
               "observer_tool_call_id": span["tool_call_id"], "root": dict(span["root"]),
               "cgroup_id": span["cgroup_id"], "begin_ns": span["begin_ns"], "end_ns": span["end_ns"],
               "command_sha256": hashlib.sha256(command.encode()).hexdigest(), "result": span.get("result"),
               "binding_basis": "SAME_SEQUENTIAL_EXEC_INVOCATION_RETURNED_EXACTLY_ONE_GATE_ENROLLMENT_NOT_TIMESTAMP_MATCHING"}
    settings.function_bindings.append(binding)
    append(settings.evidence_directory / "model-function-bindings.jsonl", binding)
    if execution_error:
        append(settings.evidence_directory / "model-tool-outputs.jsonl", {
            "request_id": request_id, "provider_function_call_id": provider_call_id,
            "observer_tool_call_id": span["tool_call_id"], "stdout": None, "stderr": None,
            "output_status": "UNAVAILABLE_ON_TOOL_ERROR", "error_type": type(execution_error).__name__})
        if isinstance(execution_error, TimeoutError):
            return {"stdout": "", "stderr": "Tool timed out; its registered root was terminated.", "return_code": None}
        raise execution_error
    stdout, stderr = executed.stdout or "", executed.stderr or ""
    append(settings.evidence_directory / "model-tool-outputs.jsonl", {
        "request_id": request_id, "provider_function_call_id": provider_call_id,
        "observer_tool_call_id": span["tool_call_id"], "stdout": stdout, "stderr": stderr,
        "return_code": executed.return_code, "output_status": "FULL_TEXT_RETURNED_BY_BOUNDED_DOCKER_EXEC_TRANSPORT"})
    return {"stdout": stdout[:3500], "stderr": stderr[:1000], "return_code": executed.return_code,
            "stdout_truncated": len(stdout) > 3500, "stderr_truncated": len(stderr) > 1000}


class BoundedModelAgent(BaseAgent):
    @staticmethod
    def name():
        return "observer-timeline-model"

    def version(self):
        return "1.0"

    async def setup(self, environment):
        return

    async def run(self, instruction, environment, context):
        settings = ACTIVE.get()
        if not isinstance(settings, ModelSettings) or settings.gate is None:
            raise ObserverBindingError("model agent requires one released, instrumented worker settings object")
        if (settings.max_rounds, settings.max_output, settings.request_timeout, settings.tool_timeout) != (4, 1024, 180, 45):
            raise ValueError("this campaign fixes 4 rounds, 1024 output tokens, 180s API and 45s tool timeout")
        settings.client = settings.client_factory(settings.base_url, settings.token_file, settings.budget_label,
            settings.evidence_directory, max_output=settings.max_output,
            request_timeout=settings.request_timeout, boot_id=settings.boot_id)
        with (settings.evidence_directory / "model-function-bindings.jsonl").open("xb"):
            pass
        with (settings.evidence_directory / "model-tool-outputs.jsonl").open("xb"):
            pass
        messages = [{"role": "system", "content": (
            "Solve the public task in the current Linux workspace with bash, then call finish. "
            "Do not read /solution, /tests or verifier artifacts, Docker control sockets, host files or credentials. "
            "There are at most 4 model responses, each at most 1024 output tokens, and each shell command has 45 seconds. "
            "Keep output concise and split edits into bounded commands. No reference solution is provided.")},
            {"role": "user", "content": instruction}]
        seen_calls = set()
        settings.termination = "ROUND_LIMIT"
        try:
            for step in range(settings.max_rounds):
                try:
                    response = await settings.client.request(messages, TOOLS, step)
                except ModelRequestError as error:
                    settings.termination = "MODEL_" + error.kind
                    return
                request_id = settings.budget_label + "-step-" + str(step)
                message = response["choices"][0]["message"]
                messages.append(message)
                calls = message.get("tool_calls") or []
                if not isinstance(calls, list) or len(calls) > 4:
                    settings.termination = "MODEL_TOOL_CALL_LIMIT_OR_FORMAT"
                    return
                if not calls:
                    messages.append({"role": "user", "content": "Use bash or finish to submit your work."})
                    continue
                for call in calls:
                    try:
                        call_id = call["id"]
                        if not isinstance(call_id, str) or not call_id or len(call_id) > 256 or (request_id, call_id) in seen_calls:
                            raise ValueError("function-call ID must be unique and bounded")
                        seen_calls.add((request_id, call_id))
                        function = call["function"]
                        args = json.loads(function["arguments"])
                        if not isinstance(args, dict):
                            raise ValueError("tool arguments must be an object")
                        name = function["name"]
                        if name == "finish":
                            if args:
                                raise ValueError("finish takes no arguments")
                            settings.termination = "MODEL_FINISH"
                            return
                        if (name != "bash" or set(args) != {"command"} or not isinstance(args["command"], str)
                                or not args["command"].strip() or len(args["command"].encode()) > 16384 or "\0" in args["command"]):
                            raise ValueError("bash requires one bounded nonempty command")
                    except (KeyError, TypeError, ValueError) as error:
                        call_id = call.get("id", "invalid") if isinstance(call, dict) else "invalid"
                        append(settings.evidence_directory / "model-function-bindings.jsonl", {
                            "event": "MODEL_FUNCTION_REJECTED", "request_id": request_id,
                            "provider_function_call_id": call_id, "reason": str(error), "monotonic_ns": time.monotonic_ns(),
                            "agent_id": settings.agent_id, "task_id": settings.task_id, "budget_label": settings.budget_label,
                            "boot_id": settings.boot_id, "clock": "CLOCK_MONOTONIC"})
                        messages.append({"role": "tool", "tool_call_id": str(call_id),
                                         "content": "Rejected malformed tool; no command executed: " + str(error)})
                        continue
                    output = await bound_tool(settings, environment, args["command"], call_id, request_id)
                    messages.append({"role": "tool", "tool_call_id": call_id, "content": json.dumps(output)})
                settings.persist()
        finally:
            value = settings.persist()
            context.n_input_tokens = value["usage"]["prompt_tokens"]
            context.n_output_tokens = value["usage"]["completion_tokens"]
            context.metadata = {"termination": settings.termination, "mode": "MODEL_AGENT", "budget_label": settings.budget_label}
