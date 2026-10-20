#!/usr/bin/env python3
"""Codex app-server transport, not a replacement model/agent loop.

The official Codex process chooses model calls, tool calls and the final answer.
This client only implements its JSON-RPC transport and one application-owned
dynamic tool. IDs, not timestamp proximity, link that request to stopped-launch
Linux execution. Receipt timestamps are explicitly client-side observations.
"""
from __future__ import annotations

from collections import deque
import csv
import json
import os
from pathlib import Path
import select
import time

from common import canonical, write_new

MAX_LINE = 8 * 1024 * 1024
BASE_INSTRUCTIONS = (
    "You are Codex, a coding agent. Complete the user's small local task. "
    "Use only the observer_bash tool for local commands or file operations. "
    "Do not claim a command ran unless the tool returned its result. "
    "Use a small number of short commands, then give a brief final answer."
)
TOOL = {"type": "function", "name": "observer_bash",
        "description": "Execute a short Bash command in the task workspace. Returns exit code, stdout and stderr.",
        "inputSchema": {"type": "object", "additionalProperties": False,
                        "properties": {"command": {"type": "string"}}, "required": ["command"]}}


def append_record(path, value):
    with Path(path).open("ab") as stream:
        stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())


def strict_object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    if not isinstance(value, dict):
        raise ValueError("JSON-RPC message must be an object")
    return value


def rpc_id(value):
    if type(value) not in (str, int) or (isinstance(value, str) and (not value or len(value) > 256)):
        raise ValueError("invalid JSON-RPC ID")
    return (type(value).__name__, value)


class CodexRPC:
    def __init__(self, read_fd, write_fd, directory, boot_id, raw_stdout):
        self.read_fd, self.write_fd = read_fd, write_fd
        self.directory, self.boot_id = Path(directory), boot_id
        self.raw_stdout = raw_stdout
        self.buffer, self.queued = bytearray(), deque()
        self.next_id, self.request_ids, self.responded = 1, set(), set()
        self.closed_input = False
        self.log = self.directory / "rpc.jsonl"
        write_new(self.log, b"")
        write_new(self.directory / "client-requests.jsonl", b"")

    def record(self, direction, value):
        append_record(self.log, {"direction": direction, "boot_id": self.boot_id,
            "receipt_ns": time.monotonic_ns(), "clock": "CLOCK_MONOTONIC",
            "timing_scope": "CLIENT_SEND_OR_RECEIVE_NOT_KERNEL_EXECUTION_BOUNDARY", "message": value})

    def send(self, value):
        raw = canonical(value)
        if len(raw) > MAX_LINE:
            raise ValueError("oversized outgoing RPC")
        self.record("CLIENT_TO_CODEX", value)
        append_record(self.directory / "client-requests.jsonl", value)
        view = memoryview(raw)
        while view:
            written = os.write(self.write_fd, view)
            view = view[written:]

    def _read(self, timeout):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.read_fd], [], [], max(0, remaining))[0]:
                raise TimeoutError("Codex JSON-RPC response timed out; no automatic retry")
            block = os.read(self.read_fd, 64 * 1024)
            if not block:
                raise EOFError("Codex app-server stdout closed")
            self.raw_stdout.write(block); self.raw_stdout.flush()
            self.buffer.extend(block)
            if len(self.buffer) > MAX_LINE and b"\n" not in self.buffer:
                raise ValueError("oversized incoming RPC")
        raw, _, rest = self.buffer.partition(b"\n"); self.buffer = bytearray(rest)
        if len(raw) > MAX_LINE:
            raise ValueError("oversized incoming RPC")
        value = strict_object(raw)
        if value.get("jsonrpc", "2.0") != "2.0":
            raise ValueError("unsupported JSON-RPC version")
        if "method" in value and (not isinstance(value["method"], str) or not value["method"]):
            raise ValueError("invalid JSON-RPC method")
        if "method" in value and "id" in value:
            key = rpc_id(value["id"])
            if key in self.request_ids:
                raise ValueError("duplicate Codex server request ID")
            self.request_ids.add(key)
        self.record("CODEX_TO_CLIENT", value)
        return value

    def request(self, method, params, timeout=60):
        request_id = self.next_id; self.next_id += 1
        self.send({"id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            value = self._read(max(.001, deadline - time.monotonic()))
            if "method" not in value and "id" in value:
                if type(value["id"]) is not int or value["id"] != request_id:
                    raise ValueError("response ID differs from pending client request")
                if "error" in value:
                    raise RuntimeError("Codex RPC failed: " + json.dumps(value["error"])[:2048])
                if "result" not in value:
                    raise ValueError("RPC response has neither result nor error")
                return value["result"]
            self.queued.append(value)
            if len(self.queued) > 8192:
                raise ValueError("too many events before RPC response")

    def receive(self, timeout):
        value = self.queued.popleft() if self.queued else self._read(timeout)
        if "method" not in value:
            raise ValueError("unsolicited JSON-RPC response")
        return value

    def respond(self, request_id, result):
        key = rpc_id(request_id)
        if key not in self.request_ids or key in self.responded:
            raise ValueError("unknown or already answered server request")
        self.responded.add(key)
        self.send({"id": request_id, "result": result})

    def close_input(self):
        if not self.closed_input:
            os.close(self.write_fd); self.closed_input = True


def validate_tool(params, thread_id, turn_id, seen, max_command_bytes=8192):
    if not isinstance(params, dict) or params.get("threadId") != thread_id or params.get("turnId") != turn_id:
        raise ValueError("dynamic tool thread/turn identity differs")
    call_id = params.get("callId")
    if not isinstance(call_id, str) or not call_id or len(call_id) > 256 or call_id in seen:
        raise ValueError("invalid or duplicate dynamic tool call ID")
    if params.get("tool") != "observer_bash" or params.get("namespace") not in (None, ""):
        raise ValueError("unregistered dynamic tool requested")
    arguments = params.get("arguments")
    if not isinstance(arguments, dict) or set(arguments) != {"command"}:
        raise ValueError("observer_bash requires only a command string")
    command = arguments["command"]
    if type(max_command_bytes) is not int or not 1 <= max_command_bytes <= 32768:
        raise ValueError("bounded command byte limit required")
    if not isinstance(command, str) or not command.strip() or "\0" in command or len(command.encode()) > max_command_bytes:
        raise ValueError("invalid or oversized observer_bash command")
    seen.add(call_id)
    return command


def run_agent(rpc, prompt, cwd, executor, directory, model="deepseek-flash", max_calls=8, timeout=300,
              base_instructions=BASE_INSTRUCTIONS, progress=None,
              binding_basis="EXPLICIT_CODEX_REQUEST_TO_OWN_STOPPED_CHILD_NOT_TIMESTAMP_MATCHING",
              tool_timing_scope="SUPERVISOR_RELEASE_THROUGH_CONFIRMED_CGROUP_EMPTY", max_command_bytes=8192):
    """Let real Codex run one turn; executor receives its actual tool requests."""
    directory = Path(directory); steps, bindings, errors, seen = [], [], [], set()
    begin = time.monotonic_ns()
    rpc.request("initialize", {"clientInfo": {"name": "observer_codex", "version": "1"},
                               "capabilities": {"experimentalApi": True}})
    rpc.send({"method": "initialized", "params": {}})
    result = rpc.request("thread/start", {"model": model, "modelProvider": "observer_proxy",
        "allowProviderModelFallback": False, "cwd": str(cwd), "approvalPolicy": "never",
        "sandbox": "danger-full-access", "ephemeral": True, "baseInstructions": base_instructions,
        "dynamicTools": [TOOL], "experimentalRawEvents": False})
    thread_id = result["thread"]["id"]
    if not isinstance(thread_id, str) or not thread_id:
        raise ValueError("thread/start did not return an ID")
    result = rpc.request("turn/start", {"threadId": thread_id, "input": [{"type": "text", "text": prompt}]})
    turn_id = result["turn"]["id"]
    if not isinstance(turn_id, str) or not turn_id:
        raise ValueError("turn/start did not return an ID")
    deadline = time.monotonic() + timeout
    status = None
    while status is None:
        message = rpc.receive(max(.001, deadline - time.monotonic()))
        method, params = message.get("method"), message.get("params", {})
        receipt = time.monotonic_ns()
        if "id" in message:
            if method != "item/tool/call":
                raise ValueError("unexpected Codex server request: " + str(method))
            command = validate_tool(params, thread_id, turn_id, seen, max_command_bytes=max_command_bytes)
            if len(seen) > max_calls:
                raise RuntimeError("dynamic tool call limit reached; no automatic retry")
            execution = executor(command, params["callId"], message["id"])
            binding = {"thread_id": thread_id, "turn_id": turn_id, "call_id": params["callId"],
                       "rpc_request_id": message["id"], "tool": "observer_bash", "command": command,
                       "client_request_received_ns": receipt, **execution["binding"],
                       "binding_basis": binding_basis}
            bindings.append(binding); append_record(directory / "function-bindings.jsonl", binding)
            steps.append({"kind": "TOOL_CALL", **binding, "exit_code": execution["exit_code"],
                          "stdout": execution["stdout"], "stderr": execution["stderr"],
                          "output_truncated": execution["output_truncated"],
                          "timing_scope": tool_timing_scope})
            if progress is not None:
                progress({"thread_id": thread_id, "turn_id": turn_id, "begin_ns": begin,
                          "steps": steps, "function_bindings": bindings, "errors": errors, "status": status})
            text = json.dumps({k: execution[k] for k in ("exit_code", "stdout", "stderr", "output_truncated")}, ensure_ascii=False)
            rpc.respond(message["id"], {"contentItems": [{"type": "inputText", "text": text}],
                                       "success": execution["exit_code"] == 0})
        elif method in ("item/started", "item/completed"):
            item = params.get("item", {})
            if params.get("threadId") != thread_id:
                raise ValueError("item thread identity differs")
            if params.get("turnId") not in (None, turn_id):
                raise ValueError("item turn identity differs")
            if item.get("type") in ("commandExecution", "fileChange", "mcpToolCall", "collabAgentToolCall", "webSearch", "imageGeneration"):
                raise RuntimeError("unexpected built-in side-effect tool; dynamic gate contract violated")
            if method == "item/completed" and item.get("type") == "agentMessage":
                steps.append({"kind": "AGENT_MESSAGE", "thread_id": thread_id, "turn_id": turn_id,
                    "item_id": item.get("id"), "text": item.get("text", ""), "receipt_ns": receipt,
                    "timing_scope": "CLIENT_RECEIVED_MESSAGE_NOT_MODEL_GENERATION_TIMESTAMP"})
        elif method == "error":
            errors.append(params)
        elif method == "turn/completed":
            turn = params.get("turn", {})
            if params.get("threadId") != thread_id or turn.get("id") != turn_id:
                raise ValueError("completed turn identity differs")
            status = turn.get("status")
            if status not in ("completed", "failed", "interrupted"):
                raise ValueError("unexpected final Codex turn status")
        if progress is not None:
            progress({"thread_id": thread_id, "turn_id": turn_id, "begin_ns": begin,
                      "steps": steps, "function_bindings": bindings, "errors": errors, "status": status})
        if time.monotonic() >= deadline and status is None:
            raise TimeoutError("Codex turn exceeded total client deadline")
    end = time.monotonic_ns()
    result = {"schema_version": 1, "mode": "REAL_CODEX_APP_SERVER_DYNAMIC_TOOLS", "model": model,
        "thread_id": thread_id, "turn_id": turn_id, "status": status, "errors": errors,
        "begin_ns": begin, "end_ns": end, "steps": steps, "function_bindings": bindings,
        "agent_loop": "OFFICIAL_CODEX_NOT_IMPLEMENTED_BY_THIS_CLIENT", "paid_request_count": None,
        "budget_authority": "EXTERNAL_SHARED_RESPONSES_BROKER_LEDGER", "gpu": "NOT_SELECTED"}
    write_new(directory / "steps.json", result)
    columns = ("kind", "thread_id", "turn_id", "call_id", "tool_call_id", "command", "exit_code",
               "begin_ns", "end_ns", "receipt_ns", "root_pid", "text", "timing_scope")
    with (directory / "steps.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader(); writer.writerows(steps); stream.flush(); os.fsync(stream.fileno())
    return result
