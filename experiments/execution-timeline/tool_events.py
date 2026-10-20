#!/usr/bin/env python3
"""Application-level tool-call evidence shared by Agent adapters.

This module deliberately records semantic tool lifecycle events instead of
trying to infer a tool call from syscalls.  A process-backed adapter may attach
an explicit Linux execution binding; an in-process or remote tool may leave
that binding absent without inventing a PID/cgroup relationship.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time

from common import canonical, write_new

SCHEMA_VERSION = 1
EVENTS = ("TOOL_REQUESTED", "TOOL_DISPATCHED", "TOOL_COMPLETED", "TOOL_RESULT_DELIVERED")
TERMINAL_STATUSES = ("SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED", "TRANSPORT_ERROR", "UNKNOWN")
SECRET_FIELDS = frozenset({
    "access_token", "api_key", "apikey", "authorization", "client_secret", "cookie",
    "credential", "password", "private_key", "proxy-authorization", "refresh_token",
    "secret", "set-cookie", "token", "x-api-key",
})


def _append(path, value):
    with Path(path).open("ab") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode()


def _valid_id(value):
    return isinstance(value, str) and 0 < len(value) <= 256 and "\0" not in value


def redact_arguments(value, *, secret_fields=SECRET_FIELDS, max_bytes=32768):
    """Return bounded structured arguments with common secret fields removed.

    Free-form strings cannot be reliably secret-scanned.  Adapters exposing a
    shell command must therefore declare that capture limitation explicitly.
    """
    def walk(item, depth=0):
        if depth > 16:
            raise ValueError("tool arguments exceed nesting limit")
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                if not isinstance(key, str) or not key or len(key) > 256:
                    raise ValueError("tool argument keys must be bounded strings")
                result[key] = "[REDACTED]" if key.casefold() in secret_fields else walk(child, depth + 1)
            return result
        if isinstance(item, list):
            if len(item) > 1024:
                raise ValueError("tool argument list exceeds limit")
            return [walk(child, depth + 1) for child in item]
        if item is None or isinstance(item, (str, int, float, bool)):
            return item
        raise ValueError("tool arguments must be JSON values")

    if len(_json_bytes(value)) > max_bytes:
        raise ValueError("tool arguments exceed byte limit")
    redacted = walk(value)
    encoded = _json_bytes(redacted)
    if len(encoded) > max_bytes:
        raise ValueError("redacted tool arguments exceed byte limit")
    # Bind only the post-policy value.  Hashing a removed low-entropy secret
    # would itself create an offline guessing oracle in the evidence bundle.
    return redacted, hashlib.sha256(encoded).hexdigest()


def execution_status(exit_code, gate_result=None, failure=None):
    """Classify transport/execution state without claiming semantic success."""
    if failure is not None:
        if isinstance(failure, TimeoutError):
            return "TIMED_OUT"
        # asyncio.CancelledError derives from BaseException on supported Python.
        if type(failure).__name__ == "CancelledError":
            return "CANCELLED"
        return "TRANSPORT_ERROR"
    if isinstance(gate_result, dict) and isinstance(gate_result.get("error"), str):
        return "TIMED_OUT" if gate_result["error"].startswith("TimeoutError:") else "TRANSPORT_ERROR"
    if type(exit_code) is not int:
        return "UNKNOWN"
    return "SUCCEEDED" if exit_code == 0 else "FAILED"


class ToolEventLedger:
    """Append-only lifecycle journal plus strict deterministic replay."""

    def __init__(self, path, *, agent_id, task_id, create=True):
        if not _valid_id(agent_id) or not _valid_id(task_id):
            raise ValueError("bounded agent_id and task_id are required")
        self.path = Path(path)
        self.agent_id, self.task_id = agent_id, task_id
        self.sequence = 0
        if create:
            write_new(self.path, b"")

    def _record(self, event, call_id, tool_name, occurred_ns, **fields):
        if event not in EVENTS or not _valid_id(call_id) or not _valid_id(tool_name):
            raise ValueError("invalid tool event identity")
        if type(occurred_ns) is not int or occurred_ns < 0:
            raise ValueError("tool event needs CLOCK_MONOTONIC nanoseconds")
        self.sequence += 1
        row = {**fields, "schema_version": SCHEMA_VERSION, "sequence": self.sequence, "event": event,
               "clock": "CLOCK_MONOTONIC", "occurred_ns": occurred_ns,
               "recorded_ns": time.monotonic_ns(), "agent_id": self.agent_id,
               "task_id": self.task_id, "call_id": call_id, "tool_name": tool_name}
        _append(self.path, row)
        return row

    def requested(self, *, call_id, tool_name, thread_id, turn_id, rpc_request_id,
                  arguments, arguments_capture, evidence_source="APPLICATION_EXPLICIT_TOOL_CALL",
                  source_event=None, occurred_ns=None):
        sanitized, arguments_sha256 = redact_arguments(arguments)
        return self._record("TOOL_REQUESTED", call_id, tool_name,
            time.monotonic_ns() if occurred_ns is None else occurred_ns,
            thread_id=thread_id, turn_id=turn_id, rpc_request_id=rpc_request_id,
            status="REQUESTED", arguments=sanitized, arguments_sha256=arguments_sha256,
            arguments_capture=arguments_capture,
            application_evidence=evidence_source, source_event=source_event,
            attribution="APPLICATION_EXPLICIT_CALL_ID_NOT_TIMESTAMP_INFERENCE")

    def dispatched(self, request, *, execution_kind, source_event=None, occurred_ns=None):
        return self._record("TOOL_DISPATCHED", request["call_id"], request["tool_name"],
            time.monotonic_ns() if occurred_ns is None else occurred_ns,
            thread_id=request["thread_id"], turn_id=request["turn_id"],
            rpc_request_id=request["rpc_request_id"], status="RUNNING",
            execution_kind=execution_kind,
            application_evidence=request["application_evidence"],
            source_event=source_event if source_event is not None else request.get("source_event"),
            execution_binding="PENDING_OR_NOT_APPLICABLE")

    def completed(self, request, dispatch, *, status, exit_code=None, binding=None,
                  output_truncated=None, failure=None, result_summary=None,
                  result_capture="SUMMARY_REDACTED_OR_NOT_PROVIDED",
                  semantic_result="NOT_VERIFIED_BY_TOOL_TRANSPORT", source_event=None,
                  producer_status=None, producer_duration_ms=None, occurred_ns=None,
                  remote_effect="NOT_APPLICABLE_OR_NOT_ESTABLISHED"):
        if status not in TERMINAL_STATUSES:
            raise ValueError("unsupported terminal tool status")
        binding = dict(binding or {})
        sanitized_result, result_sha256 = (redact_arguments(result_summary, max_bytes=8192)
            if result_summary is not None else (None, None))
        begin, end = binding.get("begin_ns"), binding.get("end_ns")
        observed = time.monotonic_ns() if occurred_ns is None else occurred_ns
        ordered = (type(begin) is int and type(end) is int
                   and dispatch["occurred_ns"] <= begin <= end <= observed)
        execution_id = binding.get("tool_call_id")
        explicitly_bound = (ordered and _valid_id(execution_id)
            and isinstance(binding.get("root"), dict) and type(binding.get("cgroup_id")) is int)
        fields = {
            "thread_id": request["thread_id"], "turn_id": request["turn_id"],
            "rpc_request_id": request["rpc_request_id"], "status": status,
            "exit_code": exit_code if type(exit_code) is int else None,
            "output_truncated": output_truncated if type(output_truncated) is bool else None,
            "semantic_result": semantic_result,
            "result_summary": sanitized_result,
            "result_summary_sha256": result_sha256,
            "result_capture": result_capture,
            "execution_kind": dispatch["execution_kind"],
            "application_evidence": request["application_evidence"],
            "source_event": source_event,
            "producer_status": producer_status if isinstance(producer_status, str) else None,
            "producer_duration_ms": producer_duration_ms
                if type(producer_duration_ms) in (int, float) and producer_duration_ms >= 0 else None,
            "execution_tool_call_id": execution_id if _valid_id(execution_id) else None,
            "execution_begin_ns": begin if ordered else None,
            "execution_end_ns": end if ordered else None,
            "execution_duration_ns": end - begin if ordered else None,
            "timing_quality": "EXPLICIT_EXECUTION_BOUNDARIES" if ordered else "APPLICATION_DISPATCH_ONLY",
            "execution_binding": "TOOL_GATE_EXECUTION_BOUND" if explicitly_bound else "NOT_ESTABLISHED",
            "linux_effect_evidence": ("BOUND_EVIDENCE_REQUIRES_NATIVE_REPLAY" if explicitly_bound
                                      else "NOT_BOUND_TO_LINUX_EXECUTION"),
            "remote_effect": remote_effect,
            "root": binding.get("root") if isinstance(binding.get("root"), dict) else None,
            "cgroup_id": binding.get("cgroup_id") if type(binding.get("cgroup_id")) is int else None,
            "stdout_artifact": binding.get("stdout_artifact") if isinstance(binding.get("stdout_artifact"), str) else None,
            "stderr_artifact": binding.get("stderr_artifact") if isinstance(binding.get("stderr_artifact"), str) else None,
            "failure_type": type(failure).__name__ if failure is not None else None,
            "failure_summary": str(failure)[:1024] if failure is not None else None,
        }
        return self._record("TOOL_COMPLETED", request["call_id"], request["tool_name"], observed, **fields)

    def delivered(self, request, completed, *, delivery="JSON_RPC_RESPONSE_WRITTEN_TO_CODEX",
                  source_event=None, occurred_ns=None):
        return self._record("TOOL_RESULT_DELIVERED", request["call_id"], request["tool_name"],
            time.monotonic_ns() if occurred_ns is None else occurred_ns,
            thread_id=request["thread_id"], turn_id=request["turn_id"],
            rpc_request_id=request["rpc_request_id"], status=completed["status"],
            execution_tool_call_id=completed.get("execution_tool_call_id"),
            application_evidence=request["application_evidence"], source_event=source_event,
            delivery=delivery)


def read_events(path):
    raw = Path(path).read_bytes()
    if raw and not raw.endswith(b"\n"):
        raise ValueError("truncated tool event journal")
    rows = []
    for line in raw.splitlines():
        def pairs(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise ValueError("duplicate tool event field")
                value[key] = item
            return value
        value = json.loads(line, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite tool event")))
        if not isinstance(value, dict):
            raise ValueError("tool event must be an object")
        rows.append(value)
    return rows


def replay_tool_events(rows, *, require_delivered=True):
    """Validate transitions and return one human-facing summary per call."""
    states, sequence = {}, 0
    transitions = {None: "TOOL_REQUESTED", "TOOL_REQUESTED": "TOOL_DISPATCHED",
                   "TOOL_DISPATCHED": "TOOL_COMPLETED", "TOOL_COMPLETED": "TOOL_RESULT_DELIVERED"}
    for row in rows:
        sequence += 1
        if row.get("schema_version") != SCHEMA_VERSION or row.get("sequence") != sequence:
            raise ValueError("tool event schema or sequence differs")
        event, call_id = row.get("event"), row.get("call_id")
        if (event not in EVENTS or not _valid_id(call_id) or not _valid_id(row.get("tool_name"))
                or not _valid_id(row.get("agent_id")) or not _valid_id(row.get("task_id"))):
            raise ValueError("invalid tool event")
        if (row.get("clock") != "CLOCK_MONOTONIC" or type(row.get("occurred_ns")) is not int
                or type(row.get("recorded_ns")) is not int or row["recorded_ns"] < row["occurred_ns"]):
            raise ValueError("invalid tool event clock")
        state = states.setdefault(call_id, {"rows": [], "last": None})
        if transitions[state["last"]] != event:
            raise ValueError("invalid tool event transition for " + call_id)
        if state["rows"] and any(row.get(key) != state["rows"][0].get(key)
                                 for key in ("agent_id", "task_id", "call_id", "tool_name",
                                             "thread_id", "turn_id", "rpc_request_id")):
            raise ValueError("tool event identity changed")
        if state["rows"] and row.get("application_evidence", "APPLICATION_EXPLICIT_TOOL_CALL") \
                != state["rows"][0].get("application_evidence", "APPLICATION_EXPLICIT_TOOL_CALL"):
            raise ValueError("tool application evidence source changed")
        if state["rows"] and row["occurred_ns"] < state["rows"][-1]["occurred_ns"]:
            raise ValueError("tool event time moved backwards")
        state["rows"].append(row)
        state["last"] = event
    calls = []
    for call_id, state in states.items():
        if require_delivered and state["last"] != "TOOL_RESULT_DELIVERED":
            raise ValueError("tool call lacks delivered terminal result: " + call_id)
        requested = state["rows"][0]
        dispatched = state["rows"][1] if len(state["rows"]) > 1 else None
        completed = state["rows"][2] if len(state["rows"]) > 2 else None
        delivered = state["rows"][3] if len(state["rows"]) > 3 else None
        if requested.get("status") != "REQUESTED" or dispatched and dispatched.get("status") != "RUNNING":
            raise ValueError("invalid nonterminal tool status")
        if (not isinstance(requested.get("arguments_capture"), str)
                or hashlib.sha256(_json_bytes(requested.get("arguments"))).hexdigest()
                != requested.get("arguments_sha256")):
            raise ValueError("tool arguments digest or policy missing")
        if not isinstance(requested.get("application_evidence", "APPLICATION_EXPLICIT_TOOL_CALL"), str):
            raise ValueError("tool application evidence source missing")
        if completed:
            if completed.get("status") not in TERMINAL_STATUSES:
                raise ValueError("invalid terminal tool status")
            begin, end, duration = (completed.get("execution_begin_ns"), completed.get("execution_end_ns"),
                                    completed.get("execution_duration_ns"))
            if completed.get("timing_quality") == "EXPLICIT_EXECUTION_BOUNDARIES":
                if not (type(begin) is int and type(end) is int and type(duration) is int
                        and dispatched["occurred_ns"] <= begin <= end <= completed["occurred_ns"]
                        and duration == end - begin):
                    raise ValueError("invalid explicit tool execution boundaries")
            elif any(value is not None for value in (begin, end, duration)):
                raise ValueError("partial timing cannot claim execution boundaries")
            explicitly_bound = (completed.get("timing_quality") == "EXPLICIT_EXECUTION_BOUNDARIES"
                and _valid_id(completed.get("execution_tool_call_id"))
                and isinstance(completed.get("root"), dict) and type(completed.get("cgroup_id")) is int)
            derived_binding = "TOOL_GATE_EXECUTION_BOUND" if explicitly_bound else "NOT_ESTABLISHED"
            derived_linux = ("BOUND_EVIDENCE_REQUIRES_NATIVE_REPLAY" if explicitly_bound
                             else "NOT_BOUND_TO_LINUX_EXECUTION")
            if completed.get("execution_binding", derived_binding) != derived_binding:
                raise ValueError("tool execution binding contradicts its evidence")
            if completed.get("linux_effect_evidence", derived_linux) != derived_linux:
                raise ValueError("tool Linux evidence label contradicts its binding")
            producer_duration = completed.get("producer_duration_ms")
            if producer_duration is not None and (type(producer_duration) not in (int, float)
                    or producer_duration < 0):
                raise ValueError("invalid producer-reported tool duration")
            exit_code = completed.get("exit_code")
            if ((completed.get("status") == "SUCCEEDED" and exit_code not in (0, None))
                    or (completed.get("status") == "FAILED" and type(exit_code) is int and exit_code == 0)):
                raise ValueError("tool terminal status contradicts exit code")
            result_summary = completed.get("result_summary")
            if result_summary is not None and hashlib.sha256(_json_bytes(result_summary)).hexdigest() != completed.get("result_summary_sha256"):
                raise ValueError("tool result summary digest differs")
        if delivered and (not completed or delivered.get("status") != completed.get("status")
                or delivered.get("execution_tool_call_id") != completed.get("execution_tool_call_id")
                or (delivered.get("delivery") is not None and not isinstance(delivered.get("delivery"), str))):
            raise ValueError("delivered tool result differs from completion")
        summary = {key: requested.get(key) for key in ("agent_id", "task_id", "thread_id", "turn_id",
                                                       "rpc_request_id", "call_id", "tool_name",
                                                       "arguments", "arguments_sha256", "arguments_capture",
                                                       "attribution")}
        summary["application_evidence"] = requested.get("application_evidence", "APPLICATION_EXPLICIT_TOOL_CALL")
        summary["request_source_event"] = requested.get("source_event")
        summary.update(status=completed.get("status") if completed else dispatched.get("status") if dispatched else "REQUESTED",
            requested_ns=requested["occurred_ns"], dispatched_ns=dispatched.get("occurred_ns") if dispatched else None,
            completed_ns=completed.get("occurred_ns") if completed else None,
            result_delivered_ns=delivered.get("occurred_ns") if delivered else None,
            execution_tool_call_id=completed.get("execution_tool_call_id") if completed else None,
            execution_begin_ns=completed.get("execution_begin_ns") if completed else None,
            execution_end_ns=completed.get("execution_end_ns") if completed else None,
            execution_duration_ns=completed.get("execution_duration_ns") if completed else None,
            exit_code=completed.get("exit_code") if completed else None,
            output_truncated=completed.get("output_truncated") if completed else None,
            semantic_result=completed.get("semantic_result") if completed else None,
            timing_quality=completed.get("timing_quality") if completed else None,
            execution_binding=(completed.get("execution_binding", "TOOL_GATE_EXECUTION_BOUND"
                if completed.get("timing_quality") == "EXPLICIT_EXECUTION_BOUNDARIES"
                    and _valid_id(completed.get("execution_tool_call_id"))
                    and isinstance(completed.get("root"), dict) and type(completed.get("cgroup_id")) is int
                else "NOT_ESTABLISHED") if completed else None),
            linux_effect_evidence=(completed.get("linux_effect_evidence", "BOUND_EVIDENCE_REQUIRES_NATIVE_REPLAY"
                if completed.get("timing_quality") == "EXPLICIT_EXECUTION_BOUNDARIES"
                    and _valid_id(completed.get("execution_tool_call_id"))
                    and isinstance(completed.get("root"), dict) and type(completed.get("cgroup_id")) is int
                else "NOT_BOUND_TO_LINUX_EXECUTION") if completed else None),
            remote_effect=completed.get("remote_effect") if completed else None,
            execution_kind=completed.get("execution_kind") if completed else dispatched.get("execution_kind") if dispatched else None,
            producer_status=completed.get("producer_status") if completed else None,
            producer_duration_ms=completed.get("producer_duration_ms") if completed else None,
            completion_source_event=completed.get("source_event") if completed else None,
            root=completed.get("root") if completed else None,
            cgroup_id=completed.get("cgroup_id") if completed else None,
            stdout_artifact=completed.get("stdout_artifact") if completed else None,
            stderr_artifact=completed.get("stderr_artifact") if completed else None,
            result_summary=completed.get("result_summary") if completed else None,
            result_summary_sha256=completed.get("result_summary_sha256") if completed else None,
            result_capture=completed.get("result_capture") if completed else None,
            failure_type=completed.get("failure_type") if completed else None,
            failure_summary=completed.get("failure_summary") if completed else None,
            delivery=delivered.get("delivery") if delivered else None,
            delivery_source_event=delivered.get("source_event") if delivered else None)
        summary["request_to_execution_ns"] = (summary["execution_begin_ns"] - summary["requested_ns"]
            if type(summary["execution_begin_ns"]) is int and summary["execution_begin_ns"] >= summary["requested_ns"] else None)
        summary["request_to_result_delivery_ns"] = (summary["result_delivered_ns"] - summary["requested_ns"]
            if type(summary["result_delivered_ns"]) is int else None)
        calls.append(summary)
    return calls
