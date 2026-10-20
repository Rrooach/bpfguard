#!/usr/bin/env python3
"""Translate Codex app-server tool items into conservative tool evidence.

Codex owns these semantic events.  They prove that the application reported a
tool lifecycle; they do not, by themselves, prove which Linux process or
syscall implemented it.  Process-backed dynamic tools keep using the separate
stopped-launch gate and are therefore handled by ``codex_client`` directly.
"""
from __future__ import annotations

import hashlib
import json

from common import canonical


ITEM_TYPES = frozenset({
    "commandExecution", "fileChange", "mcpToolCall", "collabAgentToolCall",
    "webSearch", "imageView", "imageGeneration", "sleep",
})
STATUS_VALUES = frozenset({"inProgress", "completed", "failed", "declined", "interrupted"})


def message_sha256(message):
    return hashlib.sha256(canonical(message)).hexdigest()


def _valid_id(value):
    return isinstance(value, str) and 0 < len(value) <= 256 and "\0" not in value


def _bounded_text(value, limit=8192):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Codex tool text field must be a string")
    size = len(value.encode())
    return value if size <= limit else {"capture": "OMITTED_OVERSIZED", "size_bytes": size}


def _bounded_json(value, limit=24576):
    try:
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
            allow_nan=False).encode()
    except (TypeError, ValueError) as error:
        raise ValueError("Codex tool field is not bounded JSON") from error
    return value if len(encoded) <= limit else {
        "capture": "OMITTED_OVERSIZED", "size_bytes": len(encoded),
    }


def _changes(item):
    changes = item.get("changes")
    if not isinstance(changes, list):
        raise ValueError("Codex fileChange item needs a changes list")
    if len(changes) > 4096:
        return {"capture": "OMITTED_OVERSIZED", "change_count": len(changes)}
    rows = []
    for change in changes:
        if not isinstance(change, dict) or not isinstance(change.get("path"), str):
            raise ValueError("Codex fileChange entry lacks a path")
        rows.append({"path": _bounded_text(change["path"], 4096), "kind": change.get("kind")})
    return rows


def tool_name(item):
    kind = item.get("type")
    if kind == "mcpToolCall":
        return "mcpToolCall"
    if kind == "collabAgentToolCall":
        tool = item.get("tool")
        if not isinstance(tool, str) or not tool:
            raise ValueError("Codex collab item lacks a tool name")
        return "collabAgentToolCall." + tool
    return kind


def tool_arguments(item):
    kind = item["type"]
    if kind == "commandExecution":
        return {"command": _bounded_text(item.get("command")), "cwd": _bounded_text(item.get("cwd"), 4096),
            "source": item.get("source"), "plugin_id": item.get("pluginId"),
            "script_path": _bounded_text(item.get("scriptPath"), 4096)}
    if kind == "fileChange":
        return {"changes": _changes(item)}
    if kind == "mcpToolCall":
        if not all(isinstance(item.get(key), str) and item[key] for key in ("server", "tool")):
            raise ValueError("Codex MCP item lacks server/tool identity")
        return {"server": item["server"], "tool": item["tool"],
            "arguments": _bounded_json(item.get("arguments")), "plugin_id": item.get("pluginId"),
            "read_only_hint": item.get("readOnlyHint")}
    if kind == "collabAgentToolCall":
        receivers = item.get("receiverThreadIds")
        if not isinstance(receivers, list) or not all(_valid_id(value) for value in receivers):
            raise ValueError("Codex collab receiver identities are malformed")
        prompt = item.get("prompt")
        return {"tool": item.get("tool"), "sender_thread_id": item.get("senderThreadId"),
            "receiver_thread_ids": receivers, "model": item.get("model"),
            "reasoning_effort": item.get("reasoningEffort"),
            "prompt_capture": "CONTENT_OMITTED", "prompt_bytes": len(prompt.encode()) if isinstance(prompt, str) else 0}
    if kind == "webSearch":
        return {"query": _bounded_text(item.get("query")), "action": _bounded_json(item.get("action"))}
    if kind == "imageView":
        return {"path": _bounded_text(item.get("path"), 4096)}
    if kind == "imageGeneration":
        return {"revised_prompt": _bounded_text(item.get("revisedPrompt"))}
    if kind == "sleep":
        return {"duration_ms": item.get("durationMs")}
    raise ValueError("unsupported Codex tool item")


def execution_kind(kind):
    return {
        "commandExecution": "CODEX_RUNTIME_BUILTIN_PROCESS_UNBOUND",
        "fileChange": "CODEX_RUNTIME_BUILTIN_FILE_CHANGE_UNBOUND",
        "mcpToolCall": "CODEX_RUNTIME_MCP_REMOTE_OR_IN_PROCESS_UNBOUND",
        "collabAgentToolCall": "CODEX_RUNTIME_COLLAB_UNBOUND",
        "webSearch": "CODEX_RUNTIME_HOSTED_WEB_UNBOUND",
        "imageView": "CODEX_RUNTIME_IMAGE_VIEW_UNBOUND",
        "imageGeneration": "CODEX_RUNTIME_HOSTED_IMAGE_UNBOUND",
        "sleep": "CODEX_RUNTIME_CLOCK_SLEEP_UNBOUND",
    }[kind]


def remote_effect(kind):
    return ("REMOTE_EFFECT_NOT_CONFIRMABLE" if kind in ("mcpToolCall", "webSearch", "imageGeneration")
        else "DELEGATED_EFFECT_NOT_CAUSALLY_BOUND" if kind == "collabAgentToolCall"
        else "NOT_APPLICABLE_OR_NOT_ESTABLISHED")


def terminal_status(item):
    producer = item.get("status")
    exit_code = item.get("exitCode")
    if item.get("type") == "mcpToolCall" and isinstance(item.get("error"), dict):
        return "FAILED"
    if type(exit_code) is int:
        return "SUCCEEDED" if exit_code == 0 else "FAILED"
    normalized = producer.casefold() if isinstance(producer, str) else None
    if normalized in ("completed", "succeeded", "success") or item["type"] in ("webSearch", "imageView", "sleep"):
        return "SUCCEEDED"
    if normalized in ("failed", "error"):
        return "FAILED"
    if normalized in ("declined", "cancelled", "canceled", "interrupted"):
        return "CANCELLED"
    return "UNKNOWN"


def result_summary(item):
    kind = item["type"]
    common = {"producer_status": item.get("status"), "producer_duration_ms": item.get("durationMs")}
    if kind == "commandExecution":
        output = item.get("aggregatedOutput")
        return {**common, "exit_code": item.get("exitCode"),
            "process_id": _bounded_text(item.get("processId"), 4096),
            "aggregated_output_capture": "OMITTED",
            "aggregated_output_bytes": len(output.encode()) if isinstance(output, str) else 0}
    if kind == "fileChange":
        return {**common, "change_count": len(item.get("changes", []))}
    if kind == "mcpToolCall":
        error = item.get("error")
        return {**common, "server": item.get("server"), "tool": item.get("tool"),
            "result_present": item.get("result") is not None,
            "error": _bounded_text(error.get("message"), 4096) if isinstance(error, dict) else None}
    if kind == "collabAgentToolCall":
        return {**common, "receiver_thread_ids": item.get("receiverThreadIds"),
            "agent_states": _bounded_json(item.get("agentsStates"))}
    if kind == "imageGeneration":
        return {**common, "result_present": bool(item.get("result")),
            "saved_path": _bounded_text(item.get("savedPath"), 4096),
            "transparent_background": item.get("transparentBackground"),
            "failure": _bounded_json(item.get("failure"))}
    if kind == "webSearch":
        results = item.get("results")
        return {**common, "results_count": len(results) if isinstance(results, list) else None,
            "results_capture": "CONTENT_OMITTED"}
    if kind == "sleep":
        return {**common, "requested_duration_ms": item.get("durationMs")}
    return common


def source_event(method, params, message, receipt_ns):
    item = params["item"]
    timestamp_name = "startedAtMs" if method == "item/started" else "completedAtMs"
    timestamp = params.get(timestamp_name)
    if timestamp is not None and (type(timestamp) not in (int, float) or timestamp < 0):
        raise ValueError("Codex producer timestamp is malformed")
    return {"producer": "CODEX_APP_SERVER", "method": method, "item_id": item["id"],
        "item_type": item["type"], "message_sha256": message_sha256(message),
        "observer_receipt_ns": receipt_ns, "observer_time_basis": "CLIENT_RECEIPT_CLOCK_MONOTONIC",
        "producer_timestamp_name": timestamp_name if timestamp is not None else None,
        "producer_timestamp_ms": timestamp}


class CodexReportedToolAdapter:
    """Strict, bounded adapter for built-in app-server tool notifications."""

    def __init__(self, emit, *, thread_id, turn_id, limit=256):
        self.emit = emit
        self.thread_id, self.turn_id, self.limit = thread_id, turn_id, limit
        self.active, self.finished = {}, set()

    def handle(self, method, params, message, receipt_ns):
        item = params.get("item")
        if not isinstance(item, dict) or item.get("type") not in ITEM_TYPES:
            return None
        if params.get("threadId") != self.thread_id or params.get("turnId") != self.turn_id:
            raise ValueError("Codex tool item thread/turn identity differs")
        call_id, kind = item.get("id"), item["type"]
        if not _valid_id(call_id):
            raise ValueError("Codex tool item lacks a bounded immutable ID")
        source = source_event(method, params, message, receipt_ns)
        if method == "item/started":
            if call_id in self.active or call_id in self.finished or len(self.active) + len(self.finished) >= self.limit:
                raise ValueError("duplicate or excessive Codex tool item")
            producer_status = item.get("status")
            if (producer_status is not None and producer_status not in STATUS_VALUES
                    and kind != "imageGeneration"):
                raise ValueError("unsupported Codex tool start status")
            request = self.emit("requested", call_id=call_id, tool_name=tool_name(item),
                thread_id=self.thread_id, turn_id=self.turn_id, rpc_request_id=None,
                arguments=tool_arguments(item),
                arguments_capture="CODEX_APP_SERVER_STRUCTURED_FIELDS; COMMON_SECRET_KEYS_REDACTED; LARGE_VALUES_OMITTED",
                evidence_source="CODEX_REPORTED_TOOL_CALL", source_event=source, occurred_ns=receipt_ns)
            dispatch = self.emit("dispatched", request, execution_kind=execution_kind(kind),
                source_event=source, occurred_ns=receipt_ns)
            self.active[call_id] = (kind, tool_name(item), request, dispatch)
            return {"phase": "STARTED", "call_id": call_id}
        if method != "item/completed":
            raise ValueError("unsupported Codex tool lifecycle method")
        active = self.active.pop(call_id, None)
        if active is None or call_id in self.finished:
            raise ValueError("Codex tool completion lacks one matching start")
        started_kind, started_name, request, dispatch = active
        if kind != started_kind or tool_name(item) != started_name:
            raise ValueError("Codex tool identity changed during execution")
        producer_status = item.get("status")
        if producer_status is not None and producer_status not in STATUS_VALUES and kind != "imageGeneration":
            raise ValueError("unsupported Codex tool completion status")
        duration = item.get("durationMs")
        if duration is not None and (type(duration) not in (int, float) or duration < 0):
            raise ValueError("Codex tool duration is malformed")
        completed = self.emit("completed", request, dispatch, status=terminal_status(item),
            exit_code=item.get("exitCode") if type(item.get("exitCode")) is int else None,
            result_summary=result_summary(item), result_capture="CODEX_REPORTED_METADATA_ONLY",
            semantic_result="CODEX_REPORTED_NOT_INDEPENDENTLY_VERIFIED", source_event=source,
            producer_status=producer_status, producer_duration_ms=duration, occurred_ns=receipt_ns,
            remote_effect=remote_effect(kind))
        self.emit("delivered", request, completed,
            delivery="CODEX_ITEM_COMPLETED_RECEIVED; MODEL_CONSUMPTION_NOT_INDEPENDENTLY_OBSERVED",
            source_event=source, occurred_ns=receipt_ns)
        self.finished.add(call_id)
        return {"phase": "COMPLETED", "call_id": call_id}


def tool_step(call, receipt_ns):
    return {"kind": "APPLICATION_TOOL_CALL", "thread_id": call["thread_id"], "turn_id": call["turn_id"],
        "call_id": call["call_id"], "tool_name": call["tool_name"], "tool_status": call["status"],
        "arguments": call["arguments"], "result_summary": call["result_summary"],
        "requested_ns": call["requested_ns"], "dispatched_ns": call["dispatched_ns"],
        "result_delivered_ns": call["result_delivered_ns"],
        "request_to_result_delivery_ns": call["request_to_result_delivery_ns"],
        "producer_status": call["producer_status"], "producer_duration_ms": call["producer_duration_ms"],
        "application_evidence": call["application_evidence"], "execution_binding": call["execution_binding"],
        "linux_effect_evidence": call["linux_effect_evidence"], "remote_effect": call["remote_effect"],
        "receipt_ns": receipt_ns,
        "timing_scope": "CODEX_APP_SERVER_CLIENT_RECEIPT; NOT_A_LINUX_EXECUTION_BOUNDARY"}


def verify_codex_tool_sources(rpc_rows, event_rows):
    """Bind every Codex-sourced ledger event back to manifest-bound raw RPC."""
    from tool_events import redact_arguments

    incoming = []
    for row in rpc_rows:
        if row.get("direction") != "CODEX_TO_CLIENT" or not isinstance(row.get("message"), dict):
            continue
        message = row["message"]
        method, params = message.get("method"), message.get("params", {})
        item = params.get("item") if isinstance(params, dict) else None
        is_reported_tool = (method in ("item/started", "item/completed")
            and isinstance(item, dict) and item.get("type") in ITEM_TYPES)
        is_dynamic_tool = (method == "item/tool/call" and isinstance(params, dict)
            and params.get("tool") == "observer_bash")
        # Streaming text/token/rate-limit notifications legitimately repeat
        # byte-for-byte.  They are retained in raw RPC but are not a source for
        # the tool ledger, so their digest multiplicity is irrelevant here.
        if not (is_reported_tool or is_dynamic_tool):
            continue
        incoming.append((message_sha256(message), row, message))
    by_digest = {}
    for identity, row, message in incoming:
        if identity in by_digest:
            raise ValueError("ambiguous duplicate Codex RPC message identity")
        by_digest[identity] = (row, message)

    covered = {}
    for event in event_rows:
        source = event.get("source_event")
        if event.get("application_evidence") not in ("CODEX_REPORTED_TOOL_CALL", "CODEX_DYNAMIC_TOOL_SERVER_REQUEST"):
            continue
        if not isinstance(source, dict) or source.get("producer") != "CODEX_APP_SERVER":
            raise ValueError("Codex tool event lacks its raw app-server source")
        found = by_digest.get(source.get("message_sha256"))
        if found is None:
            raise ValueError("Codex tool source message is absent from raw RPC")
        raw, message = found
        method, params = message.get("method"), message.get("params", {})
        if method != source.get("method") or not isinstance(params, dict):
            raise ValueError("Codex tool source method differs")
        item = params.get("item") if method in ("item/started", "item/completed") else None
        source_id = item.get("id") if isinstance(item, dict) else params.get("callId")
        source_type = item.get("type") if isinstance(item, dict) else params.get("tool")
        if source_id != source.get("item_id") or source_type != source.get("item_type"):
            raise ValueError("Codex tool source identity differs")
        if event.get("call_id") != source_id:
            raise ValueError("Codex source/call identity differs")
        if event.get("thread_id") != params.get("threadId") or event.get("turn_id") != params.get("turnId"):
            raise ValueError("Codex source thread/turn differs")
        if item is not None:
            if event.get("tool_name") != tool_name(item) or event.get("rpc_request_id") is not None:
                raise ValueError("Codex reported tool name/RPC identity differs")
            timestamp_name = "startedAtMs" if method == "item/started" else "completedAtMs"
            expected_timestamp = params.get(timestamp_name)
            if (source.get("producer_timestamp_name") != (timestamp_name if expected_timestamp is not None else None)
                    or source.get("producer_timestamp_ms") != expected_timestamp):
                raise ValueError("Codex producer timestamp projection differs")
            if event["event"] == "TOOL_REQUESTED":
                expected_arguments, _ = redact_arguments(tool_arguments(item))
                if (event.get("arguments") != expected_arguments
                        or event.get("application_evidence") != "CODEX_REPORTED_TOOL_CALL"):
                    raise ValueError("Codex reported tool arguments differ from raw RPC")
            elif event["event"] == "TOOL_COMPLETED":
                expected_result, _ = redact_arguments(result_summary(item), max_bytes=8192)
                if (event.get("status") != terminal_status(item)
                        or event.get("result_summary") != expected_result
                        or event.get("producer_status") != item.get("status")
                        or event.get("producer_duration_ms") != item.get("durationMs")):
                    raise ValueError("Codex reported tool result differs from raw RPC")
        else:
            if (event.get("tool_name") != params.get("tool")
                    or event.get("rpc_request_id") != message.get("id")
                    or event.get("application_evidence") != "CODEX_DYNAMIC_TOOL_SERVER_REQUEST"):
                raise ValueError("Codex dynamic tool request identity differs")
            if event["event"] == "TOOL_REQUESTED":
                expected_arguments, _ = redact_arguments(params.get("arguments"))
                if event.get("arguments") != expected_arguments:
                    raise ValueError("Codex dynamic tool arguments differ from raw RPC")
        source_receipt = source.get("observer_receipt_ns")
        if type(source_receipt) is not int or source_receipt > event.get("occurred_ns", -1):
            raise ValueError("Codex tool event predates its source receipt")
        raw_receipt = raw.get("receipt_ns")
        if type(raw_receipt) is not int or raw_receipt > source_receipt:
            raise ValueError("Codex tool ledger predates raw RPC receipt")
        covered.setdefault(source["message_sha256"], []).append(event["event"])

    expected = {}
    for identity, _, message in incoming:
        method, params = message.get("method"), message.get("params", {})
        if method in ("item/started", "item/completed") and isinstance(params, dict):
            item = params.get("item")
            if isinstance(item, dict) and item.get("type") in ITEM_TYPES:
                expected[identity] = (["TOOL_REQUESTED", "TOOL_DISPATCHED"] if method == "item/started"
                                      else ["TOOL_COMPLETED", "TOOL_RESULT_DELIVERED"])
        elif method == "item/tool/call" and isinstance(params, dict) and params.get("tool") == "observer_bash":
            expected[identity] = ["TOOL_REQUESTED", "TOOL_DISPATCHED", "TOOL_COMPLETED", "TOOL_RESULT_DELIVERED"]
    if set(covered) != set(expected):
        raise ValueError("raw Codex tool messages and lifecycle ledger differ")
    for identity, events in expected.items():
        if covered[identity] != events:
            raise ValueError("Codex source message has an invalid lifecycle projection")
    return {"status": "RAW_RPC_TOOL_EVENTS_REPLAYED", "source_messages": len(expected),
        "lifecycle_events": sum(len(value) for value in covered.values()),
        "scope": "CODEX_APPLICATION_REPORTS_AND_DYNAMIC_REQUESTS; LINUX_BINDING_VERIFIED_SEPARATELY"}
