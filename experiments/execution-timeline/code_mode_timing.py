#!/usr/bin/env python3
"""Replay explicit Code Mode dispatcher timing, without inferring V8 from gaps.

``observer-code-mode.mjs`` is a cooperative Node/V8 adapter. Its wall-clock
boundaries, synchronous JS dispatch slices, and awaited tool requests are
different measurements. In particular, time without an outstanding tool is
not JS CPU time, and overlapping tool waits are unioned instead of summed.
App-server item receipt timing is supported separately and never upgraded to
runtime execution evidence.
"""
from __future__ import annotations

import json
import math
from pathlib import Path


SCHEMA = "CODE_MODE_DISPATCH_TIMING_V1"
IDENTITY_KEYS = ("run_id", "agent_id", "task_id", "call_id", "runtime_id", "pid", "boot_id")
MEMORY_KEYS = ("rss_bytes", "heap_used_bytes", "heap_total_bytes", "external_bytes",
               "array_buffers_bytes", "v8_used_heap_bytes", "v8_total_heap_bytes", "v8_heap_limit_bytes")


def _id(value):
    return isinstance(value, str) and 0 < len(value) <= 256 and "\0" not in value


def _ns(value):
    # Node serializes hrtime BigInts as decimal strings so machines with more
    # than 104 days uptime do not lose nanoseconds to Number's 53-bit limit.
    if isinstance(value, str) and value.isascii() and value.isdigit() and (value == "0" or not value.startswith("0")):
        value = int(value)
    if type(value) is not int or value < 0:
        raise ValueError("Code Mode timestamp must be a nonnegative integer")
    return value


def _memory(value):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("Code Mode memory sample must be an object")
    for key in MEMORY_KEYS:
        if key in value and (type(value[key]) is not int or value[key] < 0):
            raise ValueError("Code Mode memory counter is malformed")
    return {key: value[key] for key in MEMORY_KEYS if key in value}


def _union_ns(intervals):
    if not intervals:
        return 0
    total = 0
    left, right = sorted(intervals)[0]
    for begin, end in sorted(intervals)[1:]:
        if begin > right:
            total += right - left
            left, right = begin, end
        else:
            right = max(right, end)
    return total + right - left


def load_code_mode_events(path):
    """Read the adapter's bounded JSONL without accepting non-finite numbers."""
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 ** 2:
        raise ValueError("bounded regular Code Mode ledger required")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate Code Mode JSON key")
            result[key] = value
        return result
    rows = []
    with path.open("rb") as stream:
        for raw in stream:
            if len(raw) > 256 * 1024 or not raw.endswith(b"\n"):
                raise ValueError("oversized or truncated Code Mode event")
            row = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("nonfinite Code Mode event")))
            if not isinstance(row, dict):
                raise ValueError("Code Mode event must be an object")
            rows.append(row)
    return rows


def replay_code_mode_events(rows, *, require_complete=True):
    """Validate explicit identities and reconstruct invocation/slice measures.

    The ledger is ordered per file. Runtime identity includes a fresh adapter
    instance UUID, so PID reuse cannot merge two V8 lifetimes. Memory values
    are boundary samples of the containing Node process, not isolate-private
    allocations, allocation totals, lifetime peaks, or Observer overhead.
    """
    calls, order, previous, runtimes, seq = {}, [], {}, {}, 0
    for event in rows:
        if event.get("schema") != SCHEMA or event.get("clock") != "NODE_HRTIME_MONOTONIC":
            raise ValueError("unsupported Code Mode event schema or clock")
        seq += 1
        if type(event.get("sequence")) is not int or event["sequence"] != seq:
            raise ValueError("Code Mode ledger sequence is discontinuous")
        if any(not _id(event.get(key)) for key in IDENTITY_KEYS if key != "pid"):
            raise ValueError("Code Mode event lacks explicit identities")
        if type(event.get("pid")) is not int or event["pid"] <= 0:
            raise ValueError("Code Mode runtime PID is malformed")
        timestamp = _ns(event.get("occurred_ns"))
        runtime = event["runtime_id"]
        runtime_identity = event["pid"], event["boot_id"]
        if runtime in runtimes and runtimes[runtime] != runtime_identity:
            raise ValueError("Code Mode runtime identity changed")
        runtimes[runtime] = runtime_identity
        if timestamp < previous.get(runtime, 0):
            raise ValueError("Code Mode monotonic counter regressed")
        previous[runtime] = timestamp
        key = event["run_id"], event["call_id"]
        kind = event.get("event")
        if kind == "CODE_MODE_STARTED":
            if key in calls:
                raise ValueError("duplicate Code Mode invocation")
            calls[key] = {**{name: event[name] for name in IDENTITY_KEYS},
                "start_ns": timestamp, "end_ns": None, "status": "INCOMPLETE",
                "runtime": event.get("runtime"), "memory_samples": [],
                "js_slices": [], "tool_waits": [], "active_js": {}, "active_waits": {}, "seen_spans": set()}
            order.append(key)
        call = calls.get(key)
        if call is None or any(event[name] != call[name] for name in IDENTITY_KEYS):
            raise ValueError("Code Mode event identity differs from invocation")
        if call["end_ns"] is not None:
            raise ValueError("Code Mode event followed completion")
        memory = _memory(event.get("memory"))
        if memory is not None:
            call["memory_samples"].append({"at_ns": timestamp, "event": kind, **memory})
        if kind in ("JS_STARTED", "TOOL_WAIT_STARTED"):
            span_id = event.get("span_id")
            if not _id(span_id) or not _id(event.get("name")):
                raise ValueError("Code Mode slice lacks explicit span identity")
            active = call["active_js"] if kind == "JS_STARTED" else call["active_waits"]
            done = call["js_slices"] if kind == "JS_STARTED" else call["tool_waits"]
            if span_id in call["seen_spans"]:
                raise ValueError("duplicate Code Mode slice")
            call["seen_spans"].add(span_id)
            if kind == "JS_STARTED" and active:
                raise ValueError("nested JS dispatch slices would double-count execution")
            child_id = event.get("child_call_id")
            if child_id is not None and not _id(child_id):
                raise ValueError("Code Mode child call ID is malformed")
            active[span_id] = {"span_id": span_id, "name": event["name"], "start_ns": timestamp,
                               "child_call_id": child_id, "purpose": event.get("purpose")}
        elif kind in ("JS_COMPLETED", "TOOL_WAIT_COMPLETED"):
            active = call["active_js"] if kind == "JS_COMPLETED" else call["active_waits"]
            done = call["js_slices"] if kind == "JS_COMPLETED" else call["tool_waits"]
            started = active.pop(event.get("span_id"), None)
            if (started is None or event.get("name") != started["name"]
                    or event.get("child_call_id") != started["child_call_id"]
                    or event.get("purpose") != started["purpose"]):
                raise ValueError("Code Mode slice completion has no matching start")
            if event.get("status") not in ("SUCCEEDED", "FAILED"):
                raise ValueError("Code Mode slice completion status is malformed")
            cpu = event.get("thread_cpu_usec")
            if cpu is not None and (type(cpu) is not int or cpu < 0):
                raise ValueError("Code Mode CPU delta is malformed")
            begin, end = started["start_ns"], timestamp
            basis = "EVENT_LIFECYCLE_ENVELOPE"
            if kind == "JS_COMPLETED" and ("dispatch_begin_ns" in event or "dispatch_end_ns" in event):
                begin, end = _ns(event.get("dispatch_begin_ns")), _ns(event.get("dispatch_end_ns"))
                if not started["start_ns"] <= begin <= end <= timestamp:
                    raise ValueError("JS measured body lies outside its lifecycle")
                basis = "SYNCHRONOUS_BODY_EXCLUDING_LEDGER_AND_MEMORY_CAPTURE"
            done.append({**started, "start_ns": begin, "end_ns": end, "duration_ns": end - begin,
                         "lifecycle_start_ns": started["start_ns"], "lifecycle_end_ns": timestamp,
                         "timing_basis": basis, "status": event.get("status"), "thread_cpu_usec": cpu})
        elif kind == "CODE_MODE_COMPLETED":
            if call["active_js"] or call["active_waits"]:
                raise ValueError("Code Mode completed with unfinished JS/tool slices")
            if event.get("status") not in ("SUCCEEDED", "FAILED"):
                raise ValueError("Code Mode completion status is malformed")
            call.update(end_ns=timestamp, status=event["status"])
        elif kind != "CODE_MODE_STARTED":
            raise ValueError("unknown Code Mode event")
    result = []
    for key in order:
        call = calls[key]
        if require_complete and call["end_ns"] is None:
            raise ValueError("Code Mode invocation lacks completion")
        call.pop("active_js"); call.pop("active_waits"); call.pop("seen_spans")
        complete = call["end_ns"] is not None
        wall = call["end_ns"] - call["start_ns"] if complete else None
        waits = _union_ns([(x["start_ns"], x["end_ns"]) for x in call["tool_waits"]])
        js = _union_ns([(x["start_ns"], x["end_ns"]) for x in call["js_slices"]])
        call.update(wall_ns=wall, tool_wait_union_ns=waits,
            tool_wait_sum_ns=sum(x["duration_ns"] for x in call["tool_waits"]),
            no_tool_outstanding_wall_ns=wall - waits if complete else None,
            instrumented_js_dispatch_wall_ns=js if call["js_slices"] else None,
            instrumented_js_thread_cpu_usec=(sum(x["thread_cpu_usec"] for x in call["js_slices"])
                if call["js_slices"] and all(x["thread_cpu_usec"] is not None for x in call["js_slices"]) else None),
            js_coverage="EXPLICIT_SYNCHRONOUS_RUN_JS_SLICES_ONLY; ASYNC_CONTINUATIONS_OUTSIDE_WRAPPER_UNMEASURED",
            js_execution_status="MEASURED_SLICES" if call["js_slices"] else "NOT_COLLECTED",
            tool_wait_coverage="EXPLICIT_AWAIT_TOOL_WRAPPERS_ONLY; UNWRAPPED_IO_NOT_MEASURED",
            timing_scope="COOPERATIVE_NODE_V8_DISPATCHER; TOOL_WAIT_UNION_IS_NOT_JS_CPU",
            memory_scope="BOUNDARY_SAMPLES_OF_NODE_PROCESS; MAY_BE_SHARED; NOT_ALLOCATION_TOTAL_OR_OBSERVER_OVERHEAD")
        samples = call["memory_samples"]
        call["memory"] = {name: {"start": samples[0].get(name), "end": samples[-1].get(name),
                "max_observed": max(sample[name] for sample in samples if name in sample)}
            for name in MEMORY_KEYS if samples and any(name in sample for sample in samples)}
        result.append(call)
    return {"schema": SCHEMA, "status": "COMPLETE" if result and all(x["end_ns"] is not None for x in result)
            else "INCOMPLETE" if result else "NOT_COLLECTED", "invocations": result}


def replay_runtime_events(rows, *, require_complete=True):
    """Return presentation fields plus a non-overlapping measured partition.

    JS has precedence when its explicit dispatch slice overlaps an outstanding
    parallel tool. AWAIT means a tool was outstanding outside those JS slices;
    OTHER is uninstrumented dispatcher work/continuations. This avoids treating
    either OTHER or the wall-minus-wait remainder as JS execution.
    """
    result = replay_code_mode_events(rows, require_complete=require_complete)
    for call in result["invocations"]:
        call["segments"] = []
        if call["end_ns"] is None:
            continue
        boundaries = {call["start_ns"], call["end_ns"]}
        for item in call["js_slices"] + call["tool_waits"]:
            boundaries.update((item["start_ns"], item["end_ns"]))
        boundaries = sorted(boundaries)
        for begin, end in zip(boundaries, boundaries[1:]):
            if begin == end:
                continue
            js = [x for x in call["js_slices"] if x["start_ns"] <= begin < x["end_ns"]]
            waits = [x for x in call["tool_waits"] if x["start_ns"] <= begin < x["end_ns"]]
            kind = "JS" if js else "AWAIT" if waits else "OTHER"
            call["segments"].append({"kind": kind, "begin_ns": begin, "end_ns": end,
                "name": js[0]["name"] if js else " / ".join(x["name"] for x in waits) if waits else "Uninstrumented dispatcher interval",
                "span_ids": [x["span_id"] for x in js or waits],
                "child_call_ids": [x["child_call_id"] for x in waits if x["child_call_id"] is not None]})
        totals = {kind: sum(x["end_ns"] - x["begin_ns"] for x in call["segments"] if x["kind"] == kind)
                  for kind in ("JS", "AWAIT", "OTHER")}
        call.update(begin_ns=call["start_ns"], wall_ms=call["wall_ns"] / 1e6,
                    js_ms=totals["JS"] / 1e6 if call["js_slices"] else None,
                    tool_wait_ms=totals["AWAIT"] / 1e6,
                    other_ms=totals["OTHER"] / 1e6,
                    outstanding_tool_ms=call["tool_wait_union_ns"] / 1e6,
                    thread_cpu_ms=(call["instrumented_js_thread_cpu_usec"] / 1000
                                   if call["instrumented_js_thread_cpu_usec"] is not None else None),
                    partition_scope="JS_EXPLICIT_SLICES; AWAIT_TOOL_OUTSTANDING_OUTSIDE_JS; OTHER_UNMEASURED")
    return result


def app_server_code_mode_timing(records, *, selectors=(), enabled=None):
    """Pair item lifecycle notifications only under explicit item selectors.

    A selector is ``(item_type, namespace_or_None, tool_name_or_None)``. The
    installed app-server schema has no dedicated codeMode item, so the caller
    must identify a known gateway's tool rather than classify all commands or
    inter-model gaps as V8. This returns receipt intervals and no JS self time.
    """
    selectors = set(tuple(item) for item in selectors)
    active, finished, intervals = {}, set(), []
    for record in records:
        if record.get("direction") != "CODEX_TO_CLIENT":
            continue
        message = record.get("message", {})
        method, params = message.get("method"), message.get("params", {})
        if method not in ("item/started", "item/completed") or not isinstance(params, dict):
            continue
        item = params.get("item", {})
        if not isinstance(item, dict) or (item.get("type"), item.get("namespace"), item.get("tool")) not in selectors:
            continue
        if enabled is False:
            raise ValueError("Code Mode event contradicts disabled configuration")
        identity = tuple(params.get(name) for name in ("threadId", "turnId")) + (item.get("id"),)
        if not all(_id(value) for value in identity):
            raise ValueError("Code Mode item lacks explicit thread/turn/item identity")
        timestamp = _ns(record.get("receipt_ns"))
        if method == "item/started":
            if identity in active or identity in finished:
                raise ValueError("duplicate Code Mode item start")
            active[identity] = timestamp
        else:
            start = active.pop(identity, None)
            if start is None or timestamp < start:
                raise ValueError("Code Mode item completion is unmatched or unordered")
            duration = item.get("durationMs")
            if duration is not None and (type(duration) not in (int, float) or not math.isfinite(duration) or duration < 0):
                raise ValueError("Code Mode producer duration is malformed")
            intervals.append({"thread_id": identity[0], "turn_id": identity[1], "item_id": identity[2],
                "start_ns": start, "end_ns": timestamp, "receipt_duration_ns": timestamp - start,
                "producer_duration_ms": duration, "js_execution_ns": None, "tool_wait_ns": None,
                "timing_scope": "CLIENT_RECEIPT_ITEM_LIFECYCLE; RUNTIME_JS_EXECUTION_NOT_OBSERVED"})
            finished.add(identity)
    return {"status": "INCOMPLETE" if active else "COMPLETE" if intervals else "NOT_ENABLED" if enabled is False
            else "NOT_COLLECTED", "invocations": intervals, "uncompleted_item_count": len(active),
            "js_execution_status": "NOT_COLLECTED" if enabled is not False else "NOT_ENABLED"}
