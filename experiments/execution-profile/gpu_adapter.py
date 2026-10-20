"""Optional NVTX/Nsight SQLite adapter. NO GPU validation has been performed.

Primary schema: https://docs.nvidia.com/nsight-systems/AnalysisGuide/
This parser uses explicit CUDA correlation IDs and containing NVTX launch ranges,
never GPU utilization to guess which request executed a kernel.
"""
from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import dataclasses
import json
import sqlite3
from pathlib import Path

from semantic import Context, identifier


class Nvtx:
    def __init__(self):
        name = ctypes.util.find_library("nvToolsExt")
        if not name:
            raise RuntimeError("NVTX_UNAVAILABLE_NOT_ENABLED")
        self.library = ctypes.CDLL(name)
        self.library.nvtxRangePushA.argtypes = [ctypes.c_char_p]
        self.library.nvtxRangePop.argtypes = []
        self.library.nvtxRangePushA.restype = ctypes.c_int
        self.library.nvtxRangePop.restype = ctypes.c_int

    @contextlib.contextmanager
    def batch(self, batch_id, contexts):
        identifier(batch_id)
        members = [dataclasses.asdict(context.validate()) for context in contexts]
        ids = [member["request_id"] for member in members]
        if not members or None in ids or len(set(ids)) != len(ids):
            raise ValueError("NVTX range needs explicit distinct request members")
        label = json.dumps({"observer_nvtx_schema": 1, "batch_id": batch_id, "members": members}, separators=(",", ":"))
        if len(label.encode()) > 16384:
            raise ValueError("NVTX label exceeds bounded payload")
        if self.library.nvtxRangePushA(label.encode()) < 0:
            raise RuntimeError("NVTX push failed")
        try:
            yield
        finally:
            if self.library.nvtxRangePop() < 0:
                raise RuntimeError("NVTX pop failed")


def clock_mapping(anchors, maximum_error_ns=100_000):
    """Explicit profiler <-> CLOCK_MONOTONIC paired anchors with read brackets.

    Two endpoints fit a linear offset/drift model; every interior anchor must
    agree within its stated bracket and the configured budget. No extrapolation.
    """
    if len(anchors) < 3:
        raise ValueError("three clock anchors required: two fit, one independent check")
    anchors = sorted(anchors, key=lambda anchor: anchor["profiler_ns"])
    for anchor in anchors:
        for name in ("profiler_ns", "monotonic_before_ns", "monotonic_after_ns"):
            if type(anchor[name]) is not int or anchor[name] < 0:
                raise ValueError("invalid clock anchor")
        if anchor["monotonic_after_ns"] < anchor["monotonic_before_ns"] or (
                anchor["monotonic_after_ns"] - anchor["monotonic_before_ns"]) > maximum_error_ns:
            raise ValueError("clock bracket exceeds error budget")
    first, last = anchors[0], anchors[-1]
    if first["profiler_ns"] == last["profiler_ns"]:
        raise ValueError("degenerate profiler clock")
    midpoint = lambda anchor: (anchor["monotonic_before_ns"] + anchor["monotonic_after_ns"]) / 2
    scale = (midpoint(last) - midpoint(first)) / (last["profiler_ns"] - first["profiler_ns"])
    if not .999 <= scale <= 1.001:
        raise ValueError("unreasonable cross-clock drift")
    offset = midpoint(first) - scale * first["profiler_ns"]
    error = max(abs(scale * anchor["profiler_ns"] + offset - midpoint(anchor)) +
                (anchor["monotonic_after_ns"] - anchor["monotonic_before_ns"]) / 2 for anchor in anchors)
    if error > maximum_error_ns:
        raise ValueError("clock calibration residual exceeds budget")
    return {"scale": scale, "offset_ns": offset, "maximum_error_ns": error,
            "valid_profiler_interval_ns": [first["profiler_ns"], last["profiler_ns"]],
            "anchor_count": len(anchors), "status": "CALIBRATED_BOUNDED_NOT_EXTRAPOLATED"}


def parse_nsight(path, expected_requests, metadata):
    """Read-only bounded parser of selected official SQLite columns.

    Metadata must bind boot/run/export version and explicit globalTid process
    instances, plus independently collected clock anchors. Tests use fabricated
    SQLite fixtures and MUST NOT be counted as hardware E2E.
    """
    identifier(metadata["run_id"])
    if not metadata.get("boot_id") or not metadata.get("nsight_version"):
        raise ValueError("profiler export identity/version required")
    calibration = clock_mapping(metadata["clock_anchors"])
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required = {"CUPTI_ACTIVITY_KIND_RUNTIME", "CUPTI_ACTIVITY_KIND_KERNEL", "NVTX_EVENTS"}
        if not required <= tables:
            raise ValueError("missing Nsight CUDA/NVTX schema; cannot infer zero work")
        def bounded(query):
            rows = list(connection.execute(query + " LIMIT 100001"))
            if len(rows) > 100000:
                raise ValueError("profiler export exceeds row budget")
            return rows
        runtime = bounded("SELECT start,end,globalTid,correlationId FROM CUPTI_ACTIVITY_KIND_RUNTIME")
        kernel_columns = {row[1] for row in connection.execute("PRAGMA table_info(CUPTI_ACTIVITY_KIND_KERNEL)")}
        selected_kernel = "start,end,globalPid,correlationId,deviceId,contextId,streamId"
        if "graphNodeId" in kernel_columns:
            selected_kernel += ",graphNodeId"
        kernels = [{**dict(row), "activity_kind": "KERNEL"} for row in bounded(
            "SELECT " + selected_kernel + " FROM CUPTI_ACTIVITY_KIND_KERNEL")]
        memcpy_status = "UNKNOWN_TABLE_ABSENT"
        copies = []
        if "CUPTI_ACTIVITY_KIND_MEMCPY" in tables:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(CUPTI_ACTIVITY_KIND_MEMCPY)")}
            required_copy = {"start", "end", "globalPid", "correlationId", "deviceId", "contextId", "streamId", "bytes", "copyKind"}
            if not required_copy <= columns:
                memcpy_status = "UNKNOWN_SCHEMA_UNSUPPORTED"
            else:
                selected = sorted(required_copy | ({"graphNodeId"} if "graphNodeId" in columns else set()))
                copies = [{**dict(row), "activity_kind": "MEMCPY"} for row in bounded(
                    "SELECT " + ",".join(selected) + " FROM CUPTI_ACTIVITY_KIND_MEMCPY")]
                memcpy_status = "PARSED_WITH_DECLARED_SCOPE"
        ranges = bounded("SELECT start,end,globalTid,eventType,text FROM NVTX_EVENTS WHERE text IS NOT NULL")
        launches = {}
        for row in runtime:
            key = row["correlationId"]
            launches.setdefault(key, []).append(dict(row))
        parsed_ranges = []
        for row in ranges:
            try:
                payload = json.loads(row["text"])
            except (json.JSONDecodeError, TypeError):
                continue
            if payload.get("observer_nvtx_schema") != 1:
                continue
            if row["eventType"] != 59:
                raise ValueError("observer NVTX marker is not push/pop range type59")
            identifier(payload["batch_id"])
            if not payload["members"]:
                raise ValueError("NVTX batch lacks explicit members")
            ids = []
            for member in payload["members"]:
                ctx = Context(**{**member, "dependencies": tuple(member["dependencies"])}).validate()
                if ctx.run_id != metadata["run_id"] or expected_requests.get(ctx.request_id) != member:
                    raise ValueError("NVTX request membership forged")
                ids.append(ctx.request_id)
            if len(set(ids)) != len(ids):
                raise ValueError("duplicate NVTX member")
            parsed_ranges.append({**dict(row), "payload": payload})
        effects, unresolved = [], []
        process_key = lambda actor: (actor["boot_id"], actor["pid"], actor["process_start_ticks"], actor["cgroup_inode"])
        for kernel in kernels + copies:
            if kernel.get("graphNodeId"):
                unresolved.append({"correlation_id": kernel["correlationId"], "reason": "CUDA_GRAPH_NODE_UNSUPPORTED"})
                continue
            gpu_actor = metadata["process_instances_by_global_pid"].get(str(kernel["globalPid"]))
            if not gpu_actor or gpu_actor["boot_id"] != metadata["boot_id"]:
                unresolved.append({"correlation_id": kernel["correlationId"], "reason": "GPU_PROCESS_INSTANCE_UNREGISTERED"})
                continue
            candidates = []
            for launch_candidate in launches.get(kernel["correlationId"], []):
                candidate_actor = metadata["process_instances_by_global_tid"].get(str(launch_candidate["globalTid"]))
                if candidate_actor and process_key(candidate_actor) == process_key(gpu_actor):
                    candidates.append(launch_candidate)
            if len(candidates) != 1:
                unresolved.append({"correlation_id": kernel["correlationId"], "reason": "AMBIGUOUS_OR_MISSING_CUDA_LAUNCH"})
                continue
            launch = candidates[0]
            containing = [row for row in parsed_ranges if row["globalTid"] == launch["globalTid"] and
                          row["start"] <= launch["start"] and row["end"] >= launch["end"]]
            if not containing:
                unresolved.append({"correlation_id": kernel["correlationId"], "reason": "NO_EXPLICIT_NVTX_REQUEST_RANGE"})
                continue
            selected = max(containing, key=lambda row: row["start"])
            actor = metadata["process_instances_by_global_tid"].get(str(launch["globalTid"]))
            if not actor or actor["boot_id"] != metadata["boot_id"] or any(
                    type(actor[name]) is not int or actor[name] <= 0
                    for name in ("pid", "tid", "process_start_ticks", "thread_start_ticks", "cgroup_inode")):
                raise ValueError("missing registered profiler process/TID instance")
            if not (calibration["valid_profiler_interval_ns"][0] <= kernel["start"] <= kernel["end"] <=
                    calibration["valid_profiler_interval_ns"][1]):
                raise ValueError("GPU activity outside calibrated clock interval")
            transfer = {}
            if kernel["activity_kind"] == "MEMCPY":
                if type(kernel["bytes"]) is not int or kernel["bytes"] < 0:
                    raise ValueError("invalid memcpy byte count")
                kinds = {}
                if "ENUM_CUDA_MEMCPY_OPER" in tables:
                    kinds = {row[0]: row[1] for row in connection.execute("SELECT id,name FROM ENUM_CUDA_MEMCPY_OPER")}
                transfer = {"bytes": kernel["bytes"], "copy_kind_id": kernel["copyKind"],
                            "copy_kind": kinds.get(kernel["copyKind"], "UNKNOWN_COPY_KIND")}
            effects.append({"batch_id": selected["payload"]["batch_id"], "members": selected["payload"]["members"],
                "activity_kind": kernel["activity_kind"], **transfer,
                "actor": actor, "device_id": kernel["deviceId"], "cuda_context_id": kernel["contextId"],
                "cuda_stream_id": kernel["streamId"], "correlation_id": kernel["correlationId"],
                "start_monotonic_ns": round(kernel["start"] * calibration["scale"] + calibration["offset_ns"]),
                "end_monotonic_ns": round(kernel["end"] * calibration["scale"] + calibration["offset_ns"]),
                "batch_cost_not_divided_by_member": True})
        return {"schema_version": 1, "adapter_status": "PARSED_WITH_DECLARED_SCOPE", "hardware_validation": "NOT_RUN",
                "clock_calibration": calibration, "activities": effects, "unresolved": unresolved,
                "memcpy_adapter_status": memcpy_status,
                "request_attribution": "EXPLICIT_CUDA_CORRELATION_AND_NVTX_MEMBERSHIP_NOT_UTILIZATION",
                "limitations": ["NO_CUDA_GRAPH_NODE_ADAPTER", "NO_PRODUCTION_GPU_TEST",
                                "CORRELATION_COLLISION_RETURNED_UNRESOLVED_NOT_GUESSED"]}
    finally:
        connection.close()
