#!/usr/bin/env python3
"""Read explicit model boundaries and resource samples for the Agent profile.

Durations measured on another Linux boot are portable; absolute monotonic
timestamps are not. Only same-boot intervals enter the wall-clock partition.
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path


def read_jsonl(path, max_bytes=64 * 1024 ** 2):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError("bounded regular JSONL artifact required")
    raw = path.read_bytes()
    if len(raw) > max_bytes or raw and not raw.endswith(b"\n"):
        raise ValueError("oversized or truncated JSONL artifact")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSONL key")
            result[key] = value
        return result
    rows = []
    for line in raw.splitlines():
        value = json.loads(line, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSONL number")))
        if not isinstance(value, dict):
            raise ValueError("JSONL object required")
        rows.append(value)
    return rows


def model_requests(rows, tools, boot_id, task_label=None):
    """Use request identities and literal returned call IDs, never proximity."""
    calls = {tool["call_id"]: tool for tool in tools}
    output, seen = [], set()
    for row in rows or []:
        if row.get("event") != "MODEL_REQUEST_FINISHED":
            continue
        if task_label is not None and row.get("task_label") != task_label:
            continue
        request_id = row.get("request_id")
        if not isinstance(request_id, str) or not request_id or request_id in seen:
            raise ValueError("duplicate/missing model request ID")
        seen.add(request_id)
        if row.get("clock") != "CLOCK_MONOTONIC" or not row.get("boot_id"):
            raise ValueError("model request requires clock and boot identity")
        stamps, durations = row.get("timestamps_ns", {}), row.get("durations_ns", {})
        for value in list(stamps.values()) + list(durations.values()):
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError("invalid model request timestamp/duration")
        begin, end = stamps.get("accepted"), stamps.get("request_end")
        if type(begin) is not int or type(end) is not int or end < begin:
            raise ValueError("unordered model request boundaries")
        if durations.get("request_total") not in (None, end - begin):
            raise ValueError("model request duration differs from raw boundaries")
        matches = [calls[key] for key in row.get("output_tool_call_ids", []) if key in calls]
        if task_label is None and not matches:
            continue
        paths = {tuple(tool.get("semantic_path") or []) for tool in matches}
        semantic = list(next(iter(paths))) if len(paths) == 1 else ["模型请求（未分配语义）"]
        ordered = [stamps.get(key) for key in ("accepted","reserved","upstream_dispatch",
            "upstream_headers","upstream_first_byte","upstream_end","request_end") if stamps.get(key) is not None]
        if ordered != sorted(ordered):
            raise ValueError("model request milestones moved backwards")
        for name,a,b in (("time_to_first_byte","upstream_dispatch","upstream_first_byte"),
            ("first_byte_to_end","upstream_first_byte","upstream_end"),
            ("delivery","response_delivery_start","response_delivery_end")):
            if type(stamps.get(a)) is int and type(stamps.get(b)) is int:
                expected=stamps[b]-stamps[a]
                if expected<0 or durations.get(name) not in (None,expected):
                    raise ValueError("model request derived duration differs: "+name)
                durations[name]=expected
        output.append({"request_id": request_id, "task_label": row.get("task_label"),
            "status": row.get("status",row.get("outcome")), "source_boot_id": row["boot_id"],
            "clock_alignment": "SAME_BOOT" if row["boot_id"] == boot_id else "DIFFERENT_BOOT_DURATION_ONLY",
            "begin_ns": begin, "end_ns": end, "semantic_path": semantic,
            "bound_tool_call_ids": [tool["tool_call_id"] for tool in matches],
            "attribution": "EXPLICIT_PROVIDER_OUTPUT_CALL_IDS" if matches else "REGISTERED_TASK_LABEL_ONLY",
            "timestamps_ns": stamps, "durations_ns": durations,
            "request_ms": (end - begin) / 1e6,
            "wait_first_byte_ms": durations.get("time_to_first_byte", 0) / 1e6
                if type(durations.get("time_to_first_byte")) is int else None,
            "response_receive_ms": durations.get("first_byte_to_end", 0) / 1e6
                if type(durations.get("first_byte_to_end")) is int else None,
            "provider_response_id": row.get("provider_response_id"),
            "usage": row.get("usage"),
            "timing_scope": "BROKER_HTTP_BOUNDARY; FIRST_BYTE_INCLUDES_NETWORK_QUEUE_AND_PROVIDER_WORK"})
    return output


def model_collection(rows, requests, summary=None, task_label=None, boot_id=None):
    """Never silently drop an accepted request without a terminal receipt."""
    selected = [row for row in rows or [] if task_label is not None and row.get("task_label") == task_label]
    accepted = [row.get("request_id") for row in selected if row.get("event") == "MODEL_REQUEST_ACCEPTED"]
    finished = [row["request_id"] for row in requests]
    if len(accepted) != len(set(accepted)) or any(not isinstance(key,str) or not key for key in accepted):
        raise ValueError("duplicate/missing accepted model request ID")
    reasons = []
    unfinished = sorted(set(accepted) - set(finished))
    if unfinished:
        reasons.append("ACCEPTED_REQUEST_WITHOUT_FINISH")
    if summary is not None:
        if summary.get("task_label") != task_label or summary.get("boot_id") != boot_id:
            raise ValueError("model transport summary identity differs")
        if (summary.get("status") != "STOPPED" or summary.get("collection_errors") != 0
                or summary.get("requests_started") != len(accepted)
                or summary.get("requests_finished") != len(finished)):
            reasons.append("TRANSPORT_SUMMARY_PARTIAL_OR_COUNT_MISMATCH")
    return {"status": "PARTIAL" if reasons else "COMPLETE_AT_DECLARED_HTTP_BOUNDARY" if summary
            else "BOUNDARIES_ONLY_NO_FINAL_TRANSPORT_RECEIPT" if requests or accepted else "NOT_COLLECTED",
        "accepted_count":len(accepted),"finished_count":len(finished),
        "unfinished_request_ids":unfinished,"reason_flags":reasons,
        "scope":"REGISTERED_TASK_HTTP_BOUNDARY_NOT_PROVIDER_INTERNAL_QUEUE_OR_FIRST_TOKEN"}


def partition_wall(begin, end, tools, model, code_mode, boot_id, runtime_phases=None):
    """Produce a disjoint wall partition; preserve concurrent memberships."""
    intervals = []
    labels = {"MODEL_WAIT": "等待模型首字节", "MODEL_RECEIVE": "接收模型响应",
        "MODEL_LOCAL": "模型请求本地处理", "MODEL_UNRESOLVED_REQUEST":"模型请求（阶段不完整）",
        "CODE_MODE_JS": "V8 JavaScript 执行",
        "CODE_MODE_AWAIT": "Code Mode 等待工具", "CODE_MODE_OTHER": "Code Mode 其余时间",
        "TOOL_EXECUTION": "工具执行", "TOOL_DISPATCH": "工具登记/派发",
        "TOOL_RETURN": "工具结果返回", "CONCURRENT": "多个活动并行",
        "UNRESOLVED_RUNTIME": "运行时处理（缺少内部阶段事件）",
        "RUNTIME_INITIALIZE":"Codex 初始化 RPC","RUNTIME_THREAD_START":"创建 Agent 会话 RPC",
        "RUNTIME_TURN_START":"提交任务 RPC"}
    def add(a, b, kind, identity, semantic=None, child_call_ids=None):
        if type(a) is not int or type(b) is not int or b < a:
            return
        a, b = max(begin, a), min(end, b)
        if b > a:
            intervals.append({"begin_ns": a, "end_ns": b, "kind": kind,
                "identity": identity, "semantic_path": semantic or [],
                "child_call_ids":child_call_ids or []})
    for tool in tools:
        a,b,c,d = (tool.get(key) for key in ("requested_ns", "execution_begin_ns", "execution_end_ns", "delivered_ns"))
        for lo, hi, kind in ((a,b,"TOOL_DISPATCH"),(b,c,"TOOL_EXECUTION"),(c,d,"TOOL_RETURN")):
            add(lo,hi,kind,tool["call_id"],tool.get("semantic_path"))
    for request in model:
        if request["clock_alignment"] != "SAME_BOOT":
            continue
        ts = request["timestamps_ns"]
        first, dispatch, upstream_end = (ts.get(key) for key in
            ("upstream_first_byte", "upstream_dispatch", "upstream_end"))
        if type(dispatch) is int and type(first) is int and type(upstream_end) is int:
            for a,b,kind in ((request["begin_ns"],dispatch,"MODEL_LOCAL"),
                (dispatch,first,"MODEL_WAIT"),(first,upstream_end,"MODEL_RECEIVE"),
                (upstream_end,request["end_ns"],"MODEL_LOCAL")):
                add(a,b,kind,request["request_id"],request.get("semantic_path"))
        else:
            add(request["begin_ns"],request["end_ns"],"MODEL_UNRESOLVED_REQUEST",request["request_id"])
    for invocation in (code_mode or {}).get("invocations", []):
        if invocation.get("boot_id") != boot_id:
            continue
        owner = next((tool for tool in tools if tool["call_id"] == invocation.get("call_id")), {})
        for segment in invocation.get("segments", []):
            kind = {"JS":"CODE_MODE_JS","AWAIT":"CODE_MODE_AWAIT"}.get(segment.get("kind"),"CODE_MODE_OTHER")
            add(segment.get("begin_ns"),segment.get("end_ns"),kind,invocation.get("call_id"),
                semantic=owner.get("semantic_path"),child_call_ids=segment.get("child_call_ids"))
    for phase in runtime_phases or []:
        if phase.get("kind") not in ("RUNTIME_INITIALIZE","RUNTIME_THREAD_START","RUNTIME_TURN_START"):
            raise ValueError("unsupported runtime RPC phase")
        add(phase.get("begin_ns"),phase.get("end_ns"),phase["kind"],phase.get("identity"))
    points = sorted({begin,end} | {value for row in intervals for value in (row["begin_ns"],row["end_ns"])})
    totals, segments = Counter(), []
    for a,b in zip(points,points[1:]):
        active = [row for row in intervals if row["begin_ns"] <= a < row["end_ns"]]
        # A control RPC can enclose model/tool activity; it refines only gaps,
        # not a second independent job running concurrently with its child.
        non_rpc=[row for row in active if not row["kind"].startswith("RUNTIME_")]
        if non_rpc:active=non_rpc
        effective = [row for row in active if not (
            (row["kind"] == "TOOL_EXECUTION" and any(
                other["identity"] == row["identity"] and other["kind"].startswith("CODE_MODE_")
                for other in active)) or
            (row["kind"]=="CODE_MODE_AWAIT" and any(
                other["identity"] in row["child_call_ids"] and other["kind"].startswith("TOOL_")
                for other in active)))]
        kinds = {row["kind"] for row in effective}
        # The same call's TOOL_EXECUTION encloses its measured Code Mode phases.
        # An explicit await encloses its named child tool. Neither is additional
        # wall time; unrelated simultaneous JS/model/tool remains concurrent.
        concurrent_ids={(row["kind"],row["identity"]) for row in effective}
        kind = (next(iter(kinds)) if len(concurrent_ids)==1 else
                "CONCURRENT" if kinds else "UNRESOLVED_RUNTIME")
        totals[kind] += b-a
        segments.append({"begin_ns":a,"end_ns":b,"kind":kind,"label":labels[kind],
            "duration_ns":b-a,"active_ids":sorted({row["identity"] for row in active if row["identity"]}),
            "semantic_path": effective[0]["semantic_path"] if len(effective)==1 else []})
    assert sum(totals.values()) == end-begin
    return {"status":"PARTITIONED_WITH_EXPLICIT_UNRESOLVED_INTERVALS", "wall_ns":end-begin,
        "totals_ns":dict(totals),"labels":labels,"segments":segments,
        "model_clock_alignment": "DIFFERENT_BOOT_REQUESTS_EXCLUDED_FROM_ABSOLUTE_WALL"
            if any(row["clock_alignment"]!="SAME_BOOT" for row in model) else "SAME_BOOT_OR_NOT_COLLECTED"}


def memory_data(summary, samples, boot_id, begin, end, agent_id=None):
    """Build series retaining separate runtime/PID/container accounting scopes."""
    if summary is None and not samples:
        return {"status":"NOT_COLLECTED","targets":[],"series":[],"capture_series":[],
            "lifecycle_markers":[],"observer_peak_rss_bytes":None,
            "reason":"RESOURCE_SAMPLER_NOT_ENABLED_OR_ARTIFACTS_NOT_PROVIDED"}
    from runtime_resources import summarize_samples
    original_summary = summary
    summary = summary or summarize_samples(samples or [])
    if summary.get("boot_id") not in (None,boot_id):
        raise ValueError("resource summary boot differs from Agent")
    if summary.get("agent_id") not in (None,agent_id):
        raise ValueError("resource summary Agent identity differs")
    if summary.get("boot_id") is None and not samples:
        raise ValueError("resource summary lacks boot identity and raw samples")
    targets = summary.get("targets", [])
    if samples:
        # Recompute peaks from the raw observations, including old captures
        # whose original summary omitted RssAnon/RssFile.  Never upgrade old
        # captures to having exit evidence or a cgroup they did not record.
        derived = summarize_samples(samples)
        registered = {row["target"]["name"]: row["target"] for row in targets}
        for row in derived["targets"]:
            if original_summary and registered.get(row["target"]["name"]) != row["target"]:
                raise ValueError("resource target identity differs from resource summary")
        targets = derived["targets"]
    identities = {row["target"]["name"]:row for row in targets}
    series = []; capture_series = []; cgroup_identities={}
    for row in samples or []:
        if row.get("event") not in ("RESOURCE_SAMPLE", "RESOURCE_TARGET_REGISTERED", "RESOURCE_TARGET_FINISHED"):
            continue
        if row.get("boot_id")!=boot_id:
            raise ValueError("resource sample boot differs from Agent")
        target=row.get("target",{}); name=target.get("name")
        if name not in identities or target!=identities[name]["target"]:
            raise ValueError("resource target identity differs from resource summary")
        if target.get("agent_id") not in (None,agent_id):
            raise ValueError("resource target Agent identity differs")
        if row.get("event")!="RESOURCE_SAMPLE":
            continue
        process=row.get("process",{})
        if process.get("start_ticks") not in (None,target.get("start_ticks")):
            raise ValueError("resource PID lifetime identity differs")
        identity=row.get("cgroup",{}).get("identity")
        if identity:
            if target.get("cgroup_identity") is not None and target["cgroup_identity"]!=identity:
                raise ValueError("resource cgroup registered identity differs")
            if name in cgroup_identities and cgroup_identities[name]!=identity:
                raise ValueError("resource cgroup lifetime identity differs")
            cgroup_identities[name]=identity
        timestamp=row.get("begin_ns")
        if type(timestamp) is not int:
            continue
        process_capture=row.get("process",{})
        cgroup_capture=row.get("cgroup",{})
        proc=process_capture.get("values",{}) if process_capture.get("status") in (None,"OBSERVED","PARTIAL") else {}
        cg=cgroup_capture.get("values",{}) if cgroup_capture.get("status") in (None,"COMPLETE","PARTIAL") else {}
        point = {"at_ms":(timestamp-begin)/1e6,"name":name,"role":target.get("role"),
            "tool_call_id":target.get("tool_call_id"),"rss_bytes":proc.get("rss_bytes"),
            "rss_anon_bytes":proc.get("rss_anon_bytes"),"rss_file_bytes":proc.get("rss_file_bytes"),
            "cgroup_current_bytes":cg.get("memory.current"),
            "cgroup_anon_bytes":cg.get("memory.stat",{}).get("anon"),
            "cgroup_file_bytes":cg.get("memory.stat",{}).get("file"),
            "cgroup_scope":target.get("cgroup_scope"),
            "process_capture_status":row.get("process",{}).get("status"),
            "cgroup_capture_status":row.get("cgroup",{}).get("status", "NOT_REGISTERED"),
            "within_agent_window":begin <= timestamp <= end}
        capture_series.append(point)
        if begin <= timestamp <= end:
            series.append(point)
    markers = []
    for row in targets:
        lifecycle = row.get("lifecycle", {})
        timestamp = lifecycle.get("end_ns")
        if type(timestamp) is int:
            markers.append({"name": row["target"]["name"], "at_ms": (timestamp-begin)/1e6,
                "target": row["target"], **lifecycle,
                "within_agent_window":begin <= timestamp <= end})
    observer = [row.get("sampled_rss_peak_bytes") for row in targets
                if str(row.get("target",{}).get("role","")).startswith("OBSERVER")]
    return {"status":summary.get("status","SAMPLED_NOT_EXHAUSTIVE"),"targets":targets,
        "interval_ms":summary.get("interval_ms"),"series":series,"capture_series":capture_series,
        "capture_begin_ms":min((row["at_ms"] for row in capture_series),default=None),
        "capture_end_ms":max([row["at_ms"] for row in capture_series] +
            [row["at_ms"] for row in markers], default=None),
        "lifecycle_markers":markers,
        "sample_limit_reached":summary.get("sample_limit_reached",False),
        "collection_warnings":summary.get("collection_warnings",[]),
        "observer_peak_rss_bytes":max((v for v in observer if type(v) is int),default=None),
        "peak_scope":"ENTIRE_CAPTURE_WINDOW_MAY_INCLUDE_AGENT_SETUP_AND_SHUTDOWN",
        "curve_end_semantics":"NO_ZERO_SAMPLE_INVENTED; CONFIRMED_PID_EXIT_IS_A_SEPARATE_LIFECYCLE_MARKER; CGROUP_MEMORY_CAN_REMAIN_AFTER_PID_EXIT",
        "overhead_semantics":"MAX_OF_INDIVIDUAL_OBSERVER_PID_PEAKS_NOT_AGGREGATE; INCREMENTAL_OVERHEAD_REQUIRES_OFF_ON_PAIRS"}
