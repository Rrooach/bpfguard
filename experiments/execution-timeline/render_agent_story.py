#!/usr/bin/env python3
"""Render one human-first Agent -> tool -> Linux syscall workload story.

This is a presentation projection over independently replayed evidence.  It
only admits application-declared tool calls that have an exact Observer tool
binding.  Internal grading/cleanup tools and unrelated cgroup threads are not
silently mixed into the Agent workload.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import errno
from html import escape
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

from semantic_profile import build_profile
from syscall_catalog import describe
from execution_metrics import memory_data, model_requests, model_collection, partition_wall, read_jsonl
from decision_evidence import build_decision_evidence
from runtime_rpc_phases import runtime_rpc_phases


MAX_JSON_BYTES = 64 * 1024 ** 2
IMPORTANT_NAMES = frozenset({
    "clone", "clone3", "fork", "vfork", "execve", "execveat", "exit", "exit_group",
    "socket", "connect", "accept", "accept4", "bind", "listen", "sendto", "sendmsg",
    "recvfrom", "recvmsg", "mount", "umount2", "setns", "unshare", "bpf", "prctl",
    "seccomp", "setuid", "setgid", "setgroups", "capset", "init_module", "finit_module",
    "delete_module",
})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_JSON_BYTES,
            "bounded regular JSON file required: " + str(path))
    raw = path.read_bytes()
    require(len(raw) <= MAX_JSON_BYTES, "JSON input grew while being read")

    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key: " + key)
            value[key] = item
        return value

    def invalid(value):
        raise ValueError("nonfinite JSON value: " + value)

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def read_rpc_usage(path):
    """Read provider-reported per-model-call token deltas from Codex RPC."""
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_JSON_BYTES,
            "bounded regular RPC ledger required")
    raw = path.read_bytes()
    require(not raw or raw.endswith(b"\n"), "truncated RPC ledger")
    result = []
    for line in raw.splitlines():
        def pairs(items):
            value = {}
            for key, item in items:
                require(key not in value, "duplicate RPC JSON key: " + key)
                value[key] = item
            return value
        row = json.loads(line, object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite RPC value: " + value)))
        require(isinstance(row, dict), "RPC ledger row must be an object")
        message = row.get("message", {})
        if (row.get("direction") != "CODEX_TO_CLIENT" or
                message.get("method") != "thread/tokenUsage/updated"):
            continue
        params = message.get("params", {})
        require(isinstance(params, dict), "token usage params must be an object")
        usage = params.get("tokenUsage", {}) if isinstance(params, dict) else {}
        last = usage.get("last", {}) if isinstance(usage, dict) else {}
        fields = ("inputTokens", "cachedInputTokens", "cacheWriteInputTokens",
                  "outputTokens", "reasoningOutputTokens", "totalTokens")
        require(all(type(last.get(name, 0)) is int and last.get(name, 0) >= 0 for name in fields),
                "invalid provider token usage")
        receipt = row.get("receipt_ns")
        require(type(receipt) is int and receipt >= 0, "token usage lacks client receipt clock")
        result.append({"receipt_ns": receipt, "thread_id": params.get("threadId"),
            "turn_id": params.get("turnId"), **{name: last.get(name, 0) for name in fields},
            "source": "CODEX_PROVIDER_REPORTED_LAST_USAGE"})
    return result


def bounded_text(value, limit=240):
    if not isinstance(value, str):
        return ""
    return value if len(value) <= limit else value[:limit] + "…"


def semantic_plans(application):
    """Bind tools to preceding Agent-authored plan text by explicit step order.

    This is not LLM semantic segmentation and is deliberately labelled as an
    Agent-reported plan.  A later profiler may replace it with reviewed stable
    task annotations without changing the raw tool/kernel evidence.
    """
    current, result = None, {}
    for step in application.get("steps", []) if isinstance(application.get("steps"), list) else []:
        if not isinstance(step, dict):
            continue
        if step.get("kind") == "AGENT_MESSAGE" and isinstance(step.get("text"), str):
            text = " ".join(step["text"].strip().split())
            if text:
                current = text
        elif step.get("kind") in ("TOOL_CALL", "APPLICATION_TOOL_CALL"):
            call_id = step.get("call_id")
            if isinstance(call_id, str):
                result[call_id] = current
    return result


def semantic_label(text):
    if not text:
        return "未提供步骤标签（任务与命令已知）"
    first = re.split(r"(?<=[。！？!?])\s+|\n", text.strip(), maxsplit=1)[0]
    return bounded_text(first, 88)


def syscall_row(call, thread, origin):
    number = call.get("nr")
    presentation = describe(number, call.get("name"))
    name = presentation["name"]
    start, end = call.get("start_ns"), call.get("end_ns")
    duration = end - start if type(start) is int and type(end) is int and end >= start else None
    result = call.get("result")
    paired = call.get("pairing") in (None, "PAIRED")
    error_name = errno.errorcode.get(-result) if type(result) is int and result < 0 and paired else None
    paths, requested, returned = [], 0, 0
    for item in call.get("files", []) if isinstance(call.get("files"), list) else []:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if isinstance(path, str) and path and path not in paths:
            paths.append(path)
        read = item.get("read")
        if isinstance(read, dict):
            if type(read.get("requested_bytes")) is int and read["requested_bytes"] >= 0:
                requested += read["requested_bytes"]
            if type(read.get("returned_bytes")) is int and read["returned_bytes"] >= 0:
                returned += read["returned_bytes"]
    return {
        "at_ms": round((start - origin) / 1e6, 3) if type(start) is int else None,
        "duration_us": round(duration / 1e3, 3) if duration is not None else None,
        "tid": thread.get("tid"), "tgid": thread.get("tgid"),
        "process_birth_ns": thread.get("process_birth_ns"),
        "comm": thread.get("comm") or "?", "name": name,
        "nr": number, "result": result, "errno": error_name,
        "pairing": call.get("pairing", "NOT_RECORDED"),
        "category": presentation.get("category"),
        "filesystem": presentation.get("is_filesystem_interface") is True,
        "important": presentation.get("is_filesystem_interface") is True or name in IMPORTANT_NAMES
            or error_name is not None or not paired,
        "paths": paths[:4], "additional_paths": max(0, len(paths) - 4),
        "requested_bytes": requested or None, "returned_bytes": returned or None,
    }


def official_summary(value):
    if not isinstance(value, dict):
        return {"status": "NOT_PROVIDED", "label": "未提供官方判题结果"}
    if "resolved" in value:
        report = value.get("report", {})
        selected = next(iter(report.values()), {}) if isinstance(report, dict) else {}
        tests = selected.get("tests_status", {}) if isinstance(selected, dict) else {}
        fail_to_pass = tests.get("FAIL_TO_PASS", {}) if isinstance(tests, dict) else {}
        failures = fail_to_pass.get("failure", []) if isinstance(fail_to_pass, dict) else []
        return {"status": "PASSED" if value.get("resolved") is True else "FAILED",
            "label": "SWE-bench 已解决" if value.get("resolved") is True else "SWE-bench 未解决",
            "failed_target_tests": failures, "test_timeouts": value.get("test_timeouts")}
    rewards = value.get("verifier_result", {}).get("rewards", {}) if isinstance(value.get("verifier_result"), dict) else {}
    reward = rewards.get("reward") if isinstance(rewards, dict) else None
    return {"status": "PASSED" if reward == 1 else "FAILED" if reward is not None else "UNKNOWN",
        "label": "Terminal-Bench reward " + str(reward) if reward is not None else "Terminal-Bench 结果未知",
        "reward": reward}


def build_story(report, application, official=None, verification=None, rpc_usage=None,
                model_timing=None, code_mode=None, resource_summary=None, resource_samples=None,
                model_transport_summary=None,rpc_rows=None,tool_event_rows=None,runtime_cleanup=None):
    require(isinstance(report, dict) and isinstance(application, dict), "report/application objects required")
    run = report.get("run", {})
    require(type(run.get("begin_ns")) is int and type(run.get("end_ns")) is int,
            "report run interval required")
    app_begin, app_end = application.get("begin_ns"), application.get("end_ns")
    require(type(app_begin) is int and type(app_end) is int and app_begin <= app_end,
            "application Agent interval required")
    bindings = application.get("function_bindings")
    calls = application.get("tool_calls")
    require(isinstance(bindings, list) and isinstance(calls, list), "application tool bindings/calls required")
    require(len(bindings) <= 256, "bounded Agent tool list required")
    reports = {tool.get("tool_call_id"): tool for tool in report.get("tools", [])
        if isinstance(tool, dict) and isinstance(tool.get("tool_call_id"), str)}
    app_calls = {call.get("call_id"): call for call in calls
        if isinstance(call, dict) and isinstance(call.get("call_id"), str)}
    critical = {tool.get("tool_call_id"): tool for tool in report.get("critical_path", {}).get("tools", [])
        if isinstance(tool, dict)}
    threads_by_tool = defaultdict(list)
    for thread in report.get("threads", []):
        if isinstance(thread, dict) and isinstance(thread.get("tool_call_id"), str):
            threads_by_tool[thread["tool_call_id"]].append(thread)
    plans = semantic_plans(application)

    seen, tools = set(), []
    for index, binding in enumerate(sorted(bindings, key=lambda row: row.get("client_request_received_ns", row.get("begin_ns", 0))), 1):
        require(isinstance(binding, dict), "tool binding object required")
        tool_id, call_id = binding.get("observer_tool_call_id"), binding.get("call_id")
        require(isinstance(tool_id, str) and tool_id not in seen and tool_id in reports,
                "unique application tool must have one report binding")
        require(isinstance(call_id, str) and call_id in app_calls, "tool binding lacks application lifecycle")
        seen.add(tool_id)
        lifecycle, kernel_tool = app_calls[call_id], reports[tool_id]
        owned = threads_by_tool.get(tool_id, [])
        rows = [syscall_row(call, thread, app_begin) for thread in owned
            for call in thread.get("calls", []) if isinstance(call, dict)]
        rows.sort(key=lambda row: (row["at_ms"] is None, row["at_ms"] or 0, row.get("tid") or 0))
        groups = defaultdict(lambda: {"count": 0, "errors": 0, "duration_us": 0.0,
            "returned_bytes": 0, "paths": set(), "filesystem": False})
        files = defaultdict(lambda: {"calls": 0, "returned_bytes": 0, "duration_us": 0.0})
        for row in rows:
            group = groups[row["name"]]
            group["count"] += 1; group["errors"] += row["errno"] is not None
            group["duration_us"] += row["duration_us"] or 0
            group["returned_bytes"] += row["returned_bytes"] or 0
            group["filesystem"] = group["filesystem"] or row["filesystem"]
            for path in row["paths"]:
                group["paths"].add(path)
                item = files[path]; item["calls"] += 1
                item["returned_bytes"] += row["returned_bytes"] or 0
                item["duration_us"] += row["duration_us"] or 0
        summaries = [{"name": name, **{key: value for key, value in item.items() if key != "paths"},
            "paths": sorted(item["paths"])[:5], "additional_paths": max(0, len(item["paths"]) - 5)}
            for name, item in groups.items()]
        summaries.sort(key=lambda item: (-item["count"], item["name"]))
        file_rows = [{"path": path, **item} for path, item in files.items()]
        file_rows.sort(key=lambda item: (-item["returned_bytes"], -item["calls"], item["path"]))
        programs = []
        for thread in owned:
            for execution in thread.get("execs", []) if isinstance(thread.get("execs"), list) else []:
                if isinstance(execution, dict):
                    programs.append({"at_ms": round((execution.get("timestamp_ns", app_begin) - app_begin) / 1e6, 3),
                        "tid": thread.get("tid"), "filename": execution.get("filename") or "NOT_CAPTURED",
                        "comm": execution.get("comm") or thread.get("comm")})
        processes = {}
        for thread in owned:
            key = (thread.get("tgid"), thread.get("process_birth_ns"))
            process = processes.setdefault(key, {"tgid": thread.get("tgid"),
                "process_birth_ns": thread.get("process_birth_ns"), "comm": thread.get("comm") or "?",
                "threads": [], "state_totals_ns": defaultdict(int), "syscalls": 0,
                "returned_bytes": 0})
            state = thread.get("state_totals_ns", {})
            if not isinstance(state, dict):
                state = {}
            for name, value in state.items():
                if type(value) is int and value >= 0:
                    process["state_totals_ns"][name] += value
            thread_calls = [row for row in rows if row.get("tid") == thread.get("tid")]
            thread_read = sum(row.get("returned_bytes") or 0 for row in thread_calls)
            process["syscalls"] += len(thread_calls); process["returned_bytes"] += thread_read
            process["threads"].append({"tid": thread.get("tid"), "comm": thread.get("comm") or "?",
                "state_totals_ns": {name: value for name, value in state.items()
                    if type(value) is int and value >= 0}, "syscalls": len(thread_calls),
                "returned_bytes": thread_read})
        process_rows = []
        for process in processes.values():
            process["state_totals_ns"] = dict(process["state_totals_ns"])
            process["threads"].sort(key=lambda row: (row.get("tid") is None, row.get("tid") or 0))
            process_rows.append(process)
        process_rows.sort(key=lambda row: (row.get("tgid") is None, row.get("tgid") or 0,
                                            row.get("process_birth_ns") or 0))
        request_ns = lifecycle.get("requested_ns", binding.get("client_request_received_ns"))
        delivered_ns = lifecycle.get("result_delivered_ns", binding.get("end_ns"))
        execute_begin, execute_end = binding.get("begin_ns"), binding.get("end_ns")
        require(all(type(value) is int for value in (request_ns, delivered_ns, execute_begin, execute_end)),
                "complete tool lifecycle timestamps required")
        require(request_ns <= execute_begin <= execute_end <= delivered_ns,
                "ordered request/execution/delivery timestamps required")
        gate = binding.get("gate_result", {}) if isinstance(binding.get("gate_result"), dict) else {}
        plan = plans.get(call_id)
        tools.append({"number": index, "call_id": call_id, "tool_call_id": tool_id,
            "tool_name": lifecycle.get("tool_name") or binding.get("tool") or "observer_bash",
            "command": binding.get("command") or kernel_tool.get("command") or "",
            "status": lifecycle.get("status"), "exit_code": lifecycle.get("exit_code", gate.get("return_code")),
            "requested_ns": request_ns, "execution_begin_ns": execute_begin,
            "execution_end_ns": execute_end, "delivered_ns": delivered_ns,
            "request_at_ms": round((request_ns - app_begin) / 1e6, 3),
            "execution_at_ms": round((execute_begin - app_begin) / 1e6, 3),
            "delivered_at_ms": round((delivered_ns - app_begin) / 1e6, 3),
            "request_to_execution_ms": round((execute_begin - request_ns) / 1e6, 3),
            "execution_ms": round((execute_end - execute_begin) / 1e6, 3),
            "result_delivery_ms": round((delivered_ns - execute_end) / 1e6, 3),
            "total_ms": round((delivered_ns - request_ns) / 1e6, 3),
            "stdout_bytes": gate.get("stdout_bytes"), "stderr_bytes": gate.get("stderr_bytes"),
            "root_pid": binding.get("root_pid"), "processes": len({(thread.get("tgid"), thread.get("process_birth_ns")) for thread in owned}),
            "threads": len(owned), "syscalls": len(rows), "important_syscalls": sum(row["important"] for row in rows),
            "distinct_files": len(files), "returned_bytes": sum(row["returned_bytes"] or 0 for row in rows),
            "semantic_path": [semantic_label(plan)], "semantic_source_text": bounded_text(plan, 512),
            "semantic_quality": "AGENT_REPORTED_PLAN_STEP_ORDER" if plan else "UNANNOTATED",
            "programs": sorted(programs, key=lambda row: row["at_ms"]), "process_profiles": process_rows,
            "resources": kernel_tool.get("resources"), "rusage": kernel_tool.get("rusage"),
            "syscall_summary": summaries,
            "files": file_rows, "syscall_rows": rows,
            "timeline_status": critical.get(tool_id, {}).get("status", "NOT_RECONSTRUCTED")})

    require(len(tools) == len(bindings), "not every application tool was projected")
    previous = app_begin
    for tool in tools:
        request = app_begin + round(tool["request_at_ms"] * 1e6)
        tool["agent_gap_before_ms"] = round(max(0, request - previous) / 1e6, 3)
        previous = app_begin + round(tool["delivered_at_ms"] * 1e6)
    trailing = round(max(0, app_end - previous) / 1e6, 3)
    usage_rows = []
    for index, usage in enumerate(rpc_usage or [], 1):
        receipt = usage.get("receipt_ns")
        if type(receipt) is not int or not app_begin <= receipt <= app_end:
            continue
        prior = [tool for tool in tools
                 if app_begin + round(tool["delivered_at_ms"] * 1e6) <= receipt]
        owner = prior[-1] if prior else None
        usage_rows.append({**usage, "number": index,
            "at_ms": round((receipt - app_begin) / 1e6, 3),
            "semantic_path": owner.get("semantic_path") if owner else ["未归属模型调用"],
            "associated_tool_call_id": owner.get("tool_call_id") if owner else None,
            "attribution": ("ORDERED_TURN_STREAM_AFTER_TOOL_RESULT_NOT_CAUSAL_BINDING"
                            if owner else "TURN_LEVEL_ONLY_NOT_TOOL_ATTRIBUTED")})
    first = bindings[0] if bindings else {"agent_id":application.get("agent_id"),"task_id":application.get("task_id")}
    boot_id = run.get("boot_id")
    budget_labels = {row.get("budget_label") for row in bindings if row.get("budget_label")}
    task_label = application.get("budget_label") or (next(iter(budget_labels)) if len(budget_labels)==1 else None)
    if task_label is None:
        explicit_calls={tool["call_id"] for tool in tools}
        labels={row.get("task_label") for row in (model_timing or [])
                if explicit_calls.intersection(row.get("output_tool_call_ids",[]))}
        if len(labels)==1:task_label=next(iter(labels))
    requests = model_requests(model_timing, tools, boot_id, task_label)
    request_collection = model_collection(model_timing,requests,model_transport_summary,task_label,boot_id)
    mode = code_mode or {"status":"NOT_COLLECTED", "invocations":[],
        "reason":"Code Mode 未启用，或没有提供执行事件"}
    for invocation in mode.get("invocations",[]):
        if invocation.get("run_id") != run.get("run_id"):
            raise ValueError("Code Mode run identity differs")
        if invocation.get("boot_id") == boot_id and not (
                type(invocation.get("begin_ns")) is int and type(invocation.get("end_ns")) is int
                and app_begin <= invocation["begin_ns"] <= invocation["end_ns"] <= app_end):
            raise ValueError("Code Mode execution lies outside Agent interval")
        if invocation.get("agent_id") not in (None,first.get("agent_id")) or invocation.get("task_id") not in (None,first.get("task_id")):
            raise ValueError("Code Mode Agent/task identity differs")
        invocation["v8_heap_used_peak_bytes"] = invocation.get("memory",{}).get("heap_used_bytes",{}).get("max_observed")
        invocation["process_rss_peak_bytes"] = invocation.get("memory",{}).get("rss_bytes",{}).get("max_observed")
    runtime_phases=runtime_rpc_phases(rpc_rows,boot_id,app_begin,app_end)
    wall_partition = partition_wall(app_begin,app_end,tools,requests,mode,boot_id,runtime_phases=runtime_phases)
    memory = memory_data(resource_summary, resource_samples, boot_id, app_begin, app_end,first.get("agent_id"))
    if runtime_cleanup is not None:
        runtime_targets=[row["target"] for row in memory.get("targets",[]) if row["target"].get("role")=="AGENT_RUNTIME"]
        require(runtime_cleanup.get("boot_id")==boot_id and any(
            target.get("pid")==runtime_cleanup.get("root_pid")
            and target.get("cgroup_identity")==runtime_cleanup.get("identity") for target in runtime_targets),
            "runtime cleanup PID/cgroup/boot identity differs")
    verify = verification if isinstance(verification, dict) else {}
    story = {"schema_version": 1, "run_id":run.get("run_id"),"task_id": first.get("task_id") or application.get("task_id"),
        "agent_id": first.get("agent_id"), "model": application.get("model"), "agent_status": application.get("status"),
        "begin_ns":app_begin,"end_ns":app_end,"boot_id":boot_id,
        "agent_wall_ms": round((app_end - app_begin) / 1e6, 3), "capture_wall_ms": round((run["end_ns"] - run["begin_ns"]) / 1e6, 3),
        "tool_count": len(tools), "total_syscalls": sum(tool["syscalls"] for tool in tools),
        "total_files": len({item["path"] for tool in tools for item in tool["files"]}),
        "total_read_bytes": sum(tool["returned_bytes"] for tool in tools),
        "event_count": report.get("totals", {}).get("events"), "capture_health": report.get("health", {}).get("status"),
        "ring_drops": report.get("health", {}).get("counters", {}).get("ring_drops"),
        "verification": {key: verify.get(key) for key in ("status", "timeline_status", "application_tool_calls", "process_bound_calls")},
        "official": official_summary(official), "tools": tools, "trailing_agent_ms": trailing,
        "model_usage": usage_rows,
        "total_tokens": sum(row.get("totalTokens", 0) for row in usage_rows),
        "model_requests": requests, "model_collection":request_collection,"runtime_phases":runtime_phases,
        "code_mode": mode, "wall_partition":wall_partition,
        "memory":memory,"runtime_cleanup":runtime_cleanup,
        "application_errors": application.get("errors", []),
        "scope_note": "只展示 Agent 明确请求并绑定到 Observer Linux root 的工具；模型/API 等待不声称为 Guest syscall。"}
    story["decision_evidence"]=build_decision_evidence(application,report,verification=verification,
        rpc_rows=rpc_rows,tool_events=tool_event_rows)
    return story


def json_for_html(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


HTML = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Agent 端到端执行记录</title><style>
:root{--bg:#f5f7fb;--card:#fff;--ink:#172033;--muted:#657086;--line:#d9dfeb;--blue:#2563eb;--green:#087f5b;--red:#c92a2a;--amber:#b45309}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}.wrap{max-width:1180px;margin:auto;padding:28px 20px 80px}h1{font-size:28px;margin:0 0 6px}h2{font-size:20px;margin:0}h3{font-size:16px;margin:18px 0 8px}.sub,.muted{color:var(--muted)}.hero,.profile,.tool,.end,.gap{background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:0 2px 8px #1720330a}.hero,.profile{padding:22px;margin:20px 0}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px;margin-top:16px}.metric{background:#f8faff;border:1px solid #e6eaf2;border-radius:10px;padding:10px}.metric b{display:block;font-size:20px}.verdict{display:inline-block;border-radius:999px;padding:4px 10px;font-weight:700}.ok{background:#dff7ed;color:var(--green)}.bad{background:#ffe3e3;color:var(--red)}.warn{background:#fff3d6;color:var(--amber)}.profile-head{display:flex;justify-content:space-between;align-items:flex-start;gap:18px}.profile select{padding:8px 10px;border:1px solid #cdd5e3;border-radius:8px;background:#fff;min-width:250px}.profile-chart{overflow-x:auto;margin-top:16px;border:1px solid #e2e7f0;border-radius:10px;background:#fbfcff}.profile-chart svg{display:block;min-width:900px}.profile-note{background:#f8faff;border-left:4px solid var(--blue);padding:9px 12px;margin:10px 0}.profile-legend{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--muted)}.legend-dot{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}.flow{position:relative;margin-left:20px;padding-left:34px}.flow:before{content:"";position:absolute;left:8px;top:0;bottom:0;width:3px;background:#cad4e6}.node{position:relative;margin:16px 0}.node:before{content:"";position:absolute;left:-32px;top:22px;width:13px;height:13px;border-radius:50%;background:var(--blue);border:4px solid var(--bg)}.gap{padding:10px 14px;color:var(--muted);background:#fafbfe}.gap:before{background:#94a3b8}.tool{padding:18px}.tool.failed{border-left:5px solid var(--red)}.tool.succeeded{border-left:5px solid var(--green)}.tool-head{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.number{color:var(--blue);font-weight:800}.command{white-space:pre-wrap;word-break:break-word;background:#101827;color:#e8eefc;border-radius:9px;padding:12px;margin:12px 0;font:13px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;max-height:220px;overflow:auto}.chips{display:flex;flex-wrap:wrap;gap:7px}.chip{border-radius:999px;background:#edf2fa;padding:3px 9px;color:#34415b;font-size:13px}.stages{display:grid;grid-template-columns:repeat(3,1fr);gap:4px;margin:13px 0}.stage{padding:8px;background:#eef3ff;text-align:center;font-size:13px}.stage:first-child{border-radius:8px 0 0 8px}.stage:last-child{border-radius:0 8px 8px 0}details{border-top:1px solid var(--line);margin-top:13px;padding-top:10px}summary{cursor:pointer;font-weight:700;color:#263b67}.tables{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #e8ebf1;vertical-align:top}th{position:sticky;top:0;background:#f8faff;z-index:1}.path{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}.controls{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.controls input,.controls select,.controls button{padding:7px 9px;border:1px solid #cdd5e3;border-radius:7px;background:#fff}.controls input{min-width:260px}.pager{color:var(--muted);padding:7px}.end{padding:17px}.end:before{background:#111827}.raw{white-space:pre-wrap;max-height:260px;overflow:auto;font:12px ui-monospace,monospace}.empty{color:var(--muted);font-style:italic}@media(max-width:700px){.profile-head{display:block}.profile select{width:100%;margin-top:10px}.stages{grid-template-columns:1fr}.stage{border-radius:6px!important}.tool-head{display:block}.flow{margin-left:6px;padding-left:26px}.node:before{left:-24px}}
</style></head><body><main class="wrap"><h1>Agent 端到端执行记录</h1><p class="sub">先看语义火焰图定位成本，再沿 Agent → 工具 → 进程/线程 → syscall/文件对象下钻原始证据。</p><section id="app"></section></main><script>const story=__STORY__;const profile=__PROFILE__;
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=n=>n==null?'—':Number(n).toLocaleString();const ms=n=>n==null?'—':Number(n).toLocaleString(undefined,{maximumFractionDigits:3})+' ms';
const bytes=n=>{if(n==null)return'—';let v=Number(n),u='B';for(const x of ['KiB','MiB','GiB']){if(v<1024)break;v/=1024;u=x}return v.toLocaleString(undefined,{maximumFractionDigits:2})+' '+u};
function badge(status){const s=String(status||'UNKNOWN'),c=/FAIL|ERROR/.test(s)?'bad':/INCOMPLETE|NOT_|UNRESOLVED|UNKNOWN|PARTIAL/.test(s)?'warn':/PASS|COMPLETE|SUCCEEDED|REPLAY/.test(s)?'ok':'warn';return `<span class="verdict ${c}">${esc(s)}</span>`}
function summaryRows(rows){return rows.slice(0,18).map(x=>`<tr><td><code>${esc(x.name)}</code></td><td>${fmt(x.count)}</td><td>${fmt(x.errors)}</td><td>${ms(x.duration_us/1000)}</td><td>${bytes(x.returned_bytes)}</td><td class="path">${x.paths.map(esc).join('<br>')}${x.additional_paths?' ＋'+x.additional_paths:''}</td></tr>`).join('')}
function fileRows(rows){return rows.slice(0,20).map(x=>`<tr><td class="path">${esc(x.path)}</td><td>${fmt(x.calls)}</td><td>${bytes(x.returned_bytes)}</td><td>${ms(x.duration_us/1000)}</td></tr>`).join('')||'<tr><td colspan="4" class="empty">没有解析到文件对象</td></tr>'}
const colors={root:'#334155',agent:'#2563eb',task:'#0f766e',semantic:'#9333ea',tool:'#c2410c',agent_phase:'#64748b',phase:'#64748b',process:'#0284c7',thread:'#16a34a',syscall_category:'#a16207',syscall:'#ca8a04',file:'#dc2626',resource:'#0891b2'};
function metric(v,u){if(u==='bytes')return bytes(v);if(u==='ms')return ms(v);return fmt(v)+' '+u}
function profilePanel(){const options=profile.views.map(v=>`<option value="${esc(v.name)}" ${v.status!=='AVAILABLE'?'disabled':''}>${esc(v.label)}${v.status==='AVAILABLE'?'':'（未采集）'}</option>`).join('');return `<section class="profile"><div class="profile-head"><div><h2>Agent 语义火焰图</h2><p class="muted">纵向：任务语义 → 工具 → 进程/线程或 syscall/文件；横向：当前选择指标的占比。相同证据可切换不同权重。</p></div><select id="profile-select" onchange="drawProfile(this.value)">${options}</select></div><div id="profile-summary" class="profile-note"></div><div id="profile-chart" class="profile-chart"></div><div class="profile-legend"><span><i class="legend-dot" style="background:#9333ea"></i>语义任务</span><span><i class="legend-dot" style="background:#c2410c"></i>工具</span><span><i class="legend-dot" style="background:#0284c7"></i>进程</span><span><i class="legend-dot" style="background:#ca8a04"></i>syscall</span><span><i class="legend-dot" style="background:#dc2626"></i>文件</span></div><details><summary>数据边界与尚未采集项</summary><ul>${profile.limitations.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></details></section>`}
function drawProfile(name){const view=profile.views.find(v=>v.name===name&&v.status==='AVAILABLE')||profile.views.find(v=>v.status==='AVAILABLE');if(!view)return;document.querySelector('#profile-select').value=view.name;const width=1120,row=29,pad=2,items=[];let depth=0;function walk(n,x,d,w,path){depth=Math.max(depth,d);items.push({n,x,d,w,path:[...path,n.label]});let at=x;(n.children||[]).forEach(c=>{const cw=n.value? w*c.value/n.value:0;walk(c,at,d+1,cw,[...path,n.label]);at+=cw})}walk(view.tree,0,0,width,[]);const height=(depth+1)*row+8;const svg=items.filter(i=>i.w>.25).map(i=>{const x=i.x+pad/2,w=Math.max(.25,i.w-pad),y=i.d*row+4,color=colors[i.n.kind]||'#64748b',label=i.w>55?esc(i.n.label):'';return `<g><title>${esc(i.path.join(' → '))}\n${esc(view.label)}: ${esc(metric(i.n.value,view.unit))} (${(100*i.n.value/view.total).toFixed(2)}%)</title><rect x="${x}" y="${y}" width="${w}" height="${row-3}" rx="3" fill="${color}" opacity=".92"></rect><text x="${x+5}" y="${y+18}" fill="white" font-size="12">${label}</text></g>`}).join('');document.querySelector('#profile-chart').innerHTML=`<svg viewBox="0 0 ${width} ${height}" width="100%" height="${height}" role="img" aria-label="${esc(view.label)} semantic flamegraph">${svg}</svg>`;document.querySelector('#profile-summary').innerHTML=`<strong>${esc(view.label)}：${esc(metric(view.total,view.unit))}</strong> · ${fmt(view.sample_count)} 个可加权 operation<br><span class="muted">${esc(view.quality)}</span>`}
const state={};function exact(i){const t=story.tools[i],s=state[i]||(state[i]={page:0,mode:'important',q:''}),q=s.q.toLowerCase();let rows=t.syscall_rows.filter(r=>(s.mode==='all'||s.mode==='important'&&r.important||s.mode==='filesystem'&&r.filesystem||s.mode==='errors'&&r.errno)&&(!q||[r.name,r.comm,r.tid,...r.paths].join(' ').toLowerCase().includes(q)));const pages=Math.max(1,Math.ceil(rows.length/100));s.page=Math.min(s.page,pages-1);const body=rows.slice(s.page*100,s.page*100+100).map(r=>`<tr><td>+${ms(r.at_ms)}</td><td>${esc(r.comm)}<br><span class="muted">TID ${esc(r.tid)}</span></td><td><code>${esc(r.name)}</code> <span class="muted">#${esc(r.nr)}</span></td><td>${r.errno?`<span class="bad verdict">${esc(r.errno)}</span>`:esc(r.result)}</td><td>${r.duration_us==null?'—':r.duration_us.toLocaleString()+' µs'}</td><td class="path">${r.paths.map(esc).join('<br>')||'—'}</td><td>${bytes(r.returned_bytes)}</td></tr>`).join('');document.querySelector(`#rows-${i}`).innerHTML=body||'<tr><td colspan="7" class="empty">没有匹配的 syscall</td></tr>';document.querySelector(`#page-${i}`).textContent=`${fmt(rows.length)} 条匹配 · 第 ${s.page+1}/${pages} 页`;}
function viewer(t,i){return `<details ontoggle="if(this.open)exact(${i})"><summary>逐次 syscall：默认显示 ${fmt(t.important_syscalls)} 条关键调用，可切换全部 ${fmt(t.syscalls)} 条</summary><div class="controls"><select onchange="state[${i}]=state[${i}]||{page:0,q:''};state[${i}].mode=this.value;state[${i}].page=0;exact(${i})"><option value="important">关键 syscall</option><option value="filesystem">文件系统 syscall</option><option value="errors">失败 syscall</option><option value="all">全部 syscall</option></select><input placeholder="搜索 syscall、路径、进程或 TID" oninput="state[${i}]=state[${i}]||{page:0,mode:'important'};state[${i}].q=this.value;state[${i}].page=0;exact(${i})"><button onclick="state[${i}].page=Math.max(0,state[${i}].page-1);exact(${i})">上一页</button><button onclick="state[${i}].page++;exact(${i})">下一页</button><span class="pager" id="page-${i}"></span></div><div class="tables"><table><thead><tr><th>Agent 相对时刻</th><th>进程/线程</th><th>syscall</th><th>结果</th><th>耗时</th><th>内核对象/路径</th><th>读取</th></tr></thead><tbody id="rows-${i}"></tbody></table></div></details>`}
function tool(t,i){const cls=t.exit_code===0?'succeeded':'failed',progs=t.programs.slice(0,30).map(p=>`<tr><td>+${ms(p.at_ms)}</td><td>${esc(p.comm)}</td><td>${esc(p.tid)}</td><td class="path">${esc(p.filename)}</td></tr>`).join('');return `${t.agent_gap_before_ms>1?`<div class="node gap">Agent/模型准备或等待：${ms(t.agent_gap_before_ms)} <span class="muted">（Codex 运行时在目标容器外，不伪装成 Guest syscall）</span></div>`:''}<article class="node tool ${cls}"><div class="tool-head"><div><span class="number">工具 ${t.number}</span> · <strong>${esc(t.tool_name)}</strong><div class="muted">请求于 Agent +${ms(t.request_at_ms)} · root PID ${esc(t.root_pid)}</div></div><div>${badge(t.status)} ${badge(t.timeline_status)}</div></div><div class="command">${esc(t.command)}</div><div class="stages"><div class="stage">登记并释放<br><b>${ms(t.request_to_execution_ms)}</b></div><div class="stage">Linux 执行<br><b>${ms(t.execution_ms)}</b></div><div class="stage">结果返回 Codex<br><b>${ms(t.result_delivery_ms)}</b></div></div><div class="chips"><span class="chip">exit ${esc(t.exit_code)}</span><span class="chip">${fmt(t.processes)} 个进程</span><span class="chip">${fmt(t.threads)} 个线程</span><span class="chip">${fmt(t.syscalls)} 次 syscall</span><span class="chip">${fmt(t.distinct_files)} 个文件对象</span><span class="chip">读取 ${bytes(t.returned_bytes)}</span><span class="chip">stdout ${bytes(t.stdout_bytes)}</span></div><details><summary>实际执行程序（${fmt(t.programs.length)} 次 exec）</summary><div class="tables"><table><thead><tr><th>时刻</th><th>进程</th><th>TID</th><th>内核执行名称</th></tr></thead><tbody>${progs||'<tr><td colspan="4" class="empty">没有成功 exec 记录</td></tr>'}</tbody></table></div></details><details><summary>syscall 汇总（先看这里）</summary><div class="tables"><table><thead><tr><th>syscall</th><th>次数</th><th>失败</th><th>累计耗时</th><th>读取</th><th>关联路径示例</th></tr></thead><tbody>${summaryRows(t.syscall_summary)}</tbody></table></div></details><details><summary>文件对象（${fmt(t.files.length)} 个路径）</summary><div class="tables"><table><thead><tr><th>路径/对象</th><th>读观测</th><th>返回字节</th><th>syscall 累计耗时</th></tr></thead><tbody>${fileRows(t.files)}</tbody></table></div></details>${viewer(t,i)}</article>`}
const official=story.official;document.querySelector('#app').innerHTML=`<section class="hero"><div>${badge(story.agent_status)} ${badge(official.status)} ${badge(story.verification.status)}</div><h2>${esc(story.task_id)}</h2><p>${esc(official.label)} · Agent ${esc(story.agent_id)} · 模型 ${esc(story.model)}</p><div class="metrics"><div class="metric"><b>${ms(story.agent_wall_ms)}</b>Agent 端到端</div><div class="metric"><b>${fmt(story.tool_count)}</b>工具调用</div><div class="metric"><b>${fmt(story.total_tokens)}</b>provider tokens</div><div class="metric"><b>${fmt(story.total_syscalls)}</b>对应 syscall</div><div class="metric"><b>${fmt(story.total_files)}</b>不同文件对象</div><div class="metric"><b>${bytes(story.total_read_bytes)}</b>实际读取</div><div class="metric"><b>${fmt(story.event_count)}</b>内核事件</div></div><p class="muted">${esc(story.scope_note)} Capture ${ms(story.capture_wall_ms)}；ring drops ${fmt(story.ring_drops)}。</p></section>${profilePanel()}<details><summary>展开逐工具执行故事与 syscall 原始证据</summary><section class="flow"><div class="node end"><strong>Agent 开始</strong><div class="muted">0 ms · workload ${esc(story.task_id)}</div></div>${story.tools.map(tool).join('')}${story.trailing_agent_ms>1?`<div class="node gap">最后一次工具结果返回后，Agent 收尾：${ms(story.trailing_agent_ms)}</div>`:''}<div class="node end"><strong>Agent 结束</strong><p>${badge(story.agent_status)} ${badge(official.status)} ${esc(official.label)}</p>${official.failed_target_tests?.length?`<p>未通过目标测试：<code>${official.failed_target_tests.map(esc).join('</code>、<code>')}</code></p>`:''}${story.application_errors.length?`<details><summary>Agent 结束错误</summary><pre class="raw">${esc(JSON.stringify(story.application_errors,null,2))}</pre></details>`:''}</div></section></details>`;drawProfile(document.querySelector('#profile-select').value);
</script></body></html>'''


def render(story, profile=None, *, profile_url="semantic-profile.json", evidence_url="evidence-links.json"):
    from runtime_metrics_panel import STYLE as runtime_style, SCRIPT as runtime_script, PROFILE_SCRIPT
    from interactive_profile_ui import render_profile_panel
    profile = build_profile(story) if profile is None else profile
    # Operations are for standard-profile export, not needed to draw a folded
    # tree. Kernel observations already exist in each tool's syscall viewer;
    # the evidence-chain panel needs only a small illustrative preview.
    # Keep full source JSON untouched instead of duplicating it into the page.
    display_profile={key:value for key,value in profile.items() if key!="operations"}
    display_story={**story}
    evidence=story.get("decision_evidence")
    if evidence:
        display_story["decision_evidence"]={**evidence,"chains":[{**chain,
            "observations":chain.get("observations",[])[:5],
            "observation_count":len(chain.get("observations",[])),
            "presentation_preview_limit":5} for chain in evidence.get("chains",[])]}
    page = (HTML.replace("__STORY__", json_for_html(display_story), 1)
            .replace("__PROFILE__", json_for_html(display_profile), 1))
    page = page.replace("</style>",runtime_style+"</style>",1)
    page = page.replace("const official=story.official;",runtime_script+"\nconst official=story.official;",1)
    chart_start=page.index("function drawProfile(name)")
    chart_end=page.index("const state={};",chart_start)
    page=page[:chart_start]+PROFILE_SCRIPT+"\n"+page[chart_end:]
    page = page.replace("${profilePanel()}","${runtimeMetricsPanel()}${profilePanel()}",1)
    page = page.replace("${badge(story.verification.status)}",
        "${badge(story.verification.status)} ${badge(story.capture_health)}",1)
    page = page.replace('<article class="node tool ${cls}">','<article id="agent-tool-${i}" class="node tool ${cls}">',1)
    page = page.replace("</script>","if(story.memory?.targets?.length)drawMemory(0);</script>",1)
    # Keep the older chart available only as a compatibility detail. The default
    # view is the interactive task-first explorer; raw operations stay in JSON.
    page = page.replace("${runtimeMetricsPanel()}${profilePanel()}",
        '${runtimeMetricsPanel()}<details><summary>旧版静态火焰图</summary>${profilePanel()}</details>', 1)
    panel = render_profile_panel(profile, profile_url=profile_url, evidence_url=evidence_url)
    page = page.replace('<section id="app"></section>', panel + '<section id="app"></section>', 1)
    return page


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--application", type=Path, required=True)
    parser.add_argument("--official-result", type=Path)
    parser.add_argument("--verification", type=Path)
    parser.add_argument("--rpc-events", type=Path,
        help="optional bound Codex rpc.jsonl for provider-reported token usage")
    parser.add_argument("--tool-events",type=Path,help="raw application tool lifecycle ledger for evidence-chain replay")
    parser.add_argument("--model-timing", type=Path,
        help="broker model-request-timing.jsonl, exact request durations and returned call IDs")
    parser.add_argument("--model-transport-summary", type=Path,
        help="local HTTP transport final receipt; unfinished requests remain partial")
    parser.add_argument("--code-mode-events", type=Path,
        help="V8 runtime dispatcher event ledger")
    parser.add_argument("--resource-summary", type=Path,
        help="Agent/tool resource-summary.json")
    parser.add_argument("--resource-samples", type=Path,
        help="Agent/tool resource-samples.jsonl for memory trajectories")
    parser.add_argument("--runtime-cleanup",type=Path,help="owned runtime cgroup root-wait/descendant-cleanup receipt")
    parser.add_argument("--semantic-annotations",type=Path,
        help="optional reviewed, trajectory-digest-bound task intervals; default uses versioned command rules")
    parser.add_argument("--profile-output", type=Path,
        help="optional fresh JSON artifact containing the folded semantic profile")
    parser.add_argument("--evidence-output",type=Path,
        help="optional fresh full application/kernel evidence-link JSON; HTML embeds only previews")
    parser.add_argument("--pprof-directory",type=Path,
        help="fresh output directory for standard pprof wall/token/RSS/tool profiles")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    require(not args.output.exists() and not args.output.is_symlink(), "fresh output required")
    if args.profile_output:
        require(not args.profile_output.exists() and not args.profile_output.is_symlink(),
                "fresh profile output required")
    if args.evidence_output:
        require(not args.evidence_output.exists() and not args.evidence_output.is_symlink(),
                "fresh evidence output required")
    mode = None
    if args.code_mode_events:
        from code_mode_timing import replay_runtime_events
        mode = replay_runtime_events(read_jsonl(args.code_mode_events))
    summary_path = args.resource_summary
    samples_path = args.resource_samples
    model_path = args.model_timing
    transport_summary = args.model_transport_summary
    runtime_cleanup_path=args.runtime_cleanup
    if runtime_cleanup_path is None and args.application.with_name("runtime-cgroup-cleanup.json").is_file():
        runtime_cleanup_path=args.application.with_name("runtime-cgroup-cleanup.json")
    rpc_path=args.rpc_events
    if rpc_path is None and args.application.with_name("rpc.jsonl").is_file():
        rpc_path=args.application.with_name("rpc.jsonl")
    tool_events_path=args.tool_events
    if tool_events_path is None and args.application.with_name("tool-events.jsonl").is_file():
        tool_events_path=args.application.with_name("tool-events.jsonl")
    if model_path is None and args.application.with_name("model-request-timing.jsonl").is_file():
        model_path = args.application.with_name("model-request-timing.jsonl")
    if transport_summary is None and args.application.with_name("model-transport-summary.json").is_file():
        transport_summary = args.application.with_name("model-transport-summary.json")
    # New capture adapters place resource evidence beside the application
    # ledger; discover it so the normal render command includes memory.
    if summary_path is None and args.application.with_name("resource-summary.json").is_file():
        summary_path = args.application.with_name("resource-summary.json")
    if samples_path is None and args.application.with_name("resource-samples.jsonl").is_file():
        samples_path = args.application.with_name("resource-samples.jsonl")
    if summary_path is None and args.application.parent.parent.joinpath("resources/resource-summary.json").is_file():
        summary_path = args.application.parent.parent/"resources/resource-summary.json"
    if samples_path is None and args.application.parent.parent.joinpath("resources/resource-samples.jsonl").is_file():
        samples_path = args.application.parent.parent/"resources/resource-samples.jsonl"
    story = build_story(read_json(args.report), read_json(args.application),
        read_json(args.official_result) if args.official_result else None,
        read_json(args.verification) if args.verification else None,
        read_rpc_usage(rpc_path) if rpc_path else None,
        read_jsonl(model_path) if model_path else None, mode,
        read_json(summary_path) if summary_path else None,
        read_jsonl(samples_path) if samples_path else None,
        read_json(transport_summary) if transport_summary else None,
        read_jsonl(rpc_path) if rpc_path else None,
        read_jsonl(tool_events_path) if tool_events_path else None,
        read_json(runtime_cleanup_path) if runtime_cleanup_path else None)
    from semantic_annotations import build_trajectory, build_annotations, apply_annotations
    trajectory = build_trajectory(read_json(args.application), story,
        read_jsonl(rpc_path) if rpc_path else None)
    annotations = build_annotations(trajectory,
        read_json(args.semantic_annotations) if args.semantic_annotations else None)
    story = apply_annotations(story, annotations)
    derived = args.output.with_suffix("")
    for suffix, document in (("-trajectory.json",trajectory),("-annotations.json",annotations)):
        with Path(str(derived)+suffix).open("x",encoding="utf-8") as stream:
            json.dump(document,stream,ensure_ascii=False,allow_nan=False,sort_keys=True)
            stream.write("\n")
    profile = build_profile(story)
    if args.evidence_output:
        with args.evidence_output.open("x",encoding="utf-8") as stream:
            json.dump(story["decision_evidence"],stream,ensure_ascii=False,allow_nan=False,
                sort_keys=True,separators=(",",":"))
    if args.pprof_directory:
        from pprof_export import write_pprof
        args.pprof_directory.mkdir(parents=True,exist_ok=False)
        exports=[]
        available={row["name"] for row in profile["views"] if row["status"]=="AVAILABLE"}
        for name in ("wall_ms","token_count","memory_rss_byte_ms","tool_count"):
            if name not in available:continue
            destination=args.pprof_directory/(name+".pb.gz")
            receipt=write_pprof(profile,name,destination)
            exports.append({"view":name,"href":quote(os.path.relpath(destination,args.output.parent)),
                "receipt":receipt})
        profile["downloads"]=exports
        with (args.pprof_directory/"export-receipt.json").open("x",encoding="utf-8") as stream:
            json.dump({"format":"STANDARD_GZIP_PPROF_PROTOBUF","exports":exports},stream,
                ensure_ascii=False,allow_nan=False,sort_keys=True)
    if args.profile_output:
        with args.profile_output.open("x", encoding="utf-8") as stream:
            json.dump(profile, stream, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":"))
            stream.write("\n")
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(render(story, profile,
            profile_url=quote(os.path.relpath(args.profile_output,args.output.parent)) if args.profile_output else "semantic-profile.json",
            evidence_url=quote(os.path.relpath(args.evidence_output,args.output.parent)) if args.evidence_output else "evidence-links.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
