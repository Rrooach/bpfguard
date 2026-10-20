#!/usr/bin/env python3
"""Expose application -> gated execution -> kernel evidence, without guessing intent.

The result is an index over the supplied evidence, not another authoritative
sensor.  JSON-pointer references allow a reader to inspect every contributing
record.  RPC replay verifies the application projection; native replay remains
a separate, explicitly reported prerequisite.  Neither establishes hidden
reasoning, delegated effects, or a counterfactual causal explanation.
"""
from __future__ import annotations

from collections import Counter


def _identifier(value):
    return isinstance(value, str) and bool(value) and len(value) <= 1024


def _positive_int(value):
    return type(value) is int and value > 0


def _index(rows, key, source):
    result = {}
    for index, row in enumerate(rows or []):
        if not isinstance(row, dict) or not _identifier(row.get(key)):
            continue
        if row[key] in result:
            raise ValueError("ambiguous duplicate identity in " + source + ": " + row[key])
        result[row[key]] = (index, row)
    return result


def _edge(kind, label, status, refs=(), **details):
    return {"kind": kind, "label": label, "status": status,
            "evidence_refs": list(refs), **details}


def _compare_fields(left, right, fields):
    missing = [key for key in fields if left.get(key) is None or right.get(key) is None]
    conflicts = [key for key in fields if left.get(key) is not None
                 and right.get(key) is not None and left[key] != right[key]]
    return ("CONFLICT" if conflicts else "MISSING" if missing else "MATCHED"), missing, conflicts


def _source_replay(application, rpc_rows, tool_events):
    if rpc_rows is None or tool_events is None:
        return {"status": "NOT_REPLAYED", "reason": "原始 RPC 或工具事件账本未提供"}
    from codex_tool_adapter import verify_codex_tool_sources
    from tool_events import replay_tool_events

    try:
        replayed = replay_tool_events(tool_events, require_delivered=True)
        if replayed != application.get("tool_calls"):
            raise ValueError("replayed tool lifecycle differs from application projection")
        receipt = verify_codex_tool_sources(rpc_rows, tool_events)
    except (ValueError, TypeError, KeyError) as error:
        return {"status": "FAILED", "reason": str(error)}
    return {"status": "RAW_APPLICATION_REPLAY_PASSED", "receipt": receipt,
            "scope": "CODEX_RPC_AND_TOOL_LEDGER_AGREEMENT_NOT_KERNEL_OR_INTENT_PROOF"}


def _contexts(application, rpc_rows=None):
    """Use explicit stream order and thread/turn IDs, never timestamp proximity."""
    current, result = {}, {}
    public_messages = {}
    for index, raw in enumerate(rpc_rows or []):
        if not isinstance(raw, dict) or raw.get("direction") != "CODEX_TO_CLIENT":
            continue
        message = raw.get("message", {})
        params = message.get("params", {}) if isinstance(message, dict) else {}
        item = params.get("item", {}) if isinstance(params, dict) else {}
        if (message.get("method") == "item/completed" and isinstance(item, dict)
                and item.get("type") == "agentMessage"):
            key = params.get("threadId"), params.get("turnId"), item.get("id")
            public_messages.setdefault(key, []).append((index, item.get("text")))
    for index, step in enumerate(application.get("steps") or []):
        if not isinstance(step, dict):
            continue
        identity = step.get("thread_id"), step.get("turn_id")
        if not all(_identifier(value) for value in identity):
            continue
        if step.get("kind") == "AGENT_MESSAGE" and isinstance(step.get("text"), str) and step["text"].strip():
            sources = public_messages.get((*identity, step.get("item_id")), [])
            source_status = ("NOT_REPLAYED" if rpc_rows is None else "RAW_MESSAGE_MATCHED"
                if len(sources) == 1 and sources[0][1] == step["text"] else "CONFLICT")
            current[identity] = {"text": step["text"][:2048], "item_id": step.get("item_id"),
                "thread_id": identity[0], "turn_id": identity[1],
                "evidence_ref": "application#/steps/" + str(index), "source_status": source_status,
                "raw_rpc_refs": ["rpc#/" + str(source_index) for source_index, _ in sources]}
        elif step.get("kind") in ("TOOL_CALL", "APPLICATION_TOOL_CALL") and _identifier(step.get("call_id")):
            if step["call_id"] in result:
                raise ValueError("ambiguous repeated tool call in application stream")
            result[step["call_id"]] = current.get(identity)
    return result


def _root_valid(root):
    return isinstance(root, dict) and all(_positive_int(root.get(key))
        for key in ("tid", "start_ticks", "clock_ticks"))


def _root_thread_matches(root, thread, boot_id):
    birth = thread.get("birth_ns", thread.get("thread_birth_ns"))
    return (_root_valid(root) and thread.get("tid") == root["tid"]
        and _positive_int(birth) and birth * root["clock_ticks"] // 1_000_000_000 == root["start_ticks"]
        and thread.get("key") == "{}:{}:{}".format(boot_id, root["tid"], birth))


def build_decision_evidence(application, report, verification=None, rpc_rows=None,
                            tool_events=None, max_observations=100_000):
    """Return readable per-call chains plus stable references to original records.

    ``verification`` is a separately supplied receipt, NOT rerun by this helper.
    Raw RPC/tool replay is executed here when both lists are supplied.  A native
    report/receipt must already have been independently verified by the caller;
    this module does not turn a self-asserted JSON status into sensor truth.
    """
    if not isinstance(application, dict) or not isinstance(report, dict):
        raise ValueError("application/report objects required")
    if type(max_observations) is not int or not 0 < max_observations <= 1_000_000:
        raise ValueError("bounded positive observation limit required")
    calls = _index(application.get("tool_calls"), "call_id", "application tool calls")
    bindings = _index(application.get("function_bindings"), "call_id", "application bindings")
    native = _index(report.get("tools"), "tool_call_id", "native tools")
    if len(calls) > 256 or len(bindings) > 256:
        raise ValueError("bounded application tool list required")
    observer_ids = [row.get("observer_tool_call_id", row.get("tool_call_id"))
                    for _, row in bindings.values()]
    explicit_ids = [value for value in observer_ids if _identifier(value)]
    if len(explicit_ids) != len(set(explicit_ids)):
        raise ValueError("multiple application calls claim one native tool")
    source = _source_replay(application, rpc_rows, tool_events)
    contexts = _contexts(application, rpc_rows)
    boot_id = report.get("run", {}).get("boot_id")
    threads = list(enumerate(report.get("threads") or []))
    receipt = verification if isinstance(verification, dict) else {}
    native_replay = {"status": "REPLAY_RECEIPT_PROVIDED" if receipt else "NOT_PROVIDED",
        "reported_status": receipt.get("status"), "timeline_status": receipt.get("timeline_status"),
        "manifest": receipt.get("manifest"), "report": receipt.get("report"),
        "scope": "SEPARATE_RECEIPT_NOT_RERUN_OR_AUTHENTICATED_BY_THIS_PRESENTATION_INDEX"}
    chains, observation_count = [], 0
    all_ids = list(calls) + [call_id for call_id in bindings if call_id not in calls]
    for call_id in all_ids:
        call_index, call = calls.get(call_id, (None, {}))
        binding_index, binding = bindings.get(call_id, (None, {}))
        tool_id = binding.get("observer_tool_call_id", binding.get("tool_call_id"))
        native_index, native_tool = native.get(tool_id, (None, {}))
        call_ref = "application#/tool_calls/" + str(call_index) if call_index is not None else None
        binding_ref = "application#/function_bindings/" + str(binding_index) if binding_index is not None else None
        native_ref = "report#/tools/" + str(native_index) if native_index is not None else None
        context = contexts.get(call_id)
        edges = [_edge("DECLARED_CONTEXT", "Agent 公开说明 → 工具调用",
            "CONFLICT" if context and context["source_status"] == "CONFLICT"
                else "ORDERED_CONTEXT_ONLY" if context else "MISSING",
            [context["evidence_ref"], call_ref] if context and call_ref else [],
            source_status=context["source_status"] if context else "NOT_PROVIDED",
            reason="同 thread/turn 的先前公开消息；不是决策因果或隐藏思维证明" if context
                   else "没有同一 thread/turn 的先前公开说明；不代表 Agent 没有思考")]
        identity_fields = ("thread_id", "turn_id", "call_id", "agent_id", "task_id")
        application_status, missing, conflicts = _compare_fields(call, binding, identity_fields)
        if not call or not binding:
            application_status = "MISSING"
        if source["status"] == "FAILED":
            application_status = "CONFLICT"
        elif application_status == "MATCHED":
            application_status = ("RAW_REPLAY_MATCHED" if source["status"] == "RAW_APPLICATION_REPLAY_PASSED"
                                  else "MATCHED_NOT_REPLAYED")
        edges.append(_edge("APPLICATION_CALL", "Codex 原始调用 → 工具生命周期", application_status,
            [ref for ref in (call_ref, binding_ref) if ref],
            missing_fields=missing, conflicting_fields=conflicts,
            identity={key: call.get(key) for key in identity_fields}))
        gate_status, missing, conflicts = _compare_fields(binding, native_tool,
            ("root", "cgroup_id", "begin_ns", "end_ns", "command", "agent_id", "task_id"))
        if (not binding or not native_tool or not _root_valid(binding.get("root"))
                or not _positive_int(binding.get("cgroup_id"))):
            gate_status = "CONFLICT" if conflicts else "MISSING"
        if binding.get("boot_id") is None or boot_id is None:
            if gate_status != "CONFLICT":
                gate_status = "MISSING"
            missing.append("boot_id")
        elif binding["boot_id"] != boot_id:
            gate_status = "CONFLICT"; conflicts.append("boot_id")
        lifecycle_fields = (("execution_tool_call_id", tool_id), ("root", binding.get("root")),
                            ("cgroup_id", binding.get("cgroup_id")),
                            ("execution_begin_ns", binding.get("begin_ns")),
                            ("execution_end_ns", binding.get("end_ns")))
        for field, expected in lifecycle_fields:
            if call.get(field) is None:
                if gate_status == "MATCHED":
                    gate_status = "MISSING"
                missing.append("lifecycle." + field)
            elif call[field] != expected:
                gate_status = "CONFLICT"; conflicts.append("lifecycle." + field)
        edges.append(_edge("EXECUTION_GATE", "工具调用 → stopped root / cgroup", gate_status,
            [ref for ref in (call_ref, binding_ref, native_ref) if ref],
            root=binding.get("root"), cgroup_id=binding.get("cgroup_id"), boot_id=binding.get("boot_id"),
            missing_fields=missing, conflicting_fields=conflicts))
        owned = [(index, thread) for index, thread in threads if isinstance(thread, dict)
                 and _identifier(tool_id) and thread.get("tool_call_id") == tool_id]
        anchors = [(index, thread) for index, thread in owned
                   if _root_thread_matches(binding.get("root"), thread, boot_id)]
        root_status = "MATCHED" if len(anchors) == 1 else "CONFLICT" if len(anchors) > 1 else "MISSING"
        edges.append(_edge("KERNEL_LIFETIME", "root 生命周期 → 内核线程 / syscall", root_status,
            ["report#/threads/" + str(index) for index, _ in anchors],
            reason="PID + start_ticks + boot_id 匹配；后代归属依赖 native replay，不按时间猜测",
            owned_threads=len(owned), native_replay=native_replay["reported_status"]))
        observations, path_count, stable_objects, missing_objects, omitted = [], 0, 0, 0, 0
        for thread_index, thread in owned:
            for syscall_index, syscall in enumerate(thread.get("calls") or []):
                if not isinstance(syscall, dict):
                    continue
                if observation_count >= max_observations:
                    omitted += 1
                    continue
                observation_count += 1
                syscall_ref = "report#/threads/{}/calls/{}".format(thread_index, syscall_index)
                objects = []
                for file_index, file in enumerate(syscall.get("files") or []):
                    if not isinstance(file, dict):
                        continue
                    identity = {key: file.get(key) for key in ("mount_id", "device", "inode", "generation")}
                    resolved = (all(type(value) is int and value >= 0 for value in identity.values())
                                and identity["mount_id"] > 0 and identity["inode"] > 0)
                    path = file.get("path") if isinstance(file.get("path"), str) else None
                    path_count += bool(path); stable_objects += resolved
                    objects.append({"path": path, "identity": identity,
                        "status": "KERNEL_OBJECT_FIELDS" if resolved else "KERNEL_PATH_ONLY" if path else "UNRESOLVED",
                        "evidence_ref": syscall_ref + "/files/" + str(file_index)})
                if not objects:
                    missing_objects += 1
                observations.append({"evidence_ref": syscall_ref, "thread_ref": "report#/threads/" + str(thread_index),
                    "thread_key": thread.get("key"), "tid": thread.get("tid"), "tgid": thread.get("tgid"),
                    "process_birth_ns": thread.get("process_birth_ns"), "syscall": syscall.get("name"),
                    "nr": syscall.get("nr"), "syscall_call_id": syscall.get("call_id"),
                    "start_ns": syscall.get("start_ns"), "end_ns": syscall.get("end_ns"),
                    "pairing": syscall.get("pairing"), "result": syscall.get("result"), "objects": objects})
        edges.append(_edge("KERNEL_OPERATIONS", "内核线程 → 实际 syscall / 文件对象",
            "TRUNCATED" if omitted else "OBSERVED" if observations else "MISSING",
            [], syscall_count=len(observations), path_records=path_count, stable_object_records=stable_objects,
            syscalls_without_object_records=missing_objects, omitted_observations=omitted,
            reason="对象仅列出内核报告中已有的解析记录；没有对象的 syscall 不自动视为文件访问失败"))
        required = edges[1:]
        if any(edge["status"] == "CONFLICT" for edge in edges):
            status = "CONFLICT"
        elif any(edge["status"] in ("MISSING", "TRUNCATED", "MATCHED_NOT_REPLAYED") for edge in required):
            status = "PARTIAL"
        else:
            status = "LINKED_WITHIN_SELECTED_EVIDENCE"
        kernel_count = len(observations)
        summary = ("{} → {} → {} 条 syscall，{} 条文件路径证据".format(call.get("tool_name") or "工具",
                    "PID " + str(binding.get("root", {}).get("tid")) if isinstance(binding.get("root"), dict) else "未绑定进程",
                    kernel_count, path_count))
        if not kernel_count:
            summary += "；没有内核操作记录，不能声称已观察实际 Linux 行为"
        chains.append({"chain_id": "tool:" + call_id, "call_id": call_id, "tool_call_id": tool_id,
            "tool_name": call.get("tool_name"), "status": status, "summary": summary,
            "context": context, "edges": edges, "observations": observations})
    counts = Counter(chain["status"] for chain in chains)
    return {"schema_version": 1, "model": "EXPLICIT_APPLICATION_KERNEL_EVIDENCE_LINKS_V1",
        "status": "CONFLICT" if counts["CONFLICT"] else "PARTIAL" if counts["PARTIAL"]
                  else "LINKED_WITHIN_SELECTED_EVIDENCE" if chains else "NO_TOOL_CALLS",
        "summary": {"tool_calls": len(chains), "linked_calls": counts["LINKED_WITHIN_SELECTED_EVIDENCE"],
            "partial_calls": counts["PARTIAL"], "conflicting_calls": counts["CONFLICT"],
            "kernel_syscall_observations": observation_count,
            "context_links": sum(chain["context"] is not None for chain in chains)},
        "application_source_replay": source, "native_replay": native_replay,
        "operation_history_status": report.get("health", {}).get("status", "NOT_PROVIDED"),
        "timeline_status": report.get("critical_path", {}).get("status", "NOT_PROVIDED"),
        "chains": chains, "limitations": [
            "公开消息只提供同一 thread/turn 的有序上下文；不采集隐藏思维，也不证明真实决策因果",
            "字段匹配和 RPC 重放只证明所给证据相互一致；native 采集器、内核及外部摘要仍是信任边界",
            "LINKED 不表示所有 syscall 或对象完整覆盖；请同时查看 operation_history_status 和 timeline_status",
            "没有用时间相近、进程名或模型文字猜测工具与系统行为之间的归属",
            "外部 daemon、远端服务以及未注册执行域的效果不由本链条证明",
        ]}
