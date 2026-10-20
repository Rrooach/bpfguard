#!/usr/bin/env python3
"""Compile Agent/tool/kernel evidence into additive semantic flamegraph views.

Raw events remain the authority.  This module folds them into a profile in the
same spirit as a CPU profiler: every operation has a semantic stack and one or
more non-negative measures.  It never infers a Linux binding by timestamp.
"""
from __future__ import annotations

from pathlib import PurePosixPath


VIEW_DEFINITIONS = (
    ("wall_ms", "Agent 墙钟时间", "ms", "应用事件边界；模型/运行时空档尚未继续细分"),
    ("model_request_ms", "模型请求总耗时", "ms", "HTTP broker 明确请求边界；并发请求时长可重叠"),
    ("model_wait_ms", "模型首字节等待", "ms", "从上游发送到首个 body 字节，包含网络、排队与生成；不等于首个 token"),
    ("model_receive_ms", "模型响应接收", "ms", "首字节到上游响应结束"),
    ("v8_js_ms", "V8 JavaScript 执行段", "ms", "V8 dispatcher 中明确 runJS 段的墙钟，含 GC/调度；不是整个 Codex 运行时"),
    ("v8_tool_wait_ms", "Code Mode 等待工具", "ms", "工具等待区间并集，扣除明确 JS 执行段"),
    ("v8_thread_cpu_ms", "V8 主线程 CPU", "ms", "V8 运行时提供的真实线程 CPU 计数器差分"),
    ("memory_rss_byte_ms", "内存驻留量 × 时间", "byte_ms", "各注册 PID 的相邻 RSS 样本梯形积分；共享页可能重复计账"),
    ("observer_rss_byte_ms", "Observer 驻留量 × 时间", "byte_ms", "Observer 进程独立积分；不混入 Agent 内存"),
    ("oncpu_ms", "线程 CPU 运行时间", "ms", "目标 Linux sched_switch 区间之和；可超过墙钟"),
    ("runnable_ms", "等待 CPU 的时间", "ms", "目标 Linux 已就绪但尚未运行的线程时间之和"),
    ("sleep_ms", "睡眠/阻塞时间", "ms", "睡眠不自动等于磁盘等待；需下钻栈和文件证据"),
    ("syscall_time_ms", "syscall 墙钟累计", "ms", "成对 syscall 入口到返回；并发调用可重叠"),
    ("syscall_count", "syscall 次数", "次", "Observer 已选择且成功配对/保留的调用"),
    ("file_read_bytes", "文件／流实际返回字节", "bytes", "选定 VFS read 对象返回字节，可含管道／伪文件；不是文件大小或块设备读取量"),
    ("file_operations", "文件访问记录数", "次", "具有内核解析路径的选定调用"),
    ("memory_peak_bytes", "每工具内存峰值", "bytes", "仅新建独立工具 cgroup 可用；宽度为各工具峰值记录之和，不是 Agent 同时峰值"),
    ("cgroup_cpu_ms", "工具 cgroup CPU", "ms", "cpu.stat 边界差分；包括该工具 cgroup 全部后代"),
    ("minor_faults", "minor faults", "次", "新建工具 cgroup 的 (pgfault-pgmajfault) 边界差分"),
    ("major_faults", "major faults", "次", "新建工具 cgroup 的 memory.stat pgmajfault 边界差分"),
    ("io_read_bytes", "块层读取字节", "bytes", "新建工具 cgroup 的 io.stat rbytes 边界差分"),
    ("io_write_bytes", "块层写入字节", "bytes", "新建工具 cgroup 的 io.stat wbytes 边界差分"),
    ("tool_count", "工具调用次数", "次", "应用明确报告且绑定到 Linux 执行域的工具调用"),
    ("token_count", "模型 token", "tokens", "需要 provider/Codex usage 记录；当前输入未提供时保持不可用"),
)


def _frame(kind, label, **metadata):
    return {"kind": kind, "label": str(label), **metadata}


def _tool_label(tool):
    return "工具 {} · {}".format(tool.get("number", "?"), tool.get("tool_name", "tool"))


def _process_label(process):
    return "{} [pid {}]".format(process.get("comm") or "?", process.get("tgid") or "?")


def _task_stack(story, tool=None):
    result = [_frame("task", str(story.get("task_id") or "unknown task"))]
    if tool is not None:
        for label in tool.get("semantic_path", []) or ["未提供步骤标签（任务与命令已知）"]:
            result.append(_frame("semantic", label, quality=tool.get("semantic_quality")))
    return result


def _tool_frame(tool):
    return _frame("tool", _tool_label(tool), call_id=tool.get("call_id"),
        tool_call_id=tool.get("tool_call_id"), command=tool.get("command"), status=tool.get("status"))


def _code_mode_operations(operations, story, tools):
    by_call = {tool["call_id"]: tool for tool in tools if isinstance(tool.get("call_id"), str)}
    for invocation in story.get("code_mode", {}).get("invocations", []):
        call_id = invocation.get("call_id")
        tool = by_call.get(call_id)
        base = _task_stack(story, tool)
        if tool is not None:
            base.append(_tool_frame(tool))
        identity = {key: invocation.get(key) for key in
                    ("run_id", "agent_id", "task_id", "call_id", "runtime_id", "pid", "boot_id")}
        base.append(_frame("v8", "Code Mode", **identity))
        segments = invocation.get("segments") or []
        previous_end = None
        totals = {"JS": 0, "AWAIT": 0}
        measured_segments = set()
        for segment in segments:
            begin, end = segment.get("begin_ns"), segment.get("end_ns")
            if (type(begin) is not int or type(end) is not int or end < begin
                    or (previous_end is not None and begin < previous_end)):
                raise ValueError("Code Mode profile requires ordered non-overlapping measured segments")
            previous_end = end
            kind = segment.get("kind")
            if kind not in totals:
                continue  # OTHER is uninstrumented, never counted as JS.
            measure = "v8_js_ms" if kind == "JS" else "v8_tool_wait_ms"
            declared = invocation.get("js_ms" if kind == "JS" else "tool_wait_ms")
            if type(declared) not in (int, float) or declared < 0:
                continue
            duration = end - begin
            totals[kind] += duration
            measured_segments.add(kind)
            spans = segment.get("span_ids") or []
            metadata = {**identity, "begin_ns": begin, "end_ns": end,
                        "span_ids": spans, "child_call_ids": segment.get("child_call_ids") or []}
            if len(spans) == 1:
                metadata["span_id"] = spans[0]
            label = ("执行 JavaScript · " if kind == "JS" else "等待工具 · ") + str(segment.get("name") or kind)
            _add(operations, "code_mode_segment", base + [_frame("code_mode_phase", label, **metadata)],
                 {measure: duration / 1e6}, **metadata,
                 attribution="EXPLICIT_CODE_MODE_CALL_ID" if tool else "NO_MATCHING_APPLICATION_TOOL_CALL",
                 timing_scope="NON_OVERLAPPING_INSTRUMENTED_JS_OR_AWAIT_SEGMENT")
        for kind, measure, field in (("JS", "v8_js_ms", "js_ms"),
                                      ("AWAIT", "v8_tool_wait_ms", "tool_wait_ms")):
            declared = invocation.get(field)
            if type(declared) not in (int, float) or declared < 0:
                continue
            if segments and abs(totals[kind] / 1e6 - declared) > max(1e-9, abs(declared) * 1e-9):
                raise ValueError("Code Mode aggregate disagrees with measured segment partition")
            if kind not in measured_segments:
                # In particular, retain a measured zero even though the replay
                # partition contains no positive-width slice of this kind.
                _add(operations, "code_mode_aggregate", base + [_frame("code_mode_phase",
                     "JavaScript 已测量汇总" if kind == "JS" else "工具等待已测量汇总")],
                     {measure: declared}, **identity,
                     begin_ns=invocation.get("begin_ns", invocation.get("start_ns")),
                     end_ns=invocation.get("end_ns"), timing_scope="EXPLICIT_INVOCATION_AGGREGATE_NO_SEGMENT")
        # Thread CPU belongs to the invocation's instrumented synchronous
        # slices as a whole.  Do not duplicate it once per JS/await segment.
        _add(operations, "code_mode_thread_cpu", base + [_frame("resource", "已标注 JS 主线程 CPU 汇总")],
             {"v8_thread_cpu_ms": invocation.get("thread_cpu_ms")}, **identity,
             begin_ns=invocation.get("begin_ns", invocation.get("start_ns")),
             end_ns=invocation.get("end_ns"), timing_scope="INSTRUMENTED_JS_THREAD_CPU_COUNTER_DELTA")


def _positive(value):
    return type(value) in (int, float) and value > 0


def _add(operations, kind, stack, measures, **evidence):
    selected = {name: value for name, value in measures.items()
                if type(value) in (int,float) and value >= 0}
    if selected:
        operations.append({"kind": kind, "stack": stack, "measures": selected,
                           "evidence": evidence})


def operations_from_story(story):
    operations = []
    tools = story.get("tools", [])
    partition = story.get("wall_partition")
    if partition:
        by_call = {tool["call_id"]:tool for tool in tools}
        for segment in partition.get("segments",[]):
            base = _task_stack(story)
            for label in segment.get("semantic_path",[]):
                base.append(_frame("semantic",label))
            if len(segment.get("active_ids",[]))==1 and segment["active_ids"][0] in by_call:
                tool=by_call[segment["active_ids"][0]]
                base.append(_frame("tool",_tool_label(tool),call_id=tool["call_id"]))
            _add(operations,"wall_partition",base+[_frame("phase",segment["label"])],
                {"wall_ms":segment["duration_ns"]/1e6},begin_ns=segment["begin_ns"],end_ns=segment["end_ns"])
    for tool in tools:
        base = _task_stack(story, tool)
        tool_frame = _tool_frame(tool)
        gap = tool.get("agent_gap_before_ms")
        if not partition:
            _add(operations, "agent_gap", base + [_frame("agent_phase", "Agent/模型阶段"),
                 _frame("phase", "工具前思考或等待")], {"wall_ms": gap},
                 quality="MODEL_AND_RUNTIME_NOT_FURTHER_SEPARATED")
        for label, key in (("工具登记/派发", "request_to_execution_ms"),
                           ("Linux 执行", "execution_ms"),
                           ("结果返回 Agent", "result_delivery_ms")):
            if not partition:
                _add(operations, "tool_phase", base + [tool_frame, _frame("phase", label)],
                     {"wall_ms": tool.get(key)}, tool_call_id=tool.get("tool_call_id"))
        _add(operations, "tool_call", base + [tool_frame], {"tool_count": 1},
             tool_call_id=tool.get("tool_call_id"))

        process_index = {(row.get("tgid"), row.get("process_birth_ns")): row
                         for row in tool.get("process_profiles", []) if isinstance(row, dict)}
        for process in process_index.values():
            pframe = _frame("process", _process_label(process), tgid=process.get("tgid"))
            for thread in process.get("threads", []):
                tframe = _frame("thread", "{} [tid {}]".format(thread.get("comm") or "?",
                                                                thread.get("tid") or "?"),
                                tid=thread.get("tid"))
                states = thread.get("state_totals_ns", {})
                _add(operations, "thread_state", base + [tool_frame, pframe, tframe], {
                    "oncpu_ms": states.get("ONCPU", 0) / 1e6,
                    "runnable_ms": states.get("RUNNABLE", 0) / 1e6,
                    "sleep_ms": (states.get("SLEEP", 0) + states.get("WAKING", 0)) / 1e6,
                }, tool_call_id=tool.get("tool_call_id"))

        for row in tool.get("syscall_rows", []):
            process = process_index.get((row.get("tgid"), row.get("process_birth_ns")), {})
            pframe = _frame("process", _process_label(process or {"comm": row.get("comm"),
                "tgid": row.get("tgid")}), tgid=row.get("tgid"))
            category = row.get("category") or "other"
            call_stack = base + [tool_frame, pframe, _frame("syscall_category", category),
                                 _frame("syscall", row.get("name") or "unknown")]
            _add(operations, "syscall", call_stack, {"syscall_count": 1,
                 "syscall_time_ms": (row.get("duration_us") or 0) / 1000},
                 tid=row.get("tid"), result=row.get("result"), errno=row.get("errno"),
                 at_ms=row.get("at_ms"))
            paths = row.get("paths") or []
            if paths:
                path = paths[0]
                try:
                    short = PurePosixPath(path).name or path
                except (TypeError, ValueError):
                    short = str(path)
                _add(operations, "file", base + [tool_frame, pframe,
                     _frame("file", short, path=path)], {
                         "file_operations": 1,
                         "file_read_bytes": row.get("returned_bytes") or 0,
                     }, path=path, additional_paths=row.get("additional_paths", 0),
                     tid=row.get("tid"), syscall=row.get("name"))

        resources = tool.get("resources")
        if isinstance(resources, dict) and resources.get("scope", "").startswith("FRESH_EPHEMERAL_TOOL_CGROUP"):
            _add(operations, "tool_resources", base + [tool_frame, _frame("resource", "工具 cgroup")], {
                "memory_peak_bytes": resources.get("memory_peak_bytes"),
                "cgroup_cpu_ms": (resources.get("cpu_usage_usec") / 1000
                                    if type(resources.get("cpu_usage_usec")) is int and resources["cpu_usage_usec"]>=0 else None),
                "minor_faults": resources.get("minor_faults"),
                "major_faults": resources.get("major_faults"),
                "io_read_bytes": resources.get("io_read_bytes"),
                "io_write_bytes": resources.get("io_write_bytes"),
            }, scope=resources.get("scope"), status=resources.get("status"))

    for usage in story.get("model_usage", []):
        base = _task_stack(story)
        for label in usage.get("semantic_path", []) or ["未归属模型调用"]:
            base.append(_frame("semantic", label, quality=usage.get("attribution")))
        _add(operations, "model_usage", base + [_frame("model", "模型调用 #{}".format(
            usage.get("number", "?")), attribution=usage.get("attribution"))], {
                "token_count": usage.get("totalTokens"),
            }, input_tokens=usage.get("inputTokens"), output_tokens=usage.get("outputTokens"),
            cached_input_tokens=usage.get("cachedInputTokens"),
            reasoning_output_tokens=usage.get("reasoningOutputTokens"),
            source=usage.get("source"), at_ms=usage.get("at_ms"))

    for request in story.get("model_requests",[]):
        base=_task_stack(story)
        for label in request.get("semantic_path",[]):base.append(_frame("semantic",label))
        _add(operations,"model_request",base+[_frame("model",request["request_id"])],{
            "model_request_ms":request.get("request_ms"),"model_wait_ms":request.get("wait_first_byte_ms"),
            "model_receive_ms":request.get("response_receive_ms")},attribution=request.get("attribution"))
    _code_mode_operations(operations, story, tools)
    by_native_tool = {tool["tool_call_id"]: tool for tool in tools
                      if isinstance(tool.get("tool_call_id"), str)}
    memory=story.get("memory",{});prev={}
    for point in memory.get("series",[]):
        name=point["name"];before=prev.get(name);prev[name]=point
        if before is None or type(point.get("rss_bytes")) is not int or type(before.get("rss_bytes")) is not int:
            continue
        if (before.get("tool_call_id") != point.get("tool_call_id")
                or before.get("role") != point.get("role")):
            continue  # Never bridge two different target/attribution scopes.
        dt=point["at_ms"]-before["at_ms"]
        if dt <=0 or dt>3*(memory.get("interval_ms") or 100):continue
        is_observer=str(point.get("role","")).startswith("OBSERVER")
        tool = by_native_tool.get(point.get("tool_call_id")) if not is_observer else None
        if is_observer:
            frames = [_frame("resource", "Observer"), _frame("process", name)]
        else:
            frames = _task_stack(story, tool)
            if tool is not None:
                frames.append(_tool_frame(tool))
            frames.append(_frame("resource", name, tool_call_id=point.get("tool_call_id")))
        measure="observer_rss_byte_ms" if is_observer else "memory_rss_byte_ms"
        _add(operations,"memory_sample",frames,{
            measure:(point["rss_bytes"]+before["rss_bytes"])*.5*dt},scope=point.get("role"),
            boot_id=story.get("boot_id"), tool_call_id=point.get("tool_call_id"),
            sample_begin_at_ms=before["at_ms"], sample_end_at_ms=point["at_ms"],
            attribution="EXPLICIT_NATIVE_TOOL_CALL_ID" if tool else "REGISTERED_PROCESS_SCOPE_NOT_TOOL_ATTRIBUTED")

    if not partition:
        _add(operations, "agent_tail", _task_stack(story) + [_frame("agent_phase", "Agent 收尾")],
             {"wall_ms": story.get("trailing_agent_ms")}, quality="MODEL_AND_RUNTIME_NOT_FURTHER_SEPARATED")
    # Preserve the measured hierarchy: evidence links annotate exact call IDs,
    # never invent an intention/parent from overlapping timestamps or labels.
    chains = {chain.get("call_id"): chain for chain in
              story.get("decision_evidence", {}).get("chains", []) if isinstance(chain, dict)}
    for operation in operations:
        for frame in operation["stack"]:
            if frame.get("kind") != "tool":
                continue
            chain = chains.get(frame.get("call_id"))
            if chain is not None:
                frame["evidence_chain_id"] = chain.get("chain_id")
                frame["evidence_chain_status"] = chain.get("status")
                operation["evidence"]["evidence_chain_id"] = chain.get("chain_id")
    return operations


def _node(label, kind, metadata=None):
    return {"label": label, "kind": kind, "value": 0, "metadata": metadata or {}, "children": {}}


def _finish(node):
    children = [_finish(child) for child in node.pop("children").values()]
    children.sort(key=lambda child: (-child["value"], child["label"]))
    node["children"] = children
    return node


def fold_view(operations, measure, root_label):
    root = _node(root_label, "root")
    samples = 0
    for operation in operations:
        value = operation.get("measures", {}).get(measure)
        if type(value) not in (int,float) or value < 0:
            continue
        samples += 1
        root["value"] += value
        current = root
        for frame in operation["stack"]:
            key = (frame.get("kind"), frame.get("label"))
            child = current["children"].setdefault(key, _node(frame["label"], frame["kind"],
                {name: item for name, item in frame.items() if name not in ("label", "kind")}))
            child["value"] += value
            current = child
    return _finish(root), samples


def build_profile(story):
    operations = operations_from_story(story)
    views = []
    root_label = "Agent " + str(story.get("agent_id") or "unknown")
    for name, label, unit, quality in VIEW_DEFINITIONS:
        tree, samples = fold_view(operations, name, "Observer" if name=="observer_rss_byte_ms" else root_label)
        views.append({"name": name, "label": label, "unit": unit, "quality": quality,
                      "status": "AVAILABLE" if samples else "NOT_COLLECTED",
                      "sample_count": samples, "total": tree["value"], "tree": tree})
    return {"schema_version": 1, "model": "SEMANTIC_OPERATION_STACK_V1",
            "agent_id": story.get("agent_id"), "task_id": story.get("task_id"), "run_id": story.get("run_id"),
            "hierarchy": "Agent → task → Agent-reported semantic segment → tool → process/thread or object/system call",
            "semantic_quality": (story.get("semantic_annotations", {}).get("method")
                or "AGENT_REPORTED_PLAN_OR_UNANNOTATED; NOT_CROSS_RUN_STABLE_SEGMENTATION"),
            "semantic_annotations": story.get("semantic_annotations"),
            "attribution": "EXPLICIT_APPLICATION_CALL_ID_TO_OBSERVER_TOOL_ROOT; NO_TIMESTAMP_GUESSING",
            "operation_count": len(operations), "operations": operations, "views": views,
            "evidence_links": {key: story.get("decision_evidence", {}).get(key)
                               for key in ("status", "summary", "operation_history_status", "timeline_status")},
            "limitations": [
                "任务名称来自声明的方法（规则或审阅标注）；不是独立验证的真实意图，未知/混合阶段保留未分配",
                "模型/V8 必须有各自的明确计时记录；缺失的墙钟区间保持未细分，不猜测为模型思考",
                "sleep 不自动证明磁盘等待，syscall 累计时长和线程状态可能因并发超过墙钟",
                "旧证据没有新建工具 cgroup 资源边界时，内存、cgroup CPU、fault 和块 I/O 视图保持 NOT_COLLECTED",
                "token 视图只有绑定 provider/Codex usage 后才可用",
                "证据联系状态与采集完整度分开；公开消息到工具只代表有序上下文，不代表意图因果",
            ]}
