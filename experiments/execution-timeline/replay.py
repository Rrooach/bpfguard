#!/usr/bin/env python3
"""Rebuild per-thread state intervals and conservative tool completion paths.

This is not a scheduler simulation or a whole-system causal proof. A sleeping
parent is replaced by a child path ONLY for a completed wait4 whose result,
observed waker and observed child exit agree. Other sleepers keep their own
interval, with the observed call/file/stack and an explicitly limited reason.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import copy
import json
import re
import subprocess
import tempfile
from pathlib import Path

from common import canonical, check_artifacts, write_new

VERSION = 1
MAX_EVENTS = 2_000_000
MAX_LINE = 128 * 1024
SYSCALLS = {0: "read", 1: "write", 2: "open", 3: "close", 7: "poll", 9: "mmap", 15: "rt_sigreturn",
            17: "pread64", 19: "readv", 20: "writev", 23: "select", 24: "sched_yield",
            35: "nanosleep", 56: "clone", 57: "fork", 58: "vfork", 59: "execve",
            60: "exit", 61: "wait4", 78: "getdents", 202: "futex", 217: "getdents64",
            230: "clock_nanosleep", 231: "exit_group", 232: "epoll_wait", 247: "waitid",
            257: "openat", 270: "pselect6", 271: "ppoll", 281: "epoll_pwait",
            295: "preadv", 322: "execveat", 327: "preadv2", 435: "clone3", 437: "openat2",
            441: "epoll_pwait2", 449: "futex_waitv"}


def integer(value):
    return type(value) is int


def identity_key(task, boot_id):
    if not isinstance(task, dict):
        return None
    tid = task.get("tid")
    birth = task.get("thread_birth_ns", task.get("birth_ns"))
    if not integer(tid) or tid <= 0 or not integer(birth) or birth <= 0:
        return None
    return f"{boot_id}:{tid}:{birth}"


def load_events(path):
    rows = []
    with Path(path).open("rb") as source:
        while line := source.readline(MAX_LINE + 1):
            if len(line) > MAX_LINE or not line.endswith(b"\n"):
                raise ValueError("oversized or truncated event record")
            event = json.loads(line)
            if event.get("schema_version") != VERSION or not integer(event.get("timestamp_ns")):
                raise ValueError("unsupported or malformed timeline event")
            rows.append(event)
            if len(rows) > MAX_EVENTS:
                raise ValueError("offline event budget exceeded")
    return rows


class Symbols:
    def __init__(self, path=None):
        self.addresses, self.names, self.kinds, self.modules = [], [], [], []
        if path is not None and Path(path).exists():
            pairs = []
            with Path(path).open() as source:
                for line in source:
                    values = line.split()
                    if len(values) >= 3:
                        address = int(values[0], 16)
                        if address:
                            pairs.append((address, values[2], values[1], values[3] if len(values) > 3 else None))
            pairs.sort()
            self.addresses = [row[0] for row in pairs]
            self.names = [row[1] for row in pairs]
            self.kinds = [row[2] for row in pairs]
            self.modules = [row[3] for row in pairs]

    def resolve(self, values):
        output = []
        for value in values or []:
            if isinstance(value, str) and not value.startswith("0x"):
                output.append(value)
                continue
            address = int(value, 0) if isinstance(value, str) else value
            index = bisect.bisect_right(self.addresses, address) - 1
            if index < 0:
                output.append(hex(address))
                continue
            name = self.names[index]
            # kallsyms was saved BEFORE this recorder attached. A newly JITed
            # address may fall after an unrelated, older BPF program symbol.
            # Nearest address is not a function range or lifetime proof. Do
            # not remove that symbol and fall back to an even farther one.
            dynamic = re.match(r"^(?:bpf_prog_[0-9a-fA-F]{16}(?:_|$)|bpf_trampoline_[0-9]+(?:_|$)|ftrace_trampoline)", name)
            if dynamic or self.modules[index]:
                output.append(f"{hex(address)} (UNRESOLVED_DYNAMIC_JIT_OR_MODULE_RANGE)")
            elif self.kinds[index] not in {"t", "T", "w", "W"}:
                output.append(f"{hex(address)} (UNRESOLVED_NON_TEXT_RANGE)")
            else:
                output.append(f"{name}+0x{address - self.addresses[index]:x}")
        return output


def health_issues(health, events):
    issues = []
    # Counters with a genuine loss/error meaning, not any nonzero metadata.
    error_words = ("lost", "drop", "error", "failed", "overflow", "unpaired", "mismatch")
    def visit(value, prefix="health"):
        if isinstance(value, dict):
            for key, child in value.items():
                name = f"{prefix}.{key}"
                if integer(child) and child > 0 and any(word in key.lower() for word in error_words):
                    issues.append({"kind": "COLLECTION_GAP", "field": name, "count": child})
                elif isinstance(child, (list, dict)):
                    visit(child, name)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{prefix}[{index}]")
    visit(health)
    for field in ("cap_discarded", "recursion_misses", "kprobe_misses"):
        if integer(health.get(field)) and health[field]:
            issues.append({"kind": "COLLECTION_GAP", "field": field, "count": health[field]})
    if health.get("truncated_tail") is True or health.get("status") == "INCOMPLETE":
        issues.append({"kind": "COLLECTION_GAP", "field": "terminal_health", "status": health.get("status")})
    sequences = collections.defaultdict(list)
    for event in events:
        if not integer(event.get("cpu")) or not integer(event.get("cpu_seq")):
            issues.append({"kind": "MISSING_CPU_SEQUENCE"})
            continue
        sequences[event["cpu"]].append(event["cpu_seq"])
    for cpu, values in sequences.items():
        values.sort()
        if values[0] != 1 or any(b != a + 1 for a, b in zip(values, values[1:])):
            issues.append({"kind": "CPU_SEQUENCE_GAP_OR_DUPLICATE", "cpu": cpu})
    return issues


def _file_key(file):
    if (not isinstance(file, dict) or any(not integer(file.get(k)) or file[k] <= 0 for k in ("mount_id", "inode"))
            or any(not integer(file.get(k)) or file[k] < 0 for k in ("device", "generation"))):
        return None
    return tuple(file.get(name) for name in ("mount_id", "device", "inode", "generation"))


def seccomp_skip_closures(events, boot):
    """Recompute skipped-dispatch closures from two independent raw records.

    Never accept ENOSYS/EPERM or a JSON assertion without a matching kernel
    hook record. The proof time is not an unobserved syscall entry/duration.
    """
    pending, closures, findings = {}, set(), []
    def stable(event):
        task = event.get('task', {})
        return tuple(task.get(k) for k in ('tid', 'tgid', 'thread_birth_ns', 'process_birth_ns', 'cgroup_id'))
    for event in events:
        key = identity_key(event.get('task'), boot)
        kind, now = event.get('event'), event['timestamp_ns']
        if kind == 'SECCOMP_SKIP':
            args = event.get('args', [])
            valid = (key is not None and not event.get('flags', 0) and not event.get('syscall_call_id')
                     and event.get('start_ns') is None and event.get('end_ns') is None
                     and event.get('duration_ns') is None and integer(event.get('syscall_nr'))
                     and event['syscall_nr'] >= 0 and integer(event.get('return_value'))
                     and event.get('seccomp_skip_proof') == 'KERNEL_FEXIT_FILTER_FALSE_AND_SAVED_REGISTERS'
                     and event.get('seccomp_action') == 'UNKNOWN_NOT_OBSERVED'
                     and len(args) == 6 and args[0] in (0, 1) and not any(args[1:])
                     and event.get('seccomp_recheck_after_trace') is bool(args[0])
                     and all(integer(v) and v > 0 for v in stable(event)))
            if not valid or key in pending:
                findings.append({'kind': 'SECCOMP_SKIP_PROOF_INVALID', 'thread': key, 'at_ns': now})
            else:
                pending[key] = event
        elif kind == 'SYSCALL_ENTER' and key in pending:
            findings.append({'kind': 'SECCOMP_SKIP_HAS_RAW_ENTRY', 'thread': key, 'at_ns': now})
            pending.pop(key)
        elif kind == 'SYSCALL_EXIT':
            proof = pending.pop(key, None)
            skipped = event.get('seccomp_skipped_exit') is True
            args = event.get('args', [])
            valid = (skipped and proof is not None and stable(proof) == stable(event)
                     and event.get('flags') == 8388608 and not event.get('syscall_call_id')
                     and event.get('start_ns') is None and event.get('end_ns') is None
                     and event.get('duration_ns') is None and event.get('closure_kind') == 'SECCOMP_SKIPPED_WITHOUT_RAW_ENTRY'
                     and event.get('syscall_nr') == proof['syscall_nr']
                     and event.get('return_value') == proof['return_value']
                     and event.get('seccomp_skip_reference_ns') == proof['timestamp_ns'] < now
                     and len(args) == 6 and args[0] == proof['timestamp_ns'] and not any(args[1:]))
            if valid:
                closures.add((key, now))
            elif skipped or proof is not None:
                findings.append({'kind': 'SECCOMP_SKIP_CLOSURE_MISMATCH', 'thread': key, 'at_ns': now})
        elif kind in {'EXEC', 'EXIT'} and key in pending:
            findings.append({'kind': 'SECCOMP_SKIP_NOT_CLOSED', 'thread': key, 'at_ns': now})
            pending.pop(key)
    findings.extend({'kind': 'SECCOMP_SKIP_NOT_CLOSED', 'thread': key, 'at_ns': proof['timestamp_ns']}
                    for key, proof in pending.items())
    return closures, findings


def _reason(segment):
    state, call = segment["state"], segment.get("syscall") or {}
    if state == "ONCPU":
        return "线程在目标 Linux 上被调度执行；不是指令级 CPU 计量，虚拟机中可能夹杂中断或 Host 停调"
    if state == "RUNNABLE":
        return "线程已可运行，正在等待 CPU 调度"
    if state == "UNKNOWN":
        return "缺少足够事件，不能解释此区间"
    if state == "NEWBORN":
        return "已观察到线程创建，尚未观察到首次唤醒／运行；不是已就绪等 CPU"
    if state == "WAKING":
        return "源 CPU 已发起唤醒，目标尚未完成入队；这是唤醒处理／递送，不是文件读盘或已就绪等 CPU"
    stack = " ".join(segment.get("stack", []))
    if "folio_wait" in stack or "filemap_get_pages" in stack or "wait_on_page" in stack:
        return "页／页缓存等待栈；不能据此断言物理 SSD 饱和"
    if "pipe_read" in stack:
        return "管道读取等待；不是普通文件磁盘读取"
    if call.get("name") in {"wait4", "waitid"}:
        return "处于等待子进程的系统调用中"
    if call.get("name") in {"futex", "futex_waitv"}:
        return "处于线程同步等待中；未证明具体锁持有者"
    if call.get("name") in {"nanosleep", "clock_nanosleep"}:
        return "处于定时睡眠调用中"
    if call.get("name") in {"poll", "ppoll", "select", "pselect6", "epoll_wait", "epoll_pwait", "epoll_pwait2"}:
        return "处于事件／FD 就绪等待调用中"
    if call.get("name") in {"read", "pread64", "readv", "preadv", "preadv2"}:
        return "读取调用期间发生阻塞；准确下层原因见栈证据"
    if segment.get("sleep_state") == "STOPPED":
        return "线程被停止／启动屏障；不是 I/O 等待"
    return "线程睡眠／阻塞；未建立更具体原因"


def build_report(events, manifest, health, symbols=None, censored_contexts=None):
    symbols = symbols or Symbols()
    boot, begin, end = manifest.get("boot_id"), manifest.get("begin_ns"), manifest.get("end_ns")
    if (manifest.get("schema_version") != VERSION or not isinstance(boot, str) or not boot
            or not integer(begin) or not integer(end) or begin >= end):
        raise ValueError("complete boot-scoped run boundaries required")
    events = sorted(events, key=lambda e: (e["timestamp_ns"], e.get("cpu", 0), e.get("cpu_seq", 0)))
    findings = health_issues(health, events)
    seccomp_closures, seccomp_findings = seccomp_skip_closures(events, boot)
    findings.extend(seccomp_findings)
    censored = {}
    for context in censored_contexts or []:
        ck = (identity_key(context.get("task"), boot), context.get("syscall_call_id"))
        if ck[0] is None or ck in censored:
            raise ValueError("invalid/duplicate right-censored context")
        censored[ck] = context
    threads, per_thread = {}, collections.defaultdict(list)
    wake_attempts = {(identity_key(e.get("task"), boot), e["timestamp_ns"]): e
                     for e in events if e.get("event") == "WAKING"}
    def wake_source(event):
        reference = event.get("wake_attempt_ns")
        if integer(reference) and reference > 0:
            attempt = wake_attempts.get((identity_key(event.get("task"), boot), reference))
            if attempt is None or reference > event["timestamp_ns"]:
                findings.append({"kind": "WAKE_ORIGIN_REFERENCE_GAP", "at_ns": event["timestamp_ns"], "reference_ns": reference})
                return None, {"quality": "UNRESOLVED_WAKE_ORIGIN"}
            return identity_key(attempt.get("peer"), boot), {
                "quality": "KERNEL_WAKING_TO_WAKEUP_EXPLICIT_REFERENCE", "attempt_ns": reference,
                "origin": attempt.get("peer"), "immediate_context": event.get("peer")}
        return identity_key(event.get("peer"), boot), {
            "quality": "IMMEDIATE_WAKEUP_CONTEXT_ONLY_NOT_REMOTE_ORIGIN_PROOF", "immediate_context": event.get("peer")}
    outside_events = 0
    for event in events:
        if event.get("boot_id", boot) != boot:
            raise ValueError("event boot identity differs from run")
        key = identity_key(event.get("task"), boot)
        if key is None:
            findings.append({"kind": "UNRESOLVED_TASK_IDENTITY", "event": event.get("event")})
            continue
        if event["timestamp_ns"] > end:
            outside_events += 1
            continue
        actor = event["task"]
        if key not in threads:
            threads[key] = {"key": key, "tid": actor["tid"], "tgid": actor.get("tgid"),
                            "birth_ns": actor.get("thread_birth_ns", actor.get("birth_ns")),
                            "process_birth_ns": actor.get("process_birth_ns"),
                            "comm": actor.get("comm", ""), "parent_key": None,
                            "capture_observed_begin_ns": event['timestamp_ns'],
                            "begin_ns": max(begin, event["timestamp_ns"]), "end_ns": end,
                            "segments": [], "calls": [], "tool_call_id": None, "agent_id": None}
        thread = threads[key]
        if (actor.get("tgid") != thread["tgid"] or actor.get("process_birth_ns") != thread["process_birth_ns"]):
            findings.append({"kind": "IDENTITY_CONFLICT", "thread": key, "event": event.get("event"),
                             "observed_tgid": actor.get("tgid"), "observed_process_birth_ns": actor.get("process_birth_ns")})
        if actor.get("comm") and actor["comm"] != thread["comm"]:
            thread.setdefault("comm_history", []).append({"timestamp_ns": event["timestamp_ns"], "comm": actor["comm"]})
            thread["comm"] = actor["comm"]
        if event.get("event") == "FORK":
            parent = identity_key(event.get("peer"), boot)
            if thread["parent_key"] is not None and thread["parent_key"] != parent:
                findings.append({"kind": "CONFLICTING_PARENT", "thread": key})
            thread["parent_key"] = parent
            thread["fork_event"] = event
        if event.get("event") == "EXEC" and event.get("old_tid") not in (None, 0, actor["tid"]):
            # de_thread() may replace BOTH the TID and start_boottime with
            # those of the former group leader. The post-exec birth plus old
            # TID is not an identity proof, even if it happens to match an
            # earlier task. This ABI does not carry the immutable pre-exec
            # task identity: disclose the unsupported transition, never guess
            # a parent/continuation or silently merge it into a green trace.
            findings.append({"kind": "IDENTITY_TRANSITION_UNRESOLVED", "thread": key,
                             "at_ns": event["timestamp_ns"], "old_tid": event["old_tid"],
                             "reason": "NONLEADER_EXEC_REQUIRES_EXPLICIT_PRE_EXEC_LIFETIME_BRIDGE"})
        per_thread[key].append(event)

    tools = copy.deepcopy(manifest.get("tools", []))
    seen_tools = set()
    for tool in tools:
        if (not isinstance(tool.get("agent_id"), str) or not isinstance(tool.get("tool_call_id"), str)
                or tool["tool_call_id"] in seen_tools
                or not integer(tool.get("begin_ns")) or not integer(tool.get("end_ns"))
                or not begin <= tool["begin_ns"] < tool["end_ns"] <= end):
            raise ValueError("unique, explicit runtime tool spans within run required")
        seen_tools.add(tool["tool_call_id"])
        if tool.get("invocation_ns") is not None and (not integer(tool["invocation_ns"])
                                                       or not begin <= tool["invocation_ns"] <= tool["begin_ns"]):
            raise ValueError("tool invocation must precede release within run")
        root = tool.get("root", {})
        key = identity_key(root, boot)
        if key is None:
            candidates = []
            for candidate, thread in threads.items():
                if thread["tid"] != root.get("tid"):
                    continue
                hz, ticks = root.get("clock_ticks"), root.get("start_ticks")
                tick_match = integer(hz) and hz > 0 and integer(ticks) and thread["birth_ns"] * hz // 1_000_000_000 == ticks
                evidence_before_release = any(e["timestamp_ns"] <= tool["begin_ns"]
                                              and e.get("caller_cgroup_id") == tool.get("cgroup_id")
                                              for e in per_thread[candidate])
                if tick_match and evidence_before_release:
                    candidates.append(candidate)
            key = candidates[0] if len(candidates) == 1 else None
        if key not in threads:
            key = None
            findings.append({"kind": "UNRESOLVED_TOOL_ROOT", "tool_call_id": tool["tool_call_id"]})
        tool["root_key"] = key
        tool["association"] = "RUNTIME_GATE_AND_KERNEL_LIFETIME" if key else "UNRESOLVED"

    # Propagate only explicit tool roots and kernel-observed fork ancestry.
    root_tools = {t["root_key"]: t for t in tools if t["root_key"]}
    def owner(key):
        path, current = set(), key
        while current in threads and current not in path:
            if current in root_tools:
                return root_tools[current]
            path.add(current)
            current = threads[current]["parent_key"]
        return None
    for key, thread in threads.items():
        tool = owner(key)
        if tool:
            thread.update({name: tool.get(name) for name in ("agent_id", "tool_call_id", "task_id")})
            thread["begin_ns"] = max(thread["begin_ns"], tool["begin_ns"])
        else:
            findings.append({"kind": "THREAD_NOT_BOUND_TO_TOOL", "thread": key})

    for key, thread in threads.items():
        rows = per_thread[key]
        # A setup descendant can complete its entire lifetime before release.
        # Preserve it as capture context with an EMPTY execution intersection,
        # instead of assigning it a negative, release-clipped lifetime.
        exit_seen = False
        for row in rows:
            if row.get('event') == 'EXIT':
                exit_seen = True
            if (exit_seen and row.get('event') == 'SWITCH_OUT'
                    and row.get('prev_state', 0) & 0x80 and not row.get('preempt', False)):
                if row['timestamp_ns'] < thread['begin_ns']:
                    thread['begin_ns'] = thread['capture_observed_begin_ns']
                    thread['timeline_scope'] = 'CAPTURE_CONTEXT_OUTSIDE_EXECUTION_WINDOW'
                break
        calls, objects, reads = {}, collections.defaultdict(list), collections.defaultdict(list)
        for event in rows:
            kind, call_id = event.get("event"), event.get("syscall_call_id")
            if kind == "SYSCALL_ENTER":
                if call_id in calls:
                    findings.append({"kind": "DUPLICATE_SYSCALL_ENTRY", "thread": key, "call_id": call_id})
                nr = event.get("syscall_nr")
                calls[call_id] = {"call_id": call_id, "nr": nr, "name": SYSCALLS.get(nr, f"syscall_{nr}"),
                                  "start_ns": event["timestamp_ns"], "end_ns": None,
                                  "args": event.get("args", []), "result": None, "files": [],
                                  "pairing": "UNPAIRED"}
            elif kind == "SYSCALL_EXIT":
                call = calls.get(call_id)
                if call is None:
                    earlier_syscalls = any(e.get("event") in {"SYSCALL_ENTER", "SYSCALL_EXIT"}
                                           and e["timestamp_ns"] < event["timestamp_ns"] for e in rows)
                    earlier_forks = [e for e in rows if e.get("event") == "FORK" and e["timestamp_ns"] < event["timestamp_ns"]]
                    proven_forks = [e for e in earlier_forks
                                    if e.get('fork_parent_syscall_nr') == event.get('syscall_nr')
                                    and (integer(e.get('fork_parent_call_id')) and e['fork_parent_call_id'] > 0
                                         or e.get('fork_parent_syscall_source') == 'KERNEL_PT_REGS_AT_FORK_NO_ENTRY_EVENT')]
                    disclosed_boundary = (event.get("boundary_return") is True and not call_id and not earlier_syscalls
                                          and not earlier_forks and (thread["tool_call_id"] is None
                                                                   or event["timestamp_ns"] < thread["begin_ns"]))
                    disclosed_fork = (event.get("fork_child_return") is True and not call_id and not earlier_syscalls
                                      and event.get("syscall_nr") in {56, 57, 58, 435}
                                      and event.get("return_value", event.get("result")) == 0 and proven_forks)
                    disclosed_seccomp = (key, event['timestamp_ns']) in seccomp_closures
                    if not disclosed_boundary and not disclosed_fork and not disclosed_seccomp:
                        findings.append({"kind": "ORPHAN_SYSCALL_EXIT", "thread": key, "call_id": call_id})
                else:
                    signal_restore = (event.get("sigreturn_restored") is True and call["nr"] == 15
                                      and event.get("syscall_nr") == -1
                                      and event.get("syscall_entry_nr") == 15
                                      and event.get("closure_kind") == "SIGNAL_FRAME_RESTORED_NOT_ORDINARY_RETURN")
                    if event.get("syscall_nr") != call["nr"] and not signal_restore:
                        findings.append({"kind": "SYSCALL_NUMBER_MISMATCH", "thread": key, "call_id": call_id})
                    call.update(end_ns=event["timestamp_ns"], result=event.get("return_value", event.get("result")), pairing="PAIRED")
                    if signal_restore:
                        call.update(pairing="SIGNAL_FRAME_RESTORED_NOT_ORDINARY_RETURN", result=None,
                                    observed_exit_syscall_nr=-1, restored_register_value=event.get("restored_register_value"))
            elif kind == "FILE_OBJECT" and call_id:
                objects[call_id].append(event.get("file") or {})
            elif kind == "FILE_READ" and call_id:
                reads[call_id].append(event)
        for call_id, call in calls.items():
            for read in reads[call_id]:
                file = copy.deepcopy(read.get("file") or {})
                object_key = _file_key(file)
                candidates = [f for f in objects[call_id] if object_key is not None and _file_key(f) == object_key]
                path_versions = {json.dumps(f, sort_keys=True) for f in candidates}
                if len(path_versions) == 1:
                    file.update(candidates[0])
                elif len(path_versions) > 1:
                    file["path_quality"] = "AMBIGUOUS_PATH_OBSERVATIONS"
                    file["observed_paths"] = candidates
                file["read"] = {name: read.get(name) for name in
                                ("start_ns", "end_ns", "requested_bytes", "returned_bytes", "result")}
                file["read"]["result"] = read.get("return_value", read.get("result"))
                file["evidence"] = "VFS_READ_INTERVAL_AND_SAME_CALL_OBJECT"
                call["files"].append(file)
            if call["end_ns"] is None:
                context = censored.pop((key, call_id), None)
                if context:
                    if context.get("syscall_nr") != call["nr"] or context.get("args") != call["args"]:
                        raise ValueError("right-censored context differs from raw syscall entry")
                    call["pairing"] = "RIGHT_CENSORED_AT_CAPTURE_BOUNDARY"
                    call["capture_boundary"] = context
                    baseline = next((row for row in manifest.get("baseline_threads", [])
                                     if row.get("tid") == thread["tid"] and integer(row.get("clock_ticks"))
                                     and thread["birth_ns"] * row["clock_ticks"] // 1_000_000_000 == row.get("start_ticks")), None)
                    if baseline and thread["tool_call_id"] is None:
                        call["censor_scope"] = "DECLARED_BASELINE_THREAD_NOT_AGENT_TOOL"
                        continue
                    findings.append({"kind": "NONBASELINE_RIGHT_CENSORED_SYSCALL", "thread": key, "call_id": call_id})
                    continue
                # exec/exit deliberately do not return as ordinary syscalls.
                terminal = call["name"] in {"execve", "execveat", "exit", "exit_group"} and any(
                    e.get("event") in {"EXEC", "EXIT"} and e["timestamp_ns"] >= call["start_ns"] for e in rows)
                if terminal:
                    call["pairing"] = "LIFECYCLE_TERMINATED_NONRETURNING_CALL"
                else:
                    findings.append({"kind": "UNPAIRED_SYSCALL_ENTRY", "thread": key, "call_id": call_id})
        thread["calls"] = sorted(calls.values(), key=lambda c: c["start_ns"])
        thread['execs'] = []
        for event in rows:
            if event.get('event') != 'EXEC':
                continue
            quality = event.get('exec_filename_quality', 'NOT_CAPTURED')
            filename = event.get('exec_filename') if quality == 'KERNEL_EXEC_FILENAME_NOT_CANONICAL_PATH' else None
            thread['execs'].append({'timestamp_ns': event['timestamp_ns'], 'old_tid': event.get('old_tid'),
                'filename': filename, 'filename_quality': quality,
                'file': copy.deepcopy(event.get('file')),
                'executable_identity_quality': event.get('exec_object_quality', 'NOT_CAPTURED'),
                'evidence': 'KERNEL_SCHED_PROCESS_EXEC_SUCCESS',
                'argv': None, 'argv_quality': 'NOT_CAPTURED',
                'scope': 'ACTUAL_SUCCESSFUL_EXEC; FILENAME_NOT_CANONICAL; FILE_MAY_BE_SCRIPT_INTERPRETER'})
        thread['seccomp_skips'] = [dict(observed_at_ns=e['timestamp_ns'], syscall_nr=e['syscall_nr'],
                                       result=e.get('return_value'), action='UNKNOWN_NOT_OBSERVED',
                                       syscall_entry_ns=None, syscall_duration_ns=None,
                                       evidence='KERNEL_FEXIT_FILTER_FALSE_AND_SAVED_REGISTERS')
                                   for e in rows if e.get('event') == 'SECCOMP_SKIP']
        # Look up the active operation by kernel call id, never time proximity
        # alone. Read intervals refine which file was active during a sleep.
        state, cursor, context = "UNKNOWN", thread["begin_ns"], {}
        exited_at, terminal_switch_ns, clear_child_tid = None, None, None
        def append(stop):
            nonlocal cursor
            stop = min(stop, thread["end_ns"])
            if stop <= cursor:
                return
            segment = {"begin_ns": cursor, "end_ns": stop, "state": state,
                       "sleep_state": context.get("sleep_state"), "cpu": context.get("cpu"),
                       "stack": context.get("stack", []), "files": [],
                       "evidence": {"sources": ["SCHEDULER_EVENT_STREAM"],
                                    "quality": "UNKNOWN" if state == "UNKNOWN" else "RECORDED_TRANSITIONS"}}
            call = calls.get(context.get("call_id"))
            if call:
                segment["syscall"] = {k: v for k, v in call.items() if k != "files"}
                segment["files"] = [f for f in call["files"]
                                    if integer(f["read"].get("start_ns")) and integer(f["read"].get("end_ns"))
                                    and f["read"]["start_ns"] < stop and f["read"]["end_ns"] > cursor]
            if context.get("waker_key"):
                segment["waker_key"] = context["waker_key"]
            segment["reason"] = _reason(segment)
            thread["segments"].append(segment)
            cursor = stop
        for event in rows:
            timestamp, kind = event["timestamp_ns"], event.get("event")
            if timestamp > thread["end_ns"]:
                break
            if kind == "EXIT":
                exited_at = timestamp
                clear_child_tid = event.get("clear_child_tid")
                continue
            if kind not in {"SWITCH_IN", "SWITCH_OUT", "WAKEUP", "FORK"}:
                continue
            invalid = ((kind == "SWITCH_IN" and state in {"ONCPU", "SLEEP", "NEWBORN"})
                       or (kind == "SWITCH_OUT" and state in {"RUNNABLE", "SLEEP", "NEWBORN"}))
            if invalid and timestamp >= thread["begin_ns"]:
                findings.append({"kind": "STATE_TRANSITION_GAP", "thread": key, "at_ns": timestamp,
                                 "previous_state": state, "event": kind})
                # The missing wakeup/switch boundary may lie anywhere in the
                # preceding interval. Do not silently turn all of it into CPU
                # queueing or sleeping merely because its endpoint is known.
                state = "UNKNOWN"
            if kind == "WAKEUP" and state in {"RUNNABLE", "ONCPU"}:
                # Duplicate wakeups do not reset a runqueue interval.
                continue
            append(timestamp)
            if kind == "SWITCH_IN":
                state, context = "ONCPU", {"cpu": event.get("cpu")}
            elif kind == "SWITCH_OUT":
                raw = event.get("state", "UNKNOWN")
                state = "RUNNABLE" if raw == "RUNNABLE" else "SLEEP" if raw in {"SLEEP_D", "SLEEP_S", "STOPPED"} else "UNKNOWN"
                context = {"sleep_state": raw, "call_id": event.get("syscall_call_id"),
                           "cpu": event.get("cpu"), "stack": symbols.resolve(event.get("kernel_stack", []))}
                # sched_process_exit is EARLY: exit_mm/exit_files/exit_notify
                # may still block or be preempted. Only TASK_DEAD deschedule
                # establishes the terminal scheduler boundary.
                if exited_at is not None and event.get("prev_state", 0) & 0x80 and not event.get("preempt", False):
                    terminal_switch_ns = timestamp
                    thread["end_ns"] = min(thread["end_ns"], timestamp)
                    cursor = thread["end_ns"]
                    break
            elif kind == "WAKEUP":
                waker_key, wake_evidence = wake_source(event)
                if thread["segments"] and thread["segments"][-1]["state"] == "SLEEP":
                    thread["segments"][-1]["waker_key"] = waker_key
                    thread["segments"][-1]["wakeup_ns"] = timestamp
                    thread["segments"][-1]["wake_evidence"] = wake_evidence
                    last = thread["segments"][-1]
                    attempt = wake_evidence.get("attempt_ns")
                    if integer(attempt) and attempt <= timestamp:
                        last["dependency_handoff_ns"] = attempt
                        if last["begin_ns"] < attempt < last["end_ns"]:
                            tail = copy.deepcopy(last)
                            last["end_ns"] = attempt
                            tail.update(begin_ns=attempt, state="WAKING")
                            tail["reason"] = _reason(tail)
                            tail["evidence"] = {"sources": ["SCHED_WAKING", "SCHED_WAKEUP", "EXPLICIT_TARGET_LIFETIME_REFERENCE"],
                                                "quality": "RECORDED_TRANSITIONS"}
                            thread["segments"].append(tail)
                        elif attempt <= last["begin_ns"]:
                            last["state"] = "WAKING"
                            last["reason"] = _reason(last)
                state, context = "RUNNABLE", {"waker_key": waker_key}
            else:
                state, context = "NEWBORN", {}
        append(thread["end_ns"])
        thread["exit_ns"] = exited_at
        thread["exit_hook_semantics"] = "EARLY_SCHED_PROCESS_EXIT_NOT_TERMINAL_DESCHEDULE"
        thread["terminal_switch_ns"] = terminal_switch_ns
        thread["clear_child_tid"] = clear_child_tid
        tool = owner(key)
        if tool:
            lo, hi = max(thread['begin_ns'], tool['begin_ns']), min(thread['end_ns'], tool['end_ns'])
            thread['execution_window_intersection'] = {
                'status': 'NONEMPTY' if hi > lo else 'EMPTY_PRE_EXEC_TOOL_SETUP' if thread['end_ns'] <= tool['begin_ns'] else 'EMPTY_AFTER_TOOL_WINDOW',
                'begin_ns': lo if hi > lo else None, 'end_ns': hi if hi > lo else None,
                'scope': 'FORK_ANCESTRY_OWNERSHIP_IS_NOT_TIME_SPENT_EXECUTING_AGENT_TOOL; CAPTURE_LIFETIME_RETAINED'}
        if tool and (exited_at is None or exited_at > tool["end_ns"]):
            findings.append({"kind": "TOOL_DESCENDANT_OUTLIVES_RETURN_OR_LIFECYCLE_UNCLOSED", "thread": key,
                             "tool_call_id": tool["tool_call_id"], "tool_return_ns": tool["end_ns"], "exit_ns": exited_at})
        if tool and terminal_switch_ns is None:
            findings.append({"kind": "TOOL_TERMINAL_SWITCH_NOT_OBSERVED", "thread": key, "exit_hook_ns": exited_at})
        thread["state_totals_ns"] = dict(collections.Counter())
        for segment in thread["segments"]:
            state_totals = thread["state_totals_ns"]
            state_totals[segment["state"]] = state_totals.get(segment["state"], 0) + segment["end_ns"] - segment["begin_ns"]
        if thread["segments"] and sum(thread["state_totals_ns"].values()) != thread["end_ns"] - thread["begin_ns"]:
            raise ValueError("thread partition does not close")
    if censored:
        raise ValueError("right-censored context has no matching raw unclosed syscall entry")

    # A parent's clone/fork return is expressed in that parent's PID namespace.
    # Bind it to the child ONLY through the kernel-recorded parent-call
    # reference on FORK. A host PID comparison or time-nearest syscall is not a
    # valid substitute when tools run inside a container PID namespace.
    process_leaders = {}
    for key, thread in threads.items():
        if thread["tid"] == thread["tgid"]:
            process_leaders[(thread["tgid"], thread["process_birth_ns"])] = thread
        fork = thread.get("fork_event") or {}
        reference = fork.get("fork_parent_call_id")
        parent = threads.get(thread.get("parent_key"))
        if parent and integer(reference) and reference > 0:
            call = next((c for c in parent["calls"] if c["call_id"] == reference), None)
            if (call and call["nr"] in {56, 57, 58, 435} and call["nr"] == fork.get("fork_parent_syscall_nr")
                    and call["pairing"] == "PAIRED" and integer(call["result"]) and call["result"] > 0
                    and call["start_ns"] <= fork["timestamp_ns"] <= call["end_ns"]):
                thread["visible_pid_to_parent"] = call["result"]
                thread["pid_binding"] = {"basis": "KERNEL_FORK_REFERENCE_AND_PARENT_CLONE_RESULT",
                                         "parent_thread_key": parent["key"], "parent_call_id": reference}

    # A global transport gap prevents an exact state claim even if remaining
    # transitions happen to form a visually plausible path.
    transport_gap = any(f["kind"] in {"COLLECTION_GAP", "CPU_SEQUENCE_GAP_OR_DUPLICATE", "MISSING_CPU_SEQUENCE",
                                      "STATE_TRANSITION_GAP", "IDENTITY_CONFLICT", "IDENTITY_TRANSITION_UNRESOLVED",
                                      "SYSCALL_NUMBER_MISMATCH"} for f in findings)
    transport_gap = transport_gap or any(f["kind"] == "WAKE_ORIGIN_REFERENCE_GAP" for f in findings)
    transport_gap = transport_gap or any(f['kind'].startswith('SECCOMP_SKIP_') for f in findings)
    if transport_gap:
        for thread in threads.values():
            for segment in thread["segments"]:
                segment["evidence"]["quality"] = "GAPPED_TRACE_CANDIDATE_ONLY"

    completions = []
    for tool in tools:
        path, edges = [], []
        left = tool["begin_ns"]
        def walk(key, right, visited):
            if right <= left:
                return []
            node = (key, right)
            if key not in threads or node in visited or len(visited) > 512:
                return [{"begin_ns": left, "end_ns": right, "state": "UNKNOWN", "thread_key": key,
                         "reason": "工具线程关联缺失、依赖成环或深度超出预算"}]
            thread = threads[key]
            visited = visited | {node}
            output, pos = [], max(left, min(right, thread["begin_ns"]))
            for segment in thread["segments"]:
                lo, hi = max(pos, segment["begin_ns"]), min(right, segment["end_ns"])
                if hi <= lo:
                    continue
                if lo > pos:
                    output.append({"begin_ns": pos, "end_ns": lo, "state": "UNKNOWN", "thread_key": key,
                                   "reason": "该线程没有覆盖此区间的事件"})
                output.append({**segment, "begin_ns": lo, "end_ns": hi, "thread_key": key})
                pos = hi
            if pos < right:
                owned = [t for t in threads.values() if t.get("tool_call_id") == tool["tool_call_id"]]
                is_return = (integer(thread.get("exit_ns")) and pos >= thread["exit_ns"]
                             and all(integer(t.get("terminal_switch_ns")) and t["terminal_switch_ns"] <= pos for t in owned))
                output.append({"begin_ns": pos, "end_ns": right,
                               "state": "RUNTIME_RETURN" if is_return else "UNKNOWN", "thread_key": key,
                               "reason": "线程退出至运行时确认结束的区间；不算工作线程 CPU 时间" if is_return else "缺少状态证据"})
            # Trace BACKWARDS from completion. Following a later blocking join
            # replaces the entire earlier prefix with the child's history,
            # including its fork ancestry. Replacing only the parent's sleep
            # would incorrectly count an earlier, parallel child's hidden wait
            # as part of the final completion path.
            for index in range(len(output) - 1, -1, -1):
                segment = output[index]
                call, waker = segment.get("syscall") or {}, segment.get("waker_key")
                child = threads.get(waker)
                child_process = process_leaders.get((child["tgid"], child["process_birth_ns"])) if child else None
                creator = threads.get(child_process.get("parent_key")) if child_process else None
                parent_process_match = (creator and creator["tgid"] == thread["tgid"]
                                        and creator["process_birth_ns"] == thread["process_birth_ns"])
                namespace_pid_match = (child_process and child_process.get("visible_pid_to_parent") == call.get("result"))
                # Older raw ABI records without explicit clone linkage can be
                # used only in a declared DIRECT host PID namespace contract.
                direct_scope = manifest.get("scope", {}).get("kind") == "COOPERATIVE_DIRECT_CGROUP_DESCENDANTS"
                legacy_host_match = (direct_scope and child and child["tgid"] == call.get("result")
                                     and child.get("parent_key") == key)
                args = call.get("args") or []
                release = segment.get("dependency_handoff_ns", segment.get("wakeup_ns"))
                complete_sleep = (segment["state"] in {"SLEEP", "WAKING"} and integer(release)
                                  and release <= segment["end_ns"] and segment.get("wakeup_ns") is not None)
                verified_thread_join = (complete_sleep and call.get("name") == "futex"
                                        and len(args) >= 2 and args[1] & 127 in {0, 9}
                                        and call.get("result") == 0 and child
                                        and child.get("tgid") == thread.get("tgid")
                                        and child.get("process_birth_ns") == thread.get("process_birth_ns")
                                        and integer(child.get("clear_child_tid")) and child["clear_child_tid"] > 0
                                        and args[0] == child["clear_child_tid"]
                                        and integer(child.get("exit_ns"))
                                        and call["start_ns"] <= child["exit_ns"] <= release)
                verified_wait = (not transport_gap and complete_sleep
                                 and call.get("name") == "wait4"
                                 and integer(call.get("result")) and call["result"] > 0
                                 and child and ((namespace_pid_match and parent_process_match) or legacy_host_match)
                                 and child.get("tool_call_id") == tool["tool_call_id"]
                                 and integer(child.get("exit_ns")) and integer(call.get("end_ns"))
                                 and call["start_ns"] <= child["exit_ns"] <= release <= call["end_ns"]
                                 and child["begin_ns"] < release)
                if verified_wait or (not transport_gap and verified_thread_join
                                     and child.get("tool_call_id") == tool["tool_call_id"]):
                    edges.append({"from_thread": key, "to_thread": waker,
                                  "begin_ns": child["begin_ns"], "end_ns": release,
                                  "parent_sleep_begin_ns": segment["begin_ns"],
                                  "basis": "BACKWARD_WAIT4_RESULT_AND_KERNEL_WAKER_AND_CHILD_EXIT" if verified_wait else
                                           "BACKWARD_FUTEX_WAIT_RESULT_AND_WAKER_EXIT_CLEAR_CHILD_TID",
                                  "call_id": call["call_id"]})
                    # Source WAKING precedes remote target WAKEUP. The child
                    # need only cover up to issuing the wake, not an IPI tail
                    # after it has already exited. Preserve the target's
                    # observed processing between these two explicit events.
                    between = []
                    for prior in output[:index]:
                        lo, hi = max(release, prior["begin_ns"]), min(segment["begin_ns"], prior["end_ns"])
                        if hi > lo:
                            between.append({**prior, "begin_ns": lo, "end_ns": hi})
                    if segment["end_ns"] > max(release, segment["begin_ns"]):
                        tail = {**segment, "begin_ns": max(release, segment["begin_ns"]), "state": "WAKING"}
                        tail["reason"] = _reason(tail)
                        between.append(tail)
                    return walk(waker, release, visited) + between + output[index + 1:]
            origin = min(right, max(left, thread["begin_ns"]))
            if origin > left:
                parent = thread.get("parent_key")
                if parent in threads and threads[parent].get("tool_call_id") == tool["tool_call_id"]:
                    edges.append({"from_thread": key, "to_thread": parent, "at_ns": origin,
                                  "basis": "KERNEL_FORK_ORIGIN_PREFIX"})
                    prefix = walk(parent, origin, visited)
                else:
                    prefix = [{"begin_ns": left, "end_ns": origin, "state": "UNKNOWN", "thread_key": key,
                               "reason": "线程开始前没有可验证的创建／运行状态证据"}]
                return prefix + output
            return output
        seed = tool.get("root_key")
        owned = [t for t in threads.values() if t.get("tool_call_id") == tool["tool_call_id"]]
        if tool.get("cgroup_empty") is True and owned and all(integer(t.get("terminal_switch_ns")) for t in owned):
            seed = max(owned, key=lambda t: t["end_ns"])["key"]
        path = walk(seed, tool["end_ns"], set())
        sums = collections.Counter()
        for segment in path:
            sums[segment["state"]] += segment["end_ns"] - segment["begin_ns"]
        wall = tool["end_ns"] - tool["begin_ns"]
        if sum(sums.values()) != wall or any(a["end_ns"] != b["begin_ns"] for a, b in zip(path, path[1:])):
            raise ValueError("tool completion-path wall-clock partition does not close")
        completions.append({"tool_call_id": tool["tool_call_id"], "wall_ns": wall, "segments": path,
                            "state_totals_ns": dict(sums), "accounted_ns": wall - sums["UNKNOWN"],
                            "unknown_ns": sums["UNKNOWN"], "dependency_edges": edges,
                            "completion_seed_thread": seed,
                            "status": "INCOMPLETE" if transport_gap or sums["UNKNOWN"] or any(t.get("terminal_switch_ns") is None for t in owned)
                                      else "RECONSTRUCTED_WITHIN_SELECTED_MODEL",
                            "scope": "BACKWARD_FORK_WAIT4_COMPLETION_PATH_NOT_GENERAL_CAUSAL_OR_COUNTERFACTUAL_PROOF"})
    return {"schema_version": VERSION, "run": {"run_id": manifest.get("run_id"), "boot_id": boot,
            "begin_ns": begin, "end_ns": end, "clock": "CLOCK_MONOTONIC"}, "tools": tools,
            "threads": sorted(threads.values(), key=lambda t: (t.get("tool_call_id") or "", t["begin_ns"], t["tid"])),
            "health": health, "findings": findings,
            "critical_path": {"status": "INCOMPLETE" if any(t["status"] == "INCOMPLETE" for t in completions) else "RECONSTRUCTED_WITHIN_SELECTED_MODEL",
                              "tools": completions},
            "totals": {"events": len(events), "threads": len(threads), "tools": len(tools),
                       "outside_run_window_events": outside_events},
            "limitations": ["应用层工具 ID 是运行时声明，不是内核推导的 Agent 语义",
                            "睡眠及等待栈不自动证明设备或物理 SSD 的因果瓶颈",
                            "并行线程时长不能相加当作墙钟；completion path 只替换经验证的 wait4／退出 clear_child_tid join 依赖",
                            "非主线程 exec 缺少显式旧生命周期桥接时标为 IDENTITY_TRANSITION_UNRESOLVED",
                            "预挂载 kallsyms 不证明动态 JIT／模块帧的生命周期和范围，无法证明的帧保留原始地址",
                            "GPU、任意共享服务及未选择的异步 I/O 不在本版合同内"]}


def verify_run(directory, collector=None, expected_manifest_sha256=None):
    from common import digest
    root = Path(directory).resolve()
    if expected_manifest_sha256 and digest(root / "manifest.json")["sha256"] != expected_manifest_sha256:
        raise ValueError("externally supplied manifest digest differs")
    manifest = json.loads((root / "manifest.json").read_bytes())
    bound = check_artifacts(root, manifest)
    capture_name = manifest.get("capture_directory", "capture")
    required = [str(Path(capture_name) / name) for name in ("events.bin", "events.jsonl", "health.json", "meta.json")]
    required += [name for name in ("kallsyms.txt", "enrollment.json", "tool-spans.jsonl", "baseline-threads.json", "closure-threads.json")
                 if (root / name).exists()]
    if (root / capture_name / "censored-contexts.json").exists():
        required.append(str(Path(capture_name) / "censored-contexts.json"))
    if (root / capture_name / "censored-wakes.json").exists():
        required.append(str(Path(capture_name) / "censored-wakes.json"))
    if any(name not in bound for name in required):
        raise ValueError("required evidence was not bound by manifest")
    check_tool_ledger(root, manifest)
    for name, field in (("baseline-threads.json", "baseline_threads"), ("closure-threads.json", "closure")):
        if (root / name).exists() and canonical(json.loads((root / name).read_bytes())) != canonical(manifest.get(field)):
            raise ValueError("baseline/closure evidence differs from manifest: " + name)
    capture = root / capture_name
    meta = json.loads((capture / "meta.json").read_bytes())
    if meta.get("boot_id") != manifest["boot_id"]:
        raise ValueError("capture metadata boot differs")
    native = Path(collector or manifest["collector_binary"])
    if digest(native) != manifest["collector_identity"]:
        raise ValueError("decoder binary differs from capture")
    # Decoder works on raw bytes without attaching BPF. Never trust a derived
    # JSON event stream, reported objects, stack labels, or cached verdict.
    with tempfile.TemporaryDirectory(prefix="timeline-replay-") as temporary:
        decoded = Path(temporary) / "decoded.jsonl"
        subprocess.run([str(native), "--decode", str(capture / "events.bin"), "--output", str(decoded)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if decoded.read_bytes() != (capture / "events.jsonl").read_bytes():
            raise ValueError("raw event projection differs from recorded JSON")
        events = load_events(decoded)
    health = json.loads((capture / "health.json").read_bytes())
    from kprobe_contract import BACKEND, validate_receipt
    if meta.get('read_hook_backend') == BACKEND or health.get('read_hook_backend') == BACKEND:
        declared_root = manifest.get('cgroup_id', manifest.get('scope', {}).get('root_cgroup_id'))
        if declared_root != meta.get('root_cgroup_id'):
            raise ValueError('owned kprobe root differs from declared run scope')
        if 'ready.json' not in bound:
            raise ValueError('owned kprobe READY is not bound by manifest')
        ready = json.loads((root/'ready.json').read_bytes())
        if (ready.get('root_cgroup_id') != declared_root or ready.get('boot_id') != manifest['boot_id']
                or ready.get('status') != 'READY' or ready.get('clock') != 'CLOCK_MONOTONIC'):
            raise ValueError('owned kprobe READY differs from boot/root/clock scope')
        if 'collector_ready' in manifest and canonical(manifest['collector_ready']) != canonical(ready):
            raise ValueError('owned kprobe READY differs from manifest declaration')
        receipt_name = str(Path(capture_name)/'kprobe-hooks.json')
        if meta.get('kprobe_evidence') != 'kprobe-hooks.json' or receipt_name not in bound:
            raise ValueError('owned kprobe receipt is missing or not bound by manifest')
        hook_receipt = json.loads((capture/'kprobe-hooks.json').read_bytes())
        validate_receipt(hook_receipt, meta, health)
        if meta.get('seccomp_hook') is not None or any(e.get('event') == 'SECCOMP_SKIP' or e.get('seccomp_skipped_exit') for e in events):
            mode = 'FEXIT_FILTER_FALSE_SAVED_REGS_V1'
            abi = hook_receipt.get('seccomp_abi', {})
            programs = [p for p in health.get('programs', []) if p.get('program') == 'et_seccomp_skip']
            if (meta.get('seccomp_hook') != mode or ready.get('seccomp_hook') != mode
                    or health.get('seccomp_hook') != mode or len(programs) != 1
                    or programs[0].get('section') != 'fexit/__seccomp_filter'
                    or programs[0].get('info_error') is not False or programs[0].get('recursion_misses') != 0
                    or abi.get('status') != 'VALIDATED_NATIVE_X86_64'
                    or abi.get('section') != 'fexit/__seccomp_filter' or abi.get('program') != 'et_seccomp_skip'
                    or not integer(abi.get('function_id')) or abi['function_id'] <= 0
                    or abi.get('prototype') != 'bool(int,bool)' or abi.get('skip_return') is not False
                    or abi.get('syscall_register') != 'orig_ax' or abi.get('result_register') != 'ax'
                    or abi.get('action') != 'UNKNOWN_NOT_OBSERVED'
                    or any(not integer(abi.get(k)) or not 0 < abi[k] < 4096 or abi[k] % 8
                           for k in ('syscall_register_offset', 'result_register_offset'))
                    or abi['syscall_register_offset'] == abi['result_register_offset']
                    or health.get('pending_seccomp_skips') != 0
                    or health.get('counters', {}).get('seccomp_skips') != sum(e.get('event') == 'SECCOMP_SKIP' for e in events)):
                raise ValueError('seccomp skip proof lacks bound READY/native BTF hook ABI/health agreement')
        if any(event.get('fork_parent_syscall_source') == 'KERNEL_PT_REGS_AT_FORK_NO_ENTRY_EVENT' for event in events):
            abi = hook_receipt.get('btf_abi', {})
            offset = abi.get('fork_syscall_register_offset')
            if (abi.get('fork_syscall_register') != 'orig_ax' or type(offset) is not int
                    or not 0 < offset < 4096 or offset % 8):
                raise ValueError('fork register proof lacks bound native BTF register ABI')
        expected_object = manifest.get('bpf_object_identity', manifest.get('bpf_identity'))
        # The exact decoder's sibling is portable after Guest evidence export.
        # It is checked by hash, not assumed correct merely because of its name.
        object_path = native.with_name('execution_timeline.bpf.o')
        if not object_path.is_file():
            object_path = Path(manifest.get('bpf_object', ''))
        if not expected_object or not object_path.is_file() or digest(object_path) != expected_object:
            raise ValueError('loaded BPF object identity unavailable or differs from pinned source')
    if health.get("records") != len(events) or health.get("raw_bytes") != (capture / "events.bin").stat().st_size:
        raise ValueError("raw evidence counts differ from health")
    if any(e.get("root_cgroup_id") != meta.get("root_cgroup_id") for e in events):
        raise ValueError("event root cgroup differs from capture")
    contexts = []
    if (capture / "censored-contexts.json").exists():
        snapshot = json.loads((capture / "censored-contexts.json").read_bytes())
        contexts = snapshot["contexts"]
        if snapshot.get("status") != "CAPTURED_NOT_CLEARED" or len(contexts) != health.get("pending_syscalls"):
            raise ValueError("censored context snapshot differs from health")
    if (capture / "censored-wakes.json").exists():
        snapshot = json.loads((capture / "censored-wakes.json").read_bytes())
        pending_wakes = snapshot["contexts"]
        if snapshot.get("status") != "CAPTURED_NOT_CLEARED" or len(pending_wakes) != health.get("pending_wakes"):
            raise ValueError("censored wake snapshot differs from health")
        attempts = {(identity_key(e.get("task"), manifest["boot_id"]), e["timestamp_ns"])
                    for e in events if e.get("event") == "WAKING"}
        resolved = {(identity_key(e.get("task"), manifest["boot_id"]), e.get("wake_attempt_ns"))
                    for e in events if e.get("event") == "WAKEUP" and e.get("wake_attempt_ns")}
        for context in pending_wakes:
            key = (identity_key(context.get("task"), manifest["boot_id"]), context.get("wake_attempt_ns"))
            if key not in attempts or key in resolved:
                raise ValueError("censored wake has no raw unclosed waking attempt")
    return build_report(events, manifest, health, Symbols(root / "kallsyms.txt"), contexts)


def check_tool_ledger(root, manifest):
    """Verify application-declared roots/spans against the separately bound log.

    The log is not a kernel attestation. Binding it prevents trusting a mutable
    summary over different recorded application spans; external anchoring is
    still required against a writer who can replace every artifact and hash.
    """
    root = Path(root)
    ledger = root / "tool-spans.jsonl"
    enrollment = root / "enrollment.json"
    tools = {t["tool_call_id"]: t for t in manifest.get("tools", [])}
    if len(tools) != len(manifest.get("tools", [])):
        raise ValueError("duplicate declared tool")
    if ledger.exists():
        enrolled, starts, ends = {}, {}, {}
        with ledger.open("rb") as stream:
            for line in stream:
                if len(line) > MAX_LINE or not line.endswith(b"\n"):
                    raise ValueError("malformed tool ledger line")
                record = json.loads(line)
                kind, tool_id = record.pop("event", None), record.get("tool_call_id")
                target = enrolled if kind == "TOOL_ENROLLED" else starts if kind == "TOOL_START" else ends if kind == "TOOL_END" else None
                if target is None or tool_id in target or tool_id not in tools:
                    raise ValueError("tool ledger lifecycle differs")
                target[tool_id] = record
        if starts.keys() != tools.keys() or ends.keys() != tools.keys():
            raise ValueError("tool ledger missing start/end")
        for tool_id, final in tools.items():
            if tool_id not in enrolled:
                raise ValueError("tool ledger has no pre-release enrollment")
            if canonical(ends[tool_id]) != canonical(final):
                raise ValueError("tool ledger final span differs from manifest")
            for name in ("agent_id", "task_id", "tool_call_id", "root", "cgroup_id", "begin_ns", "command", "invocation_ns"):
                if starts[tool_id].get(name) != final.get(name):
                    raise ValueError("tool ledger immutable binding differs: " + name)
                if name != "begin_ns" and enrolled[tool_id].get(name) != final.get(name):
                    raise ValueError("tool pre-release enrollment differs: " + name)
    elif enrollment.exists():
        declared = json.loads(enrollment.read_bytes())
        if {t["tool_call_id"] for t in declared} != tools.keys() or len(declared) != len(tools):
            raise ValueError("initial enrollment differs")
        for row in declared:
            final = tools[row["tool_call_id"]]
            for name in ("agent_id", "task_id", "tool_call_id", "root", "cgroup_id", "command", "gate", "invocation_ns"):
                if row.get(name) != final.get(name):
                    raise ValueError("enrolled tool identity differs: " + name)
    else:
        raise ValueError("no separately bound initial enrollment or tool ledger")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--collector", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-report", type=Path)
    args = parser.parse_args()
    report = verify_run(args.run_dir, args.collector, args.expected_manifest_sha256)
    if args.check_report and canonical(json.loads(args.check_report.read_bytes())) != canonical(report):
        raise SystemExit("derived report differs from independent reconstruction")
    if args.output:
        write_new(args.output, report)
    print(json.dumps({"verification_status": "REPLAY_PASSED", "timeline_status": report["critical_path"]["status"],
                      "events": report["totals"]["events"], "threads": report["totals"]["threads"],
                      "findings": len(report["findings"])}))


if __name__ == "__main__":
    main()
