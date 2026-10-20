#!/usr/bin/env python3
"""Versioned runtime semantics; this channel is separate from Observer audit WAL."""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path

IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")
TERMINAL = {"END", "FAIL", "CANCEL"}


def identifier(value, optional=False):
    if value is None and optional:
        return value
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("invalid semantic identifier")
    return value


@dataclasses.dataclass(frozen=True)
class Context:
    run_id: str
    task_id: str
    agent_id: str
    parent_task_id: str | None = None
    dependencies: tuple[str, ...] = ()
    tool_call_id: str | None = None
    request_id: str | None = None
    attempt: int = 1
    epoch: int = 1
    priority: int = 0
    effective_version: int = 1

    def validate(self):
        for name in ("run_id", "task_id", "agent_id"):
            identifier(getattr(self, name))
        for name in ("parent_task_id", "tool_call_id", "request_id"):
            identifier(getattr(self, name), optional=True)
        if not isinstance(self.dependencies, tuple) or len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError("dependencies must be a unique tuple")
        for dependency in self.dependencies:
            identifier(dependency)
        if self.task_id in self.dependencies or self.parent_task_id == self.task_id:
            raise ValueError("task cannot depend on or parent itself")
        if any(type(value) is not int or value < 1 for value in (self.attempt, self.epoch, self.effective_version)):
            raise ValueError("attempt/epoch/effective_version must be positive integers")
        if type(self.priority) is not int or not -100 <= self.priority <= 100:
            raise ValueError("priority must be within -100..100")
        return self


def identity(pid=None, tid=None):
    pid = os.getpid() if pid is None else pid
    tid = threading.get_native_id() if tid is None else tid
    proc = Path("/proc", str(pid))
    def ticks(path):
        raw = path.read_text()
        return int(raw[raw.rfind(")") + 2:].split()[19])
    membership = [line[3:] for line in (proc / "cgroup").read_text().splitlines() if line.startswith("0::")]
    if len(membership) != 1:
        raise ValueError("requires one cgroup-v2 membership")
    group = Path("/sys/fs/cgroup") / membership[0].lstrip("/")
    stat = group.stat()
    return {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "pid": pid, "process_start_ticks": ticks(proc / "stat"),
            "tid": tid, "thread_start_ticks": ticks(proc / "task" / str(tid) / "stat"),
            "cgroup_path": membership[0], "cgroup_inode": stat.st_ino,
            "cgroup_device": stat.st_dev,
            "pid_namespace_inode": (proc / "ns/pid").stat().st_ino,
            "cgroup_namespace_inode": (proc / "ns/cgroup").stat().st_ino}


class Recorder:
    def __init__(self, path, run_id, maximum_events=200_000):
        identifier(run_id)
        self.run_id, self.maximum_events = run_id, maximum_events
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
        self.stream = os.fdopen(fd, "w", encoding="utf-8", buffering=1)
        self.lock = threading.RLock()
        self.tasks, self.spans, self.active_threads, self.requests, self.batches = {}, {}, {}, {}, {}
        self.seq = 0
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()

    def emit(self, kind, context, phase, *, span_id=None, parent_span_id=None, details=None, actor=None):
        with self.lock:
            context.validate()
            if context.run_id != self.run_id or self.seq >= self.maximum_events:
                raise ValueError("semantic run mismatch or event budget exhausted")
            event = {"schema_version": 1, "seq": self.seq + 1, "kind": kind,
                     **dataclasses.asdict(context), "phase": identifier(phase),
                     "span_id": identifier(span_id, True), "parent_span_id": identifier(parent_span_id, True),
                     "monotonic_ns": time.monotonic_ns(), "boot_id": self.boot_id,
                     "actor": identity() if actor is None else actor, "details": details or {},
                     "authority": "RUNTIME_DECLARED_NOT_KERNEL_CAUSAL_PROOF"}
            encoded = json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
            self.stream.write(encoded)
            self.seq += 1
            return event

    def declare(self, context):
        with self.lock:
            if context.task_id in self.tasks:
                raise ValueError("duplicate task declaration")
            context.validate()
            self.tasks[context.task_id] = context
            self.emit("DECLARE", context, "TASK")
        return context

    def current(self, context):
        current = self.tasks.get(context.task_id)
        if current is None:
            raise ValueError("undeclared task")
        for name in ("run_id", "agent_id", "attempt", "epoch", "parent_task_id", "dependencies"):
            if getattr(current, name) != getattr(context, name):
                raise ValueError("task immutable identity changed")
        return dataclasses.replace(current, tool_call_id=context.tool_call_id, request_id=context.request_id)

    def update_policy(self, context, priority, policy):
        with self.lock:
            current = self.current(context)
            changed = dataclasses.replace(current, priority=priority, effective_version=current.effective_version + 1)
            changed.validate()
            self.tasks[context.task_id] = dataclasses.replace(changed, tool_call_id=None, request_id=None)
            self.emit("POLICY_UPDATE", changed, "RESOURCE_POLICY", details=policy)
            return changed

    def begin(self, context, phase, span_id, parent_span_id=None, dependency_spans=(), actor=None):
        with self.lock:
            current = self.current(context)
            if span_id in self.spans:
                raise ValueError("duplicate semantic span")
            if parent_span_id is not None and (parent_span_id not in self.spans or self.spans[parent_span_id]["terminal"]):
                raise ValueError("parent span is absent or terminal")
            if parent_span_id is not None and self.spans[parent_span_id]["context"].task_id not in {current.task_id, current.parent_task_id}:
                raise ValueError("parent span does not belong to this task or its declared parent")
            for dependency in dependency_spans:
                if dependency not in self.spans or self.spans[dependency]["terminal"] != "END":
                    raise ValueError("dependent phase began before successful prerequisite")
                if self.spans[dependency]["context"].task_id not in {current.task_id, *current.dependencies}:
                    raise ValueError("cross-task phase dependency was not declared")
            self.spans[span_id] = {"context": current, "phase": phase, "terminal": None,
                                  "parent_span_id": parent_span_id}
            self.emit("BEGIN", current, phase, span_id=span_id, parent_span_id=parent_span_id,
                      details={"dependency_spans": list(dependency_spans)}, actor=actor)
            return span_id

    def end(self, span_id, status="END", details=None, actor=None):
        with self.lock:
            if status not in TERMINAL or span_id not in self.spans or self.spans[span_id]["terminal"]:
                raise ValueError("invalid or duplicate span termination")
            span = self.spans[span_id]
            if any(child["parent_span_id"] == span_id and child["terminal"] is None
                   for child in self.spans.values()):
                raise ValueError("parent span has an unfinished child")
            span["terminal"] = status
            self.emit(status, self.current(span["context"]), span["phase"], span_id=span_id,
                      details=details, actor=actor)

    @contextlib.contextmanager
    def span(self, context, phase, span_id, **options):
        self.begin(context, phase, span_id, **options)
        try:
            yield
        except BaseException as error:
            self.end(span_id, "FAIL", {"error_type": type(error).__name__, "error": str(error)[:2048]})
            raise
        else:
            self.end(span_id)

    @contextlib.contextmanager
    def thread_processing(self, context, span_id, phase="SHARED_REQUEST_HANDLER"):
        actor = identity()
        key = (actor["boot_id"], actor["pid"], actor["process_start_ticks"], actor["tid"], actor["thread_start_ticks"])
        with self.lock:
            if key in self.active_threads:
                raise ValueError("shared thread already has an active request interval")
            if context.request_id is None:
                raise ValueError("shared thread interval must bind a request")
            self.active_threads[key] = context.request_id
            self.begin(context, phase, span_id, actor=actor)
        try:
            yield actor
        except BaseException as error:
            self.end(span_id, "FAIL", {"error": str(error)[:2048]}, actor=identity())
            raise
        else:
            self.end(span_id, actor=identity())
        finally:
            with self.lock:
                del self.active_threads[key]

    def request(self, context, state, details=None):
        allowed = {None: "ACCEPTED", "ACCEPTED": "QUEUED", "QUEUED": "SCHEDULED",
                   "SCHEDULED": "FIRST_TOKEN", "FIRST_TOKEN": "COMPLETE"}
        with self.lock:
            if context.request_id is None:
                raise ValueError("request ID is mandatory")
            previous = self.requests.get(context.request_id)
            if previous and (previous[0], previous[2]) != (context.task_id, context.tool_call_id):
                raise ValueError("request changed its task/tool owner")
            previous_state = None if previous is None else previous[1]
            if previous is None and state != "ACCEPTED":
                raise ValueError("unknown request must first be accepted")
            if state not in {"CANCELLED", "FAILED"} and allowed.get(previous_state) != state:
                raise ValueError("out-of-order inference request state")
            if previous_state in {"COMPLETE", "CANCELLED", "FAILED"}:
                raise ValueError("request already terminal")
            self.requests[context.request_id] = (context.task_id, state, context.tool_call_id)
            self.emit("REQUEST_" + state, self.current(context), "INFERENCE", details=details)

    def batch(self, batch_id, contexts, kind, details=None, actor=None):
        with self.lock:
            identifier(batch_id)
            members = [self.current(context) for context in contexts]
            request_ids = [context.request_id for context in members]
            if not members or None in request_ids or len(set(request_ids)) != len(request_ids):
                raise ValueError("batch must have distinct request members")
            for context in members:
                if self.requests.get(context.request_id, (None, None))[1] not in {"SCHEDULED", "FIRST_TOKEN"}:
                    raise ValueError("batch member is not an active scheduled request")
                request = self.requests[context.request_id]
                if (request[0], request[2]) != (context.task_id, context.tool_call_id):
                    raise ValueError("batch member request/task/tool owner mismatch")
            if kind == "BEGIN":
                if batch_id in self.batches:
                    raise ValueError("duplicate batch")
                self.batches[batch_id] = request_ids
            elif kind == "END":
                if self.batches.pop(batch_id, None) != request_ids:
                    raise ValueError("batch membership changed")
            else:
                raise ValueError("invalid batch transition")
            self.emit("BATCH_" + kind, members[0], "INFERENCE_BATCH",
                      details={"batch_id": batch_id, "members": [dataclasses.asdict(member) for member in members],
                               **(details or {})}, actor=actor)

    def close(self):
        with self.lock:
            if self.stream.closed:
                return
            self.stream.flush()
            os.fsync(self.stream.fileno())
            self.stream.close()


def verify(path):
    """Independently replay the JSONL; incomplete lifecycles remain incomplete."""
    events, tasks, spans, requests, batches, processing = [], {}, {}, {}, {}, {}
    errors = []
    try:
        with Path(path).open() as stream:
            for line in stream:
                if len(line.encode()) > 1024 * 1024:
                    raise ValueError("oversized semantic event")
                events.append(json.loads(line))
                if len(events) > 200_000:
                    raise ValueError("semantic verifier event budget exceeded")
        run_id, boot_id, last_ns = None, None, 0
        for seq, event in enumerate(events, 1):
            if type(event["schema_version"]) is not int or event["schema_version"] != 1 or type(event["seq"]) is not int or event["seq"] != seq or type(event["monotonic_ns"]) is not int or event["monotonic_ns"] <= 0 or event["monotonic_ns"] < last_ns:
                raise ValueError("semantic sequence/time is invalid")
            last_ns = event["monotonic_ns"]
            identifier(event["phase"])
            identifier(event["span_id"], optional=True)
            identifier(event["parent_span_id"], optional=True)
            if event["authority"] != "RUNTIME_DECLARED_NOT_KERNEL_CAUSAL_PROOF":
                raise ValueError("semantic source authority forged")
            context = Context(**{field.name: tuple(event[field.name]) if field.name == "dependencies" else event[field.name]
                                 for field in dataclasses.fields(Context)}).validate()
            if run_id is None:
                run_id, boot_id = context.run_id, event["boot_id"]
            if context.run_id != run_id or event["boot_id"] != boot_id:
                raise ValueError("semantic run/boot identity changed")
            kind = event["kind"]
            if kind == "DECLARE":
                if context.task_id in tasks:
                    raise ValueError("duplicate task declaration")
                tasks[context.task_id] = context
            else:
                previous = tasks.get(context.task_id)
                if previous is None:
                    raise ValueError("undeclared task")
                for name in ("run_id", "agent_id", "parent_task_id", "dependencies", "attempt", "epoch"):
                    if getattr(context, name) != getattr(previous, name):
                        raise ValueError("immutable task identity changed")
                if kind == "POLICY_UPDATE":
                    if context.effective_version != previous.effective_version + 1:
                        raise ValueError("policy version skipped or replayed")
                    tasks[context.task_id] = context
                elif (context.effective_version, context.priority) != (previous.effective_version, previous.priority):
                    raise ValueError("stale or forged effective policy")
            actor = event["actor"]
            if actor is not None:
                for name in ("pid", "process_start_ticks", "tid", "thread_start_ticks", "cgroup_inode", "cgroup_device"):
                    if type(actor[name]) is not int or actor[name] < 0:
                        raise ValueError("invalid process/thread instance identity")
                if actor["pid"] == 0 or actor["tid"] == 0 or actor["cgroup_inode"] == 0:
                    raise ValueError("process/thread/cgroup identity must be nonzero")
                if actor["boot_id"] != boot_id:
                    raise ValueError("actor boot identity mismatch")
                for name in ("pid_namespace_inode", "cgroup_namespace_inode"):
                    if type(actor[name]) is not int or actor[name] <= 0:
                        raise ValueError("invalid namespace instance identity")
                if not isinstance(actor["cgroup_path"], str) or not actor["cgroup_path"].startswith("/"):
                    raise ValueError("invalid cgroup path")
            else:
                raise ValueError("missing process/thread actor")
            if kind == "BEGIN":
                span = event["span_id"]
                if span in spans:
                    raise ValueError("duplicate span")
                parent = event["parent_span_id"]
                if parent is not None and (parent not in spans or spans[parent]["terminal"]):
                    raise ValueError("invalid parent span")
                if parent is not None and spans[parent]["task"] not in {context.task_id, context.parent_task_id}:
                    raise ValueError("parent span/task DAG binding forged")
                for dependency in event["details"].get("dependency_spans", []):
                    if dependency not in spans or spans[dependency]["terminal"] != "END":
                        raise ValueError("dependency not complete at phase begin")
                    if spans[dependency]["task"] not in {context.task_id, *context.dependencies}:
                        raise ValueError("phase dependency/task DAG binding forged")
                spans[span] = {"task": context.task_id, "phase": event["phase"], "terminal": None,
                               "request_id": context.request_id, "tool_call_id": context.tool_call_id,
                               "actor": actor, "parent_span_id": parent}
                if event["phase"] == "SHARED_REQUEST_HANDLER":
                    key = (actor["pid"], actor["process_start_ticks"], actor["tid"], actor["thread_start_ticks"])
                    if key in processing or context.request_id is None:
                        raise ValueError("shared thread has overlapping/unknown request ownership")
                    processing[key] = span
            elif kind in TERMINAL:
                span = spans.get(event["span_id"])
                if span is None or span["terminal"] or span["task"] != context.task_id or span["phase"] != event["phase"]:
                    raise ValueError("invalid span termination")
                if context.request_id != span["request_id"] or context.tool_call_id != span["tool_call_id"]:
                    raise ValueError("span request/tool binding changed")
                if any(child["parent_span_id"] == event["span_id"] and child["terminal"] is None
                       for child in spans.values()):
                    raise ValueError("parent terminated before child")
                span["terminal"] = kind
                if event["phase"] == "SHARED_REQUEST_HANDLER":
                    if actor != span["actor"] or context.request_id != span["request_id"]:
                        raise ValueError("request processing thread identity changed")
                    key = (actor["pid"], actor["process_start_ticks"], actor["tid"], actor["thread_start_ticks"])
                    if processing.pop(key, None) != event["span_id"]:
                        raise ValueError("shared thread interval did not close")
            elif kind.startswith("REQUEST_"):
                state = kind.removeprefix("REQUEST_") if hasattr(str, "removeprefix") else kind[8:]
                prior = requests.get(context.request_id)
                allowed = {None: "ACCEPTED", "ACCEPTED": "QUEUED", "QUEUED": "SCHEDULED",
                           "SCHEDULED": "FIRST_TOKEN", "FIRST_TOKEN": "COMPLETE"}
                if context.request_id is None or (prior and (prior[0], prior[2]) != (context.task_id, context.tool_call_id)):
                    raise ValueError("request identity/owner invalid")
                before = None if prior is None else prior[1]
                if prior is None and state != "ACCEPTED":
                    raise ValueError("request terminal without acceptance")
                if before in {"COMPLETE", "FAILED", "CANCELLED"} or (state not in {"FAILED", "CANCELLED"} and allowed.get(before) != state):
                    raise ValueError("request state skipped or replayed")
                requests[context.request_id] = (context.task_id, state, context.tool_call_id)
            elif kind.startswith("BATCH_"):
                if kind not in {"BATCH_BEGIN", "BATCH_END"}:
                    raise ValueError("unknown semantic batch transition")
                details = event["details"]
                batch_id = identifier(details["batch_id"])
                members = details["members"]
                ids = [member["request_id"] for member in members]
                if not ids or None in ids or len(set(ids)) != len(ids):
                    raise ValueError("invalid batch membership")
                for member in members:
                    if requests.get(member["request_id"], (None, None))[0] != member["task_id"]:
                        raise ValueError("batch member owner forged")
                    member_context = Context(**{**member, "dependencies": tuple(member["dependencies"])}).validate()
                    task = tasks.get(member_context.task_id)
                    if task is None or any(getattr(member_context, name) != getattr(task, name)
                          for name in ("run_id", "agent_id", "parent_task_id", "dependencies", "attempt", "epoch",
                                       "priority", "effective_version")):
                        raise ValueError("batch member context or policy forged")
                    if requests[member_context.request_id][1] not in {"SCHEDULED", "FIRST_TOKEN"}:
                        raise ValueError("batch member is not scheduled")
                if kind == "BATCH_BEGIN":
                    if batch_id in batches:
                        raise ValueError("batch duplicate begin")
                    batches[batch_id] = ids
                elif batches.pop(batch_id, None) != ids:
                    raise ValueError("batch membership changed")
            elif kind not in {"DECLARE", "POLICY_UPDATE"}:
                raise ValueError("unknown semantic event type")
        # Iterative DFS: long valid DAGs do not overflow recursion, and shared
        # dependencies are visited once rather than exponentially many times.
        colors = {}
        for task_id in tasks:
            stack = [(task_id, False)]
            while stack:
                node, exiting = stack.pop()
                if node not in tasks:
                    raise ValueError("task dependency/parent missing node")
                if exiting:
                    colors[node] = 2
                    continue
                if colors.get(node) == 1:
                    raise ValueError("task dependency/parent cycle")
                if colors.get(node) == 2:
                    continue
                colors[node] = 1
                stack.append((node, True))
                task = tasks[node]
                dependencies = (*task.dependencies, *((task.parent_task_id,) if task.parent_task_id else ()))
                stack.extend((dependency, False) for dependency in dependencies)
    except (OSError, ValueError, KeyError, TypeError) as error:
        errors.append(str(error))
    incomplete = [span_id for span_id, span in spans.items() if span["terminal"] is None]
    incomplete_requests = [request_id for request_id, (_, state, _) in requests.items() if state not in {"COMPLETE", "CANCELLED", "FAILED"}]
    return {"schema_version": 1, "verified": not errors, "status": "INVALID" if errors else
            ("INCOMPLETE" if incomplete or incomplete_requests or batches or not events else "COMPLETE"),
            "event_count": len(events), "task_count": len(tasks), "request_count": len(requests),
            "incomplete_spans": incomplete, "incomplete_requests": incomplete_requests,
            "active_batches": list(batches), "errors": errors,
            "artifact_sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).is_file() else None,
            "authority": "RUNTIME_DECLARATION_REPLAY_NOT_AUDIT_WAL"}
