#!/usr/bin/env python3
"""Versioned task explanations over an immutable, source-linked trajectory.

This is an offline interpretation layer, not a kernel sensor or a proof of the
model's intentions. Deterministic command rules and explicit reviewed marks are
separate methods. No previous-message-as-intent or timestamp parent guessing is
used. Source records and hashes remain available for review.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import shlex

from common import write_new


SCHEMA = "OBSERVER_SEMANTIC_INTERVALS_V1"
TAXONOMY_VERSION = "coding-workflow-zh-v1"
RULE_VERSION = "command-evidence-v1"
TAXONOMY = {
    "task": "完成任务", "locate": "定位问题", "inspect": "检查实现",
    "edit": "修改实现", "test": "运行测试", "build": "构建程序",
    "environment": "准备环境", "record": "记录结果", "unassigned": "未分配阶段",
    "edit_test": "实现并验证修复", "inspect_test": "检查并验证", "inspect_build": "检查并构建",
}
MAX_STEPS = 20_000
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_TEXT = 32_768


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _identity(value):
    return isinstance(value, str) and 0 < len(value) <= 1024


def _time(row):
    for field in ("requested_ns", "receipt_ns", "client_request_received_ns", "begin_ns", "at_ns"):
        if type(row.get(field)) is int and row[field] >= 0:
            return row[field]
    return None


def _clip(value):
    """Bound copied text, retaining a hash and explicit truncation metadata."""
    if isinstance(value, str) and len(value) > MAX_TEXT:
        return {"preview": value[:MAX_TEXT], "sha256": hashlib.sha256(value.encode()).hexdigest(),
                "characters": len(value), "truncated": True}
    if isinstance(value, dict):
        return {key: _clip(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clip(item) for item in value]
    return value


def build_trajectory(application, story=None, rpc_rows=None):
    """Return ordered user/message/model/tool/result steps with exact source IDs.

    ``application`` is the existing steps.json projection. ``story`` can supply
    model request IDs and registered kernel bindings. Raw RPC records are kept
    as supplementary evidence; they do not become new tool/parent guesses.
    Order is client observation order, not inferred model execution order.
    """
    if not isinstance(application, dict) or (story is not None and not isinstance(story, dict)):
        raise ValueError("application and optional story objects required")
    story = story or {}
    raw_steps = application.get("steps") or []
    calls = application.get("tool_calls") or []
    if not isinstance(raw_steps, list) or not isinstance(calls, list):
        raise ValueError("application steps/tool_calls must be lists")
    source = {"application": application}
    if story:
        source["story_model_requests"] = story.get("model_requests") or []
    if rpc_rows is not None:
        if not isinstance(rpc_rows, list):
            raise ValueError("rpc_rows must be a list")
        source["rpc"] = rpc_rows
    if len(_canonical(source)) > MAX_SOURCE_BYTES:
        raise ValueError("bounded trajectory input exceeded")
    by_call = {}
    for index, call in enumerate(calls):
        if not isinstance(call, dict) or not _identity(call.get("call_id")):
            raise ValueError("tool call requires explicit call_id")
        if call["call_id"] in by_call:
            raise ValueError("duplicate application call_id")
        by_call[call["call_id"]] = (index, call)
    pending, seen_calls = [], set()

    def add(kind, record, ref, at_ns=None, call_id=None, request_id=None):
        ordinal = len(pending)
        excerpt = _clip(deepcopy(record))
        pending.append({"step_id": "step-" + _digest([ref, kind])[:20], "kind": kind,
            "source_ref": ref, "source_sha256": _digest(record), "source": excerpt,
            "source_excerpt_sha256": _digest(excerpt),
            "at_ns": at_ns, "call_id": call_id, "request_id": request_id, "source_ordinal": ordinal})

    prompt = application.get("prompt", application.get("task_prompt"))
    if isinstance(prompt, str) and prompt:
        add("USER_TASK", {"text": prompt}, "application#/prompt", application.get("begin_ns"))
    elif rpc_rows is not None:
        # Raw turn/start is the user's actual task input. Do not replace it with
        # an Agent-authored public message or read arbitrary reasoning items.
        for index, raw in enumerate(rpc_rows):
            if not isinstance(raw, dict) or raw.get("direction") != "CLIENT_TO_CODEX":
                continue
            message = raw.get("message") or {}
            if message.get("method") == "turn/start" and (message.get("params") or {}).get("input"):
                add("USER_TASK", raw, "rpc#/" + str(index), _time(raw))
    for index, step in enumerate(raw_steps):
        if not isinstance(step, dict):
            raise ValueError("trajectory step must be object")
        kind = step.get("kind") or "UNKNOWN_APPLICATION_STEP"
        call_id = step.get("call_id")
        if kind in ("TOOL_CALL", "APPLICATION_TOOL_CALL"):
            if not _identity(call_id) or call_id in seen_calls:
                raise ValueError("tool steps require unique explicit call_id")
            seen_calls.add(call_id)
            add("TOOL_REQUEST", step, "application#/steps/" + str(index), _time(step), call_id)
        else:
            add(kind, step, "application#/steps/" + str(index), _time(step), call_id)
    for call_id, (index, call) in by_call.items():
        if call_id not in seen_calls:
            add("TOOL_REQUEST", call, "application#/tool_calls/" + str(index), _time(call), call_id)
        delivered = call.get("result_delivered_ns", call.get("completed_ns"))
        # A result is a real lifecycle record, not a new inferred tool invocation.
        if type(delivered) is int and delivered >= 0:
            add("TOOL_RESULT", call, "application#/tool_calls/" + str(index), delivered, call_id)
    seen_requests = set()
    for index, request in enumerate(story.get("model_requests") or []):
        if not isinstance(request, dict) or not _identity(request.get("request_id")):
            raise ValueError("model request requires explicit request_id")
        if request["request_id"] in seen_requests:
            raise ValueError("duplicate model request_id")
        seen_requests.add(request["request_id"])
        request_at = request.get("begin_ns")
        foreign_clock = (request.get("clock_alignment") == "DIFFERENT_BOOT_DURATION_ONLY" or
            request.get("source_boot_id") is not None and story.get("boot_id") is not None
            and request["source_boot_id"] != story["boot_id"])
        if foreign_clock:
            request_at = None
        add("MODEL_REQUEST", request, "story#/model_requests/" + str(index),
            request_at, request_id=request["request_id"])
        if foreign_clock:
            pending[-1]["ordering_quality"] = "FOREIGN_BOOT_DURATION_ONLY_NOT_SORTED_BY_ABSOLUTE_TIME"
    if len(pending) > MAX_STEPS:
        raise ValueError("trajectory step limit exceeded")
    # If observation clocks are missing, preserve the application stream rather
    # than manufacture an ordering between it and a different source.
    timed = all(type(step["at_ns"]) is int and step["at_ns"] >= 0 for step in pending)
    if timed:
        pending.sort(key=lambda step: (step["at_ns"], step["source_ordinal"]))
    for index, step in enumerate(pending):
        step["index"] = index
    identity = {key: story.get(key, application.get(key)) for key in ("run_id", "agent_id", "task_id")}
    output = {"schema_version": 1, "kind": "SOURCE_LINKED_AGENT_TRAJECTORY", **identity,
        "ordering": "CLIENT_OBSERVATION_CLOCK" if timed else "SOURCE_STREAM_ORDER_WITH_UNORDERED_SUPPLEMENTS",
        "sources": {key: {"sha256": _digest(value), "bytes": len(_canonical(value))}
                    for key, value in source.items()}, "steps": pending,
        "source_content": "PRIVATE_REVIEW_ARTIFACT; NOT_REDACTED; LONG_FIELDS_HAVE_HASHED_PREVIEWS",
        "interpretation": "PUBLIC_RECORDED_CONTENT_NOT_HIDDEN_REASONING_OR_CAUSAL_PROOF"}
    output["trajectory_digest"] = _digest(output)
    return output


def validate_trajectory(trajectory):
    if not isinstance(trajectory, dict) or trajectory.get("kind") != "SOURCE_LINKED_AGENT_TRAJECTORY":
        raise ValueError("source-linked trajectory schema required")
    bound = {key: value for key, value in trajectory.items() if key != "trajectory_digest"}
    if trajectory.get("trajectory_digest") != _digest(bound):
        raise ValueError("trajectory content digest mismatch")
    steps, seen = trajectory.get("steps"), set()
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise ValueError("nonempty bounded trajectory required")
    for index, step in enumerate(steps):
        if (not isinstance(step, dict) or not _identity(step.get("step_id"))
                or step["step_id"] in seen or step.get("index") != index):
            raise ValueError("unique ordered trajectory step IDs required")
        seen.add(step["step_id"])
        if step.get("source_excerpt_sha256") != _digest(step.get("source")):
            raise ValueError("trajectory source excerpt digest mismatch")
    return {"status": "TRAJECTORY_CONTENT_BINDING_VALID", "steps": len(steps)}


def _commands(command):
    """Read executable positions, not search-pattern words containing 'pytest'."""
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>\n")
        lex.whitespace = " \t\r"
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        return None
    groups, current = [], []
    for token in tokens:
        if token in (";", "&&", "||", "|", "&", "(", ")", "\n"):
            if current:
                groups.append(current); current = []
        else:
            current.append(token)
    if current:
        groups.append(current)
    return groups


def classify_tool(record):
    """Conservative, inspectable command classification; never claim intent."""
    arguments = record.get("arguments") or {}
    command = record.get("command") or (arguments.get("command") if isinstance(arguments, dict) else None)
    tool = str(record.get("tool_name", record.get("tool", ""))).lower()
    if tool in ("apply_patch", "edit_file", "write_file", "replace_in_file", "file_edit"):
        return "edit", [{"rule": "explicit-edit-tool", "evidence": tool}]
    if tool in ("read_file", "list_directory", "view_file"):
        return "inspect", [{"rule": "explicit-read-tool", "evidence": tool}]
    if tool in ("search", "search_files", "grep", "code_search"):
        return "locate", [{"rule": "explicit-search-tool", "evidence": tool}]
    if not isinstance(command, str) or not command:
        return "unassigned", [{"rule": "no-recognized-command-evidence"}]
    groups = _commands(command)
    if groups is None:
        return "unassigned", [{"rule": "shell-parse-failed"}]
    if any(any(token in ("<<", "<<-") for token in group) for group in groups):
        return "unassigned", [{"rule": "heredoc-content-not-treated-as-executed-shell-commands"}]
    evidence, stages = [], set()
    for group in groups:
        words = list(group)
        while words and (re.match(r"^[A-Za-z_][A-Za-z_0-9]*=", words[0]) or words[0] in ("env", "exec", "command", "sudo")):
            words.pop(0)
        if not words:
            continue
        if words[0] in ("do", "then", "else"):
            words.pop(0)
            if not words:
                continue
        name = Path(words[0]).name
        if name == "for" and "$(" not in command and "`" not in command:
            # The loop declaration is not the body; 'do cat ...' is parsed as
            # the next group. Substitutions are deliberately left unresolved.
            continue
        if name in ("cd", "true", "false", "head", "tail", "sort", "uniq", "done", "fi", "then") or (
                name in ("echo", "printf") and not any(token in (">", ">>") for token in words)):
            continue
        stage, rule = None, None
        if name in ("sh", "bash", "zsh") and "-c" in words:
            nested = words[words.index("-c") + 1:]
            if len(nested) == 1:
                nested_stage, details = classify_tool({"command": nested[0]})
                stages.add(nested_stage); evidence.extend(details)
                continue
        if name in ("rg", "grep", "ag", "ack", "find", "fd", "locate"):
            stage, rule = "locate", "search-command"
        elif name in ("pytest", "py.test", "ctest", "nosetests"):
            stage, rule = "test", "test-runner"
        elif name.startswith("python") and "-m" in words and any(x in ("pytest", "unittest") for x in words[1:]):
            stage, rule = "test", "python-test-module"
        elif name in ("cargo", "go", "npm", "pnpm", "yarn", "bun", "make", "cmake", "ninja"):
            if "--version" in words[1:] or words[1:] == ["-v"]:
                stage, rule = "inspect", "explicit-runtime-version-query"
            elif any(x in ("test", "tests", "check", "lint", "test-ci", "--build-and-test") for x in words[1:]):
                stage, rule = "test", "explicit-test-subcommand"
            elif any(x in ("build", "--build", "all", "compile") for x in words[1:]) or name in ("make", "ninja"):
                stage, rule = "build", "explicit-build-command"
            elif any(x in ("install", "add", "ci", "fetch") for x in words[1:]):
                stage, rule = "environment", "dependency-subcommand"
        elif name in ("apply_patch", "patch", "tee", "touch", "mkdir", "mv", "cp", "rm"):
            stage, rule = "edit", "explicit-mutation-command"
        elif name in ("sed", "perl") and any(x == "-i" or x.startswith("-i") for x in words[1:]):
            stage, rule = "edit", "in-place-edit-option"
        elif name in ("cat", "sed", "less", "more", "ls", "stat", "wc", "file", "diff"):
            stage, rule = "inspect", "inspection-command"
        elif name == "git":
            if any(x in ("show", "diff", "status", "log", "ls-files", "grep") for x in words[1:]):
                stage, rule = "inspect", "git-inspection-subcommand"
            elif any(x in ("commit", "tag") for x in words[1:]):
                stage, rule = "record", "git-record-subcommand"
        if any(token in (">", ">>") for token in words):
            # A search redirected to a file is still a search, not a code edit.
            if name in ("cat", "tee", "printf", "echo"):
                stage, rule = "edit", "explicit-output-redirection"
        if stage is None:
            stages.add("unassigned")
            evidence.append({"rule": "unknown-executable-or-subcommand", "executable": name})
        else:
            stages.add(stage)
            evidence.append({"rule": rule, "executable": name})
    if stages == {"locate", "inspect"}:
        return "inspect", evidence + [{"rule": "combined-source-discovery-and-inspection", "candidates": sorted(stages)}]
    if "unassigned" not in stages:
        broader = None
        if "edit" in stages and stages.intersection({"test", "build"}) and stages.issubset({"edit", "test", "build", "inspect", "locate"}):
            broader = "edit_test"
        elif "test" in stages and stages.intersection({"inspect", "locate"}) and stages.issubset({"test", "inspect", "locate"}):
            broader = "inspect_test"
        elif "build" in stages and stages.intersection({"inspect", "locate"}) and stages.issubset({"build", "inspect", "locate"}):
            broader = "inspect_build"
        if broader:
            return broader, evidence + [{"rule": "broader-composite-responsibility-no-time-splitting", "candidates": sorted(stages)}]
    if len(stages) == 1:
        return next(iter(stages)), evidence
    return "unassigned", evidence + [{"rule": "mixed-or-empty-command-responsibilities",
                                       "candidates": sorted(stages)}]


def _intervals(paths, taxonomy=TAXONOMY):
    intervals = []
    def visit(begin, end, depth, parent):
        cursor = begin
        while cursor < end:
            if len(paths[cursor]) <= depth:
                cursor += 1; continue
            key = paths[cursor][depth]
            stop = cursor + 1
            while stop < end and len(paths[stop]) > depth and paths[stop][depth] == key:
                stop += 1
            interval_id = "interval-{}-{}-{}".format(depth, cursor, stop)
            intervals.append({"interval_id": interval_id, "parent_id": parent,
                "begin_step": cursor, "end_step_exclusive": stop,
                "taxonomy_key": key, "label": taxonomy[key], "depth": depth})
            visit(cursor, stop, depth + 1, interval_id)
            cursor = stop
    visit(0, len(paths), 0, None)
    return intervals


def _vocabulary(explicit=None):
    if explicit is None or "taxonomy" not in explicit:
        return TAXONOMY_VERSION, deepcopy(TAXONOMY)
    taxonomy, version = explicit.get("taxonomy"), explicit.get("taxonomy_version")
    if (not isinstance(taxonomy, dict) or not 2 <= len(taxonomy) <= 64
            or not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", version)
            or "task" not in taxonomy or "unassigned" not in taxonomy):
        raise ValueError("bounded versioned taxonomy with task/unassigned roots required")
    for key, label in taxonomy.items():
        if (not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key)
                or not isinstance(label, str) or not 1 <= len(label.strip()) <= 80
                or label != label.strip() or any(ord(char) < 32 for char in label)):
            raise ValueError("taxonomy requires stable bounded keys and readable labels")
    if version == TAXONOMY_VERSION and taxonomy != TAXONOMY:
        raise ValueError("built-in taxonomy version cannot be overwritten")
    return version, deepcopy(taxonomy)


def _explicit_paths(trajectory, explicit, taxonomy, taxonomy_version):
    if explicit.get("trajectory_digest") != trajectory.get("trajectory_digest"):
        raise ValueError("explicit annotations must bind this trajectory_digest")
    if explicit.get("taxonomy_version") != taxonomy_version:
        raise ValueError("explicit taxonomy version mismatch")
    marks = explicit.get("marks")
    if not isinstance(marks, list) or not marks:
        raise ValueError("explicit annotation requires nonempty sparse marks")
    by_id = {step["step_id"]: step["index"] for step in trajectory["steps"]}
    normalized = []
    for mark in marks:
        if not isinstance(mark, dict) or mark.get("step_id") not in by_id:
            raise ValueError("annotation mark has unknown step_id")
        path = mark.get("path")
        if (not isinstance(path, list) or not 1 <= len(path) <= 8 or path[0] != "task"
                or any(not isinstance(key, str) or key not in taxonomy for key in path) or len(set(path)) != len(path)):
            raise ValueError("annotation path must use distinct versioned taxonomy keys rooted at task")
        normalized.append((by_id[mark["step_id"]], path))
    if normalized[0][0] != 0 or any(a[0] >= b[0] for a, b in zip(normalized, normalized[1:])):
        raise ValueError("marks must start at step zero and increase without duplicates")
    paths, cursor = [], 0
    for index in range(len(trajectory["steps"])):
        if cursor + 1 < len(normalized) and normalized[cursor + 1][0] == index:
            cursor += 1
        paths.append(list(normalized[cursor][1]))
    return paths


def build_annotations(trajectory, explicit=None):
    """Create complete nested intervals; optional marks are explicit offline review.

    Marks: {trajectory_digest, taxonomy_version, marks:[{step_id,path:["task",
    "locate"]},...]}. Boundaries reference stable step IDs, not mutable offsets.
    Rule mode uses only recognized tool syntax and exact model output call IDs.
    """
    validate_trajectory(trajectory)
    steps = trajectory.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > MAX_STEPS:
        raise ValueError("nonempty bounded source trajectory required")
    taxonomy_version, taxonomy = _vocabulary(explicit)
    paths, explanations, by_call, by_native = [], {}, {}, {}
    for step in steps:
        if step["kind"] == "TOOL_REQUEST":
            stage, evidence = classify_tool(step["source"])
            by_call[step["call_id"]] = stage
            native_id = step["source"].get("observer_tool_call_id", step["source"].get("execution_tool_call_id"))
            if _identity(native_id):
                by_native[native_id] = stage
            explanations[step["step_id"]] = evidence
    if explicit is not None:
        paths = _explicit_paths(trajectory, explicit, taxonomy, taxonomy_version)
        review = explicit.get("method", "EXPLICIT_OFFLINE_ANNOTATION")
        if review not in ("EXPLICIT_OFFLINE_ANNOTATION", "OFFLINE_OBSERVER_REVIEW"):
            raise ValueError("unknown explicit annotation method")
        method = review + "_NOT_RUNTIME_INTENT_PROOF"
    else:
        method = "DETERMINISTIC_COMMAND_RULE_INFERENCE_NOT_INTENT_PROOF"
        for step in steps:
            stage = by_call.get(step.get("call_id"), "unassigned")
            evidence = explanations.get(step["step_id"], [])
            if step["kind"] == "MODEL_REQUEST":
                # Model request output IDs carry an explicit result association,
                # not a statement that all its tokens caused exactly this tool.
                source = step["source"]
                ids = source.get("output_call_ids") or source.get("output_tool_call_ids") or []
                lookup = by_call
                if not ids:
                    ids, lookup = source.get("bound_tool_call_ids") or [], by_native
                candidates = {lookup[key] for key in ids if key in lookup}
                if ids and len(candidates) == 1 and all(key in lookup for key in ids):
                    stage = next(iter(candidates))
                    evidence = [{"rule": "exact-model-output-call-id-association", "call_ids": ids}]
            elif step["kind"] == "TOOL_RESULT" and step.get("call_id") in by_call:
                evidence = [{"rule": "exact-tool-request-result-call-id", "call_id": step["call_id"]}]
            paths.append(["task", stage])
            explanations[step["step_id"]] = evidence or [{"rule": "no-recognized-stage-evidence"}]
    assignments = []
    for step, path in zip(steps, paths):
        assignments.append({"step_id": step["step_id"], "step_index": step["index"],
            "path": path, "labels": [taxonomy[key] for key in path],
            "call_id": step.get("call_id"), "request_id": step.get("request_id"),
            "kind": step["kind"], "source_ref": step["source_ref"],
            "source_sha256": step["source_sha256"], "method": method,
            "evidence": explanations.get(step["step_id"], [])})
    call_paths, conflicts, request_paths = {}, [], {}
    for assignment in assignments:
        call_id = assignment.get("call_id")
        if not _identity(call_id):
            continue
        old = call_paths.get(call_id)
        if old is not None and old != assignment["path"]:
            conflicts.append(call_id)
        call_paths[call_id] = assignment["path"]
    for assignment in assignments:
        request_id = assignment.get("request_id")
        if _identity(request_id):
            if request_id in request_paths and request_paths[request_id] != assignment["path"]:
                raise ValueError("conflicting model request semantic paths")
            request_paths[request_id] = assignment["path"]
    # Conflicting request/result labels must never reparent native events.
    for call_id in conflicts:
        call_paths[call_id] = ["task", "unassigned"]
    result = {"schema_version": 1, "kind": SCHEMA,
        **{key: trajectory.get(key) for key in ("run_id", "agent_id", "task_id", "trajectory_digest")},
        "taxonomy_version": taxonomy_version, "taxonomy": taxonomy, "taxonomy_digest": _digest(taxonomy),
        "rule_version": RULE_VERSION if explicit is None else None, "method": method,
        "source_marks_sha256": _digest(explicit) if explicit is not None else None,
        "source_marks": deepcopy(explicit),
        "intervals": _intervals(paths, taxonomy), "assignments": assignments,
        "call_paths": call_paths, "call_path_conflicts": sorted(set(conflicts)), "request_paths": request_paths,
        "coverage": {"steps": len(steps), "assigned_steps": sum("unassigned" not in p for p in paths),
                     "unassigned_steps": sum("unassigned" in p for p in paths),
                     "stage_counts": dict(Counter(p[-1] for p in paths))},
        "limits": ["Task labels are interpretation, not hidden reasoning or causal proof.",
                   "Unknown or mixed commands remain unassigned; no catch-all successful classification.",
                   "A tool spanning different responsibilities is not split without internal events.",
                   "Rules are not the paper's LLM recursive segmentation and have no claimed benchmark F1."]}
    validate_annotations(trajectory, result)
    return result


def validate_annotations(trajectory, annotations):
    """Reconstruct every path and reject missing, crossing, or forged intervals."""
    validate_trajectory(trajectory)
    if annotations.get("trajectory_digest") != trajectory.get("trajectory_digest"):
        raise ValueError("annotation trajectory identity mismatch")
    taxonomy_version, taxonomy = _vocabulary(annotations)
    if annotations.get("taxonomy_digest") != _digest(taxonomy):
        raise ValueError("annotation taxonomy digest mismatch")
    marks = annotations.get("source_marks")
    if marks is not None and annotations.get("source_marks_sha256") != _digest(marks):
        raise ValueError("annotation source marks digest mismatch")
    steps, assignments = trajectory["steps"], annotations.get("assignments")
    if not isinstance(assignments, list) or len(assignments) != len(steps):
        raise ValueError("annotations must cover every trajectory step exactly once")
    paths = []
    expected_calls, conflicting, expected_requests = {}, set(), {}
    for index, (step, assignment) in enumerate(zip(steps, assignments)):
        if assignment.get("step_id") != step["step_id"] or assignment.get("step_index") != index:
            raise ValueError("annotation order/step identity mismatch")
        if assignment.get("source_sha256") != step["source_sha256"]:
            raise ValueError("annotation evidence digest mismatch")
        for field in ("call_id", "request_id", "kind", "source_ref"):
            if assignment.get(field) != step.get(field):
                raise ValueError("annotation source identity mismatch: " + field)
        path = assignment.get("path")
        if (not isinstance(path, list) or not path or path[0] != "task" or len(path) > 8
                or any(not isinstance(key, str) or key not in taxonomy for key in path) or len(set(path)) != len(path)):
            raise ValueError("invalid semantic path")
        if assignment.get("labels") != [taxonomy[key] for key in path]:
            raise ValueError("semantic labels disagree with frozen taxonomy")
        paths.append(path)
        call_id = step.get("call_id")
        if _identity(call_id):
            if call_id in expected_calls and expected_calls[call_id] != path:
                conflicting.add(call_id)
            expected_calls[call_id] = path
        request_id = step.get("request_id")
        if _identity(request_id):
            if request_id in expected_requests and expected_requests[request_id] != path:
                raise ValueError("conflicting model request semantic paths")
            expected_requests[request_id] = path
    if marks is not None and paths != _explicit_paths(trajectory, marks, taxonomy, taxonomy_version):
        raise ValueError("assignments disagree with supplied reviewed marks")
    if annotations.get("intervals") != _intervals(paths, taxonomy):
        raise ValueError("intervals must be the exact nested, complete path partition")
    for call_id in conflicting:
        expected_calls[call_id] = ["task", "unassigned"]
    if annotations.get("call_paths") != expected_calls or annotations.get("call_path_conflicts") != sorted(conflicting):
        raise ValueError("call paths must derive exclusively from validated step assignments")
    if annotations.get("request_paths") != expected_requests:
        raise ValueError("request paths must derive exclusively from validated step assignments")
    for field in ("run_id", "agent_id", "task_id"):
        if annotations.get(field) != trajectory.get(field):
            raise ValueError("annotation/trajectory identity mismatch")
    return {"status": "STRUCTURE_AND_SOURCE_BINDING_VALID", "steps": len(steps),
            "meaning": "NOT_SEMANTIC_ACCURACY_OR_CAUSAL_PROOF"}


def apply_annotations(story, annotations):
    """Copy story, attach paths by exact call IDs, preserving old labels as evidence."""
    for key in ("run_id", "agent_id", "task_id"):
        if annotations.get(key) is not None and story.get(key) != annotations[key]:
            raise ValueError("annotation/story " + key + " mismatch")
    output = deepcopy(story)
    calls = annotations.get("call_paths") or {}
    _, taxonomy = _vocabulary(annotations)
    native_paths, known_calls = {}, {}
    for tool in output.get("tools") or []:
        path = calls.get(tool.get("call_id"), ["task", "unassigned"])
        labels = [taxonomy[key] for key in path]
        tool["semantic_original_path"] = tool.get("semantic_path")
        tool["semantic_path"] = labels
        tool["semantic_quality"] = annotations["method"]
        tool["semantic_taxonomy_path"] = path
        known_calls[tool.get("call_id")] = labels
        native_paths[tool.get("tool_call_id")] = labels
    for request in output.get("model_requests") or []:
        ids = request.get("bound_tool_call_ids") or []
        paths = {tuple(native_paths[key]) for key in ids if key in native_paths}
        request["semantic_original_path"] = request.get("semantic_path")
        reviewed = (annotations.get("request_paths") or {}).get(request.get("request_id"))
        request["semantic_path"] = ([taxonomy[key] for key in reviewed] if reviewed else
            list(next(iter(paths))) if ids and len(paths) == 1 and all(key in native_paths for key in ids) else
            [taxonomy["task"], taxonomy["unassigned"]])
        request["semantic_annotation_method"] = annotations["method"]
        known_calls[request.get("request_id")] = request["semantic_path"]
    by_request = {request.get("request_id"): request for request in output.get("model_requests") or []}
    for usage in output.get("model_usage") or []:
        usage["semantic_original_path"] = usage.get("semantic_path")
        owner = by_request.get(usage.get("request_id"))
        usage["semantic_path"] = (owner["semantic_path"] if owner else
                                  [taxonomy["task"], taxonomy["unassigned"]])
        usage["semantic_annotation_method"] = (annotations["method"] if owner else
            "NO_EXACT_REQUEST_ID; PRECEDING_TOOL_ORDER_NOT_USED_FOR_SEMANTIC_ATTRIBUTION")
    for segment in (output.get("wall_partition") or {}).get("segments") or []:
        active_ids = segment.get("active_ids") or []
        candidates = {tuple(known_calls[key]) for key in active_ids if key in known_calls}
        segment["semantic_original_path"] = segment.get("semantic_path")
        segment["semantic_path"] = (list(next(iter(candidates))) if active_ids and len(candidates) == 1
                                     and all(key in known_calls for key in active_ids) else
                                     [taxonomy["task"], taxonomy["unassigned"]])
    output["semantic_annotations"] = {key: deepcopy(annotations.get(key)) for key in
        ("schema_version", "kind", "taxonomy_version", "taxonomy_digest", "trajectory_digest", "method", "coverage", "limits")}
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--application", type=Path, required=True)
    parser.add_argument("--story", type=Path)
    parser.add_argument("--rpc-events", type=Path, help="raw RPC JSONL, including original user turn/start")
    parser.add_argument("--marks", type=Path, help="explicit reviewed sparse marks, bound to trajectory digest")
    parser.add_argument("--trajectory-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    def read(path):
        if path.stat().st_size > MAX_SOURCE_BYTES:
            raise ValueError("input file exceeds bound")
        return json.loads(path.read_text())
    rpc = None
    if args.rpc_events:
        if args.rpc_events.stat().st_size > MAX_SOURCE_BYTES:
            raise ValueError("RPC file exceeds bound")
        rpc = [json.loads(line) for line in args.rpc_events.read_text().splitlines() if line.strip()]
    trajectory = build_trajectory(read(args.application), read(args.story) if args.story else None, rpc)
    annotations = build_annotations(trajectory, read(args.marks) if args.marks else None)
    write_new(args.trajectory_output, trajectory)
    write_new(args.output, annotations)
    print(json.dumps({"status": "WRITTEN", "method": annotations["method"],
        "trajectory_digest": trajectory["trajectory_digest"], "coverage": annotations["coverage"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
