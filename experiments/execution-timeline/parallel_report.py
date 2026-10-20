#!/usr/bin/env python3
"""Composite display of separately replayed timelines, never a merged raw trace.

merge_reports is pure. Its caller must first run replay.verify_run for each
leaf and supply artifact identities from that verification step. The metadata
checks here prevent accidental report/receipt mixups; they are not signatures
or a substitute for independently decoding each original stream.
"""
from __future__ import annotations

import copy
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
from collections.abc import Mapping


AUTHORITY = "COMPOSITE_VIEW_OF_INDEPENDENTLY_VERIFIED_STREAMS"
GOOD_PATH = "RECONSTRUCTED_WITHIN_SELECTED_MODEL"
BAD_HEALTH = frozenset(("INCOMPLETE", "PARTIAL", "UNKNOWN", "UNRESOLVED", "FAILED"))
THREAD_REFERENCES = frozenset(("parent_key", "root_key", "thread_key", "thread",
    "target_thread_key", "parent_thread_key", "waker_key", "origin_key",
    "completion_seed_thread", "exec_predecessor_key", "from_thread", "to_thread"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def semantic_sha256(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False,
                     allow_nan=False, separators=(",", ":")).encode() + b"\n"
    return hashlib.sha256(raw).hexdigest()


def namespace(job_id, run_id, identity):
    # JSON tuple encoding avoids collisions when IDs themselves contain '/' or ':'.
    return "leaf:" + json.dumps([job_id, run_id, identity], ensure_ascii=True,
                                allow_nan=False, separators=(",", ":"))


def _identity(value, label):
    require(isinstance(value, dict), label + " identity required")
    require(isinstance(value.get("sha256"), str)
            and re.fullmatch("[0-9a-f]{64}", value["sha256"]), label + " SHA256 required")
    require(integer(value.get("size_bytes"), 1), label + " positive size_bytes required")
    return copy.deepcopy(value)


def _span(value, label):
    require(isinstance(value, dict), label + " must be an object")
    begin, end = value.get("begin_ns"), value.get("end_ns")
    require(integer(begin) and integer(end) and end > begin,
            label + " ordered positive interval required")
    return begin, end


def _references(value, job_id, run_id):
    if isinstance(value, list):
        return [_references(item, job_id, run_id) for item in value]
    if not isinstance(value, dict):
        return copy.deepcopy(value)
    result = {}
    for key, item in value.items():
        if key in THREAD_REFERENCES and isinstance(item, str) and item:
            result[key] = namespace(job_id, run_id, item)
        else:
            result[key] = _references(item, job_id, run_id)
    return result


def merge_reports(reports, jobs):
    """Return a read-only view; preserve all leaf findings and attribution gaps.

    reports may be a mapping keyed by job_id or a list aligned with jobs. Each
    job must have a verification receipt supplied by the independent replay
    caller: status=REPLAY_PASSED, manifest_identity, report_identity, and the
    semantic SHA256 of the replayed report. No CPU sequence stream is joined,
    and identical numeric TIDs in two leaves remain distinct display nodes.
    """
    require(isinstance(jobs, list) and jobs, "nonempty explicit jobs required")
    require(all(isinstance(job, dict) and isinstance(job.get("job_id"), str)
                and job["job_id"] for job in jobs), "nonempty job_id required")
    job_ids = [job["job_id"] for job in jobs]
    require(len(set(job_ids)) == len(job_ids), "duplicate job_id")
    if isinstance(reports, Mapping):
        require(set(reports) == set(job_ids), "report/job identities differ")
        reports = [reports[job_id] for job_id in job_ids]
    require(isinstance(reports, list) and len(reports) == len(jobs), "one report per job required")

    leaves, tools, threads, findings, paths, limits = [], [], [], [], [], []
    boot_id = None
    seen_tools, run_ids = set(), set()
    begin, end, event_count = None, None, 0
    for source, job in zip(reports, jobs):
        require(isinstance(source, dict) and source.get("schema_version") == 1,
                "leaf timeline schema v1 required")
        a, b = _span(source.get("run"), "leaf run")
        run = source["run"]
        run_id = run.get("run_id")
        require(isinstance(run_id, str) and run_id and run_id not in run_ids,
                "unique nonempty leaf run_id required")
        run_ids.add(run_id)
        require(run.get("clock") == "CLOCK_MONOTONIC", "explicit leaf CLOCK_MONOTONIC required")
        require(isinstance(run.get("boot_id"), str) and run["boot_id"], "leaf boot identity required")
        if boot_id is None:
            boot_id = run["boot_id"]
        require(run["boot_id"] == boot_id, "different boots cannot share an absolute composite time axis")
        begin, end = a if begin is None else min(begin, a), b if end is None else max(end, b)
        verification = job.get("verification")
        require(isinstance(verification, dict) and verification.get("status") == "REPLAY_PASSED",
                "every leaf must independently pass raw replay before composition")
        manifest_identity = _identity(verification.get("manifest_identity"), "manifest")
        report_identity = _identity(verification.get("report_identity"), "report")
        require(verification.get("report_semantic_sha256") == semantic_sha256(source),
                "replayed report differs from supplied verification binding")
        job_id = job["job_id"]
        require(isinstance(source.get("tools"), list) and isinstance(source.get("threads"), list)
                and isinstance(source.get("findings"), list), "explicit leaf tools/threads/findings required")
        health, critical = source.get("health"), source.get("critical_path")
        require(isinstance(health, dict) and isinstance(critical, dict)
                and isinstance(critical.get("tools"), list), "leaf health and completion-path statuses required")
        keys = [thread.get("key") for thread in source["threads"] if isinstance(thread, dict)]
        require(len(keys) == len(source["threads"]) and all(isinstance(key, str) and key for key in keys)
                and len(set(keys)) == len(keys), "unique stable thread keys within each leaf required")
        leaf_tools = set()
        for original in source["tools"]:
            require(isinstance(original, dict) and isinstance(original.get("tool_call_id"), str)
                    and original["tool_call_id"], "leaf tool_call_id required")
            tool_id = original["tool_call_id"]
            require(tool_id not in seen_tools, "tool_call_id collision across independent leaves")
            seen_tools.add(tool_id)
            leaf_tools.add(tool_id)
            ta, tb = _span(original, "tool")
            require(a <= ta < tb <= b, "tool interval outside its source run")
            tool = _references(original, job_id, run_id)
            tool.update(source_job_id=job_id, source_run_id=run_id)
            if tool.get("root_key") is None and isinstance(original.get("root"), dict):
                root = original["root"]
                birth = root.get("birth_ns", root.get("thread_birth_ns"))
                candidates = [thread["key"] for thread in source["threads"]
                              if thread.get("tid") == root.get("tid") and thread.get("birth_ns") == birth]
                if len(candidates) == 1:
                    tool["root_key"] = namespace(job_id, run_id, candidates[0])
            tools.append(tool)
        for original in source["threads"]:
            thread = _references(original, job_id, run_id)
            thread.update(key=namespace(job_id, run_id, original["key"]),
                          source_thread_key=original["key"], source_job_id=job_id, source_run_id=run_id)
            process = original.get("process_key")
            if process is None and integer(original.get("tgid"), 1) and integer(original.get("process_birth_ns"), 1):
                process = [boot_id, original["tgid"], original["process_birth_ns"]]
            if process is not None:
                thread["process_key"] = namespace(job_id, run_id, process)
            # Missing Agent/tool ownership stays missing; job membership does
            # not establish who owns an infrastructure/background thread.
            threads.append(thread)
        for original in source["findings"]:
            require(isinstance(original, dict), "leaf finding must be an object")
            finding = _references(original, job_id, run_id)
            finding.update(source_job_id=job_id, source_run_id=run_id)
            findings.append(finding)
        for original in critical["tools"]:
            require(isinstance(original, dict) and original.get("tool_call_id") in leaf_tools,
                    "completion path must refer to its own leaf tool")
            path = _references(original, job_id, run_id)
            path.update(source_job_id=job_id, source_run_id=run_id)
            declared = next(tool for tool in source["tools"] if tool["tool_call_id"] == original["tool_call_id"])
            path.setdefault("agent_id", declared.get("agent_id"))
            path.setdefault("task_id", declared.get("task_id"))
            paths.append(path)
        leaf_events = source.get("totals", {}).get("events")
        require(integer(leaf_events), "explicit leaf event count required")
        event_count += leaf_events
        unowned = sum(not thread.get("agent_id") or not thread.get("tool_call_id") for thread in source["threads"])
        leaves.append({"job_id": job_id, "source_run_id": run_id, "run": copy.deepcopy(run),
            "manifest_identity": manifest_identity, "report_identity": report_identity,
            "report_semantic_sha256": semantic_sha256(source), "verification": copy.deepcopy(verification),
            "job": {key: copy.deepcopy(value) for key, value in job.items() if key != "verification"},
            "health": copy.deepcopy(health), "critical_path_status": critical.get("status"),
            "findings": copy.deepcopy(source["findings"]), "unowned_thread_rows": unowned,
            "totals": copy.deepcopy(source.get("totals", {})),
            "limitations": copy.deepcopy(source.get("limitations", []))})
        for text in source.get("limitations", []):
            if text not in limits:
                limits.append(copy.deepcopy(text))

    bad_health = any(str(leaf["health"].get("status", "UNKNOWN")).upper() in BAD_HEALTH for leaf in leaves)
    good_paths = all(leaf["critical_path_status"] == GOOD_PATH for leaf in leaves)
    composite_id = "composite-" + semantic_sha256([
        [leaf["job_id"], leaf["source_run_id"], leaf["manifest_identity"], leaf["report_identity"]]
        for leaf in leaves])[:24]
    preferred = {"begin_ns": min(tool["invocation_ns"] if integer(tool.get("invocation_ns"))
                    and begin <= tool["invocation_ns"] <= tool["begin_ns"] else tool["begin_ns"] for tool in tools),
                 "end_ns": max(tool["end_ns"] for tool in tools),
                 "scope": "DISPLAY_HINT_ONLY; FULL_LEAF_DATA_NOT_CROPPED"} if tools else None
    return {"schema_version": 1, "authority": AUTHORITY,
        "verification_status": "INDEPENDENT_LEAF_REPLAY_PASSED; NOT_A_SINGLE_MERGED_RAW_STREAM",
        "run": {"run_id": composite_id, "boot_id": boot_id, "clock": "CLOCK_MONOTONIC",
                "begin_ns": begin, "end_ns": end},
        "preferred_view": preferred, "leaves": leaves, "tools": tools, "threads": threads,
        "health": {"status": "INCOMPLETE" if bad_health else "COMPOSITE_PER_LEAF_HEALTH_RETAINED",
                   "scope": "NO_NEW_TRANSPORT_VERDICT; SEE_EACH_LEAF_HEALTH", "leaves": [
                       {"job_id": leaf["job_id"], "source_run_id": leaf["source_run_id"],
                        "health": copy.deepcopy(leaf["health"])} for leaf in leaves]},
        "findings": findings,
        "critical_path": {"status": GOOD_PATH if good_paths else "INCOMPLETE", "tools": paths,
                          "scope": "SEPARATE_PER_TOOL_PATHS; NO_CROSS_JOB_CAUSAL_EDGES_OR_BATCH_CRITICAL_PATH"},
        "totals": {"tools": len(tools), "threads": len(threads), "events": event_count,
                   "leaf_streams": len(leaves), "unowned_thread_rows": sum(leaf["unowned_thread_rows"] for leaf in leaves),
                   "scope": "SUM_OF_LEAF_ROWS; NOT_GLOBAL_DISTINCT_THREADS_FILES_OR_EVENTS"},
        "limitations": limits + [
            "合成页面只展示分别重放通过的独立流，不把多个CPU序号拼接成一个原始记录流。",
            "批次墙钟以campaign记录为准；线程、工具、并发读取累计时长都不能相加冒充墙钟。",
            "跨Agent文件行数或bytes之和不代表全局不同文件数；共享inode与重复逻辑读取仍分开保留。",
            "source_job_id只说明来源流，不给未归属线程补造Agent身份。"]}


def campaign_wall(campaign):
    """Validate the controller's fixed-work wall record without inventing it."""
    require(isinstance(campaign, dict), "campaign object required")
    require(campaign.get("concurrency") in (2, 4, 6, 8)
            and type(campaign.get("concurrency")) is int, "concurrency must be 2/4/6/8")
    require(campaign.get("total_jobs") == 8 and type(campaign.get("total_jobs")) is int,
            "fixed total_jobs=8 required; concurrency is not the total work")
    jobs = campaign.get("jobs")
    require(isinstance(jobs, list) and len(jobs) == 8, "all eight jobs must be retained")
    begin, end = campaign.get("batch_start_ns"), campaign.get("batch_end_ns")
    require(integer(begin) and integer(end) and end >= begin, "controller batch boundaries required")
    require(integer(campaign.get("batch_wall_ns")) and campaign["batch_wall_ns"] == end - begin,
            "batch wall must exactly match controller batch boundaries")
    campaign_begin, campaign_end = campaign.get("campaign_start_ns"), campaign.get("campaign_end_ns")
    require(integer(campaign_begin) and integer(campaign_end) and campaign_begin <= begin <= end <= campaign_end
            and integer(campaign.get("campaign_wall_ns"))
            and campaign["campaign_wall_ns"] == campaign_end - campaign_begin,
            "full campaign wall must match its separate setup-to-postprocess boundaries")
    require(all(isinstance(job, dict) and isinstance(job.get("job_id"), str) and job["job_id"] for job in jobs)
            and len({job["job_id"] for job in jobs}) == 8, "unique eight job IDs required")
    complete = campaign.get("status") == "WORKERS_COMPLETED" and all(job.get("worker_exit_code") == 0
        and type(job.get("worker_exit_code")) is int for job in jobs)
    returned, return_wall = campaign.get("agent_return_end_ns"), campaign.get("agent_return_batch_wall_ns")
    if returned is not None or return_wall is not None:
        require(integer(returned) and begin <= returned <= end and integer(return_wall)
                and return_wall == returned - begin,
                "Agent-return wall must match its explicit controller boundary")
        require(all(integer(job.get("agent_return_ns")) for job in jobs)
                and max(job["agent_return_ns"] for job in jobs) == returned,
                "last Agent-return boundary differs from job records")
    quiet_tail = end - returned if returned is not None else None
    return {"benchmark": campaign.get("benchmark"), "concurrency": campaign["concurrency"],
            "total_jobs": 8, "batch_start_ns": begin, "batch_end_ns": end,
            "batch_wall_ns": campaign["batch_wall_ns"],
            "campaign_start_ns": campaign_begin, "campaign_end_ns": campaign_end,
            "campaign_wall_ns": campaign["campaign_wall_ns"],
            "agent_return_end_ns": returned, "agent_return_batch_wall_ns": return_wall,
            "last_agent_return_to_last_quiescence_ns": quiet_tail,
            "management_tail_scope": "LAST_QUIESCENCE_MINUS_LAST_AGENT_RETURN; NOT_SUM_OF_JOB_FREEZE_COSTS; MAY_OVERLAP_OTHER_JOBS",
            "status": "COMPLETE" if complete else "INCOMPLETE", "source_status": campaign.get("status"),
            "scope": "PRIMARY_BATCH_WALL=FIRST_RELEASE_TO_LAST_QUIESCENCE; CAMPAIGN_WALL_ALSO_INCLUDES_SETUP_AND_FINALIZATION; NEVER_SUM_THREAD_DURATIONS"}


def resource_delta(before, after, expected_cgroup_id):
    """Cgroup boundary counters only; absent/reset counters stay unknown."""
    result = {"status": "UNKNOWN", "counters": {}, "gauges": {}, "io_by_device": {}, "issues": [],
        "scope": "CGROUP_BEFORE_AFTER_BOUNDARY_WINDOW; NOT_EXACT_TOOL_SYSCALL_COUNTERS_OR_HARDWARE_DEVICE_TIME; PSI_NOT_ADDED_TO_WALL",
        "memory_peak_scope": "CGROUP_LIFETIME_HIGH_WATER_GAUGE; NOT_THIS_WINDOW_PEAK_OR_SAMPLED_PEAK"}
    snapshots = (before, after)
    identity_ok = (all(isinstance(value, dict) for value in snapshots) and integer(expected_cgroup_id, 1)
        and all(value.get("status") in {"CAPTURED_BOUNDARY_COUNTERS", "PARTIAL_BOUNDARY_COUNTERS"} for value in snapshots)
        and all(value.get("cgroup_id") == expected_cgroup_id for value in snapshots)
        and isinstance(before.get("cgroup_root"), str) and before["cgroup_root"] == after.get("cgroup_root")
        and all(integer(value.get(key)) for value in snapshots for key in ("begin_ns", "end_ns"))
        and before["begin_ns"] <= before["end_ns"] <= after["begin_ns"] <= after["end_ns"])
    result["cgroup_id"] = expected_cgroup_id
    result["window_begin_ns"] = before.get("begin_ns") if isinstance(before, dict) else None
    result["window_end_ns"] = after.get("end_ns") if isinstance(after, dict) else None
    if not identity_ok:
        result["issues"].append("MISSING_OR_DIFFERENT_CGROUP_IDENTITY_OR_UNORDERED_BOUNDARY")

    def text(snapshot, name):
        if not identity_ok or name in snapshot.get("errors", {}):
            return None
        value = snapshot.get("files", {}).get(name)
        return value if isinstance(value, str) else None

    def unsigned(value):
        return int(value) if isinstance(value, str) and value.isascii() and value.isdigit() else None

    def table(snapshot, name):
        value = text(snapshot, name)
        parsed = {}
        if value is None:
            return parsed
        for line in value.splitlines():
            fields = line.split()
            if len(fields) != 2 or fields[0] in parsed:
                return {}
            parsed[fields[0]] = unsigned(fields[1])
        return parsed

    def counter(name, first, last):
        valid = integer(first) and integer(last) and last >= first
        result["counters"][name] = {"before": first, "after": last,
            "delta": last - first if valid else None,
            "status": "KNOWN_BOUNDARY_DELTA" if valid else "UNKNOWN_COUNTER_RESET" if integer(first) and integer(last) else "UNKNOWN_MISSING_OR_PARSE"}

    for filename, keys in (("cpu.stat", ("usage_usec", "user_usec", "system_usec", "nr_periods", "nr_throttled", "throttled_usec")),
            ("memory.stat", ("pgfault", "pgmajfault", "workingset_refault_file", "workingset_refault_anon", "pgscan", "pgsteal")),
            ("pids.events", ("max",))):
        first, last = table(before, filename), table(after, filename)
        for key in keys:
            counter(filename + "." + key, first.get(key), last.get(key))
    for domain in ("cpu", "memory", "io"):
        values = []
        for snapshot in snapshots:
            parsed = {}
            for line in (text(snapshot, domain + ".pressure") or "").splitlines():
                fields = line.split()
                if not fields or fields[0] in parsed:
                    parsed = {}
                    break
                totals = [part[6:] for part in fields[1:] if part.startswith("total=")]
                parsed[fields[0]] = unsigned(totals[0]) if len(totals) == 1 else None
            values.append(parsed)
        for kind in ("some", "full"):
            counter(domain + ".pressure." + kind + ".total_usec", values[0].get(kind), values[1].get(kind))
    devices = []
    for snapshot in snapshots:
        parsed = {}
        for line in (text(snapshot, "io.stat") or "").splitlines():
            fields = line.split()
            if not fields or not re.fullmatch(r"[0-9]+:[0-9]+", fields[0]) or fields[0] in parsed:
                parsed = {}
                break
            entry = {}
            for part in fields[1:]:
                key, separator, value = part.partition("=")
                if not separator or key in entry:
                    entry = {}
                    break
                entry[key] = unsigned(value)
            parsed[fields[0]] = entry
        devices.append(parsed)
    for device in sorted(set(devices[0]) | set(devices[1])):
        result["io_by_device"][device] = {}
        for key in ("rbytes", "wbytes", "rios", "wios"):
            name = "io.stat." + device + "." + key
            counter(name, devices[0].get(device, {}).get(key), devices[1].get(device, {}).get(key))
            result["io_by_device"][device][key] = copy.deepcopy(result["counters"][name])
    for key in ("rbytes", "wbytes", "rios", "wios"):
        entries = [value[key] for value in result["io_by_device"].values()]
        known = [value["delta"] for value in entries if integer(value["delta"])]
        result["counters"]["io.stat.listed_devices_sum." + key] = {
            "delta": sum(known) if entries and len(known) == len(entries) else None,
            "known_delta_sum": sum(known), "unknown_devices": len(entries) - len(known),
            "status": "KNOWN_LISTED_DEVICE_BOUNDARY_SUM" if entries and len(known) == len(entries) else "UNKNOWN_MISSING_BASELINE_OR_NO_RECORDED_DEVICE",
            "scope": "SUM_OF_REPORTED_GUEST_DEVICE_COUNTERS; NOT_PHYSICAL_HOST_SSD_BYTES"}
    for filename in ("memory.current", "memory.peak", "pids.current"):
        values = [text(snapshot, filename) for snapshot in snapshots]
        result["gauges"][filename] = {"before": unsigned(values[0].strip()) if values[0] is not None else None,
            "after": unsigned(values[1].strip()) if values[1] is not None else None}
    for key in ("anon", "file", "kernel", "slab"):
        result["gauges"]["memory.stat." + key] = {"before": table(before, "memory.stat").get(key),
            "after": table(after, "memory.stat").get(key)}
    unknown = sum(value.get("delta") is None for value in result["counters"].values())
    unknown += sum(value[key] is None for value in result["gauges"].values() for key in ("before", "after"))
    result["unknown_values"] = unknown
    result["status"] = "COMPLETE_FOR_DECLARED_BOUNDARY_FIELDS" if identity_ok and not unknown else "PARTIAL_OR_UNKNOWN_BOUNDARY_FIELDS"
    return result


MAX_JSON_BYTES = 64 * 1024 * 1024
DISPLAY_JSON_BYTES = 8 * 1024 * 1024
JOB_COLUMNS = ("benchmark", "concurrency", "job_id", "source_run_id", "task_id", "mode",
    "official_passed", "worker_exit_code", "ready_ns", "release_issued_ns", "agent_return_ns",
    "quiescent_ns", "agent_return_to_quiescence_ns", "done_observed_ns", "leaf_health_status", "leaf_critical_path_status",
    "selected_tool_timeline_status", "unowned_thread_rows", "read_calls", "returned_bytes",
    "returned_bytes_known_sum", "unknown_return_tools", "per_tool_object_rows_sum_not_global_distinct",
    "resource_status", "cpu_usage_usec", "cpu_user_usec", "cpu_system_usec", "pgfault", "pgmajfault",
    "io_read_bytes", "io_write_bytes", "cpu_psi_some_usec", "memory_psi_some_usec", "io_psi_some_usec",
    "memory_current_before", "memory_current_after", "memory_lifetime_peak_after")


def _display_fields(value, fields):
    return {key: copy.deepcopy(value[key]) for key in fields if key in value}


def _longest_intervals(values, limit):
    """Select existing intervals, not a coalesced or reinterpreted state span."""
    selected = sorted(enumerate(values), key=lambda pair: (
        -(pair[1].get("end_ns", 0) - pair[1].get("begin_ns", 0)), pair[0]))[:limit]
    return [value for _, value in sorted(selected)]


def display_projection(report, complete_identity, budget=DISPLAY_JSON_BYTES):
    """Bound only the viewer input; the complete composite and leaves stay intact.

    Calls are available in each complete leaf and CSV, not copied into this
    overview. Existing longest state intervals are shown without joining gaps.
    The same budget per leaf keeps a busy Agent from consuming all lanes.
    """
    require(integer(budget, 1024), "positive bounded display budget required")
    _identity(complete_identity, "complete composite")
    source_threads = report.get("threads", [])
    counts = {"threads": len(source_threads),
        "thread_segments": sum(len(thread.get("segments", [])) for thread in source_threads),
        "calls": sum(len(thread.get("calls", [])) for thread in source_threads),
        "critical_segments": sum(len(tool.get("segments", [])) for tool in report.get("critical_path", {}).get("tools", [])),
        "findings": len(report.get("findings", []))}
    thread_fields = ("key", "tid", "tgid", "birth_ns", "process_birth_ns", "process_key", "parent_key",
        "root_key", "agent_id", "task_id", "tool_call_id", "comm", "begin_ns", "end_ns",
        "source_job_id", "source_run_id", "source_thread_key", "state_totals_ns", "status",
        "capture_observed_begin_ns", "timeline_scope", "execution_window_intersection")
    interval_fields = ("begin_ns", "end_ns", "state", "cpu", "reason", "wait_kind", "waker_key",
        "wakeup_ns", "thread_key", "syscall_call_id", "evidence", "wake_evidence")
    syscall_fields = ("call_id", "nr", "name", "start_ns", "end_ns", "result", "closure", "status")
    tool_fields = ("tool_call_id", "agent_id", "task_id", "root", "root_key", "begin_ns", "end_ns",
        "invocation_ns", "status", "source_job_id", "source_run_id", "name")
    root_keys = {tool.get("root_key") for tool in report.get("tools", [])}
    by_job = {}
    for thread in source_threads:
        by_job.setdefault(thread.get("source_job_id"), []).append(thread)
    for threads in by_job.values():
        threads.sort(key=lambda thread: (thread.get("key") not in root_keys,
            -(thread["end_ns"] - thread["begin_ns"]), thread["key"]))

    def interval(value):
        result = _display_fields(value, interval_fields)
        if isinstance(value.get("syscall"), dict):
            result["syscall"] = _display_fields(value["syscall"], syscall_fields)
        if isinstance(value.get("stack"), list):
            result["stack"] = copy.deepcopy(value["stack"][:8])
            result["display_stack_frames_omitted"] = max(0, len(value["stack"]) - 8)
        result["display_context_scope"] = "DISPLAY_SUMMARY; FULL_FILES_CALLS_STACK_AND_CONTEXT_IN_LEAF_REPORT"
        return result

    # Even the most conservative fallback retains one existing lane per leaf.
    for lane_cap, segment_cap in ((64, 64), (32, 32), (16, 16), (8, 8), (4, 4), (1, 1)):
        view = {key: copy.deepcopy(report[key]) for key in ("schema_version", "authority", "verification_status",
            "run", "preferred_view", "health", "totals", "campaign_timing") if key in report}
        view["tools"] = [_display_fields(tool, tool_fields) for tool in report.get("tools", [])]
        view["threads"] = []
        for threads in by_job.values():
            for thread in threads[:lane_cap]:
                shown = _display_fields(thread, thread_fields)
                selected = _longest_intervals(thread.get("segments", []), segment_cap)
                shown["segments"] = [interval(value) for value in selected]
                shown["calls"] = []
                shown["display_omitted_calls"] = len(thread.get("calls", []))
                shown["display_omitted_segments"] = len(thread.get("segments", [])) - len(selected)
                view["threads"].append(shown)
        critical = report.get("critical_path", {})
        view["critical_path"] = {key: copy.deepcopy(value) for key, value in critical.items() if key != "tools"}
        view["critical_path"]["tools"] = []
        for tool in critical.get("tools", []):
            shown = _display_fields(tool, ("tool_call_id", "agent_id", "task_id", "source_job_id", "source_run_id",
                "status", "wall_ns", "unknown_ns", "accounted_ns", "state_totals_ns", "completion_seed_thread"))
            selected = _longest_intervals(tool.get("segments", []), segment_cap)
            shown["segments"] = [interval(value) for value in selected]
            shown["display_omitted_segments"] = len(tool.get("segments", [])) - len(selected)
            view["critical_path"]["tools"].append(shown)
        view["findings"] = copy.deepcopy(report.get("findings", [])[:64])
        view["leaves"] = [{**_display_fields(leaf, ("job_id", "source_run_id", "manifest_identity", "report_identity",
                "report_semantic_sha256", "health", "critical_path_status", "unowned_thread_rows", "totals")),
            "complete_report_href": "reports/" + leaf["job_id"] + "/report.json",
            "complete_view_href": "reports/" + leaf["job_id"] + "/timeline.html",
            "read_csv_href": "reports/" + leaf["job_id"] + "/reads/reads.csv"} for leaf in report.get("leaves", [])]
        displayed = {"threads": len(view["threads"]),
            "thread_segments": sum(len(thread["segments"]) for thread in view["threads"]),
            "calls": 0, "critical_segments": sum(len(tool["segments"]) for tool in view["critical_path"]["tools"]),
            "findings": len(view["findings"])}
        view["display_projection"] = {"status": "DISPLAY_ONLY_BOUNDED_PROJECTION", "budget_bytes": budget,
            "source_complete_report_identity": copy.deepcopy(complete_identity), "source_counts": counts,
            "displayed_counts": displayed, "omitted_counts": {key: counts[key] - displayed[key] for key in counts},
            "per_leaf_thread_cap": lane_cap, "per_thread_and_path_segment_cap": segment_cap,
            "selection": "ROOT_FIRST_THEN_LONGEST_THREAD_PER_LEAF; LONGEST_EXISTING_INTERVALS; NO_STATE_COALESCING_OR_GAP_FILLING",
            "complete_report_href": "timeline-report.json", "index_href": "index.html",
            "coverage": "ORIGINAL_HEALTH_AND_PATH_STATUS_RETAINED; DISPLAY_SUBSET_IS_NOT_A_NEW_VERIFICATION_OR_COMPLETE_HISTORY"}
        view["limitations"] = copy.deepcopy(report.get("limitations", [])) + [
            "当前合成图是有界显示投影，不是完整事件或调用历史。省略区间留空，不补造成运行、等待或空闲。",
            "所有完整leaf JSON/逐次读取CSV/单Agent完整页面及完整合成JSON均保留；省略数量不改变原始health。"]
        if len(json.dumps(view, ensure_ascii=False, allow_nan=False).encode()) <= budget:
            return view
    raise ValueError("minimum display metadata exceeds viewer budget; full leaf evidence retained")


def navigation_index(view):
    """Small static, relative navigation; all labels are escaped, no JS fetch."""
    from html import escape
    links = []
    for leaf in view["leaves"]:
        label = escape(leaf["job_id"])
        prefix = 'reports/' + leaf["job_id"] + '/'
        destinations = [('完整时间线', leaf["complete_view_href"]), ('完整JSON', leaf["complete_report_href"]),
            ('逐次读取CSV', leaf["read_csv_href"]), ('逐文件聚合CSV', prefix + 'reads/files.csv'),
            ('窗口外读取CSV', prefix + 'reads/excluded-reads.csv'), ('未归属读取CSV', prefix + 'reads/unassigned-reads.csv'),
            ('完整读取导出回执', prefix + 'reads/receipt.json'), ('汇总JSON', prefix + 'summary.json'),
            ('资源边界与差值JSON', prefix + 'resources.json'), ('独立重放回执', prefix + 'verification.json'),
            ('官方结果与coverage', prefix + 'acceptance.json')]
        links.append('<li>{}: {}</li>'.format(label, ' · '.join('<a href="{}">{}</a>'.format(
            escape(href, quote=True), escape(title)) for title, href in destinations)))
    return ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>多Agent结果导航</title>'
        '<h1>多Agent结果导航</h1><p>合成页只做有界显示，不代替独立重放或完整记录。</p>'
        '<p><a href="timeline.html">多Agent合成泳道（显示子集）</a> · '
        '<a href="timeline-report.json">完整合成JSON（可能较大）</a> · '
        '<a href="timeline-display.json">显示投影JSON</a> · <a href="jobs.csv">任务与墙钟CSV</a> · '
        '<a href="resources.csv">资源CSV</a></p><ul>' + ''.join(links) + '</ul></html>')


def load_json(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_JSON_BYTES,
            "bounded regular non-symlink JSON required: " + str(path))
    raw = path.read_bytes()
    require(len(raw) <= MAX_JSON_BYTES, "JSON grew past input limit")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("nonfinite JSON number: " + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def resolve_job(root, job):
    """Rebase an exported Guest output path using the controller's job ID only."""
    root = Path(root).resolve(strict=True)
    name = job.get("job_id")
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}", name),
            "safe controller job ID required")
    old = Path(job.get("output", ""))
    require(old.name == name and ".." not in old.parts and old.parent.name == "jobs",
            "Guest output basename/jobs binding differs from job ID")
    path = root / "jobs" / name
    require(path.is_dir() and not path.is_symlink() and path.resolve(strict=True) == path,
            "fresh exported job path must not escape campaign or traverse symlinks")
    worker = load_json(path / "worker-result.json")
    require(worker.get("schema_version") == 1 and worker.get("job_id") == name,
            "worker result identity differs from controller job")
    relative = Path(worker.get("timeline_directory", ""))
    require(isinstance(worker.get("timeline_directory"), str) and worker["timeline_directory"]
            and not relative.is_absolute() and ".." not in relative.parts, "safe relative timeline_directory required")
    timeline = path / relative
    resolved = timeline.resolve(strict=True)
    require(timeline.is_dir() and not timeline.is_symlink() and (resolved == path or path in resolved.parents),
            "timeline directory escapes its job")
    return path, resolved, worker


def process_campaign(directory, output, collector=None, expected_mode="ORACLE_REFERENCE"):
    """Independently replay each leaf, then write fresh report/CSV/display files."""
    from common import digest, write_new
    from export_reads import export_report
    from render import render_report
    from replay import verify_run
    from summarize import summarize_report

    require(expected_mode in ("ORACLE_REFERENCE", "MODEL_AGENT"), "explicit supported campaign mode required")
    root, output = Path(directory).resolve(strict=True), Path(output)
    require(not output.exists() and not output.is_symlink(), "fresh output required; never overwrite")
    campaign_path = root / "campaign.json"
    before = digest(campaign_path)
    campaign = load_json(campaign_path)
    timing = campaign_wall(campaign)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / "reports").mkdir(mode=0o700)
    reports, jobs, rows, receipts, resource_rows = {}, [], [], [], []
    for original in campaign["jobs"]:
        job_dir, timeline, worker = resolve_job(root, original)
        require(worker.get("benchmark") == campaign.get("benchmark"), "worker benchmark differs")
        require(worker.get("mode") == expected_mode and type(worker.get("official_passed")) is bool,
                "worker mode must match explicitly selected mode and official boolean result")
        for key in ("agent_return_ns", "quiescent_ns"):
            require(type(worker.get(key)) is int and worker[key] == original.get(key),
                    "worker/controller lifecycle boundary differs: " + key)
        require(original["release_issued_ns"] <= original["agent_return_ns"] <= original["quiescent_ns"]
                <= original["done_observed_ns"], "job lifecycle boundaries are not ordered")
        manifest_path = timeline / "manifest.json"
        manifest_identity, worker_identity = digest(manifest_path), digest(job_dir / "worker-result.json")
        report = verify_run(timeline, collector, manifest_identity["sha256"])
        require(report["run"]["boot_id"] == campaign.get("boot_id"), "leaf/controller boot identity differs")
        require(digest(manifest_path) == manifest_identity and digest(job_dir / "worker-result.json") == worker_identity,
                "leaf manifest or worker result changed during independent replay")
        leaf = output / "reports" / original["job_id"]
        leaf.mkdir(mode=0o700)
        report_path = leaf / "report.json"
        write_new(report_path, report)
        report_identity = digest(report_path)
        write_new(leaf / "timeline.html", render_report(report).encode())
        verification = {"status": "REPLAY_PASSED", "manifest_identity": manifest_identity,
            "report_identity": report_identity, "report_semantic_sha256": semantic_sha256(report),
            "source_manifest": str(manifest_path), "source_timeline": str(timeline),
            "worker_result_identity": worker_identity,
            "scope": "ACTUAL_INDEPENDENT_RAW_DECODE_AND_REPLAY; NOT_A_COVERAGE_OR_OFFICIAL_TASK_PASS"}
        write_new(leaf / "verification.json", verification)
        summary = summarize_report(report)
        write_new(leaf / "summary.json", summary)
        snapshots, snapshot_identities = [], []
        for phase in ("before", "after"):
            snapshot_path = root / "control" / original["job_id"] / ("resources-" + phase + ".json")
            snapshots.append(load_json(snapshot_path) if snapshot_path.exists() else None)
            snapshot_identities.append(digest(snapshot_path) if snapshot_path.exists() else None)
        metadata = original.get("ready_metadata") or {}
        expected_cgroup = metadata.get("cgroup_id") if isinstance(metadata, dict) else None
        resources = resource_delta(snapshots[0], snapshots[1], expected_cgroup)
        if isinstance(metadata, dict) and metadata.get("cgroup_root") and any(
                isinstance(snapshot, dict) and snapshot.get("cgroup_root") != metadata["cgroup_root"] for snapshot in snapshots):
            resources = resource_delta(snapshots[0], snapshots[1], None)
            resources["issues"].append("SNAPSHOT_ROOT_DIFFERS_FROM_READY_REGISTRATION")
        if all(isinstance(snapshot, dict) and all(integer(snapshot.get(key)) for key in ("begin_ns", "end_ns"))
               for snapshot in snapshots) and not (original["release_issued_ns"] <= snapshots[0]["begin_ns"]
                <= snapshots[0]["end_ns"] <= original["agent_return_ns"] <= original["quiescent_ns"]
                <= snapshots[1]["begin_ns"] <= snapshots[1]["end_ns"] <= original["done_observed_ns"]):
            resources = resource_delta(snapshots[0], snapshots[1], None)
            resources["issues"].append("RESOURCE_BOUNDARIES_DO_NOT_ENCLOSE_THIS_JOB_RELEASE_AND_QUIESCENCE")
        write_new(leaf / "resources.json", {"schema_version": 1, "before": snapshots[0], "after": snapshots[1],
            "source_identities": snapshot_identities, "delta": resources})
        exported = export_report(report, leaf / "reads", {"path": str(report_path.absolute()),
            "bytes": report_identity["size_bytes"], "sha256": report_identity["sha256"]})
        acceptance = {"schema_version": 1, "job_id": original["job_id"], "benchmark": worker["benchmark"],
            "mode": worker["mode"], "official_passed": worker["official_passed"],
            "official_result": worker.get("official_result"), "worker_exit_code": original.get("worker_exit_code"),
            "verification": verification, "health": report["health"],
            "critical_path_status": report["critical_path"]["status"],
            "selected_tool_timeline_status": summary.get("selected_tool_timeline_status"),
            "capture_status": worker.get("capture_status"), "reads_receipt": digest(leaf / "reads" / "receipt.json"),
            "complete_view_receipt": digest(leaf / "timeline.html"),
            "resource_receipt": digest(leaf / "resources.json"), "resource_status": resources["status"],
            "authority": "SEPARATE_OFFICIAL_RESULT_RAW_REPLAY_AND_COVERAGE_DIMENSIONS_NOT_ONE_GREEN_BOOLEAN"}
        write_new(leaf / "acceptance.json", acceptance)
        job = copy.deepcopy(original)
        job["verification"] = verification
        jobs.append(job)
        reports[job["job_id"]] = report
        receipts.append(acceptance)
        reading = [tool["reads"] for tool in summary["tools"]]
        unknown = sum(type(value.get("returned_bytes")) is not int for value in reading)
        row = {key: original.get(key) for key in JOB_COLUMNS}
        row.update(benchmark=worker["benchmark"], concurrency=campaign["concurrency"], mode=worker["mode"],
            agent_return_to_quiescence_ns=original["quiescent_ns"] - original["agent_return_ns"],
            task_id=worker.get("task_id"), official_passed=worker["official_passed"],
            source_run_id=report["run"]["run_id"], leaf_health_status=report["health"].get("status"),
            leaf_critical_path_status=report["critical_path"]["status"],
            selected_tool_timeline_status=summary.get("selected_tool_timeline_status"),
            unowned_thread_rows=len(exported["unassigned_thread_keys"]),
            read_calls=sum(value["read_calls"] for value in reading),
            returned_bytes=None if unknown else sum(value["returned_bytes"] for value in reading),
            returned_bytes_known_sum=sum(value["returned_bytes_known_sum"] for value in reading),
            unknown_return_tools=unknown,
            per_tool_object_rows_sum_not_global_distinct=sum(value["selected_vfs_object_count"] for value in reading))
        names = {"cpu_usage_usec": "cpu.stat.usage_usec", "cpu_user_usec": "cpu.stat.user_usec",
            "cpu_system_usec": "cpu.stat.system_usec", "pgfault": "memory.stat.pgfault",
            "pgmajfault": "memory.stat.pgmajfault", "io_read_bytes": "io.stat.listed_devices_sum.rbytes",
            "io_write_bytes": "io.stat.listed_devices_sum.wbytes", "cpu_psi_some_usec": "cpu.pressure.some.total_usec",
            "memory_psi_some_usec": "memory.pressure.some.total_usec", "io_psi_some_usec": "io.pressure.some.total_usec"}
        row.update({key: resources["counters"][name]["delta"] for key, name in names.items()})
        row.update(resource_status=resources["status"], memory_current_before=resources["gauges"]["memory.current"]["before"],
            memory_current_after=resources["gauges"]["memory.current"]["after"],
            memory_lifetime_peak_after=resources["gauges"]["memory.peak"]["after"])
        resource_row = {"job_id": original["job_id"], "benchmark": worker["benchmark"],
            "concurrency": campaign["concurrency"], "status": resources["status"],
            "window_begin_ns": resources["window_begin_ns"], "window_end_ns": resources["window_end_ns"],
            "unknown_values": resources["unknown_values"]}
        for name, values in resources["counters"].items():
            resource_row[name + ".delta"] = values["delta"]
            resource_row[name + ".status"] = values["status"]
        for name, values in resources["gauges"].items():
            for phase, value in values.items():
                resource_row[name + "." + phase] = value
        resource_rows.append(resource_row)
        rows.append(row)
    composite = merge_reports(reports, jobs)
    composite["campaign_timing"] = timing
    write_new(output / "timeline-report.json", composite)
    complete_identity = digest(output / "timeline-report.json")
    display = display_projection(composite, complete_identity)
    write_new(output / "timeline-display.json", display)
    write_new(output / "timeline.html", render_report(display).encode())
    write_new(output / "index.html", navigation_index(display).encode())
    with (output / "jobs.csv").open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, JOB_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with (output / "resources.csv").open("x", newline="", encoding="utf-8") as stream:
        fields = sorted(set().union(*(row.keys() for row in resource_rows)))
        writer = csv.DictWriter(stream, fields)
        writer.writeheader()
        writer.writerows(resource_rows)
    require(digest(campaign_path) == before, "controller campaign changed during report processing")
    result = {"schema_version": 1, "authority": AUTHORITY, "timing": timing,
        "source_campaign": {"path": str(campaign_path), **before}, "jobs": rows,
        "status": "INDEPENDENT_LEAF_REPORTS_COMPOSED", "total_jobs": 8,
        "official_passed_jobs": sum(row["official_passed"] for row in rows),
        "independent_replay_passed_jobs": len(reports), "leaf_acceptance": [
            {"job_id": job["job_id"], "identity": digest(output / "reports" / job["job_id"] / "acceptance.json")}
            for job in jobs], "raw_health_statuses": [receipt["health"].get("status") for receipt in receipts],
        "critical_path_status": composite["critical_path"]["status"],
        "display_projection": copy.deepcopy(display["display_projection"]),
        "resource_configuration": copy.deepcopy(campaign.get("resource_configuration")),
        "artifacts": {name: digest(output / name) for name in ("timeline-report.json", "timeline-display.json", "timeline.html", "index.html", "jobs.csv", "resources.csv")},
        "limits": composite["limitations"]}
    write_new(output / "result.json", result)
    return result


def compare_groups(groups, expected_mode="ORACLE_REFERENCE"):
    """Descriptive fixed-eight-job comparison, not a slowdown or significance test."""
    require(expected_mode in ("ORACLE_REFERENCE", "MODEL_AGENT"), "explicit supported campaign mode required")
    require(isinstance(groups, list) and groups, "group result list required")
    benchmark, configuration, workload = None, None, None
    rows, seen = [], set()
    for group in groups:
        require(isinstance(group, dict) and group.get("authority") == AUTHORITY
                and group.get("status") == "INDEPENDENT_LEAF_REPORTS_COMPOSED", "completed composition receipt required")
        timing = group.get("timing", {})
        concurrency = timing.get("concurrency")
        require(type(concurrency) is int and concurrency in (2, 4, 6, 8) and concurrency not in seen,
                "one explicit result for each concurrency required")
        seen.add(concurrency)
        require(group.get("total_jobs") == 8 and len(group.get("jobs", [])) == 8,
                "cannot compare groups doing different numbers of jobs")
        tasks = [(job.get("task_id"), job.get("mode")) for job in group["jobs"]]
        require(all(isinstance(task, str) and task and mode == expected_mode for task, mode in tasks),
                "explicit task multiset and selected mode required")
        tasks.sort()
        require(isinstance(group.get("resource_configuration"), dict) and group["resource_configuration"],
                "explicit nonempty resource configuration required for comparison")
        config_digest = semantic_sha256(group["resource_configuration"])
        if benchmark is None:
            benchmark, configuration, workload = timing.get("benchmark"), config_digest, tasks
        require(timing.get("benchmark") == benchmark and configuration == config_digest and tasks == workload,
                "benchmark, resource configuration, or fixed task multiset differs")
        require(integer(timing.get("batch_wall_ns"), 1), "positive measured batch wall required")
        resources = [job.get("resource_status") for job in group["jobs"]]
        rows.append({"benchmark": benchmark, "concurrency": concurrency, "total_jobs": 8,
            "batch_wall_ns": timing["batch_wall_ns"], "batch_wall_seconds": timing["batch_wall_ns"] / 1e9,
            "agent_return_batch_wall_ns": timing.get("agent_return_batch_wall_ns"),
            "last_agent_return_to_last_quiescence_ns": timing.get("last_agent_return_to_last_quiescence_ns"),
            "campaign_wall_ns": timing.get("campaign_wall_ns"), "official_passed_jobs": group.get("official_passed_jobs"),
            "independent_replay_passed_jobs": group.get("independent_replay_passed_jobs"),
            "critical_path_status": group.get("critical_path_status"), "controller_status": timing.get("status"),
            "raw_health_statuses": copy.deepcopy(group.get("raw_health_statuses")),
            "resource_statuses": resources})
    rows.sort(key=lambda row: row["concurrency"])
    def completed(row):
        return (row["controller_status"] == "COMPLETE" and row["official_passed_jobs"] == 8
                and row["independent_replay_passed_jobs"] == 8)
    baseline = next((row["batch_wall_ns"] for row in rows if row["concurrency"] == 2 and completed(row)), None)
    for row in rows:
        row["batch_speedup_vs_c2"] = baseline / row["batch_wall_ns"] if expected_mode == "ORACLE_REFERENCE" and baseline is not None and completed(row) else None
        row["wall_ratio_status"] = "DESCRIPTIVE_SINGLE_GROUP_RATIO_NOT_STATISTICAL_EFFECT" if row["batch_speedup_vs_c2"] is not None else "NO_ACCEPTED_C2_BASELINE_OR_OFFICIAL_CONTROLLER_FAILURE"
    return {"schema_version": 1, "authority": "DESCRIPTIVE_CONTROLLER_WALL_COMPARISON_OF_INDEPENDENT_COMPOSITES",
        "benchmark": benchmark, "total_jobs_per_group": 8, "groups": rows,
        "reported_task_multiset": [list(value) for value in workload],
        "resource_configuration_semantic_sha256": configuration,
        "concurrency_matrix_complete": seen == {2, 4, 6, 8},
        "status": "COMPLETE_2468_COMPARISON" if seen == {2, 4, 6, 8} else "PARTIAL_CONCURRENCY_COMPARISON",
        "limits": ["比较的是同样8个已报告任务完成的batch墙钟，不是单任务平均，也不是Observer slowdown。",
            "按任务ID多重集合和声明资源配置核对等工作量；完整镜像、数据集、Oracle版本仍需检查源plan绑定。",
            "单轮比值没有统计显著性或多轮median/p95含义；official成绩、raw重放、coverage分别保留。",
            "未把并发Agent文件行数之和当全局不同文件数；PSI和线程时间都不加进墙钟。"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--campaign", type=Path)
    source.add_argument("--compare", type=Path, nargs="+", help="existing per-group result.json files; arithmetic only")
    parser.add_argument("--output", type=Path, help="fresh directory, default campaign/report-001")
    parser.add_argument("--collector", type=Path, help="Host/Guest decoder matching each manifest's pinned identity")
    parser.add_argument("--mode", choices=("ORACLE_REFERENCE", "MODEL_AGENT"), default="ORACLE_REFERENCE",
                        help="explicit mode; real model failures remain separate from evidence verification")
    args = parser.parse_args(argv)
    if args.compare:
        from common import digest, write_new
        require(args.output is not None and not args.output.exists(), "fresh --output required for comparison")
        result = compare_groups([load_json(path) for path in args.compare], args.mode)
        args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        result["source_results"] = [{"path": str(path.absolute()), **digest(path)} for path in args.compare]
        write_new(args.output / "comparison.json", result)
        fields = ("benchmark", "concurrency", "total_jobs", "batch_wall_ns", "batch_wall_seconds",
            "agent_return_batch_wall_ns", "last_agent_return_to_last_quiescence_ns",
            "campaign_wall_ns", "batch_speedup_vs_c2", "official_passed_jobs", "independent_replay_passed_jobs",
            "critical_path_status", "controller_status", "raw_health_statuses", "resource_statuses", "wall_ratio_status")
        with (args.output / "comparison.csv").open("x", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fields)
            writer.writeheader()
            for row in result["groups"]:
                writer.writerow({key: json.dumps(value, ensure_ascii=False) if isinstance(value, list) else value
                                 for key, value in row.items()})
        print(json.dumps({"status": result["status"], "benchmark": result["benchmark"], "output": str(args.output)}))
        return 0
    result = process_campaign(args.campaign, args.output or args.campaign / "report-001", args.collector, args.mode)
    print(json.dumps({"status": result["status"], "total_jobs": result["total_jobs"],
                      "batch_wall_ns": result["timing"]["batch_wall_ns"],
                      "official_passed_jobs": result["official_passed_jobs"], "authority": AUTHORITY}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
