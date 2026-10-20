#!/usr/bin/env python3
"""Offline task/resource correlation. Measurements are not Observer evidence.

Only Python's standard library is used. No live /proc reads are performed: a
report must be reproducible from the saved trial, even on a different host.
"""

import argparse
import bisect
import hashlib
import html
import json
import math
from pathlib import Path
import random
import stat
import statistics
from urllib.parse import quote


TERMINALS = {"COMPLETE", "FAILED", "CANCELLED"}
IDENTITY_KEYS = (
    "run_id", "boot_id", "task_id", "attempt", "epoch", "tool_call_id",
    "request_id", "parent_task_id", "dependencies", "phase", "priority",
    "process", "cgroup",
)
CPU_TIME_LIMIT = "采用准备基线扣除的运行中，任务 CPU 为 wait4 累计值减去 worker 准备基线；仍包含基线之后写 ready 文件及暂停握手的少量 CPU，不是计时窗口内或每线程的精确 CPU 分账。"


def _number(value):
    return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and math.isfinite(value))


def _integer(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _get(value, *keys):
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


class Problems:
    def __init__(self):
        self.items = []
        self.seen = set()

    def add(self, code, location, detail):
        key = (code, str(location), str(detail))
        if key not in self.seen:
            self.seen.add(key)
            self.items.append({"code": code, "location": str(location), "detail": str(detail)})


def _read(path, problems, lines=False):
    try:
        with path.open(encoding="utf-8") as stream:
            if not lines:
                value = json.load(stream)
                if not isinstance(value, dict):
                    raise ValueError("expected JSON object")
                return value
            values = []
            for line_no, line in enumerate(stream, 1):
                try:
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError("expected JSON object")
                    values.append(value)
                except (ValueError, TypeError) as error:
                    problems.add("PARSE_ERROR", "{}:{}".format(path.name, line_no), error)
            return values
    except (OSError, ValueError) as error:
        problems.add("MISSING_OR_INVALID_ARTIFACT", path.name, error)
        return [] if lines else {}


def _identity(cgroup):
    if not isinstance(cgroup, dict):
        return None
    path, inode, device = (cgroup.get(k) for k in ("path", "inode", "device"))
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    if not _integer(inode) or not _integer(device):
        return None
    return path, inode, device


def _query_measurements(directory, run, tasks, problems):
    """Rebuild per-query timing from raw worker stats, never task duration / N."""
    config = run.get('config') if isinstance(run.get('config'), dict) else {}
    result = {'status': 'NOT_COLLECTED_LEGACY', 'queries': [], 'expected_queries': None,
              'observed_queries': 0, 'duration_seconds': None,
              'interpretation': 'Cooperative worker call spans include lock/cache/output/subprocess; not pure scan cost or exclusive resource accounting.'}
    if config.get('calibration_kind'):
        result['status'] = 'NOT_APPLICABLE_CALIBRATION'
        return result
    if 'query_measurement_version' not in config:
        return result
    before = len(problems.items)
    if type(config.get('query_measurement_version')) is not int or config.get('query_measurement_version') != 1:
        problems.add('UNSUPPORTED_QUERY_MEASUREMENT_VERSION', 'profile-run.json', config.get('query_measurement_version'))
        result['status'] = 'INCOMPLETE'
        return result
    passes = config.get('passes')
    if not _integer(passes) or not 1 <= passes <= 1000:
        problems.add('INVALID_QUERY_COUNT', 'profile-run.json', 'passes must be 1..1000')
        result['status'] = 'INCOMPLETE'
        return result
    jobs = config.get('jobs')
    if not _integer(jobs) or not 1 <= jobs <= 128:
        problems.add('INVALID_QUERY_TASK_COUNT', 'profile-run.json', 'jobs must be 1..128')
        result['status'] = 'INCOMPLETE'
        return result
    result['expected_queries'] = passes * jobs
    declared_tasks = run.get('tasks')
    declared_ids = [row.get('task_id') for row in declared_tasks if isinstance(row, dict)] if isinstance(declared_tasks, list) else []
    if (len(tasks) != jobs or len(declared_ids) != jobs or any(not isinstance(value, str) for value in declared_ids)
            or set(declared_ids) != {row['task_id'] for row in tasks}):
        problems.add('INCOMPLETE_QUERY_TASK_SET', 'profile-run.json', 'every declared job needs exactly one matching task lifecycle')
    for task in tasks:
        task_id, start, end = task['task_id'], task.get('start'), task.get('end')
        # IDs become local filenames only; never follow an event-supplied path.
        if Path(task_id).name != task_id or task_id in ('.', '..') or '\\' in task_id:
            problems.add('INVALID_QUERY_TASK_ID', task_id, 'unsafe artifact basename')
            continue
        stats = _read(directory / (task_id + '-statistics.json'), problems)
        job = _read(directory / (task_id + '-job.json'), problems)
        rows = stats.get('query_spans')
        if (stats.get('schema_version') != 2 or stats.get('query_timing_contract') != 'WORKER_MONOTONIC_PER_LOGICAL_QUERY_V1'
                or not isinstance(rows, list)):
            problems.add('MISSING_QUERY_SPANS', task_id, 'new run requires raw schema-2 query spans')
            continue
        if (len(rows) != passes or not _integer(stats.get('logical_queries')) or stats.get('logical_queries') != passes
                or not _integer(job.get('passes')) or job.get('passes') != passes):
            problems.add('INCOMPLETE_QUERY_SEQUENCE', task_id, 'one span per declared logical query required')
        query = job.get('query')
        query_digest = hashlib.sha256(query.encode()).hexdigest() if isinstance(query, str) else None
        query_index = job.get('query_index')
        identity = job.get('query_identity')
        if not isinstance(identity, dict) or not query_digest or not _integer(query_index):
            problems.add('MISSING_QUERY_IDENTITY', task_id, 'job query, ordinal assignment and bound identity required')
            identity = {}
        if not start or not end or not task['identity_valid']:
            problems.add('QUERY_TASK_LIFECYCLE_INVALID', task_id, 'cannot bind query to invalid/incomplete task')
        previous_end = None
        observed_kinds = {'SCAN': 0, 'CACHE_HIT': 0}
        for index, row in enumerate(rows):
            location = task_id + '/query:' + str(index)
            issues_before = len(problems.items)
            if not isinstance(row, dict):
                problems.add('INVALID_QUERY_SPAN', location, 'expected object')
                continue
            required_identity = {**identity, 'boot_id': run.get('boot_id'),
                                 'process': start.get('process') if start else None}
            for key, expected in required_identity.items():
                if row.get(key) != expected:
                    problems.add('QUERY_IDENTITY_MISMATCH', location, key)
            for key in ('run_id', 'task_id', 'agent_id', 'tool_call_id', 'attempt', 'epoch', 'cgroup'):
                if not start or key not in identity or identity.get(key) != start.get(key):
                    problems.add('QUERY_JOB_IDENTITY_MISMATCH', location, key)
            if not start or any(not isinstance(start.get(key), str) or not start[key] for key in ('agent_id', 'tool_call_id')):
                problems.add('MISSING_QUERY_AGENT_OR_TOOL', location, 'nonempty agent/tool identities required')
            if (type(row.get('schema_version')) is not int or row.get('schema_version') != 1 or row.get('query_ordinal') != index
                    or type(row.get('query_ordinal')) is not int
                    or row.get('query_id') != '{}:query-{:06d}'.format(identity.get('tool_call_id', 'unbound'), index)
                    or row.get('query_sha256') != query_digest or not _integer(row.get('query_index'))
                    or row.get('query_index') != query_index):
                problems.add('QUERY_SEQUENCE_OR_CONTENT_MISMATCH', location, 'ordinal/id/content/assignment changed')
            begin, finish, duration = (row.get(key) for key in ('begin_ns', 'end_ns', 'duration_ns'))
            valid_time = all(_integer(value) for value in (begin, finish, duration)) and finish >= begin and duration == finish - begin
            if not valid_time:
                problems.add('INVALID_QUERY_DURATION', location, 'monotonic endpoints must reconstruct duration')
            elif (not start or not end or not _integer(start.get('monotonic_ns')) or not _integer(end.get('monotonic_ns'))
                  or begin < start['monotonic_ns'] or finish > end['monotonic_ns']
                  or (previous_end is not None and begin < previous_end)):
                problems.add('QUERY_OUTSIDE_TASK_OR_OVERLAP', location, 'queries must be ordered and contained in task window')
            if valid_time:
                previous_end = finish
            if not _integer(row.get('lock_wait_ns')) or not valid_time or row['lock_wait_ns'] > duration:
                problems.add('INVALID_QUERY_LOCK_WAIT', location, 'lock wait must be bounded by query span')
            kind = row.get('execution_kind')
            if kind not in observed_kinds:
                problems.add('UNRESOLVED_QUERY_EXECUTION_KIND', location, kind)
            else:
                observed_kinds[kind] += 1
            mode = config.get('intervention', 'none')
            if (row.get('mode') != mode or (mode == 'none' and kind != 'SCAN')
                    or row.get('status') != 'COMPLETE' or type(row.get('returncode')) is not int or row.get('returncode') not in (0, 1)):
                problems.add('QUERY_EXECUTION_INCOMPLETE', location, 'mode/result must match declared successful logical query')
            if (row.get('timing_scope') != 'WORKER_QUERY_CALL_INCLUDING_LOCK_CACHE_OUTPUT_AND_SUBPROCESS'
                    or row.get('identity_scope') != 'CALLING_WORKER; GREP_DESCENDANT_NOT_INDIVIDUALLY_RESOLVED'):
                problems.add('UNKNOWN_QUERY_TIMING_SCOPE', location, 'must retain calling-worker and timing limitations')
            result['queries'].append({**row, 'measurement_status': 'OBSERVED' if len(problems.items) == issues_before and task['identity_valid'] else 'INCOMPLETE'})
        if (not _integer(stats.get('physical_grep_executions')) or not _integer(stats.get('cache_hits'))
                or stats.get('physical_grep_executions') != observed_kinds['SCAN'] or stats.get('cache_hits') != observed_kinds['CACHE_HIT']
                or stats.get('intervention') != config.get('intervention', 'none')):
            problems.add('QUERY_STATISTICS_MISMATCH', task_id, 'scan/hit counts and intervention must reconstruct from raw spans')
        raw_results = run.get('results')
        declared = [item for item in raw_results if isinstance(item, dict) and item.get('task_id') == task_id] if isinstance(raw_results, list) else []
        if len(declared) != 1 or declared[0].get('query_statistics') != stats or declared[0].get('query_index') != query_index:
            problems.add('QUERY_DERIVED_STATISTICS_MISMATCH', task_id, 'raw stats must equal result binding; regenerate rather than trusting derived JSON')
    observed = [row for row in result['queries'] if row['measurement_status'] == 'OBSERVED']
    result['observed_queries'] = len(observed)
    result['status'] = 'OBSERVED' if len(problems.items) == before and len(observed) == result['expected_queries'] else 'INCOMPLETE'
    result['duration_seconds'] = _summary_statistics((row['duration_ns'] / 1e9 for row in observed), bootstrap=False)
    result['by_execution_kind'] = {kind: _summary_statistics((row['duration_ns'] / 1e9 for row in observed if row['execution_kind'] == kind), bootstrap=False)
                                   for kind in ('SCAN', 'CACHE_HIT')}
    result['latency_sampling_unit'] = 'Queries within a task/trial are correlated; no independent-query confidence interval.'
    return result


def _task_events(events, run, problems):
    tasks = {}
    previous_seq = None
    previous_time = None
    seen_sequences = set()
    for index, event in enumerate(events):
        location = "task-events.jsonl:{}".format(index + 1)
        task_id = event.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            problems.add("INVALID_TASK_ID", location, "task_id must be a nonempty string")
            continue
        task = tasks.setdefault(task_id, {"task_id": task_id, "start": None, "end": None,
                                         "identity_valid": True, "issues": []})

        def invalid(code, detail):
            problems.add(code, location, detail)
            task["identity_valid"] = False
            task["issues"].append(code)

        missing = [key for key in IDENTITY_KEYS if key not in event]
        if missing:
            invalid("MISSING_EVENT_IDENTITY", ", ".join(missing))
        if event.get("schema_version") != 1:
            invalid("UNSUPPORTED_EVENT_SCHEMA", event.get("schema_version"))
        for key in ("attempt", "epoch"):
            if not _integer(event.get(key)) or event[key] == 0:
                invalid("INVALID_EVENT_IDENTITY", key + " must be a positive integer")
        if not isinstance(event.get("tool_call_id"), str) or not event.get("tool_call_id"):
            invalid("INVALID_EVENT_IDENTITY", "tool_call_id must be nonempty")
        if not isinstance(event.get("dependencies"), list) or not all(isinstance(item, str) for item in event.get("dependencies", [])):
            invalid("INVALID_EVENT_IDENTITY", "dependencies must be a string list")
        for key in ("run_id", "boot_id"):
            if not run.get(key) or event.get(key) != run.get(key):
                invalid("EVENT_IDENTITY_MISMATCH", key)
        process = event.get("process", {})
        if not isinstance(process, dict) or not all(_integer(process.get(k)) for k in ("pid", "start_ticks")) or process.get("pid", 0) == 0:
            invalid("MISSING_PROCESS_IDENTITY", "pid and process birth start_ticks required")
        if _identity(event.get("cgroup")) is None:
            # A no-cgroup control run still has useful task timing, not attribution.
            invalid("MISSING_CGROUP_IDENTITY", "path + inode + device required for attribution")
        seq, stamp = event.get("seq"), event.get("monotonic_ns")
        if not _integer(seq) or seq in seen_sequences:
            invalid("INVALID_EVENT_SEQUENCE", seq)
        elif previous_seq is not None and seq != previous_seq + 1:
            invalid("EVENT_SEQUENCE_GAP", "{} -> {}".format(previous_seq, seq))
        elif previous_seq is None and seq not in (0, 1):
            invalid("EVENT_SEQUENCE_GAP", "first seq must be 0 or 1")
        if _integer(seq):
            previous_seq = seq
            seen_sequences.add(seq)
        if not _integer(stamp) or (previous_time is not None and stamp < previous_time):
            invalid("INVALID_EVENT_TIME", stamp)
        if _integer(stamp):
            previous_time = stamp
        kind = event.get("event")
        if kind == "START":
            if task["start"] is not None or task["end"] is not None:
                invalid("DUPLICATE_OR_REORDERED_START", kind)
            else:
                task["start"] = event
        elif kind in TERMINALS:
            if task["start"] is None or task["end"] is not None:
                invalid("DUPLICATE_OR_ORPHAN_TERMINAL", kind)
            else:
                task["end"] = event
                for key in IDENTITY_KEYS:
                    if task["start"].get(key) != event.get(key):
                        invalid("LIFECYCLE_IDENTITY_CHANGED", key)
                start_stamp = task["start"].get("monotonic_ns")
                if not _integer(stamp) or not _integer(start_stamp) or stamp < start_stamp:
                    invalid("NEGATIVE_TASK_DURATION", stamp)
                for key in ("exit_code", "output_sha256", "output_bytes", "wall_ns", "user_usec", "system_usec", "max_rss_kb"):
                    if key not in event:
                        invalid("MISSING_COMPLETION_FIELD", key)
                for key in ("output_bytes", "wall_ns", "user_usec", "system_usec", "max_rss_kb",
                            "lifetime_user_usec", "lifetime_system_usec"):
                    if key in event and not _integer(event[key]):
                        invalid("INVALID_COMPLETION_FIELD", key + " must be nonnegative integer")
        else:
            invalid("UNKNOWN_EVENT", kind)
    for task in tasks.values():
        if task["start"] is None or task["end"] is None:
            task["identity_valid"] = False
            task["issues"].append("INCOMPLETE_TASK_LIFECYCLE")
            problems.add("INCOMPLETE_TASK_LIFECYCLE", task["task_id"], "exactly one START and terminal required")
    declared = run.get("tasks", [])
    if isinstance(declared, list):
        for item in declared:
            task_id = item.get("task_id") if isinstance(item, dict) else item
            if isinstance(task_id, str) and task_id not in tasks:
                problems.add("MISSING_DECLARED_TASK", task_id, "no task events")
    return list(tasks.values())


def _delta(first, last, problems, location):
    if not _number(first) or not _number(last):
        problems.add("MISSING_COUNTER", location, "missing is unknown, not zero")
        return None
    if first < 0 or last < first:
        problems.add("COUNTER_RESET", location, "{} -> {}".format(first, last))
        return None
    return last - first


def _rate(delta, seconds):
    return None if delta is None else delta / seconds


def _metrics(first, last, duration_ns, problems, location):
    """Derive independent dimensions; PSI resources and some/full are NOT summed."""
    seconds = duration_ns / 1e9
    result = {"duration_ns": duration_ns, "cpu": {}, "psi": {}, "io_by_device": {}, "memory": {}}
    for field in ("usage_usec", "user_usec", "system_usec", "throttled_usec"):
        delta = _delta(_get(first, "cpu_stat", field), _get(last, "cpu_stat", field), problems, location + "/cpu/" + field)
        result["cpu"][field + "_delta"] = delta
    result["cpu"]["usage_cores"] = _rate(result["cpu"]["usage_usec_delta"], seconds * 1e6)
    for resource in ("cpu", "memory", "io"):
        result["psi"][resource] = {}
        for kind in ("some", "full"):
            delta = _delta(_get(first, "psi", resource, kind + "_total_us"), _get(last, "psi", resource, kind + "_total_us"), problems, location + "/psi/" + resource + "/" + kind)
            result["psi"][resource][kind + "_stall_us"] = delta
            result["psi"][resource][kind + "_fraction"] = _rate(delta, seconds * 1e6)
    before, after = first.get("io_stat_by_device"), last.get("io_stat_by_device")
    if not isinstance(before, dict) or not isinstance(after, dict):
        problems.add("MISSING_DEVICE_IO", location, "aggregate io.stat cannot substitute per-device identity")
        result["io_by_device"] = None
    else:
        for device in sorted(set(before) | set(after)):
            row = {}
            for field in ("rbytes", "wbytes", "rios", "wios"):
                delta = _delta(_get(before, device, field), _get(after, device, field), problems, location + "/io/" + device + "/" + field)
                row[field + "_delta"] = delta
                row[field + "_per_second"] = _rate(delta, seconds)
            result["io_by_device"][device] = row
    for field in ("memory_current", "memory_peak"):
        value = last.get(field)
        if not _number(value):
            problems.add("MISSING_GAUGE", location + "/" + field, "not observed")
            value = None
        result["memory"][field + "_bytes"] = value
    for field in ("workingset_refault_file", "workingset_refault_anon", "pgmajfault"):
        result["memory"][field + "_delta"] = _delta(_get(first, "memory_stat", field), _get(last, "memory_stat", field), problems, location + "/memory/" + field)
    result['memory']['reclaim_counters'] = {}
    for field in ('pgscan', 'pgsteal', 'pgscan_direct', 'pgsteal_direct', 'pgfault'):
        before, after = _get(first, 'memory_stat', field), _get(last, 'memory_stat', field)
        available = _number(before) and _number(after)
        delta = _delta(before, after, problems, location + '/memory/' + field) if available else None
        result['memory']['reclaim_counters'][field] = {'delta': delta, 'status': 'OBSERVED' if delta is not None else 'UNKNOWN'}
    for field in ("high", "max", "oom", "oom_kill"):
        result["memory"]["events_" + field + "_delta"] = _delta(_get(first, "memory_events", field), _get(last, "memory_events", field), problems, location + "/memory/events/" + field)
    return result


def _samples(samples, meta, stats, problems):
    valid = []
    previous = None
    interval_ms = meta.get("interval_ms")
    interval_ns = interval_ms * 1000000 if _number(interval_ms) and interval_ms > 0 else 0
    if not interval_ns:
        problems.add("MISSING_SAMPLE_INTERVAL", "load-meta.json", "cannot assess sampling gaps")
    for index, row in enumerate(samples):
        location = "sample:{}".format(index)
        stamp, end = row.get("monotonic_ns"), row.get("collection_end_ns")
        if not _integer(row.get("seq")) or row.get("seq") != index:
            problems.add("SAMPLE_SEQUENCE_GAP", location, row.get("seq"))
        if not _integer(stamp) or (previous is not None and stamp <= previous):
            problems.add("INVALID_SAMPLE_TIME", location, stamp)
            continue
        if not _integer(end) or end < stamp:
            problems.add("MISSING_COLLECTION_WINDOW", location, "cannot assume instantaneous capture")
            # Retain raw counters for interval views, but do not bracket tasks.
        if previous is not None and interval_ns and stamp - previous > interval_ns * 1.5:
            problems.add("SAMPLING_GAP", location, "actual interval {} ns; configured {} ns".format(stamp - previous, interval_ns))
        if row.get("errors"):
            problems.add("SAMPLE_READ_ERRORS", location, row["errors"])
        previous = stamp
        valid.append(row)
    if not stats:
        problems.add("MISSING_FINAL_STATS", "load-sampler-stats.json", "stream may be truncated")
    else:
        for key in ("samples", "missed_ticks", "read_errors", "truncated_process_sets"):
            if not _integer(stats.get(key)):
                problems.add("MISSING_FINAL_STAT", key, "required sampler completion counter")
        if stats.get("samples") != len(samples):
            problems.add("SAMPLE_COUNT_MISMATCH", "load-sampler-stats.json", "file={} declared={}".format(len(samples), stats.get("samples")))
        for key in ("missed_ticks", "read_errors", "truncated_process_sets"):
            if _number(stats.get(key)) and stats[key] > 0:
                problems.add("SAMPLER_INCOMPLETE", key, stats[key])
        for key in ("truncated_cgroup_traversals", "cgroup_traversal_read_errors", "vanished_processes"):
            if _number(stats.get(key)) and stats[key] > 0:
                problems.add("PROCESS_SAMPLING_INCOMPLETE", key, stats[key])
        if not stats.get("stop_reason"):
            problems.add("MISSING_STOP_REASON", "load-sampler-stats.json", "unknown termination")
        final_time = _get(stats, "end_clock", "monotonic_ns")
        last_end = valid[-1].get("collection_end_ns") if valid else None
        if not _integer(final_time) or (_integer(last_end) and final_time < last_end):
            problems.add("INVALID_FINAL_TIME", "load-sampler-stats.json", "final time must follow last collection")
    if len(valid) < 2:
        problems.add("INSUFFICIENT_SAMPLES", "load-samples.jsonl", "at least two observations required for deltas")
    return valid


def _group_sample(row, index, problems, location):
    groups = row.get("cgroups", [])
    if not isinstance(groups, list) or index >= len(groups) or not isinstance(groups[index], dict):
        problems.add("MISSING_CGROUP_SAMPLE", location, index)
        return {}
    value = groups[index]
    if value.get("present") is not True:
        problems.add("CGROUP_NOT_PRESENT", location, index)
        return {}
    return value


def _process_stream(directory, meta, stats, problems):
    """Optional leader snapshots are not a complete process/thread census."""
    period = meta.get("process_interval_ms", 0)
    if not _number(period) or period <= 0 or not meta.get("cgroups"):
        return
    rows = _read(directory / "load" / "load-processes.jsonl", problems, lines=True)
    if stats.get("process_samples") != len(rows):
        problems.add("PROCESS_SAMPLE_COUNT_MISMATCH", "load-processes.jsonl", "file={} declared={}".format(len(rows), stats.get("process_samples")))
    previous = None
    for index, row in enumerate(rows):
        stamp, end, seq = (row.get(key) for key in ("monotonic_ns", "collection_end_ns", "seq"))
        location = "load-processes.jsonl:{}".format(index + 1)
        if not _integer(stamp) or not _integer(end) or end < stamp:
            problems.add("INVALID_PROCESS_COLLECTION_WINDOW", location, "not instantaneous")
        if not _integer(seq) or (previous is not None and seq <= previous):
            problems.add("INVALID_PROCESS_SAMPLE_SEQUENCE", location, seq)
        if _integer(seq):
            previous = seq
        if row.get("errors"):
            problems.add("PROCESS_SAMPLE_ERRORS", location, row["errors"])
        groups = row.get("cgroups", [])
        if not isinstance(groups, list):
            problems.add("INVALID_PROCESS_GROUP", location, "expected cgroup list")
            continue
        for group in groups:
            if not isinstance(group, dict):
                problems.add("INVALID_PROCESS_GROUP", location, "expected object")
                continue
            for key in ("truncated_cgroup_dirs", "truncated_process_set", "traversal_errors"):
                if group.get(key):
                    problems.add("PROCESS_SAMPLE_ERRORS", location, key)


def _hypotheses(metrics):
    candidates = []
    for resource, title, next_step in (
        ("cpu", "存在 CPU 等待线索", "固定总任务数，只降低搜索并发，比较总完成时间与 CPU PSI。"),
        ("io", "存在 I/O 等待线索", "对照预热与首次读取；结合逐设备读取量，不把全机磁盘活动归到任务。"),
        ("memory", "存在内存压力线索", "检查 refault、memory.events；控制并发或工作集大小再测。"),
    ):
        value = _get(metrics, "psi", resource, "some_stall_us")
        if _number(value) and value > 0:
            candidates.append({"kind": resource, "label": title, "basis": "enclosing_interval.psi.{}.some_stall_us={}".format(resource, value), "next_experiment": next_step, "causality": "NOT_ESTABLISHED"})
    return candidates


def thread_report(meta, stats, rows):
    """Instance-bound polled TID deltas; never a claim of full thread lifecycle."""
    if _get(meta, 'thread_sampling', 'enabled') is not True:
        return {'status': 'NOT_COLLECTED', 'instances': [], 'issues': []}
    problems, instances = Problems(), {}
    registry = meta.get('cgroups', [])
    identity_fields = ('boot_id', 'pid', 'process_start_ticks', 'tid', 'thread_start_ticks')
    for row in rows:
        if not isinstance(row, dict):
            problems.add('THREAD_SAMPLE_SCHEMA_INVALID', 'load-processes.jsonl', 'expected object')
            continue
        if not _integer(row.get('seq')) or not isinstance(row.get('cgroups'), list):
            problems.add('THREAD_SAMPLE_SCHEMA_INVALID', 'load-processes.jsonl', 'sample sequence/cgroup list required')
            continue
        for index, group in enumerate(row['cgroups']):
            if not isinstance(group, dict):
                continue
            if not isinstance(group.get('processes'), list):
                problems.add('THREAD_SAMPLE_SCHEMA_INVALID', str(index), 'process list required')
                continue
            for process in group['processes']:
                if not isinstance(process, dict):
                    continue
                for issue in process.get('tid_sampling_issues', []) or []:
                    problems.add('THREAD_COLLECTION_ISSUE', str(process.get('pid')), issue)
                if not isinstance(process.get('tid_samples'), list):
                    problems.add('THREAD_SAMPLE_SCHEMA_INVALID', str(process.get('pid')), 'TID list required')
                    continue
                for thread in process['tid_samples']:
                    identity = _get(thread, 'identity')
                    if (not isinstance(identity, dict) or identity.get('boot_id') != meta.get('boot_id')
                            or identity.get('pid') != process.get('pid')
                            or identity.get('process_start_ticks') != process.get('start_ticks')
                            or any(not _integer(identity.get(field)) for field in identity_fields[1:])
                            or identity.get('pid', 0) == 0 or identity.get('tid', 0) == 0):
                        problems.add('THREAD_INSTANCE_IDENTITY_INVALID', str(index), 'bind boot/process birth/thread birth, not PID/TID alone')
                        continue
                    start, end = thread.get('collection_start_ns'), thread.get('collection_end_ns')
                    if not _integer(start) or not _integer(end) or end < start:
                        problems.add('THREAD_COLLECTION_WINDOW_INVALID', str(identity), 'non-atomic collection boundaries required')
                        continue
                    key = tuple(identity[field] for field in identity_fields)
                    instance = instances.setdefault(key, {'identity': identity, 'observations': {}, 'cgroup_views': set()})
                    if index < len(registry) and _identity(registry[index]) is not None:
                        instance['cgroup_views'].add(_identity(registry[index]))
                    # Parent/child registries can read the same instance twice in
                    # a process sample. Keep one endpoint; do not sum them.
                    previous = instance['observations'].get(row.get('seq'))
                    if previous is None or start < previous['collection_start_ns']:
                        instance['observations'][row.get('seq')] = thread
    result = []
    for instance in instances.values():
        samples = sorted(instance['observations'].values(), key=lambda thread: thread['collection_start_ns'])
        first, last = samples[0], samples[-1]
        item = {'identity': instance['identity'], 'observations': len(samples),
            'cgroup_views': [{'path': path, 'inode': inode, 'device': device} for path, inode, device in sorted(instance['cgroup_views'])],
            'first_window': [first['collection_start_ns'], first['collection_end_ns']],
            'last_window': [last['collection_start_ns'], last['collection_end_ns']],
            'status': 'PARTIAL_POLLED' if len(samples) > 1 else 'SINGLE_SAMPLE_DELTA_UNKNOWN', 'deltas': {}}
        for field in ('utime', 'stime', 'run_ns', 'wait_ns', 'timeslices'):
            before, after = first.get(field), last.get(field)
            if len(samples) < 2 or (field in ('wait_ns', 'timeslices') and any(sample.get('wait_counter_status') != 'ENABLED' for sample in samples)):
                item['deltas'][field] = None
            elif not _number(before) or not _number(after):
                item['deltas'][field] = None
                problems.add('THREAD_COUNTER_UNAVAILABLE', str(instance['identity']), field)
            elif any(not _number(sample.get(field)) or sample[field] < previous[field]
                     for previous, sample in zip(samples, samples[1:])):
                item['deltas'][field] = None
                problems.add('THREAD_COUNTER_RESET_OR_GAP', str(instance['identity']), field)
            else:
                item['deltas'][field] = after - before
        result.append(item)
    for name in ('thread_read_errors', 'vanished_threads_during_read', 'truncated_thread_samples', 'thread_identity_changes'):
        value = stats.get(name)
        if not _integer(value):
            problems.add('THREAD_HEALTH_COUNTER_MISSING', name, 'unknown, not zero')
        elif value:
            problems.add('THREAD_COLLECTION_GAPS', name, value)
    return {'status': 'PARTIAL_POLLED_WITH_GAPS' if problems.items else 'PARTIAL_POLLED', 'instances': result,
        'issues': problems.items, 'disappeared_between_samples': stats.get('thread_disappeared_between_samples'),
        'interpretation': 'Polled endpoints can miss short threads. Disappearance is not an exit proof. Parent/child cgroup views overlap; do not sum. Thread waits overlap wall time.',
        'identity_resolution': 'boot ID plus process/thread USER_HZ start ticks; not arbitrary hostile TID-reuse protection'}


def _system_intervals(samples, meta, problems):
    result = []
    tick = meta.get("clk_tck")
    for first, last in zip(samples, samples[1:]):
        duration_ns = last["monotonic_ns"] - first["monotonic_ns"]
        row = {"start_ns": first["monotonic_ns"], "end_ns": last["monotonic_ns"], "scope": "SYSTEM_ONLY", "cpu_active_cores": None, "psi": {}}
        before, after = _get(first, "stat", "cpu_total"), _get(last, "stat", "cpu_total")
        if isinstance(before, list) and isinstance(after, list) and len(before) >= 8 and len(after) >= 8 and _number(tick) and tick > 0:
            diffs = [_delta(before[i], after[i], problems, "system/cpu/{}".format(i)) for i in (0, 1, 2, 5, 6)]
            if all(value is not None for value in diffs):
                row["cpu_active_cores"] = sum(diffs) / tick / (duration_ns / 1e9)
        else:
            problems.add("MISSING_SYSTEM_CPU", "system", "CPU accounting unavailable")
        for resource in ("cpu", "memory", "io"):
            delta = _delta(_get(first, "psi", resource, "some_total_us"), _get(last, "psi", resource, "some_total_us"), problems, "system/psi/" + resource)
            row["psi"][resource + "_some_fraction"] = _rate(delta, duration_ns / 1000)
        row["memory_available_kb"] = _get(last, "meminfo_kb", "MemAvailable")
        result.append(row)
    return result


def _block_diagnostics(configuration, stats, health):
    """Versioned system-only hints; unknown queue spans are never inferred loss."""
    initial = _get(configuration, 'programs', 'block_diagnostics')
    final = _get(stats, 'kernel_hist', 'block_diagnostics')
    if initial is None and final is None:
        return {'status': 'NOT_AVAILABLE_LEGACY_COLLECTOR', 'scope': 'SYSTEM_UNATTRIBUTED'}
    expected = ('request_read_failed', 'flush_issued', 'flush_completed', 'flush_error',
                'queue_span_unknown', 'untracked_complete', 'untracked_requeue',
                'zero_nonflush_unsupported', 'zero_flush_invalid_bytes', 'sample_attempts')
    result = {'status': 'UNKNOWN', 'scope': 'SYSTEM_UNATTRIBUTED', 'initial': initial, 'final': final,
        'counter_deltas': {}, 'queue_interval': 'UNKNOWN_WHEN_INSERT_NOT_OBSERVED',
        'sample_completeness': 'UNKNOWN',
        'interpretation': 'System block only; no Agent attribution. Legal direct dispatch may have no insert. Untracked completion/requeue remains UNKNOWN. Successful zero-byte FLUSH service is not data throughput or fdatasync end-to-end latency.'}
    for phase, value in (('initial', initial), ('final', final)):
        if (not isinstance(value, dict) or value.get('version') != 1
                or value.get('status') != 'OBSERVED_NON_ATOMIC' or value.get('scope') != 'SYSTEM_UNATTRIBUTED'
                or not isinstance(value.get('counters'), dict)
                or any(not _integer(_get(value, 'counters', name)) for name in expected)):
            health.add('KERNEL_HIST_BLOCK_DIAGNOSTICS_UNKNOWN', phase, 'versioned endpoints/counters unavailable; not zero')
            return result
    for name in expected:
        before, after = initial['counters'][name], final['counters'][name]
        result['counter_deltas'][name] = after - before if after >= before else None
        if after < before:
            health.add('KERNEL_HIST_BLOCK_DIAGNOSTIC_RESET', name, 'cumulative endpoint counter decreased')
    result['status'] = 'OBSERVED_NON_ATOMIC_WITH_EXPLICIT_UNKNOWNS'
    for name in ('request_read_failed', 'zero_nonflush_unsupported', 'zero_flush_invalid_bytes'):
        if final['counters'][name]:
            health.add('KERNEL_HIST_BLOCK_OBJECT_UNRESOLVED', name, final['counters'][name])
    samples, truncated = final.get('samples'), final.get('samples_truncated')
    if not isinstance(samples, list) or final.get('sample_capacity_per_cpu') != 8 or not _integer(truncated):
        health.add('KERNEL_HIST_BLOCK_DIAGNOSTICS_UNKNOWN', 'samples', 'bounded diagnostic sample health unavailable')
    else:
        result['sample_completeness'] = 'BOUNDED_SAMPLES_TRUNCATED' if truncated else 'BOUNDED_FIRST_SAMPLES_ONLY'
        result['samples_truncated'] = truncated
        # Truncation only limits optional request hints. It is not a claim that
        # the independent baseline histograms lost this many events.
    service = final.get('flush_service')
    buckets = _get(service, 'buckets')
    if (not isinstance(service, dict) or not _integer(service.get('count')) or not _integer(service.get('sum_ns'))
            or not isinstance(buckets, list) or len(buckets) != 32 or not all(_integer(v) for v in buckets)):
        health.add('KERNEL_HIST_BLOCK_DIAGNOSTICS_UNKNOWN', 'flush_service', 'flush span counter/histogram unavailable')
    return result


def _kernel_hist(meta, stats, samples, problems, requested=False, domain_index=None):
    """Histograms describe completed spans, never a disjoint time partition."""
    configuration = meta.get("kernel_hist")
    result = {"enabled": requested or configuration is not None, "status": "NOT_COLLECTED", "aggregates": [],
              "intervals": [], "diagnostic_counters": {}, "programs": [], "issues": [],
              "raw_source": "load/load-samples.jsonl",
              "interpretation": "Completed spans can overlap and cross window boundaries. Target metrics aggregate the registered root cgroup and descendants; system metrics are never Agent attribution. No summing into task wall time.",
              "collection": "NON_ATOMIC_MMAP_COUNTER_READ",
              "percentiles": "NOT_COMPUTED",
              "recursion_miss_scope": "COLLECTOR_PROGRAM_GLOBAL; cannot determine whether missed invocation was in target cgroup"}
    health = Problems()
    if not isinstance(configuration, dict):
        if configuration is not None:
            health.add("INVALID_KERNEL_HIST_SCHEMA", "load-meta.json", "probe metadata must be an object")
        elif requested:
            health.add("MISSING_KERNEL_HIST", "load-meta.json", "kernel-hist requested but no probe metadata")
        else:
            return result
        configuration = {}
    domains = configuration.get('domains')
    if domains is not None and (not isinstance(domains, list) or not 1 <= len(domains) <= 16
            or any(not isinstance(domain, dict) or domain.get('domain_index') != index or _identity(domain) is None
                   for index, domain in enumerate(domains))):
        health.add('INVALID_KERNEL_HIST_DOMAINS', 'load-meta.json', '1..16 indexed path/inode/device domains required')
        domains = None
    if domain_index is not None:
        if not isinstance(domains, list) or domain_index >= len(domains) or not isinstance(domains[domain_index], dict):
            health.add('KERNEL_HIST_DOMAIN_IDENTITY_UNKNOWN', 'load-meta.json', 'selected domain unavailable')
            domain = {}
        else:
            domain = domains[domain_index]
        result['domain_index'] = domain_index
        result['target_cgroup'] = domain.get('path')
        result['scope'] = 'INCLUSIVE_CGROUP_AND_DESCENDANTS_NOT_ADDITIVE'
    else:
        result["target_cgroup"] = configuration.get("target_cgroup")
    registry = meta.get("cgroups", [])
    matched_targets = [group for group in registry if isinstance(group, dict) and group.get("path") == result["target_cgroup"] and _identity(group) is not None] if isinstance(registry, list) else []
    if len(matched_targets) != 1:
        health.add("KERNEL_HIST_TARGET_IDENTITY_UNKNOWN", "load-meta.json", "target needs exactly one path/inode/device registry entry")
    else:
        result["target_identity"] = {key: matched_targets[0][key] for key in ("path", "inode", "device")}
        selected_domain = (domains[0 if domain_index is None else domain_index]
                           if isinstance(domains, list) else None)
        if selected_domain is not None and _identity(selected_domain) != _identity(matched_targets[0]):
            health.add('KERNEL_HIST_DOMAIN_IDENTITY_CHANGED', 'load-meta.json', 'domain differs from sampler cgroup registry')
    metrics, counters = configuration.get("metrics"), configuration.get("counters")
    groups = configuration.get("groups", [])
    if not isinstance(metrics, list) or not isinstance(counters, list) or not isinstance(groups, list):
        health.add("INVALID_KERNEL_HIST_SCHEMA", "load-meta.json", "metrics/counters/groups required")
        metrics, counters, groups = [], [], []
    selected = []
    for index, metric in enumerate(metrics):
        if not isinstance(metric, dict) or metric.get("scope") not in ("target", "system") or not isinstance(metric.get("name"), str):
            health.add("INVALID_KERNEL_HIST_METRIC", str(index), "name/scope required")
            continue
        if metric.get("subsystem") in groups and (domain_index is None or metric['scope'] == 'target'):
            selected.append((index, metric))
    if not selected:
        health.add("NO_SELECTED_KERNEL_HIST_METRICS", "load-meta.json", "no enabled metric definitions")
    bucket_count = configuration.get("buckets")
    if not _integer(bucket_count) or not 1 <= bucket_count <= 64:
        health.add("INVALID_KERNEL_HIST_BUCKETS", "load-meta.json", "1..64 log2 buckets required for u64 nanoseconds")
        bucket_count = 0

    def scoped_source(row, definition, location):
        if not isinstance(domains, list):
            return _get(row, 'khist')
        if definition.get('scope') == 'system':
            return _get(row, 'khist', 'system')
        selected_index = 0 if domain_index is None else domain_index
        entries = _get(row, 'khist', 'domains')
        if not isinstance(entries, list) or selected_index >= len(entries):
            health.add('MISSING_KERNEL_HIST_DOMAIN_SAMPLE', location, 'registered domain vector unavailable')
            return None
        entry = entries[selected_index]
        identity = _get(entry, 'identity')
        expected = domains[selected_index]
        if (not isinstance(identity, dict) or _identity(identity) != _identity(expected)
                or identity.get('domain_index') != selected_index):
            health.add('KERNEL_HIST_DOMAIN_IDENTITY_CHANGED', location, 'path/inode/device/domain index mismatch')
            return None
        return entry

    def raw_metric(row, index, location, definition):
        values = _get(scoped_source(row, definition, location), "m")
        if not isinstance(values, list) or len(values) != len(metrics) or index >= len(values):
            health.add("MISSING_KERNEL_HIST_SAMPLE", location, "missing or wrong metric vector length")
            return None
        value = values[index]
        if not isinstance(value, list) or len(value) < 2 or len(value) > bucket_count + 2 or not all(_integer(item) for item in value):
            health.add("INVALID_KERNEL_HIST_SAMPLE", location, "count/sum/buckets must be bounded nonnegative integer vector")
            return None
        # The encoder omits trailing zero histogram buckets, not the count/sum.
        return value + [0] * (bucket_count + 2 - len(value))

    def metric_delta(first, last, index, definition, location):
        left = raw_metric(first, index, location + "/before", definition)
        right = raw_metric(last, index, location + "/after", definition)
        row = {"name": definition["name"], "subsystem": definition.get("subsystem"),
               "scope": "TARGET_ROOT_CGROUP_AGGREGATE" if definition["scope"] == "target" else "SYSTEM_ONLY",
               "completed_count": None, "completed_sum_ns": None, "mean_completed_span_ns": None,
               "bucket_count_deltas": None, "time_semantics": "COMPLETED_SPANS_MAY_CROSS_WINDOW_BOUNDARIES"}
        if left is None or right is None:
            return row
        values = []
        for i, (before, after) in enumerate(zip(left, right)):
            if after < before:
                health.add("KERNEL_HIST_COUNTER_RESET", location, "vector index {}: {} -> {}".format(i, before, after))
                values.append(None)
            else:
                values.append(after - before)
        row.update(completed_count=values[0], completed_sum_ns=values[1], bucket_count_deltas=values[2:])
        if None in values:
            return row
        if sum(values[2:]) != values[0]:
            health.add("KERNEL_HIST_NONATOMIC_READ", location, "bucket sum differs from count; no exact distribution asserted")
        elif values[0] is not None and values[0] > 0 and values[1] is not None:
            row["mean_completed_span_ns"] = values[1] / values[0]
        elif values[0] == 0 and values[1] not in (0, None):
            health.add("KERNEL_HIST_NONATOMIC_READ", location, "duration changed without completed count")
        return row

    if len(samples) < 2:
        health.add("INSUFFICIENT_KERNEL_HIST_SAMPLES", "load-samples.jsonl", "two endpoints needed")
    else:
        for first, last in zip(samples, samples[1:]):
            result["intervals"].append({"start_ns": first["monotonic_ns"], "end_ns": last["monotonic_ns"],
                                        "metrics": [metric_delta(first, last, index, definition, "khist/{}/{}-{}".format(definition["name"], first.get("seq"), last.get("seq"))) for index, definition in selected]})
        result["aggregates"] = [metric_delta(samples[0], samples[-1], index, definition, "khist/aggregate/" + definition["name"]) for index, definition in selected]
        result["aggregate_window"] = {"first_collection": [samples[0]["monotonic_ns"], samples[0].get("collection_end_ns")], "last_collection": [samples[-1]["monotonic_ns"], samples[-1].get("collection_end_ns")]}
    bad_counters = {"storage_miss", "blk_untracked", "unpaired_end", "domain_change", "blk_start_collision",
                    "blk_issue_without_insert", "blk_complete_error", "blk_byte_mismatch", "blk_update_failed",
                    "blk_delete_failed", "blk_zero_length_unsupported"}
    for index, name in enumerate(counters):
        if not isinstance(name, str):
            health.add("INVALID_KERNEL_HIST_SCHEMA", "counters", "counter name must be string")
            continue
        previous, first_value, final_value = None, None, None
        for row in samples:
            vector = (_get(row, "khist", "c") if domain_index is None else
                      _get(scoped_source(row, {'scope': 'target'}, 'khist/c/' + name), 'c'))
            value = vector[index] if isinstance(vector, list) and len(vector) == len(counters) else None
            if not _integer(value):
                health.add("MISSING_KERNEL_HIST_COUNTER", "khist/" + name, "counter unavailable")
                final_value = None
                continue
            if first_value is None:
                first_value = value
            if previous is not None and value < previous:
                health.add("KERNEL_HIST_COUNTER_RESET", "khist/" + name, "{} -> {}".format(previous, value))
            if name in bad_counters and value > 0:
                block_version = _get(configuration, 'programs', 'block_diagnostics', 'version')
                if block_version == 1 and name in ('blk_untracked', 'blk_issue_without_insert'):
                    code = 'KERNEL_HIST_BLOCK_UNTRACKED_UNKNOWN' if name == 'blk_untracked' else 'KERNEL_HIST_BLOCK_QUEUE_UNKNOWN'
                    detail = 'nonzero cumulative block coverage gap {}; cannot distinguish legal bypass/late attach/secondary completion from genuine loss; not zero'.format(value)
                else:
                    code, detail = 'KERNEL_HIST_COVERAGE_LOSS', 'nonzero cumulative diagnostic counter: {}'.format(value)
                health.add(code, 'khist/' + name, detail)
            if name == "reserved" and value != 0:
                health.add("UNKNOWN_KERNEL_HIST_COUNTER", "khist/reserved", value)
            previous = final_value = value
        result["diagnostic_counters"][name] = {"first": first_value, "last": final_value,
            "delta": final_value - first_value if first_value is not None and final_value is not None and final_value >= first_value else None}
    first_programs = _get(configuration, "programs", "programs")
    final_programs = _get(stats, "kernel_hist", "programs")
    if not isinstance(first_programs, list) or not isinstance(final_programs, list) or not final_programs:
        health.add("MISSING_KERNEL_HIST_PROGRAM_STATS", "load-sampler-stats.json", "cannot assess recursion loss")
    else:
        initial = {(row.get("id"), row.get("name")): row for row in first_programs if isinstance(row, dict) and _integer(row.get("id")) and isinstance(row.get("name"), str)}
        if len(initial) != len(first_programs):
            health.add("INVALID_KERNEL_HIST_PROGRAM_STATS", "initial programs", "invalid or duplicate program identity")
        final_keys = set()
        for program in final_programs:
            if not isinstance(program, dict) or not _integer(program.get("id")) or not isinstance(program.get("name"), str):
                health.add("INVALID_KERNEL_HIST_PROGRAM_STATS", "programs", "expected object")
                continue
            key = (program.get("id"), program.get("name"))
            before, after = _get(initial.get(key), "recursion_misses"), program.get("recursion_misses")
            if key in final_keys or key not in initial:
                health.add("KERNEL_HIST_PROGRAM_IDENTITY_MISMATCH", str(key), "duplicate or unknown final program")
            final_keys.add(key)
            registration_only = program.get('role') == 'REGISTRATION_ONLY_NO_HISTOGRAM_PAYLOAD'
            if registration_only and (_get(initial.get(key), 'role') != program.get('role') or not key[1].endswith('_dispatch')):
                health.add('KERNEL_HIST_PROGRAM_ROLE_MISMATCH', str(key), 'registration-only role must match frozen initial descriptor and dispatch-only program')
                registration_only = False
            delta = None
            if not _integer(before) or not _integer(after):
                health.add("MISSING_KERNEL_HIST_RECURSION_COUNTER", str(key), "missing is not zero")
            elif after < before:
                health.add("KERNEL_HIST_COUNTER_RESET", str(key), "recursion counter decreased")
            else:
                delta = after - before
                if after > 0 and not registration_only:
                    health.add("KERNEL_HIST_RECURSION_MISSES", str(key), "initial={}, final={}, delta={}; collector-global, target attribution unknown".format(before, after, delta))
            result["programs"].append({"id": key[0], "name": key[1], "recursion_misses_initial": before,
                                        "recursion_misses_final": after, "recursion_misses_delta": delta,
                                        "role": program.get('role', 'MEASUREMENT_OR_LEGACY_UNKNOWN'),
                                        "role_basis": 'collector source/config pinned; dispatch-only probes have no histogram payload'})
        if final_keys != set(initial):
            health.add("KERNEL_HIST_PROGRAM_IDENTITY_MISMATCH", "programs", "initial/final program sets differ")
    expected_count = _get(stats, 'kernel_hist', 'program_info_expected_count')
    if expected_count is not None and (not _integer(expected_count) or not isinstance(final_programs, list) or len(final_programs) != expected_count):
        health.add('KERNEL_HIST_PROGRAM_INFO_INCOMPLETE', 'program_info_expected_count', 'not all loaded programs inspected')
    if _get(stats, 'kernel_hist', 'program_info_read_errors'):
        health.add('KERNEL_HIST_PROGRAM_INFO_INCOMPLETE', 'program_info_read_errors', _get(stats, 'kernel_hist', 'program_info_read_errors'))
    result['memory_backend'] = configuration.get('memory_backend', 'LEGACY_UNSPECIFIED')
    result['memory_fault_metric_interpretation'] = configuration.get('memory_fault_metric_interpretation',
        'Completed selected fault-hook returns; do not assume equivalence to successful rusage minor faults.')
    result['memory_return_probe_profiles'] = _get(stats, 'kernel_hist', 'memory_return_probe_profiles')
    result['tracefs_cleanup'] = _get(stats, 'kernel_hist', 'tracefs_cleanup')
    if 'mem' in groups and configuration.get('memory_backend') == 'kprobe-tracefs':
        initial_probes = _get(configuration, 'programs', 'memory_return_probe_profiles')
        final_probes = result['memory_return_probe_profiles']
        identity_fields = ('name', 'group', 'anchor', 'is_return', 'maxactive', 'device', 'directory_inode', 'event_id', 'definition')
        def probe_identity(probe):
            if not isinstance(probe, dict) or any(isinstance(probe.get(field), (dict, list)) for field in identity_fields):
                return None
            return tuple(probe.get(field) for field in identity_fields)
        if not isinstance(initial_probes, list) or not isinstance(final_probes, list) or not initial_probes:
            health.add('KERNEL_HIST_RETURN_PROBE_PROFILE_UNKNOWN', 'memory_return_probe_profiles', 'initial and terminal owned profiles required')
        else:
            identities = {probe_identity(probe): probe for probe in initial_probes if probe_identity(probe) is not None}
            if len(identities) != len(initial_probes):
                health.add('KERNEL_HIST_RETURN_PROBE_PROFILE_UNKNOWN', 'memory_return_probe_profiles', 'invalid or duplicated initial identity')
            final_identities = set()
            for probe in final_probes:
                if not isinstance(probe, dict):
                    health.add('KERNEL_HIST_RETURN_PROBE_PROFILE_UNKNOWN', 'memory_return_probe_profiles', 'profile object required')
                    continue
                key = probe_identity(probe)
                if key is None:
                    health.add('KERNEL_HIST_RETURN_PROBE_PROFILE_UNKNOWN', 'memory_return_probe_profiles', 'invalid terminal probe identity')
                    continue
                final_identities.add(key)
                before = identities.get(key, {})
                if not before or probe.get('profile_status') != 'OBSERVED':
                    health.add('KERNEL_HIST_RETURN_PROBE_PROFILE_UNKNOWN', str(probe.get('name')), 'exact owned probe identity or profile unavailable')
                for field in ('hits', 'misses'):
                    left, right = before.get(field), probe.get(field)
                    if not _integer(left) or not _integer(right) or right < left:
                        health.add('KERNEL_HIST_RETURN_PROBE_PROFILE_UNKNOWN', str(probe.get('name')), field + ' unavailable/reset')
                    elif field == 'misses' and right:
                        health.add('KERNEL_HIST_RETURN_PROBE_MISSES', str(probe.get('name')), 'global profile misses {}, before {}; target attribution unknown'.format(right, left))
            if final_identities != set(identities) or len(final_identities) != len(final_probes):
                health.add('KERNEL_HIST_RETURN_PROBE_IDENTITY_CHANGED', 'memory_return_probe_profiles', 'initial/final identities differ or duplicated')
        cleanup = result['tracefs_cleanup']
        if (not isinstance(cleanup, dict) or cleanup.get('status') != 'COMPLETE'
                or cleanup.get('remaining_owned_events') != 0 or cleanup.get('detach_errors') or cleanup.get('errors')):
            health.add('KERNEL_HIST_TRACEFS_CLEANUP_INCOMPLETE', 'tracefs_cleanup', 'owned events not proven removed')
    result["runtime_accounting"] = {"requested": configuration.get("runtime_stats_requested"),
        "enabled_by_sampler": _get(stats, "kernel_hist", "runtime_stats_enabled_by_sampler"),
        "external_state": _get(stats, "kernel_hist", "runtime_stats_external_state"),
        "scope": "global BPF accounting when enabled; can itself perturb measurement"}
    if domain_index is None and 'blk' in groups:
        result['block_diagnostics'] = _block_diagnostics(configuration, stats, health)
    result["issues"] = health.items
    result["status"] = "INCOMPLETE" if health.items else "NO_REPORTED_LOSS_WITHIN_SELECTED_PROBES"
    for issue in health.items:
        problems.add(issue["code"], issue["location"], issue["detail"])
    if domain_index is None and isinstance(domains, list):
        result['domains'] = [_kernel_hist(meta, stats, samples, problems, requested, index)
                             for index in range(len(domains))]
        result['domain_semantics'] = 'Each domain includes descendants; overlapping root/child domains and their waits are never additive.'
        if any(entry['status'] == 'INCOMPLETE' for entry in result['domains']):
            result['status'] = 'INCOMPLETE'
    return result


def analyze_trial(directory):
    """Return a JSON-serializable report; malformed/missing evidence stays explicit."""
    directory = Path(directory)
    problems = Problems()
    run = _read(directory / "profile-run.json", problems)
    if run.get("schema_version") != 1:
        problems.add("UNSUPPORTED_RUN_SCHEMA", "profile-run.json", run.get("schema_version"))
    events = _read(directory / "task-events.jsonl", problems, lines=True)
    tasks = _task_events(events, run, problems)
    sampling_requested = _get(run, "config", "mode") not in ("baseline", "observer")
    if sampling_requested:
        meta = _read(directory / "load" / "load-meta.json", problems)
        stats = _read(directory / "load" / "load-sampler-stats.json", problems)
        raw_samples = _read(directory / "load" / "load-samples.jsonl", problems, lines=True)
        samples = _samples(raw_samples, meta, stats, problems)
        _process_stream(directory, meta, stats, problems)
    else:
        meta, stats, samples = {}, {}, []
    boot_matches = bool(run.get("boot_id")) and run.get("boot_id") == meta.get("boot_id")
    if sampling_requested and not boot_matches:
        problems.add("SAMPLER_BOOT_IDENTITY_UNKNOWN_OR_MISMATCH", "load-meta.json", "do not correlate different or unknown boot clocks")
    if meta.get("label") and meta["label"] != run.get("run_id"):
        boot_matches = False
        problems.add("SAMPLER_RUN_IDENTITY_MISMATCH", "load-meta.json", "nonempty sampler label must equal run_id")
    groups = meta.get("cgroups", [])
    if not isinstance(groups, list):
        groups = []
        problems.add("INVALID_CGROUP_REGISTRY", "load-meta.json", "expected list")
    registry = {}
    duplicated = set()
    for index, group in enumerate(groups):
        identity = _identity(group)
        if identity is None:
            problems.add("MISSING_SAMPLER_CGROUP_IDENTITY", "cgroup:{}".format(index), "old path-only metadata is not identity proof")
        elif identity in registry:
            duplicated.add(identity)
            problems.add("DUPLICATE_CGROUP_IDENTITY", str(identity), "ambiguous sample index")
        else:
            registry[identity] = index
    for identity in duplicated:
        del registry[identity]
    group_intervals = []
    for identity, index in registry.items():
        intervals = []
        for first, last in zip(samples, samples[1:]):
            location = "cgroup:{}/{}-{}".format(index, first.get("seq"), last.get("seq"))
            before = len(problems.items)
            metrics = _metrics(_group_sample(first, index, problems, location), _group_sample(last, index, problems, location), last["monotonic_ns"] - first["monotonic_ns"], problems, location)
            intervals.append({"start_ns": first["monotonic_ns"], "end_ns": last["monotonic_ns"], "status": "INCOMPLETE" if len(problems.items) != before else "OBSERVED", "metrics": metrics})
        group_intervals.append({"cgroup": {"path": identity[0], "inode": identity[1], "device": identity[2]}, "intervals": intervals})
    measurement_incomplete = bool(problems.items)
    stamps = [row["monotonic_ns"] for row in samples]
    task_results = []
    for task in tasks:
        start, end = task["start"], task["end"]
        item = {"task_id": task["task_id"], "identity_valid": task["identity_valid"], "status": end.get("event") if end else "INCOMPLETE", "start_ns": start.get("monotonic_ns") if start else None, "end_ns": end.get("monotonic_ns") if end else None, "duration_ns": None, "cgroup": start.get("cgroup") if start else None, "process": start.get("process") if start else None, "resources": None, "resource_status": "UNKNOWN" if sampling_requested else "NOT_COLLECTED", "candidates": [], "issues": task["issues"]}
        item["phase"] = start.get("phase") if start else None
        if start and end and _integer(item["start_ns"]) and _integer(item["end_ns"]) and item["end_ns"] >= item["start_ns"]:
            item["duration_ns"] = item["end_ns"] - item["start_ns"]
            item["completion"] = {key: end.get(key) for key in ("exit_code", "output_sha256", "output_bytes", "wall_ns", "user_usec", "system_usec", "max_rss_kb")}
            # New runners distinguish task CPU from whole worker lifetime. Keep
            # old evidence readable without silently relabelling its counters.
            for key in ("lifetime_user_usec", "lifetime_system_usec", "cpu_time_scope", "other_rusage_scope"):
                if key in end:
                    item["completion"][key] = end[key]
            if end.get("cpu_time_scope") == "WAIT4_LIFETIME_MINUS_WORKER_PREFLIGHT_RUSAGE":
                item["completion"]["cpu_accounting_note"] = CPU_TIME_LIMIT
        if not task["identity_valid"] or not start or not end or not boot_matches:
            task_results.append(item)
            continue
        index = registry.get(_identity(start.get("cgroup")))
        if index is None:
            problems.add("UNMATCHED_TASK_CGROUP", task["task_id"], "path, inode and device must all match sampler registry")
            task_results.append(item)
            continue
        left = bisect.bisect_right(stamps, item["start_ns"]) - 1
        while left >= 0 and (not _integer(samples[left].get("collection_end_ns")) or samples[left]["collection_end_ns"] > item["start_ns"]):
            left -= 1
        right = bisect.bisect_left(stamps, item["end_ns"])
        if left < 0 or right >= len(samples) or right <= left or not _integer(samples[right].get("collection_end_ns")):
            problems.add("NO_BRACKETING_SAMPLES", task["task_id"], "task retained; resource use unknown (including sub-interval tasks)")
            task_results.append(item)
            continue
        first, last = samples[left], samples[right]
        before = len(problems.items)
        metrics = _metrics(_group_sample(first, index, problems, task["task_id"]), _group_sample(last, index, problems, task["task_id"]), last["monotonic_ns"] - first["monotonic_ns"], problems, task["task_id"])
        metrics["measurement_scope"] = "ENCLOSING_SAMPLED_CGROUP_INTERVAL_NOT_EXACT_TASK"
        if _get(run, "config", "cgroup_layout") == "shared-leaf":
            metrics["measurement_scope"] = "SHARED_EXECUTION_GROUP_ENCLOSING_INTERVAL_NOT_TASK_EXCLUSIVE"
            item["resource_owner"] = "ALL_TASKS_IN_SHARED_LEAF"
        metrics["boundary"] = {"before_collection": [first["monotonic_ns"], first["collection_end_ns"]], "after_collection": [last["monotonic_ns"], last["collection_end_ns"]], "before_uncertainty_ns": item["start_ns"] - first["monotonic_ns"], "after_uncertainty_ns": last["collection_end_ns"] - item["end_ns"], "interpolation": "NONE"}
        metrics["memory"]["max_observed_current_bytes"] = max((row["cgroups"][index]["memory_current"] for row in samples[left:right + 1] if isinstance(row.get("cgroups"), list) and index < len(row["cgroups"]) and isinstance(row["cgroups"][index], dict) and _number(row["cgroups"][index].get("memory_current"))), default=None)
        item["resources"] = metrics
        item["resource_status"] = "INCOMPLETE" if measurement_incomplete or len(problems.items) != before else "OBSERVED_ENCLOSING_INTERVAL"
        item["candidates"] = _hypotheses(metrics)
        task_results.append(item)
    system = _system_intervals(samples, meta, problems)
    sampling_incomplete = bool(problems.items)
    hist = _kernel_hist(meta, stats, samples, problems, requested=_get(run, "config", "mode") == "kernel-hist")
    for task in task_results:
        matches = [domain for domain in hist.get('domains', [])
                   if _identity(domain.get('target_identity')) == _identity(task.get('cgroup'))
                   and _identity(task.get('cgroup')) is not None]
        task['kernel_hist_domain_index'] = matches[0]['domain_index'] if len(matches) == 1 else None
        task['kernel_hist_scope'] = ('SELECTED_INCLUSIVE_DOMAIN_WHOLE_COLLECTION_NOT_EXACT_TASK'
            if len(matches) == 1 else 'NOT_LINKED; FIRST_DOMAIN_IS_NOT_ASSIGNED_TO_OTHER_TASKS')
    if hist["enabled"] and not boot_matches:
        issue = {"code": "KERNEL_HIST_RUN_IDENTITY_UNKNOWN", "location": "load-meta.json", "detail": "probe samples cannot be tied to run with mismatched/unknown boot or run identity"}
        hist["issues"].append(issue)
        hist["status"] = "INCOMPLETE"
        problems.add(issue["code"], issue["location"], issue["detail"])
    timed = [task for task in task_results if task["duration_ns"] is not None]
    makespan = max(task["end_ns"] for task in timed) - min(task["start_ns"] for task in timed) if timed else None
    queries = _query_measurements(directory, run, tasks, problems)
    status = "INCOMPLETE" if problems.items else ("COMPLETE_WITHIN_DECLARED_MEASUREMENT" if sampling_requested else "TIMING_ONLY")
    return {"schema_version": 1, "run_id": run.get("run_id"), "boot_id": run.get("boot_id"), "config": run.get("config", {}), "status": status, "sampling_status": ("INCOMPLETE" if sampling_incomplete else "OBSERVED") if sampling_requested else "NOT_COLLECTED", "query_measurements": queries, "issues": problems.items, "task_count": len(task_results), "execution_makespan_ns": makespan, "tasks": task_results, "cgroup_intervals": group_intervals, "system_intervals": system, "sampler_stats": stats, "kernel_hist": hist, "limits": ["性能采样是测量旁路，不是 Observer WAL 或安全审计证据。", "阶段资源值来自包围阶段的采样区间，不插值；采集本身也不是原子操作。", "PSI CPU、memory、io 以及 some/full 可以重叠，不能相加为总等待时间。", "全机指标仅反映背景，不能自动归因到 Agent；cgroup 共享或委托进程也需要额外关联。", "根 cgroup 包含子 cgroup 用量，不能将根与任务曲线相加。", "读取量是内核块 I/O 记账，不等于应用读取字节或磁盘物理读取总量；逐设备数据不跨存储层叠加。", "候选瓶颈是可验证线索，不是因果证明；需保持结果一致并做单因素对照。", "短任务始终保留；无采样、缺字段、计数器回退或采样缺口不解释为零。", "baseline 显式关闭资源采样，状态为 NOT_COLLECTED；这与请求采样后丢失数据的 INCOMPLETE 不同。", "CPU cores 为累计 CPU 时间除以真实时间间隔；不是按固定采样周期换算。", "逐查询耗时由 worker 单调时钟直接记录，包含锁、缓存、输出与子进程；统计写盘仍在任务退出前，因此整体任务耗时也包含计量和统计写盘成本。旧数据不从总任务耗时均分出逐查询延迟。"]}


def timeline(report):
    events = []
    for index, task in enumerate(report["tasks"]):
        if task["duration_ns"] is None:
            continue
        events.append({"name": task["task_id"], "cat": task.get("phase") or "unknown", "ph": "X", "pid": 1, "tid": index + 1, "ts": task["start_ns"] / 1000, "dur": task["duration_ns"] / 1000, "args": {"phase": task.get("phase"), "status": task["status"], "identity_valid": task["identity_valid"], "cgroup": task["cgroup"], "resource_status": task["resource_status"]}})
        for query in report.get('query_measurements', {}).get('queries', []):
            if query.get('task_id') != task['task_id'] or query.get('measurement_status') != 'OBSERVED':
                continue
            events.append({'name': query['query_id'], 'cat': 'logical_query:' + query['execution_kind'],
                           'ph': 'X', 'pid': 1, 'tid': index + 1, 'ts': query['begin_ns'] / 1000,
                           'dur': query['duration_ns'] / 1000, 'args': query})
    for index, group in enumerate(report["cgroup_intervals"]):
        for row in group["intervals"]:
            value = _get(row, "metrics", "cpu", "usage_cores")
            if _number(value):
                events.append({"name": "cgroup_cpu_cores", "ph": "C", "pid": index + 2, "tid": 0, "ts": row["end_ns"] / 1000, "args": {"cores": value}})
    return {"traceEvents": events, "displayTimeUnit": "ms", "metadata": {"run_id": report["run_id"], "clock": "CLOCK_MONOTONIC; microseconds", "status": report["status"], "note": "Task durations are runtime spans; resource counters refer to enclosing sampling intervals, not instantaneous truth."}}


def _svg(points, title, unit):
    valid = [(x, y) for x, y in points if _number(x) and _number(y)]
    if not valid:
        return "<section><h3>{}</h3><p>未观测，不能解释为零。</p></section>".format(html.escape(title))
    x0, x1 = min(x for x, _ in valid), max(x for x, _ in valid)
    ymax = max(y for _, y in valid) or 1
    # Point markers do not join across unknown/missing samples.
    dots = "".join('<circle cx="{:.2f}" cy="{:.2f}" r="2.7"><title>{:.6f} s: {:.6f} {}</title></circle>'.format(52 + (x - x0) / max(1, x1 - x0) * 650, 164 - y / ymax * 135, (x - x0) / 1e9, y, html.escape(unit)) for x, y in valid)
    return '<section><h3>{}</h3><svg viewBox="0 0 730 195" role="img" aria-label="{}"><path d="M52 24V164H710" fill="none" stroke="#8b949e"/><g fill="#2563eb">{}</g><text x="4" y="27">{:.3g}</text><text x="5" y="164">0</text><text x="52" y="187">0 s</text><text x="590" y="187">{:.3f} s</text></svg><small>单位 {}；每点表示一个实际采样区间，缺失点不连线。</small></section>'.format(html.escape(title), html.escape(title), dots, ymax, (x1 - x0) / 1e9, html.escape(unit))


def _trial_html_content(report):
    esc = lambda value: html.escape(str(value))
    rows = []
    for task in report["tasks"]:
        duration = "未知" if task["duration_ns"] is None else "{:.3f}".format(task["duration_ns"] / 1e6)
        resources = task["resources"] or {}
        cores = _get(resources, "cpu", "usage_cores")
        cpu = "未知" if cores is None else "{:.3f}".format(cores)
        candidates = "；".join(item["label"] for item in task["candidates"]) or "证据不足以指出瓶颈"
        boundary = resources.get("boundary", {})
        uncertainty = "未知" if not boundary else "前 {:.3f} / 后 {:.3f} ms".format(boundary["before_uncertainty_ns"] / 1e6, boundary["after_uncertainty_ns"] / 1e6)
        rows.append("<tr>{}</tr>".format("".join("<td>{}</td>".format(esc(value)) for value in (task["task_id"], task["status"], duration, cpu, uncertainty, candidates))))
    issues = "".join("<li><code>{}</code> — {}：{}</li>".format(esc(item["code"]), esc(item["location"]), esc(item["detail"])) for item in report["issues"])
    curves = []
    for group in report["cgroup_intervals"]:
        name = group["cgroup"]["path"].rsplit("/", 1)[-1]
        for keys, label, unit in ((('cpu', 'usage_cores'), 'CPU 使用', 'cores'), (('psi', 'cpu', 'some_fraction'), 'CPU 等待比例', 'fraction'), (('psi', 'io', 'some_fraction'), 'I/O 等待比例', 'fraction'), (('psi', 'memory', 'some_fraction'), '内存压力比例', 'fraction'), (('memory', 'memory_current_bytes'), '已记账内存', 'bytes')):
            curves.append(_svg([(row["end_ns"], _get(row["metrics"], *keys)) for row in group["intervals"]], name + " · " + label, unit))
        devices = sorted({device for row in group["intervals"] for device in (row["metrics"].get("io_by_device") or {})})
        for device in devices:
            curves.append(_svg([(row["end_ns"], _get(row["metrics"], "io_by_device", device, "rbytes_per_second")) for row in group["intervals"]], name + " · 设备 " + device + " 块读取", "bytes/s"))
    curves.append(_svg([(row["end_ns"], row["cpu_active_cores"]) for row in report["system_intervals"]], "全机背景 CPU（不归因到 Agent）", "cores"))
    return '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>并发搜索性能分析</title><style>body{font:15px/1.6 system-ui,sans-serif;max-width:1200px;margin:32px auto;padding:0 20px;color:#172033}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:8px;border:1px solid #d5dae3;text-align:left}th{background:#eef2ff}code{overflow-wrap:anywhere}section{border:1px solid #ddd;border-radius:8px;padding:12px}svg{width:100%;max-height:210px}svg text{font-size:12px}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}.note{background:#fff6df;padding:14px}li{overflow-wrap:anywhere}</style><h1>并发搜索：时间花在哪里？</h1><p>Run：<code>' + esc(report["run_id"]) + '</code> · 数据状态：<strong>' + esc(report["status"]) + '</strong></p><p class="note">这里给出任务时间和资源线索，不宣称已证明瓶颈。资源值包含阶段边界之外的采样误差；PSI 不能相加；全机曲线不是 Agent 的用量。</p><h2>每次搜索</h2><p>总执行窗口：' + ("未知" if report["execution_makespan_ns"] is None else "{:.3f} ms".format(report["execution_makespan_ns"] / 1e6)) + '</p><table><thead><tr><th>任务</th><th>结果</th><th>耗时 ms</th><th>包围区间 CPU cores</th><th>边界不确定性</th><th>候选线索（非因果结论）</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table><h2>资源时间序列</h2><main>' + "".join(curves) + '</main><h2>缺失与异常</h2><ul>' + (issues or '<li>声明范围内未发现数据完整性问题；不等于覆盖所有性能因素。</li>') + '</ul><h2>如何解读</h2><ul>' + "".join('<li>' + esc(limit) + '</li>' for limit in report["limits"]) + '</ul><p>原始计数保存在 load/；机器可读结果 report.json；任务时间线 timeline.json 可导入 Chrome Trace / Perfetto。修改并发后请比较相同查询结果、总任务完成时间和每任务延迟，而非只比较 CPU 利用率。</p></html>'


def _label_calibration(document, configuration):
    kind = _get(configuration, "calibration_kind")
    if kind is None:
        return document
    label = {"cpu": "CPU", "sleep": "sleep 睡眠", "read": "read 文件读取"}.get(kind, "未知类型") if isinstance(kind, str) else "未知类型"
    title = label + "校准（不是搜索优化实验）"
    document = document.replace("<title>并发搜索性能分析</title>", "<title>" + title + "</title>")
    document = document.replace("<title>并发搜索对照实验</title>", "<title>" + title + "</title>")
    document = document.replace("<h1>并发搜索：时间花在哪里？</h1>", "<h1>" + title + "</h1>")
    document = document.replace("<h1>并发搜索：测量与单因素对照</h1>", "<h1>" + title + "</h1>")
    document = document.replace("<h2>每次搜索</h2>", "<h2>每次校准任务</h2>")
    document = document.replace("<h2>每个搜索任务（可能包含多次查询）</h2>", "<h2>每次校准任务</h2>")
    duration = _get(configuration, "calibration_seconds")
    detail = "每任务目标约 {} 秒{}。".format(html.escape(str(duration)), "进程 CPU 时间" if kind == "cpu" else "睡眠时间") if kind in ("cpu", "sleep") else "按固定文件列表及 passes 读取；calibration_seconds 不控制 read 工作量。"
    badge = '<p class="note"><strong>这是测量校准，不是搜索优化结果。</strong>' + detail + '空输出的一致性不能证明计量准确；仍需对照目标时长、CPU 计量及实际采样窗口。短任务只有包围样本时，不能据此验证细粒度延迟。</p>'
    return document.replace("<h2>", badge + "<h2>", 1)


def _html(report):
    document = _trial_html_content(report)
    document = document.replace('<h2>每次搜索</h2>', '<h2>每个搜索任务（可能包含多次查询）</h2>')
    measurement = report.get('query_measurements', {})
    escape = lambda value: html.escape(str(value))
    rows = []
    for query in measurement.get('queries', [])[:200]:
        duration = query.get('duration_ns')
        values = (query.get('task_id'), query.get('query_ordinal'), query.get('execution_kind'),
                  '{:.3f}'.format(duration / 1e6) if _integer(duration) else '未知', query.get('measurement_status'))
        rows.append('<tr>' + ''.join('<td>' + escape(value) + '</td>' for value in values) + '</tr>')
    section = '<h2>逐次查询延迟</h2><p>状态：' + escape(measurement.get('status', 'NOT_COLLECTED_LEGACY')) + '；已验证查询：' + escape(measurement.get('observed_queries', 0)) + ' / ' + escape(measurement.get('expected_queries', '未知')) + '。</p><p>每一行是一轮真实查询调用；SCAN 为实际 grep，CACHE_HIT 为读取本轮缓存，耗时包含等待缓存锁。不是总任务时间除以查询次数。旧数据未采集时显示未知。最多展示 200 行，完整数据和单调时钟起止见 report.json / timeline.json。</p><table><thead><tr><th>任务</th><th>查询序号</th><th>执行方式</th><th>耗时 ms</th><th>质量</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table>'
    document = document.replace('<h2>资源时间序列</h2>', section + '<h2>资源时间序列</h2>')
    document = document.replace("<h2>如何解读</h2><ul>", "<h2>如何解读</h2><ul><li>" + html.escape(CPU_TIME_LIMIT) + "</li>")
    return _label_calibration(document, report.get("config"))


def write_report(directory):
    directory = Path(directory)
    report = analyze_trial(directory)
    extra = Problems()
    run = _read(directory / 'profile-run.json', extra)
    report["observer_audit"] = {"status": run.get("observer_audit", "NOT_ENABLED"), "result": run.get("observer_result"),
        "preparation_ns": run.get("observer_prepare_ns"),
        "interpretation": "Audit verification and resource sampling are independent; verified=true is not whole-system coverage."}
    if (directory / 'load/load-meta.json').exists():
        meta = _read(directory / 'load/load-meta.json', extra)
        if _get(meta, 'thread_sampling', 'enabled') is True:
            stats = _read(directory / 'load/load-sampler-stats.json', extra)
            issues = Problems()
            rows = _read(directory / 'load/load-processes.jsonl', issues, lines=True)
            report['threads'] = thread_report(meta, stats, rows)
            report['threads']['issues'].extend(issues.items)
            if issues.items:
                report['threads']['status'] = 'PARTIAL_POLLED_WITH_GAPS'
            extra.items.extend(report['threads']['issues'])
    for issue in extra.items:
        if issue not in report['issues']:
            report['issues'].append(issue)
    if extra.items:
        report['status'] = 'INCOMPLETE'
        if report['sampling_status'] != 'NOT_COLLECTED':
            report['sampling_status'] = 'INCOMPLETE'
    report["analysis"] = {"tool": "search-profile-analyzer", "schema_version": 1,
                          "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (directory / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (directory / "timeline.json").write_text(json.dumps(timeline(report), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    html_report = _html(report).replace("<h2>缺失与异常</h2>", _kernel_hist_html(report) + _domain_thread_html(report) + "<h2>缺失与异常</h2>")
    (directory / "report.html").write_text(html_report, encoding="utf-8")
    return report


def _kernel_hist_html(report):
    hist = report["kernel_hist"]
    if not hist["enabled"]:
        return ""
    rows = []
    for metric in hist["aggregates"]:
        mean = metric["mean_completed_span_ns"]
        values = (metric["name"], metric["scope"], metric["completed_count"],
                  metric["completed_sum_ns"], "未观测 / 无完成事件" if mean is None else "{:.3f}".format(mean))
        rows.append("<tr>" + "".join("<td>" + html.escape(str(value)) + "</td>" for value in values) + "</tr>")
    issues = "".join("<li><code>" + html.escape(item["code"]) + "</code>：" + html.escape(item["location"]) + " — " + html.escape(item["detail"]) + "</li>" for item in hist["issues"])
    document = '<h2>内核延迟探针（单独的诊断层）</h2><p>健康状态：<strong>' + html.escape(hist["status"]) + '</strong>。目标根 cgroup：<code>' + html.escape(str(hist.get("target_cgroup"))) + '</code>。</p><p class="note">以下是已完成片段的累计统计，不是每个 Agent 的精确时间分账。runq、on-CPU、off-CPU、syscall 片段可能跨采样边界并相互重叠，不能相加为任务总耗时。SYSTEM_ONLY 指全机背景。发生递归漏采时保留已观测值，但不能宣称完整。</p><table><thead><tr><th>指标</th><th>作用范围</th><th>完成片段数</th><th>已完成片段时长之和 ns</th><th>平均完成片段 ns</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table><ul>' + (issues or '<li>没有报告选定探针的已知丢失；仍存在非原子采样和未覆盖机制，未计算 p99。</li>') + '</ul>'
    block = hist.get('block_diagnostics')
    if isinstance(block, dict) and block.get('status') != 'NOT_AVAILABLE_LEGACY_COLLECTOR':
        escape = lambda value: html.escape(str('未知' if value is None else value))
        document += '<h2>全系统 block 边界诊断（不归因到 Agent）</h2><p>状态：' + escape(block.get('status')) + '</p><p class="note">没有 insert 的请求可能直接分发，queue 时间是 UNKNOWN，不是零，也不能仅凭它判定丢事件。未追踪 completion 的原因仍未知。零字节 FLUSH 单独记录服务片段，不是数据读取量，也不是 fdatasync 总延迟。请求提示样本是每 CPU 有界的首批样本，截断不等于基础直方图丢失。</p><p>最终 FLUSH 已完成片段：' + escape(_get(block, 'final', 'flush_service', 'count')) + '；queue 未知计数：' + escape(_get(block, 'final', 'counters', 'queue_span_unknown')) + '；untracked completion 未知计数：' + escape(_get(block, 'final', 'counters', 'untracked_complete')) + '；诊断样本截断：' + escape(block.get('samples_truncated')) + '。</p>'
    return document


def _domain_thread_html(report):
    escape = lambda value: html.escape(str(value))
    sections = []
    domains = _get(report, 'kernel_hist', 'domains') or []
    if domains:
        rows = []
        for domain in domains:
            for metric in domain['aggregates']:
                values = (domain['domain_index'], domain.get('target_cgroup'), domain['status'],
                          metric['name'], metric['completed_count'], metric['completed_sum_ns'])
                rows.append('<tr>' + ''.join('<td>' + escape(value) + '</td>' for value in values) + '</tr>')
        sections.append('<h2>分 cgroup 域的诊断（不是任务耗时分账）</h2><p>按 path/inode/device/index 选域；父域包含子域，不能相加。全系统 block/softirq 不分配给 Agent。</p><table><thead><tr><th>域</th><th>cgroup</th><th>健康</th><th>片段</th><th>完成数</th><th>累计 ns</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table>')
    threads = report.get('threads')
    if threads and threads.get('status') != 'NOT_COLLECTED':
        rows = []
        for instance in threads['instances'][:200]:
            identity = instance['identity']
            values = (identity['pid'], identity['process_start_ticks'], identity['tid'], identity['thread_start_ticks'],
                      instance['observations'], instance['status'], instance['deltas'].get('utime'),
                      instance['deltas'].get('run_ns'), instance['deltas'].get('wait_ns'))
            rows.append('<tr>' + ''.join('<td>' + escape('未知' if value is None else value) + '</td>' for value in values) + '</tr>')
        sections.append('<h2>线程实例采样：' + escape(threads['status']) + '</h2><p>轮询会漏掉短线程，不是完整生命周期。wait 在 schedstats 关闭时显示未知；线程等待和墙钟时间不能相加。最多展示200实例，全部数据见 JSON。</p><table><thead><tr><th>PID</th><th>进程 birth ticks</th><th>TID</th><th>线程 birth ticks</th><th>样本</th><th>质量</th><th>user ticks 增量</th><th>run ns 增量</th><th>wait ns 增量</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table>')
    return ''.join(sections)


def _summary_statistics(values, bootstrap=True):
    """Exploratory percentile bootstrap of the mean, NOT a median interval."""
    values = list(values)
    if not values:
        return {"n": 0, "median": None, "mean": None, "observed_p95": None, "mean_ci95_bootstrap": None}
    ordered = sorted(values)
    interval = None
    if bootstrap and len(values) >= 3:
        rng = random.Random(1)
        means = sorted(statistics.mean(rng.choices(values, k=len(values))) for _ in range(2000))
        interval = [means[49], means[1949]]
    return {"n": len(values), "median": statistics.median(values), "mean": statistics.mean(values), "observed_p95": ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)], "mean_ci95_bootstrap": interval}


def _pair_measurements(reference, intervention):
    values, repetitions = [], []
    for repetition in sorted(set(reference) & set(intervention)):
        baseline = reference[repetition].get("makespan_ns")
        changed = intervention[repetition].get("makespan_ns")
        if _number(baseline) and baseline > 0 and _number(changed) and changed > 0:
            values.append(changed / baseline - 1)
            repetitions.append(repetition)
    result = _summary_statistics(values)
    result.update(repetitions=repetitions, paired_relative_changes=values,
                  definition="intervention_makespan / reference_makespan - 1",
                  interpretation="negative means faster; exploratory paired comparison, not causal attribution")
    return result


def _trial_observation_health(index, trial, evidence=None):
    """Keep measurement health independent from fixed-work output equivalence."""
    problems = Problems()
    evidence = evidence or {}
    for issue in evidence.get("issues", []):
        problems.add(issue["code"], issue["location"], issue["detail"])
    report = evidence.get("report")
    mode = trial.get("mode")
    legacy_status = trial.get("analysis_status")
    analysis_status = legacy_status
    sampling_requested = mode not in ("baseline", "observer")
    sampling = "NOT_COLLECTED" if not sampling_requested else "UNKNOWN"
    diagnostic = "UNKNOWN" if mode == "kernel-hist" else "NOT_COLLECTED"
    diagnostic_issues = []
    basis = "LEGACY_ANALYSIS_SUMMARY" if legacy_status else "NO_TRIAL_REPORT"
    identity_valid = True
    if isinstance(report, dict):
        basis = "SAVED_TRIAL_REPORT"
        analysis_status = report.get("status")
        if trial.get("run_id") is not None and trial["run_id"] != report.get("run_id"):
            identity_valid = False
            problems.add("TRIAL_REPORT_IDENTITY_MISMATCH", "run_id", "saved report does not belong to the declared trial")
        report_mode = _get(report, "config", "mode")
        if report_mode is not None and report_mode != mode:
            identity_valid = False
            problems.add("TRIAL_REPORT_IDENTITY_MISMATCH", "mode", "saved report and campaign mode differ")
        sampling = report.get("sampling_status", "UNKNOWN")
        if sampling not in ("OBSERVED", "INCOMPLETE", "NOT_COLLECTED"):
            sampling = "UNKNOWN"
        if not sampling_requested and sampling != "NOT_COLLECTED":
            problems.add("UNEXPECTED_BASELINE_SAMPLING", "sampling_status", sampling)
            sampling = "INCOMPLETE"
        elif sampling_requested and sampling == "NOT_COLLECTED":
            problems.add("REQUESTED_SAMPLING_NOT_COLLECTED", "sampling_status", mode)
            sampling = "INCOMPLETE"
        raw_issues = report.get("issues")
        if not isinstance(raw_issues, list):
            problems.add("INVALID_TRIAL_REPORT_ISSUES", "issues", "missing or invalid issue list")
            sampling = "UNKNOWN" if sampling == "OBSERVED" else sampling
            raw_issues = []
        for issue in raw_issues:
            if isinstance(issue, dict) and isinstance(issue.get("code"), str):
                problems.add(issue["code"], issue.get("location"), issue.get("detail"))
                if sampling_requested and not issue["code"].startswith("KERNEL_HIST_"):
                    sampling = "INCOMPLETE"
            else:
                problems.add("INVALID_TRIAL_REPORT_ISSUES", "issues", "issue must contain a code")
                sampling = "UNKNOWN" if sampling == "OBSERVED" else sampling
        hist = report.get("kernel_hist")
        if mode == "kernel-hist" or _get(hist, "enabled") is True:
            diagnostic = {"NO_REPORTED_LOSS_WITHIN_SELECTED_PROBES": "OBSERVED", "INCOMPLETE": "INCOMPLETE"}.get(_get(hist, "status"), "UNKNOWN")
            if mode == "kernel-hist" and _get(hist, "enabled") is not True:
                problems.add("REQUESTED_DIAGNOSTIC_NOT_COLLECTED", "kernel_hist/enabled", "kernel-hist mode needs an enabled probe report")
                diagnostic = "INCOMPLETE"
            hist_issues = _get(hist, "issues")
            if isinstance(hist_issues, list):
                for issue in hist_issues:
                    if isinstance(issue, dict) and isinstance(issue.get("code"), str):
                        normalized = {key: str(issue.get(key)) for key in ("code", "location", "detail")}
                        diagnostic_issues.append(normalized)
                        problems.add(normalized["code"], normalized["location"], normalized["detail"])
                if hist_issues:
                    diagnostic = "INCOMPLETE"
            else:
                problems.add("INVALID_TRIAL_DIAGNOSTIC_ISSUES", "kernel_hist/issues", "missing or invalid issue list")
                diagnostic = "UNKNOWN" if diagnostic == "OBSERVED" else diagnostic
        if not identity_valid:
            sampling = "UNKNOWN" if sampling_requested else "NOT_COLLECTED"
            diagnostic = "UNKNOWN" if diagnostic != "NOT_COLLECTED" else diagnostic
    elif legacy_status == "INCOMPLETE":
        # An old aggregate cannot distinguish ordinary sampling from probe loss.
        problems.add("LEGACY_TRIAL_ANALYSIS_INCOMPLETE", "analysis_status", "inspect or regenerate the trial report for causes")
    if analysis_status == "INCOMPLETE" or "INCOMPLETE" in (sampling, diagnostic) or (isinstance(report, dict) and report.get("issues")):
        status = "INCOMPLETE"
    elif "UNKNOWN" in (sampling, diagnostic) or evidence.get("issues"):
        status = "UNKNOWN"
    elif "OBSERVED" in (sampling, diagnostic):
        status = "OBSERVED_WITHIN_DECLARED_MEASUREMENT"
    else:
        status = "NOT_COLLECTED"
    return {"trial_index": index, "path": trial.get("path"), "run_id": trial.get("run_id"),
            "mode": mode, "warmup": trial.get("warmup"), "analysis_status": analysis_status,
            "status": status, "sampling_status": sampling, "diagnostic_status": diagnostic,
            "basis": basis, "source": evidence.get("source"), "issues": problems.items,
            "diagnostic_issues": diagnostic_issues,
            "process_sampling_gap": any(issue["code"].startswith(("PROCESS_", "INVALID_PROCESS_")) for issue in problems.items)}


def _campaign_observation_health(trials, trial_evidence=None):
    rows = []
    for index, trial in enumerate(trials):
        if isinstance(trial, dict):
            rows.append(_trial_observation_health(index, trial, (trial_evidence or {}).get(index)))
        else:
            rows.append(_trial_observation_health(index, {}, {"issues": [{"code": "INVALID_CAMPAIGN_TRIAL", "location": index, "detail": "trial must be an object"}]}))

    def summarize(field):
        statuses = ("OBSERVED", "INCOMPLETE", "UNKNOWN", "NOT_COLLECTED")
        counts = {status: sum(row[field] == status for row in rows) for status in statuses}
        status = next((value for value in ("INCOMPLETE", "UNKNOWN", "OBSERVED") if counts[value]), "NOT_COLLECTED")
        return {"status": status, "counts": counts,
                "measured_counts": {status: sum(row[field] == status and row["warmup"] is False for row in rows) for status in statuses},
                "warmup_counts": {status: sum(row[field] == status and row["warmup"] is True for row in rows) for status in statuses}}

    sampling, diagnostic = summarize("sampling_status"), summarize("diagnostic_status")
    status = "INCOMPLETE" if any(row["status"] == "INCOMPLETE" for row in rows) else (
        "UNKNOWN" if not rows or any(row["status"] == "UNKNOWN" for row in rows) else (
        "OBSERVED_WITHIN_DECLARED_MEASUREMENT" if sampling["counts"]["OBSERVED"] or diagnostic["counts"]["OBSERVED"] else "NOT_COLLECTED"))
    issues = [dict(issue, trial_index=row["trial_index"], trial_path=row["path"])
              for row in rows for issue in row["issues"]]
    return {"status": status, "trial_count": len(rows), "sampling": sampling,
            "diagnostic": diagnostic, "process_sampling_gap_trial_count": sum(row["process_sampling_gap"] for row in rows),
            "issues": issues, "trials": rows,
            "interpretation": "Independent of execution completion and fixed-work output equivalence. NOT_COLLECTED is explicit baseline/disabled coverage, not successful sampling. UNKNOWN or INCOMPLETE is never interpreted as zero resource use."}


def _campaign_trial_evidence(directory, trials):
    """Read saved reports only inside the campaign, with bounded file/batch sizes."""
    root = Path(directory).resolve()
    remaining = 128 * 1024 * 1024
    evidence = {}
    for index, trial in enumerate(trials if isinstance(trials, list) else []):
        if not isinstance(trial, dict):
            continue
        problems = Problems()
        result = {"report": None, "issues": problems.items}
        evidence[index] = result
        try:
            path = trial.get("path")
            if not isinstance(path, str) or not path or Path(path).is_absolute() or ".." in Path(path).parts or Path(path) == Path("."):
                raise ValueError("trial path must be a nonempty relative directory without traversal")
            candidate = (root / path / "report.json").resolve()
            candidate.relative_to(root)
            limit = min(16 * 1024 * 1024, remaining)
            if index >= 4096 or limit <= 0:
                raise ValueError("campaign trial-report read budget exhausted")
            file_stat = candidate.stat()
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > limit:
                raise ValueError("trial report must be a bounded regular file")
            with candidate.open("rb") as stream:
                raw = stream.read(limit + 1)
            remaining -= len(raw)
            if len(raw) > limit:
                raise ValueError("trial report exceeded byte limit")
            report = json.loads(raw.decode("utf-8"))
            if not isinstance(report, dict) or report.get("schema_version") != 1:
                raise ValueError("unsupported trial report schema")
            result["report"] = report
            result["source"] = {"path": str(candidate.relative_to(root)), "sha256": hashlib.sha256(raw).hexdigest(),
                                "analyzer_sha256": _get(report, "analysis", "source_sha256")}
        except (OSError, ValueError, UnicodeError, RecursionError) as error:
            problems.add("TRIAL_REPORT_UNAVAILABLE_OR_INVALID", trial.get("path"), error)
    return evidence


def campaign_report(campaign, trial_evidence=None):
    """Compare randomized fixed-work blocks without choosing a noisy best run."""
    problems = Problems()
    trials = campaign.get("trials", [])
    if not isinstance(trials, list):
        problems.add("INVALID_CAMPAIGN_TRIALS", "campaign.json", "trials must be a list")
        trials = []
    groups, expected = {}, {}
    expected_assignment = None
    equivalence = "PASS" if trials else "INDETERMINATE"
    expected_jobs = campaign.get("jobs")
    for index, trial in enumerate(trials):
        location = "trial:{}".format(index)
        if not isinstance(trial, dict):
            problems.add("INVALID_CAMPAIGN_TRIAL", location, "trial must be an object")
            equivalence = "INDETERMINATE" if equivalence != "FAIL" else equivalence
            continue
        results = trial.get("results", [])
        if not isinstance(results, list) or not all(isinstance(row, dict) for row in results) or not _integer(expected_jobs) or expected_jobs == 0 or len(results) != expected_jobs:
            problems.add("INCOMPLETE_FIXED_WORK", location, "every trial needs the same declared job count")
            equivalence = "INDETERMINATE" if equivalence != "FAIL" else equivalence
            continue
        task_ids = [row.get("task_id") for row in results]
        if any(not isinstance(task, str) for task in task_ids) or len(set(task_ids)) != len(task_ids):
            problems.add("DUPLICATE_OR_MISSING_TASK", location, "fixed-work tasks must be unique")
            equivalence = "INDETERMINATE" if equivalence != "FAIL" else equivalence
        assignment = sorted((row.get("task_id"), row.get("query_index")) for row in results if isinstance(row.get("task_id"), str) and _integer(row.get("query_index")))
        if expected_assignment is not None and assignment != expected_assignment:
            problems.add("QUERY_ASSIGNMENT_CHANGED", location, "fixed work requires identical task-to-query assignment")
            equivalence = "FAIL"
        expected_assignment = assignment
        for result in results:
            key = result.get("query_index")
            checksum = result.get("output_sha256")
            if not _integer(key) or not isinstance(checksum, str) or len(checksum) != 64 or any(c not in "0123456789abcdef" for c in checksum) or not _integer(result.get("output_bytes")):
                problems.add("MISSING_OUTPUT_IDENTITY", location, "query index, SHA256 and byte count required")
                equivalence = "INDETERMINATE" if equivalence != "FAIL" else equivalence
                continue
            value = (result.get("exit_code"), checksum, result["output_bytes"])
            if value[0] != 0 or (key in expected and value != expected[key]):
                equivalence = "FAIL"
                problems.add("OUTPUT_NOT_EQUIVALENT", location, "query_index={}".format(key))
            expected[key] = value
        if trial.get("warmup") is not False:
            continue
        mode, concurrency, repetition = (trial.get(key) for key in ("mode", "concurrency", "repetition"))
        if not isinstance(mode, str) or not _integer(concurrency) or concurrency == 0 or not _integer(repetition):
            problems.add("INVALID_CONDITION_IDENTITY", location, "mode/concurrency/repetition required")
            continue
        grouped = groups.setdefault((mode, concurrency), {})
        if repetition in grouped:
            problems.add("DUPLICATE_REPETITION", location, "would invalidate paired comparison")
            continue
        if not _number(trial.get("makespan_ns")) or trial["makespan_ns"] <= 0:
            problems.add("INVALID_CAMPAIGN_DURATION", location, "positive makespan required")
            continue
        grouped[repetition] = trial
    conditions = []
    trial_index_by_identity = {id(trial): index for index, trial in enumerate(trials)}
    for (mode, concurrency), rows in sorted(groups.items()):
        cpu = []
        latencies = []
        query_latencies = []
        query_statuses = []
        for trial in rows.values():
            counters = [(result.get("user_usec"), result.get("system_usec")) for result in trial["results"]]
            if all(_number(user) and _number(system) and user >= 0 and system >= 0 for user, system in counters):
                cpu.append(sum(user + system for user, system in counters) / 1e6)
            else:
                problems.add("MISSING_CAMPAIGN_CPU", trial.get("path"), "resource cost unknown")
            latencies.extend(result["completion_latency_ns"] / 1e9 for result in trial["results"] if _number(result.get("completion_latency_ns")))
            source = (trial_evidence or {}).get(trial_index_by_identity[id(trial)], {})
            saved = _get(source, 'report')
            measurements = _get(saved, 'query_measurements')
            if not isinstance(measurements, dict):
                query_statuses.append('NOT_COLLECTED_LEGACY' if measurements is None else 'INCOMPLETE')
                continue
            status = measurements.get('status', 'INCOMPLETE')
            query_rows = measurements.get('queries')
            if status == 'OBSERVED':
                count = campaign.get('passes')
                expected_queries = expected_jobs * count if _integer(count) else None
                bound = (isinstance(trial.get('run_id'), str) and bool(trial['run_id'])
                    and _get(saved, 'run_id') == trial['run_id']
                    and _get(saved, 'config', 'mode') == trial['mode']
                    and _get(saved, 'config', 'concurrency') == trial['concurrency'])
                if (not bound or not isinstance(query_rows, list) or len(query_rows) != expected_queries
                        or measurements.get('expected_queries') != expected_queries
                        or measurements.get('observed_queries') != expected_queries
                        or any(not isinstance(row, dict) or row.get('measurement_status') != 'OBSERVED'
                               or not _integer(row.get('duration_ns')) for row in query_rows)):
                    status = 'INCOMPLETE'
                else:
                    query_latencies.extend(row['duration_ns'] / 1e9 for row in query_rows)
            query_statuses.append(status)
        conditions.append({"mode": mode, "concurrency": concurrency,
                           "makespan_seconds": _summary_statistics(trial["makespan_ns"] / 1e9 for trial in rows.values()),
                           "total_task_cpu_seconds": _summary_statistics(cpu),
                           "task_completion_latency_seconds": _summary_statistics(latencies, bootstrap=False),
                           "logical_query_duration_seconds": _summary_statistics(query_latencies, bootstrap=False),
                           "query_measurement_status": 'OBSERVED' if query_statuses and all(value == 'OBSERVED' for value in query_statuses) else ('INCOMPLETE' if 'INCOMPLETE' in query_statuses else 'NOT_COLLECTED_OR_MIXED'),
                           "latency_sampling_unit": "pooled tasks within trials are correlated; exploratory distribution, not independent trial confidence"})
    overhead = []
    for (mode, concurrency), rows in sorted(groups.items()):
        if mode == "baseline" or ("baseline", concurrency) not in groups:
            continue
        overhead.append({"mode": mode, "concurrency": concurrency,
                         "reference": "baseline (same concurrency, repetition)",
                         "relative_makespan": _pair_measurements(groups[("baseline", concurrency)], rows)})
    incremental = []
    for (mode, concurrency), rows in sorted(groups.items()):
        if mode == "observer-sampler" and ("observer", concurrency) in groups:
            incremental.append({"mode": mode, "concurrency": concurrency,
                "reference": "observer (same concurrency, repetition)",
                "relative_makespan": _pair_measurements(groups[("observer", concurrency)], rows)})
    intervention = []
    for mode in sorted({key[0] for key in groups}):
        levels = sorted(concurrency for item_mode, concurrency in groups if item_mode == mode)
        reference = levels[-1]
        for concurrency in levels[:-1]:
            intervention.append({"mode": mode, "reference_concurrency": reference, "intervention_concurrency": concurrency,
                                 "relative_makespan": _pair_measurements(groups[(mode, reference)], groups[(mode, concurrency)])})
    if problems.items and equivalence == "PASS":
        equivalence = "INDETERMINATE"
    limits = ["比较保持总搜索次数、查询和语料一致；降低并发只是一个预先声明的干预，不自动选取最快样本。",
              "并发对照以本轮测试的最高并发为参照，逐个展示所有较低并发；负比值表示总完成时间缩短。",
              "开销对照仅比较相同并发、相同 repetition 的 baseline 与采样档；它包含采样器本身及其扰动。",
              "区间是以 trial 或配对 block 为单位重采样得到的均值区间，不是中位数区间；少于 3 个样本不计算。",
              "任务延迟在同一 trial 内相关，任务级 pooled 分位数仅作描述，不能当独立重复估计置信区间。",
              "少样本 bootstrap、观测 p95 和单次 VM 测量都不能建立生产 SLA 或稳定尾延迟。",
              "warm 为显式预读，未证明所有数据一直驻留；guest-cold 只清理 Guest 缓存，不证明 Host/存储缓存冷。",
              "根 cgroup 与任务子 cgroup 的资源统计有包含关系，不能求和；PSI 资源/层级也不能相加。",
              "计时范围由运行器声明：新版本在 worker 初始化后开始计时，旧版本可能包含解释器初始化；都包含搜索子进程启动、worker 调度与父进程退出轮询。总窗口包含队列管理，结果 hash 在计时后执行。",
              CPU_TIME_LIMIT,
              "lifetime CPU（如提供）另含 worker 初始化。max RSS 是进程生命周期高水位，不能相加成并发内存峰值。",
              "输出相同仅保证本实验 grep 的文件名结果/计数一致，不声称所有搜索工具语义等价。",
              "性能曲线是测量旁路；observer/observer-sampler 的 WAL 及独立 verifier 结果另存，不与采样完整度混为一类。资源线索不能单独证明因果瓶颈。",
              "shared-leaf 中所有任务共享 cgroup，cgroup 用量是执行组总量，不是某个任务独占资源；进程 wait4 计数仍按任务保存。"]
    # Do not publish a spurious confidence interval by resampling correlated
    # task observations as if they were independent trial repetitions.
    for condition in conditions:
        condition["task_completion_latency_seconds"]["mean_ci95_bootstrap"] = None
    return {"schema_version": 1, "campaign_id": campaign.get("campaign_id"),
            "status": campaign.get("status", "UNKNOWN"), "output_equivalence": equivalence,
            "fixed_work": {key: campaign.get(key) for key in ("jobs", "passes", "corpus_sha256", "permission_scope_sha256", "repository_version", "intervention", "workspace_layout", "cgroup_layout", "memory_max_mb", "memory_high_mb", "cache", "timing_scope", "cpu_time_scope", "calibration_kind", "calibration_seconds")},
            "conditions": conditions, "paired_overhead": overhead, "paired_concurrency_interventions": intervention,
            "paired_incremental_sampler_overhead": incremental,
            "observation_health": _campaign_observation_health(trials, trial_evidence),
            "issues": problems.items, "trials": [{key: trial.get(key) for key in ("path", "run_id", "mode", "concurrency", "repetition", "warmup", "analysis_status")} for trial in trials if isinstance(trial, dict)],
            "limits": limits}


def _campaign_html_content(report):
    esc = lambda value: html.escape(str(value))

    def number(value):
        return "未知" if value is None else "{:.4f}".format(value)

    def interval(value):
        return "样本不足 / 不计算" if value is None else "[{}, {}]".format(number(value[0]), number(value[1]))

    def table(headers, rows):
        return '<table><thead><tr>' + ''.join('<th>' + esc(value) + '</th>' for value in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + esc(value) + '</td>' for value in row) + '</tr>' for row in rows) + '</tbody></table>'

    rows = []
    for condition in report["conditions"]:
        duration = condition["makespan_seconds"]
        rows.append((condition["mode"], condition["concurrency"], duration["n"], number(duration["median"]), number(duration["observed_p95"]), number(duration["mean"]), interval(duration["mean_ci95_bootstrap"]), number(condition["total_task_cpu_seconds"]["median"])))
    overhead = []
    for item in report["paired_overhead"]:
        values = item["relative_makespan"]
        overhead.append((item["mode"], item["concurrency"], values["n"], number(values["median"]), number(values["mean"]), interval(values["mean_ci95_bootstrap"])))
    interventions = []
    for item in report["paired_concurrency_interventions"]:
        values = item["relative_makespan"]
        interventions.append((item["mode"], '{} → {}'.format(item["reference_concurrency"], item["intervention_concurrency"]), values["n"], number(values["median"]), number(values["mean"]), interval(values["mean_ci95_bootstrap"])))
    links = []
    for trial in report["trials"]:
        path = trial.get("path")
        if not isinstance(path, str) or Path(path).is_absolute() or '..' in Path(path).parts:
            continue
        url = quote(path.rstrip('/') + '/report.html', safe='/')
        links.append('<li><a href="{}">{} · {} 并发 · repetition {}{}</a>：{}</li>'.format(url, esc(trial.get("mode")), esc(trial.get("concurrency")), esc(trial.get("repetition")), '（预热，不计入统计）' if trial.get("warmup") else '', esc(trial.get("analysis_status"))))
    issues = ''.join('<li>' + esc(item) + '</li>' for item in report["issues"]) or '<li>未发现 campaign 结果结构异常。单次 trial 的采样缺失请查看其报告。</li>'
    return '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>并发搜索对照实验</title><style>body{font:15px/1.7 system-ui,sans-serif;max-width:1200px;margin:32px auto;padding:0 20px;color:#172033}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:7px;border:1px solid #d5dae3;text-align:left}th{background:#eef2ff}code{overflow-wrap:anywhere}.note{background:#fff6df;padding:14px}li{overflow-wrap:anywhere}</style><h1>并发搜索：测量与单因素对照</h1><p>Campaign：<code>' + esc(report["campaign_id"]) + '</code> · 执行状态：' + esc(report["status"]) + ' · 固定工作输出一致性：<strong>' + esc(report["output_equivalence"]) + '</strong></p><p class="note">先看结果是否一致，再比较全部任务完成时间。采样缺失不等于资源没有消耗；改善与否必须结合重复次数、区间和单次资源线索判断。</p><h2>1. 每种配置完成相同任务需要多久？</h2><p>单位为秒；预热不计入。p95 仅为当前样本的观测分位数，不能代表稳定尾延迟。</p>' + table(('采样档', '并发', 'trial 数', '总耗时中位数', '观测 p95', '均值', '均值 95% bootstrap 区间', '任务 CPU 总秒数中位数'), rows) + '<h2>2. 采样本身增加了多少耗时？</h2><p>配对比值 = 有采样总耗时 / 同并发无采样总耗时 − 1。0.10 表示增加 10%；负数不是采样必然加速的证据。</p>' + table(('采样档', '并发', '配对数', '比值中位数', '比值均值', '均值 95% bootstrap 区间'), overhead) + '<h2>3. 只降低并发，整体是否更快？</h2><p>以测试集合中的最高并发作预先固定的参照，不挑最快结果。比值 = 较低并发总耗时 / 最高并发总耗时 − 1；负数表示本次对照更快。</p>' + table(('采样档', '并发改变', '配对数', '比值中位数', '比值均值', '均值 95% bootstrap 区间'), interventions) + '<h2>4. 查看每轮任务和资源时间线</h2><ul>' + ''.join(links) + '</ul><h2>结构问题</h2><ul>' + issues + '</ul><h2>实验边界</h2><ul>' + ''.join('<li>' + esc(value) + '</li>' for value in report["limits"]) + '</ul><p>机器可读汇总：campaign-report.json。它与 trial 的 report.json 都是性能分析结果，不是 Observer 安全 verdict。</p></html>'


def _campaign_html(report):
    health = report["observation_health"]
    esc = lambda value: html.escape(str(value))
    headings = ("观测部分", "状态", "已观测", "不完整", "未知", "明确关闭")
    rows = []
    for key, label in (("sampling", "资源与进程采样"), ("diagnostic", "内核诊断探针")):
        item = health[key]
        for counts_key, suffix in (("measured_counts", "（正式测量）"), ("warmup_counts", "（预热）")):
            counts = item[counts_key]
            rows.append((label + suffix, item["status"], counts["OBSERVED"], counts["INCOMPLETE"], counts["UNKNOWN"], counts["NOT_COLLECTED"]))
    table = '<table><thead><tr>' + ''.join('<th>' + esc(value) + '</th>' for value in headings) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + esc(value) + '</td>' for value in row) + '</tr>' for row in rows) + '</tbody></table>'
    findings = ''.join('<li><code>' + esc(item["trial_path"]) + '</code>：' + esc(item["code"]) + ' · ' + esc(item["location"]) + ' · ' + esc(item["detail"]) + '</li>' for item in health["issues"]) or '<li>已读取的 trial 报告未报告观测问题；覆盖仍以声明的采样和探针为准。</li>'
    trial_rows = []
    for trial in health["trials"]:
        trial_rows.append((trial["path"], "预热" if trial["warmup"] else "正式测量", trial["sampling_status"], trial["diagnostic_status"], trial["status"], ', '.join(issue["code"] for issue in trial["issues"]) or '—'))
    detail = '<table><thead><tr>' + ''.join('<th>' + esc(value) + '</th>' for value in ("trial", "用途", "资源采样", "内核诊断", "整体观测", "问题")) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + esc(value) + '</td>' for value in row) + '</tr>' for row in trial_rows) + '</tbody></table>'
    block = '<h2>观测是否完整？</h2><p class="note">观测完整度：<strong>' + esc(health["status"]) + '</strong>。流程完成和输出一致分别说明执行结束、搜索结果相同；观测完整度说明用于解释资源瓶颈的数据是否齐全。OBSERVED 表示声明范围内已观测，NOT_COLLECTED 表示明确关闭，UNKNOWN / INCOMPLETE 表示未知或缺失，不能解释为资源用量为零。</p>' + table + '<p>含预热共 ' + esc(health["trial_count"]) + ' 个 trial，其中 ' + esc(health["process_sampling_gap_trial_count"]) + ' 个报告进程采样缺口。短进程在 procfs 读取期间退出也保留为缺口；这些问题不改变已经验证的固定工作输出一致性。</p><details><summary>查看每轮观测状态和全部缺失原因</summary>' + detail + '<ul>' + findings + '</ul></details>'
    document = _campaign_html_content(report).replace('<h2>1. 每种配置完成相同任务需要多久？</h2>', block + '<h2>1. 每种配置完成相同任务需要多久？</h2>', 1)
    return _label_calibration(document, report.get("fixed_work"))


def write_campaign_report(directory, campaign):
    """Write offline campaign summaries without changing the input campaign."""
    directory = Path(directory)
    report = campaign_report(campaign, _campaign_trial_evidence(directory, campaign.get("trials")))
    report["analysis"] = {"tool": "search-profile-analyzer", "schema_version": 1,
                          "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (directory / "campaign-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (directory / "campaign-report.html").write_text(_campaign_html(report), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trial_dir", type=Path)
    args = parser.parse_args()
    report = write_report(args.trial_dir)
    print(json.dumps({"run_id": report["run_id"], "status": report["status"], "tasks": report["task_count"], "issues": len(report["issues"]), "report": str(args.trial_dir / "report.html")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
