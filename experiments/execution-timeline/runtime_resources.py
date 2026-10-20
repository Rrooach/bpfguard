#!/usr/bin/env python3
"""Bounded resource trajectories for explicitly registered Linux processes.

RSS belongs to the registered PID, not its descendants.  Optional cgroup
gauges retain their declared scope, so a shared container is never reported as
one tool's private memory.  Sampling cannot observe every short-lived child.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import threading
import time

from resource_accounting import capture as capture_cgroup


def _stat_fields(raw):
    # comm may contain spaces and parentheses; the final ')' ends field 2.
    end = raw.rfind(")")
    if end < 0:
        raise ValueError("malformed /proc stat")
    fields = raw[end + 2:].split()
    return {"state": fields[0], "start_ticks": int(fields[19]), "minor_faults": int(fields[7]),
            "major_faults": int(fields[9]), "cpu_user_ticks": int(fields[11]),
            "cpu_system_ticks": int(fields[12]), "threads": int(fields[17]),
            "rss_pages": int(fields[21])}


def _status_values(raw):
    result = {}
    names = {"VmRSS": "rss_bytes", "VmHWM": "rss_high_water_bytes",
             "RssAnon": "rss_anon_bytes", "RssFile": "rss_file_bytes",
             "RssShmem": "rss_shmem_bytes", "VmSize": "virtual_bytes",
             "VmSwap": "swap_bytes", "voluntary_ctxt_switches": "voluntary_switches",
             "nonvoluntary_ctxt_switches": "involuntary_switches"}
    for line in raw.splitlines():
        key, sep, rest = line.partition(":")
        if sep and key in names:
            parts = rest.split()
            if parts:
                result[names[key]] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1] == "kB" else 1)
    return result


def capture_process(pid, expected_start_ticks=None, proc_root=Path("/proc")):
    """Check PID identity before and after reading non-atomic /proc gauges."""
    begin = time.monotonic_ns()
    root = Path(proc_root) / str(pid)
    errors = {}
    try:
        first = _stat_fields((root / "stat").read_text())
        if expected_start_ticks is not None and first["start_ticks"] != expected_start_ticks:
            return {"status": "PID_IDENTITY_CHANGED", "begin_ns": begin,
                    "end_ns": time.monotonic_ns(), "pid": pid,
                    "expected_start_ticks": expected_start_ticks, "values": {}}
        try:
            values = _status_values((root / "status").read_text())
        except (OSError, ValueError) as error:
            values = {}
            errors["status"] = type(error).__name__
        last = _stat_fields((root / "stat").read_text())
        if first["start_ticks"] != last["start_ticks"]:
            return {"status": "PID_IDENTITY_CHANGED", "begin_ns": begin,
                    "end_ns": time.monotonic_ns(), "pid": pid, "values": {}}
        values.update(last)
        values["cpu_user_ns"] = last["cpu_user_ticks"] * 1_000_000_000 // os.sysconf("SC_CLK_TCK")
        values["cpu_system_ns"] = last["cpu_system_ticks"] * 1_000_000_000 // os.sysconf("SC_CLK_TCK")
        values.setdefault("rss_bytes", last["rss_pages"] * os.sysconf("SC_PAGE_SIZE"))
        return {"status": "OBSERVED" if not errors else "PARTIAL", "pid": pid,
                "start_ticks": last["start_ticks"], "begin_ns": begin,
                "end_ns": time.monotonic_ns(), "values": values, "errors": errors,
                "scope": "REGISTERED_PID_ONLY_NOT_DESCENDANT_SUM"}
    except (OSError, ValueError, IndexError) as error:
        return {"status": "PROCESS_UNAVAILABLE", "pid": pid, "begin_ns": begin,
                "end_ns": time.monotonic_ns(), "values": {}, "error": type(error).__name__}


def summarize_samples(records):
    """Derive measured peaks, explicit collection reasons, and exit evidence.

    RssFile is resident file-backed mappings of one PID; it is *not* that
    workload's page cache.  Only memory.stat:file has cgroup page-cache scope.
    A missing /proc entry by itself is not evidence of a confirmed exit.
    """
    targets = {}
    limit_events = []
    for record in records:
        event = record.get("event")
        if event == "RESOURCE_SAMPLING_LIMIT_REACHED":
            limit_events.append(record)
            continue
        if event not in ("RESOURCE_SAMPLE", "RESOURCE_TARGET_REGISTERED", "RESOURCE_TARGET_FINISHED"):
            continue
        metadata = record["target"]
        name = metadata["name"]
        item = targets.setdefault(name, {"target": metadata, "sample_count": 0,
            "process_sample_count": 0, "process_unavailable_count": 0,
            "process_identity_changed": False, "cgroup_identity_changed": False,
            "cgroup_sample_count": 0,
            "begin_ns": record.get("begin_ns", record.get("monotonic_ns")),
            "end_ns": record.get("end_ns", record.get("monotonic_ns")),
            "sampled_rss_peak_bytes": None, "process_rss_high_water_bytes": None,
            "sampled_process_rss_anon_peak_bytes": None,
            "sampled_process_rss_file_peak_bytes": None,
            "sampled_process_rss_shmem_peak_bytes": None,
            "sampled_cgroup_memory_peak_bytes": None, "cgroup_lifetime_memory_peak_bytes": None,
            "sampled_cgroup_anon_peak_bytes": None, "sampled_cgroup_file_peak_bytes": None,
            "process_status_counts": {}, "cgroup_status_counts": {},
            "collection_errors": {}, "lifecycle": None,
            "_first": None, "_last": None})
        if metadata != item["target"]:
            raise ValueError("resource target registration identity changed")
        if event == "RESOURCE_TARGET_FINISHED":
            if item["lifecycle"] is not None:
                raise ValueError("resource target finished more than once")
            item["lifecycle"] = record["lifecycle"]
            item["end_ns"] = max(item["end_ns"], record["monotonic_ns"])
            continue
        if event != "RESOURCE_SAMPLE":
            continue
        item["sample_count"] += 1
        item["end_ns"] = max(item["end_ns"], record["end_ns"])

        def peak(key, value):
            if type(value) is int and value >= 0:
                previous = item[key]
                item[key] = max(previous, value) if previous is not None else value

        process = record.get("process", {})
        process_status = process.get("status", "NOT_REGISTERED")
        item["process_status_counts"][process_status] = item["process_status_counts"].get(process_status, 0) + 1
        if process.get("status") in ("OBSERVED", "PARTIAL"):
            item["process_sample_count"] += 1
            values = process["values"]
            peak("sampled_rss_peak_bytes", values.get("rss_bytes"))
            peak("process_rss_high_water_bytes", values.get("rss_high_water_bytes"))
            peak("sampled_process_rss_anon_peak_bytes", values.get("rss_anon_bytes"))
            peak("sampled_process_rss_file_peak_bytes", values.get("rss_file_bytes"))
            peak("sampled_process_rss_shmem_peak_bytes", values.get("rss_shmem_bytes"))
            if item["_first"] is None:
                item["_first"] = values
            item["_last"] = values
        elif metadata.get("pid") is not None:
            item["process_unavailable_count"] += 1
            item["process_identity_changed"] |= process.get("status") == "PID_IDENTITY_CHANGED"
        cgroup = record.get("cgroup", {})
        cgroup_status = cgroup.get("status", "NOT_REGISTERED")
        item["cgroup_status_counts"][cgroup_status] = item["cgroup_status_counts"].get(cgroup_status, 0) + 1
        item["cgroup_identity_changed"] |= cgroup_status == "CGROUP_IDENTITY_CHANGED"
        for source, capture in (("process", process), ("cgroup", cgroup)):
            for field, error in capture.get("errors", {}).items():
                item["collection_errors"][source + ":" + field] = str(error)[:1024]
            if capture.get("error"):
                item["collection_errors"][source] = str(capture["error"])[:1024]
        if cgroup.get("values") and cgroup.get("status") in (None, "COMPLETE", "PARTIAL"):
            item["cgroup_sample_count"] += 1
            values = cgroup["values"]
            peak("sampled_cgroup_memory_peak_bytes", values.get("memory.current"))
            peak("cgroup_lifetime_memory_peak_bytes", values.get("memory.peak"))
            peak("sampled_cgroup_anon_peak_bytes", values.get("memory.stat", {}).get("anon"))
            peak("sampled_cgroup_file_peak_bytes", values.get("memory.stat", {}).get("file"))
    for item in targets.values():
        first, last = item.pop("_first"), item.pop("_last")
        for key in ("cpu_user_ns", "cpu_system_ns", "minor_faults", "major_faults",
                    "voluntary_switches", "involuntary_switches"):
            a, b = (first or {}).get(key), (last or {}).get(key)
            item[key] = b - a if type(a) is int and type(b) is int and b >= a and not item["process_identity_changed"] else None
        item["coverage"] = "SAMPLED_NOT_EXHAUSTIVE"
        item["short_processes"] = "MAY_EXIT_BETWEEN_SAMPLES; ROOT_PID_IS_NOT_PROCESS_TREE"
        item["memory_semantics"] = "RSS_HIGH_WATER_IS_PID_LIFETIME; CGROUP_PEAK_IS_CGROUP_LIFETIME; DO_NOT_SUM_PEAKS"
        item["memory_metrics"] = {}
        fields = (
            ("process_rss", "sampled_rss_peak_bytes", "REGISTERED_PID_ONLY_NOT_DESCENDANT_SUM", "rss_bytes"),
            ("process_rss_anon", "sampled_process_rss_anon_peak_bytes", "REGISTERED_PID_ANONYMOUS_RESIDENT_PAGES", "rss_anon_bytes"),
            ("process_rss_file", "sampled_process_rss_file_peak_bytes", "REGISTERED_PID_FILE_BACKED_RESIDENT_MAPPINGS_NOT_CGROUP_PAGE_CACHE", "rss_file_bytes"),
            ("process_rss_shmem", "sampled_process_rss_shmem_peak_bytes", "REGISTERED_PID_SHARED_MEMORY_RESIDENT_PAGES", "rss_shmem_bytes"),
            ("cgroup_memory", "sampled_cgroup_memory_peak_bytes", item["target"].get("cgroup_scope"), "memory.current"),
            ("cgroup_anon", "sampled_cgroup_anon_peak_bytes", item["target"].get("cgroup_scope"), "memory.stat:anon"),
            ("cgroup_file", "sampled_cgroup_file_peak_bytes", item["target"].get("cgroup_scope"), "memory.stat:file"),
        )
        for metric, field, scope, source_field in fields:
            pid_metric = metric.startswith("process_")
            identity_changed = item["process_identity_changed"] if pid_metric else item["cgroup_identity_changed"]
            reason = None
            if not item["target"].get("pid" if pid_metric else "cgroup"):
                reason = "PID_NOT_REGISTERED" if pid_metric else "CGROUP_NOT_REGISTERED_FOR_TARGET"
            elif identity_changed:
                reason = "PID_IDENTITY_CHANGED" if pid_metric else "CGROUP_IDENTITY_CHANGED"
            elif item[field] is None:
                reason = "NO_SUCCESSFUL_SAMPLE_FOR_FIELD"
                if pid_metric and item["target"].get("start_ticks") is None:
                    reason = "PID_IDENTITY_NOT_ESTABLISHED_AT_REGISTRATION"
                elif not pid_metric and item["collection_errors"]:
                    reason = "CGROUP_CONTROLLER_OR_FILE_UNAVAILABLE_SEE_COLLECTION_ERRORS"
            item["memory_metrics"][metric] = {"peak_bytes": item[field], "scope": scope,
                "source_field": source_field,
                "status": "IDENTITY_CHANGED_PARTIAL" if identity_changed else
                    "OBSERVED_SAMPLED_PEAK" if item[field] is not None else "NOT_COLLECTED",
                "reason": reason}
        if item["lifecycle"] is None:
            item["lifecycle"] = {"status": "END_NOT_RECORDED", "confirmed_exit": False,
                "reason": "LEGACY_OR_INCOMPLETE_CAPTURE_NO_FINISH_EVENT"}
    return {"schema_version": 2, "clock": "CLOCK_MONOTONIC", "targets": list(targets.values()),
            "status": "SAMPLED_NOT_EXHAUSTIVE", "sample_limit_reached": bool(limit_events),
            "collection_warnings": limit_events,
            "memory_accounting": "PID_RSS_AND_EXPLICIT_CGROUP_GAUGES; NO_V8_HEAP_ATTRIBUTION"}


class RuntimeResourceSampler:
    def __init__(self, directory, interval_ms=100, max_samples=20000, agent_id=None):
        if not 50 <= interval_ms <= 60000 or not 1 <= max_samples <= 1_000_000:
            raise ValueError("resource sampler requires bounded samples and interval >= 50 ms")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.samples_path = self.directory / "resource-samples.jsonl"
        self.summary_path = self.directory / "resource-summary.json"
        self.interval_ms, self.max_samples, self.agent_id = interval_ms, max_samples, agent_id
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self._stream = self.samples_path.open("x")
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None
        self._targets = {}
        self._sample_count = self._overhead_ns = self._max_capture_ns = self._deadline_misses = 0
        self._limit_reached = self._closed = False

    def _write(self, record):
        self._stream.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
        self._stream.flush()

    def register(self, name, pid=None, role="PROCESS", tool_call_id=None, cgroup=None,
                 cgroup_scope="EXPLICIT_TARGET_CGROUP"):
        with self._lock:
            if self._closed or name in self._targets or len(self._targets) >= 1000:
                raise ValueError("resource target duplicate, closed, or target limit reached")
            if pid is None and cgroup is None:
                raise ValueError("resource target needs a PID or explicit cgroup")
            if pid is not None and (type(pid) is not int or pid < 1):
                raise ValueError("resource target PID must be a positive integer")
            cgroup_path = Path(cgroup).resolve(strict=True) if cgroup is not None else None
            cgroup_identity = ({"path": str(cgroup_path), "inode": cgroup_path.stat().st_ino,
                                "device": cgroup_path.stat().st_dev} if cgroup_path is not None else None)
            process = capture_process(pid) if pid is not None else None
            target = {"name": name, "pid": pid, "role": role, "tool_call_id": tool_call_id,
                      "agent_id": self.agent_id, "start_ticks": (process or {}).get("start_ticks"),
                      "cgroup": str(cgroup_path) if cgroup_path is not None else None,
                      "cgroup_identity": cgroup_identity,
                      "cgroup_scope": cgroup_scope if cgroup is not None else None}
            pidfd, pidfd_error = None, None
            if pid is not None and target["start_ticks"] is not None:
                try:
                    pidfd = os.pidfd_open(pid, 0)
                    # Opening a pidfd raced with PID reuse only if identity changed.
                    identity = capture_process(pid, target["start_ticks"])
                    if identity.get("status") not in ("OBSERVED", "PARTIAL"):
                        os.close(pidfd)
                        pidfd = None
                        pidfd_error = "PIDFD_IDENTITY_NOT_CONFIRMED_DURING_REGISTRATION"
                except (AttributeError, OSError) as error:
                    pidfd_error = type(error).__name__
            self._targets[name] = {"metadata": target, "active": True, "pidfd": pidfd,
                                   "pidfd_error": pidfd_error, "last_sample": None}
            self._write({"event": "RESOURCE_TARGET_REGISTERED", "boot_id": self.boot_id,
                         "clock": "CLOCK_MONOTONIC", "monotonic_ns": time.monotonic_ns(),
                         "pidfd_status": "OPEN" if pidfd is not None else "UNAVAILABLE",
                         "pidfd_error": pidfd_error, "target": target})
            self._sample(name)
            return target

    def _sample(self, name):
        if self._sample_count >= self.max_samples:
            if not self._limit_reached:
                self._write({"event": "RESOURCE_SAMPLING_LIMIT_REACHED", "clock": "CLOCK_MONOTONIC",
                    "boot_id": self.boot_id, "monotonic_ns": time.monotonic_ns(),
                    "max_samples": self.max_samples, "sample_count": self._sample_count,
                    "consequence": "FURTHER_RESOURCE_SAMPLES_NOT_CAPTURED; LIFECYCLE_EVENTS_RETAINED"})
            self._limit_reached = True
            return
        target = self._targets[name]["metadata"]
        begin = time.monotonic_ns()
        record = {"schema_version": 1, "event": "RESOURCE_SAMPLE", "clock": "CLOCK_MONOTONIC",
                  "boot_id": self.boot_id, "sequence": self._sample_count,
                  "begin_ns": begin, "target": target}
        if target["pid"] is not None:
            if target["start_ticks"] is None:
                record["process"] = {"status": "IDENTITY_NOT_ESTABLISHED", "values": {}}
            else:
                record["process"] = capture_process(target["pid"], target["start_ticks"])
        if target["cgroup"] is not None:
            try:
                record["cgroup"] = capture_cgroup(target["cgroup"])
                if record["cgroup"]["identity"] != target["cgroup_identity"]:
                    record["cgroup"] = {"status": "CGROUP_IDENTITY_CHANGED", "values": {},
                                        "observed_identity": record["cgroup"]["identity"]}
            except (OSError, ValueError) as error:
                record["cgroup"] = {"status": "UNAVAILABLE", "values": {}, "error": type(error).__name__}
        record["end_ns"] = time.monotonic_ns()
        self._write(record)
        self._targets[name]["last_sample"] = record
        self._sample_count += 1
        duration = time.monotonic_ns() - begin
        self._overhead_ns += duration
        self._max_capture_ns = max(self._max_capture_ns, duration)

    def finish(self, name, *, reason="OBSERVATION_ENDED", confirmed_exit=None, exit_source=None):
        """End one target's observation, preserving why its curve ended.

        ``confirmed_exit`` is a returncode obtained by the caller's actual wait
        operation (zero is valid).  Ordinary /proc read failure never proves
        exit.  A readable identity-bound pidfd can independently confirm exit,
        but does not supply the exit status of a non-child process.
        """
        with self._lock:
            if not self._closed and self._targets[name]["active"]:
                if confirmed_exit is not None and (type(confirmed_exit) is not int or not exit_source):
                    raise ValueError("confirmed process exit needs an integer wait returncode and source")
                if not isinstance(reason, str) or not reason:
                    raise ValueError("resource observation end needs a nonempty reason")
                state = self._targets[name]
                target = state["metadata"]
                if confirmed_exit is not None and target["pid"] is None:
                    raise ValueError("cgroup-only target cannot carry a PID exit returncode")
                if confirmed_exit is not None and target["start_ticks"] is None:
                    raise ValueError("wait exit claim lacks a registered PID lifetime identity")
                pidfd = state["pidfd"]
                readable = False
                if pidfd is not None:
                    poller = select.poll()
                    poller.register(pidfd, select.POLLIN)
                    readiness = poller.poll(0)
                    if any(flags & (select.POLLERR | select.POLLNVAL) for _, flags in readiness):
                        raise RuntimeError("identity-bound pidfd polling failed; exit is unconfirmed")
                    readable = any(flags & select.POLLIN for _, flags in readiness)
                    if confirmed_exit is not None and not readable:
                        raise ValueError("wait exit claim conflicts with still-live identity-bound pidfd")
                self._sample(name)
                sample = state["last_sample"] or {}
                process = sample.get("process", {})
                confirmed = confirmed_exit is not None or readable
                current_process = capture_process(target["pid"], target["start_ticks"]) \
                    if not confirmed and pidfd is None and target["pid"] is not None else process
                status = "EXIT_CONFIRMED" if confirmed else "CGROUP_OBSERVATION_ENDED" if target["pid"] is None else \
                    "PID_STILL_PRESENT_AT_OBSERVATION_END" if pidfd is not None or current_process.get("status") in ("OBSERVED", "PARTIAL") else \
                    "EXIT_UNCONFIRMED_PROCESS_UNAVAILABLE"
                timestamp = time.monotonic_ns()
                lifecycle = {"status": status, "confirmed_exit": confirmed,
                    "reason": reason, "end_ns": timestamp, "exit_returncode": confirmed_exit,
                    "exit_source": exit_source if confirmed_exit is not None else
                        "IDENTITY_BOUND_PIDFD_READABLE" if readable else None,
                    "pidfd_status": "READABLE_EXIT_CONFIRMED" if readable else
                        "OPEN_NOT_READABLE" if pidfd is not None else "UNAVAILABLE",
                    "pidfd_error": state["pidfd_error"],
                    "last_process_capture_status": process.get("status"),
                    "last_process_state": process.get("values", {}).get("state"),
                    "last_sample_sequence": sample.get("sequence"),
                    "rss_after_exit_semantics": "PID_ADDRESS_SPACE_NO_LONGER_EXISTS; NOT_A_SAMPLED_RSS_ZERO" if confirmed else
                        "NO_ZERO_INFERRED_FROM_OBSERVATION_END",
                    "cgroup_after_exit_semantics": "CGROUP_MEMORY_MAY_REMAIN_CHARGED_INCLUDING_PAGE_CACHE; NO_ZERO_INFERRED"}
                self._write({"schema_version": 2, "event": "RESOURCE_TARGET_FINISHED",
                    "clock": "CLOCK_MONOTONIC", "boot_id": self.boot_id,
                    "monotonic_ns": timestamp, "target": target, "lifecycle": lifecycle})
                state["active"] = False
                if pidfd is not None:
                    os.close(pidfd)
                    state["pidfd"] = None

    def _loop(self):
        interval = self.interval_ms / 1000
        deadline = time.monotonic() + interval
        while not self._stop.wait(max(0, deadline - time.monotonic())):
            with self._lock:
                for name, target in self._targets.items():
                    if target["active"]:
                        self._sample(name)
            deadline += interval
            if time.monotonic() > deadline:
                self._deadline_misses += 1
                deadline = time.monotonic() + interval

    def start(self):
        if self._thread is not None or self._closed:
            raise ValueError("resource sampler already started or closed")
        self._thread = threading.Thread(target=self._loop, name="observer-resource-sampler", daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(5, self.interval_ms / 1000 + 1))
            if self._thread.is_alive():
                raise RuntimeError("resource sampling thread did not stop")
        with self._lock:
            if self._closed:
                return self._summary
            for name, target in self._targets.items():
                if target["active"]:
                    self.finish(name, reason="SAMPLER_STOPPED")
            # Keep memory bounded independently of run length: aggregate the
            # durable JSONL stream without retaining all samples in Python.
            with self.samples_path.open() as source:
                summary = summarize_samples(json.loads(line) for line in source if line.strip())
            summary.update(boot_id=self.boot_id, agent_id=self.agent_id,
                interval_ms=self.interval_ms, sample_count=self._sample_count,
                sample_limit_reached=self._limit_reached, deadline_misses=self._deadline_misses,
                sampling_read_write_wall_ns=self._overhead_ns, max_capture_wall_ns=self._max_capture_ns,
                overhead_semantics="SAMPLER_WORK_DURATION_NOT_PAIRED_WORKLOAD_SLOWDOWN",
                samples_artifact=self.samples_path.name)
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._stream.close()
            with self.summary_path.open("x") as stream:
                json.dump(summary, stream, indent=2, sort_keys=True)
                stream.write("\n")
            self._summary = summary
            self._closed = True
            return summary
