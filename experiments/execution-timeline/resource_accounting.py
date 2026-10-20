#!/usr/bin/env python3
"""Bounded cgroup-v2 accounting for one stopped-launch tool domain.

The caller owns a freshly created cgroup.  These counters are read at the
release boundary and again only after the group is empty, so memory.peak is a
tool-lifetime high-water mark instead of a container-lifetime value.  This is
boundary accounting, not a sampled memory trajectory.
"""
from __future__ import annotations

from pathlib import Path
import time


FILES = (
    "cpu.stat", "memory.current", "memory.peak", "memory.stat",
    "memory.events", "io.stat", "pids.current", "pids.events",
)


def _key_values(raw):
    result = {}
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) == 2:
            try:
                result[fields[0]] = int(fields[1])
            except ValueError:
                continue
    return result


def _io_stat(raw):
    totals = {}
    devices = {}
    for line in raw.splitlines():
        fields = line.split()
        if not fields:
            continue
        values = {}
        for field in fields[1:]:
            if "=" not in field:
                continue
            name, value = field.split("=", 1)
            try:
                values[name] = int(value)
                totals[name] = totals.get(name, 0) + values[name]
            except ValueError:
                continue
        devices[fields[0]] = values
    return {"aggregate": totals, "by_device": devices}


def capture(cgroup):
    """Capture one identity-bound resource boundary without hiding errors."""
    path = Path(cgroup).resolve(strict=True)
    if Path("/sys/fs/cgroup").resolve(strict=True) not in path.parents:
        raise ValueError("resource accounting requires an explicit cgroup-v2 child")
    begin = time.monotonic_ns()
    raw, errors = {}, {}
    identity = {"path": str(path), "inode": path.stat().st_ino,
                "device": path.stat().st_dev}
    for name in FILES:
        try:
            raw[name] = (path / name).read_text()
        except OSError as error:
            errors[name] = type(error).__name__ + ": " + str(error)
    parsed = {}
    for name in ("cpu.stat", "memory.stat", "memory.events", "pids.events"):
        if name in raw:
            parsed[name] = _key_values(raw[name])
    for name in ("memory.current", "memory.peak", "pids.current"):
        if name in raw:
            try:
                parsed[name] = int(raw[name].strip())
            except ValueError:
                errors[name] = "INVALID_INTEGER"
    if "io.stat" in raw:
        parsed["io.stat"] = _io_stat(raw["io.stat"])
    return {"schema_version": 1, "clock": "CLOCK_MONOTONIC",
            "begin_ns": begin, "end_ns": time.monotonic_ns(),
            "identity": identity, "values": parsed, "errors": errors,
            "status": "COMPLETE" if not errors else "PARTIAL"}


def tool_accounting(before, after):
    """Validate two boundaries and expose only counters with sound semantics."""
    if before.get("identity") != after.get("identity"):
        raise ValueError("tool cgroup identity changed across resource boundaries")
    if before.get("end_ns", 0) > after.get("begin_ns", -1):
        raise ValueError("tool resource boundaries are unordered")
    a, b = before.get("values", {}), after.get("values", {})
    cpu_a, cpu_b = a.get("cpu.stat", {}), b.get("cpu.stat", {})
    io_a = a.get("io.stat", {}).get("aggregate", {})
    io_b = b.get("io.stat", {}).get("aggregate", {})

    def delta(left, right, name):
        x, y = left.get(name), right.get(name)
        return y - x if type(x) is int and type(y) is int and y >= x else None

    total_faults = delta(a.get("memory.stat", {}), b.get("memory.stat", {}), "pgfault")
    major_faults = delta(a.get("memory.stat", {}), b.get("memory.stat", {}), "pgmajfault")
    minor_faults = (total_faults - major_faults if total_faults is not None
                    and major_faults is not None and total_faults >= major_faults else None)
    return {"schema_version": 1,
            "status": "COMPLETE" if before.get("status") == after.get("status") == "COMPLETE" else "PARTIAL",
            "scope": "FRESH_EPHEMERAL_TOOL_CGROUP_BOUNDARIES; MEMORY_PEAK_IS_LIFETIME_HIGH_WATER; NO_MEMORY_TIME_SERIES",
            "identity": before["identity"], "before": before, "after": after,
            "cpu_usage_usec": delta(cpu_a, cpu_b, "usage_usec"),
            "cpu_user_usec": delta(cpu_a, cpu_b, "user_usec"),
            "cpu_system_usec": delta(cpu_a, cpu_b, "system_usec"),
            "memory_peak_bytes": b.get("memory.peak"),
            "memory_current_end_bytes": b.get("memory.current"),
            "memory_anon_end_bytes": b.get("memory.stat", {}).get("anon"),
            "memory_file_end_bytes": b.get("memory.stat", {}).get("file"),
            "total_faults": total_faults, "minor_faults": minor_faults,
            "major_faults": major_faults,
            "fault_semantics": "CGROUP_PGFAULT_INCLUDES_MAJOR; MINOR_EQUALS_PGFAULT_MINUS_PGMAJFAULT",
            "io_read_bytes": delta(io_a, io_b, "rbytes"),
            "io_write_bytes": delta(io_a, io_b, "wbytes"),
            "oom_events": delta(a.get("memory.events", {}), b.get("memory.events", {}), "oom"),
            "oom_kill_events": delta(a.get("memory.events", {}), b.get("memory.events", {}), "oom_kill")}
