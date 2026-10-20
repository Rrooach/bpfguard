#!/usr/bin/env python3
"""Offline integrity and phase summary for one Terminal-Bench campaign."""
import argparse
import json
from pathlib import Path


def check(root):
    campaign = json.loads((root / "campaign-summary.json").read_text())
    rows = []
    for task in campaign["tasks"]:
        name, interval = task["task"], task["interval"]
        folder = root / "profiles" / name
        meta = json.loads((folder / "load-meta.json").read_text())
        stats = json.loads((folder / "load-sampler-stats.json").read_text())
        first, last, count, psi_complete, io_rows = None, None, 0, True, False
        with (folder / "load-samples.jsonl").open() as stream:
            for index, line in enumerate(stream):
                if index >= 100000 or len(line) > 1024 * 1024:
                    raise ValueError("Sample bound exceeded")
                row = json.loads(line)
                if row["seq"] != index or (last and row["monotonic_ns"] <= last["monotonic_ns"]):
                    raise ValueError("Sample sequence or clock is not monotonic")
                if first is None:
                    first = row
                last, count = row, index + 1
                psi_complete = psi_complete and all(domain in row["cgroups"][0].get("psi", {}) for domain in ("cpu", "memory", "io"))
                io_rows = io_rows or bool(row["cgroups"][0].get("io_stat_by_device"))
        groups = meta["cgroups"]
        binding = (len(groups) == 1 and meta["boot_id"] == interval["boot_id"]
                   and meta["label"] == interval["run_id"]
                   and groups[0]["path"] == interval["cgroup_path"]
                   and groups[0]["inode"] == interval["cgroup_inode"]
                   and groups[0]["device"] == interval["cgroup_device"])
        coverage = (first and first["monotonic_ns"] <= interval["agent_start_ns"]
                    and last["monotonic_ns"] > interval["agent_end_ns"]
                    and count == stats["samples"])
        completed = task["observer_completed"]
        verified = len(completed) == 1 and completed[0]["observer"]["offline_verification"].get("verified") is True
        trajectory = root / "harbor-trials"
        candidates = list(trajectory.glob("*/agent/tool-intervals.json"))
        candidates = [path for path in candidates if name[:24] in path.parent.parent.name]
        actions = json.loads(candidates[0].read_text()) if len(candidates) == 1 else []
        result = {"task": name, "agent": campaign["agent"], "reward": (task["harbor_rewards"] or {}).get("reward"),
            "harbor_exception": (task["harbor_exception"] or {}).get("exception_message"),
            "observer_verified": verified, "sampler_binding": binding, "sample_boundary_coverage": bool(coverage),
            "psi_available_every_sample": psi_complete, "sample_count": count,
            "sampler_read_errors": stats["read_errors"], "sampler_missed_ticks": stats["missed_ticks"],
            "agent_wall_seconds": (interval["agent_end_ns"] - interval["agent_start_ns"]) / 1e9,
            "model_requests": sum(row["kind"] == "model_request" for row in actions),
            "model_request_seconds": sum((row["end_ns"] - row["start_ns"]) / 1e9 for row in actions if row["kind"] == "model_request"),
            "tool_seconds": sum((row["end_ns"] - row["start_ns"]) / 1e9 for row in actions if row["kind"] == "tool"),
            "rejected_tools": sum(row["kind"] == "tool_rejected" for row in actions),
            "bpf_endpoint_causality": "NOT_ESTABLISHED_OTHER_ACTORS_MAY_BE_PRESENT",
            "io_accounting": "AVAILABLE" if io_rows else "NO_DEVICE_ROWS_NO_ZERO_IO_CLAIM"}
        result["measurement_integrity_passed"] = bool(binding and coverage and psi_complete and verified and not task["sampler_error"])
        rows.append(result)
    return {"schema_version": 1, "benchmark": "Terminal-Bench", "campaign": str(root), "tasks": rows,
            "scope": "SELECTED_TASK_INTEGRATION_NO_FULL_SUITE_OR_A_B_OVERHEAD_CLAIM"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("campaign", type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.campaign), indent=2))
