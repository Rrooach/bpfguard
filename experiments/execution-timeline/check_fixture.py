#!/usr/bin/env python3
"""Assert real trace properties, independently of whether the workload passed."""
import argparse
import json
from pathlib import Path

from common import write_new
from replay import verify_run


def check(report, expected_file, join=False):
    threads = report["threads"]
    assert len(threads) >= (2 if join else 6), "controlled process/thread identities missing"
    assert all(t["tool_call_id"] == "tool-1" for t in threads), "whole controlled tree must be attributed"
    if not join:
        assert any(t["comm"] == "short-lived" for t in threads), "short thread must not disappear between samples"
    states = [s for t in threads for s in t["segments"]]
    if not join:
        assert sum(s["end_ns"] - s["begin_ns"] for s in states if s["state"] == "RUNNABLE") > 10_000_000, "CPU competition wait absent"
    file_calls = [c for t in threads for c in t["calls"] if any(f.get("path") == expected_file for f in c["files"])]
    assert file_calls, "kernel-resolved fixture file path missing"
    # Sum actual VFS completion bytes, never read() requested size.
    read_bytes = sum(f["read"]["returned_bytes"] for c in file_calls for f in c["files"]
                     if f.get("path") == expected_file and (f["read"].get("returned_bytes") or 0) > 0)
    assert read_bytes == 64 * 1024 * 1024, f"fixture file bytes differ: {read_bytes}"
    file_waits = [s for s in states if s["state"] == "SLEEP"
                  and any(f.get("path") == expected_file for f in s.get("files", []))]
    assert file_waits, "no regular-file blocking interval was observed: cannot claim cold I/O validation"
    assert any(s.get("stack") for s in file_waits), "file wait has no captured stack"
    pipe_waits = [s for s in states if s["state"] == "SLEEP" and "pipe_read" in " ".join(s.get("stack", []))]
    if not join:
        assert pipe_waits, "controlled blocking pipe read not explained by captured stack"
    paths = report["critical_path"]["tools"]
    assert paths and paths[0]["dependency_edges"], "wait4 completion dependency did not reconstruct"
    if join:
        assert any("CLEAR_CHILD_TID" in e["basis"] for e in paths[0]["dependency_edges"]), "thread-exit join dependency was not established"
        assert any(any(f.get("path") == expected_file for f in s.get("files", [])) and s["state"] == "SLEEP"
                   for s in paths[0]["segments"]), "file waiting was not on reconstructed completion dependency path"
    assert paths[0]["unknown_ns"] == 0, "controlled wall-clock path has unexplained gaps"
    assert report["critical_path"]["status"] == "RECONSTRUCTED_WITHIN_SELECTED_MODEL", "capture gap remains"
    return {"status": "PASS", "threads": len(threads), "file_bytes": read_bytes,
            "file_blocking_intervals": len(file_waits), "pipe_blocking_intervals": len(pipe_waits),
            "completion_dependency_edges": len(paths[0]["dependency_edges"]),
            "wall_ns": paths[0]["wall_ns"], "wall_state_ns": paths[0]["state_totals_ns"],
            "scope": "CONTROLLED_COOPERATIVE_GUEST_FIXTURE_NOT_GENERAL_COVERAGE_PROOF"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--collector", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--join", action="store_true")
    args = parser.parse_args()
    report = verify_run(args.run_dir, args.collector)
    result = check(report, args.file, args.join)
    if args.output:
        write_new(args.output, result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
