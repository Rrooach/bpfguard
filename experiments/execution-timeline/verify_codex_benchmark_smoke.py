#!/usr/bin/env python3
"""Offline replay for one Codex benchmark smoke timeline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from codex_tool_adapter import verify_codex_tool_sources
from common import digest, write_new
from replay import verify_run
from tool_events import read_events, replay_tool_events


def require(value, message):
    if not value:
        raise ValueError(message)


def rows(path):
    raw = path.read_bytes()
    require(not raw or raw.endswith(b"\n"), "truncated JSONL: " + path.name)
    return [json.loads(line) for line in raw.splitlines()]


def verify(root, prefix, collector=None):
    root = Path(root).resolve(strict=True)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    artifacts = manifest.get("artifacts", {})
    for name in (f"{prefix}/rpc.jsonl", f"{prefix}/tool-events.jsonl",
                 f"{prefix}/function-bindings.jsonl", f"{prefix}/steps.json"):
        require(name in artifacts, "application evidence not bound by manifest: " + name)
        require(digest(root / name) == artifacts[name], "application artifact digest differs: " + name)
    report = verify_run(root, collector=collector,expected_manifest_sha256=digest(manifest_path)["sha256"])
    events = read_events(root / prefix / "tool-events.jsonl")
    calls = replay_tool_events(events, require_delivered=True)
    source = verify_codex_tool_sources(rows(root / prefix / "rpc.jsonl"), events)
    application = json.loads((root / prefix / "steps.json").read_bytes())
    require(application.get("tool_calls") == calls, "replayed calls differ from Codex result")
    bindings = rows(root / prefix / "function-bindings.jsonl")
    require(application.get("function_bindings") == bindings, "function binding ledger differs")
    by_id = {call["call_id"]: call for call in calls}
    native = {tool["tool_call_id"]: tool for tool in manifest.get("tools", [])}
    require(len(native) == len(manifest.get("tools", [])), "duplicate native tool identity")
    for binding in bindings:
        call = by_id.get(binding.get("call_id"))
        tool = native.get(binding.get("tool_call_id"))
        require(call is not None and tool is not None, "application binding lacks call/native tool")
        require(call.get("execution_binding") == "TOOL_GATE_EXECUTION_BOUND"
            and call.get("execution_tool_call_id") == binding.get("tool_call_id"),
            "Codex call is not explicitly execution-bound")
        require(call.get("root") == binding.get("root")
            and call.get("cgroup_id") == binding.get("cgroup_id")
            and call.get("execution_begin_ns") == binding.get("begin_ns")
            and call.get("execution_end_ns") == binding.get("end_ns"),
            "tool lifecycle binding differs")
        require(call["root"] == tool.get("root") and call["cgroup_id"] == tool.get("cgroup_id"),
            "application/native root identity differs")
    return {"schema_version": 1, "status": "REPLAY_PASSED",
        "manifest": digest(manifest_path), "report": report,
        "application_tool_source_verification": source,
        "application_tool_calls": len(calls), "process_bound_calls": len(bindings),
        "native_tools": len(native), "capture_health": report.get("health"),
        "timeline_status": report.get("critical_path", {}).get("status")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--application-prefix", choices=("app", "application"), required=True)
    parser.add_argument("--collector",type=Path,help="host-local copied collector; its digest must match the original manifest")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report-output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = verify(args.run_dir, args.application_prefix,args.collector)
    report = result.pop("report")
    write_new(args.report_output, report)
    result["report"] = digest(args.report_output)
    write_new(args.output, result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
