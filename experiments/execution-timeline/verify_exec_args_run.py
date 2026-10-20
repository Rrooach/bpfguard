#!/usr/bin/env python3
"""Recompute a native exec sidecar/tool scope join from both binary WALs.

This does not rerun a workload, infer tool ownership from nearby timestamps, or
change a capture. The report hash is recomputed in a streaming encoder to avoid
making another full copy of large cached reports in memory.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from codex_tool_adapter import verify_codex_tool_sources
from common import digest, write_new
from exec_args_sidecar import (codex_snapshot_contract, correlate_commands,
                               correlate_core_scopes, verify_capture)
from replay import verify_run
from tool_events import replay_tool_events


def rows(path):
    with Path(path).open() as source:
        return [json.loads(line) for line in source if line.strip()]


def canonical_digest(value):
    sha, size = hashlib.sha256(), 0
    encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    for part in encoder.iterencode(value):
        data = part.encode("utf-8"); sha.update(data); size += len(data)
    sha.update(b"\n")
    return {"sha256": sha.hexdigest(), "size_bytes": size + 1}


def verify_native_exec_scopes(root, *, snapshot_projection=False):
    root = Path(root).resolve(strict=True)
    manifest_identity = digest(root / "manifest.json")
    manifest = json.loads((root / "manifest.json").read_text())
    report = verify_run(root, collector=root / "pinned-artifacts/collect",
                        expected_manifest_sha256=manifest_identity["sha256"])
    recomputed = canonical_digest(report)
    if recomputed != digest(root / "report.json"):
        raise ValueError("cached report bytes differ from independent pinned-collector binary WAL reconstruction")
    application = json.loads((root / "app/steps.json").read_text())
    rpc, ledger = rows(root / "app/rpc.jsonl"), rows(root / "app/tool-events.jsonl")
    source_check = verify_codex_tool_sources(rpc, ledger)
    if replay_tool_events(ledger) != application["tool_calls"]:
        raise ValueError("application tools differ from independently replayed lifecycle ledger")
    sidecar = verify_capture(root / "exec-args", expected_artifacts={name:
        manifest["artifacts"]["exec-args/" + name] for name in ("events.bin", "health.bin", "ready.json")})
    receipt = {"status": "REPLAY_PASSED", "method": "HOST_PINNED_COLLECTOR_BINARY_WAL_RECONSTRUCTION",
        "manifest_identity": manifest_identity, "collector_identity": digest(root / "pinned-artifacts/collect"),
        "report_identity": recomputed, "cached_report_hash_matches_recomputed": True,
        "application_sources": source_check, "scope": "SELECTED_CORE_HOOKS_AND_MANIFEST_BINDING_NOT_FULL_SYSTEM_COMPLETENESS"}
    strict = correlate_commands(application["tool_calls"], sidecar)
    contract = (codex_snapshot_contract(application, rpc, json.loads((root / "app/config.public.json").read_text()))
                if snapshot_projection else None)
    adapted = correlate_commands(application["tool_calls"], sidecar, runtime_contract=contract)
    scopes = correlate_core_scopes(adapted, sidecar, report, receipt)
    scopes.update({"run_directory": str(root), "run_id": manifest["run_id"],
        "provider_provenance": manifest.get("provider_provenance"), "core_replay": receipt,
        "sidecar_artifacts": sidecar["artifacts"], "sidecar_history_status": sidecar["history_status"],
        "sidecar_argv_evidence_status": sidecar["argv_evidence_status"],
        "sidecar_successful_exec_count": len(sidecar["executions"]),
        "strict_unchanged_argv_status_counts": dict(Counter(row["status"] for row in strict["calls"])),
        "projection_status_counts": dict(Counter(row["status"] for row in adapted["calls"])),
        "core_scope_status_counts": dict(Counter(row["status"] for row in scopes["calls"])),
        "runtime_projection_contract": contract,
        "limitations": ["A versioned argv projection is not exact unchanged argv or strong causal proof.",
            "The sidecar reads bounded mutable user memory at syscall entry, not final immutable kernel argv.",
            "Unmatched fileChange or shared runtime events remain unassigned.",
            "This receipt does not infer benchmark correctness or replay new model reasoning."]})
    return scopes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--codex-snapshot-projection", action="store_true",
                        help="Explicitly allow identified Codex 0.154.0 unifiedExecStartup -lc to -c projection")
    args = parser.parse_args()
    scopes = verify_native_exec_scopes(args.run, snapshot_projection=args.codex_snapshot_projection)
    write_new(args.output, scopes)
    print(json.dumps({key: scopes[key] for key in ("run_id", "sidecar_successful_exec_count",
        "strict_unchanged_argv_status_counts", "projection_status_counts", "core_scope_status_counts",
        "correlated_syscall_references")}, ensure_ascii=False))


if __name__ == "__main__": main()
