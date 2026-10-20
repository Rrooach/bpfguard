#!/usr/bin/env python3
"""Independently replay the copied pilot evidence with its pinned verifier."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def verify(base):
    verifier = base / "terminal-20261014/pinned-artifacts/deployment-observe-verify"
    artifacts = json.loads((base / "artifacts.json").read_text())
    if hashlib.sha256(verifier.read_bytes()).hexdigest() != artifacts["verifier_sha256"]:
        raise ValueError("Archived verifier digest does not match the tested artifact config")
    inputs = []
    for mode in ("agentbench-audit-control-20261014", "agentbench-audit-model-20261014"):
        for folder in sorted((base / "agentbench-20261014" / mode).glob("*/audit")):
            inputs.append((folder / "observer", folder / "verification-expectation.json"))
    for mode in ("terminal-prebuilt-control-20261014", "terminal-prebuilt-bun-control-20261014",
                 "terminal-model-20261014", "terminal-model-retry-20261014"):
        for folder in sorted((base / "terminal-20261014" / mode / "evidence").glob("*")):
            inputs.append((folder / "observer", folder / "control/verification-expectation.json"))
    if len(inputs) != 11:
        raise ValueError("Expected all 11 recorded audit artifacts; refusing silently missing runs")
    checks = []
    for observation, expectation in inputs:
        result = subprocess.run([str(verifier), "--artifacts", str(observation), "--expectation", str(expectation)],
                                capture_output=True, text=True, timeout=300)
        parsed = json.loads(result.stdout) if result.stdout else {}
        checks.append({"artifacts": str(observation), "return_code": result.returncode,
                       "verified": parsed.get("verified"), "result": parsed, "error": result.stderr.strip()})
    return {"schema_version": 1, "count": len(checks), "verifier_sha256": artifacts["verifier_sha256"],
            "all_pass": all(row["return_code"] == 0 and row["verified"] for row in checks), "checks": checks}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(".output/agent-benchmarks"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.root)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps({key: value for key, value in result.items() if key != "checks"}))
    raise SystemExit(0 if result["all_pass"] else 1)
