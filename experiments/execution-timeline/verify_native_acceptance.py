#!/usr/bin/env python3
"""Independent same-run checks for normal Codex, model, tools and kernel evidence.

PASS means the declared records bind and replay, not that every Linux effect
or internal V8 phase is supported. Missing per-tool Linux links remain missing.
Provider receipts are private input; the output contains only hashes/counts.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys

from common import canonical, digest, write_new
from codex_tool_adapter import verify_codex_tool_sources
from native_raw_tools import replay_native_raw_tools
from replay import verify_run
from tool_events import replay_tool_events


def rows(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def reconcile_projection(application, projection):
    """Do not mistake RPC receipt vs later handler receipt for content changes."""
    reconciled = []
    for field in ("native_model_tool_calls", "native_model_responses"):
        original, replayed = application.get(field), projection[field]
        if not isinstance(original, list) or len(original) != len(replayed):
            raise ValueError("native raw RPC projection count differs: " + field)
        for left, right in zip(original, replayed):
            left, right = deepcopy(left), deepcopy(right)
            if field.endswith("calls"):
                for value in (left, right):
                    start, end = value.get("request_received_ns"), value.get("output_received_ns")
                    duration = value.get("request_to_output_ms")
                    if end is not None and (type(start) is not int or type(end) is not int or end < start
                            or not isinstance(duration, (int, float))
                            or abs(duration - (end - start) / 1e6) > 1e-9):
                        raise ValueError("native Code Mode wall duration does not recompute from its own boundaries")
            clock_fields = ("request_received_ns", "output_received_ns") if field.endswith("calls") else ("receipt_ns",)
            differences = {}
            for key in clock_fields:
                handler, raw = left.pop(key, None), right.pop(key, None)
                if handler is None and raw is None:
                    continue
                if type(handler) is not int or type(raw) is not int or handler < raw:
                    raise ValueError("native handler timestamp predates bound raw RPC receipt")
                differences[key] = handler - raw
            if field.endswith("calls"):
                for key in ("source_request", "source_output"):
                    if left.get(key) is None and right.get(key) is None:
                        continue
                    handler = left[key].pop("receipt_ns")
                    raw = right[key].pop("receipt_ns")
                    if type(handler) is not int or type(raw) is not int or handler < raw:
                        raise ValueError("native source timestamp predates raw RPC")
                for value in (left, right):
                    value.pop("request_to_output_ms", None)
                # The originals are retained in immutable app/steps.json.
            if left != right:
                raise ValueError("native RPC content/identity projection differs: " + field)
            reconciled.append({"field": field, "id": left.get("call_id", left.get("response_id")),
                               "handler_after_raw_ns": differences})
    return reconciled


def completed_sse(body):
    found = []
    for block in body.replace(b"\r\n", b"\n").split(b"\n\n"):
        data = b"\n".join(line[5:].lstrip() for line in block.splitlines() if line.startswith(b"data:"))
        if not data or data == b"[DONE]":
            continue
        item = json.loads(data)
        if item.get("type") == "response.completed":
            found.append(item["response"])
    if len(found) != 1:
        raise ValueError("one completed response required per saved provider delivery")
    return found[0]


def verify_provider(directory, label, projection, timing_rows, boot_id):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent-benchmarks"))
    from native_provider_wire import prepare_request, restore_response
    root = Path(directory).resolve(strict=True)
    output = []
    responses = projection["native_model_responses"]
    delivered_paths = list(root.glob(label + "-step-*-delivered.sse"))
    if len(delivered_paths) != len(responses):
        raise ValueError("provider deliveries and native completions differ")
    for index, response in enumerate(responses):
        prefix = root / (label + "-step-" + str(index))
        def file(suffix):
            return Path(str(prefix) + suffix)
        native = json.loads(file("-native-request.json").read_text())
        provider = json.loads(file("-request.json").read_text())
        receipt = json.loads(file("-wire-adapter.json").read_text())
        prepared, recomputed = prepare_request(native)
        if prepared != provider or receipt != recomputed:
            raise ValueError("provider request/wire mapping does not independently recompute")
        upstream = file("-upstream.sse").read_bytes()
        delivered = file("-delivered.sse").read_bytes()
        if restore_response(upstream, receipt) != delivered:
            raise ValueError("delivered native SSE differs from independent protocol translation")
        before, after = completed_sse(upstream), completed_sse(delivered)
        if before.get("id") != after.get("id") or before.get("usage") != after.get("usage"):
            raise ValueError("wire adaptation changed response identity or token accounting")
        if after.get("id") != response["response_id"]:
            raise ValueError("provider and native RPC model response IDs differ")
        usage = after.get("usage", {})
        native_usage = response.get("usage") or {}
        for key, native_key in (("input_tokens", "inputTokens"), ("output_tokens", "outputTokens"), ("total_tokens", "totalTokens")):
            if usage.get(key) != native_usage.get(native_key):
                raise ValueError("provider and native RPC usage differ")
        matching = [row for row in timing_rows if row.get("provider_response_id") == after["id"]]
        request_ids = {row.get("request_id") for row in matching}
        if not matching or len(request_ids) != 1 or any(row.get("boot_id") != boot_id for row in matching):
            raise ValueError("provider response lacks unique same-boot transport request link")
        output.append({"response_id": after["id"], "transport_request_id": next(iter(request_ids)),
                       "usage": usage, "wire_adapter": receipt["version"],
                       "upstream_sse": digest(file("-upstream.sse")), "delivered_sse": digest(file("-delivered.sse"))})
    return output


def verify_native_run(root, provider_directory, label):
    root = Path(root).resolve(strict=True)
    manifest_digest = digest(root / "manifest.json")
    manifest = json.loads((root / "manifest.json").read_text())
    report = verify_run(root, collector=root / "pinned-artifacts/collect",
                        expected_manifest_sha256=manifest_digest["sha256"])
    if canonical(report) != canonical(json.loads((root / "report.json").read_text())):
        raise ValueError("kernel report differs from raw binary WAL replay")
    application = json.loads((root / "app/steps.json").read_text())
    rpc = rows(root / "app/rpc.jsonl")
    ledger = rows(root / "app/tool-events.jsonl")
    source_check = verify_codex_tool_sources(rpc, ledger)
    if replay_tool_events(ledger) != application["tool_calls"]:
        raise ValueError("application tool summary differs from raw lifecycle ledger")
    projection = replay_native_raw_tools(rpc, thread_id=application["thread_id"], turn_id=application["turn_id"])
    clocks = reconcile_projection(application, projection)
    provider = verify_provider(provider_directory, label, projection,
                               rows(root / "app/model-request-timing.jsonl"), manifest["boot_id"])
    resources = json.loads((root / "resources/resource-summary.json").read_text())
    samples = rows(root / "resources/resource-samples.jsonl")
    if resources.get("boot_id") != manifest["boot_id"] or any(row.get("boot_id") != manifest["boot_id"] for row in samples):
        raise ValueError("resource samples are not bound to the same boot")
    targets = resources.get("targets", [])
    runtime_targets = [row.get("target", {}) for row in targets
                       if row.get("target", {}).get("name") == "codex-native-runtime"]
    if len(runtime_targets) != 1:
        raise ValueError("resource summary lacks the full native runtime group")
    runtime = runtime_targets[0]
    if (runtime.get("cgroup_identity", {}).get("inode") != manifest["tools"][0]["cgroup_id"]
            or runtime.get("cgroup_scope") != "FRESH_EXCLUSIVE_AGENT_CGROUP_INCLUDES_RUNTIME_AND_ALL_NATIVE_TOOL_DESCENDANTS"):
        raise ValueError("resource group differs from the native runtime kernel capture group")
    config = json.loads((root / "app/config.public.json").read_text())
    if config.get("dynamic_tools") != "NONE" or config.get("native_shell") != "ENABLED":
        raise ValueError("not the normal native-tools capture contract")
    observed_comms = sorted({thread.get("comm") for thread in report["threads"] if thread.get("comm")})
    return {"schema_version": 1, "status": "SAME_RUN_BINDING_AND_REPLAY_PASSED",
        "manifest": manifest_digest, "run_id": manifest["run_id"], "boot_id": manifest["boot_id"],
        "application_outcome": application["status"], "native_configuration": config,
        "model_requests": len(provider), "model_receipts": provider, "native_tool_ledger": source_check,
        "native_model_tool_calls": len(projection["native_model_tool_calls"]),
        "inner_tool_calls": len(application["tool_calls"]), "kernel_totals": report["totals"],
        "runtime_and_descendant_comms": observed_comms,
        "kernel_health": report["health"], "resource_sample_rows": len(samples),
        "native_rpc_clock_reconciliation": clocks,
        "per_tool_linux_binding": "CHECK_SEPARATE_NATIVE_OS_PID_OR_EXEC_ARGV_EVIDENCE; NOT_IMPLIED_BY_REPLAY_PASS",
        "limits": ["Evidence binding/replay is not proof of complete Linux coverage or successful task semantics",
            "Native Code Mode request/output wall is observed; internal JS CPU/await slices are not exposed",
            "Task phase names are source-linked rule/reviewer annotations, not model intent ground truth",
            "Provider credentials and private bodies are not copied into this result"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--provider-directory", required=True, type=Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = verify_native_run(args.run, args.provider_directory, args.label)
    write_new(args.output, result)
    print(json.dumps({key: result[key] for key in ("status", "application_outcome", "model_requests", "native_model_tool_calls", "inner_tool_calls")}))


if __name__ == "__main__":
    main()
