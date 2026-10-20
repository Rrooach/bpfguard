#!/usr/bin/env python3
"""Select, project, and fold existing measured operations across Agent runs.

Unlike a timeline, default frames omit run IDs, tool ordinals and PIDs. Those
remain labels on every source sample. Semantic annotations remain hypotheses;
this module does not create a kernel binding or reinterpret missing values as 0.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from copy import deepcopy
from decimal import Decimal
import json
import math
from pathlib import Path
import re

from common import write_new
from semantic_profile import fold_view


FIELDS = frozenset({"task", "semantic", "phase", "action", "object", "tool", "process", "thread",
    "syscall", "syscall_category", "file", "resource", "model", "result", "kind", "run", "agent", "outcome"})
DEFAULT_STACK = ("semantic", "action", "object", "result")
MAX_OPERATIONS = 500_000
MAX_PROFILES = 256
MAX_RULES = 64


def _number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("profile measures must be finite nonnegative numbers")
    return Decimal(str(value))


def _registry(profile):
    annotations = profile.get("semantic_annotations") or {}
    return (profile.get("taxonomy_version", annotations.get("taxonomy_version")),
            profile.get("taxonomy_digest", annotations.get("taxonomy_digest")))


def _field_name(value):
    if value not in FIELDS:
        raise ValueError("unknown operation field: " + str(value))
    return value


def _regex(pattern):
    try:
        return re.compile(pattern)
    except re.error as error:
        raise ValueError("invalid query regular expression: " + str(error)) from error


def _append(fields, name, value):
    if value is not None and str(value) and str(value) not in fields[name]:
        fields[name].append(str(value))


def operation_fields(operation, profile, outcome="UNKNOWN"):
    """Extract queryable field bags without discarding original measured evidence."""
    fields = {name: [] for name in FIELDS}
    _append(fields, "run", profile.get("run_id"))
    _append(fields, "agent", profile.get("agent_id"))
    _append(fields, "outcome", outcome)
    _append(fields, "kind", operation.get("kind"))
    evidence = operation.get("evidence") or {}
    stack = operation.get("stack")
    if not isinstance(stack, list) or not stack:
        raise ValueError("each measured operation requires a source stack")
    for frame in stack:
        if not isinstance(frame, dict) or not isinstance(frame.get("label"), str):
            raise ValueError("invalid source frame")
        kind, label = frame.get("kind"), frame["label"]
        if kind == "tool":
            # Ordinals are navigation identifiers, not stable responsibilities.
            tool = frame.get("tool_name") or re.sub(r"^工具\s+[^·]+·\s*", "", label)
            _append(fields, "tool", tool)
            _append(fields, "result", frame.get("status"))
        elif kind in ("process", "thread"):
            _append(fields, kind, re.sub(r"\s*\[(?:pid|tid)\s+[^]]+\]$", "", label))
        elif kind == "file":
            _append(fields, "file", frame.get("path") or evidence.get("path") or label)
            _append(fields, "object", frame.get("path") or evidence.get("path") or label)
        elif kind in FIELDS:
            _append(fields, kind, label)
        elif kind in ("code_mode_phase", "agent_phase"):
            _append(fields, "phase", label)
        if kind == "syscall":
            _append(fields, "action", label)
        elif kind in ("resource", "v8"):
            _append(fields, "object", label)
    if not fields["action"]:
        if fields["phase"]:
            fields["action"] = list(fields["phase"])
        elif fields["tool"]:
            fields["action"] = list(fields["tool"])
        else:
            fields["action"] = list(fields["kind"])
    if not fields["object"]:
        fields["object"] = fields["file"] or fields["resource"] or fields["syscall_category"]
    if not fields["semantic"]:
        fields["semantic"] = ["完成任务", "未分配阶段"]
    if operation.get("kind") == "syscall":
        fields["result"] = []  # Outer tool success does not mean every syscall succeeded.
    if not fields["result"]:
        if evidence.get("errno"):
            _append(fields, "result", evidence["errno"])
        elif type(evidence.get("result")) is int:
            _append(fields, "result", "调用失败" if evidence["result"] < 0 else "调用成功")
    return fields


def parse_filters(filters):
    normalized = []
    if len(filters or []) > MAX_RULES:
        raise ValueError("too many query filters")
    for item in filters or []:
        if isinstance(item, str):
            match = re.fullmatch(r"([a-z_]+)(!?=)(.*)", item)
            if not match:
                raise ValueError("filter must be FIELD=REGEX or FIELD!=REGEX")
            field, op, pattern = match.groups()
            item = {"field": field, "pattern": pattern, "negate": op == "!="}
        if not isinstance(item, dict) or not isinstance(item.get("pattern"), str):
            raise ValueError("invalid filter")
        field = _field_name(item.get("field"))
        if len(item["pattern"]) > 2048 or type(item.get("negate", False)) is not bool:
            raise ValueError("filter pattern/negation exceeds schema")
        normalized.append({"field": field, "pattern": item["pattern"],
            "negate": item.get("negate", False), "regex": _regex(item["pattern"])})
    return normalized


def _mapping_rules(rules):
    if len(rules or []) > MAX_RULES:
        raise ValueError("too many operation mapping rules")
    output = []
    for rule in rules or []:
        if not isinstance(rule, dict):
            raise ValueError("mapping rule object required")
        target, source = _field_name(rule.get("field")), _field_name(rule.get("source_field"))
        label, pattern = rule.get("label"), rule.get("pattern")
        if not isinstance(label, str) or not 1 <= len(label) <= 120 or not isinstance(pattern, str) or len(pattern) > 2048:
            raise ValueError("bounded mapping label/regex required")
        output.append({"field": target, "source_field": source, "label": label, "pattern": pattern,
                       "regex": _regex(pattern)})
    return output


def _mapped(fields, rules):
    result, claimed = deepcopy(fields), set()
    for rule in rules:
        if rule["field"] not in claimed and any(rule["regex"].search(value) for value in result[rule["source_field"]]):
            result[rule["field"]] = [rule["label"]]
            claimed.add(rule["field"])
    return result


def query_profiles(profiles, measure, stack=DEFAULT_STACK, filters=None, mappings=None, outcomes=None):
    """Project multiple profiles with conserved measure and source sample labels.

    ``outcomes`` is an explicit run_id→label map; no benchmark pass is inferred
    from shell exit. Filters run AFTER mapping, BEFORE stack projection. Values
    absent from an operation stay absent; measured zero samples are retained.
    """
    if not isinstance(profiles, list) or not 1 <= len(profiles) <= MAX_PROFILES:
        raise ValueError("1..256 source profiles required")
    if not isinstance(measure, str) or not measure:
        raise ValueError("explicit measure required")
    if isinstance(stack, str):
        stack = tuple(stack.split(","))
    if not isinstance(stack, (tuple, list)) or not 1 <= len(stack) <= 16 or len(set(stack)) != len(stack):
        raise ValueError("nonempty unique stack fields required")
    for field in stack:
        _field_name(field)
    selected_filters, mapping_rules = parse_filters(filters), _mapping_rules(mappings)
    operations, runs, sources = [], set(), []
    total, excluded, missing_count, source_count = Decimal(0), Decimal(0), 0, 0
    unit, label, registries = None, None, set()
    for profile in profiles:
        if not isinstance(profile, dict) or not isinstance(profile.get("operations"), list):
            raise ValueError("profiles require original operations, not folded trees only")
        run_id = profile.get("run_id")
        if not isinstance(run_id, str) or not run_id or run_id in runs:
            raise ValueError("each source profile requires a unique explicit run_id")
        runs.add(run_id)
        registry = _registry(profile)
        if registry[0] is not None:
            registries.add(registry)
            if len(registries) > 1:
                raise ValueError("cannot silently combine different semantic taxonomy versions/digests")
        matching = [view for view in profile.get("views") or [] if view.get("name") == measure]
        if len(matching) != 1:
            raise ValueError("each source profile requires one selected measure definition")
        view = matching[0]
        if unit is None:
            unit, label = view.get("unit"), view.get("label", measure)
        elif view.get("unit") != unit:
            raise ValueError("cannot combine incompatible measure units")
        per_source, measured = Decimal(0), 0
        for ordinal, operation in enumerate(profile["operations"]):
            source_count += 1
            if source_count > MAX_OPERATIONS:
                raise ValueError("profile operation bound exceeded")
            measures = operation.get("measures") if isinstance(operation, dict) else None
            if not isinstance(measures, dict):
                raise ValueError("operation measures required")
            if measure not in measures:
                missing_count += 1; continue
            weight = _number(measures[measure]); total += weight; per_source += weight; measured += 1
            fields = _mapped(operation_fields(operation, profile, (outcomes or {}).get(run_id, "UNKNOWN")), mapping_rules)
            accepted = all((any(rule["regex"].search(value) for value in fields[rule["field"]])) != rule["negate"]
                           for rule in selected_filters)
            if not accepted:
                excluded += weight; continue
            projected = []
            for field in stack:
                for value in fields[field]:
                    projected.append({"kind": field, "label": value})
            if not projected:
                projected = [{"kind": "semantic", "label": "未分配阶段"}]
            operations.append({"kind": operation.get("kind", "operation"), "stack": projected,
                "measures": {measure: float(weight)}, "fields": fields,
                "evidence": {**deepcopy(operation.get("evidence") or {}), "run_id": run_id,
                    "agent_id": profile.get("agent_id"), "task_id": profile.get("task_id"),
                    "source_operation_index": ordinal,
                    "source_stack": deepcopy(operation["stack"]),
                    "semantic_quality": profile.get("semantic_quality"),
                    "outcome": (outcomes or {}).get(run_id, "UNKNOWN")}})
        if view.get("status") == "AVAILABLE" and measured == 0:
            raise ValueError("AVAILABLE measure has no actual samples")
        if measured and view.get("status") != "AVAILABLE":
            raise ValueError("measured operations conflict with view availability")
        if measured and abs(per_source - _number(view.get("total"))) > max(Decimal("1e-6"), per_source * Decimal("1e-9")):
            raise ValueError("source view total disagrees with measured operation sum")
        sources.append({"run_id": run_id, "status": view.get("status"), "measured_samples": measured,
                        "taxonomy_version": registry[0], "taxonomy_digest": registry[1],
                        "total": float(per_source), "semantic_quality": profile.get("semantic_quality")})
    included = sum((_number(operation["measures"][measure]) for operation in operations), Decimal(0))
    tolerance = max(Decimal("1e-6"), total * Decimal("1e-9"))
    if abs(total - excluded - included) > tolerance:
        raise ValueError("measure conservation failed")
    tree, samples = fold_view(operations, measure, "任务聚合")
    unassigned = sum((_number(row["measures"][measure]) for row in operations if
        any(any(word in value for word in ("未分配", "未提供", "未归属", "unmatched", "UNANNOTATED"))
            for value in row["fields"]["semantic"])), Decimal(0))
    output = {"schema_version": 1, "kind": "QUERYABLE_OPERATION_PROFILE", "run_id": "aggregate:" + "+".join(sorted(runs)),
        "agent_id": "aggregate", "task_id": "multi-run", "operations": operations,
        "operation_count": len(operations), "semantic_quality": "SOURCE_ANNOTATION_METHOD_RETAINED_PER_SAMPLE",
        "views": [{"name": measure, "label": label, "unit": unit,
            "status": "AVAILABLE" if samples else "NO_SELECTED_SAMPLES", "sample_count": samples,
            "total": float(included), "tree": tree}],
        "query": {"stack": list(stack), "measure": measure,
            "filters": [{key: item[key] for key in ("field", "pattern", "negate")} for item in selected_filters],
            "mappings": [{key: item[key] for key in ("field", "source_field", "label", "pattern")} for item in mapping_rules]},
        "sources": sources, "conservation": {"status": "PASSED", "source_total": float(total),
            "excluded_total": float(excluded), "selected_total": float(included),
            "missing_measure_operations": missing_count, "meaning": "selected+excluded=source; missing is not zero"},
        "semantic_registry": {"status": "SAME_VERSIONED_TAXONOMY" if registries and
                all(source["taxonomy_version"] is not None for source in sources) else "VERSION_NOT_KNOWN_FOR_ALL_SOURCES",
            "identities": [{"version": version, "digest": digest} for version, digest in sorted(registries)]},
        "semantic_coverage": {"unassigned_weight": float(unassigned), "selected_weight": float(included),
            "unassigned_weight_fraction": float(unassigned / included) if included else None,
            "meaning": "Label coverage is not annotation accuracy or causal confidence."},
        "limits": ["Same task names are source annotations, not proof of equal hidden intent.",
                   "Run, PID and call IDs remain evidence labels unless explicitly selected as frames.",
                   "Summed wall time across independent runs is not one shared makespan.",
                   "Summed peaks are not a concurrent memory peak; RSS can double-count shared pages."]}
    return output


def compare_profiles(baseline, comparison, measure, stack=DEFAULT_STACK, filters=None, mappings=None,
                     normalization="per_run"):
    """Return signed stable-stack differences; never silently call negative width 0.

    Width is baseline+comparison mass, sign is comparison-baseline. Per-run
    normalization avoids presenting a larger cohort as an automatic regression.
    It does not make unmatched workloads comparable; callers must control tasks.
    """
    if normalization not in ("none", "per_run"):
        raise ValueError("normalization must be none or per_run")
    base = query_profiles(baseline, measure, stack, filters, mappings)
    other = query_profiles(comparison, measure, stack, filters, mappings)
    if base["views"][0]["unit"] != other["views"][0]["unit"]:
        raise ValueError("comparison measure units differ")
    base_registry = base["semantic_registry"]["identities"]
    other_registry = other["semantic_registry"]["identities"]
    if base_registry and other_registry and base_registry != other_registry:
        raise ValueError("baseline/comparison semantic taxonomy versions differ")
    def values(profile, divisor):
        folded = defaultdict(Decimal)
        for operation in profile["operations"]:
            key = tuple((frame["kind"], frame["label"]) for frame in operation["stack"])
            folded[key] += _number(operation["measures"][measure]) / divisor
        return folded
    base_values = values(base, Decimal(len(baseline) if normalization == "per_run" else 1))
    other_values = values(other, Decimal(len(comparison) if normalization == "per_run" else 1))
    rows = []
    for path in sorted(set(base_values) | set(other_values)):
        old, new = base_values[path], other_values[path]
        rows.append({"stack": [{"kind": kind, "label": label} for kind, label in path],
            "baseline": float(old), "comparison": float(new), "delta": float(new - old),
            "display_width": float(old + new), "direction": "INCREASE" if new > old else "DECREASE" if new < old else "EQUAL"})
    rows.sort(key=lambda row: (-abs(row["delta"]), -row["display_width"], str(row["stack"])))
    return {"schema_version": 1, "kind": "SIGNED_TASK_PROFILE_COMPARISON", "measure": measure,
        "unit": base["views"][0]["unit"], "normalization": normalization,
        "baseline_runs": [item["run_id"] for item in base["sources"]],
        "comparison_runs": [item["run_id"] for item in other["sources"]], "rows": rows,
        "baseline_total": float(sum(base_values.values(), Decimal(0))),
        "comparison_total": float(sum(other_values.values(), Decimal(0))),
        "delta_total": float(sum(other_values.values(), Decimal(0)) - sum(base_values.values(), Decimal(0))),
        "conservation": {"baseline": base["conservation"], "comparison": other["conservation"]},
        "meaning": "Signed resource difference, not automatic performance regression or task quality judgement.",
        "workload_comparability": "CALLER_MUST_CONTROL_TASKS_AND_TOTAL_WORK; NOT_INFERRED_FROM_SIMILAR_LABELS"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, action="append", required=True)
    parser.add_argument("--baseline", type=Path, action="append", default=[])
    parser.add_argument("--measure", required=True)
    parser.add_argument("--stack", default=",".join(DEFAULT_STACK))
    parser.add_argument("--where", action="append", default=[])
    parser.add_argument("--mapping-file", type=Path, help="JSON list of operation field mapping rules")
    parser.add_argument("--normalization", choices=("none", "per_run"), default="per_run")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    def read(path):
        if path.stat().st_size > 256 * 1024 * 1024:
            raise ValueError("input profile exceeds bound")
        return json.loads(path.read_text())
    profiles, mappings = [read(path) for path in args.profile], read(args.mapping_file) if args.mapping_file else None
    if args.baseline:
        output = compare_profiles([read(path) for path in args.baseline], profiles, args.measure,
            args.stack, args.where, mappings, args.normalization)
    else:
        output = query_profiles(profiles, args.measure, args.stack, args.where, mappings)
    write_new(args.output, output)
    print(json.dumps({"status": "WRITTEN", "kind": output["kind"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
