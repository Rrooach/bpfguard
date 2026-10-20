#!/usr/bin/env python3
"""Export semantic operations as a standard gzip pprof protobuf.

No protobuf runtime is required.  The small encoder follows the public schema:
https://github.com/google/pprof/blob/main/proto/profile.proto

These are semantic operation stacks, NOT sampled CPU call stacks.  Millisecond
views use integer nanoseconds.  RSS integrals retain the custom, dimensionally
correct ``byte_milliseconds`` unit: converting them to byte*ns can overflow
pprof's signed int64 for otherwise ordinary long-lived agents.  Integer export
rounds half-even; the receipt reports the quantization difference.  Missing
measurements are never replaced by zero; explicitly measured zero is retained.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile


MAX_INT64 = (1 << 63) - 1
MAX_OPERATIONS = 500_000
MAX_STACK_DEPTH = 64
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_TEXT_BYTES = 384
ID_FIELDS = frozenset({
    "run_id", "agent_id", "task_id", "operation_id", "call_id", "tool_call_id",
    "evidence_id", "evidence_chain_id", "evidence_chain_status", "request_id",
    "tgid", "tid", "pid", "process_birth_ns", "runtime_id", "source_kind",
    "attribution", "scope", "status", "quality", "tool_name",
})
REFERENCE_FIELDS = frozenset({
    "evidence_ref", "evidence_refs", "artifact", "artifacts", "wal_ref",
    "wal_sequence", "source_path", "source_file", "path", "source", "ledger",
})
_SECRETS = re.compile(
    r"(?i)(?:bearer\s+\S+|(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*\S+|"
    r"\bsk-[a-z0-9_-]{8,})"
)
_URL = re.compile(r"https?://[^\s]+", re.I)


def _safe_text(value, limit=MAX_TEXT_BYTES):
    """Bound labels and redact recognized secrets; not a general PII scrubber."""
    raw = str(value)
    # Query strings / userinfo can contain credentials. Evidence URLs should be
    # hashes; a URL appearing in a semantic frame is not copied to the export.
    raw = _URL.sub("[url-sha256:" + hashlib.sha256(raw.encode()).hexdigest()[:16] + "]", raw)
    text = _SECRETS.sub("[redacted]", raw)
    text = "".join(char if char >= " " and char != "\x7f" else " " for char in text)
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    suffix = "…[sha256:" + hashlib.sha256(encoded).hexdigest()[:16] + "]"
    prefix = encoded[:max(0, limit - len(suffix.encode()))].decode("utf-8", "ignore")
    return prefix + suffix


def _number(value, field):
    if type(value) not in (int, float) or (isinstance(value, float) and not math.isfinite(value)):
        raise ValueError(f"{field}: expected a finite nonnegative number")
    number = Decimal(str(value))
    if number < 0:
        raise ValueError(f"{field}: negative measurement")
    return number


def _varint(value):
    if not isinstance(value, int) or value < 0 or value > MAX_INT64:
        raise ValueError("protobuf integer is outside supported nonnegative int64 range")
    data = bytearray()
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    data.append(value)
    return bytes(data)


def _integer(field, value):
    return _varint(field << 3) + _varint(value)


def _bytes(field, value):
    return _varint((field << 3) | 2) + _varint(len(value)) + value


def _packed(field, values):
    return _bytes(field, b"".join(_varint(value) for value in values))


def _unit(view):
    source = view.get("unit")
    if source == "ms":
        return "nanoseconds", Decimal(1_000_000)
    if source == "byte_ms":
        return "byte_milliseconds", Decimal(1)
    if source in ("bytes", "byte"):
        return "bytes", Decimal(1)
    if source in ("次", "count", "tokens"):
        return "count", Decimal(1)
    raise ValueError(f"unsupported view unit: {source!r}")


def _labels(operation, ordinal, profile=None):
    labels = {"operation_index": str(ordinal), "operation_kind": _safe_text(operation.get("kind", "operation"))}
    found = {}
    for key in ("run_id", "agent_id", "task_id"):
        value = (profile or {}).get(key)
        if type(value) in (str, int):
            found[key] = {_safe_text(value)}
    # Only known IDs / status fields are copied. Commands, arguments, buffers,
    # model text and environment variables are never sample labels.
    containers = [operation, operation.get("evidence", {})] + operation["stack"]
    references = []
    for fields in containers:
        if not isinstance(fields, dict):
            continue
        if fields.get("kind") == "tool" and isinstance(fields.get("label"), str):
            found.setdefault("tool", set()).add(_safe_text(fields["label"]))
        for key, value in fields.items():
            if value is None:
                continue
            if key in ID_FIELDS and type(value) in (str, int):
                found.setdefault(key, set()).add(_safe_text(value))
            elif key in REFERENCE_FIELDS:
                references.append((key, value))
    for key, values in sorted(found.items()):
        labels[key] = _safe_text(" | ".join(sorted(values)))
    if references:
        # No arbitrary source filename or evidence contents enter pprof labels.
        digest = hashlib.sha256(json.dumps(references, sort_keys=True, ensure_ascii=False,
            separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        labels["evidence_ref_sha256"] = digest
    return labels


def _prepare(profile, view_name):
    if not isinstance(profile, dict):
        raise ValueError("profile must be an object")
    if not isinstance(view_name, str) or not view_name or len(view_name) > 128:
        raise ValueError("view name must be a nonempty bounded string")
    if not isinstance(profile.get("views"), list):
        raise ValueError("profile.views must be an array")
    matches = [view for view in profile["views"]
               if isinstance(view, dict) and view.get("name") == view_name]
    if len(matches) != 1:
        raise ValueError(f"view {view_name!r} must exist exactly once")
    view = matches[0]
    if view.get("status") != "AVAILABLE":
        raise ValueError(f"view {view_name!r} is {view.get('status', 'UNKNOWN')}; refusing invented samples")
    operations = profile.get("operations")
    if not isinstance(operations, list):
        raise ValueError("profile.operations is required; folded trees cannot reconstruct original evidence")
    if len(operations) > MAX_OPERATIONS:
        raise ValueError("profile.operations exceeds bounded export limit")
    unit, scale = _unit(view)
    samples = []
    source_total = Decimal(0)
    exported_total = 0
    for ordinal, operation in enumerate(operations):
        if not isinstance(operation, dict) or not isinstance(operation.get("measures"), dict):
            raise ValueError(f"operation {ordinal}: invalid operation/measures")
        if view_name not in operation["measures"]:
            continue
        value = _number(operation["measures"][view_name], f"operation {ordinal}/{view_name}")
        if unit in ("count", "bytes") and value != value.to_integral_value():
            raise ValueError(f"operation {ordinal}: fractional {unit} measurement")
        weight = int((value * scale).to_integral_value(rounding=ROUND_HALF_EVEN))
        if weight > MAX_INT64:
            raise ValueError("individual sample exceeds pprof signed int64 range")
        source_total += value
        exported_total += weight
        if exported_total > MAX_INT64:
            raise ValueError("sample total exceeds pprof signed int64 range")
        stack = operation.get("stack")
        if not isinstance(stack, list) or not stack or len(stack) > MAX_STACK_DEPTH:
            raise ValueError(f"operation {ordinal}: expected 1..{MAX_STACK_DEPTH} stack frames")
        frames = []
        for frame in stack:
            if not isinstance(frame, dict) or not isinstance(frame.get("label"), str):
                raise ValueError(f"operation {ordinal}: frame label must be a string")
            kind = _safe_text(frame.get("kind", "semantic"), 64)
            label = _safe_text(frame["label"])
            frames.append(f"{kind}: {label}")
        samples.append((frames, weight, _labels(operation, ordinal, profile)))
    if not samples:
        raise ValueError("AVAILABLE view has no measured operations (zero is valid, absence is not)")
    if "sample_count" in view and view["sample_count"] != len(samples):
        raise ValueError("view sample_count disagrees with measured operations")
    if "total" in view:
        declared = _number(view["total"], "view.total")
        tolerance = max(Decimal("0.000001"), abs(source_total) * Decimal("1e-9"))
        if abs(source_total - declared) > tolerance:
            raise ValueError("view total disagrees with measured operation sum")
    comments = [
        "Observer semantic operation profile. Frames are NOT sampled native CPU call stacks.",
        f"Source view: {view_name}; source unit: {view.get('unit')}; export unit: {unit}.",
        "Explicit measured zero samples retained; absent measurements omitted. Integer rounding: half-even.",
        "RSS integrals sum registered process RSS and may double-count shared pages; peaks are not concurrent totals.",
        "Sample labels are bounded and recognized secrets redacted; do not treat this as a complete PII scrubber.",
        "Task names are source annotations, not independently verified intent or completed recursive semantic segmentation.",
    ]
    if unit == "byte_milliseconds":
        comments.append("Custom unit byte_milliseconds means bytes multiplied by milliseconds, NOT bytes or allocation count.")
    if profile.get("semantic_quality"):
        comments.append("Semantic quality: " + _safe_text(profile["semantic_quality"]))
    metadata = {"view": view_name, "unit": unit, "source_unit": view.get("unit"),
        "source_status": view["status"], "sample_count": len(samples),
        "zero_sample_count": sum(weight == 0 for _, weight, _ in samples),
        "source_total": str(source_total), "exported_total": exported_total,
        "quantization_delta_source_units": str(Decimal(exported_total) / scale - source_total),
        "quantization": "ROUND_HALF_EVEN_TO_INTEGER_EXPORT_UNIT",
        "format": "GZIP_PPROF_PROTOBUF", "labels": "ALLOWLISTED_BOUNDED_RECOGNIZED_SECRETS_REDACTED"}
    return samples, comments, metadata


def encode_pprof(profile, view):
    """Return ``(gzip_bytes, receipt)``; never synthesize an unavailable view."""
    samples, comments, receipt = _prepare(profile, view)
    # Sort the universe, not encounter order: string/function/location IDs do
    # not depend on the order of operations. IDs are stable for a fixed set.
    functions = sorted({frame for frames, _, _ in samples for frame in frames})
    function_ids = {name: ordinal + 1 for ordinal, name in enumerate(functions)}
    string_values = {"", view, receipt["unit"], *comments, *functions}
    for _, _, labels in samples:
        for key, value in labels.items():
            string_values.update((key, value))
    strings = [""] + sorted(string_values - {""})
    string_ids = {value: ordinal for ordinal, value in enumerate(strings)}
    msg = bytearray()
    msg.extend(_bytes(1, _integer(1, string_ids[view]) + _integer(2, string_ids[receipt["unit"]])))
    for frames, weight, labels in samples:
        # pprof requires LEAF FIRST; our operation schema is ROOT FIRST.
        sample = _packed(1, [function_ids[frame] for frame in reversed(frames)]) + _packed(2, [weight])
        for key, value in sorted(labels.items()):
            sample += _bytes(3, _integer(1, string_ids[key]) + _integer(2, string_ids[value]))
        msg.extend(_bytes(2, sample))
    for name in functions:
        identity = function_ids[name]
        line = _integer(1, identity)
        msg.extend(_bytes(4, _integer(1, identity) + _bytes(4, line)))
        msg.extend(_bytes(5, _integer(1, identity) + _integer(2, string_ids[name]) + _integer(3, string_ids[name])))
    for value in strings:
        msg.extend(_bytes(6, value.encode("utf-8")))
    for comment in comments:
        msg.extend(_integer(13, string_ids[comment]))
    # Official schema: default_sample_type=14; 15 is doc_url, not the default.
    msg.extend(_integer(14, string_ids[view]))
    encoded = gzip.compress(bytes(msg), mtime=0)
    receipt = {**receipt, "uncompressed_bytes": len(msg), "compressed_bytes": len(encoded),
               "sha256": hashlib.sha256(encoded).hexdigest()}
    return encoded, receipt


def write_pprof(profile, view, output):
    """Atomically write gzip pprof and return a JSON-compatible export receipt."""
    encoded, receipt = encode_pprof(profile, view)
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".pprof-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {**receipt, "output": str(path)}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", type=Path, required=True, help="semantic-profile JSON including operations")
    parser.add_argument("--view", required=True, help="AVAILABLE measure name, e.g. wall_ms or memory_rss_byte_ms")
    parser.add_argument("--output", type=Path, required=True, help="gzip pprof output, conventionally *.pb.gz")
    args = parser.parse_args(argv)
    try:
        with args.profile.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("input profile exceeds bounded input limit")
        profile = json.loads(raw, object_pairs_hook=_unique_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON number: {value}")))
        receipt = write_pprof(profile, args.view, args.output)
    except (OSError, ValueError, InvalidOperation) as error:
        parser.exit(2, f"pprof export failed: {error}\n")
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
