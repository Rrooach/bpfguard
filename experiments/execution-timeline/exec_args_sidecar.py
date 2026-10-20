#!/usr/bin/env python3
"""Independent decoder and lifecycle helper for the opt-in exec argv sidecar.

Raw binary WAL is authoritative. USER_ARGV_AT_SYSCALL_ENTRY is racy user memory,
not the kernel's final copy. sched_process_exec proves successful image exec,
not successful tool completion. This sidecar never adds to core syscall counts.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shlex
import signal
import struct
import subprocess
import time
import uuid

from common import write_new

MAGIC = 0x4E454131
HEALTH_MAGIC = 0x4E454148
HEADER = struct.Struct("<IHHII16s7Qq4Ii3I8H8H16s256s")
HEALTH = struct.Struct("<IHH16s24Q")
HEADER_BYTES, ENTRY_BYTES = 432, 33200
ARG_BYTES, MAX_ARGS = 4096, 8
KINDS = {1: "ENTRY", 2: "SUCCESS", 3: "FAILED", 4: "ABORTED", 5: "UNCONFIRMED"}
COUNTERS = ("attempted_entries", "entries", "successes", "failures", "aborts", "unconfirmed_results",
    "ring_drops", "read_failures", "identity_failures", "pending_full", "pending_collisions",
    "unmatched_success", "delete_errors", "sequence")
MAX_WAL_BYTES = 256 * 1024 * 1024
assert HEADER.size == HEADER_BYTES and HEALTH.size == 216


def _hash(path):
    sha, size = hashlib.sha256(), 0
    with Path(path).open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block: break
            sha.update(block); size += len(block)
    return {"sha256": sha.hexdigest(), "size_bytes": size}


def _string(raw, length, maximum, failed=False):
    if failed:
        if length: raise ValueError("failed string claims a complete length")
        # A nofault copy may have modified a prefix before failing. The raw
        # bytes remain in WAL but are not exposed as a valid argument string.
        return b""
    if not 1 <= length <= maximum or raw[length - 1] != 0 or any(raw[length:]):
        raise ValueError("invalid string length, terminator or nonzero padding")
    if b"\0" in raw[:length - 1]: raise ValueError("embedded NUL disagrees with string length")
    return raw[:length - 1]


def decode_record(raw, offset=0):
    if len(raw) < HEADER_BYTES: raise ValueError("truncated argv record header")
    h = HEADER.unpack_from(raw)
    magic, version, kind, size, flags, boot = h[:6]
    if magic != MAGIC or version != 1 or kind not in KINDS or size != len(raw):
        raise ValueError("argv WAL magic/version/kind/size mismatch")
    if size != (ENTRY_BYTES if kind == 1 else HEADER_BYTES) or flags & ~127:
        raise ValueError("invalid argv record size/flags")
    timestamp, sequence, root, entry, thread_birth, process_birth, cgroup = h[6:13]
    result, tid, tgid, cpu, old_tid, nr, argc, filename_bytes, reserved = h[13:22]
    arg_lengths, arg_flags, comm, filename = h[22:30], h[30:38], h[38], h[39]
    if not all((timestamp, sequence, root, thread_birth, process_birth, cgroup, tid, tgid)) or reserved or root != cgroup:
        raise ValueError("invalid task/clock/cgroup identity")
    if timestamp < entry or cpu > 1048576 or argc > MAX_ARGS:
        raise ValueError("invalid argv time/count/cpu")
    if kind == 1 and (nr not in (59, 322) or not entry or flags & 32 or old_tid or result):
        raise ValueError("invalid exec entry metadata")
    if kind != 1 and (argc or filename_bytes or any(arg_lengths) or any(arg_flags) or any(filename)):
        raise ValueError("terminal marker must not manufacture argv")
    if kind != 1 and flags not in (0, 32):
        raise ValueError("terminal marker has entry-only capture flags")
    if flags & 32 and (kind != 2 or entry or nr != -1):
        raise ValueError("missing-entry marker must be an unmatched successful exec")
    if kind != 1 and not flags & 32 and (not entry or nr not in (59, 322)):
        raise ValueError("terminal marker lacks exec entry reference")
    if kind == 3 and result >= 0 or kind in (2, 4) and result != 0:
        raise ValueError("exec result disagrees with terminal event")
    if kind == 5 and result < 0:
        raise ValueError("unconfirmed nonnegative return has negative errno")
    filename_raw, args, args_hex = b"", [], []
    if kind == 1:
        filename_raw = _string(filename, filename_bytes, 256, bool(flags & 2))
        if bool(flags & 1) != (filename_bytes == 256): raise ValueError("filename truncation flag mismatch")
        for index in range(MAX_ARGS):
            slot = raw[HEADER_BYTES + index * ARG_BYTES:HEADER_BYTES + (index + 1) * ARG_BYTES]
            if index >= argc:
                if arg_lengths[index] or arg_flags[index] or any(slot): raise ValueError("nonzero unused argv slot")
                continue
            status, length = arg_flags[index], arg_lengths[index]
            if status not in (1, 2, 3): raise ValueError("invalid captured argument status")
            value = _string(slot, length, ARG_BYTES, status == 3)
            if status == 2 and length != ARG_BYTES or status == 1 and length >= ARG_BYTES:
                raise ValueError("argument truncation status/length mismatch")
            args.append(value.decode("utf-8", "replace")); args_hex.append(value.hex())
        if any(status == 3 for status in arg_flags) != bool(flags & 16):
            raise ValueError("argv string failure flag mismatch")
        if any(status == 2 for status in arg_flags) != bool(flags & 64):
            raise ValueError("argv string truncation flag mismatch")
        if flags & 4 and argc != MAX_ARGS: raise ValueError("argument-count truncation mismatch")
        if argc == MAX_ARGS and not flags & (4 | 8 | 16):
            raise ValueError("eight nonnull argv entries require conservative count-truncation flag")
    return {"kind": KINDS[kind], "wal_offset": offset, "wal_size": size,
        "boot_id": str(uuid.UUID(bytes=boot)), "timestamp_ns": timestamp, "cpu_sequence": sequence,
        "root_cgroup_id": root, "cgroup_id": cgroup, "entry_ns": entry,
        "thread_birth_ns": thread_birth, "process_birth_ns": process_birth,
        "tid": tid, "tgid": tgid, "cpu": cpu, "old_tid": old_tid, "syscall_nr": nr, "result": result,
        "flags": flags, "argc": argc, "filename": filename_raw.decode("utf-8", "replace"),
        "filename_hex": filename_raw.hex(), "argv": args, "argv_hex": args_hex,
        "argv_lengths_with_nul": list(arg_lengths[:argc]), "argv_flags": list(arg_flags[:argc]),
        "comm": comm.split(b"\0", 1)[0].decode("utf-8", "replace"),
        "argv_quality": "COMPLETE_USER_ENTRY_STRINGS" if kind == 1 and not flags else "INCOMPLETE_OR_NOT_AN_ENTRY",
        "source": "USER_ARGV_AT_SYSCALL_ENTRY_NOT_FINAL_KERNEL_COPY",
        "identity_scope": "PRE_EXEC_SYSCALL_CALLER; old_tid handles de-thread; not a post-exec birth assertion"}


def _read_health(path):
    raw = Path(path).read_bytes()
    if len(raw) != HEALTH.size: raise ValueError("truncated/extra health WAL bytes")
    fields = HEALTH.unpack(raw)
    if fields[:3] != (HEALTH_MAGIC, 1, HEALTH.size): raise ValueError("health WAL ABI mismatch")
    names = ("cgroup_id", "begin_ns", "end_ns", "records", "bytes", "max_bytes",
             "parse_errors", "write_errors", "cap_discarded", "pending_at_end")
    output = dict(zip(names, fields[4:14]))
    output["boot_id"] = str(uuid.UUID(bytes=fields[3]))
    output["counters"] = dict(zip(COUNTERS, fields[14:]))
    if not output["cgroup_id"] or not 0 < output["begin_ns"] <= output["end_ns"]:
        raise ValueError("invalid health scope/boundary")
    return output


def verify_capture(directory, expected_artifacts=None, max_bytes=MAX_WAL_BYTES):
    """Independently decode binary WAL and counters; never read projected event JSON.

    Optional expected hashes must come from a separately bound run manifest.
    Hashes here are integrity receipts, not authentication of a compromised kernel.
    """
    directory = Path(directory)
    artifacts = {name: _hash(directory / name) for name in ("events.bin", "health.bin", "ready.json")}
    if expected_artifacts is not None:
        for name, expected in expected_artifacts.items():
            if name not in artifacts or artifacts[name] != expected:
                raise ValueError("sidecar artifact differs from independently supplied manifest: " + name)
    if artifacts["events.bin"]["size_bytes"] > max_bytes: raise ValueError("bounded WAL read limit exceeded")
    health = _read_health(directory / "health.bin")
    ready = json.loads((directory / "ready.json").read_text())
    if ready.get("status") != "READY" or ready.get("cgroup_id") != health["cgroup_id"] or ready.get("scope") != "EXACT_CGROUP_ID_NOT_DESCENDANTS":
        raise ValueError("sidecar readiness/scope missing or changed")
    records, pending, executions, cpu_sequences = [], {}, [], {}
    sequence_gaps, counts = 0, Counter()
    with (directory / "events.bin").open("rb") as stream:
        offset = 0
        while True:
            prefix = stream.read(16)
            if not prefix: break
            if len(prefix) != 16: raise ValueError("truncated argv WAL prefix")
            magic, version, kind, size, flags = struct.unpack("<IHHII", prefix)
            if magic != MAGIC or version != 1 or kind not in KINDS or size != (ENTRY_BYTES if kind == 1 else HEADER_BYTES):
                raise ValueError("invalid argv WAL record prefix")
            body = stream.read(size - 16)
            if len(body) != size - 16: raise ValueError("truncated argv WAL record")
            row = decode_record(prefix + body, offset); offset += size
            if len(records) >= 200_000: raise ValueError("sidecar record bound exceeded")
            if row["boot_id"] != health["boot_id"] or row["cgroup_id"] != health["cgroup_id"]:
                raise ValueError("WAL record escaped declared boot/cgroup")
            if not health["begin_ns"] <= row["timestamp_ns"] <= health["end_ns"]:
                raise ValueError("WAL record outside capture boundaries")
            previous = cpu_sequences.get(row["cpu"], 0)
            if row["cpu_sequence"] <= previous: raise ValueError("duplicate/backwards CPU sequence")
            sequence_gaps += row["cpu_sequence"] - previous - 1
            cpu_sequences[row["cpu"]] = row["cpu_sequence"]
            counts[row["kind"]] += 1
            key = (row["entry_ns"], row["tid"], row["thread_birth_ns"])
            if row["kind"] == "ENTRY":
                if key in pending: raise ValueError("duplicate exec entry identity")
                pending[key] = row
            elif not row["flags"] & 32:
                entry = pending.pop(key, None)
                if entry is None:
                    row["entry_evidence"] = "MISSING_FROM_WAL"
                else:
                    if row["syscall_nr"] != entry["syscall_nr"] or row["process_birth_ns"] != entry["process_birth_ns"] or row["tgid"] != entry["tgid"]:
                        raise ValueError("exec completion conflicts with entry identity")
                    row["entry_evidence"] = "EXACT_BINARY_ENTRY_REFERENCE"
                    if row["kind"] == "SUCCESS":
                        executions.append({"entry": entry, "success": row,
                            "status": "SUCCESSFUL_EXEC_CONFIRMED_BY_SCHED_PROCESS_EXEC",
                            "argv_quality": entry["argv_quality"]})
            records.append(row)
    if len(records) != health["records"] or offset != health["bytes"]:
        raise ValueError("raw WAL record/byte totals differ from binary health")
    counters = health["counters"]
    emitted = sum(counters[key] for key in ("entries", "successes", "failures", "aborts", "unconfirmed_results"))
    if emitted != len(records) + health["parse_errors"] + health["cap_discarded"]:
        raise ValueError("kernel emitted count differs from raw/explicitly discarded records")
    if counters["sequence"] != emitted + counters["ring_drops"]:
        raise ValueError("event sequence attempts differ from emitted+dropped events")
    reasons = [name for name in ("parse_errors", "write_errors", "cap_discarded", "pending_at_end") if health[name]]
    reasons += [name for name in ("ring_drops", "identity_failures", "pending_full", "pending_collisions", "unmatched_success", "delete_errors", "unconfirmed_results") if counters[name]]
    if pending: reasons.append("unclosed_entry_records")
    if sequence_gaps: reasons.append("cpu_sequence_gaps")
    if any(row.get("entry_evidence") == "MISSING_FROM_WAL" for row in records): reasons.append("missing_entry_wal")
    complete_args = sum(row["kind"] == "ENTRY" and row["argv_quality"] == "COMPLETE_USER_ENTRY_STRINGS" for row in records)
    incomplete_args = counts["ENTRY"] - complete_args
    return {"schema_version": 1, "kind": "INDEPENDENT_EXEC_ARGV_WAL_REPLAY", "status": "REPLAY_PASSED",
        "history_status": "INCOMPLETE" if reasons else "COMPLETE_FOR_SELECTED_EXACT_CGROUP_EXEC_HOOKS",
        "scope": "EXACT_CGROUP_ID_NOT_DESCENDANTS; NATIVE_X86_64_EXECVE_EXECVEAT",
        "boot_id": health["boot_id"], "cgroup_id": health["cgroup_id"], "artifacts": artifacts,
        "health": health, "reason_flags": sorted(set(reasons)), "record_counts": dict(counts),
        "sequence_gaps": sequence_gaps, "executions": executions, "records": records,
        "argv_evidence_status": "INCOMPLETE" if incomplete_args else "COMPLETE_FOR_CAPTURED_ENTRIES",
        "argv_complete_entries": complete_args, "argv_incomplete_entries": incomplete_args,
        "core_syscall_count_increment": 0,
        "limits": ["Entry argv is bounded user memory and subject to TOCTOU, not final kernel copied argv.",
                   "Successful exec does not prove successful command completion or causal task ownership.",
                   "Complete parameter evidence requires no truncation/read failure in that entry.",
                   "No descendant cgroup scope, compat ABI, envp, or post-exec memory capture."]}


def codex_snapshot_contract(application, rpc_rows, config):
    """Opt-in known Codex version contract, derived from bound native records."""
    matches = []
    for index, row in enumerate(rpc_rows):
        message = row.get("message") or {}
        thread = (message.get("result") or {}).get("thread") or {}
        if thread.get("id") == application.get("thread_id") and thread.get("cliVersion") == "0.154.0":
            matches.append(index)
    if len(matches) != 1 or config.get("native_shell") != "ENABLED" or config.get("dynamic_tools") != "NONE":
        raise ValueError("snapshot projection requires identified Codex 0.154.0 native-shell source")
    return {"kind": "CODEX_BASH_SNAPSHOT_LC_TO_C_V1", "codex_version": "0.154.0",
        "source": "BOUND_RAW_THREAD_START_AND_NATIVE_SHELL_CONFIGURATION",
        "evidence_refs": ["rpc#/" + str(matches[0]), "app/config.public.json"],
        "meaning": "Declared flag projection, not unchanged full-argv equality or causal proof"}


def correlate_commands(tool_calls, replay, runtime_contract=None):
    """Exact argv + unique evidence candidate; never a strong causal binding."""
    rows, seen = [], set()
    if runtime_contract is not None and (runtime_contract.get("kind") != "CODEX_BASH_SNAPSHOT_LC_TO_C_V1" or
                                        runtime_contract.get("codex_version") != "0.154.0"):
        raise ValueError("unsupported explicit argv projection contract")
    healthy = replay.get("history_status") == "COMPLETE_FOR_SELECTED_EXACT_CGROUP_EXEC_HOOKS"
    for call in tool_calls:
        call_id = call.get("call_id")
        if not isinstance(call_id, str) or not call_id or call_id in seen:
            raise ValueError("unique application call_id required")
        seen.add(call_id)
        arguments = call.get("arguments") or {}
        command = call.get("command") or (arguments.get("command") if isinstance(arguments, dict) else None)
        tokens = None
        try:
            tokens = shlex.split(command) if isinstance(command, str) else command if isinstance(command, list) else None
            if tokens is not None and not all(isinstance(token, str) for token in tokens): tokens = None
            encoded = [token.encode("utf-8").hex() for token in tokens] if tokens else None
        except (ValueError, AttributeError, UnicodeError):
            encoded = None
        projection = None
        if (runtime_contract is not None and call.get("tool_name") == "commandExecution" and isinstance(arguments, dict) and
                arguments.get("source") == "unifiedExecStartup" and tokens is not None and
                len(tokens) == 3 and tokens[:2] == ["/bin/bash", "-lc"]):
            projected = [tokens[0], "-c", tokens[2]]
            encoded = [token.encode("utf-8").hex() for token in projected]
            projection = {"kind": runtime_contract["kind"], "changed_argument_index": 1,
                "source_argument": "-lc", "kernel_argument": "-c", "script_comparison": "EXACT_BYTES",
                "runtime_contract": runtime_contract}
        matches, possible_incomplete = [], 0
        if encoded:
            for execution in replay.get("executions") or []:
                entry = execution["entry"]
                if entry["argv_quality"] == "COMPLETE_USER_ENTRY_STRINGS" and entry["argv_hex"] == encoded:
                    matches.append(execution)
                elif entry["argv_quality"] != "COMPLETE_USER_ENTRY_STRINGS":
                    # A different successful exec with unknown arguments may
                    # destroy uniqueness. Exclude it only by incompatible
                    # positively observed argument bytes/count, never by label.
                    could_match = len(encoded) >= entry["argc"]
                    if not entry["flags"] & (4 | 8 | 16) and len(encoded) != entry["argc"]:
                        could_match = False
                    for index, (value, status) in enumerate(zip(entry["argv_hex"], entry["argv_flags"])):
                        if index >= len(encoded): could_match = False; break
                        if status == 1 and value != encoded[index]: could_match = False
                        if status == 2 and not encoded[index].startswith(value): could_match = False
                    possible_incomplete += bool(could_match)
        status = ("NO_PARSEABLE_NATIVE_COMMAND" if encoded is None else "NO_EXACT_ARGV_MATCH" if not matches else
            "AMBIGUOUS_EXACT_ARGV_MATCH" if len(matches) != 1 else
            "EXACT_ARGV_CANDIDATE_OTHER_EXEC_ARGV_INCOMPLETE" if possible_incomplete else
            "KERNEL_ARGV_CODEX_SNAPSHOT_PROJECTED_CORRELATED" if healthy and projection else
            "KERNEL_ARGV_EXACT_CORRELATED" if healthy else "EXACT_ARGV_CANDIDATE_CAPTURE_INCOMPLETE")
        rows.append({"call_id": call_id, "status": status, "candidate_count": len(matches),
            "incomplete_potential_matches": possible_incomplete,
            "argv_projection": projection,
            "application_result_delivered_ns": call.get("result_delivered_ns"),
            "candidates": [{"entry_wal_offset": item["entry"]["wal_offset"],
                "success_wal_offset": item["success"]["wal_offset"], "entry_ns": item["entry"]["entry_ns"],
                "tid": item["entry"]["tid"], "tgid": item["entry"]["tgid"],
                "thread_birth_ns": item["entry"]["thread_birth_ns"],
                "process_birth_ns": item["entry"]["process_birth_ns"], "boot_id": replay["boot_id"],
                "cgroup_id": replay["cgroup_id"]} for item in matches],
            "meaning": ("Versioned Codex snapshot flag projection with exact remaining argument bytes; not exact unchanged argv, TOCTOU immunity, or strong causal attribution" if projection else
                        "Exact entry argv correlation, not TOCTOU immunity, final argv, or strong causal attribution")})
    uses = Counter(row["candidates"][0]["entry_wal_offset"] for row in rows if row["candidate_count"] == 1)
    for row in rows:
        if row["candidate_count"] == 1 and uses[row["candidates"][0]["entry_wal_offset"]] > 1:
            row["status"] = "AMBIGUOUS_APPLICATION_CALLS_CLAIM_SAME_EXEC"
    return {"schema_version": 1, "kind": "NATIVE_TOOL_KERNEL_ARGV_CORRELATION", "calls": rows,
            "history_status": replay.get("history_status"), "core_syscall_count_increment": 0}


def correlate_core_scopes(correlations, replay, report, core_verification=None):
    """Join argv correlations to core exec identities and explicit fork ancestry.

    This helper does not run the core verifier. The caller must supply its
    independently checked REPLAY_PASSED receipt. Exact lifetime identities and
    complete equal-count ordered successful-exec sequences are required; nearby timestamps
    and the shared Agent cgroup never establish a tool owner. Kernel exec/fork
    boundaries delimit ranges only AFTER this identity join. References, not
    duplicate syscall events, are returned. Non-leader de-thread is unsupported.
    """
    output = {"schema_version": 1, "kind": "ARGV_AND_CORE_EXEC_LIFETIME_CORRELATION", "calls": [],
        "core_syscall_count_increment": 0,
        "core_verification": "CALLER_SUPPLIED_RECEIPT_NOT_RERUN_BY_THIS_HELPER",
        "meaning": "CORRELATED_EXECUTION_SUBTREE_NOT_STRONG_AGENT_CAUSAL_ATTRIBUTION"}
    run, health = report.get("run") or {}, report.get("health") or {}
    counters = health.get("counters") or {}
    gate = None
    if not isinstance(core_verification, dict) or core_verification.get("status") != "REPLAY_PASSED":
        gate = "CORE_INDEPENDENT_REPLAY_RECEIPT_REQUIRED"
    elif run.get("boot_id") != replay.get("boot_id"):
        gate = "CORE_SIDECAR_BOOT_MISMATCH"
    elif health.get("status") != "COMPLETE_FOR_SELECTED_HOOKS" or any(
            health.get(name, 0) for name in ("parse_errors", "write_errors", "cap_discarded", "sequence_errors", "truncated_tail",
                                            "recursion_misses", "program_info_errors")) or any(
            counters.get(name, 0) for name in ("ring_drops", "identity_read_errors", "context_full", "context_collision")):
        gate = "CORE_EXEC_IDENTITY_COVERAGE_INCOMPLETE"
    threads, by_key = report.get("threads") or [], {}
    for index, thread in enumerate(threads):
        key = thread.get("key")
        if not isinstance(key, str) or key in by_key: raise ValueError("unique core thread lifetime keys required")
        by_key[key] = (index, thread)
    roots = {}
    for call in correlations.get("calls") or []:
        row = {"call_id": call["call_id"], "status": gate or call.get("status"),
               "thread_ranges": [], "syscall_count": 0, "core_exec_refs": []}
        output["calls"].append(row)
        accepted_statuses = ("KERNEL_ARGV_EXACT_CORRELATED", "KERNEL_ARGV_CODEX_SNAPSHOT_PROJECTED_CORRELATED")
        if gate or call.get("status") not in accepted_statuses: continue
        candidates = call.get("candidates") or []
        if len(candidates) != 1:
            row["status"] = "AMBIGUOUS_ARGV_CANDIDATE"; continue
        candidate = candidates[0]
        source_execs = [execution for execution in replay.get("executions") or []
            if execution["entry"]["wal_offset"] == candidate.get("entry_wal_offset")
            and execution["success"]["wal_offset"] == candidate.get("success_wal_offset")]
        if len(source_execs) != 1 or any(candidate.get(field) != source_execs[0]["entry"].get(field)
                for field in ("entry_ns", "tid", "tgid", "thread_birth_ns", "process_birth_ns", "boot_id", "cgroup_id")):
            row["status"] = "ARGV_CORRELATION_NOT_BOUND_TO_REPLAY"; continue
        if candidate.get("tid") != candidate.get("tgid"):
            row["status"] = "NONLEADER_DETHREAD_SCOPE_UNSUPPORTED"; continue
        matches = [(index, thread) for index, thread in enumerate(threads)
            if thread.get("tid") == candidate.get("tid") and thread.get("tgid") == candidate.get("tgid")
            and thread.get("birth_ns") == candidate.get("thread_birth_ns")
            and thread.get("process_birth_ns") == candidate.get("process_birth_ns")]
        if len(matches) != 1:
            row["status"] = "CORE_THREAD_LIFETIME_MISSING_OR_AMBIGUOUS"; continue
        index, thread = matches[0]
        expected_key = "{}:{}:{}".format(replay["boot_id"], thread["tid"], thread["birth_ns"])
        if thread["key"] != expected_key:
            row["status"] = "CORE_THREAD_KEY_CONFLICT"; continue
        execs = thread.get("execs") or []
        valid_execs = [(exec_index, event) for exec_index, event in enumerate(execs)
            if type(event.get("timestamp_ns")) is int and event.get("evidence") == "KERNEL_SCHED_PROCESS_EXEC_SUCCESS"
            and event.get("old_tid") in (None, 0, candidate["tid"])]
        side_execs = [execution for execution in replay.get("executions") or [] if
            all(execution["entry"].get(field) == candidate.get(field) for field in
                ("tid", "tgid", "thread_birth_ns", "process_birth_ns"))]
        side_execs.sort(key=lambda execution: execution["success"]["timestamp_ns"])
        valid_execs.sort(key=lambda value: value[1]["timestamp_ns"])
        if len(execs) != len(valid_execs) or len(valid_execs) != len(side_execs) or not valid_execs:
            row["status"] = "CORE_SIDECAR_SUCCESSFUL_EXEC_SEQUENCE_COUNT_MISMATCH"; continue
        selected = [position for position, execution in enumerate(side_execs) if
            execution["entry"]["wal_offset"] == candidate["entry_wal_offset"]]
        if (len(selected) != 1 or any(a[1]["timestamp_ns"] >= b[1]["timestamp_ns"] for a, b in zip(valid_execs, valid_execs[1:])) or
                any(a["success"]["timestamp_ns"] >= b["success"]["timestamp_ns"] for a, b in zip(side_execs, side_execs[1:]))):
            row["status"] = "CORE_SUCCESSFUL_EXEC_SEQUENCE_AMBIGUOUS"; continue
        exec_index, event = valid_execs[selected[0]]
        completion = call.get("application_result_delivered_ns")
        if len(valid_execs) > 1 and (type(thread.get("exit_ns")) is not int or type(completion) is not int or
                                     thread["exit_ns"] > completion):
            row["status"] = "MULTI_EXEC_SCOPE_REQUIRES_KERNEL_EXIT_BEFORE_APP_COMPLETION"; continue
        row["exec_sequence_alignment"] = {"method": "EXACT_LIFETIME_EQUAL_COUNT_ORDERED_SUCCESS_SEQUENCE_NOT_NEAREST_TIME",
            "count": len(valid_execs), "matched_position": selected[0],
            "sidecar_entry_offsets": [execution["entry"]["wal_offset"] for execution in side_execs],
            "core_exec_indices": [index for index, _ in valid_execs]}
        row["core_exec_refs"] = ["report#/threads/{}/execs/{}".format(index, exec_index)]
        row["root_thread_key"] = thread["key"]
        row["root_exec_timestamp_ns"] = event["timestamp_ns"]
        row["argv_evidence"] = candidate
        row["argv_projection"] = call.get("argv_projection")
        row["status"] = ("KERNEL_ARGV_SNAPSHOT_PROJECTED_AND_CORE_EXEC_IDENTITY_CORRELATED" if call.get("argv_projection") else
                         "KERNEL_ARGV_AND_CORE_EXEC_IDENTITY_CORRELATED")
        if thread["key"] in roots:
            row["status"] = "AMBIGUOUS_TOOLS_CLAIM_SAME_CORE_ROOT"
            roots[thread["key"]][0]["status"] = row["status"]
        else:
            roots[thread["key"]] = (row, event["timestamp_ns"])
    roots = {key: value for key, value in roots.items() if value[0]["status"] in (
        "KERNEL_ARGV_AND_CORE_EXEC_IDENTITY_CORRELATED", "KERNEL_ARGV_SNAPSHOT_PROJECTED_AND_CORE_EXEC_IDENTITY_CORRELATED")}

    def fork_parent(thread):
        parent_key, fork = thread.get("parent_key"), thread.get("fork_event") or {}
        if parent_key not in by_key or fork.get("event") != "FORK" or fork.get("peer_quality") != "STABLE_TASK_IDENTITY":
            return None
        parent = by_key[parent_key][1]; peer, child = fork.get("peer") or {}, fork.get("task") or {}
        if any(peer.get(field) != parent.get(target) for field, target in
               (("tid", "tid"), ("tgid", "tgid"), ("thread_birth_ns", "birth_ns"), ("process_birth_ns", "process_birth_ns"))):
            return None
        if any(child.get(field) != thread.get(target) for field, target in
               (("tid", "tid"), ("tgid", "tgid"), ("thread_birth_ns", "birth_ns"), ("process_birth_ns", "process_birth_ns"))):
            return None
        if peer.get("cgroup_id") != replay["cgroup_id"] or child.get("cgroup_id") != replay["cgroup_id"]:
            return None
        return parent_key

    assigned = set()
    for index, thread in enumerate(threads):
        chain, key, owner, begin = [], thread["key"], None, None
        while key in by_key and key not in chain:
            chain.append(key)
            if key in roots:
                owner, root_begin = roots[key]
                if len(chain) == 1:
                    begin = root_begin
                else:
                    # Every edge is an explicit stable-identity FORK, not a
                    # same-cgroup or temporal-proximity relationship.
                    forks = [(by_key[child][1].get("fork_event") or {}).get("timestamp_ns") for child in chain[:-1]]
                    if any(type(timestamp) is not int or timestamp < root_begin for timestamp in forks):
                        owner = None; break
                    begin = (thread.get("fork_event") or {})["timestamp_ns"]
                break
            parent = fork_parent(by_key[key][1])
            if parent is None: break
            key = parent
        if owner is None: continue
        end = thread.get("end_ns", run.get("end_ns"))
        if type(end) is not int or end < begin: continue
        call_indices = []
        for call_index, syscall in enumerate(thread.get("calls") or []):
            # The exec/fork event is a measured image/lifetime boundary. A
            # syscall crossing it is kept unassigned, not split or guessed.
            start, finish = syscall.get("start_ns"), syscall.get("end_ns")
            if type(start) is int and type(finish) is int and begin <= start <= finish <= end:
                identity = (thread["key"], call_index)
                if identity in assigned: raise ValueError("core syscall assigned to multiple tool scopes")
                assigned.add(identity); call_indices.append(call_index)
        owner["thread_ranges"].append({"thread_key": thread["key"], "thread_ref": "report#/threads/" + str(index),
            "scope_begin_ns": begin, "scope_end_ns": end, "call_indices": call_indices,
            "ancestry_keys": chain, "boundary_basis": "EXACT_CORE_EXEC_OR_STABLE_IDENTITY_FORK"})
        owner["syscall_count"] += len(call_indices)
    output["correlated_syscall_references"] = len(assigned)
    output["scope"] = "POST_MATCHED_EXEC_AND_VERIFIED_FORK_DESCENDANTS; MOST_SPECIFIC_MATCHED_ROOT_WINS"
    return output


class ExecArgsSidecar:
    def __init__(self, collector, object_path, cgroup_id, directory, max_bytes=MAX_WAL_BYTES):
        self.collector, self.object_path = Path(collector), Path(object_path)
        self.cgroup_id, self.directory, self.max_bytes = cgroup_id, Path(directory), max_bytes
        self.process = None

    def start(self, timeout=15):
        if self.directory.exists(): raise ValueError("sidecar output directory must be new")
        self.process = subprocess.Popen([str(self.collector), "--object", str(self.object_path),
            "--cgroup-id", str(self.cgroup_id), "--output", str(self.directory), "--max-bytes", str(self.max_bytes)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if (self.directory / "ready.json").exists():
                ready = json.loads((self.directory / "ready.json").read_text())
                if ready.get("status") == "READY" and ready.get("cgroup_id") == self.cgroup_id: return self
            if self.process.poll() is not None:
                error = self.process.stderr.read(12000).decode("utf-8", "replace")
                raise RuntimeError("exec argv sidecar failed before READY: " + error)
            time.sleep(.025)
        self.process.terminate()
        try: self.process.wait(timeout=2)
        except subprocess.TimeoutExpired: self.process.kill(); self.process.wait()
        raise RuntimeError("exec argv sidecar readiness timeout")

    def stop(self):
        if self.process is None: raise ValueError("sidecar not started")
        if self.process.poll() is None: self.process.send_signal(signal.SIGTERM)
        try: _, errors = self.process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill(); _, errors = self.process.communicate()
            raise RuntimeError("sidecar did not finalize; raw WAL remains incomplete")
        if self.process.returncode:
            raise RuntimeError("sidecar capture failed: " + errors[:12000].decode("utf-8", "replace"))
        return verify_capture(self.directory, max_bytes=self.max_bytes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--application", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    replay = verify_capture(args.capture)
    if args.application:
        app = json.loads(args.application.read_text())
        replay["tool_correlations"] = correlate_commands(app.get("tool_calls") or [], replay)
    write_new(args.output, replay)
    print(json.dumps({"status": replay["status"], "history_status": replay["history_status"],
                      "counts": replay["record_counts"], "executions": len(replay["executions"])}))


if __name__ == "__main__": main()
