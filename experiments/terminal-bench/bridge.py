#!/usr/bin/env python3
"""Strict Harbor/Docker lifecycle bridge for the deployment observer.

This module intentionally uses only public Harbor Trial construction and hook
APIs.  The hook closures retain the Trial object because Harbor's hook event
does not expose a live environment handle.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import signal
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, NoReturn, Sequence


PROTOCOL_VERSION = 2
SUPPORTED_HARBOR_VERSION = "0.23.0"
SUPPORTED_HARBOR_SOURCE_REVISION = "26f5d8f423786d55a25c5ef4f0eb5869e93ad2df"
DOCKER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
NONCE_RE = DOCKER_ID_RE
CGROUP_COMPONENT_PATTERNS = (
    "{container_id}",
    "docker-{container_id}.scope",
    "cri-containerd-{container_id}.scope",
    "crio-{container_id}.scope",
    "libpod-{container_id}.scope",
)
SYSCTL_KEYS = (
    "kernel/domainname",
    "kernel/hostname",
    "kernel/modules_disabled",
    "kernel/unprivileged_bpf_disabled",
    "net/ipv4/conf/all/forwarding",
    "net/ipv4/ip_forward",
    "net/ipv4/tcp_syncookies",
    "net/ipv6/conf/all/forwarding",
)
MAX_NETWORK_INTERFACES = 1024
MAX_PROC_NET_DEV_BYTES = 1024 * 1024


def bpf_program_map_scope() -> dict[str, Any]:
    """Return the explicit metadata-only BPF endpoint scope for this campaign."""
    return {
        "event_interfaces": ["BPF_USER_SYSCALL"],
        # Deployment endpoint confirmation does not claim complete bpf(2)
        # command evidence. The system-effect WAL remains a separate channel.
        "allowed_bpf_commands": [],
        "object_types": ["PROGRAM", "MAP"],
        "map_content_types": [],
        "map_ids": [],
        "bpffs_roots": [],
        "attachment_targets": [],
        "budget": {
            "max_map_entries": 65_536,
            "max_map_bytes": 64 * 1024 * 1024,
            "per_map_deadline_ms": 5_000,
        },
    }


class BridgeError(RuntimeError):
    """Fail-closed integration error."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def write_new_json(path: Path, value: Any) -> None:
    write_new_bytes(path, canonical_json_bytes(value))


def write_new_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def replace_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(canonical_json_bytes(value))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise BridgeError(f"trusted input is not a singly-linked regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
            after = os.fstat(source.fileno())
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise BridgeError(f"trusted input changed while hashing: {path}")
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return digest.hexdigest()


def read_json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeError(f"cannot read canonical {label}: {path}: {error}") from error
    if not isinstance(value, dict):
        raise BridgeError(f"{label} must be a JSON object")
    return value


def _safe_task_input(task: Path, relative: str) -> Path:
    candidate = task / relative
    resolved = candidate.resolve(strict=True)
    task_root = task.resolve(strict=True)
    if task_root not in resolved.parents:
        raise BridgeError(f"task input escapes task root: {relative}")
    if candidate.is_symlink():
        raise BridgeError(f"task input must not be a symlink: {relative}")
    return resolved


def _source_input_paths(task: Path) -> list[str]:
    selected = ["instruction.md", "task.toml"]
    environment = task / "environment"
    if not environment.is_dir() or environment.is_symlink():
        raise BridgeError(f"task has no ordinary environment directory: {task}")
    for path in environment.rglob("*"):
        if path.is_symlink():
            raise BridgeError(f"task environment contains a symlink: {path}")
        if path.is_file():
            selected.append(path.relative_to(task).as_posix())
    return sorted(selected, key=lambda value: value.encode("utf-8"))


def _task_name_from_toml(path: Path) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise BridgeError(f"cannot read task metadata: {path}") from error
    in_task = False
    names: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_task = stripped == "[task]"
            continue
        if not in_task:
            continue
        match = re.fullmatch(r'name\s*=\s*"([^"\\]+)"\s*', stripped)
        if match:
            names.append(match.group(1))
    if len(names) != 1:
        raise BridgeError(f"task metadata must contain one simple [task].name: {path}")
    return names[0]


def validate_selection_manifest(
    manifest_path: Path,
    expected_sha256: str,
    task_arguments: Sequence[Path],
) -> dict[str, Any]:
    manifest_path = validate_trusted_file(
        manifest_path, expected_sha256, "selection manifest"
    )
    manifest = read_json_file(manifest_path, "selection manifest")
    if manifest.get("schema_version") != 1:
        raise BridgeError("selection manifest schema_version must be 1")
    assertion = manifest.get("planned_count_assertion")
    records = manifest.get("tasks")
    if not isinstance(assertion, dict) or not isinstance(records, list):
        raise BridgeError("selection manifest lacks task/count assertions")
    expected_count = assertion.get("planned_count")
    expected_names = assertion.get("resolved_task_names_must_equal_in_order")
    if (
        assertion.get("mode") != "EXACT_COUNT_SET_AND_ORDER"
        or not isinstance(expected_count, int)
        or expected_count < 1
        or assertion.get("resolved_task_count_must_equal") != expected_count
        or assertion.get("resolved_task_names_must_be_unique") is not True
        or assertion.get("reject_additional_tasks") is not True
        or not isinstance(expected_names, list)
        or len(expected_names) != expected_count
        or len(set(expected_names)) != expected_count
        or len(records) != expected_count
        or len(task_arguments) != expected_count
    ):
        raise BridgeError("selection manifest exact-count contract is inconsistent")

    observed_names: list[str] = []
    aggregate_results: list[dict[str, Any]] = []
    for index, (argument, record) in enumerate(zip(task_arguments, records), 1):
        if not isinstance(record, dict) or record.get("order") != index:
            raise BridgeError(f"selection task record {index} is malformed")
        task = argument.resolve(strict=True)
        if not task.is_dir() or task.name != record.get("directory"):
            raise BridgeError(f"task {index} directory does not match selection manifest")
        task_name = _task_name_from_toml(task / "task.toml")
        if (
            not isinstance(task_name, str)
            or task_name != record.get("name")
            or task_name != expected_names[index - 1]
        ):
            raise BridgeError(f"task {index} name/order does not match selection manifest")
        source_inputs = record.get("source_inputs")
        if not isinstance(source_inputs, list):
            raise BridgeError(f"task {task_name} lacks source_inputs")
        expected_inputs: dict[str, str] = {}
        for item in source_inputs:
            if not isinstance(item, dict):
                raise BridgeError(f"task {task_name} has a malformed source input")
            relative = item.get("path")
            digest = item.get("sha256")
            if (
                not isinstance(relative, str)
                or relative.startswith("/")
                or not isinstance(digest, str)
                or not DOCKER_ID_RE.fullmatch(digest)
                or relative in expected_inputs
            ):
                raise BridgeError(f"task {task_name} has an invalid source input record")
            expected_inputs[relative] = digest
        actual_paths = _source_input_paths(task)
        if actual_paths != sorted(
            expected_inputs, key=lambda value: value.encode("utf-8")
        ):
            raise BridgeError(f"task {task_name} source input set changed")
        encoded_entries = bytearray()
        for relative in actual_paths:
            digest = sha256_file(_safe_task_input(task, relative))
            if digest != expected_inputs[relative]:
                raise BridgeError(f"task {task_name} source input changed: {relative}")
            encoded_entries.extend(f"{digest}  {relative}\n".encode("utf-8"))
        aggregate = hashlib.sha256(encoded_entries).hexdigest()
        if aggregate != record.get("source_input_manifest_sha256"):
            raise BridgeError(f"task {task_name} aggregate source-input digest changed")
        observed_names.append(task_name)
        aggregate_results.append(
            {"name": task_name, "source_input_manifest_sha256": aggregate}
        )
    if observed_names != expected_names:
        raise BridgeError("resolved task set/order changed")
    dataset = manifest.get("dataset")
    if not isinstance(dataset, dict) or not GIT_COMMIT_RE.fullmatch(
        str(dataset.get("git_commit", ""))
    ):
        raise BridgeError("selection manifest lacks a pinned dataset commit")
    # Detect replacement while the comparatively expensive task input validation
    # was in progress. validate_trusted_file also checks file type/link count and
    # detects mutation during each individual hash pass.
    validate_trusted_file(manifest_path, expected_sha256, "selection manifest")
    return {
        "selection_manifest_path": str(manifest_path),
        "selection_manifest_sha256": expected_sha256,
        "selection_id": manifest.get("selection_id"),
        "dataset": dataset,
        "tasks": aggregate_results,
    }


def validate_trusted_file(path: Path, expected_sha256: str, label: str) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_absolute():
        raise BridgeError(f"{label} path is not absolute")
    if not DOCKER_ID_RE.fullmatch(expected_sha256):
        raise BridgeError(f"{label} SHA-256 must be 64 lowercase hexadecimal bytes")
    observed = sha256_file(resolved)
    if observed != expected_sha256:
        raise BridgeError(
            f"{label} SHA-256 mismatch: expected {expected_sha256}, observed {observed}"
        )
    return resolved


def validate_network_collector(path: Path, expected_sha256: str, label: str) -> Path:
    """Apply the confirmer's immutable, root-owned ELF collector contract early."""
    resolved = validate_trusted_file(path, expected_sha256, label)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(resolved, flags)
    try:
        metadata = os.fstat(descriptor)
        magic = os.read(descriptor, 4)
    finally:
        os.close(descriptor)
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise BridgeError(f"{label} must be root-owned and not group/other writable")
    if metadata.st_mode & 0o111 == 0:
        raise BridgeError(f"{label} must be executable")
    if metadata.st_size <= 0 or metadata.st_size > 256 * 1024 * 1024:
        raise BridgeError(f"{label} size is outside the confirmer hard bound")
    if magic != b"\x7fELF":
        raise BridgeError(f"{label} must be an ELF binary")
    return resolved


def sanitize_compose_project_name(session_id: str) -> str:
    value = session_id.lower()
    if not value or not re.match(r"^[a-z0-9]", value):
        value = "0" + value
    return re.sub(r"[^a-z0-9_-]", "-", value)


def parse_proc_cgroup(text: str) -> str:
    paths: list[str] = []
    for raw_line in text.splitlines():
        fields = raw_line.split(":", 2)
        if len(fields) != 3:
            raise BridgeError("/proc PID cgroup contains a malformed line")
        hierarchy, controllers, path = fields
        if hierarchy == "0" and controllers == "":
            paths.append(path)
    if len(paths) != 1:
        raise BridgeError("target PID does not have exactly one cgroup-v2 membership")
    path = paths[0]
    if not path.startswith("/") or "//" in path or path.endswith("/"):
        raise BridgeError("target cgroup-v2 path is not canonical and non-root")
    if path == "/" or any(component in ("", ".", "..") for component in path[1:].split("/")):
        raise BridgeError("refusing host/root or non-canonical cgroup path")
    return path


def parse_proc_net_dev(text: str) -> tuple[str, ...]:
    """Return the complete, canonical interface set from procfs net/dev."""
    lines = text.splitlines()
    if (
        len(lines) < 2
        or not lines[0].strip().startswith("Inter-|")
        or "face |bytes" not in lines[1]
    ):
        raise BridgeError("target /proc PID net/dev has malformed headers")
    interfaces: set[str] = set()
    for raw_line in lines[2:]:
        if not raw_line.strip():
            continue
        name_field, separator, counters = raw_line.rpartition(":")
        name = name_field.strip()
        values = counters.split()
        if (
            separator != ":"
            or not name
            or len(name.encode("ascii", errors="ignore")) != len(name)
            or len(name) > 15
            or any(
                not (character.isalnum() or character in "_-.:@")
                for character in name
            )
            or len(values) != 16
            or any(not value.isdecimal() for value in values)
        ):
            raise BridgeError("target /proc PID net/dev contains a malformed interface record")
        if name in interfaces:
            raise BridgeError("target /proc PID net/dev contains duplicate interfaces")
        interfaces.add(name)
    if not interfaces or len(interfaces) > MAX_NETWORK_INTERFACES:
        raise BridgeError("target network interface set is empty or exceeds its bound")
    return tuple(sorted(interfaces, key=lambda value: value.encode("ascii")))


def read_bounded_proc_text(path: Path, label: str, maximum: int) -> str:
    if maximum <= 0:
        raise BridgeError(f"{label} byte bound must be positive")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise BridgeError(f"{label} exceeds its {maximum}-byte bound")
    finally:
        os.close(descriptor)
    try:
        return b"".join(chunks).decode("ascii")
    except UnicodeDecodeError as error:
        raise BridgeError(f"{label} is not ASCII procfs data") from error


def absolute_path_bytes_hex(path: Path, label: str) -> str:
    if not path.is_absolute() or b"\x00" in os.fsencode(path):
        raise BridgeError(f"{label} must be an absolute path without NUL bytes")
    return os.fsencode(path).hex()


def validate_sha256(value: str, label: str) -> None:
    if not DOCKER_ID_RE.fullmatch(value):
        raise BridgeError(f"{label} must be 64 lowercase hexadecimal bytes")


def validate_network_interfaces(interfaces: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(interfaces)
    if not normalized or len(normalized) > MAX_NETWORK_INTERFACES:
        raise BridgeError("network interface scope is empty or exceeds its bound")
    for name in normalized:
        try:
            encoded = name.encode("ascii")
        except UnicodeEncodeError as error:
            raise BridgeError("network interface name must be ASCII") from error
        if (
            not encoded
            or len(encoded) > 15
            or any(
                not (
                    0x30 <= byte <= 0x39
                    or 0x41 <= byte <= 0x5A
                    or 0x61 <= byte <= 0x7A
                    or byte in b"_-.:@"
                )
                for byte in encoded
            )
        ):
            raise BridgeError("network interface name is invalid or exceeds IFNAMSIZ-1")
    if normalized != tuple(sorted(set(normalized), key=lambda value: value.encode("ascii"))):
        raise BridgeError("network interfaces must be strictly sorted and unique")
    return normalized


def cgroup_binds_container(cgroup_path: str, container_id: str) -> bool:
    if not DOCKER_ID_RE.fullmatch(container_id):
        return False
    allowed = {
        pattern.format(container_id=container_id)
        for pattern in CGROUP_COMPONENT_PATTERNS
    }
    return any(component in allowed for component in cgroup_path.split("/"))


def parse_docker_id_lines(raw: bytes) -> list[str]:
    identities: list[str] = []
    for line in raw.splitlines():
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise BridgeError("docker ps returned malformed container identity") from error
        if not isinstance(value, str) or not DOCKER_ID_RE.fullmatch(value):
            raise BridgeError("docker ps did not return a full 64-hex container ID")
        identities.append(value)
    if len(set(identities)) != len(identities):
        raise BridgeError("docker ps returned duplicate container identities")
    return identities


def parse_single_json_line(raw: bytes, label: str, maximum: int = 1024 * 1024) -> dict[str, Any]:
    if not raw or len(raw) > maximum or not raw.endswith(b"\n"):
        raise BridgeError(f"{label} is empty, unterminated, or exceeds {maximum} bytes")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeError(f"{label} is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise BridgeError(f"{label} must be a JSON object")
    return value


def validate_ready(
    value: dict[str, Any],
    *,
    run_id: str,
    epoch: int,
    effect_sha256: str,
    lifecycle_sha256: str,
    expected_cgroup_id: int,
) -> str:
    if value.get("protocol_version") != PROTOCOL_VERSION or value.get("status") != "READY":
        raise BridgeError("observer did not emit protocol-v2 READY")
    if value.get("run_id") != run_id or value.get("epoch") != epoch:
        raise BridgeError("READY run identity mismatch")
    if value.get("recorder_object_sha256") != effect_sha256:
        raise BridgeError("READY system-effect object digest mismatch")
    if value.get("lifecycle_object_sha256") != lifecycle_sha256:
        raise BridgeError("READY lifecycle object digest mismatch")
    if value.get("socket_state_enabled") is not True:
        raise BridgeError("READY did not enable expanded socket-state evidence")
    registrations = value.get("registration_cgroup_ids")
    if registrations != [expected_cgroup_id]:
        raise BridgeError("READY root cgroup ID does not match the frozen Docker root")
    capability = value.get("cgroup_scope_capability")
    if not isinstance(capability, dict):
        raise BridgeError("READY lacks cgroup scope capability")
    if (
        capability.get("mode") != "CGROUP_V2_ANCESTOR_ROOT"
        or capability.get("membership_authority") != "BPF_CURRENT_TASK_UNDER_CGROUP"
        or capability.get("dynamic_descendants_including_ephemeral") is not True
        or capability.get("root_cgroup_ids") != registrations
    ):
        raise BridgeError("READY cgroup ancestor capability is insufficient")
    for name in (
        "deployment_scope_sha256",
        "cgroup_scope_capability_sha256",
        "deployment_manifest_sha256",
        "ready_barrier_sha256",
        "ready_validation_sha256",
        "bpf_state_scope_sha256",
        "bpf_state_s0_sha256",
        "filesystem_state_scope_sha256",
        "filesystem_state_s0_sha256",
        "linux_state_scope_sha256",
        "linux_state_s0_sha256",
    ):
        if not isinstance(value.get(name), str) or not DOCKER_ID_RE.fullmatch(value[name]):
            raise BridgeError(f"READY lacks canonical {name}")
    nonce = value.get("finish_nonce")
    if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
        raise BridgeError("READY finish nonce is invalid")
    return nonce


def validate_finished(value: dict[str, Any], *, run_id: str) -> tuple[str, str]:
    if value.get("protocol_version") != PROTOCOL_VERSION or value.get("status") != "FINISHED":
        raise BridgeError("observer did not emit protocol-v2 FINISHED")
    if value.get("run_id") != run_id:
        raise BridgeError("FINISHED run identity mismatch")
    report = value.get("report_sha256")
    manifest = value.get("artifact_manifest_sha256")
    if not isinstance(report, str) or not DOCKER_ID_RE.fullmatch(report):
        raise BridgeError("FINISHED report SHA-256 is invalid")
    if not isinstance(manifest, str) or not DOCKER_ID_RE.fullmatch(manifest):
        raise BridgeError("FINISHED artifact-manifest SHA-256 is invalid")
    return report, manifest


def capture_limits(*, max_records: int = 16384) -> dict[str, int]:
    return {
        "max_records": max_records,
        "max_value_bytes": 4 * 1024 * 1024,
        "max_total_value_bytes": 16 * 1024 * 1024,
        "deadline_ms": 30_000,
    }


def build_observer_config(
    *,
    container_id: str,
    init_pid: int,
    cgroup_path: str,
    mount_namespace_inode: int,
    network_namespace_inode: int,
    network_interfaces: Sequence[str],
    ip_binary: Path,
    ip_sha256: str,
    tc_binary: Path,
    tc_sha256: str,
    nft_binary: Path,
    nft_sha256: str,
    recorder_object: Path,
    recorder_sha256: str,
    lifecycle_object: Path,
    lifecycle_sha256: str,
    output_directory: Path,
    run_id: str,
    epoch: int,
) -> dict[str, Any]:
    if not DOCKER_ID_RE.fullmatch(container_id):
        raise BridgeError("Docker container ID is not full 64-hex identity")
    if (
        init_pid <= 0
        or mount_namespace_inode <= 0
        or network_namespace_inode <= 0
        or epoch <= 0
    ):
        raise BridgeError("Docker PID, namespace inode, and epoch must be nonzero")
    if not cgroup_binds_container(cgroup_path, container_id):
        raise BridgeError("Docker cgroup path is not bound to the full container ID")
    network_interfaces = validate_network_interfaces(network_interfaces)
    validate_sha256(ip_sha256, "ip SHA-256")
    validate_sha256(tc_sha256, "tc SHA-256")
    validate_sha256(nft_sha256, "nft SHA-256")
    ip_binary_hex = absolute_path_bytes_hex(ip_binary, "ip binary")
    tc_binary_hex = absolute_path_bytes_hex(tc_binary, "tc binary")
    nft_binary_hex = absolute_path_bytes_hex(nft_binary, "nft binary")
    return {
        "protocol_version": PROTOCOL_VERSION,
        "deployment": {
            "deployment_kind": "DOCKER",
            "configuration": {
                "container_id": container_id,
                "init_pid": init_pid,
                "expected_cgroup_path": cgroup_path,
                "limits": {
                    "max_proc_entries": 131_072,
                    "max_cgroup_nodes": 4096,
                    "max_cgroup_depth": 64,
                    "max_open_fds_per_process": 8192,
                },
            },
        },
        "recorder_object_path": str(recorder_object),
        "recorder_object_sha256": recorder_sha256,
        "lifecycle_object_path": str(lifecycle_object),
        "lifecycle_object_sha256": lifecycle_sha256,
        "output_directory": str(output_directory),
        "run_id": run_id,
        "epoch": epoch,
        "profile": "full",
        "object_resolution_mode": "KERNEL_OBJECT_EXPANDED_PARTIAL",
        "bpf_state_scope": bpf_program_map_scope(),
        "filesystem_state_scope": {
            "protocol_version": 1,
            "roots": [{"path_bytes_hex": "/app".encode().hex()}],
            "capture": {
                "regular_file_content": "SHA256",
                "symlinks": "TARGET_BYTES",
                "xattrs": "NAMES_AND_VALUE_SHA256",
                "cross_filesystems": "SAME_DEVICE_ONLY",
            },
            "limits": {
                "max_entries": 65_536,
                "max_total_path_bytes": 64 * 1024 * 1024,
                "max_file_content_bytes": 64 * 1024 * 1024,
                "max_total_content_bytes": 256 * 1024 * 1024,
                "max_xattr_list_bytes": 1024 * 1024,
                "max_xattrs_per_entry": 1024,
                "max_total_xattrs": 262_144,
                "max_xattr_value_bytes": 4 * 1024 * 1024,
                "max_total_xattr_bytes": 64 * 1024 * 1024,
                "max_symlink_target_bytes": 4096,
                "max_depth": 256,
                "deadline_ms": 60_000,
            },
        },
        # One explicit mount domain makes the scope independently valid.  The
        # deployment adapter adds the exact recursive process-residual domain.
        "linux_state_scope": {
            "protocol_version": 1,
            "sysctl": {
                "proc_sys_root_bytes_hex": os.fsencode("/proc/sys").hex(),
                "keys": list(SYSCTL_KEYS),
                "evidence": "BYTES_AND_SHA256",
                "limits": capture_limits(max_records=16),
            },
            "mounts": {
                "namespace": {
                    "pid": init_pid,
                    "expected_namespace_inode": mount_namespace_inode,
                },
                "evidence": "BYTES_AND_SHA256",
                "limits": capture_limits(max_records=65_536),
            },
            "network": {
                "namespace": {
                    "pid": init_pid,
                    "expected_namespace_inode": network_namespace_inode,
                },
                "collectors": {
                    "addresses": True,
                    "routes": True,
                    "rules": True,
                    "traffic_control": True,
                    "nftables": True,
                },
                "normalization": "NETWORK_CONFIGURATION_ONLY_V1",
                "ip_binary_bytes_hex": ip_binary_hex,
                "expected_ip_sha256": ip_sha256,
                "tc_binary_bytes_hex": tc_binary_hex,
                "expected_tc_sha256": tc_sha256,
                "nft_binary_bytes_hex": nft_binary_hex,
                "expected_nft_sha256": nft_sha256,
                "tc_interfaces": list(network_interfaces),
                "evidence": "BYTES_AND_SHA256",
                "limits": capture_limits(max_records=16_384),
            },
            "modules": {
                "proc_modules_path_bytes_hex": os.fsencode("/proc/modules").hex(),
                "sys_module_root_bytes_hex": os.fsencode("/sys/module").hex(),
                "selection": {"mode": "ALL_LOADED"},
                "capture_parameters": False,
                "evidence": "BYTES_AND_SHA256",
                "limits": capture_limits(max_records=16_384),
            },
            "process_residual": None,
        },
        "poll_interval_ms": 20,
        "drain_timeout_ms": 5000,
    }


async def run_command(
    *arguments: str,
    timeout: float,
    input_bytes: bytes | None = None,
) -> tuple[bytes, bytes]:
    return_code, stdout, stderr = await capture_command(
        *arguments, timeout=timeout, input_bytes=input_bytes
    )
    if return_code != 0:
        detail = stderr.decode("utf-8", errors="replace")[-4096:]
        raise BridgeError(f"command failed ({return_code}): {arguments!r}: {detail}")
    return stdout, stderr


async def capture_command(
    *arguments: str,
    timeout: float,
    input_bytes: bytes | None = None,
) -> tuple[int, bytes, bytes]:
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.PIPE if input_bytes is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(input_bytes), timeout=timeout)
    except BaseException:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        raise
    if process.returncode is None:
        raise BridgeError(f"command status is unavailable: {arguments!r}")
    return process.returncode, stdout, stderr


def persist_verifier_result(
    control_dir: Path,
    return_code: int,
    stdout: bytes,
    stderr: bytes,
) -> None:
    """Persist complete verifier diagnostics before interpreting its status."""
    write_new_bytes(control_dir / "verifier.stdout", stdout)
    write_new_bytes(control_dir / "verifier.stderr", stderr)
    if return_code != 0:
        detail = stderr.decode("utf-8", errors="replace")[-4096:]
        raise BridgeError(
            f"offline verifier failed ({return_code}); complete stdout/stderr are retained: {detail}"
        )


async def docker_json(*arguments: str, timeout: float = 30) -> Any:
    stdout, _ = await run_command("docker", *arguments, timeout=timeout)
    try:
        return json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeError(f"Docker returned invalid JSON for {arguments!r}") from error


@dataclass(frozen=True)
class DockerTarget:
    container_id: str
    init_pid: int
    cgroup_path: str
    cgroup_directory: Path
    cgroup_id: int
    mount_namespace_inode: int
    network_namespace_inode: int
    network_interfaces: tuple[str, ...]
    project: str


@dataclass
class ObserverRun:
    run_id: str
    epoch: int
    root: Path
    control_dir: Path
    output_dir: Path
    config_path: Path
    config: dict[str, Any]
    target: DockerTarget
    process: asyncio.subprocess.Process
    stderr_handle: Any
    finish_nonce: str
    paused_by_bridge: bool = False


@dataclass
class BridgeOptions:
    observer_binary: Path
    verifier_binary: Path
    recorder_object: Path
    recorder_sha256: str
    lifecycle_object: Path
    lifecycle_sha256: str
    ip_binary: Path
    ip_sha256: str
    tc_binary: Path
    tc_sha256: str
    nft_binary: Path
    nft_sha256: str
    evidence_root: Path
    ready_timeout: float
    finish_timeout: float
    docker_timeout: float


@dataclass
class TrialObserverBridge:
    trial: Any
    options: BridgeOptions
    task_label: str
    epoch: int = 1
    active: ObserverRun | None = None
    completed: list[dict[str, Any]] = field(default_factory=list)
    failure: str | None = None
    recovery_target: DockerTarget | None = None

    async def _docker_inspect(self, container_id: str) -> dict[str, Any]:
        value = await docker_json("inspect", container_id, timeout=self.options.docker_timeout)
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise BridgeError("docker inspect did not return exactly one object")
        return value[0]

    async def discover_target(self) -> DockerTarget:
        environment = self.trial.agent_environment
        network_plan = self.trial._network_plan(None)
        if network_plan.agent_phase != network_plan.agent_env_baseline:
            raise BridgeError(
                "Harbor dynamic Agent-phase network transition would contaminate the observation interval"
            )
        session_id = getattr(environment, "session_id", None)
        if not isinstance(session_id, str) or not session_id:
            raise BridgeError("Harbor Docker environment exposes no stable session_id")
        project = sanitize_compose_project_name(session_id)
        stdout, _ = await run_command(
            "docker",
            "ps",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            "label=com.docker.compose.service=main",
            "--format",
            "{{json .ID}}",
            timeout=self.options.docker_timeout,
        )
        ids = parse_docker_id_lines(stdout)
        if len(ids) != 1:
            raise BridgeError(
                f"expected exactly one running Harbor main container for project {project!r}; found {len(ids)}"
            )
        all_stdout, _ = await run_command(
            "docker",
            "ps",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{json .ID}}",
            timeout=self.options.docker_timeout,
        )
        all_ids = parse_docker_id_lines(all_stdout)
        if all_ids != ids:
            raise BridgeError(
                "Harbor Compose project contains sidecars; v1 observes exactly the main container"
            )
        container_id = ids[0]
        inspected = await self._docker_inspect(container_id)
        if inspected.get("Id") != container_id:
            raise BridgeError("docker inspect full identity mismatch")
        labels = inspected.get("Config", {}).get("Labels", {})
        if not isinstance(labels, dict) or (
            labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.service") != "main"
        ):
            raise BridgeError("container Compose labels changed during discovery")
        state = inspected.get("State")
        if not isinstance(state, dict):
            raise BridgeError("docker inspect lacks State")
        init_pid = state.get("Pid")
        if (
            state.get("Running") is not True
            or state.get("Paused") is not False
            or not isinstance(init_pid, int)
            or init_pid <= 0
        ):
            raise BridgeError("Harbor main container is not running and unpaused")
        proc = Path("/proc") / str(init_pid)
        try:
            cgroup_path = parse_proc_cgroup((proc / "cgroup").read_text())
            mount_namespace_inode = (proc / "ns/mnt").stat().st_ino
            network_namespace_inode = (proc / "ns/net").stat().st_ino
        except OSError as error:
            raise BridgeError("Docker init PID is not visible in this target Linux /proc") from error
        if not cgroup_binds_container(cgroup_path, container_id):
            raise BridgeError("live Docker cgroup does not bind the full container identity")
        cgroup_directory = Path("/sys/fs/cgroup") / cgroup_path.lstrip("/")
        metadata = cgroup_directory.stat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_ino <= 0:
            raise BridgeError("Docker cgroup-v2 root is not an anchored directory")
        try:
            cgroup_type = os.statvfs(cgroup_directory)
            del cgroup_type
            events = (cgroup_directory / "cgroup.events").read_text()
            freeze = (cgroup_directory / "cgroup.freeze").read_text()
        except OSError as error:
            raise BridgeError("Docker target lacks a usable cgroup-v2 freezer") from error
        if "frozen " not in events or freeze.strip() not in {"0", "1"}:
            raise BridgeError("Docker target cgroup freezer interface is malformed")
        app = proc / "root/app"
        if not app.is_dir():
            raise BridgeError("selected Terminal-Bench task has no /app directory in main container")
        return DockerTarget(
            container_id=container_id,
            init_pid=init_pid,
            cgroup_path=cgroup_path,
            cgroup_directory=cgroup_directory,
            cgroup_id=metadata.st_ino,
            mount_namespace_inode=mount_namespace_inode,
            network_namespace_inode=network_namespace_inode,
            network_interfaces=(),
            project=project,
        )

    async def bind_frozen_network_scope(self, target: DockerTarget) -> DockerTarget:
        await self.wait_frozen(target, True)
        inspected = await self._docker_inspect(target.container_id)
        state = inspected.get("State")
        if (
            not isinstance(state, dict)
            or state.get("Running") is not True
            or state.get("Paused") is not True
            or state.get("Pid") != target.init_pid
        ):
            raise BridgeError("Docker target identity changed before frozen network binding")
        proc = Path("/proc") / str(target.init_pid)
        try:
            if parse_proc_cgroup((proc / "cgroup").read_text()) != target.cgroup_path:
                raise BridgeError("Docker cgroup membership changed before network binding")
            if (proc / "ns/mnt").stat().st_ino != target.mount_namespace_inode:
                raise BridgeError("Docker mount namespace changed before network binding")
            network_before = (proc / "ns/net").stat().st_ino
            if network_before != target.network_namespace_inode:
                raise BridgeError("Docker network namespace changed before network binding")
            interfaces = parse_proc_net_dev(
                read_bounded_proc_text(
                    proc / "net/dev", "target /proc PID net/dev", MAX_PROC_NET_DEV_BYTES
                )
            )
            network_after = (proc / "ns/net").stat().st_ino
        except OSError as error:
            raise BridgeError("Docker init PID disappeared during frozen network binding") from error
        if network_after != network_before:
            raise BridgeError("Docker network namespace changed during interface discovery")
        return DockerTarget(
            container_id=target.container_id,
            init_pid=target.init_pid,
            cgroup_path=target.cgroup_path,
            cgroup_directory=target.cgroup_directory,
            cgroup_id=target.cgroup_id,
            mount_namespace_inode=target.mount_namespace_inode,
            network_namespace_inode=target.network_namespace_inode,
            network_interfaces=interfaces,
            project=target.project,
        )

    async def wait_frozen(self, target: DockerTarget, frozen: bool) -> None:
        deadline = asyncio.get_running_loop().time() + self.options.docker_timeout
        expected = "1" if frozen else "0"
        while asyncio.get_running_loop().time() < deadline:
            try:
                if target.cgroup_directory.stat().st_ino != target.cgroup_id:
                    raise BridgeError("Docker cgroup root identity changed")
                freeze = (target.cgroup_directory / "cgroup.freeze").read_text().strip()
                events = (target.cgroup_directory / "cgroup.events").read_text().splitlines()
            except OSError as error:
                raise BridgeError("Docker cgroup disappeared during freeze transition") from error
            fields = {
                pair[0]: pair[1]
                for line in events
                if len(pair := line.split()) == 2
            }
            if freeze == expected and fields.get("frozen") == expected:
                return
            await asyncio.sleep(0.02)
        raise BridgeError(f"Docker cgroup did not reach frozen={expected}")

    async def pause(self, target: DockerTarget) -> None:
        await run_command(
            "docker", "pause", target.container_id, timeout=self.options.docker_timeout
        )
        await self.wait_frozen(target, True)

    async def unpause(self, target: DockerTarget) -> None:
        await run_command(
            "docker", "unpause", target.container_id, timeout=self.options.docker_timeout
        )
        await self.wait_frozen(target, False)

    async def ensure_unpaused(self, target: DockerTarget) -> None:
        inspected = await self._docker_inspect(target.container_id)
        state = inspected.get("State")
        if (
            not isinstance(state, dict)
            or state.get("Running") is not True
            or state.get("Pid") != target.init_pid
        ):
            raise BridgeError("cannot recover Docker target: running identity changed")
        if state.get("Paused") is True:
            await self.unpause(target)
        elif state.get("Paused") is not False:
            raise BridgeError("cannot recover Docker target: pause state is unknown")
        else:
            await self.wait_frozen(target, False)

    def journal_failure(self, control_dir: Path | None, message: str) -> None:
        if control_dir is None:
            return
        try:
            replace_json(control_dir / "bridge-failure.json", {"error": message})
        except OSError as error:
            self.failure = f"{message}; FAILURE_JOURNAL_ERROR: {error}"

    async def _terminate_observer(self, active: ObserverRun) -> None:
        process = active.process
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        active.stderr_handle.close()

    async def agent_start(self, _event: Any) -> None:
        if self.active is not None or self.completed:
            raise BridgeError("bridge supports exactly one Agent phase per Trial")
        if os.geteuid() != 0:
            raise BridgeError("Harbor Observer bridge must run as root on the Docker host")
        target = await self.discover_target()
        run_id = f"tbench-{self.task_label}-{self.trial.id.hex[:12]}"
        root = self.options.evidence_root / run_id
        control_dir = root / "control"
        output_dir = root / "observer"
        if root.exists():
            raise BridgeError(f"evidence run directory already exists: {root}")
        control_dir.mkdir(mode=0o700, parents=True)
        config_path = control_dir / "config.json"
        stderr_handle = None
        active: ObserverRun | None = None
        self.recovery_target = target
        try:
            await self.pause(target)
            target = await self.bind_frozen_network_scope(target)
            self.recovery_target = target
            config = build_observer_config(
                container_id=target.container_id,
                init_pid=target.init_pid,
                cgroup_path=target.cgroup_path,
                mount_namespace_inode=target.mount_namespace_inode,
                network_namespace_inode=target.network_namespace_inode,
                network_interfaces=target.network_interfaces,
                ip_binary=self.options.ip_binary,
                ip_sha256=self.options.ip_sha256,
                tc_binary=self.options.tc_binary,
                tc_sha256=self.options.tc_sha256,
                nft_binary=self.options.nft_binary,
                nft_sha256=self.options.nft_sha256,
                recorder_object=self.options.recorder_object,
                recorder_sha256=self.options.recorder_sha256,
                lifecycle_object=self.options.lifecycle_object,
                lifecycle_sha256=self.options.lifecycle_sha256,
                output_directory=output_dir,
                run_id=run_id,
                epoch=self.epoch,
            )
            write_new_json(config_path, config)
            metadata = {
                "schema_version": 1,
                "task_label": self.task_label,
                "trial_name": self.trial.config.trial_name,
                "trial_id": str(self.trial.id),
                "compose_project": target.project,
                "container_id": target.container_id,
                "init_pid": target.init_pid,
                "cgroup_path": target.cgroup_path,
                "cgroup_id": target.cgroup_id,
                "mount_namespace_inode": target.mount_namespace_inode,
                "network_namespace_inode": target.network_namespace_inode,
                "network_interfaces": list(target.network_interfaces),
            }
            write_new_json(control_dir / "target.json", metadata)
            stderr_handle = (control_dir / "observer.stderr").open("xb", buffering=0)
            process = await asyncio.create_subprocess_exec(
                str(self.options.observer_binary),
                "--config",
                str(config_path),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=stderr_handle,
            )
            active = ObserverRun(
                run_id=run_id,
                epoch=self.epoch,
                root=root,
                control_dir=control_dir,
                output_dir=output_dir,
                config_path=config_path,
                config=config,
                target=target,
                process=process,
                stderr_handle=stderr_handle,
                finish_nonce="",
                paused_by_bridge=True,
            )
            if process.stdout is None:
                raise BridgeError("observer stdout pipe was not created")
            raw_ready = await asyncio.wait_for(
                process.stdout.readline(), timeout=self.options.ready_timeout
            )
            ready = parse_single_json_line(raw_ready, "READY", maximum=16 * 1024)
            active.finish_nonce = validate_ready(
                ready,
                run_id=run_id,
                epoch=self.epoch,
                effect_sha256=self.options.recorder_sha256,
                lifecycle_sha256=self.options.lifecycle_sha256,
                expected_cgroup_id=target.cgroup_id,
            )
            write_new_json(control_dir / "ready.external.json", ready)
            self.active = active
            await self.unpause(target)
            active.paused_by_bridge = False
            self.recovery_target = None
        except BaseException as error:
            self.failure = f"AGENT_START: {error}"
            cleanup_errors: list[str] = []
            if active is not None:
                try:
                    await self._terminate_observer(active)
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"observer termination failed: {cleanup_error}")
            else:
                if stderr_handle is not None:
                    stderr_handle.close()
            try:
                await self.ensure_unpaused(target)
                self.recovery_target = None
            except BaseException as cleanup_error:
                cleanup_errors.append(f"Docker recovery failed: {cleanup_error}")
            if cleanup_errors:
                self.failure = f"{self.failure}; " + "; ".join(cleanup_errors)
            self.journal_failure(control_dir, self.failure)
            if cleanup_errors:
                raise BridgeError(self.failure) from error
            raise

    async def agent_end(self, _event: Any) -> None:
        active = self.active
        if active is None:
            raise BridgeError("AGENT_END arrived without an active Observer run")
        completion: dict[str, Any] | None = None
        try:
            inspected = await self._docker_inspect(active.target.container_id)
            state = inspected.get("State", {})
            if (
                not isinstance(state, dict)
                or state.get("Running") is not True
                or state.get("Paused") is not False
                or state.get("Pid") != active.target.init_pid
            ):
                raise BridgeError("Docker target stopped, paused, or changed PID before FINISH")
            active.paused_by_bridge = True
            self.recovery_target = active.target
            await self.pause(active.target)
            if active.process.stdin is None or active.process.stdout is None:
                raise BridgeError("observer control pipes are unavailable")
            finish = {
                "protocol_version": PROTOCOL_VERSION,
                "command": "FINISH",
                "run_id": active.run_id,
                "finish_nonce": active.finish_nonce,
            }
            write_new_json(active.control_dir / "finish.external.json", finish)
            active.process.stdin.write(canonical_json_bytes(finish))
            await active.process.stdin.drain()
            active.process.stdin.close()
            await active.process.stdin.wait_closed()
            raw_finished = await asyncio.wait_for(
                active.process.stdout.readline(), timeout=self.options.finish_timeout
            )
            finished = parse_single_json_line(raw_finished, "FINISHED", maximum=16 * 1024)
            report_sha256, manifest_sha256 = validate_finished(
                finished, run_id=active.run_id
            )
            write_new_json(active.control_dir / "finished.external.json", finished)
            return_code = await asyncio.wait_for(
                active.process.wait(), timeout=self.options.finish_timeout
            )
            active.stderr_handle.close()
            if return_code != 0:
                raise BridgeError(f"deployment-observe exited with status {return_code}")
            expectation = {
                "expected_config": active.config,
                "expected_artifact_manifest_sha256": manifest_sha256,
                "expected_report_sha256": report_sha256,
            }
            expectation_path = active.control_dir / "verification-expectation.json"
            write_new_json(expectation_path, expectation)
            verify_return_code, verify_stdout, verify_stderr = await capture_command(
                str(self.options.verifier_binary),
                "--artifacts",
                str(active.output_dir),
                "--expectation",
                str(expectation_path),
                timeout=self.options.finish_timeout,
            )
            persist_verifier_result(
                active.control_dir,
                verify_return_code,
                verify_stdout,
                verify_stderr,
            )
            verification = parse_single_json_line(
                verify_stdout if verify_stdout.endswith(b"\n") else verify_stdout + b"\n",
                "offline verification",
            )
            if verification.get("verified") is not True:
                raise BridgeError("offline verifier did not return verified=true")
            write_new_json(active.control_dir / "offline-verification.json", verification)
            report = json.loads(
                (active.output_dir / "deployment-observation-report.json").read_bytes()
            )
            completion = {
                "schema_version": 1,
                "status": "OBSERVER_VERIFIED",
                "run_id": active.run_id,
                "task_label": self.task_label,
                "trial_id": str(self.trial.id),
                "container_id": active.target.container_id,
                "observer": {
                    "offline_verification": verification,
                    "overall_evidence_status": report.get("overall_evidence_status"),
                    "aggregate_health": report.get("aggregate_health"),
                    "aggregate_lifecycle_health": report.get(
                        "aggregate_lifecycle_health"
                    ),
                    "socket_state": report.get("socket_state"),
                    "bpf_state": report.get("bpf_state"),
                    "filesystem_state": report.get("filesystem_state"),
                    "linux_state": report.get("linux_state"),
                },
            }
            write_new_json(active.control_dir / "observer-summary.json", completion)
        except BaseException as error:
            self.failure = f"AGENT_END: {error}"
            if active.process.returncode is None:
                try:
                    await self._terminate_observer(active)
                except BaseException as cleanup_error:
                    self.failure = (
                        f"{self.failure}; observer termination failed: {cleanup_error}"
                    )
            self.journal_failure(active.control_dir, self.failure)
            raise
        finally:
            try:
                await self.ensure_unpaused(active.target)
                active.paused_by_bridge = False
                self.recovery_target = None
                self.active = None
            except BaseException as error:
                self.failure = f"{self.failure + '; ' if self.failure else ''}UNPAUSE: {error}"
                self.journal_failure(active.control_dir, self.failure)
                raise BridgeError(self.failure) from error
        if completion is not None:
            self.completed.append(completion)

    async def cleanup(self) -> None:
        active = self.active
        target = self.recovery_target or (active.target if active is not None else None)
        if active is None and target is None:
            return
        errors: list[str] = []
        try:
            if active is not None:
                await self._terminate_observer(active)
        except BaseException as error:
            errors.append(f"observer cleanup failed: {error}")
        if target is not None:
            try:
                await self.ensure_unpaused(target)
            except BaseException as error:
                errors.append(f"Docker cleanup failed: {error}")
        if not errors:
            self.active = None
            self.recovery_target = None
            return
        self.failure = f"{self.failure + '; ' if self.failure else ''}" + "; ".join(errors)
        self.journal_failure(active.control_dir if active is not None else None, self.failure)
        raise BridgeError(self.failure)


def slug(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]", "-", value).strip("-._")
    return (normalized or "task")[:48]


def utc_run_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def require_empty_directory_target(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=False)
    if resolved.exists():
        if not resolved.is_dir() or any(resolved.iterdir()):
            raise BridgeError(f"{label} must be absent or an empty directory: {resolved}")
    else:
        resolved.mkdir(mode=0o700, parents=True)
    return resolved


async def run_trials(arguments: argparse.Namespace) -> int:
    try:
        from harbor.models.environment_type import EnvironmentType
        from harbor.models.trial.config import (
            AgentConfig,
            EnvironmentConfig,
            TaskConfig,
            TrialConfig,
        )
        from harbor.trial.hooks import TrialEvent
        from harbor.trial.trial import Trial
    except ImportError as error:
        raise BridgeError(
            "Harbor is not importable; install the pinned Harbor version in this Python environment"
        ) from error

    if os.geteuid() != 0:
        raise BridgeError("run the bridge as root on the Docker/target-Linux host")
    try:
        harbor_version = version("harbor")
    except PackageNotFoundError as error:
        raise BridgeError("the Harbor Python distribution is not installed") from error
    if harbor_version != arguments.expected_harbor_version:
        raise BridgeError(
            f"Harbor version mismatch: expected {arguments.expected_harbor_version}, observed {harbor_version}"
        )
    if (
        not GIT_COMMIT_RE.fullmatch(arguments.harbor_source_revision)
        or arguments.harbor_source_revision != SUPPORTED_HARBOR_SOURCE_REVISION
    ):
        raise BridgeError(
            "Harbor source revision does not match the reviewed bridge revision"
        )
    selection = validate_selection_manifest(
        arguments.selection_manifest,
        arguments.selection_manifest_sha256,
        arguments.task,
    )
    observer_binary = validate_trusted_file(
        arguments.observer_binary, arguments.observer_sha256, "deployment observer"
    )
    verifier_binary = validate_trusted_file(
        arguments.verifier_binary, arguments.verifier_sha256, "deployment verifier"
    )
    recorder_object = validate_trusted_file(
        arguments.recorder_object, arguments.recorder_sha256, "system-effect object"
    )
    lifecycle_object = validate_trusted_file(
        arguments.lifecycle_object,
        arguments.lifecycle_sha256,
        "process-lifecycle object",
    )
    ip_binary = validate_network_collector(
        arguments.ip_binary, arguments.ip_sha256, "ip collector"
    )
    tc_binary = validate_network_collector(
        arguments.tc_binary, arguments.tc_sha256, "tc collector"
    )
    nft_binary = validate_network_collector(
        arguments.nft_binary, arguments.nft_sha256, "nft collector"
    )
    evidence_root = require_empty_directory_target(arguments.evidence_root, "evidence root")
    trials_dir = require_empty_directory_target(arguments.trials_dir, "Harbor trials directory")
    options = BridgeOptions(
        observer_binary=observer_binary,
        verifier_binary=verifier_binary,
        recorder_object=recorder_object,
        recorder_sha256=arguments.recorder_sha256,
        lifecycle_object=lifecycle_object,
        lifecycle_sha256=arguments.lifecycle_sha256,
        ip_binary=ip_binary,
        ip_sha256=arguments.ip_sha256,
        tc_binary=tc_binary,
        tc_sha256=arguments.tc_sha256,
        nft_binary=nft_binary,
        nft_sha256=arguments.nft_sha256,
        evidence_root=evidence_root,
        ready_timeout=arguments.ready_timeout,
        finish_timeout=arguments.finish_timeout,
        docker_timeout=arguments.docker_timeout,
    )
    docker_info = await docker_json("info", "--format", "{{json .}}", timeout=30)
    if not isinstance(docker_info, dict) or docker_info.get("OSType") != "linux":
        raise BridgeError("Docker daemon is not a locally usable Linux daemon")
    summaries: list[dict[str, Any]] = []
    failed = False
    for index, task_argument in enumerate(arguments.task):
        task = task_argument.resolve(strict=True)
        label = slug(task.name)
        trial_name = (
            f"obs-{index + 1:02d}-{slug(label)[:24]}-"
            f"{slug(arguments.run_label)[:16]}"
        )
        trial = None
        bridge = None
        result = None
        orchestration_error = None
        try:
            config = TrialConfig(
                task=TaskConfig(path=task),
                trial_name=trial_name,
                trials_dir=trials_dir,
                agent=AgentConfig(name="oracle"),
                environment=EnvironmentConfig(type=EnvironmentType.DOCKER, delete=True),
            )
            trial = await Trial.create(config)
            if getattr(trial.task, "has_steps", False):
                raise BridgeError(
                    f"multi-step task is unsupported by this v1 bridge: {task}"
                )
            bridge = TrialObserverBridge(trial=trial, options=options, task_label=label)
            trial.add_hook(TrialEvent.AGENT_START, bridge.agent_start)
            trial.add_hook(TrialEvent.AGENT_END, bridge.agent_end)
            result = await trial.run()
        except Exception as error:
            orchestration_error = f"{type(error).__name__}: {error}"
        finally:
            if bridge is not None:
                try:
                    await bridge.cleanup()
                except Exception as error:
                    cleanup_error = f"{type(error).__name__}: {error}"
                    orchestration_error = (
                        f"{orchestration_error}; cleanup: {cleanup_error}"
                        if orchestration_error is not None
                        else f"cleanup: {cleanup_error}"
                    )
        rewards = (
            result.verifier_result.rewards
            if result is not None and result.verifier_result is not None
            else None
        )
        reward_passed = reward_matches(rewards, arguments.expected_reward)
        result_summary = {
            "schema_version": 1,
            "task": str(task),
            "task_label": label,
            "trial_name": trial_name,
            "trial_id": str(trial.id) if trial is not None else None,
            "task_checksum": result.task_checksum if result is not None else None,
            "harbor_result_path": (
                str(trial.paths.result_path) if trial is not None else None
            ),
            "orchestration_error": orchestration_error,
            "harbor_exception": (
                result.exception_info.model_dump(mode="json")
                if result is not None and result.exception_info is not None
                else None
            ),
            "harbor_rewards": rewards,
            "expected_reward": arguments.expected_reward,
            "reward_passed": reward_passed,
            "observer_runs": bridge.completed if bridge is not None else [],
            "observer_failure": bridge.failure if bridge is not None else None,
        }
        summaries.append(result_summary)
        if (
            orchestration_error is not None
            or result is None
            or result.exception_info is not None
            or not reward_passed
            or bridge is None
            or bridge.failure is not None
            or len(bridge.completed) != 1
        ):
            failed = True
            if arguments.fail_fast:
                break
    campaign = {
        "schema_version": 1,
        "status": "FAILED" if failed else "COMPLETE",
        "run_label": arguments.run_label,
        "harbor_version": harbor_version,
        "harbor_source_revision": arguments.harbor_source_revision,
        "agent": "oracle",
        "environment": "docker",
        "bpf_state_object_types": ["PROGRAM", "MAP"],
        "bpf_map_content": "DISABLED_METADATA_ONLY",
        "filesystem_scope": ["/app"],
        "linux_state_domains": [
            "sysctl",
            "mounts",
            "network",
            "modules",
            "process_residual",
        ],
        "selection": selection,
        "expected_reward": arguments.expected_reward,
        "tasks": summaries,
    }
    write_new_json(evidence_root / "campaign-summary.json", campaign)
    print(json.dumps(campaign, ensure_ascii=False, sort_keys=True))
    return 1 if failed else 0


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def unit_interval(value: str) -> float:
    parsed = float(value)
    if parsed < 0 or parsed > 1:
        raise argparse.ArgumentTypeError("value must be between zero and one")
    return parsed


def reward_matches(rewards: Any, expected: float) -> bool:
    primary = rewards.get("reward") if isinstance(rewards, dict) else None
    return (
        isinstance(primary, (int, float))
        and not isinstance(primary, bool)
        and float(primary) == expected
    )


def path_argument(value: str) -> Path:
    return Path(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run local Harbor Oracle trials under the strict Docker deployment observer"
    )
    parser.add_argument("--task", type=path_argument, action="append", required=True)
    parser.add_argument(
        "--selection-manifest", type=path_argument, required=True
    )
    parser.add_argument("--selection-manifest-sha256", required=True)
    parser.add_argument("--trials-dir", type=path_argument, required=True)
    parser.add_argument("--evidence-root", type=path_argument, required=True)
    parser.add_argument("--run-label", default=utc_run_label())
    parser.add_argument(
        "--expected-harbor-version", default=SUPPORTED_HARBOR_VERSION
    )
    parser.add_argument(
        "--harbor-source-revision",
        default=SUPPORTED_HARBOR_SOURCE_REVISION,
    )
    parser.add_argument("--expected-reward", type=unit_interval, default=1.0)
    parser.add_argument("--observer-binary", type=path_argument, required=True)
    parser.add_argument("--observer-sha256", required=True)
    parser.add_argument("--verifier-binary", type=path_argument, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--recorder-object", type=path_argument, required=True)
    parser.add_argument("--recorder-sha256", required=True)
    parser.add_argument("--lifecycle-object", type=path_argument, required=True)
    parser.add_argument("--lifecycle-sha256", required=True)
    parser.add_argument("--ip-binary", type=path_argument, required=True)
    parser.add_argument("--ip-sha256", required=True)
    parser.add_argument("--tc-binary", type=path_argument, required=True)
    parser.add_argument("--tc-sha256", required=True)
    parser.add_argument("--nft-binary", type=path_argument, required=True)
    parser.add_argument("--nft-sha256", required=True)
    parser.add_argument("--ready-timeout", type=positive_float, default=180.0)
    parser.add_argument("--finish-timeout", type=positive_float, default=300.0)
    parser.add_argument("--docker-timeout", type=positive_float, default=30.0)
    failure_mode = parser.add_mutually_exclusive_group()
    failure_mode.add_argument("--fail-fast", dest="fail_fast", action="store_true")
    failure_mode.add_argument("--no-fail-fast", dest="fail_fast", action="store_false")
    parser.set_defaults(fail_fast=True)
    return parser


def main(argv: Sequence[str] | None = None) -> NoReturn:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def cancel() -> None:
        for task in asyncio.all_tasks(loop):
            task.cancel()

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, cancel)
        except NotImplementedError:
            pass
    try:
        status = loop.run_until_complete(run_trials(arguments))
    except (BridgeError, OSError, asyncio.TimeoutError) as error:
        print(f"terminal-bench observer bridge: {error}", file=sys.stderr)
        status = 1
    finally:
        loop.close()
    raise SystemExit(status)


if __name__ == "__main__":
    main()
