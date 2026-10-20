#!/usr/bin/env python3
"""Small, dependency-free evidence helpers for the opt-in timeline recorder."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def write_new(path, value):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(value if isinstance(value, bytes) else canonical(value))
        output.flush()
        os.fsync(output.fileno())


def digest(path):
    sha = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            sha.update(block)
            size += len(block)
    return {"sha256": sha.hexdigest(), "size_bytes": size}


def proc_identity(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    values = raw[raw.rfind(")") + 2:].split()
    return {"tid": pid, "start_ticks": int(values[19]), "clock_ticks": os.sysconf("SC_CLK_TCK")}


def bind_artifacts(directory, names):
    root = Path(directory).resolve()
    return {str(Path(name)): digest(root / name) for name in names}


def check_artifacts(directory, manifest):
    root = Path(directory).resolve()
    bound = manifest.get("artifacts", {})
    if not bound or not isinstance(bound, dict):
        raise ValueError("manifest has no bound evidence")
    for name, expected in bound.items():
        path = root / name
        if Path(name).is_absolute() or ".." in Path(name).parts or path.is_symlink():
            raise ValueError("unsafe artifact path")
        resolved = path.resolve(strict=True)
        if root not in resolved.parents or digest(resolved) != expected:
            raise ValueError(f"artifact binding differs: {name}")
    return bound
