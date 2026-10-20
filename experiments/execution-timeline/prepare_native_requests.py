#!/usr/bin/env python3
"""Prepare an unpatched public Requests task, never expose a reference patch.

The repository archive must be made with git archive from the recorded commit.
The compatibility launcher addresses Python 3.13's removed collections aliases;
an explicitly supplied historical stdlib cgi.py can address its removed cgi
module. Neither changes Requests behavior. No network or model calls are made.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import tarfile

from common import digest, write_new


COMPAT = '''import collections
import collections.abc
for _name in ("Mapping", "MutableMapping", "Sequence", "MutableSequence", "Callable", "Iterable"):
    if not hasattr(collections, _name):
        setattr(collections, _name, getattr(collections.abc, _name))
'''


def prepare(root, archive, python, cgi_compat_file=None):
    root = Path(root).resolve(strict=True)
    baseline, workspace = root / "requests-baseline", root / "requests-work"
    if baseline.exists() or workspace.exists():
        raise ValueError("fresh baseline and workspace required; no previous task is overwritten")
    baseline.mkdir(mode=0o700)
    with tarfile.open(archive, "r:") as source:
        for entry in source.getmembers():
            name = Path(entry.name)
            if name.is_absolute() or ".." in name.parts or not (entry.isfile() or entry.isdir()):
                raise ValueError("archive must contain only relative regular files and directories")
        source.extractall(baseline)
    compat = baseline / ".observer-python-compat"
    compat.mkdir()
    write_new(compat / "sitecustomize.py", COMPAT.encode())
    adaptations = ["collections aliases via supplied compatibility launcher"]
    cgi_identity = None
    if cgi_compat_file is not None:
        cgi = Path(cgi_compat_file).resolve(strict=True)
        if not cgi.is_file() or cgi.stat().st_size > 1024 * 1024:
            raise ValueError("bounded explicit historical stdlib cgi.py file required")
        write_new(compat / "cgi.py", cgi.read_bytes())
        cgi_identity = digest(compat / "cgi.py")
        adaptations.append("explicit historical stdlib cgi.py for interpreters without cgi")
    launcher = baseline / "run-python"
    # Resolve at execution time so repeated runs use the same fixed workspace.
    body = '#!/bin/sh\nset -eu\ntask_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
    body += 'export PYTHONPATH="$task_dir/.observer-python-compat${PYTHONPATH:+:$PYTHONPATH}"\n'
    body += 'exec "' + str(Path(python).resolve(strict=True)) + '" "$@"\n'
    write_new(launcher, body.encode())
    launcher.chmod(0o700)
    shutil.copytree(baseline, workspace)
    prompt = """Fix this real Requests issue in the current repository:

requests.get is ALWAYS sending content length
GET requests currently add a Content-Length header automatically even when no
body is supplied. Some servers reject this. GET and HEAD without a body should
not receive an automatically added Content-Length. Preserve appropriate behavior
for methods with bodies and explicit caller-provided headers.

Inspect the implementation, reproduce the problem, implement a focused fix, add
offline regression tests, and run them. Do not use external network services.
Use your normal native tools. The supplied ./run-python launcher uses a prepared
Python environment with compatibility aliases for this historical repository;
use it for Python commands and do not modify the launcher or its compatibility
directory. Existing offline tests can be selected from test_requests.py. Explain
what changed and which checks passed. Keep work focused and avoid dumping files.
"""
    write_new(root / "requests-prompt.txt", prompt.encode())
    write_new(root / "task-provenance.json", {"schema_version": 1,
        "kind": "PUBLIC_SWE_BENCH_ISSUE_DIRECT_NATIVE_WORKSPACE_VALIDATION",
        "instance_id": "psf__requests-1142", "base_commit": "546130c8c878adabd16ac5221a36e39e4dab3645",
        "archive": digest(archive), "workspace": str(workspace), "baseline": str(baseline),
        "reference_patch_exposed": False, "official_benchmark_score": "NOT_RUN_BY_THIS_PREPARER",
        "environment_adaptation": adaptations, "cgi_compat_identity": cgi_identity,
        "task_prompt": digest(root / "requests-prompt.txt")})
    return workspace


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--cgi-compat-file", type=Path,
                        help="explicit historical stdlib cgi.py when using Python 3.13; copied and hashed")
    args = parser.parse_args()
    print(prepare(args.root, args.archive, args.python, args.cgi_compat_file))
