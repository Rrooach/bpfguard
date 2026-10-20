"""Launch only this local validation inside fresh, owned memory cgroups.

Never moves a shell/session, edits a shared controller configuration, or kills
an existing group.  The new process is stopped before entering its leaf and
executes a fresh Python interpreter there.  Empty-group accounting survives
until after collection; page cache is not forced to zero.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

from common import write_new
from resource_accounting import capture
from run import kill_group, populated, wait_stopped


def run_private_fixture(args):
    parent=Path("/sys/fs/cgroup")
    if os.geteuid()!=0 or "memory" not in (parent/"cgroup.subtree_control").read_text().split():
        raise RuntimeError("private fixture requires delegated/enabled memory controller; no shared configuration is changed")
    root=parent/("observer-runtime-fixture-"+uuid.uuid4().hex)
    root.mkdir()
    groups=[]; child=None; receipt={"root":str(root),"scope":"NEW_EXCLUSIVE_FIXTURE_GROUPS_ONLY",
        "parent_configuration_modified":False,"page_cache_forced_reclaim":False}
    try:
        (root/"cgroup.subtree_control").write_text("+memory")
        for name in ("observer","runtime","tool"):
            leaf=root/name;leaf.mkdir();groups.append(leaf)
        command=[sys.executable,str(Path(__file__).with_name("validate_runtime_metrics.py")),
            "--codex",str(args.codex.resolve()),"--catalog",str(args.catalog.resolve()),
            "--output",str(args.output.resolve()),"--resource-cgroup-root",str(root)]
        if getattr(args,"collector",None) is not None:
            command.extend(["--collector",str(args.collector.resolve()),"--object",str(args.object.resolve())])
        child=subprocess.Popen(["/bin/sh","-c",'kill -STOP $$; exec "$@"',"observer-fixture",*command],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,text=True)
        wait_stopped(child.pid,5)
        (groups[0]/"cgroup.procs").write_text(str(child.pid))
        receipt.update(child_pid=child.pid,gate="SIGSTOP_CGROUP_ENTRY_BEFORE_FRESH_PYTHON_EXEC",
            release_ns=time.monotonic_ns())
        os.kill(child.pid,signal.SIGCONT)
        out,err=child.communicate(timeout=60)
        receipt.update(return_code=child.returncode,wait_confirmed_ns=time.monotonic_ns(),
            final_groups={leaf.name:{"populated":populated(leaf),"accounting":capture(leaf)} for leaf in groups})
        output=args.output.resolve()
        if output.is_dir():
            write_new(output/"private-cgroup-receipt.json",receipt)
            write_new(output/"private-launcher.stdout",out.encode())
            write_new(output/"private-launcher.stderr",err.encode())
        if child.returncode or any(row["populated"] for row in receipt["final_groups"].values()):
            raise RuntimeError("private fixture failed or retained processes: "+err[-1500:])
        return json.loads(out.strip().splitlines()[-1])
    finally:
        if child is not None and child.poll() is None:
            # PID is the new, owned session root, never an existing process.
            os.killpg(child.pid,signal.SIGKILL);child.communicate(timeout=5)
        for leaf in reversed(groups):
            if populated(leaf):
                kill_group(leaf)
                deadline=time.monotonic()+5
                while populated(leaf) and time.monotonic()<deadline:time.sleep(.01)
            if not populated(leaf):leaf.rmdir()
        if not populated(root):
            try:root.rmdir()
            except OSError:pass
        output=args.output.resolve()
        if output.is_dir():
            write_new(output/"private-cgroup-cleanup.json",{"root":str(root),
                "removed":not root.exists(),"finished_ns":time.monotonic_ns(),
                "scope":"ONLY_FRESH_GROUPS_CREATED_BY_THIS_FIXTURE"})
