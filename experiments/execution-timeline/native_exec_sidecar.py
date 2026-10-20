#!/usr/bin/env python3
"""Optional bounded exec-argv sensor; separate ABI from the timeline WAL."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import signal
import subprocess
import time

from common import digest,write_new


class NativeExecSidecar:
    def __init__(self,collector,object_path,root,cgroup):
        self.root=Path(root);self.cgroup=Path(cgroup)
        pinned=self.root/"pinned-artifacts"
        self.collector=pinned/"exec-args-collect";self.object_path=pinned/"native_exec_args.bpf.o"
        shutil.copy2(Path(collector).resolve(strict=True),self.collector)
        shutil.copy2(Path(object_path).resolve(strict=True),self.object_path)
        self.stdout=(self.root/"exec-args.stdout").open("xb")
        self.stderr=(self.root/"exec-args.stderr").open("xb")
        self.process=None;self.receipt=None

    def start(self):
        self.process=subprocess.Popen([str(self.collector),"--object",str(self.object_path),
            "--cgroup-id",str(self.cgroup.stat().st_ino),"--output",str(self.root/"exec-args")],
            stdin=subprocess.DEVNULL,stdout=self.stdout,stderr=self.stderr)
        deadline=time.monotonic()+20
        ready_path=self.root/"exec-args/ready.json"
        while not ready_path.exists():
            if self.process.poll() is not None:raise RuntimeError("exec argv sidecar exited before READY")
            if time.monotonic()>=deadline:raise TimeoutError("exec argv sidecar READY timed out")
            time.sleep(.005)
        ready=json.loads(ready_path.read_text())
        if ready.get("status")!="READY" or ready.get("cgroup_id")!=self.cgroup.stat().st_ino:
            raise ValueError("exec argv sidecar READY differs from declared native runtime group")
        self.ready=ready
        return self

    def stop(self):
        if self.receipt is not None:return self.receipt
        if self.process is None:return None
        if self.process.poll() is None:self.process.send_signal(signal.SIGTERM)
        try:code=self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill();code=self.process.wait(timeout=5)
        self.stdout.close();self.stderr.close()
        self.receipt={"status":"COLLECTOR_EXITED_SUCCESSFULLY" if code==0 else "COLLECTOR_FAILED",
            "return_code":code,"collector":digest(self.collector),"object":digest(self.object_path),
            "scope":"OPT_IN_EXACT_RUNTIME_CGROUP_EXEC_ARGV; SEPARATE_WAL_NOT_A_CALL_ID_BINDING",
            "ready":getattr(self,"ready",None),
            "capture_semantics":"USER_ARGV_AT_SYSCALL_ENTRY; BOUNDED_8_ARGUMENTS_4096_BYTES_EACH; TRUNCATION_REMAINS_EXPLICIT"}
        write_new(self.root/"exec-args-receipt.json",self.receipt)
        return self.receipt
