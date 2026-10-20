"""Real, opt-in tool-cgroup capture for the zero-paid-API runtime fixture.

The collector stays outside its tool-only scope.  Report generation always
uses the existing raw-WAL verifier; no synthetic events or old-run evidence.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from common import bind_artifacts, digest, write_new
from replay import verify_run
from run import populated, ready_line


class NativeFixtureCapture:
    def __init__(self, root, collector, object_path, cgroup, run_id):
        self.root = Path(root)
        self.cgroup = Path(cgroup).resolve(strict=True)
        if self.cgroup.name != "tool" or not self.cgroup.parent.name.startswith("observer-runtime-fixture-"):
            raise ValueError("native fixture requires the newly owned tool cgroup")
        if populated(self.cgroup) or (self.cgroup / "cgroup.procs").read_text().strip():
            raise ValueError("native fixture tool cgroup must initially be empty")
        self.cgroup_id = self.cgroup.stat().st_ino
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.run_id = run_id
        pinned = self.root / "pinned-artifacts"
        pinned.mkdir()
        self.collector = pinned / "collect"
        self.object_path = pinned / "execution_timeline.bpf.o"
        shutil.copy2(Path(collector).resolve(strict=True), self.collector)
        shutil.copy2(Path(object_path).resolve(strict=True), self.object_path)
        write_new(self.root / "kallsyms.txt", Path("/proc/kallsyms").read_bytes())
        self.stderr = (self.root / "collector.stderr").open("xb")
        self.process = None
        self.ledger = None
        self.started = None
        self.tool = None

    def start(self):
        try:
            self.process = subprocess.Popen([str(self.collector),"--object",str(self.object_path),
                "--cgroup",str(self.cgroup),"--output-dir",str(self.root/"capture"),
                "--kernel-stacks","--ring-bytes",str(64*1024*1024),
                "--max-records","1000000","--max-bytes",str(256*1024*1024)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr)
            ready = ready_line(self.process,30)
            if ready.get("boot_id") != self.boot_id or ready.get("root_cgroup_id") != self.cgroup_id or \
                    ready.get("clock") != "CLOCK_MONOTONIC" or ready.get("schema_version") != 1:
                raise ValueError("native READY boot/cgroup/clock/ABI differs")
            self.ready = ready
            self.started = time.monotonic_ns()
            write_new(self.root / "ready.json",ready)
            self.ledger = (self.root / "tool-spans.jsonl").open("x")
            return self
        except BaseException:
            self.close()
            raise

    def event(self, kind, tool):
        self.ledger.write(json.dumps({"event":kind,**tool},sort_keys=True)+"\n")
        self.ledger.flush()
        os.fsync(self.ledger.fileno())
        if kind == "TOOL_END":
            self.tool = json.loads(json.dumps(tool))

    def finish(self, application):
        if self.tool is None:
            raise ValueError("native fixture lacks a completed gated tool span")
        if populated(self.cgroup):
            raise ValueError("native tool group remains populated; no completed manifest")
        self.process.stdin.write(b"STOP\n")
        self.process.stdin.flush()
        self.process.stdin.close()
        returncode = self.process.wait(timeout=30)
        self.ledger.close()
        self.stderr.close()
        if returncode != 0:
            raise RuntimeError("native collector returned "+str(returncode))
        # Bind the entire current app evidence, including timing and memory,
        # into this same run.  Workspace file contents are not evidence logs.
        names = ["kallsyms.txt","ready.json","tool-spans.jsonl","collector.stderr"]
        for directory in (self.root/"capture",self.root/"pinned-artifacts",self.root/"app"):
            names += [str(path.relative_to(self.root)) for path in sorted(directory.rglob("*")) if path.is_file()]
        manifest = {"schema_version":1,"run_id":self.run_id,"boot_id":self.boot_id,
            "kernel_release":os.uname().release,"clock":"CLOCK_MONOTONIC",
            "begin_ns":self.started,"end_ns":time.monotonic_ns(),"tools":[self.tool],
            "capture_directory":"capture","collector_binary":str(self.collector.resolve()),
            "collector_identity":digest(self.collector),"collector_return_code":returncode,
            "bpf_object":str(self.object_path.resolve()),"bpf_identity":digest(self.object_path),
            "scope":{"kind":"COOPERATIVE_DIRECT_CGROUP_DESCENDANTS","root_cgroup":str(self.cgroup),
                "root_cgroup_id":self.cgroup_id,"kernel_stacks":True,"gpu":"NOT_SELECTED",
                "runtime_kernel_scope":"TOOL_NODE_AND_DESCENDANTS_ONLY; CODEX_RUNTIME_NOT_SELECTED"},
            "agent_application_window":{"begin_ns":application["begin_ns"],"end_ns":application["end_ns"]},
            "artifacts":bind_artifacts(self.root,names)}
        write_new(self.root/"manifest.json",manifest)
        manifest_digest = digest(self.root/"manifest.json")["sha256"]
        report = verify_run(self.root,expected_manifest_sha256=manifest_digest)
        if report["totals"]["events"] == 0 or not any(thread.get("calls") for thread in report["threads"]):
            raise RuntimeError("native fixture did not record actual tool syscalls")
        if any(tool.get("association") != "RUNTIME_GATE_AND_KERNEL_LIFETIME" for tool in report["tools"]):
            raise RuntimeError("native fixture tool root was not kernel-lifetime resolved")
        write_new(self.root/"kernel-report.json",report)
        write_new(self.root/"kernel-verification.json",{"status":"REPLAY_PASSED",
            "manifest_sha256":manifest_digest,"report":digest(self.root/"kernel-report.json"),
            "boot_id":self.boot_id,"run_id":self.run_id,
            "capture_health_status":report["health"].get("status"),
            "timeline_status":report["critical_path"].get("status"),
            "caveat":"RAW_BINDING_AND_REPLAY_PASS_DO_NOT_ERASE_COVERAGE_FINDINGS"})
        return report

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.ledger is not None and not self.ledger.closed:
            self.ledger.close()
        if not self.stderr.closed:
            self.stderr.close()
