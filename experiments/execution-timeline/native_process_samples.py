#!/usr/bin/env python3
"""Optional /proc candidates for native tools; never authoritative call binding.

The kernel timeline establishes process ancestry/lifetimes. This bounded
sampler contributes argv/cwd observed while a process is alive, not exec-time
arguments. Sampling can miss short commands or an argv/cwd transition.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import threading
import time

from common import write_new


def process_snapshot(pid, proc_root=Path("/proc")):
    directory=Path(proc_root)/str(pid)
    def identity():
        raw=(directory/"stat").read_text()
        values=raw[raw.rfind(")")+2:].split()
        return int(values[19]),int(values[1])
    before,parent=identity()
    with (directory/"cmdline").open("rb") as stream:
        raw=stream.read(65537)
    if len(raw)>65536:
        raise ValueError("process argv exceeds sample bound")
    argv=[part.decode(errors="surrogateescape") for part in raw.rstrip(b"\0").split(b"\0")] if raw else []
    cwd=os.readlink(directory/"cwd")
    after,_=identity()
    if before!=after:
        raise ValueError("PID identity changed during argv/cwd capture")
    return {"pid":pid,"start_ticks":before,"ppid":parent,"argv":argv,"cwd":cwd,
        "clock_ticks":os.sysconf("SC_CLK_TCK"),"capture":"LIVE_PROC_ARGV_CWD_NOT_EXEC_ENTRY"}


class NativeProcessSampler:
    def __init__(self, group, directory, *, interval_ms=20, max_records=20000):
        if not 10<=interval_ms<=1000 or not 1<=max_records<=100000:
            raise ValueError("bounded process sampling interval and records required")
        self.group=Path(group).resolve(strict=True)
        self.identity=(self.group.stat().st_dev,self.group.stat().st_ino)
        self.directory=Path(directory)
        self.path=self.directory/"native-process-samples.jsonl"
        self.stream=self.path.open("x")
        self.interval_ms,self.max_records=interval_ms,max_records
        self.boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.rows=[];self.seen=set();self.errors=0;self.limit_reached=False
        self._stop=threading.Event();self.thread=None;self.duration_ns=0

    def sample(self):
        begin=time.monotonic_ns()
        if (self.group.stat().st_dev,self.group.stat().st_ino)!=self.identity:
            raise ValueError("native process sampling cgroup identity changed")
        pids=set()
        for entry in self.group.rglob("cgroup.procs"):
            if self.group not in entry.resolve().parents:
                raise ValueError("native process scan escaped owned cgroup")
            try:pids.update(int(value) for value in entry.read_text().split())
            except (FileNotFoundError,ProcessLookupError):continue
        for pid in sorted(pids):
            try:
                value=process_snapshot(pid)
                key=(pid,value["start_ticks"],tuple(value["argv"]),value["cwd"])
                # Preserve repeated observations for the actual intersection
                # window, but cap total writes independently of run duration.
                if len(self.rows)>=self.max_records:
                    self.limit_reached=True
                    break
                row={"event":"NATIVE_PROCESS_SAMPLE","clock":"CLOCK_MONOTONIC","boot_id":self.boot_id,
                    "begin_ns":begin,"end_ns":time.monotonic_ns(),"cgroup_id":self.identity[1],**value}
                self.rows.append(row);self.seen.add(key)
                self.stream.write(json.dumps(row,ensure_ascii=True,separators=(",",":"))+"\n")
            except (OSError,ValueError,IndexError):
                self.errors+=1
        self.stream.flush()
        self.duration_ns+=time.monotonic_ns()-begin

    def _loop(self):
        while not self._stop.wait(self.interval_ms/1000):
            try:self.sample()
            except (OSError,ValueError):
                self.errors+=1
                return
            if self.limit_reached:return

    def start(self):
        if self.thread is not None:raise ValueError("native process sampler already started")
        self.sample()
        self.thread=threading.Thread(target=self._loop,name="observer-native-process-samples",daemon=True)
        self.thread.start()
        return self

    def stop(self):
        if self.stream.closed:return self.rows
        self._stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
            if self.thread.is_alive():raise RuntimeError("native process sampler failed to stop")
        self.sample()
        self.stream.flush();os.fsync(self.stream.fileno());self.stream.close()
        write_new(self.directory/"native-process-sampling-summary.json",{
            "status":"SAMPLED_NOT_EXHAUSTIVE","interval_ms":self.interval_ms,
            "sample_count":len(self.rows),"distinct_argv_cwd_identities":len(self.seen),
            "errors":self.errors,"sample_limit_reached":self.limit_reached,
            "sampler_work_wall_ns":self.duration_ns,
            "scope":"FRESH_OWNED_AGENT_CGROUP_AND_CHILD_CGROUPS",
            "meaning":"LIVE_ARGV_CWD_CANDIDATES_NOT_EXEC_ENTRY_OR_CALL_ID_BINDING; SHORT_PROCESSES_MAY_BE_MISSED",
            "overhead":"SAMPLER_WORK_NOT_PAIRED_WORKLOAD_SLOWDOWN"})
        return self.rows


def correlate_native_commands(application, report, samples):
    """Conservative candidate edges; never changes tool syscall ownership.

All four requirements are explicit: exact shell command, exact cwd, immutable
kernel lifetime in the captured runtime ancestry, and overlapping observed
tool interval. An opaque numeric application handle is intentionally ignored.
"""
    boot=report.get("run",{}).get("boot_id")
    threads={row["key"]:row for row in report.get("threads",[]) if isinstance(row,dict) and row.get("key")}
    roots={row.get("root_key") for row in report.get("tools",[])
           if row.get("tool_call_id")=="codex-native-runtime"
           and row.get("association")=="RUNTIME_GATE_AND_KERNEL_LIFETIME"}
    def in_tree(key):
        seen=set()
        while key in threads and key not in seen:
            if key in roots:return True
            seen.add(key);key=threads[key].get("parent_key")
        return False
    result=[]
    for call in application.get("tool_calls",[]):
        if call.get("tool_name")!="commandExecution":
            result.append({"call_id":call.get("call_id"),"status":"UNBOUND",
                "reason":"NOT_A_PROCESS_COMMAND_ITEM; SHARED_OR_REMOTE_EXECUTION_NOT_GUESSED","candidates":[]})
            continue
        args=call.get("arguments",{})
        command,cwd=args.get("command"),args.get("cwd")
        begin,end=call.get("requested_ns"),call.get("result_delivered_ns")
        candidates={}
        for sample in samples:
            argv=sample.get("argv",[])
            # No shell parsing, basename approximation, fuzzy command matching,
            # timestamp tolerance, or application-handle-to-PID coercion.
            exact_shell=(len(argv)>=3 and argv[0] in ("/bin/bash","/usr/bin/bash","/bin/sh","/usr/bin/sh","/bin/zsh","/usr/bin/zsh")
                and argv[-2] in ("-c","-lc","-cl") and argv[-1]==command)
            if (not exact_shell or sample.get("cwd")!=cwd or sample.get("boot_id")!=boot
                    or type(begin) is not int or type(end) is not int
                    or not begin<=sample.get("end_ns",-1)<=end):continue
            for key,thread in threads.items():
                birth=thread.get("birth_ns",thread.get("thread_birth_ns"))
                hz=sample.get("clock_ticks")
                if (thread.get("tid")!=sample.get("pid") or thread.get("tid")!=thread.get("tgid")
                        or type(birth) is not int or type(hz) is not int or hz<=0
                        or birth*hz//1000000000!=sample.get("start_ticks") or not in_tree(key)):continue
                candidates[key]={"thread_key":key,"pid":sample["pid"],"start_ticks":sample["start_ticks"],
                    "argv":argv,"cwd":cwd,"sample_ns":sample["end_ns"],"kernel_ancestry":"CAPTURED_RUNTIME_DESCENDANT",
                    "basis":"EXACT_LIVE_ARGV_CWD_AND_KERNEL_LIFETIME_AND_OBSERVED_TOOL_INTERVAL"}
        result.append({"call_id":call.get("call_id"),"status":"CORRELATED_NOT_CAUSAL" if len(candidates)==1 else
            "AMBIGUOUS" if candidates else "UNBOUND", "candidates":list(candidates.values()),
            "reason":"NOT_A_CALL_ID_TO_OS_DISPATCH_PROOF; CANDIDATE_ONLY" if candidates else
                "NO_EXACT_CANDIDATE_OBSERVED; SHORT_PROCESSES_OR_UNEXPOSED_ARGUMENTS_MAY_BE_MISSED"})
    return {"schema_version":1,"model":"NATIVE_EXACT_PROCESS_CANDIDATES_V1","links":result,
        "attribution":"CORRELATED_NOT_CAUSAL; NEVER_AUTHORITATIVE_TOOL_SYSCALL_ASSIGNMENT",
        "sampling":"MAY_MISS_SHORT_COMMANDS_AND_ARGV_CWD_TRANSITIONS"}
