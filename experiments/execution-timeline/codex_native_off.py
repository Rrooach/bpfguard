#!/usr/bin/env python3
"""Observer-OFF native Codex control-plane baseline; no BPF/resource sampler.

The same native app-server loop, local transport relay and raw RPC ledger
remain as the comparison harness. Observer's active background-terminal PID
queries are disabled as well as BPF and all resource/process sampling. The
baseline is minimal passive replay/correctness logging, not zero logging.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import tempfile
import time
import uuid

from codex_client import CodexRPC,append_record
from codex_native_events import run_native_agent
from codex_run import start_runtime,proxy_token,usage_record
from common import bind_artifacts,digest,proc_identity,write_new
from model_transport_timing import ModelTransportProxy
import run as linux_run


def collect_native_off(args):
    from codex_native_run import native_command,capture_window,_settle
    if os.geteuid()!=0:raise RuntimeError("native OFF lifecycle requires root in the owned experiment VM")
    if not 1<=args.timeout<=1800:raise ValueError("bounded native replay timeout required")
    for key in ("codex","catalog","workspace","prompt"):
        setattr(args,key,getattr(args,key).resolve(strict=True))
    prompt=args.prompt.read_text()
    if not 1<=len(prompt.encode())<=32768:raise ValueError("bounded native prompt required")
    token=proxy_token(args.broker_token_file)
    parent=args.cgroup_parent.resolve(strict=True)
    if not (parent/"cgroup.controllers").is_file():raise ValueError("explicit cgroup v2 parent required")
    root=args.output.resolve();root.mkdir(mode=0o700,parents=True,exist_ok=False)
    app=root/"app";target=root/"native-runtime";app.mkdir();target.mkdir()
    write_new(app/"prompt.txt",prompt.encode());write_new(app/"model-catalog.json",args.catalog.read_bytes())
    native_command(args,app/"model-catalog.json")
    group=parent/("observer-codex-native-off-"+uuid.uuid4().hex);group.mkdir()
    boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    transport,rpc,raw,pid,read_fd,write_fd=None,None,None,None,None,None
    reaped=False;partial={};error=None
    try:
        with tempfile.TemporaryDirectory(prefix="observer-native-codex-private-") as home:
            transport=ModelTransportProxy(app,args.broker_base_url,token,args.budget_label).start()
            command,config=native_command(args,app/"model-catalog.json",base_url=transport.base_url)
            write_new(app/"config.public.json",{"config":config,"budget_label":args.budget_label,
                "provider_provenance":getattr(args,"provider_provenance","EXTERNAL_PROVIDER_NOT_INDEPENDENTLY_CLASSIFIED"),
                "agent_loop":"OFFICIAL_CODEX_NATIVE_TOOLS","dynamic_tools":"NONE","capture_mode":"off",
                "comparison_harness":"SAME_PASSIVE_NATIVE_RPC_MODEL_RELAY; NO_BPF_RESOURCE_PROCESS_SAMPLING_OR_ACTIVE_OSPID_QUERIES"})
            capture_begin=time.monotonic_ns()
            environment={"PATH":str(args.codex.parent)+":/usr/local/bin:/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8",
                "CODEX_HOME":home,"OBSERVER_BROKER_TOKEN":token}
            pid,read_fd,write_fd=start_runtime(command,group,target,args.workspace,environment)
            tool={"agent_id":args.agent_id,"task_id":args.task_id,"tool_call_id":"codex-native-runtime",
                "root":proc_identity(pid),"cgroup_id":group.stat().st_ino,"cgroup_path":str(group),"command":command,
                "gate":"SIGSTOP_AFTER_CGROUP_ENTRY_BEFORE_EXEC","invocation_ns":time.monotonic_ns(),"begin_ns":None,"end_ns":None}
            append_record(root/"tool-spans.jsonl",{"event":"TOOL_ENROLLED",**tool})
            raw=(target/"stdout").open("xb");rpc=CodexRPC(read_fd,write_fd,app,boot,raw)
            tool["begin_ns"]=time.monotonic_ns()
            append_record(root/"tool-spans.jsonl",{"event":"TOOL_START",**tool});os.kill(pid,signal.SIGCONT)
            def progress(value):
                nonlocal partial
                partial=json.loads(json.dumps(value))
            try:
                state=run_native_agent(rpc,prompt,args.workspace,app,model=args.model,timeout=args.timeout,
                    agent_id=args.agent_id,task_id=args.task_id,budget_label=args.budget_label,progress=progress,os_pid_tracker=None)
            except BaseException as failure:
                error=type(failure).__name__+": "+str(failure)[:2048]
                state={"schema_version":2,"mode":"OFFICIAL_CODEX_NATIVE_TOOLS_NO_REPLACEMENT",**partial,
                    "agent_id":args.agent_id,"task_id":args.task_id,"budget_label":args.budget_label,
                    "begin_ns":partial.get("begin_ns",tool["begin_ns"]),"end_ns":time.monotonic_ns(),
                    "status":"NATIVE_CLIENT_OR_RUNTIME_FAILURE","error":error}
                if not (app/"steps.json").exists():write_new(app/"steps.json",state)
            finally:
                rpc.close_input();write_fd=None
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    found,status,usage=os.wait4(pid,os.WNOHANG)
                    if found:reaped=True;break
                    time.sleep(.005)
                if not reaped:
                    tool["cleanup"]="OWNED_CGROUP_TERMINATED_AFTER_CLIENT_CLOSE";linux_run.kill_group(group)
                    _,status,usage=os.wait4(pid,0);reaped=True
                tool.update(result=os.waitstatus_to_exitcode(status),rusage={**usage_record(usage),
                    "max_rss_kib":usage.ru_maxrss,"memory_scope":"WAIT4_ROOT_AND_REAPED_CHILDREN_HIGHWATER_NOT_SUM"},
                    root_exit_observed_ns=time.monotonic_ns())
                if linux_run.populated(group):
                    tool["cleanup"]="OWNED_CGROUP_RESIDUAL_DESCENDANTS_TERMINATED";linux_run.kill_group(group)
                if not _settle(group):raise RuntimeError("OFF native cgroup remained populated")
                while True:
                    block=os.read(read_fd,65536)
                    if not block:break
                    raw.write(block)
                raw.flush();os.fsync(raw.fileno());raw.close();raw=None;os.close(read_fd);read_fd=None
                tool.update(end_ns=time.monotonic_ns(),cgroup_empty=True,
                    termination="FORCED_CGROUP_CLEANUP" if tool.get("cleanup") else "NATURAL_CGROUP_EMPTY")
                append_record(root/"tool-spans.jsonl",{"event":"TOOL_END",**tool})
            transport.stop()
            write_new(app/"codex-result.json",state)
            names=[str(path.relative_to(root)) for path in sorted(root.rglob("*")) if path.is_file()]
            baseline={"schema_version":1,"run_id":args.run_id or "native-off-"+uuid.uuid4().hex,"boot_id":boot,
                "clock":"CLOCK_MONOTONIC",**capture_window(capture_begin,time.monotonic_ns(),tool),"tools":[tool],
                "observer_enabled":False,"capture_mode":"off","mode":"OFFICIAL_CODEX_NATIVE_TOOLS_NO_REPLACEMENT",
                "agent_id":args.agent_id,"task_id":args.task_id,"agent_outcome":state.get("status"),
                "provider_provenance":getattr(args,"provider_provenance","EXTERNAL_PROVIDER_NOT_INDEPENDENTLY_CLASSIFIED"),
                "codex_identity":digest(args.codex),"verification_status":"NOT_APPLICABLE_NO_KERNEL_CAPTURE",
                "comparison_harness":"MINIMAL_PASSIVE_NATIVE_RPC_MODEL_RELAY_CORRECTNESS_LOGGING; ACTIVE_OSPID_QUERIES_DISABLED",
                "resource_sampling":"NOT_SELECTED","artifacts":bind_artifacts(root,names)}
            write_new(root/"baseline.json",baseline)
            return {"output":str(root),"capture_mode":"off","agent_outcome":state.get("status"),"error":error,
                "native_tool_calls":len(state.get("tool_calls",[])),"verification":"NOT_APPLICABLE_NO_KERNEL_CAPTURE"}
    finally:
        if pid is not None and not reaped:
            linux_run.kill_group(group)
            try:os.waitpid(pid,0)
            except ChildProcessError:pass
        if linux_run.populated(group):linux_run.kill_group(group);_settle(group)
        if transport is not None:transport.stop()
        if rpc is not None:rpc.close_input()
        elif write_fd is not None:os.close(write_fd)
        if read_fd is not None:os.close(read_fd)
        if raw is not None:raw.close()
        if not linux_run.populated(group):
            try:group.rmdir()
            except OSError:pass
