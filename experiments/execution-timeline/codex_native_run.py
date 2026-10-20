#!/usr/bin/env python3
"""Observe normal Codex native tools and its entire cooperative Linux tree.

This intentionally does not implement observer_bash, install dynamic tools,
disable native shell/Code Mode, or claim opaque processId handles are PIDs.
Run only in an owned experiment VM: danger-full-access is not containment.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import uuid

from codex_client import CodexRPC, append_record
from codex_native_events import run_native_agent
from codex_run import finalize_replay, proxy_token, start_runtime, usage_record
from common import bind_artifacts, digest, proc_identity, write_new
from model_transport_timing import ModelTransportProxy
from resource_accounting import capture, tool_accounting
from runtime_resources import RuntimeResourceSampler
from native_process_samples import NativeProcessSampler, correlate_native_commands
from native_os_pid import NativeOsPidTracker, verify_native_pid_links
import run as linux_run


def native_command(args, catalog, *, base_url=None):
    endpoint = base_url or args.broker_base_url
    parsed = urlsplit(endpoint)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None
            or parsed.path != "/v1" or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("an explicit local authenticated budget broker /v1 endpoint is required")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", args.budget_label):
        raise ValueError("bounded budget label required")
    if not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", args.model):
        raise ValueError("bounded provider model identifier required")
    config = {"model": args.model, "model_provider": "observer_proxy", "forced_login_method": "api",
        "model_reasoning_effort": "none", "model_catalog_json": str(catalog),
        "model_providers.observer_proxy.name": "Budgeted native Codex provider",
        "model_providers.observer_proxy.base_url": endpoint,
        "model_providers.observer_proxy.env_key": "OBSERVER_BROKER_TOKEN",
        "model_providers.observer_proxy.wire_api": "responses",
        "model_providers.observer_proxy.requires_openai_auth": False,
        "model_providers.observer_proxy.request_max_retries": 0,
        "model_providers.observer_proxy.stream_max_retries": 0,
        "model_providers.observer_proxy.stream_idle_timeout_ms": 180000,
        "model_providers.observer_proxy.supports_websockets": False,
        "features.shell_tool": True, "features.unified_exec": True,
        "features.code_mode": True, "features.code_mode_host": True,
        "web_search": "disabled", "otel.exporter": "none", "shell_environment_policy.inherit": "none"}
    command = [str(args.codex), "app-server", "--listen", "stdio://", "--strict-config"]
    for key, value in config.items():
        command += ["-c", key + "=" + json.dumps(value)]
    command += ["-c", "model_providers.observer_proxy.http_headers="
                + '{"X-Benchmark-Task"=' + json.dumps(args.budget_label) + "}"]
    return command, config


def _settle(group, timeout=5):
    deadline = time.monotonic()+timeout
    while linux_run.populated(group) and time.monotonic() < deadline:
        time.sleep(.005)
    return not linux_run.populated(group)


def capture_window(capture_begin_ns,end_ns,tool):
    """The run starts before invocation; SIGCONT is only the tool release."""
    values=(capture_begin_ns,tool.get("invocation_ns"),tool.get("begin_ns"),tool.get("end_ns"),end_ns)
    if any(type(value) is not int for value in values) or not (
            values[0]<=values[1]<=values[2]<values[3]<=values[4]):
        raise ValueError("capture start <= invocation <= release < closure <= capture end required")
    return {"begin_ns":capture_begin_ns,"end_ns":end_ns}


def collect_native(args):
    if getattr(args,"capture_mode","full")=="off":
        from codex_native_off import collect_native_off
        return collect_native_off(args)
    if os.geteuid() != 0 or not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise RuntimeError("root in an owned Linux VM with writable cgroup v2 is required")
    if not 1 <= args.timeout <= 1800 or not 4096 <= args.ring_bytes <= 256*1024**2 or args.ring_bytes & (args.ring_bytes-1):
        raise ValueError("bounded timeout and power-of-two ring size required")
    for key in ("collector", "object", "codex", "catalog", "workspace", "prompt"):
        setattr(args, key, getattr(args, key).resolve(strict=True))
    if not args.workspace.is_dir():
        raise ValueError("task workspace directory required")
    prompt = args.prompt.read_text()
    if not 1 <= len(prompt.encode()) <= 32768:
        raise ValueError("bounded public task prompt required")
    token = proxy_token(args.broker_token_file)
    parent = args.cgroup_parent.resolve(strict=True)
    if parent == Path("/") or not (parent / "cgroup.controllers").is_file():
        raise ValueError("explicit cgroup v2 parent required")
    root = args.output.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    app, target, pinned = root/"app", root/"native-runtime", root/"pinned-artifacts"
    for directory in (app, target, pinned):
        directory.mkdir(mode=0o700)
    import shutil
    collector, object_path = pinned/"collect", pinned/"execution_timeline.bpf.o"
    shutil.copy2(args.collector, collector)
    shutil.copy2(args.object, object_path)
    write_new(app/"model-catalog.json", args.catalog.read_bytes())
    write_new(app/"prompt.txt", prompt.encode())
    # Validate before starting the HTTP proxy or executing any child.
    native_command(args, app/"model-catalog.json")
    group = parent/("observer-codex-native-"+uuid.uuid4().hex)
    group.mkdir()
    run_id = args.run_id or "codex-native-"+uuid.uuid4().hex
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    collector_process, runtime_pid, rpc, sampler, transport = None, None, None, None, None
    process_sampler=None;os_pid_tracker=None;exec_sidecar=None
    read_fd, write_fd, runtime_reaped, raw_stdout = None, None, False, None
    tool, state, partial, error = None, None, {}, None
    collector_stderr = (root/"collector.stderr").open("xb")
    begin = time.monotonic_ns()
    try:
        with tempfile.TemporaryDirectory(prefix="observer-native-codex-private-") as home:
            transport = ModelTransportProxy(app,args.broker_base_url,token,args.budget_label).start()
            command, config = native_command(args,app/"model-catalog.json",base_url=transport.base_url)
            write_new(app/"config.public.json",{"config":config,"budget_label":args.budget_label,
                "provider_provenance":getattr(args,"provider_provenance","EXTERNAL_PROVIDER_NOT_INDEPENDENTLY_CLASSIFIED"),
                "agent_loop":"OFFICIAL_CODEX_NATIVE_TOOLS", "dynamic_tools":"NONE",
                "native_shell":"ENABLED", "native_code_mode":"ENABLED_NOT_EXTERNALLY_REPLACED",
                "credentials":"LOCAL_PROXY_ENV_ONLY_NOT_LOGGED_OR_INHERITED_BY_SHELL",
                "scope":"WHOLE_CODEX_CGROUP_AND_DESCENDANTS; PER_TOOL_PROCESS_LINKS_UNBOUND",
                "security":"COOPERATIVE_DANGER_FULL_ACCESS_EXPERIMENT_NOT_HOSTILE_CONTAINMENT"})
            write_new(root/"kallsyms.txt",Path("/proc/kallsyms").read_bytes())
            collector_process = subprocess.Popen([str(collector),"--object",str(object_path),
                "--cgroup",str(group),"--output-dir",str(root/"capture"),"--kernel-stacks",
                "--ring-bytes",str(args.ring_bytes),"--max-records",str(args.max_records),
                "--max-bytes",str(args.max_bytes)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=collector_stderr)
            ready = linux_run.ready_line(collector_process,30)
            if ready.get("boot_id") != boot or ready.get("root_cgroup_id") != group.stat().st_ino or ready.get("clock") != "CLOCK_MONOTONIC":
                raise ValueError("native collector READY boot/cgroup/clock differs")
            write_new(root/"ready.json",ready)
            exec_collector=getattr(args,"exec_args_collector",None)
            exec_object=getattr(args,"exec_args_object",None)
            if bool(exec_collector)!=bool(exec_object):
                raise ValueError("both exec-args-collector and exec-args-object are required")
            if exec_collector:
                from native_exec_sidecar import NativeExecSidecar
                exec_sidecar=NativeExecSidecar(exec_collector,exec_object,root,group)
                exec_sidecar.start()
            # Capture/run boundary precedes the launch invocation. The later
            # SIGCONT release is a different boundary and must not overwrite it.
            capture_begin_ns = begin = time.monotonic_ns()
            environment = {"PATH":str(args.codex.parent)+":/usr/local/bin:/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8",
                "CODEX_HOME":home,"OBSERVER_BROKER_TOKEN":token}
            runtime_pid,read_fd,write_fd = start_runtime(command,group,target,args.workspace,environment)
            identity = proc_identity(runtime_pid)
            tool = {"agent_id":args.agent_id,"task_id":args.task_id,"tool_call_id":"codex-native-runtime",
                "root":identity,"cgroup_id":group.stat().st_ino,"cgroup_path":str(group),"command":command,
                "gate":"SIGSTOP_AFTER_CGROUP_ENTRY_BEFORE_EXEC","invocation_ns":time.monotonic_ns(),
                "begin_ns":None,"end_ns":None,"kind":"WHOLE_NATIVE_CODEX_RUNTIME_NOT_AN_INDIVIDUAL_TOOL"}
            append_record(root/"tool-spans.jsonl",{"event":"TOOL_ENROLLED",**tool})
            sampler = RuntimeResourceSampler(root/"resources",agent_id=args.agent_id)
            sampler.register("codex-native-runtime",pid=runtime_pid,role="AGENT_RUNTIME",cgroup=group,
                cgroup_scope="FRESH_EXCLUSIVE_AGENT_CGROUP_INCLUDES_RUNTIME_AND_ALL_NATIVE_TOOL_DESCENDANTS")
            sampler.register("observer-supervisor",pid=os.getpid(),role="OBSERVER_SUPERVISOR")
            sampler.register("observer-collector",pid=collector_process.pid,role="OBSERVER_COLLECTOR")
            if exec_sidecar:
                sampler.register("observer-exec-args",pid=exec_sidecar.process.pid,role="OBSERVER_EXEC_ARGV_COLLECTOR")
            sampler.start()
            process_sampler=NativeProcessSampler(group,app,interval_ms=args.process_sample_ms).start()
            os_pid_tracker=NativeOsPidTracker(app,group)
            before = capture(group)
            raw_stdout = (target/"stdout").open("xb")
            rpc = CodexRPC(read_fd,write_fd,app,boot,raw_stdout)
            tool["begin_ns"] = time.monotonic_ns()
            append_record(root/"tool-spans.jsonl",{"event":"TOOL_START",**tool})
            os.kill(runtime_pid,signal.SIGCONT)
            def progress(value):
                nonlocal partial
                partial = json.loads(json.dumps(value))
            try:
                state = run_native_agent(rpc,prompt,args.workspace,app,model=args.model,timeout=args.timeout,
                    agent_id=args.agent_id,task_id=args.task_id,budget_label=args.budget_label,progress=progress,
                    os_pid_tracker=os_pid_tracker)
            except BaseException as failure:
                error = type(failure).__name__+": "+str(failure)[:2048]
                state = {"schema_version":2,"mode":"OFFICIAL_CODEX_NATIVE_TOOLS_NO_REPLACEMENT",**partial,
                    "agent_id":args.agent_id,"task_id":args.task_id,"budget_label":args.budget_label,
                    "begin_ns":partial.get("begin_ns",begin),"end_ns":time.monotonic_ns(),
                    "function_bindings":[],"steps":partial.get("steps",[]),"tool_calls":partial.get("tool_calls",[]),
                    "status":"NATIVE_CLIENT_OR_RUNTIME_FAILURE","error":error}
                if not (app/"steps.json").exists():
                    write_new(app/"steps.json",state)
            finally:
                rpc.close_input()
                write_fd = None
                deadline=time.monotonic()+5
                while time.monotonic() < deadline:
                    found,status,usage=os.wait4(runtime_pid,os.WNOHANG)
                    if found:
                        runtime_reaped=True
                        break
                    time.sleep(.005)
                if not runtime_reaped:
                    tool["cleanup"]="OWNED_CGROUP_TERMINATED_AFTER_CLIENT_CLOSE"
                    linux_run.kill_group(group)
                    _,status,usage=os.wait4(runtime_pid,0)
                    runtime_reaped=True
                tool.update(result=os.waitstatus_to_exitcode(status),rusage={**usage_record(usage),
                    "max_rss_kib":usage.ru_maxrss,"memory_scope":"WAIT4_ROOT_AND_REAPED_CHILDREN_HIGHWATER_NOT_SUM"},
                    root_exit_observed_ns=time.monotonic_ns())
                if linux_run.populated(group):
                    tool["cleanup"]="OWNED_CGROUP_RESIDUAL_DESCENDANTS_TERMINATED"
                    linux_run.kill_group(group)
                if not _settle(group):
                    raise RuntimeError("native runtime cgroup remained populated; no completed evidence claim")
                # All writers are gone, making this final stdout drain bounded by EOF.
                while True:
                    block=os.read(read_fd,65536)
                    if not block:break
                    raw_stdout.write(block)
                raw_stdout.flush();os.fsync(raw_stdout.fileno());raw_stdout.close();raw_stdout=None
                os.close(read_fd);read_fd=None
                tool.update(cgroup_empty=True,end_ns=time.monotonic_ns(),
                    termination="FORCED_CGROUP_CLEANUP" if tool.get("cleanup") else "NATURAL_CGROUP_EMPTY",
                    resources=tool_accounting(before,capture(group)))
                sampler.finish("codex-native-runtime",reason="ROOT_WAIT4_AND_WHOLE_AGENT_CGROUP_EMPTY",
                    confirmed_exit=tool["result"],exit_source="OS_WAIT4")
                append_record(root/"tool-spans.jsonl",{"event":"TOOL_END",**tool})
            end=time.monotonic_ns()
            transport.stop()
            exec_receipt=exec_sidecar.stop() if exec_sidecar else None
            if exec_receipt and exec_receipt["return_code"]!=0:
                raise RuntimeError("requested exec argv collector failed; raw evidence retained")
            resources=sampler.stop()
            process_samples=process_sampler.stop()
            os_pid_tracker.finish()
            write_new(app/"codex-result.json",state)
            collector_process.stdin.write(b"STOP\n");collector_process.stdin.flush();collector_process.stdin.close()
            code=collector_process.wait(timeout=30)
            collector_stderr.close()
            if code != 0 or not (root/"capture/health.json").is_file():
                raise RuntimeError("native collector did not finalize successfully")
            names=[str(path.relative_to(root)) for path in sorted(root.rglob("*")) if path.is_file()]
            manifest={"schema_version":1,"run_id":run_id,"boot_id":boot,"kernel_release":os.uname().release,
                "clock":"CLOCK_MONOTONIC",**capture_window(capture_begin_ns,end,tool),"tools":[tool],
                "agent_id":args.agent_id,"task_id":args.task_id,"mode":"OFFICIAL_CODEX_NATIVE_TOOLS_NO_REPLACEMENT",
                "provider_provenance":getattr(args,"provider_provenance","EXTERNAL_PROVIDER_NOT_INDEPENDENTLY_CLASSIFIED"),
                "exec_args_capture":exec_receipt,
                "capture_directory":"capture","collector_binary":str(collector),"collector_identity":digest(collector),
                "collector_return_code":code,"bpf_object":str(object_path),"bpf_identity":digest(object_path),
                "codex_binary":str(args.codex),"codex_identity":digest(args.codex),
                "agent_outcome":state.get("status"),"agent_application_window":{"begin_ns":state.get("begin_ns"),"end_ns":state.get("end_ns")},
                "resource_sampling":{"summary":"resources/resource-summary.json","samples":"resources/resource-samples.jsonl",
                    "interval_ms":resources["interval_ms"],"coverage":resources["status"]},
                "scope":{"kind":"COOPERATIVE_DIRECT_CGROUP_DESCENDANTS","root_cgroup":str(group),
                    "root_cgroup_id":group.stat().st_ino,"kernel_stacks":True,"gpu":"NOT_SELECTED",
                    "runtime_kernel_scope":"WHOLE_CODEX_RUNTIME_AND_ALL_DESCENDANTS",
                    "tool_process_binding":"NATIVE_APPLICATION_REPORTS_UNBOUND; PROCESSID_IS_NOT_OS_PID",
                    "security":"COOPERATIVE_EXPERIMENT_NOT_HOSTILE_CONTAINMENT"},
                "artifacts":bind_artifacts(root,names)}
            write_new(root/"manifest.json",manifest)
            verification=finalize_replay(root)
            write_new(root/"verification.json",verification)
            if (root/"report.json").is_file():
                report=json.loads((root/"report.json").read_text())
                write_new(root/"native-process-correlations.json",correlate_native_commands(state,report,process_samples))
                rpc_rows=[json.loads(line) for line in (app/"rpc.jsonl").read_text().splitlines() if line.strip()]
                write_new(root/"native-os-pid-links.json",verify_native_pid_links(state,report,os_pid_tracker.rows,rpc_rows))
            return {"output":str(root),"agent_outcome":state.get("status"),"error":error,
                "native_tool_calls":len(state.get("tool_calls",[])),"verification":verification["status"],
                "runtime_kernel_scope":manifest["scope"]["runtime_kernel_scope"],
                "per_tool_process_binding":"UNBOUND_NO_FABRICATED_PID_OR_TIME_MATCH"}
    finally:
        if runtime_pid is not None and not runtime_reaped:
            linux_run.kill_group(group)
            try:os.waitpid(runtime_pid,0)
            except ChildProcessError:pass
        if linux_run.populated(group):
            linux_run.kill_group(group)
            _settle(group)
        if transport is not None:transport.stop()
        if exec_sidecar is not None:exec_sidecar.stop()
        if sampler is not None:sampler.stop()
        if process_sampler is not None:process_sampler.stop()
        if collector_process is not None and collector_process.poll() is None:
            collector_process.terminate()
            try:collector_process.wait(timeout=5)
            except subprocess.TimeoutExpired:collector_process.kill();collector_process.wait(timeout=5)
        if rpc is not None:rpc.close_input()
        elif write_fd is not None:os.close(write_fd)
        if read_fd is not None:os.close(read_fd)
        if raw_stdout is not None:raw_stdout.close()
        if not collector_stderr.closed:collector_stderr.close()
        if not linux_run.populated(group):
            try:group.rmdir()
            except OSError:pass


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ("collector","object","codex","catalog","workspace","prompt","output","broker-token-file"):
        parser.add_argument("--"+key,type=Path,required=True)
    parser.add_argument("--broker-base-url",default="http://127.0.0.1:10091/v1")
    parser.add_argument("--budget-label",required=True)
    parser.add_argument("--model",default="deepseek-flash")
    parser.add_argument("--capture-mode",choices=("full","off"),default="full",
        help="off keeps the same native RPC/HTTP replay harness but loads no BPF and no resource sampler")
    parser.add_argument("--provider-provenance",default="EXTERNAL_PROVIDER_NOT_INDEPENDENTLY_CLASSIFIED")
    parser.add_argument("--exec-args-collector",type=Path,
        help="opt-in separate bounded argv collector; never changes the existing timeline WAL ABI")
    parser.add_argument("--exec-args-object",type=Path)
    parser.add_argument("--agent-id",default="codex-native-agent")
    parser.add_argument("--task-id",default="codex-native-task")
    parser.add_argument("--run-id")
    parser.add_argument("--cgroup-parent",type=Path,default=Path("/sys/fs/cgroup"))
    parser.add_argument("--timeout",type=float,default=300)
    parser.add_argument("--ring-bytes",type=int,default=64*1024**2)
    parser.add_argument("--process-sample-ms",type=int,default=20,
        help="bounded /proc argv/cwd candidate sampling; not a call-ID/PID binding")
    parser.add_argument("--max-records",type=int,default=2000000)
    parser.add_argument("--max-bytes",type=int,default=2*1024**3)
    args=parser.parse_args(argv)
    print(json.dumps(collect_native(args),ensure_ascii=False),flush=True)


if __name__ == "__main__":
    main()
