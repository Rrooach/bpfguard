#!/usr/bin/env python3
"""Real Codex + instrumented Node/V8 + local fake Responses, zero paid API.

This validates application timing, resource sampling, and their presentation.
It does not run a benchmark. Kernel capture is optional, explicit, and only
available in the fixture's fresh tool cgroup; no old evidence is reused.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch
import uuid

import codex_harbor_agent as runtime
from code_mode_timing import load_code_mode_events, replay_runtime_events
from common import bind_artifacts, proc_identity, write_new
from execution_metrics import read_jsonl
from render_agent_story import build_story, read_rpc_usage, render
from semantic_profile import build_profile
import run as linux_run


MODE = "LOCAL_DETERMINISTIC_FIXTURE_NO_MODEL_NO_PAID_API"
BINDING = "EXPLICIT_LOCAL_STOPPED_CHILD_PID_STARTTICKS; NO_DOCKER_OR_KERNEL_CAPTURE"
CALL_ID = "call_runtime_metrics_fixture_1"


def response_events(index, tool_name, command):
    if index == 0:
        item = {"type": "function_call", "id": "fc_runtime_fixture", "call_id": CALL_ID,
                "name": tool_name, "arguments": json.dumps({"command": command}), "status": "completed"}
    else:
        item = {"type": "message", "id": "msg_runtime_fixture", "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": "Local deterministic runtime metrics fixture finished.",
                             "annotations": []}]}
    response = {"id": "resp_runtime_fixture_" + str(index), "object": "response",
        "created_at": int(time.time()), "status": "completed", "model": "deepseek-flash",
        "output": [item], "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
    events = [{"type": "response.created", "response": {**response, "status": "in_progress", "output": [], "usage": None}},
        {"type": "response.output_item.added", "output_index": 0,
         "item": {**item, "status": "in_progress", **({"arguments": ""} if index == 0 else {"content": []})}}]
    if index == 0:
        events += [{"type": "response.function_call_arguments.delta", "item_id": item["id"], "output_index": 0,
                    "delta": item["arguments"]},
                   {"type": "response.function_call_arguments.done", "item_id": item["id"], "output_index": 0,
                    "arguments": item["arguments"]}]
    else:
        content = item["content"][0]
        events += [{"type": "response.content_part.added", "item_id": item["id"], "output_index": 0,
                    "content_index": 0, "part": {**content, "text": ""}},
                   {"type": "response.output_text.delta", "item_id": item["id"], "output_index": 0,
                    "content_index": 0, "delta": content["text"]},
                   {"type": "response.output_text.done", "item_id": item["id"], "output_index": 0,
                    "content_index": 0, "text": content["text"]},
                   {"type": "response.content_part.done", "item_id": item["id"], "output_index": 0,
                    "content_index": 0, "part": content}]
    events += [{"type": "response.output_item.done", "output_index": 0, "item": item},
               {"type": "response.completed", "response": response}]
    return b"".join(("event: " + row["type"] + "\ndata: " + json.dumps(row) + "\n\n").encode() for row in events)


class FixtureResponses(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/v1/responses" or self.headers.get("X-Benchmark-Task") != "codex-terminal-smoke-001":
            self.send_error(400, "LOCAL_FIXTURE_REQUEST_MISMATCH")
            return
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        names = [row.get("name") for row in request.get("tools", [])
                 if row.get("type") == "function" and "observer_bash" in str(row.get("name"))]
        index = len(self.server.receipts)
        if len(names) != 1 or index >= 2:
            self.send_error(400, "LOCAL_FIXTURE_TOOL_OR_REQUEST_LIMIT")
            return
        self.server.receipts.append({"request_index": index, "received_ns": time.monotonic_ns(),
            "mode": MODE, "model": request.get("model"), "tool_name": names[0]})
        body = response_events(index, names[0], self.server.command)
        # Known local fixture delays exercise both wait and receive counters.
        time.sleep(.060)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        middle = len(body) // 2
        self.wfile.write(body[:middle]); self.wfile.flush()
        time.sleep(.030)
        self.wfile.write(body[middle:]); self.wfile.flush()

    def log_message(self, *args):
        pass


def node_workload(module, metadata, child_ledger, input_path):
    """Produce actual instrumented JS and an explicitly linked shell child."""
    # wc -c < regular-file can return fstat/lseek size without reading its
    # contents.  Force ordinary read(2), avoiding cat/splice optimizations too.
    reader = "import sys\ncount=0\nwith open(sys.argv[1], 'rb', buffering=0) as source:\n while True:\n  chunk=source.read(128*1024)\n  if not chunk: break\n  count+=len(chunk)\nprint(count)"
    read_command = "python3 -c " + shlex.quote(reader) + ' "$1"; sleep 0.25'
    return """import fs from 'node:fs';
import {spawn} from 'node:child_process';
import {runObservedCodeMode,closeCodeModeLedgers} from MODULE;
const meta=METADATA, input=INPUT, ledger=CHILD_LEDGER;
const childId='child-file-read-fixture-1';
try {
  const result=await runObservedCodeMode(meta,async ({runJS,awaitTool})=>{
    const prepared=runJS('prepare search input and allocate working memory',()=>{
      const values=Array.from({length:1000000},(_,i)=>i%97);
      const buffer=Buffer.alloc(16*1024*1024,97);
      return {values,buffer};
    });
    const bytes=await awaitTool('read fixture input through shell',()=>new Promise((resolve,reject)=>{
      const command=READ_COMMAND;
      const argv=['-c',command,'runtime-metrics-fixture',input];
      const child=spawn('/bin/sh',argv,{stdio:['ignore','pipe','pipe']});
      let out='',err='';
      child.stdout.on('data',data=>{out+=data}); child.stderr.on('data',data=>{err+=data});
      let startTicks=null;
      try {const raw=fs.readFileSync('/proc/'+child.pid+'/stat','utf8');
        startTicks=Number(raw.slice(raw.lastIndexOf(')')+2).trim().split(/\\s+/)[19]);} catch {}
      fs.appendFileSync(ledger,JSON.stringify({event:'LOCAL_CHILD_STARTED',child_call_id:childId,
        parent_call_id:meta.call_id,run_id:meta.run_id,agent_id:meta.agent_id,task_id:meta.task_id,
        pid:child.pid,start_ticks:startTicks,parent_pid:process.pid,command:['/bin/sh',...argv],
        monotonic_ns:process.hrtime.bigint().toString(),scope:'APPLICATION_SPAWN_IDENTITY_NOT_KERNEL_TRACE'})+'\\n');
      child.on('error',reject);
      child.on('close',code=>{
        fs.appendFileSync(ledger,JSON.stringify({event:'LOCAL_CHILD_COMPLETED',child_call_id:childId,
          parent_call_id:meta.call_id,pid:child.pid,exit_code:code,stdout:out,stderr:err,
          monotonic_ns:process.hrtime.bigint().toString()})+'\\n');
        if(code!==0)reject(new Error('fixture child failed')); else resolve(Number(out.trim()));
      });
    }),{call_id:childId});
    return runJS('reduce search input and format result',()=>({bytes,
      checksum:prepared.values.reduce((sum,value)=>sum+value,0),bufferBytes:prepared.buffer.length}));
  });
  if(result.bytes!==4*1024*1024)throw new Error('fixture read byte count differs');
  console.log(JSON.stringify({mode:'REAL_NODE_V8_LOCAL_FIXTURE',...result}));
} finally {closeCodeModeLedgers();}
""".replace("MODULE", json.dumps(module.as_uri())).replace("METADATA", json.dumps(metadata)).replace(
        "INPUT", json.dumps(str(input_path))).replace("CHILD_LEDGER", json.dumps(str(child_ledger))).replace(
        "READ_COMMAND", json.dumps(read_command))


def input_read_proof(report, input_path, expected_bytes):
    """Prove file content reads from same-call VFS objects, not stdout/stat."""
    path=Path(input_path).resolve(strict=True)
    stat=path.stat()
    selected=[]; pipes=[]; seen={}
    for thread in report.get("threads",[]):
        for call in thread.get("calls",[]):
            for obj in call.get("files",[]):
                read=obj.get("read",{})
                amount=read.get("returned_bytes")
                if type(amount) is not int or amount<0:
                    continue
                key=(thread.get("tid"),thread.get("birth_ns"),call.get("call_id"),
                     read.get("start_ns"),read.get("end_ns"),obj.get("mount_id_unique"),obj.get("inode"))
                if key in seen:
                    if seen[key]!=amount:raise RuntimeError("conflicting duplicate VFS read evidence")
                    continue
                seen[key]=amount
                row={"tid":thread.get("tid"),"call_id":call.get("call_id"),
                    "syscall":call.get("name"),"path":obj.get("path"),"path_quality":obj.get("path_quality"),
                    "inode":obj.get("inode"),"mount_id_unique":obj.get("mount_id_unique"),
                    "device_major":obj.get("device_major"),"device_minor":obj.get("device_minor"),
                    "requested_bytes":read.get("requested_bytes"),"returned_bytes":amount,
                    "start_ns":read.get("start_ns"),"end_ns":read.get("end_ns")}
                if obj.get("path")==str(path):
                    if obj.get("inode")!=stat.st_ino or obj.get("device_major")!=os.major(stat.st_dev) or \
                            obj.get("device_minor")!=os.minor(stat.st_dev):
                        raise RuntimeError("input file VFS object identity differs from fixture input")
                    selected.append(row)
                elif str(obj.get("path","")).startswith("pipe:"):
                    pipes.append(row)
    total=sum(row["returned_bytes"] for row in selected)
    if total!=expected_bytes:
        raise RuntimeError(f"actual input VFS reads {total} != expected {expected_bytes}; stdout/file size are not substitutes")
    return {"status":"EXACT_INPUT_PATH_DEVICE_INODE_AND_SAME_CALL_VFS_READ_PROVEN",
        "input_path":str(path),"expected_bytes":expected_bytes,"input_file_actual_read_bytes":total,
        "input_object_identity":{"inode":stat.st_ino,"device_major":os.major(stat.st_dev),
            "device_minor":os.minor(stat.st_dev)},
        "input_file_vfs_read_calls":len(selected),"input_file_reads":selected,
        "pipe_vfs_read_returned_bytes":sum(row["returned_bytes"] for row in pipes),"pipe_reads":pipes,
        "pipe_identification":"KERNEL_PATH_PIPE_PREFIX; UNRESOLVED_OBJECTS_NOT_ASSUMED_PIPES",
        "accounting":"INPUT_FILE_BYTES_ONLY; PIPE_AND_OTHER_FILE_READS_NOT_ADDED_TO_INPUT_CONTENT_BYTES"}


def validate(args):
    codex, catalog = args.codex.resolve(strict=True), args.catalog.resolve(strict=True)
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("real Node/V8 required")
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    app, workspace = output / "app", output / "workspace"
    app.mkdir(); workspace.mkdir()
    run_id = "runtime-metrics-fixture-" + uuid.uuid4().hex
    agent_id, task_id = "codex-local-runtime-validation", "LOCAL_RUNTIME_METRICS_NOT_BENCHMARK"
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    input_path = workspace / "input.bin"
    write_new(input_path, b"a" * (4 * 1024 * 1024))
    metadata = {"run_id": run_id, "agent_id": agent_id, "task_id": task_id,
        "call_id": CALL_ID, "ledgerPath": str(app / "code-mode-events.jsonl")}
    module = Path(__file__).with_name("observer-code-mode.mjs").resolve()
    workload = workspace / "workload.mjs"
    write_new(workload, node_workload(module, metadata, app / "child-process-events.jsonl", input_path).encode())
    command = "exec " + shlex.join([node, str(workload)])
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureResponses)
    server.command, server.receipts = command, []
    server_thread = threading.Thread(target=server.serve_forever, daemon=True); server_thread.start()
    spans = []
    native = None
    selected_binding = "EXPLICIT_LOCAL_STOPPED_CHILD_PID_STARTTICKS_AND_NATIVE_TOOL_CGROUP" \
        if getattr(args,"collector",None) is not None else BINDING
    try:
        with tempfile.TemporaryDirectory(prefix="observer-local-fixture-credential-") as private:
            token = Path(private) / "token"
            write_new(token, b"LOCAL_DETERMINISTIC_FAKE_PROVIDER_ONLY")
            settings = runtime.CodexSettings("http://127.0.0.1:" + str(server.server_port) + "/v1", token,
                "codex-terminal-smoke-001", app, agent_id, task_id, boot_id, codex, catalog)
            settings.thread_cwd = workspace
            settings.benchmark_kind = "LOCAL_PROTOCOL_RESOURCE_VALIDATION_NOT_BENCHMARK"
            settings.base_instructions = ("Execute the supplied harmless local runtime fixture using observer_bash, then finish. "
                "This is deterministic fake-provider validation, not a benchmark or real model inference.")
            settings.gate = SimpleNamespace(resource_sampler=None)
            resource_root=getattr(args,"resource_cgroup_root",None)
            if resource_root is not None:
                resource_root=resource_root.resolve(strict=True)
                if resource_root.parent!=Path("/sys/fs/cgroup") or not resource_root.name.startswith("observer-runtime-fixture-"):
                    raise ValueError("explicit fresh fixture cgroup root required")
                settings.runtime_cgroup=resource_root/"runtime"
                settings.runtime_cgroup_owned=True
            if getattr(args,"collector",None) is not None:
                if resource_root is None:
                    raise ValueError("native capture requires --private-cgroups or its owned child mode")
                from native_fixture_capture import NativeFixtureCapture
                native=NativeFixtureCapture(output,args.collector,args.object,resource_root/"tool",run_id).start()
                settings.observer_cgroup=resource_root/"observer"

            def execute(text, call_id, request_id):
                if text != command or call_id != CALL_ID:
                    raise ValueError("local fixture command/call identity differs")
                stdout_path, stderr_path = app / "tool.stdout", app / "tool.stderr"
                with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                    invocation_ns=time.monotonic_ns()
                    if native is not None:
                        launch=["/bin/sh","-c",'printf "%s" "$$" > "$1"; kill -STOP $$; exec /bin/bash --noprofile --norc -c "$2"',
                            "observer-owned-tool",str(resource_root/"tool"/"cgroup.procs"),text]
                    else:
                        launch=["/bin/sh","-c","kill -STOP $$; exec /bin/bash --noprofile --norc -c "+shlex.quote(text)]
                    child = subprocess.Popen(launch,
                        stdout=stdout, stderr=stderr, cwd=workspace, start_new_session=True)
                    sampler = settings.gate.resource_sampler
                    try:
                        linux_run.wait_stopped(child.pid, 5)
                        identity = proc_identity(child.pid)
                        tool_id = "local-metrics-tool-1"
                        tool_cgroup=resource_root/"tool" if resource_root is not None else None
                        if tool_cgroup is not None:
                            (tool_cgroup/"cgroup.procs").write_text(str(child.pid))
                        sampler.register(tool_id, pid=child.pid, role="TOOL_ROOT", tool_call_id=tool_id,
                            cgroup=tool_cgroup,cgroup_scope="FRESH_EXCLUSIVE_TOOL_CGROUP_INCLUDES_DESCENDANTS")
                        if native is not None:
                            sampler.register("observer-native-collector",pid=native.process.pid,role="OBSERVER_COLLECTOR",
                                cgroup=resource_root/"observer",cgroup_scope="SHARED_OBSERVER_FIXTURE_CGROUP_INCLUDES_SUPERVISOR_AND_COLLECTOR")
                            native_tool={"agent_id":agent_id,"task_id":task_id,"tool_call_id":tool_id,
                                "command":text,"root":identity,"cgroup_id":tool_cgroup.stat().st_ino,
                                "invocation_ns":invocation_ns,"gate":"SELF_CGROUP_ENTRY_SIGSTOP_BEFORE_EXEC",
                                "begin_ns":None,"end_ns":None}
                            native.event("TOOL_ENROLLED",native_tool)
                        begin = time.monotonic_ns()
                        if native is not None:
                            native_tool["begin_ns"]=begin
                            native.event("TOOL_START",native_tool)
                        os.kill(child.pid, signal.SIGCONT)
                        code = child.wait(timeout=15)
                        end = time.monotonic_ns()
                        sampler.finish(tool_id,reason="TOOL_ROOT_WAIT_CONFIRMED",confirmed_exit=code,exit_source="SUBPROCESS_WAIT")
                        if native is not None:
                            native_tool.update(end_ns=end,result={"return_code":code},cgroup_empty=not linux_run.populated(tool_cgroup))
                            native.event("TOOL_END",native_tool)
                    finally:
                        if child.poll() is None:
                            os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
                out, err = stdout_path.read_text(), stderr_path.read_text()
                binding = {"observer_tool_call_id": tool_id, "tool_call_id": tool_id,
                    "agent_id": agent_id, "task_id": task_id, "boot_id": boot_id,
                    "budget_label": settings.budget_label, "root_pid": child.pid, "root": identity,
                    "begin_ns": begin, "end_ns": end, "gate_result": {"return_code": code,
                        "stdout_bytes": len(out.encode()), "stderr_bytes": len(err.encode())},
                    "stdout_artifact": "app/tool.stdout", "stderr_artifact": "app/tool.stderr",
                    "gate_binding_basis": selected_binding, "kernel_evidence": "REAL_NATIVE_CAPTURE" if native else "NOT_COLLECTED"}
                if native is not None:
                    binding["cgroup_id"]=native.cgroup_id
                spans.append({**binding, "command": command, "result": {"return_code": code}})
                return {"exit_code": code, "stdout": out, "stderr": err, "output_truncated": False, "binding": binding}

            # Reuse the transport lifecycle while accurately declaring the
            # local stopped-child fixture instead of the Docker adapter basis.
            with patch.object(runtime, "BINDING", selected_binding):
                result = runtime.run_runtime(settings, "Run the local instrumented V8 fixture and finish.", execute)
            if result["status"] != "completed" or len(spans) != 1 or len(server.receipts) != 2:
                raise RuntimeError("real Codex/local fixture did not finish exactly one tool and two requests")
        mode = replay_runtime_events(load_code_mode_events(app / "code-mode-events.jsonl"))
        call = mode["invocations"][0]
        if not call["js_ms"] or not call["tool_wait_ms"] or call["memory"]["heap_used_bytes"]["max_observed"] <= 0:
            raise RuntimeError("explicit JS, child wait, or V8 memory evidence absent")
        report = {"schema_version": 1, "run": {"run_id": run_id, "boot_id": boot_id,
            "begin_ns": result["begin_ns"], "end_ns": result["end_ns"]}, "tools": spans, "threads": [],
            "health": {"status": "NOT_COLLECTED_PROTOCOL_VALIDATION", "counters": {}},
            "critical_path": {"status": "NOT_COLLECTED", "tools": []}, "totals": {"events": 0},
            "findings": [{"kind": "NO_KERNEL_CAPTURE", "scope": "APPLICATION_PROCESS_GATE_AND_RESOURCE_VALIDATION_ONLY"}]}
        if native is not None:
            report=native.finish(result)
            read_proof=input_read_proof(report,input_path,4*1024*1024)
            write_new(output/"input-file-read-proof.json",read_proof)
        write_new(output / "presentation-report.json", report)
        write_new(output / "fixture-provider-receipts.json", {"mode": MODE, "requests": server.receipts})
        write_new(output / "official-result.json", {"status": "NOT_PROVIDED", "reason": "Not a benchmark"})
        summary = json.loads((app / "resource-summary.json").read_text())
        story = build_story(report, result, rpc_usage=read_rpc_usage(app / "rpc.jsonl"),
            model_timing=read_jsonl(app / "model-request-timing.jsonl"), code_mode=mode,
            resource_summary=summary, resource_samples=read_jsonl(app / "resource-samples.jsonl"),
            model_transport_summary=json.loads((app / "model-transport-summary.json").read_text()),
            rpc_rows=read_jsonl(app/"rpc.jsonl"),tool_event_rows=read_jsonl(app/"tool-events.jsonl"),
            runtime_cleanup=json.loads((app/"runtime-cgroup-cleanup.json").read_text())
                if (app/"runtime-cgroup-cleanup.json").is_file() else None)
        if (len(story["model_requests"]) != 2 or
                any(row["clock_alignment"] != "SAME_BOOT" for row in story["model_requests"]) or
                story["model_collection"]["status"] != "COMPLETE_AT_DECLARED_HTTP_BOUNDARY" or
                "CONCURRENT" in story["wall_partition"]["totals_ns"] or
                not story["memory"]["series"] or (story["total_syscalls"] <= 0 if native else story["total_syscalls"] != 0) or
                sum(story["wall_partition"]["totals_ns"].values()) != result["end_ns"] - result["begin_ns"]):
            raise RuntimeError("model timing, resource identity, or conserved wall-clock projection failed")
        profile = build_profile(story)
        write_new(output / "story.json", story)
        write_new(output / "semantic-profile.json", profile)
        write_new(output / "index.html", render(story, profile).encode())
        checks = {"mode": MODE, "status": "APPLICATION_TIMING_AND_RESOURCE_VALIDATION_PASSED",
            "run_id": run_id, "agent_id": agent_id, "task_id": task_id,
            "kernel_capture": "REAL_NATIVE_TOOL_CGROUP" if native else "NOT_COLLECTED", "official_result": "NOT_PROVIDED",
            "kernel_events":report["totals"]["events"],"tool_syscalls":story["total_syscalls"],
            "kernel_replay":"REPLAY_PASSED" if native else "NOT_APPLICABLE",
            "input_file_actual_read_bytes":read_proof["input_file_actual_read_bytes"] if native else None,
            "input_file_vfs_read_calls":read_proof["input_file_vfs_read_calls"] if native else None,
            "pipe_vfs_read_returned_bytes":read_proof["pipe_vfs_read_returned_bytes"] if native else None,
            "paid_api_calls": 0, "real_codex_binary": str(codex), "real_node_binary": node,
            "model_requests": len(story["model_requests"]), "agent_wall_ms": story["agent_wall_ms"],
            "model_request_ms": sum(row["request_ms"] for row in story["model_requests"]),
            "model_wait_ms": sum(row["wait_first_byte_ms"] or 0 for row in story["model_requests"]),
            "v8_js_ms": call["js_ms"], "v8_child_wait_ms": call["tool_wait_ms"],
            "v8_heap_used_max_observed_bytes": call["memory"]["heap_used_bytes"]["max_observed"],
            "v8_process_rss_max_observed_bytes": call["memory"]["rss_bytes"]["max_observed"],
            "resource_sample_count": summary["sample_count"],
            "scope": "REAL_CODEX_AND_NODE_LOCAL_DETERMINISTIC_PROTOCOL_FIXTURE; NOT_MODEL_OR_BENCHMARK_SUCCESS"}
        write_new(output / "validation.json", checks)
        files = sorted(str(path.relative_to(output)) for path in output.rglob("*") if path.is_file())
        write_new(output / "validation-manifest.json", {"schema_version": 1, **checks,
            "artifacts": bind_artifacts(output, files)})
        return {"output": str(output), **checks}
    finally:
        if native is not None:
            native.close()
        server.shutdown(); server.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--collector",type=Path,help="opt-in real native tool-only capture; requires private cgroups")
    parser.add_argument("--object",type=Path,help="matching execution_timeline.bpf.o")
    parser.add_argument("--no-kernel",action="store_true",help="explicit application-only validation (the default)")
    parser.add_argument("--private-cgroups",action="store_true",
        help="launch this local fixture in new dedicated observer/runtime/tool memory cgroups")
    parser.add_argument("--resource-cgroup-root",type=Path,help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if (args.collector is None)!=(args.object is None) or (args.no_kernel and args.collector is not None):
        raise ValueError("provide paired collector/object or --no-kernel, not both")
    if args.private_cgroups:
        if args.resource_cgroup_root is not None:raise ValueError("choose one cgroup launch mode")
        from private_resource_fixture import run_private_fixture
        print(json.dumps(run_private_fixture(args),ensure_ascii=False),flush=True)
        return 0
    print(json.dumps(validate(args), ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
