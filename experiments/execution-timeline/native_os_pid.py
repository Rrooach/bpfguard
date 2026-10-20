#!/usr/bin/env python3
"""Native app-server itemId -> osPid assertions cross-checked with Linux.

Only the documented optional ``osPid`` field is a PID. processId remains an
opaque session handle. The list endpoint may omit foreground/short processes;
absence is a coverage gap, never permission to guess a PID from timing.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time

from codex_client import append_record
from common import canonical, write_new
from native_process_samples import process_snapshot


def value_digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class NativeOsPidTracker:
    def __init__(self,directory,cgroup,*,interval_ms=100,max_queries=64):
        self.directory=Path(directory);self.cgroup=Path(cgroup).resolve(strict=True)
        self.cgroup_id=self.cgroup.stat().st_ino
        self.boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.path=self.directory/"native-os-pid-observations.jsonl"
        write_new(self.path,b"")
        self.interval_ms,self.max_queries=interval_ms,max_queries
        self.queries=0;self.last_ns=0;self.rows=[];self.disabled=False;self.errors=[]

    def query(self,rpc,thread_id,*,force=False):
        now=time.monotonic_ns()
        if self.disabled or self.queries>=self.max_queries or (not force and now-self.last_ns<self.interval_ms*1000000):
            return
        self.last_ns=now;self.queries+=1
        request_id=rpc.next_id
        begin=time.monotonic_ns()
        try:
            result=rpc.request("thread/backgroundTerminals/list",{"threadId":thread_id,"limit":128},timeout=3)
            received=time.monotonic_ns()
            if not isinstance(result,dict) or not isinstance(result.get("data"),list) or len(result["data"])>128:
                raise ValueError("malformed bounded background terminal list")
            row={"event":"NATIVE_OS_PID_QUERY","boot_id":self.boot_id,"clock":"CLOCK_MONOTONIC",
                "cgroup_id":self.cgroup_id,"thread_id":thread_id,"rpc_request_id":request_id,
                "query_begin_ns":begin,"response_received_ns":received,"result_sha256":value_digest(result),
                "pagination":"TRUNCATED_NEXT_CURSOR" if result.get("nextCursor") else "COMPLETE_RESPONSE_PAGE",
                "observations":[]}
            for terminal in result["data"]:
                if not isinstance(terminal,dict):continue
                item={key:terminal.get(key) for key in ("itemId","processId","osPid","command","cwd")}
                item["status"]="OS_PID_NOT_EXPOSED"
                pid=item["osPid"]
                if type(pid) is int and pid>0:
                    try:
                        snapshot_begin=time.monotonic_ns()
                        # Register only a PID actually present in the owned
                        # runtime scope, including future native child groups.
                        members=set()
                        for entry in self.cgroup.rglob("cgroup.procs"):
                            members.update(int(value) for value in entry.read_text().split())
                        if pid not in members:raise ValueError("reported OS PID is outside the registered runtime cgroup")
                        item["process_snapshot"]=process_snapshot(pid)
                        item["snapshot_begin_ns"]=snapshot_begin
                        item["snapshot_end_ns"]=time.monotonic_ns()
                        item["status"]="APP_OS_PID_AND_LIVE_PROC_IDENTITY_OBSERVED"
                    except (OSError,ValueError,IndexError) as error:
                        item["status"]="OS_PID_LIFETIME_NOT_CAPTURED"
                        item["error_class"]=type(error).__name__
                row["observations"].append(item)
            self.rows.append(row);append_record(self.path,row)
        except (ValueError,RuntimeError,TimeoutError,EOFError) as error:
            # A protocol request timeout is not safe to continue: its late
            # response would otherwise become an unsolicited RPC reply.
            self.errors.append(type(error).__name__)
            self.disabled=True
            append_record(self.path,{"event":"NATIVE_OS_PID_QUERY_UNAVAILABLE","query_begin_ns":begin,
                "clock":"CLOCK_MONOTONIC","boot_id":self.boot_id,"rpc_request_id":request_id,
                "error_class":type(error).__name__,"status":"NOT_SUPPORTED_OR_UNAVAILABLE; NO_PID_GUESSED"})
            if isinstance(error,(TimeoutError,EOFError)):raise

    def finish(self):
        write_new(self.directory/"native-os-pid-collection.json",{
            "status":"BOUNDED_NATIVE_OS_PID_QUERY_SCOPE_NOT_ALL_COMMANDS",
            "queries":self.queries,"max_queries":self.max_queries,"query_limit_reached":self.queries>=self.max_queries,
            "interval_ms":self.interval_ms,"disabled":self.disabled,"errors":self.errors,
            "limitations":"BACKGROUND_TERMINAL_API_MAY_OMIT_FOREGROUND_OR_SHORT_COMMANDS; NULL_OSPID_STAYS_UNBOUND"})


def verify_native_pid_links(application,report,observations,rpc_rows):
    """Replay explicit itemId/osPid observations against raw RPC and kernel IDs."""
    boot=report.get("run",{}).get("boot_id")
    incoming={};outgoing={}
    for row in rpc_rows:
        message=row.get("message",{})
        if "id" not in message:continue
        target=incoming if row.get("direction")=="CODEX_TO_CLIENT" and "method" not in message else (
            outgoing if row.get("direction")=="CLIENT_TO_CODEX" else None)
        if target is not None:
            key=(type(message["id"]).__name__,message["id"])
            if key in target:raise ValueError("ambiguous native OS PID source RPC identity")
            target[key]=message
    threads={row["key"]:row for row in report.get("threads",[]) if row.get("key")}
    roots={tool.get("root_key") for tool in report.get("tools",[])
        if tool.get("tool_call_id")=="codex-native-runtime" and tool.get("association")=="RUNTIME_GATE_AND_KERNEL_LIFETIME"}
    def descendant(key):
        seen=set()
        while key in threads and key not in seen:
            if key in roots:return True
            seen.add(key);key=threads[key].get("parent_key")
        return False
    calls={call["call_id"]:call for call in application.get("tool_calls",[])}
    matches={};rejected=[]
    for row in observations:
        if row.get("event")!="NATIVE_OS_PID_QUERY":continue
        key=(type(row.get("rpc_request_id")).__name__,row.get("rpc_request_id"))
        request,response=outgoing.get(key,{}),incoming.get(key,{})
        if (request.get("method")!="thread/backgroundTerminals/list" or
                request.get("params",{}).get("threadId")!=row.get("thread_id") or
                "result" not in response or value_digest(response["result"])!=row.get("result_sha256")):
            raise ValueError("native OS PID query differs from raw RPC request/response")
        raw_items=response["result"].get("data",[])
        for observation in row.get("observations",[]):
            if observation.get("status")!="APP_OS_PID_AND_LIVE_PROC_IDENTITY_OBSERVED":continue
            call_id=observation.get("itemId");call=calls.get(call_id)
            selected=[item for item in raw_items if isinstance(item,dict) and item.get("itemId")==call_id]
            if len(selected)!=1 or any(selected[0].get(name)!=observation.get(name)
                    for name in ("osPid","processId","command","cwd")):
                raise ValueError("native OS PID observation differs from original terminal item")
            if (not call or call.get("thread_id")!=row.get("thread_id") or row.get("boot_id")!=boot):
                rejected.append({"call_id":call_id,"reason":"CALL_THREAD_OR_BOOT_NOT_MATCHED"});continue
            snapshot=observation.get("process_snapshot",{});pid=observation.get("osPid")
            if type(pid) is not int or pid<=0 or snapshot.get("pid")!=pid:
                raise ValueError("native OS PID source and live /proc PID disagree")
            for thread_key,thread in threads.items():
                birth=thread.get("birth_ns",thread.get("thread_birth_ns"));hz=snapshot.get("clock_ticks")
                query_begin=row.get("query_begin_ns");snapshot_end=observation.get("snapshot_end_ns")
                terminal_end=thread.get("exit_ns") or thread.get("end_ns")
                if (thread.get("tid")!=pid or thread.get("tgid")!=pid or type(birth) is not int
                        or type(hz) is not int or hz<=0 or birth*hz//1000000000!=snapshot.get("start_ticks")
                        or not descendant(thread_key) or not all(type(value) is int for value in (query_begin,snapshot_end,terminal_end))
                        or not birth<=query_begin<=row["response_received_ns"]<=observation["snapshot_begin_ns"]<=snapshot_end<=terminal_end):continue
                matches.setdefault(call_id,{})[thread_key]={"pid":pid,"thread_key":thread_key,
                    "start_ticks":snapshot["start_ticks"],"clock_ticks":hz,"boot_id":boot,
                    "application_process_handle":observation.get("processId"),"source_rpc_request_id":row["rpc_request_id"],
                    "source_result_sha256":row["result_sha256"],"kernel_ancestry":"CAPTURED_RUNTIME_DESCENDANT",
                    "meaning":"EXPLICIT_NATIVE_ITEM_ID_OS_PID_ASSERTION_CROSSCHECKED_WITH_PROC_AND_KERNEL_LIFETIME"}
    links=[]
    for call_id,call in calls.items():
        found=list(matches.get(call_id,{}).values())
        links.append({"call_id":call_id,"status":"APP_REPORTED_OS_PID_KERNEL_LIFETIME_VERIFIED" if len(found)==1 else
            "AMBIGUOUS" if found else "UNBOUND", "processes":found,
            "limitation":"APPLICATION_ITEM_TO_OS_PROCESS_ASSERTION_NOT_HIDDEN_INTENT_OR_ALL_SYSCALL_CAUSAL_PROOF"})
    return {"schema_version":1,"model":"NATIVE_ITEM_OS_PID_AND_KERNEL_LIFETIME_V1","links":links,
        "rejected":rejected,"scope":"EXPLICIT_OSPID_FROM_OFFICIAL_BACKGROUND_TERMINAL_API; NEVER_OPAQUE_PROCESSID_AS_PID"}
