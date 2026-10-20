#!/usr/bin/env python3
"""Replay native model tool calls, including real Code Mode exec, from raw RPC.

These are application-receipt wall boundaries, NOT V8 CPU/JS execution slices.
Nested command items stay separate unless the native protocol provides a
parent identifier; ordering/overlap is not silently promoted to a parent edge.
"""
from __future__ import annotations

import json

from codex_tool_adapter import message_sha256


def bounded_value(value,limit=65536):
    raw=(value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,sort_keys=True)).encode()
    return {"text":raw[:limit].decode(errors="replace"),"size_bytes":len(raw),"truncated":len(raw)>limit}


class NativeRawTools:
    def __init__(self,thread_id,turn_id,emit=None):
        self.thread_id,self.turn_id,self.emit=thread_id,turn_id,emit
        self.calls={};self.responses=[];self.pending=[];self.response_ids=set()

    def accept(self,message,receipt_ns):
        method,params=message.get("method"),message.get("params",{})
        if method not in ("rawResponseItem/completed","rawResponse/completed"):return False
        if not isinstance(params,dict) or params.get("threadId")!=self.thread_id or params.get("turnId")!=self.turn_id:
            raise ValueError("raw native response thread/turn identity differs")
        source={"source_message_sha256":message_sha256(message),"method":method,"receipt_ns":receipt_ns,
            "thread_id":self.thread_id,"turn_id":self.turn_id}
        if method=="rawResponse/completed":
            response_id=params.get("responseId")
            if not isinstance(response_id,str) or not response_id or response_id in self.response_ids:
                raise ValueError("raw native model response has missing/duplicate identity")
            self.response_ids.add(response_id)
            usage=params.get("usage")
            if usage is not None and (not isinstance(usage,dict) or any(type(value) is not int or value<0 for value in usage.values())):
                raise ValueError("raw native model usage is malformed")
            call_ids=list(self.pending);self.pending.clear()
            for call_id in call_ids:self.calls[call_id]["response_id"]=response_id
            row={"event":"NATIVE_MODEL_RESPONSE_COMPLETED","response_id":response_id,"usage":usage,
                "output_tool_call_ids":call_ids,"association":"ORDERED_NATIVE_RESPONSE_TERMINATOR_NOT_TIMESTAMP_GUESS",
                **source}
            self.responses.append(row)
            if self.emit:self.emit(row)
            return True
        item=params.get("item",{});kind=item.get("type") if isinstance(item,dict) else None
        if kind not in ("custom_tool_call","function_call","custom_tool_call_output","function_call_output"):return True
        call_id=item.get("call_id")
        if not isinstance(call_id,str) or not call_id or len(call_id)>256:
            raise ValueError("raw native tool item lacks a bounded call ID")
        if kind in ("custom_tool_call","function_call"):
            if call_id in self.calls:raise ValueError("duplicate raw native tool request")
            name=item.get("name")
            if not isinstance(name,str) or not name:raise ValueError("raw native tool request has no name")
            request=bounded_value(item.get("input") if kind=="custom_tool_call" else item.get("arguments"))
            call={"call_id":call_id,"tool_name":name,"api_type":kind,"namespace":item.get("namespace"),
                "thread_id":self.thread_id,"turn_id":self.turn_id,"request":request,"output":None,
                "request_received_ns":receipt_ns,"output_received_ns":None,"request_to_output_ms":None,
                "source_request":source,"source_output":None,"response_id":None,"status":"OUTPUT_NOT_OBSERVED",
                "runtime":"NATIVE_CODE_MODE" if kind=="custom_tool_call" and name=="exec" else "NATIVE_MODEL_TOOL",
                "timing_scope":"CLIENT_RECEIPT_OF_MODEL_TOOL_REQUEST_THROUGH_MATCHED_TOOL_OUTPUT; NOT_JS_CPU",
                "v8_js_ms":None,"v8_cpu_ms":None,"child_call_ids":[],
                "child_relation":"NOT_EXPOSED_BY_NATIVE_PROTOCOL; CHILDREN_NOT_ASSIGNED_BY_TIME"}
            self.calls[call_id]=call;self.pending.append(call_id)
            if self.emit:self.emit({"event":"NATIVE_MODEL_TOOL_REQUEST",**call})
        else:
            call=self.calls.get(call_id)
            if not call or call["source_output"] is not None:
                raise ValueError("raw native tool output lacks one matching request")
            if receipt_ns<call["request_received_ns"]:raise ValueError("raw native tool output precedes request")
            call.update(output=bounded_value(item.get("output")),output_received_ns=receipt_ns,
                request_to_output_ms=(receipt_ns-call["request_received_ns"])/1000000,
                source_output=source,status="MATCHED_TOOL_OUTPUT_OBSERVED")
            if self.emit:self.emit({"event":"NATIVE_MODEL_TOOL_OUTPUT",**call})
        return True

    def projection(self):
        return {"native_model_tool_calls":list(self.calls.values()),"native_model_responses":self.responses,
            "native_code_mode":"RAW_NATIVE_EXEC_CALL_AND_OUTPUT_BOUNDARIES_COLLECTED; JS_CPU_NOT_EXPOSED" if
                any(call["runtime"]=="NATIVE_CODE_MODE" for call in self.calls.values()) else
                "ENABLED_IN_CONFIG; NO_NATIVE_EXEC_CALL_OBSERVED; INTERNAL_JS_CPU_NOT_EXPOSED"}


def replay_native_raw_tools(rows,*,thread_id,turn_id):
    replay=NativeRawTools(thread_id,turn_id)
    for row in rows:
        if row.get("direction")=="CODEX_TO_CLIENT":
            replay.accept(row.get("message",{}),row["receipt_ns"])
    return replay.projection()
