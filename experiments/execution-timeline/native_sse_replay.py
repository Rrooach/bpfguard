#!/usr/bin/env python3
"""Loopback-only deterministic replay of saved native provider SSE bytes.

No upstream HTTP client exists here. Responses are byte-identical recorded
deliveries, with no original inference delay. This replays decisions, NOT new
inference. Each request must declare the recorded model and exact tool schema.
Actual tool outputs and final workspace are checked separately by the paired
experiment, not assumed equal because a provider trace was replayed.
"""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import threading
import time

from common import canonical,digest,write_new


def _sha(value):return hashlib.sha256(canonical(value)).hexdigest()


def load_trace(directory,label):
    directory=Path(directory).resolve(strict=True)
    entries=[]
    for path in directory.glob(label+"-step-*-delivered.sse"):
        match=re.fullmatch(re.escape(label)+r"-step-(\d+)-delivered\.sse",path.name)
        if not match:continue
        number=int(match.group(1));prefix=path.name[:-len("-delivered.sse")]
        request=directory/(prefix+"-native-request.json")
        if not request.is_file():raise ValueError("native provider request body is required for exact tool-schema validation")
        payload=json.loads(request.read_text());body=path.read_bytes()
        if not 1<=len(body)<=4*1024**2:raise ValueError("recorded SSE body outside bounded size")
        completed=[]
        for raw in body.replace(b"\r\n",b"\n").split(b"\n\n"):
            data=b"\n".join(line[5:].lstrip() for line in raw.splitlines() if line.startswith(b"data:"))
            if not data or data==b"[DONE]":continue
            item=json.loads(data)
            if item.get("type")=="response.completed":completed.append(item)
        if len(completed)!=1:raise ValueError("exactly one completed response required per replay SSE delivery")
        entries.append({"number":number,"path":path,"request_path":request,"body":body,
            "model":payload.get("model"),"tools_sha256":_sha(payload.get("tools")),
            "response_id":completed[0].get("response",{}).get("id"),
            "body_identity":digest(path),"request_identity":digest(request)})
    entries.sort(key=lambda entry:entry["number"])
    if not entries or len(entries)>64:raise ValueError("between one and 64 saved native SSE responses required")
    return entries


class _Handler(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def log_message(self,*args):pass
    def _reply(self,status,body,kind="application/json"):
        self.send_response(status);self.send_header("Content-Type",kind)
        self.send_header("Content-Length",str(len(body)));self.send_header("Connection","close");self.end_headers()
        self.wfile.write(body);self.wfile.flush();self.close_connection=True
    def do_POST(self):
        owner=self.server.owner
        if self.path!="/v1/responses":return self._reply(404,b'{"error":"REPLAY_RESPONSES_ONLY"}')
        if not secrets.compare_digest(self.headers.get("Authorization",""),"Bearer "+owner.token):
            return self._reply(401,b'{"error":"LOCAL_REPLAY_CREDENTIAL_REQUIRED"}')
        if self.headers.get("X-Benchmark-Task")!=owner.replay_label:
            return self._reply(400,b'{"error":"EXACT_REPLAY_LABEL_REQUIRED"}')
        try:
            if len(self.headers.get_all("Content-Length",[]))!=1 or self.headers.get("Transfer-Encoding"):
                raise ValueError("unambiguous content length required")
            length=int(self.headers["Content-Length"])
            if not 1<=length<=192*1024:raise ValueError("replay request bound exceeded")
            raw=self.rfile.read(length)
            if len(raw)!=length:raise ValueError("replay request incomplete")
            payload=json.loads(raw)
            with owner.lock:
                if owner.cursor>=len(owner.entries):
                    owner.errors.append("REQUEST_EXCEEDS_RECORDED_TRACE")
                    return self._reply(409,b'{"error":"RECORDED_TRACE_EXHAUSTED_NO_NETWORK_FALLBACK"}')
                entry=owner.entries[owner.cursor]
                if payload.get("model")!=entry["model"] or _sha(payload.get("tools"))!=entry["tools_sha256"]:
                    owner.errors.append("MODEL_OR_TOOL_SCHEMA_MISMATCH")
                    return self._reply(409,b'{"error":"REPLAY_MODEL_OR_TOOL_SCHEMA_MISMATCH"}')
                owner.cursor+=1
                owner.receipts.append({"index":owner.cursor-1,"recorded_number":entry["number"],
                    "received_ns":time.monotonic_ns(),"request_sha256":hashlib.sha256(raw).hexdigest(),
                    "delivered_sse":entry["body_identity"],"source_response_id":entry["response_id"],
                    "mode":"REPLAYED_PROVIDER_RESPONSES_NOT_NEW_INFERENCE",
                    "request_contract":"EXACT_MODEL_AND_TOOL_SCHEMA; INPUT_CONTENT_VALIDATED_BY_WORKLOAD_OUTPUT_AND_FINAL_STATE_CHECKS"})
            self._reply(200,entry["body"],"text/event-stream")
        except (ValueError,TypeError,KeyError):
            with owner.lock:owner.errors.append("MALFORMED_REPLAY_REQUEST")
            self._reply(400,b'{"error":"BOUNDED_REPLAY_REQUEST_REQUIRED"}')


class NativeSSEReplayServer:
    def __init__(self,entries,token,replay_label="native-trace-replay"):
        self.entries,self.token,self.replay_label=entries,token,replay_label
        self.cursor=0;self.receipts=[];self.errors=[];self.lock=threading.Lock()
        self.server=ThreadingHTTPServer(("127.0.0.1",0),_Handler);self.server.daemon_threads=True;self.server.owner=self
        self.base_url="http://127.0.0.1:%d/v1"%self.server.server_address[1]
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
    def start(self):self.thread.start();return self
    def reset(self):
        with self.lock:self.cursor=0;self.receipts=[];self.errors=[]
    def receipt(self):
        with self.lock:
            return {"mode":"REPLAYED_PROVIDER_RESPONSES_NOT_NEW_INFERENCE","paid_api_calls":0,
                "trace_responses":len(self.entries),"served_responses":self.cursor,"errors":list(self.errors),
                "complete":self.cursor==len(self.entries) and not self.errors,"requests":list(self.receipts),
                "timing":"IMMEDIATE_LOCAL_REPLAY; ORIGINAL_PROVIDER_INFERENCE_AND_NETWORK_DELAY_NOT_REPRODUCED"}
    def stop(self):
        self.server.shutdown();self.thread.join(timeout=5);self.server.server_close()
