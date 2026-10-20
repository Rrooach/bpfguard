"""Pair control-RPC boundaries by literal IDs; never infer V8 execution."""

METHODS={"initialize":("RUNTIME_INITIALIZE","Codex 初始化 RPC"),
    "thread/start":("RUNTIME_THREAD_START","创建 Agent 会话 RPC"),
    "turn/start":("RUNTIME_TURN_START","提交任务 RPC")}


def runtime_rpc_phases(rows,boot_id,begin_ns,end_ns):
    pending={};seen=set();phases=[]
    for index,row in enumerate(rows or []):
        message=row.get("message",{})
        if not isinstance(message,dict) or "id" not in message:continue
        request_id=message["id"]
        if type(request_id) not in (int,str):continue
        key=type(request_id).__name__,request_id
        outgoing=row.get("direction")=="CLIENT_TO_CODEX" and message.get("method") in METHODS
        incoming=row.get("direction")=="CODEX_TO_CLIENT" and "method" not in message and key in pending
        if not outgoing and not incoming:continue
        if row.get("clock")!="CLOCK_MONOTONIC" or row.get("boot_id")!=boot_id:
            raise ValueError("runtime RPC boot/clock differs")
        timestamp=row.get("receipt_ns")
        if type(timestamp) is not int or not begin_ns<=timestamp<=end_ns:
            raise ValueError("runtime RPC lies outside Agent interval")
        if outgoing:
            if key in seen:raise ValueError("duplicate control RPC request ID")
            seen.add(key);pending[key]=(index,timestamp,message["method"])
        else:
            start_index,start,method=pending.pop(key)
            if timestamp<start:raise ValueError("control RPC boundaries reversed")
            kind,label=METHODS[method]
            phases.append({"kind":kind,"label":label,"identity":"rpc:"+str(request_id),
                "begin_ns":start,"end_ns":timestamp,"method":method,
                "status":"ERROR_RETURNED" if "error" in message else "RETURNED",
                "evidence_refs":["rpc#/"+str(start_index),"rpc#/"+str(index)],
                "timing_scope":"CLIENT_SEND_TO_RESPONSE_RECEIPT; NOT_CPU_TIME_OR_V8_EXECUTION"})
    return phases
