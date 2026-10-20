#!/usr/bin/env python3
"""Whole native Codex/V8/tool trace replay, paired OFF/FULL, zero inference.

Unlike shell-text replay this launches the same official Codex and its native
Code Mode/tools, serving byte-identical saved provider Responses SSE. All
model decisions are recorded, not new inference; original model/network
delay is not replayed. Keep the actual workspace at its original absolute
path and retain every replaced workspace rather than deleting evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

from codex_native_run import collect_native
from common import canonical,digest,write_new
from native_profile_overhead import paired_statistics,restore_new_workspace,tree_digest
from native_raw_tools import replay_native_raw_tools
from native_sse_replay import NativeSSEReplayServer,load_trace


def _digest(value):return hashlib.sha256(canonical(value)).hexdigest()


COMPARISON_POLICY="NATIVE_REPLAY_CORRECTNESS_METADATA_V4"


def native_worker_command(args,script=None):
    script=Path(script) if script is not None else Path(__file__).with_name("codex_native_run.py")
    command=[sys.executable,"-B",str(script)]
    required=("collector","object","codex","catalog","workspace","prompt","output","broker_token_file","broker_base_url",
        "budget_label","model","agent_id","task_id","run_id","cgroup_parent","timeout","ring_bytes","max_records",
        "max_bytes","process_sample_ms","capture_mode","provider_provenance")
    for name in required:
        command.extend(("--"+name.replace("_","-"),str(getattr(args,name))))
    for name in ("exec_args_collector","exec_args_object"):
        if getattr(args,name,None) is not None:command.extend(("--"+name.replace("_","-"),str(getattr(args,name))))
    return command


def fresh_native_worker(args,logs,label,*,script=None,max_output_bytes=65536):
    """Exec a fresh normal CLI so prior decoder heaps cannot be inherited.

    Child stdout/stderr go to files, not unbounded in-memory communicate
    buffers. JSON is decoded only after checking the small CLI result limit;
    complete stdout/stderr and the exact argv/return code remain evidence.
    """
    logs=Path(logs);logs.mkdir(mode=0o700,exist_ok=True)
    command=native_worker_command(args,script)
    stdout=logs/(label+".stdout");stderr=logs/(label+".stderr")
    timed_out=False
    with stdout.open("xb") as out,stderr.open("xb") as err:
        process=subprocess.Popen(command,stdout=out,stderr=err)
        try:code=process.wait(timeout=args.timeout+180)
        except subprocess.TimeoutExpired:
            timed_out=True;process.send_signal(signal.SIGINT)
            try:code=process.wait(timeout=45)
            except subprocess.TimeoutExpired:process.kill();code=process.wait(timeout=10)
        out.flush();err.flush();os.fsync(out.fileno());os.fsync(err.fileno())
    receipt={"mode":"FRESH_PYTHON_EXEC_NORMAL_NATIVE_CLI_PER_ARM","pid":process.pid,"argv":command,
        "return_code":code,"timed_out":timed_out,"stdout":digest(stdout),"stderr":digest(stderr),"stdout_artifact":str(stdout),
        "stderr_artifact":str(stderr),"json_result_limit_bytes":max_output_bytes}
    write_new(logs/(label+"-worker.json"),receipt)
    if code!=0 or timed_out:raise RuntimeError("fresh native worker failed; raw CLI stdout/stderr retained")
    if stdout.stat().st_size>max_output_bytes or stderr.stat().st_size>max_output_bytes:
        raise ValueError("native worker CLI output exceeded bounded decode size; originals retained")
    outcome=json.loads(stdout.read_text())
    if not isinstance(outcome,dict) or not isinstance(outcome.get("verification"),str):
        raise ValueError("native worker returned an invalid bounded CLI result")
    return outcome,receipt


def evidence_sink_preflight(directory,archive_root,*,minimum_tmpfs_bytes=1536*1024**2,minimum_archive_bytes=500*1024**2):
    """Fail before a new arm, not during capture, if bounded scratch is unsafe."""
    directory=Path(directory).resolve(strict=True);archive_root=Path(archive_root).resolve(strict=True)
    if directory.parent!=Path("/dev/shm") or not directory.name.startswith("observer-native-replay-"):
        raise ValueError("explicit owned /dev/shm/observer-native-replay-* evidence directory required")
    tmpfs=shutil.disk_usage(directory);archive=shutil.disk_usage(archive_root)
    if tmpfs.free<minimum_tmpfs_bytes or archive.free<minimum_archive_bytes:
        raise RuntimeError("insufficient evidence sink capacity before arm")
    available=None
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):available=int(line.split()[1])*1024;break
    if available is None or available<minimum_tmpfs_bytes+512*1024**2:
        raise RuntimeError("insufficient available memory for bounded tmpfs evidence before arm")
    return {"tmpfs_free_bytes":tmpfs.free,"archive_free_bytes":archive.free,"memory_available_bytes":available,
        "minimum_tmpfs_bytes":minimum_tmpfs_bytes,"minimum_archive_bytes":minimum_archive_bytes}


def archive_verified_arm(run,scratch,archives):
    """Archive exact owned evidence, compare every member, then reclaim tmpfs.

    No raw evidence is discarded until tar's content/metadata comparison and
    the compressed archive fsync have succeeded. Failures leave the raw arm.
    """
    run=Path(run).resolve(strict=True);scratch=Path(scratch).resolve(strict=True)
    archives=Path(archives).resolve(strict=True)
    if run.parent!=scratch or not re.fullmatch(r"pair-\d{2}-(?:off|full)",run.name):
        raise ValueError("only one exact owned replay arm may be archived")
    archive=archives/(run.name+".tar.gz")
    if archive.exists():raise ValueError("replay arm archive already exists")
    begin=time.monotonic_ns()
    subprocess.run(["tar","--numeric-owner","--xattrs","--acls","-czf",str(archive),"-C",str(scratch),run.name],check=True,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    with archive.open("rb") as stream:os.fsync(stream.fileno())
    subprocess.run(["tar","--numeric-owner","--xattrs","--acls","--compare","--gzip","--file",str(archive),
        "--directory",str(scratch)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    identity=digest(archive);size=archive.stat().st_size
    shutil.rmtree(run)
    return {"archive":str(archive),"identity":identity,"compressed_bytes":size,"content_comparison":"TAR_COMPARE_PASSED",
        "raw_path_at_capture":str(run),"raw_tmpfs_copy_reclaimed":True,"archive_wall_ms":(time.monotonic_ns()-begin)/1000000}


def normalize_native_output(value,command,cwd=None):
    if not isinstance(value,dict) or value.get("truncated") or not isinstance(value.get("text"),str):return value
    text=value["text"];normalized=text
    if isinstance(command,str) and "-m unittest" in command:
        # Only the standard unittest footer, retaining count and OK/FAILED.
        normalized=re.sub(r"(?m)(^-{20,}\nRan \d+ tests? in )[0-9.]+s(\n\n(?:OK|FAILED)[^\n]*(?:\n|$))",
            r"\1<TEST_RUNNER_TIMING>s\2",normalized)
    if isinstance(command,str) and "ls -la" in command and isinstance(cwd,str):
        # Recognize only `ls -la` on the declared cwd. Explicit other paths or
        # shell constructs do not get generalized to an unknown directory.
        text_command=command
        try:
            words=shlex.split(command)
            if len(words)==3 and words[0] in ("/bin/bash","/bin/sh","bash","sh") and words[1] in ("-c","-lc"):
                text_command=words[2]
        except ValueError:pass
        if re.search(r"(?:^|[;&])\s*ls\s+-la\s*(?:\||;|&&|$)",text_command):
            def directory_time(match):
                # The exact name, links, size, mode and owner remain part of
                # comparison. Bind the ls-reported directory to its cwd path.
                name=match.group(3)
                path=os.path.normpath(os.path.join(cwd,name))
                return match.group(1)+"<DIRECTORY_MTIME:"+path+">"+match.group(2)+name
            normalized=re.sub(r"(?m)^(d[rwxstST-]{9}[.+]?\s+\d+\s+\S+\s+\S+\s+\d+\s+)"
                r"[A-Za-z]{3}\s+\d{1,2}\s+(?:\d{2}:\d{2}|\d{4})(\s+)([A-Za-z0-9_.-]+)$",directory_time,normalized)
    return {"text":normalized,"truncated":False,"comparison_policy":COMPARISON_POLICY} if normalized!=text else value


def normalize_outer_output(value,known_inner_outputs=None):
    """Normalize only a complete known V8 transport-metadata-only block.

    Arbitrary output lines are never stripped. The original text stays in raw
    RPC; this versioned comparison excludes only the wrapper's measured time.
    """
    if not isinstance(value,dict) or value.get("truncated"):return value
    try:blocks=json.loads(value["text"])
    except (ValueError,TypeError,KeyError):return value
    if not isinstance(blocks,list) or not blocks or not isinstance(blocks[0],dict):return value
    first=blocks[0];changed=False
    if (first.get("type")=="input_text" and isinstance(first.get("text"),str)
            and re.fullmatch(r"Script completed\nWall time [0-9.]+ seconds\nOutput:\n\s*",first["text"])):
        blocks=[{**first,"text":"<CODEX_SCRIPT_COMPLETED_TRANSPORT_TIMING>"}]+blocks[1:];changed=True
    for index,block in enumerate(blocks):
        if isinstance(block,dict) and isinstance(block.get("text"),str) and block["text"] in (known_inner_outputs or {}):
            normalized=known_inner_outputs[block["text"]]
            if isinstance(normalized,dict) and normalized.get("text")!=block["text"]:
                blocks[index]={**block,"text":normalized["text"]};changed=True
    return blocks if changed else value


def workload_identity(application):
    """Exact local tool semantics, with only documented transport-time removal."""
    calls=[]
    for call in application.get("tool_calls",[]):
        if call.get("tool_name") in ("mcpToolCall","webSearch","imageGeneration") or call.get("tool_name","").startswith("collabAgentToolCall"):
            raise ValueError("remote/delegated tool workload is outside reproducible local replay scope")
        calls.append({"tool_name":call.get("tool_name"),"arguments":call.get("arguments"),"status":call.get("status"),
            "exit_code":call.get("exit_code")})
    call_by_id={row["call_id"]:row for row in application.get("tool_calls",[]) if row.get("call_id")}
    outputs=[];known_outputs={}
    for row in application.get("native_tool_results",[]):
        original=row.get("output")
        arguments=call_by_id.get(row.get("call_id"),{}).get("arguments",{})
        command=arguments.get("command")
        normalized=normalize_native_output(original,command,arguments.get("cwd"))
        outputs.append({"tool_name":row.get("tool_name"),"exit_code":row.get("exit_code"),
            "producer_status":row.get("producer_status"),"output":normalized})
        if isinstance(original,dict) and isinstance(original.get("text"),str):known_outputs[original["text"]]=normalized
    if any((row.get("output") or {}).get("truncated") for row in outputs):
        raise ValueError("native output truncation prevents strict replay correctness comparison")
    outer=[{"call_id":row["call_id"],"tool_name":row["tool_name"],"api_type":row["api_type"],
        "request":row["request"],"status":row["status"],"output":normalize_outer_output(row.get("output"),known_outputs)}
        for row in application.get("native_model_tool_calls",[])]
    return json.loads(json.dumps({"native_tools":calls,"native_outputs":outputs,"native_model_tool_calls":outer,
        "comparison_policy":COMPARISON_POLICY+"; KNOWN_WRAPPER_UNITTEST_FOOTER_AND_LS_CWD_BOUND_DIRECTORY_MTIME_ONLY; RAW_OUTPUTS_RETAINED"}))


def business_identity(workload):
    """Compare model-delivered results; retain partial inner aggregates aside."""
    if not workload["native_model_tool_calls"]:
        raise ValueError("complete matched native model-delivered tool results are required")
    for call in workload["native_model_tool_calls"]:
        if (call["status"]!="MATCHED_TOOL_OUTPUT_OBSERVED" or not isinstance(call.get("output"),(dict,list))
                or (isinstance(call["output"],dict) and call["output"].get("truncated")) or call["request"].get("truncated")):
            raise ValueError("native model-delivered request/output capture is missing or truncated")
    return {key:value for key,value in workload.items() if key!="native_outputs"}


def restore_fixed_workspace(baseline,workspace,campaign_root,archive_name,owned_parent):
    baseline=Path(baseline).resolve(strict=True);workspace=Path(workspace).absolute()
    campaign_root=Path(campaign_root).resolve(strict=True);owned_parent=Path(owned_parent).resolve(strict=True)
    if (owned_parent in (Path("/"),Path("/opt"),Path("/tmp"),Path("/root")) or workspace.parent!=owned_parent
            or workspace==baseline or workspace in baseline.parents or baseline in workspace.parents
            or workspace==campaign_root or workspace in campaign_root.parents or campaign_root in workspace.parents):
        raise ValueError("explicit non-broad owned workspace parent and disjoint replay evidence/baseline required")
    retained=campaign_root/"retained-workspaces";retained.mkdir(exist_ok=True)
    archive=retained/archive_name
    if workspace.exists():
        if archive.exists():raise ValueError("workspace archive already exists")
        workspace.rename(archive)
    # Reuse the tested owner/xattr/hardlink-preserving clone, then move the
    # newly created clone to the original absolute execution location.
    stage=campaign_root/"workspace"
    if stage.exists():raise ValueError("unexpected leftover replay staging workspace")
    restore_new_workspace(baseline,stage,retained/("unused-"+archive_name))
    stage.rename(workspace)


def _complete_application(path):
    application=json.loads(path.read_text())
    if application.get("mode")!="OFFICIAL_CODEX_NATIVE_TOOLS_NO_REPLACEMENT" or application.get("status")!="completed":
        raise ValueError("a completed real native source trace is required; truncated/failed turns are not a whole-Agent baseline")
    if application.get("unmapped_items"):raise ValueError("unmapped source operations prevent complete local replay comparison")
    return application


def campaign(args):
    if os.geteuid()!=0:raise RuntimeError("native trace replay must run in the owned privileged experiment VM")
    if not 5<=args.pairs<=30:raise ValueError("at least five and at most thirty paired repetitions required")
    source=args.source_run.resolve(strict=True)
    application=_complete_application(source/"app/steps.json")
    source_manifest=json.loads((source/"manifest.json").read_text())
    if digest(args.codex)!=source_manifest.get("codex_identity"):
        raise ValueError("the exact recorded native Codex binary is required")
    entries=load_trace(args.trace_directory,args.source_label)
    # Verify source model-call projections using its own unmodified raw RPC.
    raw=[json.loads(line) for line in (source/"app/rpc.jsonl").read_text().splitlines() if line.strip()]
    projection=replay_native_raw_tools(raw,thread_id=application["thread_id"],turn_id=application["turn_id"])
    application={**application,**projection}
    if len(projection["native_model_responses"])!=len(entries):
        raise ValueError("saved provider trace and original native model completions differ")
    workload_identity(application)  # rejects unsupported remote/delegated work
    baseline=args.baseline.resolve(strict=True);initial=tree_digest(baseline)
    root=args.output.resolve();root.mkdir(mode=0o700,parents=True,exist_ok=False)
    scratch=getattr(args,"evidence_tmpfs_root",None)
    archives=None
    if scratch is not None:
        scratch=Path(scratch).absolute()
        if scratch.parent!=Path("/dev/shm") or not scratch.name.startswith("observer-native-replay-"):
            raise ValueError("explicit owned /dev/shm/observer-native-replay-* evidence directory required")
        scratch.mkdir(mode=0o700,exist_ok=False)
        archives=root/"archives";archives.mkdir(mode=0o700)
        evidence_sink_preflight(scratch,archives)
    schedule=[];generator=random.Random(args.seed)
    for pair in range(args.pairs):
        arms=["off","full"];generator.shuffle(arms)
        schedule.extend({"pair":pair,"arm":arm} for arm in arms)
    write_new(root/"replay-config.json",{"mode":"TRACE_REPLAY_NATIVE_AGENT_NOT_NEW_INFERENCE","source_manifest":digest(source/"manifest.json"),
        "source_application":digest(source/"app/steps.json"),"codex":digest(args.codex),"baseline":initial,
        "provider_deliveries":[{"number":entry["number"],"sse":entry["body_identity"],"native_request":entry["request_identity"]} for entry in entries],
        "schedule":schedule,"seed":args.seed,"workspace":str(args.workspace),"owned_workspace_parent":str(args.owned_workspace_parent),
        "capture_off":"NO_BPF_RESOURCE_PROCESS_SAMPLING_OR_ACTIVE_OSPID_QUERIES; SAME_PASSIVE_RPC_NATIVE_TOOLS_MODEL_RELAY_CORRECTNESS_HARNESS",
        "evidence_sink":"TMPFS_PER_ARM_THEN_VERIFIED_COMPRESSED_ARCHIVE" if scratch is not None else "CAMPAIGN_DIRECTORY",
        "evidence_tmpfs_root":str(scratch) if scratch is not None else None,
        "execution_worker":"FRESH_PYTHON_EXEC_NORMAL_NATIVE_CLI_PER_ARM" if getattr(args,"fresh_worker",True) else "LONG_LIVED_IN_PROCESS_DIAGNOSTIC",
        "python_sources":{name:digest(Path(__file__).with_name(name)) for name in
            ("native_agent_replay_overhead.py","codex_native_run.py","codex_native_off.py")},
        "timing":"IMMEDIATE_SSE_REPLAY_EXCLUDES_ORIGINAL_MODEL_AND_REMOTE_NETWORK_DELAY",
        "correctness":"EXACT_NATIVE_COMMANDS_ARGUMENTS_EXIT_AND_MODEL_DELIVERED_RESULTS_AND_LOGICAL_FINAL_TREE_BETWEEN_ALL_ARMS",
        "comparison_policy":COMPARISON_POLICY,"inner_command_aggregates":"RETAINED_SEPARATE_PARTIAL_COVERAGE_EVIDENCE_NOT_FULL_OS_STDOUT_PROOF"})
    measurements=[];reference=None;reference_tree=None;reference_internal=None;valid=True
    with tempfile.TemporaryDirectory(prefix="observer-native-replay-credential-") as private:
        token=secrets.token_urlsafe(32);token_path=Path(private)/"token";write_new(token_path,token.encode())
        server=NativeSSEReplayServer(entries,token).start()
        try:
            for index,scheduled in enumerate(schedule):
                label="pair-%02d-%s"%(scheduled["pair"],scheduled["arm"])
                sink_capacity=evidence_sink_preflight(scratch,archives) if scratch is not None else None
                restore_begin=time.monotonic_ns()
                restore_fixed_workspace(baseline,args.workspace,root,"before-%03d"%index,args.owned_workspace_parent)
                restore_end=time.monotonic_ns();pre_hash_begin=restore_end
                if tree_digest(args.workspace)!=initial:raise ValueError("replay baseline clone logical identity mismatch")
                pre_hash_end=time.monotonic_ns()
                server.reset()
                run_args=SimpleNamespace(collector=args.collector,object=args.object,codex=args.codex,
                    catalog=source/"app/model-catalog.json",workspace=args.workspace,prompt=source/"app/prompt.txt",
                    output=(scratch if scratch is not None else root)/label,broker_token_file=token_path,broker_base_url=server.base_url,budget_label=server.replay_label,
                    model=application["model"],agent_id=application["agent_id"],task_id=application["task_id"],run_id=label,
                    cgroup_parent=args.cgroup_parent,timeout=args.timeout,ring_bytes=args.ring_bytes,
                    max_records=args.max_records,max_bytes=args.max_bytes,process_sample_ms=args.process_sample_ms,
                    capture_mode=scheduled["arm"],provider_provenance="REPLAYED_PROVIDER_RESPONSES_NOT_NEW_INFERENCE")
                run_args.exec_args_collector=getattr(args,"exec_args_collector",None)
                run_args.exec_args_object=getattr(args,"exec_args_object",None)
                pipeline_begin=time.monotonic_ns()
                worker_receipt=None
                if getattr(args,"fresh_worker",True):
                    outcome,worker_receipt=fresh_native_worker(run_args,root/"worker-logs",label)
                else:outcome=collect_native(run_args)
                pipeline_end=time.monotonic_ns()
                replay_app=json.loads((run_args.output/"app/steps.json").read_text())
                current=workload_identity(replay_app)
                business=business_identity(current)
                final_hash_begin=time.monotonic_ns()
                raw_final=tree_digest(args.workspace)
                final=tree_digest(args.workspace,normalize_pyc_timestamp=True)
                final_hash_end=time.monotonic_ns();provider=server.receipt()
                if reference is None:
                    reference,reference_tree=business,final;reference_internal=current["native_outputs"]
                matches=(replay_app.get("status")=="completed" and business==reference and final==reference_tree and provider["complete"]
                    and (scheduled["arm"]=="off" or outcome["verification"]=="REPLAY_PASSED"))
                valid=valid and matches
                window=json.loads((run_args.output/("baseline.json" if scheduled["arm"]=="off" else "manifest.json")).read_text())
                runtime=window["tools"][0]
                resources_path=run_args.output/"resources/resource-summary.json"
                resources=json.loads(resources_path.read_text()) if resources_path.is_file() else None
                row={**scheduled,"run_directory":label,"correctness":"MATCHED" if matches else "MISMATCH",
                    "agent_wall_ms":(replay_app["end_ns"]-replay_app["begin_ns"])/1000000,
                    "runtime_wall_ms":(runtime["end_ns"]-runtime["begin_ns"])/1000000,
                    "capture_pipeline_wall_ms":(pipeline_end-pipeline_begin)/1000000,
                    "worker":worker_receipt,
                    "baseline_restore_wall_ms":(restore_end-restore_begin)/1000000,
                    "pre_run_baseline_hash_wall_ms":(pre_hash_end-pre_hash_begin)/1000000,
                    "final_raw_and_logical_hash_wall_ms":(final_hash_end-final_hash_begin)/1000000,
                    "kernel_verification":outcome["verification"],"provider_replay":provider,"runtime_wait4":runtime.get("rusage"),
                    "workload_identity_sha256":_digest(business),"final_tree":final,"raw_final_tree":raw_final,"resources":resources,
                    "internal_aggregate_output_identity_sha256":_digest(current["native_outputs"]),
                    "internal_aggregate_matches_reference":current["native_outputs"]==reference_internal,
                    "os_stdout_completeness":"NOT_ESTABLISHED; NATIVE_COMMAND_AGGREGATES_MAY_OMIT_NON_STREAMED_CHUNKS; RETAINED_NOT_DISCARDED",
                    "ring_bytes":args.ring_bytes if scheduled["arm"]=="full" else 0,
                    "evidence_bytes":sum(path.stat().st_size for path in run_args.output.rglob("*") if path.is_file()),
                    "native_model_calls":len(replay_app.get("native_model_tool_calls",[])),"native_inner_tools":len(replay_app.get("tool_calls",[]))}
                if scratch is not None:
                    row["evidence_sink_capacity_before_arm"]=sink_capacity
                    row["evidence_archive"]=archive_verified_arm(run_args.output,scratch,archives)
                measurements.append(row)
                write_new(root/(label+"-measurement.json"),row)
        finally:server.stop()
    baseline_unchanged=tree_digest(baseline)==initial;valid=valid and baseline_unchanged
    pairs=[]
    for index in range(args.pairs):
        arms={row["arm"]:row for row in measurements if row["pair"]==index}
        pairs.append({"off_ms":arms["off"]["agent_wall_ms"],"full_ms":arms["full"]["agent_wall_ms"]})
    statistics=None
    if valid:
        agent_stats=paired_statistics(pairs,args.seed)
        agent_stats["scope"]="NATIVE_AGENT_TURN_WINDOW; IMMEDIATE_SSE_REPLAY_NOT_REAL_MODEL_LATENCY"
        pipeline_pairs=[]
        for index in range(args.pairs):
            arms={row["arm"]:row for row in measurements if row["pair"]==index}
            pipeline_pairs.append({"off_ms":arms["off"]["capture_pipeline_wall_ms"],"full_ms":arms["full"]["capture_pipeline_wall_ms"]})
        pipeline_stats=paired_statistics(pipeline_pairs,args.seed)
        pipeline_stats["scope"]="NATIVE_CLI_INCLUDING_FRESH_INTERPRETER_IF_SELECTED_BPF_LOAD_CAPTURE_DRAIN_EXPORT_NATIVE_REPLAY_RENDER; RESTORE_FINAL_HASH_AND_ARCHIVE_EXCLUDED"
        statistics={"agent_window":agent_stats,"capture_pipeline":pipeline_stats}
    report={"status":"PAIRED_NATIVE_AGENT_TRACE_REPLAY_VERIFIED" if valid else "INCOMPARABLE_CORRECTNESS_MISMATCH",
        "scope":"TRACE_REPLAY_MODEL_DELIVERED_RESULTS_AND_FINAL_LOGICAL_FILES_VERIFIED","provider_mode":"TRACE_REPLAY_NATIVE_AGENT_NOT_NEW_INFERENCE",
        "paid_api_calls":0,"all_correctness_checks_passed":valid,
        "baseline_unchanged":baseline_unchanged,"statistics":statistics,"measurements":measurements,
        "retained_previous_workspaces":str(root/"retained-workspaces"),
        "evidence_sink":"TMPFS_PER_ARM_THEN_VERIFIED_COMPRESSED_ARCHIVE" if scratch is not None else "CAMPAIGN_DIRECTORY",
        "execution_worker":"FRESH_PYTHON_EXEC_NORMAL_NATIVE_CLI_PER_ARM" if getattr(args,"fresh_worker",True) else "LONG_LIVED_IN_PROCESS_DIAGNOSTIC",
        "limitations":["Uses the real official Codex/native V8/tools, but every model decision comes from byte-identical recorded SSE",
            "Original model and remote-network delays are excluded; do not call this fresh model inference or production Agent slowdown",
            "OFF retains the same passive RPC/HTTP relay/correctness harness but disables BPF, resource and process sampling, and active OSPID queries; this is not completely unlogged Codex",
            "NATIVE_REPLAY_CORRECTNESS_METADATA_V4 normalizes only known wrapper timing, standard unittest duration footer, explicit ls cwd-bound directory mtime fields, and PEP552 timestamp-pyc source-mtime header; all raw originals retained",
            "Compares the complete native model-delivered result object, including native bounded/truncation notices; does not claim untruncated OS stdout is equal",
            "Internal command aggregatedOutput coverage is independently retained and may differ because native notifications omit non-streamed chunks",
            "PID RSS includes shared mappings; resource samples are not private physical memory or exact full-lifetime CPU",
            "BPF load/detach/export, baseline restore and content hashing are outside the Agent turn wall window",
            "capture_pipeline_wall_ms separately measures BPF load/drain/export/replay/render end to end; baseline restore and hashes have their own measured boundaries",
            "Fresh-worker mode starts the ordinary CLI in a new Python interpreter per arm; the pipeline window includes interpreter startup and excludes the separate archive boundary",
            "When selected, evidence is written to a bounded Guest tmpfs and archived between arms; the sink and its page-cache/memory effects are part of this experiment, not a general disk-backed production SLA",
            "Every failed correctness arm remains recorded and suppresses the entire slowdown claim"]}
    write_new(root/"native-agent-overhead-report.json",report)
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source-run","trace-directory","baseline","workspace","owned-workspace-parent","output","codex","collector","object"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--source-label",required=True)
    parser.add_argument("--exec-args-collector",type=Path)
    parser.add_argument("--exec-args-object",type=Path)
    parser.add_argument("--evidence-tmpfs-root",type=Path,help="owned /dev/shm/observer-native-replay-* scratch; verify and archive each arm before reclaiming")
    workers=parser.add_mutually_exclusive_group()
    workers.add_argument("--fresh-worker",dest="fresh_worker",action="store_true",default=True,
        help="default: exec the normal native CLI in a fresh Python process per arm")
    workers.add_argument("--in-process-worker",dest="fresh_worker",action="store_false",
        help="diagnostic only: retain one Python heap across arms, not a normal fresh-CLI memory baseline")
    parser.add_argument("--pairs",type=int,default=5);parser.add_argument("--seed",type=int,default=20261020)
    parser.add_argument("--timeout",type=float,default=300)
    parser.add_argument("--cgroup-parent",type=Path,default=Path("/sys/fs/cgroup"))
    parser.add_argument("--ring-bytes",type=int,default=64*1024**2)
    parser.add_argument("--process-sample-ms",type=int,default=20)
    parser.add_argument("--max-records",type=int,default=2000000);parser.add_argument("--max-bytes",type=int,default=2*1024**3)
    args=parser.parse_args(argv);report=campaign(args)
    print(json.dumps({key:report[key] for key in ("status","scope","statistics")},ensure_ascii=False),flush=True)


if __name__=="__main__":main()
