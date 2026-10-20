#!/usr/bin/env python3
"""Paired OFF/FULL overhead for recorded native command workloads, zero API.

This is NOT_WHOLE_AGENT_SLOWDOWN: it replays command text emitted by a real
native Codex run, not the model loop, Code Mode JS, or provider responses.
Unsupported apply_patch/MCP/other tool operations reject the campaign rather
than quietly reducing the workload. Baseline restore and hashing are outside
the measured release -> whole-cgroup-empty window.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import random
import shutil
import statistics
import sys
from types import SimpleNamespace

from common import digest, write_new
from runtime_resources import RuntimeResourceSampler
import run as linux_run


def recorded_plan(application, source_workspace, *, shell="/bin/bash", command_timeout=45):
    """Reject every unhandled operation; do not call a shell-only subset full."""
    source_workspace=Path(source_workspace)
    if not source_workspace.is_absolute():raise ValueError("original workspace must be absolute")
    if application.get("status")!="completed":raise ValueError("a completed native source run is required")
    if application.get("mode")!="OFFICIAL_CODEX_NATIVE_TOOLS_NO_REPLACEMENT":
        raise ValueError("source must be a real native-tools run, not observer_bash or artificial fixture")
    if application.get("unmapped_items"):
        raise ValueError("NOT_REPLAYABLE: source contains unmapped native items")
    calls=application.get("tool_calls",[])
    results={row["call_id"]:row for row in application.get("native_tool_results",[])}
    commands=[]
    for call in calls:
        if call.get("tool_name")!="commandExecution":
            raise ValueError("NOT_REPLAYABLE: native non-shell operation "+str(call.get("tool_name")))
        arguments=call.get("arguments",{})
        command,cwd=arguments.get("command"),arguments.get("cwd")
        if not isinstance(command,str) or not command.strip() or "\0" in command:
            raise ValueError("NOT_REPLAYABLE: missing untruncated command text")
        if str(source_workspace) in command:
            raise ValueError("NOT_REPLAYABLE: absolute original-workspace path in command; no silent command rewriting")
        if not isinstance(cwd,str):raise ValueError("NOT_REPLAYABLE: original cwd missing")
        try:relative=Path(cwd).relative_to(source_workspace)
        except ValueError as error:raise ValueError("NOT_REPLAYABLE: source command cwd lies outside workspace") from error
        if ".." in relative.parts:raise ValueError("NOT_REPLAYABLE: parent traversal in source cwd")
        result=results.get(call.get("call_id"))
        if not result or type(result.get("exit_code")) is not int:
            raise ValueError("NOT_REPLAYABLE: native command result/exit missing")
        if not isinstance(result.get("output"),dict) or not isinstance(result["output"].get("text"),str):
            raise ValueError("NOT_REPLAYABLE: source native output is absent")
        if result["output"].get("truncated"):
            raise ValueError("NOT_REPLAYABLE: source command output was truncated")
        source_bytes=result["output"]["text"].encode()
        commands.append({"call_id":call["call_id"],"command":command,"relative_cwd":str(relative),
            "source_exit_code":result["exit_code"],"source_output":result.get("output"),
            "source_output_digest":{"sha256":hashlib.sha256(source_bytes).hexdigest(),"size_bytes":len(source_bytes)}})
    if not commands:raise ValueError("NOT_REPLAYABLE: no native command work recorded")
    return {"schema_version":1,"scope":"RECORDED_NATIVE_SHELL_TEXT_REPLAY_NOT_WHOLE_AGENT",
        "source_mode":application["mode"],"source_agent_id":application.get("agent_id"),
        "source_task_id":application.get("task_id"),"source_workspace":str(source_workspace),
        "shell":shell,"path":"/usr/local/bin:/usr/bin:/bin","command_timeout":command_timeout,
        "commands":commands,"provider":"NO_MODEL_REQUESTS_OR_NEW_INFERENCE_BY_HARNESS",
        "excluded":"MODEL_RUNTIME_CODE_MODE_JS_AND_AGENT_SCHEDULING_NOT_REPLAYED",
        "shell_semantics":"EXPLICIT_HARNESS_BASH_NOT_CLAIMED_IDENTICAL_NATIVE_EXEC_ARGV"}


def tree_digest(root,*,normalize_pyc_timestamp=False):
    """Logical content/mode/owner/xattr/hardlink digest, not raw inode/ctime."""
    root=Path(root).resolve(strict=True)
    rows=[];hardlinks={}
    for path in [root]+sorted(root.rglob("*")):
        info=path.lstat();relative=str(path.relative_to(root))
        row={"path":relative,"mode":info.st_mode,"uid":info.st_uid,"gid":info.st_gid}
        if path.is_symlink():row.update(kind="symlink",target=os.readlink(path))
        elif path.is_file():
            identity=digest(path)
            if normalize_pyc_timestamp and path.suffix==".pyc" and path.parent.name=="__pycache__":
                content=path.read_bytes()
                # PEP 552 timestamp-pyc: only bytes 8..11 encode source mtime.
                # Retain flags, size, bytecode, filenames and all other bytes.
                if len(content)>=16 and content[2:4]==b"\r\n" and content[4:8]==b"\0\0\0\0":
                    normalized=content[:8]+b"\0\0\0\0"+content[12:]
                    identity={"sha256":hashlib.sha256(normalized).hexdigest(),"size_bytes":len(content),
                        "normalization":"PEP552_TIMESTAMP_PYC_SOURCE_MTIME_ONLY_V1"}
            row.update(kind="file",**identity)
            key=(info.st_dev,info.st_ino)
            row["hardlink_group"]=hardlinks.setdefault(key,relative)
        elif path.is_dir():row["kind"]="directory"
        else:raise ValueError("unsupported special object in replay baseline: "+relative)
        row["xattrs"]={name:os.getxattr(path,name,follow_symlinks=False).hex()
            for name in sorted(os.listxattr(path,follow_symlinks=False))}
        rows.append(row)
    raw=json.dumps(rows,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
    return {"sha256":hashlib.sha256(raw).hexdigest(),"objects":len(rows),
        "scope":"LOGICAL_PATH_CONTENT_MODE_OWNER_XATTR_HARDLINKS; EXCLUDES_INODE_CTIME_MTIME"+
            ("; NORMALIZES_ONLY_PEP552_TIMESTAMP_PYC_SOURCE_MTIME_HEADER; RAW_TREE_REPORTED_SEPARATELY" if normalize_pyc_timestamp else "")}


def restore_new_workspace(baseline,workspace,archive):
    """Retain every prior workspace; never delete user input or broad paths."""
    baseline=Path(baseline).resolve(strict=True);workspace=Path(workspace);archive=Path(archive)
    if workspace.parent!=archive.parent.parent or workspace.name!="workspace":
        raise ValueError("only the campaign's explicit new workspace may be restored")
    if workspace.exists():
        if archive.exists():raise ValueError("workspace archive already exists")
        workspace.rename(archive)
    cache={}
    def copy_file(source,destination):
        stat=Path(source).stat();key=(stat.st_dev,stat.st_ino)
        if key in cache:
            os.link(cache[key],destination)
            return destination
        shutil.copy2(source,destination)
        os.chown(destination,stat.st_uid,stat.st_gid,follow_symlinks=False)
        cache[key]=destination
        return destination
    shutil.copytree(baseline,workspace,symlinks=True,copy_function=copy_file)
    # copytree preserves mode/xattrs; preserve owner separately for directory
    # and symlink objects, without following workspace symlinks.
    for source in [baseline]+list(baseline.rglob("*")):
        target=workspace/source.relative_to(baseline);stat=source.lstat()
        os.chown(target,stat.st_uid,stat.st_gid,follow_symlinks=False)


def percentile(values,q):
    values=sorted(values)
    if not values:return None
    index=(len(values)-1)*q
    low=math.floor(index);high=math.ceil(index)
    return values[low]+(values[high]-values[low])*(index-low)


def paired_statistics(pairs,seed=1,bootstrap=5000):
    if len(pairs)<5:raise ValueError("at least five complete pairs required")
    off=[row["off_ms"] for row in pairs];full=[row["full_ms"] for row in pairs]
    if any(not math.isfinite(value) or value<=0 for value in off+full):
        raise ValueError("strictly positive finite wall times required")
    ratios=[b/a-1 for a,b in zip(off,full)]
    generator=random.Random(seed)
    resampled=[statistics.median(generator.choices(ratios,k=len(ratios))) for _ in range(bootstrap)]
    return {"pairs":len(pairs),"off_wall_ms":{"median":statistics.median(off),"p95":percentile(off,.95)},
        "full_wall_ms":{"median":statistics.median(full),"p95":percentile(full,.95)},
        "paired_slowdown":{"median_fraction":statistics.median(ratios),"median_percent":100*statistics.median(ratios),
            "bootstrap_95_percent":[100*percentile(resampled,.025),100*percentile(resampled,.975)],
            "bootstrap_resamples":bootstrap,"statistic":"MEDIAN_OF_PAIRED_FULL_OVER_OFF_MINUS_ONE"},
        "scope":"NOT_WHOLE_AGENT_SLOWDOWN; SAME_RECORDED_SHELL_COMMAND_BATCH"}


def output_identity(result):
    return [{"call_id":row["call_id"],"command":row["command"],"relative_cwd":row["relative_cwd"],
        "return_code":row["return_code"],"output":row["output"],"timed_out":row["timed_out"]}
        for row in result["commands"]]


def campaign(args):
    if os.geteuid()!=0:raise RuntimeError("run only as root in the owned experiment VM")
    if not 5<=args.pairs<=30:raise ValueError("between five and thirty paired repetitions required")
    application=json.loads(args.application.read_text())
    plan=recorded_plan(application,args.source_workspace,command_timeout=args.command_timeout)
    baseline=args.baseline.resolve(strict=True)
    baseline_identity=tree_digest(baseline)
    root=args.output.resolve();root.mkdir(mode=0o700,parents=True,exist_ok=False)
    workspace=root/"workspace";archive=root/"retained-workspaces";archive.mkdir()
    write_new(root/"replay-plan.json",plan)
    write_new(root/"source-and-baseline.json",{"application":digest(args.application),"baseline":baseline_identity,
            "collector":digest(args.collector),"object":digest(args.object),"shell":digest(Path(plan["shell"])),
        "scope":plan["scope"],"provider":"NO_PROVIDER_REQUESTS_BY_HARNESS; NOT_PROVIDER_RESPONSE_REPLAY"})
    generator=random.Random(args.seed)
    schedule=[]
    for pair in range(args.pairs):
        arms=["off","full"];generator.shuffle(arms)
        schedule.extend({"pair":pair,"arm":arm} for arm in arms)
    write_new(root/"schedule.json",{"seed":args.seed,"paired_order":schedule,
        "cache":"BASELINE_RESTORE_AND_HASH_BEFORE_EACH_ARM; WARM_COPY_CONDITION_NOT_COLD_STORAGE"})
    results=[];reference=None;reference_tree=None;correct=True
    worker=Path(__file__).with_name("native_profile_replay_worker.py").resolve()
    for index,scheduled in enumerate(schedule):
        run_name="pair-%02d-%s"%(scheduled["pair"],scheduled["arm"])
        restore_new_workspace(baseline,workspace,archive/("before-%03d"%index))
        if tree_digest(workspace)!=baseline_identity:
            raise ValueError("baseline logical identity changed during clone; refusing incomparable measurement")
        side=root/(run_name+"-work");side.mkdir()
        output=root/run_name
        monitor=None
        def collector_started(pid):
            nonlocal monitor
            monitor=RuntimeResourceSampler(side/"observer-resource",interval_ms=50,agent_id="observer-overhead")
            monitor.register("collector",pid=pid,role="OBSERVER_COLLECTOR")
            monitor.start()
        options=SimpleNamespace(tools=None,agent_id="recorded-native-command-replay",run_id=run_name,
            command=[sys.executable,str(worker),"--plan",str(root/"replay-plan.json"),"--workspace",str(workspace),"--output",str(side)],
            output=output,collector=args.collector.resolve(strict=True),object=args.object.resolve(strict=True),
            cgroup_parent=args.cgroup_parent,timeout=args.timeout,max_records=args.max_records,max_bytes=args.max_bytes,
            ring_bytes=args.ring_bytes,no_kernel_stacks=False,live_json=False,no_trace=scheduled["arm"]=="off",
            collector_started=collector_started)
        try:
            # Keep collector's textual status in each arm, not mixed into the
            # final statistics JSON. No events or errors are discarded.
            with (side/"runner.stdout").open("x") as log,contextlib.redirect_stdout(log):
                linux_run.collect_run(options)
        finally:
            if monitor is not None:monitor.stop()
        manifest_path=output/("baseline.json" if scheduled["arm"]=="off" else "manifest.json")
        manifest=json.loads(manifest_path.read_text())
        span=manifest["tools"][0]
        result=json.loads((side/"replay-result.json").read_text())
        identity=output_identity(result);final_tree=tree_digest(workspace)
        if reference is None:reference,reference_tree=identity,final_tree
        valid=(result["complete"] and identity==reference and final_tree==reference_tree
            and len(result["commands"])==len(plan["commands"])
            and all(row["return_code"]==row["original_return_code"] for row in result["commands"])
            and all(row["output"]==source["source_output_digest"]
                    for row,source in zip(result["commands"],plan["commands"])))
        correct=correct and valid
        resources=json.loads((side/"observer-resource/resource-summary.json").read_text()) if monitor else None
        evidence_bytes=sum(path.stat().st_size for directory in (output,side) for path in directory.rglob("*") if path.is_file())
        row={**scheduled,"run_name":run_name,"correctness":"MATCHED" if valid else "MISMATCH",
            "wall_ms":(span["end_ns"]-span["begin_ns"])/1000000,
            "command_wall_ms":sum(command["end_ns"]-command["begin_ns"] for command in result["commands"])/1000000,
            "command_count":len(result["commands"]),"output_identity":identity,"final_tree":final_tree,
            "ring_bytes":0 if scheduled["arm"]=="off" else args.ring_bytes,"evidence_bytes":evidence_bytes,
            "observer_resources":resources,"observer_resource_scope":"REGISTERED_COLLECTOR_PID_ONLY; CPU_IS_OBSERVED_SAMPLE_DELTA_NOT_LIFETIME_TOTAL",
            "kernel_verification":"NOT_APPLICABLE_OFF" if scheduled["arm"]=="off" else
                json.loads((output/"verification.json").read_text()),
            "measurement":"SIGCONT_OF_IDENTICAL_SERIAL_DRIVER_THROUGH_CGROUP_EMPTY; RESTORE_HASH_EXCLUDED"}
        results.append(row)
        write_new(root/(run_name+"-measurement.json"),row)
    unchanged_baseline=tree_digest(baseline)==baseline_identity
    correct=correct and unchanged_baseline
    pairs=[]
    for pair in range(args.pairs):
        arms={row["arm"]:row for row in results if row["pair"]==pair}
        pairs.append({"pair":pair,"off_ms":arms["off"]["wall_ms"],"full_ms":arms["full"]["wall_ms"]})
    report={"status":"PAIRED_WITHIN_DECLARED_COMMAND_SCOPE" if correct else "INCOMPARABLE_CORRECTNESS_MISMATCH",
        "scope":"NOT_WHOLE_AGENT_SLOWDOWN; RECORDED_NATIVE_SHELL_COMMAND_BATCH_ONLY",
        "provider":"NO_NEW_INFERENCE_AND_NO_PROVIDER_RESPONSE_REPLAY", "source":digest(args.application),
        "baseline_unchanged":unchanged_baseline,"all_correctness_checks_passed":correct,
        "statistics":paired_statistics(pairs,args.seed) if correct else None,"measurements":results,
        "limitations":["Does not measure model waiting, real Agent decisions, native Code Mode JS, or actual native tool dispatcher overhead",
            "Paired stdout/file correctness is checked; does not prove unobserved remote effects unchanged",
            "Observer PID RSS/CPU are sampled; ring shared mappings are not private physical overhead",
            "BPF attach/detach, replay/render/export, baseline restore and correctness hash are outside workload wall window",
            "Copy/hash warms Guest cache; not a cold-cache experiment",
            "Small shell batches may be dominated by serial driver/startup/closure costs; report confidence interval",
            "No correctness-failing arm is silently removed or replaced"]}
    write_new(root/"overhead-report.json",report)
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("application","baseline","source-workspace","output","collector","object"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--pairs",type=int,default=5)
    parser.add_argument("--seed",type=int,default=20261020)
    parser.add_argument("--command-timeout",type=float,default=45)
    parser.add_argument("--timeout",type=float,default=180)
    parser.add_argument("--cgroup-parent",type=Path,default=Path("/sys/fs/cgroup"))
    parser.add_argument("--ring-bytes",type=int,default=64*1024**2)
    parser.add_argument("--max-records",type=int,default=2000000)
    parser.add_argument("--max-bytes",type=int,default=2*1024**3)
    args=parser.parse_args(argv)
    report=campaign(args)
    print(json.dumps({key:report[key] for key in ("status","scope","statistics")},ensure_ascii=False),flush=True)


if __name__=="__main__":main()
