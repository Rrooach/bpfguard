#!/usr/bin/env python3
"""Run the SAME eight benchmark jobs with 2/4/6/8 admitted at once.

Preparation and all collectors complete before the first release. JSON
projection and official post-Agent verification wait for the last quiescent
job. Every worker is a separate process; this controller runs only in its
dedicated experiment Guest.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from common import digest, write_new
from phase_control import CampaignAborted, cgroup_snapshot, job_name, publish, read_record


def complete_sample(path, last=False):
    """Only a complete, bounded JSONL sample can satisfy a timing barrier."""
    path = Path(path)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError('sampler output must be a regular non-symlink file')
    limit = 1024 * 1024
    with path.open('rb') as stream:
        if last:
            size = path.stat().st_size
            offset = max(0, size-limit)
            stream.seek(offset)
            data = stream.read(limit)
            if offset:
                data = data.partition(b'\n')[2]
            lines = data.split(b'\n')[:-1]
            raw = lines[-1] if lines else None
        else:
            data = stream.readline(limit+1)
            if len(data) > limit:
                raise ValueError('sampler sample exceeds bounded line size')
            raw = data[:-1] if data.endswith(b'\n') else None
    if raw is None:
        return None
    row = json.loads(raw)
    if (not isinstance(row, dict) or type(row.get('seq')) is not int or row['seq'] < 0
            or type(row.get('monotonic_ns')) is not int
            or type(row.get('collection_end_ns')) is not int
            or not 0 <= row['monotonic_ns'] <= row['collection_end_ns']):
        raise ValueError('invalid sampler clock/sequence sample')
    if not last and row['seq'] != 0:
        raise ValueError('sampler first sequence is not zero')
    return row


def load_plan(path):
    plan = json.loads(Path(path).read_bytes())
    jobs = plan.get("jobs")
    if plan.get("schema_version") != 1 or not isinstance(jobs, list) or len(jobs) != 8:
        raise ValueError("exactly eight explicit jobs are required for equal-work comparison")
    names = [job_name(job.get("job_id")) for job in jobs]
    if len(names) != len(set(names)):
        raise ValueError("duplicate job IDs")
    for job in jobs:
        argv = job.get("command")
        if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) or "\0" in arg for arg in argv):
            raise ValueError("worker command must be a nonempty argv list")
        if not all(token in argv for token in ("@JOB_OUTPUT@", "@CONTROL_DIR@", "@JOB_ID@")):
            raise ValueError("worker argv must explicitly bind output, control and job ID")
    return plan


def done_times(record, released):
    meta = record.get("metadata", {})
    returned = meta.get("agent_return_ns")
    quiet = meta.get("quiescent_ns")
    if (type(returned) is not int or type(quiet) is not int or not released <= returned <= quiet <= record["monotonic_ns"]
            or meta.get("quiescent") is not True):
        raise ValueError("worker did not establish ordered return and quiescence")
    return returned, quiet


def run(args):
    plan = load_plan(args.plan)
    if args.concurrency not in (2, 4, 6, 8):
        raise ValueError("concurrency must be 2,4,6,8")
    root = args.output.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    control = root / "control"
    control.mkdir(mode=0o700)
    logs = root / "worker-logs"
    logs.mkdir(mode=0o700)
    (root / "jobs").mkdir(mode=0o700)
    write_new(root / "plan.json", plan)
    started = time.monotonic_ns()
    rows, processes, streams = [], {}, []
    result = {"schema_version": 1, "benchmark": plan.get("benchmark"), "scope": plan.get("scope"),
        "plan_identity": digest(args.plan), "concurrency": args.concurrency, "total_jobs": 8,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "resource_configuration": plan.get("resource_configuration"), "jobs": rows,
        "measurement": "FIRST_CONTROLLER_RELEASE_TO_LAST_WORKER_QUIESCENCE; NOT_SUM_OF_THREADS; ALL_EIGHT_COLLECTORS_READY_IN_EVERY_GROUP",
        "status": "STARTING", "max_admitted_observed": 0}
    error = None
    sampler = None
    try:
        for spec in plan["jobs"]:
            name = spec["job_id"]
            (control / name).mkdir(mode=0o700)
            output = root / "jobs" / name
            substitutions = {"@JOB_OUTPUT@": str(output), "@CONTROL_DIR@": str(control), "@JOB_ID@": name}
            command = [substitutions.get(arg, arg) for arg in spec["command"]]
            stdout, stderr = (logs / (name + ".stdout")).open("xb"), (logs / (name + ".stderr")).open("xb")
            streams.extend((stdout, stderr))
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            processes[name] = process
            rows.append({"job_id": name, "task_id": spec.get("task_id"), "output": str(output), "pid": process.pid})
        deadline = time.monotonic() + args.setup_timeout
        while not all((control / row["job_id"] / "ready.json").exists() for row in rows):
            if (control / "abort.json").exists():
                raise CampaignAborted(str(read_record(control / "abort.json")))
            if any(process.poll() is not None for process in processes.values()):
                raise RuntimeError("worker exited before the all-ready barrier")
            if time.monotonic() > deadline:
                raise TimeoutError("all-ready barrier timed out")
            time.sleep(0.01)
        for row in rows:
            ready = read_record(control / row["job_id"] / "ready.json")
            if ready.get("event") != "READY" or ready.get("job_id") != row["job_id"]:
                raise ValueError("ready record identity differs")
            row.update(ready_ns=ready["monotonic_ns"], ready_metadata=ready.get("metadata"))
            if row['ready_metadata'].get('cgroup_root'):
                # Independently read frozen=1; do not rely only on a worker flag.
                snapshot = cgroup_snapshot(row['ready_metadata'])
                publish(control/row['job_id']/'all-ready-frozen-check.json', snapshot)
        result["all_ready_ns"] = time.monotonic_ns()
        sampler_path = getattr(args, 'sampler', None)
        if sampler_path:
            sampler_path = Path(sampler_path).resolve(strict=True)
            command = [str(sampler_path),'--output-dir',str(root/'load'),'--interval-ms','100',
                       '--process-interval-ms','0','--exit-with-parent','--label',root.name]
            for row in rows:
                metadata=row['ready_metadata']
                target=Path(metadata['cgroup_root']).resolve(strict=True)
                if Path('/sys/fs/cgroup') not in target.parents or target.stat().st_ino != metadata['cgroup_id']:
                    raise ValueError('sampler target differs from registered frozen cgroup')
                command.extend(['--cgroup',str(target)])
            sampler_log=(root/'sampler.stderr').open('xb');streams.append(sampler_log)
            sampler=subprocess.Popen(command,stdout=sampler_log,stderr=sampler_log)
            result['sampler_identity']=digest(sampler_path)
            deadline=time.monotonic()+15
            sample_file=root/'load/load-samples.jsonl'
            while complete_sample(sample_file) is None:
                if sampler.poll() is not None:
                    raise RuntimeError('resource sampler exited before its first sample')
                if time.monotonic()>deadline:
                    raise TimeoutError('resource sampler first-sample barrier timed out')
                time.sleep(.01)
            result['sampler_first_sample_ns']=complete_sample(sample_file)['monotonic_ns']
            result['sampler_ready_ns']=time.monotonic_ns()
        waiting, active, done = list(rows), {}, []
        while waiting or active:
            if sampler is not None and sampler.poll() is not None:
                raise RuntimeError('resource sampler exited before the final quiescence barrier')
            if (control / "abort.json").exists():
                raise CampaignAborted(str(read_record(control / "abort.json")))
            while waiting and len(active) < args.concurrency:
                row = waiting.pop(0)
                released = time.monotonic_ns()
                row["release_issued_ns"] = released
                result.setdefault("batch_start_ns", released)
                publish(control / row["job_id"] / "release.json", {"schema_version": 1, "event": "RELEASE",
                    "job_id": row["job_id"], "monotonic_ns": released})
                active[row["job_id"]] = row
            result["max_admitted_observed"] = max(result["max_admitted_observed"], len(active))
            for name, row in list(active.items()):
                path = control / name / "agent-done.json"
                if path.exists():
                    record = read_record(path)
                    if record.get("event") != "AGENT_DONE" or record.get("job_id") != name:
                        raise ValueError("done record identity differs")
                    returned, quiet = done_times(record, row["release_issued_ns"])
                    row.update(agent_return_ns=returned, quiescent_ns=quiet,
                        done_observed_ns=time.monotonic_ns(), done_metadata=record["metadata"])
                    done.append(row)
                    del active[name]
                elif processes[name].poll() is not None:
                    raise RuntimeError("worker exited before quiescent DONE: " + name)
                elif time.monotonic_ns() - row["release_issued_ns"] > args.task_timeout * 1_000_000_000:
                    raise TimeoutError("admitted task timed out: " + name)
            time.sleep(0.002)
        result["batch_end_ns"] = max(row["quiescent_ns"] for row in done)
        result["agent_return_end_ns"] = max(row["agent_return_ns"] for row in done)
        result["controller_observed_batch_end_ns"] = time.monotonic_ns()
        result["batch_wall_ns"] = result["batch_end_ns"] - result["batch_start_ns"]
        result["agent_return_batch_wall_ns"] = result["agent_return_end_ns"] - result["batch_start_ns"]
        if sampler is not None:
            # A signal exits the sampler without a final sample. Wait for an
            # actual complete sample after quiescence, not an imagined endpoint.
            deadline=time.monotonic()+15
            while True:
                if sampler.poll() is not None:
                    raise RuntimeError('resource sampler exited before its enclosing final sample')
                final_sample=complete_sample(root/'load/load-samples.jsonl', last=True)
                if final_sample is not None and final_sample['monotonic_ns'] >= result['batch_end_ns']:
                    break
                if time.monotonic()>deadline:
                    raise TimeoutError('resource sampler final-sample barrier timed out')
                time.sleep(.01)
            result['sampler_last_sample_ns']=final_sample['monotonic_ns']
            sampler.send_signal(signal.SIGTERM)
            result['sampler_return_code']=sampler.wait(timeout=15)
            result['sampler_stopped_ns']=time.monotonic_ns()
            if result['sampler_return_code'] != 0:
                raise RuntimeError('resource sampler did not finalize cleanly')
        result["postprocessing_released_ns"] = time.monotonic_ns()
        publish(control / "all-agents-done.json", {"schema_version": 1, "event": "ALL_AGENTS_DONE",
            "monotonic_ns": result["postprocessing_released_ns"], "total_jobs": 8})
        deadline = time.monotonic() + args.finalize_timeout
        while any(process.poll() is None for process in processes.values()):
            if (control / "abort.json").exists():
                raise CampaignAborted(str(read_record(control / "abort.json")))
            if time.monotonic() > deadline:
                raise TimeoutError("official evaluation/postprocessing timed out")
            time.sleep(0.05)
        for row in rows:
            row["worker_exit_code"] = processes[row["job_id"]].returncode
        result["status"] = "WORKERS_COMPLETED" if all(row["worker_exit_code"] == 0 for row in rows) else "WORKER_FAILURE_RETAINED"
    except BaseException as exc:
        error = type(exc).__name__ + ": " + str(exc)
        result.update(status="ABORTED", error=error)
        try:
            publish(control / "abort.json", {"schema_version": 1, "event": "ABORT", "job_id": "controller",
                "monotonic_ns": time.monotonic_ns(), "error": error})
        except FileExistsError:
            pass
        # Let worker finally blocks resume/clean only their own containers.
        deadline = time.monotonic() + 30
        while any(process.poll() is None for process in processes.values()) and time.monotonic() < deadline:
            time.sleep(0.05)
        for process in processes.values():
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        for process in processes.values():
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
        for row in rows:
            row["worker_exit_code"] = processes[row["job_id"]].returncode
    finally:
        if sampler is not None and sampler.poll() is None:
            sampler.terminate()
            try:
                sampler.wait(timeout=10)
            except subprocess.TimeoutExpired:
                sampler.kill();sampler.wait(timeout=10)
        result["campaign_end_ns"] = time.monotonic_ns()
        result["campaign_wall_ns"] = result["campaign_end_ns"] - started
        result["campaign_start_ns"] = started
        for stream in streams:
            stream.close()
        write_new(root / "campaign.json", result)
    print(json.dumps({key:result.get(key) for key in ("status","concurrency","total_jobs","batch_wall_ns","campaign_wall_ns","error")}))
    return int(error is not None or result["status"] != "WORKERS_COMPLETED")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, choices=(2,4,6,8), required=True)
    parser.add_argument("--setup-timeout", type=float, default=1800)
    parser.add_argument("--task-timeout", type=float, default=900)
    parser.add_argument("--finalize-timeout", type=float, default=1800)
    parser.add_argument("--sampler", type=Path, help="optional pinned allox-load-sampler; 100ms, all eight cgroups, no thread polling")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
