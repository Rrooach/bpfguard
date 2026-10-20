#!/usr/bin/env python3
"""One real Terminal-Bench Oracle trial in a parent-controlled parallel batch.

The parent launches eight independent worker processes. This adapter does not
invent eight searches, alter the official solution/tests, or make model calls.
It reuses terminal_validate's reviewed single-trial capture and Docker Exec
gate, adding only public Harbor phase hooks around that adapter's callbacks.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
import json
import math
import re
import sys
import time
from pathlib import Path
from types import SimpleNamespace


JOB_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z")
ORACLE_SCOPE = "OFFICIAL_ORACLE_REFERENCE_CONTROL_NOT_MODEL_SCORE"


class WorkerHooks:
    """Per-process, per-trial phase barriers; dependencies are injectable.

    No expensive collector STOP/JSON projection runs before Control.done has
    observed the parent's all-agents-done release. A nonbaseline survivor is
    a failed static workload contract, not automatically a process-leak claim.
    """

    def __init__(self, *, job_id, task, control, terminal, finder_factory,
                 baseline_reader=None, clock=time.monotonic_ns, agent_id=None, agent_scope=ORACLE_SCOPE):
        if JOB_PATTERN.fullmatch(job_id) is None:
            raise ValueError("job-id must be one safe, bounded path component")
        self.job_id, self.task, self.control, self.terminal = job_id, task, control, terminal
        self.agent_id = agent_id or "official-oracle:" + job_id
        self.agent_scope = agent_scope
        self.finder_factory = finder_factory
        self.baseline_reader = baseline_reader or terminal.frozen_baseline_threads
        self.clock = clock
        self.adapter = self.finder = self.target = self.trial = None
        self.paused = False
        self.started = self.ended = False
        self.start_hooks = self.end_hooks = 0
        self.events = []
        self.agent_return_ns = self.quiescent_ns = None

    def phase(self, name, **metadata):
        row = {"schema_version": 1, "job_id": self.job_id, "agent_id": self.agent_id,
               "task_id": "terminal-bench/" + self.task, "phase": name,
               "monotonic_ns": self.clock(), **metadata}
        self.events.append(row)
        return row["monotonic_ns"]

    def abort(self, error):
        # A broken error-reporting channel must not replace the original
        # exception or make it possible to publish a healthy DONE.
        try:
            self.control.fail(self.job_id + ": " + type(error).__name__ + ": " + str(error))
        except Exception as failure:
            self.phase("ABORT_PUBLICATION_FAILED", error_type=type(failure).__name__)

    def identity(self):
        manifest = self.adapter.manifest
        return {"job_id": self.job_id, "benchmark": "Terminal-Bench", "task": self.task,
                "agent_id": self.agent_id, "agent_scope": self.agent_scope,
                "run_id": manifest["run_id"], "boot_id": manifest["boot_id"],
                "container_id": self.target.container_id, "cgroup_root": str(self.target.cgroup_directory),
                "cgroup_id": self.target.cgroup_id, "namespace": manifest["namespace"],
                "capture_directory": str(self.adapter.directory)}

    async def freeze(self):
        await self.finder.pause(self.target)
        self.paused = True

    async def unfreeze(self):
        if self.paused:
            await self.finder.unpause(self.target)
            self.paused = False

    async def start(self, trial, callback, *args, **kwargs):
        try:
            if self.started:
                raise RuntimeError("worker AGENT_START may execute only once")
            result = await callback(*args, **kwargs)
            adapter = trial.agent_environment.exec
            if not isinstance(adapter, self.terminal.GatedExec) or adapter.manifest.get("tools"):
                raise RuntimeError("expected unused real Docker Exec gate before releasing the Agent")
            self.adapter, self.trial = adapter, trial
            self.finder = self.finder_factory(trial)
            self.target = await self.finder.discover_target()
            manifest = adapter.manifest
            if (adapter.container_id != self.target.container_id
                    or manifest.get("container_id") != self.target.container_id
                    or manifest.get("cgroup_id") != self.target.cgroup_id
                    or manifest.get("cgroup_root") != str(self.target.cgroup_directory)):
                raise RuntimeError("worker gate, capture, and live container identity disagree")
            if not manifest.get("baseline_threads"):
                raise RuntimeError("worker requires the original frozen baseline ledger")
            # Both paths are set: GatedExec may otherwise keep an explicit old
            # agent_id, and its per-tool IDs must also be unique across jobs.
            adapter.agent_id = self.agent_id
            adapter.tool_prefix = self.job_id + "-exec"
            manifest.update(agent_id=self.agent_id, agent_scope=self.agent_scope, job_id=self.job_id)
            manifest["parallel_worker"] = {"job_id": self.job_id, "agent_scope": self.agent_scope,
                "control_directory": str(self.control.directory) if hasattr(self.control, "directory") else None,
                "timing_scope": "PARENT_CONTROLS_AGENT_PHASE_ONLY; POSTPROCESS_AND_OFFICIAL_TESTS_AFTER_BATCH"}
            await self.freeze()
            adapter.persist()
            self.started = True
            ready_ns = self.phase("FROZEN_READY")
            released = await self.control.ready({**self.identity(), "frozen": True, "frozen_ready_ns": ready_ns})
            observed = getattr(self.control, "release_observed_ns", None)
            self.phase("PARENT_RELEASE_OBSERVED", release_observed_ns=observed, release=released)
            manifest["parallel_worker"]["release_observed_ns"] = observed
            await self.unfreeze()
            manifest["parallel_worker"]["agent_release_ns"] = self.phase("AGENT_RELEASED")
            return result
        except BaseException as error:
            self.abort(error)
            try:
                await self.unfreeze()
            except Exception as cleanup:
                self.phase("UNFREEZE_FAILED", error_type=type(cleanup).__name__)
            raise

    async def finish(self, trial, callback, *args, **kwargs):
        try:
            if not self.started or self.ended or trial is not self.trial:
                raise RuntimeError("AGENT_END requires exactly one matching, released worker")
            returned = self.phase("AGENT_RETURNED")
            self.agent_return_ns = returned
            await self.freeze()
            closure = self.baseline_reader(self.target.cgroup_directory)
            baseline = {(row["tid"], row["start_ticks"]) for row in self.adapter.manifest["baseline_threads"]}
            candidates = [row for row in closure if (row["tid"], row["start_ticks"]) not in baseline]
            quiescent = self.phase("FROZEN_AGENT_END", nonbaseline_thread_candidates=candidates)
            if candidates:
                raise RuntimeError("NONBASELINE_THREADS_REMAIN_AT_AGENT_END; requires lineage review, not an automatic leak verdict")
            self.quiescent_ns = quiescent
            metadata = {**self.identity(), "agent_return_ns": returned, "quiescent_ns": quiescent,
                        "frozen": True, "quiescent": True, "closure_threads": closure, "nonbaseline_thread_candidates": []}
            self.adapter.manifest["parallel_worker"].update(agent_return_ns=returned, quiescent_ns=quiescent)
            self.phase("DONE_PUBLICATION_REQUESTED", agent_return_ns=returned, quiescent_ns=quiescent)
            released = await self.control.done(metadata)
            self.phase("POSTPROCESS_RELEASE_OBSERVED", release=released)
            self.ended = True
            # Retain and bind these additional boundaries without modifying
            # any raw collector record or the original immutable tool ledger.
            path = self.adapter.directory / "parallel-phases.json"
            self.terminal.write_json(path, {"schema_version": 1, "job_id": self.job_id,
                "agent_id": self.agent_id, "agent_scope": self.agent_scope,
                "events": self.events, "end_scope": "BEFORE_COLLECTOR_STOP_AND_OFFICIAL_VERIFICATION"})
            self.adapter.manifest["artifacts"][path.name] = {
                "sha256": self.terminal.sha256(path), "size_bytes": path.stat().st_size}
            self.adapter.persist()
            # Original finish issues docker pause itself. No Agent-owned
            # workload survives this boundary, and all Agents are now done.
            await self.unfreeze()
            return await callback(*args, **kwargs)
        except BaseException as error:
            self.abort(error)
            try:
                await self.unfreeze()
            except Exception as cleanup:
                self.phase("UNFREEZE_FAILED", error_type=type(cleanup).__name__)
            raise

    @contextmanager
    def install(self, trial_class, start_event, end_event):
        """Wrap only terminal_validate's reviewed hooks, not Harbor internals."""
        original = trial_class.add_hook
        hooks = self

        def register(trial, event, callback, *args, **kwargs):
            adapter_hook = getattr(callback, "__module__", None) == hooks.terminal.__name__
            wrapped = callback
            if adapter_hook and event == start_event and getattr(callback, "__name__", None) == "start":
                hooks.start_hooks += 1
                if hooks.start_hooks != 1:
                    raise RuntimeError("one worker must register exactly one trial")

                async def wrapped(*values, **options):
                    return await hooks.start(trial, callback, *values, **options)
            elif adapter_hook and event == end_event and getattr(callback, "__name__", None) == "finish":
                hooks.end_hooks += 1
                if hooks.end_hooks != 1:
                    raise RuntimeError("one worker must register exactly one trial")

                async def wrapped(*values, **options):
                    return await hooks.finish(trial, callback, *values, **options)
            elif adapter_hook and event in (start_event, end_event):
                raise RuntimeError("unsupported terminal adapter hook ABI; refusing ungated execution")
            return original(trial, event, wrapped, *args, **kwargs)

        trial_class.add_hook = register
        try:
            yield self
        finally:
            trial_class.add_hook = original


def validate_options(args):
    if JOB_PATTERN.fullmatch(args.job_id) is None:
        raise ValueError("job-id must be one safe, bounded path component")
    if len(args.task) != 1:
        raise ValueError("each worker must execute exactly one real benchmark task")
    if not math.isfinite(args.phase_timeout) or not 0 < args.phase_timeout <= 7200:
        raise ValueError("phase-timeout must be within (0,7200]")
    if args.output.exists():
        raise ValueError("worker output must be fresh")


def write_worker_result(args, hooks, terminal, error=None):
    """A reference score and pending capture status remain separate dimensions."""
    summary_path = args.output / "campaign-summary.json"
    rows = json.loads(summary_path.read_text()).get("tasks", []) if summary_path.exists() else []
    if rows and (len(rows) != 1 or rows[0].get("task") != args.task[0]):
        raise ValueError("single-worker campaign summary contains the wrong task")
    row = rows[0] if rows else {}
    directory = Path(row.get("timeline_directory", args.output / "timelines" / args.task[0]))
    relative = directory.resolve().relative_to(args.output.resolve())
    result = {"schema_version": 1, "benchmark": "Terminal-Bench", "job_id": args.job_id,
              "task_id": "terminal-bench/" + args.task[0], "mode": "ORACLE_REFERENCE",
              "agent_id": hooks.agent_id, "timeline_directory": str(relative),
              "official_passed": row.get("task_reward_passed") is True and not row.get("harbor_exception"),
              "official_result": {key: row.get(key) for key in ("harbor_rewards", "harbor_exception", "harbor_result")},
              "agent_return_ns": hooks.agent_return_ns, "quiescent_ns": hooks.quiescent_ns,
              "capture_status": row.get("timeline_acceptance", "INCOMPLETE"),
              "error": error}
    terminal.write_json(args.output / "worker-result.json", result)
    return result


async def run_worker(args, *, control=None, terminal=None, trial_class=None, trial_events=None, finder_factory=None):
    validate_options(args)
    if terminal is None:
        import terminal_validate as terminal
    if control is None:
        from phase_control import Control
        control = Control(args.control_dir, args.job_id, timeout=args.phase_timeout)
    if trial_class is None or trial_events is None:
        from harbor.trial.trial import Trial
        from harbor.trial.hooks import TrialEvent
        trial_class, trial_events = Trial, TrialEvent
    if finder_factory is None:
        bridge = terminal.load_bridge(args.bridge)
        finder_factory = lambda trial: bridge.TrialObserverBridge(
            trial=trial, options=SimpleNamespace(docker_timeout=30), task_label=args.task[0])
    # Deliberately no search-probe or model-agent path in this worker.
    args.search_probe = False
    hooks = WorkerHooks(job_id=args.job_id, task=args.task[0], control=control, terminal=terminal,
                        finder_factory=finder_factory)
    try:
        with hooks.install(trial_class, trial_events.AGENT_START, trial_events.AGENT_END):
            result = await terminal.campaign(args)
        worker_result = write_worker_result(args, hooks, terminal)
        if result or not hooks.ended or (hooks.start_hooks, hooks.end_hooks) != (1, 1):
            raise RuntimeError("worker did not complete one healthy reference trial; campaign code=" + str(result))
        if (not worker_result["official_passed"]
                or any(row.get("agent_id") != hooks.agent_id or not row.get("tool_call_id", "").startswith(args.job_id + "-exec-")
                       for row in hooks.adapter.manifest.get("tools", []))):
            raise RuntimeError("official reference failed or a tool was assigned to the wrong parallel worker")
        return 0
    except BaseException as error:
        hooks.abort(error)
        if args.output.is_dir() and not (args.output / "worker-result.json").exists():
            try:
                write_worker_result(args, hooks, terminal, type(error).__name__ + ": " + str(error))
            except Exception:
                pass  # The original error and durable control abort remain primary.
        raise


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--control-dir", type=Path, required=True)
    result.add_argument("--job-id", required=True)
    result.add_argument("--phase-timeout", type=float, default=1800.0)
    for name in ("collector", "object", "bridge", "selection", "tasks-dir", "prebuilt-images", "output"):
        result.add_argument("--" + name, type=Path, required=True)
    result.add_argument("--selection-sha256", required=True)
    result.add_argument("--task", action="append", required=True)
    result.add_argument("--docker-socket", default="/var/run/docker.sock")
    result.add_argument("--kernel-stacks", action="store_true")
    result.add_argument("--capture-only", action="store_true")
    result.add_argument("--ring-bytes", type=int, default=64 * 1024 * 1024)
    result.add_argument("--collector-cpus")
    result.add_argument("--replay", type=Path, default=Path(__file__).with_name("replay.py"))
    result.add_argument("--renderer", type=Path, default=Path(__file__).with_name("render.py"))
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return asyncio.run(run_worker(args))
    except Exception as error:
        print(json.dumps({"job_id": args.job_id, "status": "WORKER_FAILED", "agent_scope": ORACLE_SCOPE,
                          "error_type": type(error).__name__, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
