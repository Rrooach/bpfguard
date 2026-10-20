"""Parallel Terminal worker tests without Harbor, Docker, BPF, or model APIs."""
import asyncio
import functools
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load("tested_parallel_terminal", "parallel_terminal.py")
T = load("tested_base_terminal", "terminal_validate.py")


class FakeTrial:
    def __init__(self):
        self.hooks = {}
        self.agent_environment = SimpleNamespace(exec=None)

    def add_hook(self, event, callback):
        self.hooks[event] = callback


class FakeAdapter:
    def __init__(self, directory, target):
        self.directory, self.container_id = directory, target.container_id
        self.agent_id, self.tool_prefix = "OLD_EXPLICIT_AGENT", "exec"
        self.manifest = {"schema_version": 1, "run_id": "run-" + directory.parent.parent.name,
            "boot_id": "test-boot", "container_id": target.container_id,
            "cgroup_id": target.cgroup_id, "cgroup_root": str(target.cgroup_directory),
            "namespace": {"pid": 1, "mnt": 2}, "tools": [], "artifacts": {},
            "baseline_threads": [{"tid": 10, "start_ticks": 100, "clock_ticks": 100}]}

    def persist(self):
        path = self.directory / "manifest.json"
        T.write_json(path, self.manifest, replace=path.exists())

    async def __call__(self, command):
        self.manifest["tools"].append({"agent_id": self.agent_id,
            "tool_call_id": self.tool_prefix + "-0001", "command": command})
        self.persist()
        return SimpleNamespace(return_code=0)


class FakeFinder:
    def __init__(self, target, events):
        self.target, self.events, self.paused = target, events, False

    async def discover_target(self):
        self.events.append("discover")
        return self.target

    async def pause(self, target):
        if self.paused:
            raise RuntimeError("already paused")
        self.events.append("freeze")
        self.paused = True

    async def unpause(self, target):
        if not self.paused:
            raise RuntimeError("not paused")
        self.events.append("unfreeze")
        self.paused = False


class FakeControl:
    def __init__(self, finder, events, fail_ready=False, fail_done=False):
        self.finder, self.events = finder, events
        self.fail_ready, self.fail_done = fail_ready, fail_done
        self.failures = []
        self.ready_metadata = self.done_metadata = None
        self.release_observed_ns = None

    def fail(self, error):
        self.failures.append(str(error))

    async def ready(self, metadata):
        if not self.finder.paused:
            raise AssertionError("READY must be published while target is frozen")
        self.events.append("ready")
        self.ready_metadata = metadata
        if self.fail_ready:
            raise RuntimeError("controller aborted READY")
        self.release_observed_ns = 123
        return {"event": "RELEASE", "observed_ns": 123}

    async def done(self, metadata):
        if not self.finder.paused or metadata.get("quiescent") is not True:
            raise AssertionError("DONE requires confirmed frozen closure")
        self.events.append("done")
        self.done_metadata = metadata
        if self.fail_done:
            raise TimeoutError("controller aborted DONE")
        self.events.append("all-agents-done")
        return {"event": "ALL_AGENTS_DONE", "observed_ns": 456}


class ParallelTerminalTests(unittest.TestCase):
    def fixture(self, root, *, job="job-a", survivor=False, fail_ready=False, fail_done=False,
                wrong_identity=False, old_start_error=False, official_passed=True):
        events, output = [], Path(root) / job
        target = SimpleNamespace(container_id="container-" + job, cgroup_id=100,
                                 cgroup_directory=Path(root) / "cgroups" / job)
        finder = FakeFinder(target, events)
        control = FakeControl(finder, events, fail_ready, fail_done)
        state = SimpleNamespace()

        async def campaign(args):
            output.mkdir()
            directory = output / "timelines" / "bun-sourcemap-leak"
            directory.mkdir(parents=True)
            trial = FakeTrial()
            state.trial = trial

            async def start(event):
                events.append("old-start")
                if old_start_error:
                    raise RuntimeError("old adapter did not become READY")
                adapter = FakeAdapter(directory, target)
                if wrong_identity:
                    adapter.manifest["cgroup_id"] += 1
                state.adapter = adapter
                trial.agent_environment.exec = adapter
                adapter.persist()

            async def finish(event):
                if "all-agents-done" not in events or finder.paused:
                    raise AssertionError("STOP/projection cannot run before the all-done release")
                events.append("old-finish")

            trial.add_hook("start", start)
            trial.add_hook("end", finish)
            await trial.hooks["start"]("start-event")
            events.append("oracle")
            await trial.agent_environment.exec(command="real official command is supplied by Harbor")
            await trial.hooks["end"]("end-event")
            T.write_json(output / "campaign-summary.json", {"tasks": [{
                "task": "bun-sourcemap-leak", "timeline_directory": str(directory),
                "task_reward_passed": official_passed, "harbor_rewards": {"reward": int(official_passed)},
                "harbor_exception": None, "harbor_result": str(output / "official.json"),
                "timeline_acceptance": "PENDING_INDEPENDENT_REPLAY"}]})
            return 0 if official_passed else 1

        terminal = SimpleNamespace(__name__=__name__, GatedExec=FakeAdapter, campaign=campaign,
            write_json=T.write_json, sha256=T.sha256,
            frozen_baseline_threads=lambda path: ([{"tid": 10, "start_ticks": 100, "clock_ticks": 100}]
                + ([{"tid": 20, "start_ticks": 200, "clock_ticks": 100}] if survivor else [])))
        args = SimpleNamespace(job_id=job, task=["bun-sourcemap-leak"], phase_timeout=1800.0,
            output=output, control_dir=Path(root) / "control", search_probe=True)
        state.args, state.events, state.finder, state.control, state.terminal = args, events, finder, control, terminal
        state.execute = lambda: asyncio.run(M.run_worker(args, control=state.control, terminal=terminal,
            trial_class=FakeTrial, trial_events=SimpleNamespace(AGENT_START="start", AGENT_END="end"),
            finder_factory=lambda trial: finder))
        return state

    def test_public_hooks_preserve_order_and_bind_job_agent_and_tools(self):
        original = FakeTrial.add_hook
        with tempfile.TemporaryDirectory() as root:
            state = self.fixture(root)
            self.assertEqual(state.execute(), 0)
            self.assertEqual(state.events, ["old-start", "discover", "freeze", "ready", "unfreeze", "oracle",
                "freeze", "done", "all-agents-done", "unfreeze", "old-finish"])
            self.assertIs(FakeTrial.add_hook, original)
            self.assertFalse(state.args.search_probe)
            self.assertEqual(state.adapter.manifest["agent_id"], "official-oracle:job-a")
            tool = state.adapter.manifest["tools"][0]
            self.assertEqual(tool["agent_id"], "official-oracle:job-a")
            self.assertEqual(tool["tool_call_id"], "job-a-exec-0001")
            self.assertTrue(state.control.done_metadata["quiescent"])
            self.assertLessEqual(state.control.done_metadata["agent_return_ns"], state.control.done_metadata["quiescent_ns"])
            phase = state.adapter.directory / "parallel-phases.json"
            bound = state.adapter.manifest["artifacts"][phase.name]
            self.assertEqual(bound["sha256"], hashlib.sha256(phase.read_bytes()).hexdigest())
            result = json.loads((state.args.output / "worker-result.json").read_text())
            self.assertEqual(result["mode"], "ORACLE_REFERENCE")
            self.assertEqual(result["timeline_directory"], "timelines/bun-sourcemap-leak")
            self.assertTrue(result["official_passed"])
            self.assertEqual(result["capture_status"], "PENDING_INDEPENDENT_REPLAY")

    def test_independent_worker_directories_and_ids_do_not_collide(self):
        with tempfile.TemporaryDirectory() as root:
            first, second = self.fixture(root, job="job-1"), self.fixture(root, job="job-2")
            first.execute()
            second.execute()
            self.assertNotEqual(first.adapter.directory, second.adapter.directory)
            self.assertNotEqual(first.adapter.container_id, second.adapter.container_id)
            self.assertNotEqual(first.adapter.manifest["tools"][0]["agent_id"], second.adapter.manifest["tools"][0]["agent_id"])
            self.assertNotEqual(first.adapter.manifest["tools"][0]["tool_call_id"], second.adapter.manifest["tools"][0]["tool_call_id"])

    def test_background_survivor_aborts_without_publishing_done(self):
        with tempfile.TemporaryDirectory() as root:
            state = self.fixture(root, survivor=True)
            with self.assertRaisesRegex(RuntimeError, "NONBASELINE_THREADS"):
                state.execute()
            self.assertTrue(state.control.failures)
            self.assertIsNone(state.control.done_metadata)
            self.assertNotIn("old-finish", state.events)
            self.assertFalse(state.finder.paused)
            result = json.loads((state.args.output / "worker-result.json").read_text())
            self.assertFalse(result["official_passed"])
            self.assertEqual(result["capture_status"], "INCOMPLETE")

    def test_abort_at_ready_and_done_unfreezes_target_and_restores_hooks(self):
        original = FakeTrial.add_hook
        for where in ("fail_ready", "fail_done"):
            with self.subTest(where=where), tempfile.TemporaryDirectory() as root:
                state = self.fixture(root, **{where: True})
                with self.assertRaises((RuntimeError, TimeoutError)):
                    state.execute()
                self.assertFalse(state.finder.paused)
                self.assertTrue(state.control.failures)
                self.assertNotIn("old-finish", state.events)
                self.assertIs(FakeTrial.add_hook, original)

    def test_changed_container_identity_and_original_start_failure_abort(self):
        for defect in ("wrong_identity", "old_start_error"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as root:
                state = self.fixture(root, **{defect: True})
                with self.assertRaises(RuntimeError):
                    state.execute()
                self.assertIsNone(state.control.ready_metadata)
                self.assertIsNone(state.control.done_metadata)
                self.assertTrue(state.control.failures)

    def test_failed_official_score_is_retained_and_worker_fails(self):
        with tempfile.TemporaryDirectory() as root:
            state = self.fixture(root, official_passed=False)
            with self.assertRaisesRegex(RuntimeError, "healthy reference trial"):
                state.execute()
            result = json.loads((state.args.output / "worker-result.json").read_text())
            self.assertFalse(result["official_passed"])
            self.assertEqual(result["official_result"]["harbor_rewards"], {"reward": 0})
            self.assertTrue(state.control.failures)

    def test_exactly_one_real_task_and_fresh_safe_worker_are_required(self):
        with tempfile.TemporaryDirectory() as root:
            state = self.fixture(root)
            for tasks in ([], ["one", "two"]):
                state.args.task = tasks
                with self.assertRaisesRegex(ValueError, "exactly one"):
                    M.validate_options(state.args)
            state.args.task = ["bun-sourcemap-leak"]
            for job in ("../escape", "a/b", "", "x" * 65):
                state.args.job_id = job
                with self.assertRaisesRegex(ValueError, "job-id"):
                    M.validate_options(state.args)
            state.args.job_id = "safe"
            for timeout in (0, -1, 7201, float("nan")):
                state.args.phase_timeout = timeout
                with self.assertRaisesRegex(ValueError, "phase-timeout"):
                    M.validate_options(state.args)
            state.args.phase_timeout = 1800
            state.args.output.mkdir()
            with self.assertRaisesRegex(ValueError, "fresh"):
                M.validate_options(state.args)

    def test_real_file_barriers_do_not_allow_early_postprocessing(self):
        phase = load("tested_worker_phase_control", "phase_control.py")
        with tempfile.TemporaryDirectory() as root:
            state = self.fixture(root)
            control_root = Path(root) / "control"
            job = control_root / state.args.job_id
            job.mkdir(parents=True)
            state.control = phase.Control(control_root, state.args.job_id, timeout=3)
            parent_errors = []

            def wait(path):
                deadline = time.monotonic() + 3
                while not path.exists():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("test parent did not observe " + path.name)
                    time.sleep(0.002)
                return phase.read_record(path)

            def parent():
                try:
                    ready = wait(job / "ready.json")
                    self.assertEqual(ready["metadata"]["agent_id"], "official-oracle:job-a")
                    self.assertTrue(state.finder.paused)
                    self.assertNotIn("oracle", state.events)
                    phase.publish(job / "release.json", {"schema_version": 1, "event": "RELEASE",
                        "job_id": state.args.job_id, "monotonic_ns": time.monotonic_ns()})
                    done = wait(job / "agent-done.json")
                    self.assertTrue(done["metadata"]["quiescent"])
                    self.assertTrue(state.finder.paused)
                    self.assertNotIn("old-finish", state.events)
                    self.assertFalse((state.adapter.directory / "parallel-phases.json").exists())
                    state.events.append("all-agents-done")
                    phase.publish(control_root / "all-agents-done.json", {"schema_version": 1,
                        "event": "ALL_AGENTS_DONE", "monotonic_ns": time.monotonic_ns()})
                except BaseException as error:
                    parent_errors.append(error)
                    state.control.fail(error)

            async def offload(function, *args, **kwargs):
                return await asyncio.get_running_loop().run_in_executor(None, functools.partial(function, *args, **kwargs))

            parent_thread = threading.Thread(target=parent)
            parent_thread.start()
            # The IPC records are real; resources are an explicitly labeled
            # fixture, never readings of or writes to the Host's cgroups.
            with patch.object(phase.asyncio, "to_thread", side_effect=offload, create=True), \
                    patch.object(phase, "cgroup_snapshot", return_value={"status": "UNIT_FIXTURE_NOT_REAL_RESOURCES"}):
                try:
                    self.assertEqual(state.execute(), 0)
                finally:
                    parent_thread.join(4)
            self.assertFalse(parent_thread.is_alive())
            self.assertEqual(parent_errors, [])
            self.assertIsNotNone(state.control.release_observed_ns)
            self.assertLess(state.events.index("all-agents-done"), state.events.index("old-finish"))

    def test_changed_adapter_hook_abi_is_rejected_before_any_ungated_work(self):
        with tempfile.TemporaryDirectory() as root:
            state = self.fixture(root)
            hooks = M.WorkerHooks(job_id="job-a", task="bun-sourcemap-leak", control=state.control,
                terminal=state.terminal, finder_factory=lambda trial: state.finder)

            async def unexpectedly_renamed_hook(event):
                raise AssertionError("must never run")

            original = FakeTrial.add_hook
            with hooks.install(FakeTrial, "start", "end"):
                with self.assertRaisesRegex(RuntimeError, "refusing ungated"):
                    FakeTrial().add_hook("start", unexpectedly_renamed_hook)
            self.assertIs(FakeTrial.add_hook, original)


if __name__ == "__main__":
    unittest.main()
