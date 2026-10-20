"""Terminal adapter contracts without Docker, Harbor, BPF, or paid API calls."""
import asyncio
import copy
import importlib.util
import functools
import json
import signal
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("tested_timeline_terminal", Path(__file__).with_name("terminal_validate.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def frame(stream, data):
    return bytes([stream, 0, 0, 0]) + struct.pack(">I", len(data)) + data


class FakeDocker:
    def __init__(self):
        self.released = threading.Event()
        self.started = False
        self.finished = False
        self.created = None

    def request(self, method, path, data=None, **kwargs):
        if path.endswith("/exec"):
            self.created = data
            return {"Id": "a" * 64}
        if path.endswith("/start"):
            self.started = True
            if not self.released.wait(2):
                raise TimeoutError("test gate not released")
            self.finished = True
            return frame(1, b"hello\n") + frame(2, b"warning\n")
        if path.endswith("/json"):
            return {"Pid": 123 if self.started else 0, "Running": not self.finished, "ExitCode": 0}
        raise AssertionError(path)


class TerminalAdapterTests(unittest.TestCase):
    def test_stat_comm_parentheses_do_not_shift_birth(self):
        fields = ["T", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "9876", "20"]
        value = M.parse_stat("123 (strange (comm) suffix) " + " ".join(fields))
        self.assertEqual(value, {"tid": 123, "state": "T", "start_ticks": 9876})

    def test_demux_and_reject_truncated_or_unknown_stream(self):
        self.assertEqual(M.demultiplex(frame(1, b"a") + frame(2, b"b") + frame(1, b"c")), ("ac", "b"))
        for raw in (b"x", frame(1, b"abc")[:-1], frame(3, b"abc"), b"\1\1\0\0\0\0\0\0"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                M.demultiplex(raw)

    def test_unified_cgroup_required(self):
        self.assertEqual(M.parse_cgroup("1:cpu:/ignored\n0::/docker/x\n"), "/docker/x")
        for raw in ("", "0::relative", "0::/a/../b", "0::/x\n0::/y"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                M.parse_cgroup(raw)

    def test_manifest_updates_are_atomic_and_initial_write_is_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.json"
            M.write_json(path, {"v": 1})
            with self.assertRaises(FileExistsError):
                M.write_json(path, {"v": 2})
            M.write_json(path, {"v": 3}, replace=True)
            self.assertEqual(json.loads(path.read_text()), {"v": 3})
            self.assertEqual(list(Path(tmp).iterdir()), [path])

    def test_baseline_is_enrolled_only_while_frozen_and_membership_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "docker" / "x"
            root.mkdir(parents=True)
            (root / "cgroup.events").write_text("populated 1\nfrozen 0\n")
            (root / "cgroup.threads").write_text("123\n")
            with self.assertRaisesRegex(ValueError, "frozen"):
                M.frozen_baseline_threads(root, tmp)
            (root / "cgroup.events").write_text("populated 1\nfrozen 1\n")
            with patch.object(M, "proc_identity", return_value={"tid": 123, "start_ticks": 9876}), \
                    patch.object(M, "proc_cgroup", return_value="/docker/x"):
                baseline = M.frozen_baseline_threads(root, tmp)
            self.assertEqual(baseline[0]["tid"], 123)
            self.assertEqual(baseline[0]["start_ticks"], 9876)
            self.assertEqual(baseline[0]["cgroup_id"], root.stat().st_ino)
            with patch.object(M, "proc_identity", return_value={"tid": 123, "start_ticks": 9876}), \
                    patch.object(M, "proc_cgroup", return_value="/docker/not-the-same"):
                with self.assertRaisesRegex(ValueError, "changed"):
                    M.frozen_baseline_threads(root, tmp)

    def run_gate(self, directory, *, cgroup="/docker/x", identities=None, command="echo hello", environment=None):
        docker = FakeDocker()
        manifest = {"agent_id": "oracle:test", "task_id": "terminal-bench/test", "tools": []}
        adapter = M.GatedExec(docker, "b" * 64, "/docker/x", manifest, directory, environment=environment)
        identity = {"tid": 123, "state": "T", "start_ticks": 9876}
        calls = []
        self.last_gate_signals = calls

        def send(fd, sig):
            calls.append((fd, sig))
            if sig == signal.SIGCONT:
                # The application start and root identity must be persisted
                # before releasing the first instruction of the tool shell.
                retained = json.loads((Path(directory) / "manifest.json").read_text())
                self.assertEqual(retained["tools"][0]["root"]["tid"], 123)
                self.assertIsNone(retained["tools"][0]["begin_ns"], "enrollment fsync must precede the measured begin")
                self.assertIsNone(retained["tools"][0]["end_ns"])
            docker.released.set()

        async def offload(function, *args, **kwargs):
            return await asyncio.get_running_loop().run_in_executor(None, functools.partial(function, *args, **kwargs))

        with patch.object(M, "proc_identity", side_effect=identities or (lambda pid: identity)), \
                patch.object(M, "proc_cgroup", return_value=cgroup), \
                patch.object(M, "cgroup_inode", return_value=456), \
                patch.object(M, "proc_affinity", return_value=[0, 1]), \
                patch.object(M.os, "pidfd_open", return_value=777, create=True), \
                patch.object(M.os, "close"), \
                patch.object(M.signal, "pidfd_send_signal", side_effect=send, create=True), \
                patch.object(M.asyncio, "to_thread", side_effect=offload, create=True):
            value = asyncio.run(adapter(command=command, user="root", timeout_sec=3, env={"X": "x"}))
        return value, manifest, calls, docker

    def test_actual_root_is_bound_before_release_and_not_docker_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            value, manifest, calls, docker = self.run_gate(Path(tmp))
            self.assertEqual(value.return_code, 0)
            self.assertEqual(value.stdout, "hello\n")
            self.assertEqual(value.stderr, "warning\n")
            self.assertEqual(calls, [(777, signal.SIGCONT)])
            entry = manifest["tools"][0]
            self.assertEqual(entry["cgroup_id"], 456)
            self.assertLess(entry["begin_ns"], entry["end_ns"])
            self.assertEqual(docker.created["User"], "root")
            self.assertEqual(docker.created["Cmd"][0], "/bin/sh", "outer gate must not source BASH_ENV before STOP")
            rows = [json.loads(line) for line in (Path(tmp) / "tool-spans.jsonl").read_text().splitlines()]
            self.assertEqual([row["event"] for row in rows], ["TOOL_ENROLLED", "TOOL_START", "TOOL_END"])
            self.assertIsNone(rows[0]["begin_ns"])
            self.assertLessEqual(rows[0]["enrolled_ns"], rows[1]["begin_ns"])
            self.assertEqual(rows[2]["result"]["return_code"], 0)

    def test_cgroup_prefix_lookalike_is_rejected_without_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "outside"):
                self.run_gate(Path(tmp), cgroup="/docker/x-lookalike")

    def test_reused_pid_identity_is_rejected(self):
        initial = {"tid": 123, "state": "T", "start_ticks": 9876}
        changed = dict(initial, start_ticks=9877)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "identity changed"):
                self.run_gate(Path(tmp), identities=[initial, changed])
            self.assertEqual(self.last_gate_signals, [], "a reused PID must never receive even cleanup SIGKILL")

    def test_harbor_scoped_env_user_workdir_and_shell_are_preserved(self):
        environment = SimpleNamespace(task_env_config=SimpleNamespace(workdir="/app"),
            _merge_env=lambda env: {**env, "X": "scoped", "PERSISTENT": "yes"},
            _resolve_user=lambda user: user,
            _platform=SimpleNamespace(exec_shell_args=lambda command: ["bash", "-lc", command]))
        with tempfile.TemporaryDirectory() as tmp:
            _, _, _, docker = self.run_gate(Path(tmp), environment=environment, command="printf 'x y'")
            self.assertEqual(docker.created["WorkingDir"], "/app")
            self.assertEqual(docker.created["Env"], ["PERSISTENT=yes", "X=scoped"])
            self.assertIn("exec bash -lc", docker.created["Cmd"][-1])

    def assessment_fixture(self):
        tool = {"tool_call_id": "probe-1", "agent_id": "calibration-1", "task_id": "terminal-bench/bun",
                "root": {"tid": 123, "start_ticks": 9876, "clock_ticks": 100},
                "tool_kind": "LABELED_READONLY_SEARCH_CALIBRATION", "command": M.SEARCH_PROBE_COMMAND}
        manifest = {"tools": [tool], "end_ns": 1000,
                    "closure": {"frozen": True, "nonbaseline_thread_candidates": []}}
        report = {"health": {"status": "COMPLETE_FOR_SELECTED_HOOKS"}, "findings": [],
                  "tools": [{**copy.deepcopy(tool), "association": "RUNTIME_GATE_AND_KERNEL_LIFETIME", "root_key": "root"}],
                  "threads": [{"tool_call_id": "probe-1", "agent_id": "calibration-1", "task_id": "terminal-bench/bun",
                      "comm": "bash", "key": "root", "exit_ns": 900, "terminal_switch_ns": 950, "calls": [{"files": [{
                      "path": "/app/src/a.ts", "mount_id": 1, "device": 2, "inode": 3, "generation": 0,
                      "read": {"returned_bytes": 100, "requested_bytes": 4096}}]}]}],
                  "critical_path": {"status": "RECONSTRUCTED_WITHIN_SELECTED_MODEL", "tools": [{
                      "tool_call_id": "probe-1", "status": "RECONSTRUCTED_WITHIN_SELECTED_MODEL", "unknown_ns": 0,
                      "wall_ns": 800, "state_totals_ns": {"ONCPU": 500, "SLEEP": 300},
                      "dependency_edges": [{"basis": basis} for basis in (
                          "BACKWARD_WAIT4_RESULT_AND_KERNEL_WAKER_AND_CHILD_EXIT", "KERNEL_FORK_ORIGIN_PREFIX")
                          for _ in range(M.SEARCH_PROBE_QUERIES)]}]}}
        report["threads"].extend({"tool_call_id": "probe-1", "agent_id": "calibration-1", "task_id": "terminal-bench/bun",
                                  "comm": "grep", "parent_key": "root", "key": "child-" + str(number),
                                  "exit_ns": 900, "terminal_switch_ns": 950, "calls": []}
                                 for number in range(M.SEARCH_PROBE_QUERIES))
        return report, manifest

    def test_goal_assessment_requires_more_than_decodable_evidence_or_reward(self):
        report, manifest = self.assessment_fixture()
        result = M.assess_timeline(report, manifest)
        self.assertEqual(result["status"], "PASS_WITHIN_SELECTED_MODEL")
        self.assertEqual(result["tools"][0]["source_returned_bytes"], 100)
        self.assertEqual(result["tools"][0]["source_unique_files_read"], 1)
        report["critical_path"]["status"] = "INCOMPLETE"
        self.assertEqual(M.assess_timeline(report, manifest)["status"], "FAIL")

    def test_goal_assessment_rejects_missing_exits_or_namespace_dependencies(self):
        report, manifest = self.assessment_fixture()
        report["threads"][0]["exit_ns"] = None
        report["critical_path"]["tools"][0]["dependency_edges"] = []
        result = M.assess_timeline(report, manifest)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("TOOL_DESCENDANT_EXIT_NOT_OBSERVED:probe-1", result["issues"])
        self.assertIn("CONTAINER_SEARCH_WAIT_DEPENDENCY_NOT_ESTABLISHED:probe-1", result["issues"])

    def test_goal_assessment_rejects_zero_source_bytes_and_surviving_thread(self):
        report, manifest = self.assessment_fixture()
        report["threads"][0]["calls"][0]["files"][0]["read"]["returned_bytes"] = 0
        manifest["closure"]["nonbaseline_thread_candidates"] = [{"tid": 456}]
        result = M.assess_timeline(report, manifest)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("TASK_SOURCE_FILE_READ_NOT_RESOLVED:probe-1", result["issues"])
        self.assertIn("FROZEN_TOOL_TREE_CLOSURE_NOT_ESTABLISHED", result["issues"])

    def test_exit_hook_does_not_replace_observed_terminal_switch(self):
        report, manifest = self.assessment_fixture()
        for value in (None, 899, 1001):
            with self.subTest(terminal_switch_ns=value):
                report["threads"][0]["terminal_switch_ns"] = value
                result = M.assess_timeline(report, manifest)
                self.assertEqual(result["status"], "FAIL")
                self.assertIn("TOOL_DESCENDANT_TERMINAL_SWITCH_NOT_OBSERVED:probe-1", result["issues"])

    def test_search_workload_requires_all_queries_and_ownership(self):
        for defect in ("missing-child", "wrong-agent", "missing-edge"):
            with self.subTest(defect=defect):
                report, manifest = self.assessment_fixture()
                if defect == "missing-child":
                    report["threads"].pop()
                elif defect == "wrong-agent":
                    report["threads"][-1]["agent_id"] = "not-the-declared-agent"
                else:
                    report["critical_path"]["tools"][0]["dependency_edges"].pop()
                result = M.assess_timeline(report, manifest)
                self.assertEqual(result["status"], "FAIL")
                self.assertIn("CONCURRENT_SEARCH_WORKLOAD_LINEAGE_NOT_FULLY_RECONSTRUCTED:probe-1", result["issues"])


if __name__ == "__main__":
    unittest.main()
