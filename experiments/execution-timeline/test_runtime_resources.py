#!/usr/bin/env python3
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from runtime_resources import RuntimeResourceSampler, _stat_fields, capture_process, summarize_samples


class ResourceSamplingTests(unittest.TestCase):
    def test_proc_stat_comm_and_pid_identity(self):
        # Fields after comm begin with state (field 3).
        fields = ["S"] + ["0"] * 21
        for index, value in ((7, "17"), (9, "2"), (11, "3"), (12, "4"),
                             (17, "2"), (19, "987"), (21, "100")):
            fields[index] = value
        raw = "123 (name with ) parens) " + " ".join(fields)
        self.assertEqual(_stat_fields(raw)["start_ticks"], 987)
        with tempfile.TemporaryDirectory() as temp:
            process = Path(temp) / "123"
            process.mkdir()
            (process / "stat").write_text(raw)
            (process / "status").write_text("VmRSS:\t40 kB\nRssAnon:\t20 kB\nVmHWM:\t60 kB\n")
            good = capture_process(123, 987, Path(temp))
            self.assertEqual(good["values"]["rss_bytes"], 40960)
            self.assertEqual(good["values"]["minor_faults"], 17)
            bad = capture_process(123, 986, Path(temp))
            self.assertEqual(bad["status"], "PID_IDENTITY_CHANGED")
            self.assertEqual(bad["values"], {})

    def test_shared_cgroup_retains_scope_and_counter_regression_is_unknown(self):
        target = {"name": "tool", "pid": 1, "cgroup_scope": "SHARED_CONTAINER_CGROUP"}
        records = []
        for index, faults in enumerate((9, 4)):
            records.append({"event": "RESOURCE_SAMPLE", "target": target,
                "begin_ns": index + 1, "end_ns": index + 2,
                "process": {"status": "OBSERVED", "values": {"minor_faults": faults,
                    "rss_bytes": 100 + index}}, "cgroup": {"values": {"memory.current": 1000}}})
        result = summarize_samples(records)["targets"][0]
        self.assertIsNone(result["minor_faults"])
        self.assertEqual(result["target"]["cgroup_scope"], "SHARED_CONTAINER_CGROUP")
        self.assertEqual(result["sampled_rss_peak_bytes"], 101)
        self.assertEqual(result["sampled_cgroup_memory_peak_bytes"], 1000)
        self.assertEqual(result["coverage"], "SAMPLED_NOT_EXHAUSTIVE")

    @unittest.skipUnless(Path("/proc/self/stat").exists(), "Linux /proc required")
    def test_real_cooperative_process_memory_and_bounded_artifacts(self):
        command = [sys.executable, "-c", "import sys; data=bytearray(16*1024*1024); print('READY',flush=True); sys.stdin.read()"]
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "READY")
            with tempfile.TemporaryDirectory() as temp:
                sampler = RuntimeResourceSampler(temp, interval_ms=50, max_samples=4)
                sampler.register("runtime", pid=child.pid, role="AGENT_RUNTIME")
                sampler.start()
                time.sleep(.18)
                sampler.finish("runtime")
                summary = sampler.stop()
                self.assertEqual(sampler.stop(), summary)
                target = summary["targets"][0]
                self.assertGreaterEqual(target["sampled_rss_peak_bytes"], 16 * 1024 * 1024)
                self.assertGreaterEqual(target["process_sample_count"], 2)
                self.assertLessEqual(summary["sample_count"], 4)
                self.assertTrue(summary["sample_limit_reached"])
                samples = [json.loads(line) for line in (Path(temp) / "resource-samples.jsonl").read_text().splitlines()]
                self.assertTrue(all(row["boot_id"] == summary["boot_id"] for row in samples))
                self.assertEqual(json.loads((Path(temp) / "resource-summary.json").read_text()), summary)
        finally:
            child.communicate(timeout=5)

    def test_exited_identity_never_becomes_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            sampler = RuntimeResourceSampler(temp)
            sampler.register("already-exited", pid=2_147_483_647, role="TOOL_PROCESS")
            summary = sampler.stop()
            item = summary["targets"][0]
            self.assertEqual(item["process_sample_count"], 0)
            self.assertIsNone(item["sampled_rss_peak_bytes"])
            self.assertEqual(summary["status"], "SAMPLED_NOT_EXHAUSTIVE")
            self.assertEqual(item["lifecycle"]["status"], "EXIT_UNCONFIRMED_PROCESS_UNAVAILABLE")
            self.assertFalse(item["lifecycle"]["confirmed_exit"])

    def test_pid_anon_file_are_not_reported_as_cgroup_page_cache(self):
        target = {"name": "pid", "pid": 1, "start_ticks": 2, "cgroup": None}
        records = [{"event": "RESOURCE_SAMPLE", "target": target, "begin_ns": 1,
            "end_ns": 2, "process": {"status": "OBSERVED", "values": {
                "rss_bytes": 100, "rss_anon_bytes": 60, "rss_file_bytes": 30,
                "rss_shmem_bytes": 10}}}]
        item = summarize_samples(records)["targets"][0]
        self.assertEqual(item["sampled_process_rss_anon_peak_bytes"], 60)
        self.assertEqual(item["sampled_process_rss_file_peak_bytes"], 30)
        self.assertEqual(item["sampled_process_rss_shmem_peak_bytes"], 10)
        self.assertIsNone(item["sampled_cgroup_file_peak_bytes"])
        self.assertIn("NOT_CGROUP_PAGE_CACHE", item["memory_metrics"]["process_rss_file"]["scope"])
        self.assertEqual(item["memory_metrics"]["cgroup_file"]["reason"], "CGROUP_NOT_REGISTERED_FOR_TARGET")
        self.assertEqual(item["lifecycle"]["status"], "END_NOT_RECORDED")

    def test_unavailable_cgroup_memory_preserves_controller_error(self):
        target = {"name": "cg", "pid": None, "cgroup": "/sys/fs/cgroup/test",
                  "cgroup_scope": "PRIVATE_TOOL_CGROUP"}
        records = [{"event": "RESOURCE_SAMPLE", "target": target, "begin_ns": 1,
            "end_ns": 2, "cgroup": {"status": "PARTIAL", "values": {},
                "errors": {"memory.current": "PermissionError: denied"}}}]
        item = summarize_samples(records)["targets"][0]
        self.assertEqual(item["collection_errors"]["cgroup:memory.current"], "PermissionError: denied")
        self.assertIn("CONTROLLER_OR_FILE_UNAVAILABLE", item["memory_metrics"]["cgroup_memory"]["reason"])
        self.assertEqual(item["memory_metrics"]["cgroup_memory"]["scope"], "PRIVATE_TOOL_CGROUP")

    def test_identity_change_retains_earlier_peak_but_does_not_mark_complete(self):
        target = {"name": "pid", "pid": 1, "start_ticks": 2, "cgroup": "/cg"}
        records = [{"event": "RESOURCE_SAMPLE", "target": target, "begin_ns": 1,
            "end_ns": 2, "process": {"status": "OBSERVED", "values": {"rss_bytes": 100}},
            "cgroup": {"status": "COMPLETE", "values": {"memory.current": 200}}},
            {"event": "RESOURCE_SAMPLE", "target": target, "begin_ns": 3, "end_ns": 4,
            "process": {"status": "PID_IDENTITY_CHANGED", "values": {}},
            "cgroup": {"status": "CGROUP_IDENTITY_CHANGED", "values": {}}}]
        item = summarize_samples(records)["targets"][0]
        self.assertEqual(item["sampled_rss_peak_bytes"], 100)
        self.assertEqual(item["memory_metrics"]["process_rss"]["status"], "IDENTITY_CHANGED_PARTIAL")
        self.assertEqual(item["memory_metrics"]["cgroup_memory"]["status"], "IDENTITY_CHANGED_PARTIAL")

    def test_live_process_end_is_not_an_exit_or_a_zero_sample(self):
        with tempfile.TemporaryDirectory() as temp:
            sampler = RuntimeResourceSampler(temp)
            sampler.register("self", pid=os.getpid())
            sampler.finish("self", reason="TASK_WINDOW_CLOSED_RUNTIME_STILL_ALIVE")
            item = sampler.stop()["targets"][0]
            self.assertEqual(item["lifecycle"]["status"], "PID_STILL_PRESENT_AT_OBSERVATION_END")
            self.assertFalse(item["lifecycle"]["confirmed_exit"])
            self.assertEqual(item["lifecycle"]["reason"], "TASK_WINDOW_CLOSED_RUNTIME_STILL_ALIVE")
            rows = [json.loads(line) for line in (Path(temp) / "resource-samples.jsonl").read_text().splitlines()]
            self.assertEqual(sum(row["event"] == "RESOURCE_TARGET_FINISHED" for row in rows), 1)
            self.assertTrue(all(row.get("process", {}).get("values", {}).get("rss_bytes", 1) > 0 for row in rows))

    def test_real_wait_confirmation_retains_returncode_without_fake_zero(self):
        child = subprocess.Popen([sys.executable, "-c", "import sys; print('READY',flush=True); sys.stdin.read(); sys.exit(7)"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "READY")
            with tempfile.TemporaryDirectory() as temp:
                sampler = RuntimeResourceSampler(temp)
                sampler.register("child", pid=child.pid)
                child.communicate(timeout=5)
                sampler.finish("child", reason="TOOL_WAIT_COMPLETED", confirmed_exit=child.returncode,
                               exit_source="SUBPROCESS_WAIT")
                item = sampler.stop()["targets"][0]
                self.assertEqual(item["lifecycle"]["status"], "EXIT_CONFIRMED")
                self.assertTrue(item["lifecycle"]["confirmed_exit"])
                self.assertEqual(item["lifecycle"]["exit_returncode"], 7)
                self.assertEqual(item["lifecycle"]["exit_source"], "SUBPROCESS_WAIT")
                self.assertGreater(item["sampled_rss_peak_bytes"], 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux pidfd required")
    def test_pidfd_confirms_exit_even_without_caller_returncode(self):
        child = subprocess.Popen([sys.executable, "-c", "import sys; print('READY',flush=True); sys.stdin.read()"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "READY")
            with tempfile.TemporaryDirectory() as temp:
                sampler = RuntimeResourceSampler(temp, max_samples=1)
                sampler.register("child", pid=child.pid)
                child.communicate(timeout=5)
                sampler.finish("child")
                summary = sampler.stop()
                item = summary["targets"][0]
                self.assertTrue(item["lifecycle"]["confirmed_exit"])
                self.assertEqual(item["lifecycle"]["exit_source"], "IDENTITY_BOUND_PIDFD_READABLE")
                self.assertTrue(summary["sample_limit_reached"])
                self.assertEqual(summary["collection_warnings"][0]["event"], "RESOURCE_SAMPLING_LIMIT_REACHED")
                self.assertEqual(item["sample_count"], 1)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux pidfd required")
    def test_false_exit_claim_for_live_pid_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            sampler = RuntimeResourceSampler(temp)
            sampler.register("self", pid=os.getpid())
            try:
                with self.assertRaisesRegex(ValueError, "still-live"):
                    sampler.finish("self", confirmed_exit=0, exit_source="SUBPROCESS_WAIT")
            finally:
                sampler.stop()

    def test_proc_failure_without_pidfd_does_not_prove_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch("runtime_resources.os.pidfd_open", side_effect=PermissionError, create=True):
                sampler = RuntimeResourceSampler(temp)
                sampler.register("self", pid=os.getpid())
            unavailable = {"status": "PROCESS_UNAVAILABLE", "values": {}, "error": "PermissionError"}
            with mock.patch("runtime_resources.capture_process", return_value=unavailable):
                sampler.finish("self")
            item = sampler.stop()["targets"][0]
            self.assertFalse(item["lifecycle"]["confirmed_exit"])
            self.assertEqual(item["lifecycle"]["status"], "EXIT_UNCONFIRMED_PROCESS_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
