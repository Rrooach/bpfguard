import json
import tempfile
import unittest
from pathlib import Path

from analyze import interval, load_health, resource_windows, thread_associations


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "load-samples.jsonl"
        self.groups = {"agent-A": {"path": "/sys/fs/cgroup/test", "inode": 9, "device": 28}}
        self.meta = {"boot_id": "boot", "cgroups": [{**self.groups["agent-A"],
            "available": {"cpu.stat": True, "memory.stat": True, "io.stat": True, "pressure": True}}], "kernel_hist": None}
        self.stats = {key: 0 for key in ("read_errors", "missed_ticks", "truncated_process_sets",
                                        "truncated_cgroup_traversals", "cgroup_traversal_read_errors")}
        self.rows = [{"seq": index, "monotonic_ns": stamp, "collection_end_ns": stamp + 1,
            "psi": {name: {"some_total_us": index} for name in ("cpu", "memory", "io")},
            "cgroups": [{"present": True, "cpu_stat": {"usage_usec": index * 10, "throttled_usec": 0},
                "memory_stat": {"pgfault": index, "pgmajfault": 0}, "memory_events": {"oom": 0},
                "memory_current": 1000, "io_stat_by_device": {},
                "psi": {name: {"some_total_us": index} for name in ("cpu", "memory", "io")}}]}
            for index, stamp in enumerate((10, 60, 110))]
        self.write()

    def tearDown(self):
        self.temp.cleanup()

    def write(self):
        self.path.write_text("".join(json.dumps(row) + "\n" for row in self.rows))
        (self.root / "load-meta.json").write_text(json.dumps(self.meta))
        (self.root / "load-sampler-stats.json").write_text(json.dumps(self.stats))

    def test_health_not_inferred_only_from_sequence_and_brackets(self):
        self.assertEqual(load_health(self.path, 20, 100, self.groups, "boot")["status"], "COMPLETE")
        self.stats["read_errors"] = 1
        self.write()
        self.assertEqual(load_health(self.path, 20, 100, self.groups, "boot")["status"], "INCOMPLETE")
        self.stats["read_errors"] = 0
        del self.rows[1]["cgroups"][0]["psi"]["memory"]
        self.write()
        self.assertEqual(load_health(self.path, 20, 100, self.groups, "boot")["status"], "INCOMPLETE")

    def test_identity_counter_regression_and_boot_rejected(self):
        self.meta["cgroups"][0]["inode"] = 999
        self.rows[2]["cgroups"][0]["cpu_stat"]["usage_usec"] = 0
        self.write()
        result = load_health(self.path, 20, 100, self.groups, "wrong")
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIn("sampler_group_identity_mismatch", result["errors"])
        self.assertIn("counter_regression:cpu_stat.usage_usec", result["errors"])

    def test_phase_resource_resolution_and_non_additive_psi(self):
        result = resource_windows(self.path, [("SEARCH", 20, 100, {})], self.groups)
        window = result["windows"][0]
        self.assertEqual(window["before_uncertainty_ns"], 10)
        self.assertEqual(window["after_uncertainty_ns"], 10)
        self.assertTrue(window["not_additive_between_phases"])
        self.assertEqual(window["domains"]["agent-A"]["cpu_usage_usec"], 20)
        self.assertEqual(set(window["domains"]["agent-A"]["psi_delta_us_by_resource_not_additive"]), {"cpu", "memory", "io"})
        self.assertEqual(result["quality_status"], "COMPLETE")

    def phase_domain(self):
        result = resource_windows(self.path, [("SEARCH", 20, 100, {})], self.groups)
        return result, result["windows"][0]["domains"]["agent-A"]

    def test_new_io_device_is_unknown_not_zero_baseline(self):
        self.rows[-1]["cgroups"][0]["io_stat_by_device"] = {"8:0": {"rbytes": 4096, "rios": 1}}
        self.write()
        result, domain = self.phase_domain()
        self.assertEqual(domain["io_by_device"]["8:0"], {"rbytes": None, "rios": None})
        self.assertEqual(domain["counter_status"], "INCOMPLETE")
        self.assertEqual(result["quality_status"], "INCOMPLETE")
        health = load_health(self.path, 20, 100, self.groups, "boot")
        self.assertEqual(health["status"], "INCOMPLETE")
        self.assertIn("counter_missing_or_invalid:io_stat_by_device.8:0.rbytes", health["errors"])

    def test_disappeared_io_device_is_retained_as_unknown(self):
        self.rows[0]["cgroups"][0]["io_stat_by_device"] = {"8:0": {"rbytes": 4096}}
        self.write()
        result, domain = self.phase_domain()
        self.assertEqual(domain["io_by_device"]["8:0"]["rbytes"], None)
        self.assertEqual(result["quality_status"], "INCOMPLETE")
        self.assertEqual(load_health(self.path, 20, 100, self.groups)["status"], "INCOMPLETE")

    def test_device_io_field_missing_invalid_or_regressed_is_unknown(self):
        for current in ({}, {"rbytes": None}, {"rbytes": True}, {"rbytes": 50}, {"rbytes": -1}):
            with self.subTest(current=current):
                for row in self.rows:
                    row["cgroups"][0]["io_stat_by_device"] = {"8:0": {"rbytes": 100}}
                self.rows[-1]["cgroups"][0]["io_stat_by_device"]["8:0"] = current
                self.write()
                result, domain = self.phase_domain()
                self.assertIsNone(domain["io_by_device"]["8:0"]["rbytes"])
                self.assertEqual(result["quality_status"], "INCOMPLETE")
                self.assertEqual(load_health(self.path, 20, 100, self.groups)["status"], "INCOMPLETE")

    def test_device_io_observed_zero_and_positive_deltas_remain_valid(self):
        for index, row in enumerate(self.rows):
            row["cgroups"][0]["io_stat_by_device"] = {"8:0": {"rbytes": 100 + index * 50, "rios": 0}}
        self.write()
        result, domain = self.phase_domain()
        self.assertEqual(domain["io_by_device"]["8:0"], {"rbytes": 100, "rios": 0})
        self.assertEqual(result["quality_status"], "COMPLETE")
        self.assertEqual(load_health(self.path, 20, 100, self.groups)["status"], "COMPLETE")

    def test_missing_device_io_map_is_not_empty_complete_evidence(self):
        del self.rows[-1]["cgroups"][0]["io_stat_by_device"]
        self.write()
        result, domain = self.phase_domain()
        self.assertIsNone(domain["io_by_device"])
        self.assertEqual(result["quality_status"], "INCOMPLETE")
        self.assertEqual(load_health(self.path, 20, 100, self.groups)["status"], "INCOMPLETE")

    def test_cpu_and_psi_regression_never_produce_negative_valid_deltas(self):
        self.rows[0]["cgroups"][0]["cpu_stat"]["usage_usec"] = 100
        self.rows[-1]["cgroups"][0]["psi"]["cpu"]["some_total_us"] = -1
        self.write()
        result, domain = self.phase_domain()
        self.assertIsNone(domain["cpu_usage_usec"])
        self.assertIsNone(domain["psi_delta_us_by_resource_not_additive"]["cpu"]["some_total_us"])
        self.assertEqual(result["quality_status"], "INCOMPLETE")

    def test_missing_psi_domain_or_counter_is_unknown_not_hidden_by_intersection(self):
        for remove_domain in (False, True):
            with self.subTest(remove_domain=remove_domain):
                self.rows[-1]["cgroups"][0]["psi"]["memory"] = {}
                if remove_domain:
                    del self.rows[-1]["cgroups"][0]["psi"]["memory"]
                self.write()
                result, domain = self.phase_domain()
                self.assertIsNone(domain["psi_delta_us_by_resource_not_additive"]["memory"]["some_total_us"])
                self.assertEqual(result["quality_status"], "INCOMPLETE")

    def test_unbracketed_phase_downgrades_quality(self):
        result = resource_windows(self.path, [("SEARCH", 5, 100, {})], self.groups)
        self.assertEqual(result["windows"][0]["status"], "UNBRACKETED")
        self.assertEqual(result["quality_status"], "INCOMPLETE")

    def test_paired_bootstrap_interval_contains_median(self):
        result = interval([-4, -2, -3, -1, -5])
        self.assertEqual(result["median"], -3)
        self.assertLessEqual(result["bootstrap_median_ci95"][0], -3)
        self.assertGreaterEqual(result["bootstrap_median_ci95"][1], -3)


class ThreadCounterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "load-processes.jsonl"
        self.actor = {"boot_id": "boot", "pid": 31, "process_start_ticks": 40,
                      "tid": 32, "thread_start_ticks": 41}
        self.interval = {"actor": self.actor, "start_ns": 20, "end_ns": 90,
                         "request_id": "request-A", "scope": "NATIVE_WORKER"}
        self.samples = [{"identity": dict(self.actor), "collection_start_ns": start,
                         "collection_end_ns": start + 1, "run_ns": run, "wait_ns": wait,
                         "wait_counter_status": "ENABLED"}
                        for start, run, wait in ((10, 100, 200), (100, 150, 225))]

    def tearDown(self):
        self.temp.cleanup()

    def analyze_threads(self):
        self.path.write_text("".join(json.dumps({"cgroups": [{"processes": [{"tid_samples": [sample]}]}]}) + "\n"
                                     for sample in self.samples))
        result = thread_associations(self.path, [self.interval])
        return result, result["intervals"][0]

    def test_valid_bracketed_deltas_keep_explicit_nonexclusive_scope(self):
        result, record = self.analyze_threads()
        self.assertEqual((record["run_ns"], record["wait_ns"]), (50, 25))
        self.assertEqual(record["counter_status"], "COMPLETE")
        self.assertIn("NOT_EXCLUSIVE_REQUEST_COST", record["status"])
        self.assertEqual(result["bracketed_intervals"], 1)
        self.assertEqual(result["unresolved_intervals"], 0)
        self.assertEqual(result["quality_status"], "COMPLETE")

    def test_thread_counter_regression_is_unknown_and_unresolved(self):
        self.samples[-1].update(run_ns=50, wait_ns=50)
        result, record = self.analyze_threads()
        self.assertIsNone(record["run_ns"])
        self.assertIsNone(record["wait_ns"])
        self.assertEqual(record["counter_status"], "INCOMPLETE")
        self.assertEqual(record["status"], "UNRESOLVED_THREAD_COUNTER_ENVELOPE")
        self.assertEqual(result["bracketed_intervals"], 0)
        self.assertEqual(result["sample_bracketed_intervals"], 1)
        self.assertEqual(result["unresolved_intervals"], 1)
        self.assertEqual(result["quality_status"], "INCOMPLETE")

    def test_interior_thread_counter_reset_is_not_hidden_by_positive_endpoints(self):
        interior = {**self.samples[0], "collection_start_ns": 50, "collection_end_ns": 51,
                    "run_ns": 25, "wait_ns": 50}
        self.samples.insert(1, interior)
        result, record = self.analyze_threads()
        self.assertIsNone(record["run_ns"])
        self.assertIsNone(record["wait_ns"])
        self.assertEqual(result["unresolved_intervals"], 1)

    def test_missing_or_invalid_thread_counters_are_not_valid_bracketed_work(self):
        for field in ("run_ns", "wait_ns"):
            for invalid in (None, True, -1, "150"):
                with self.subTest(field=field, value=invalid):
                    before = dict(self.samples[-1])
                    self.samples[-1][field] = invalid
                    result, record = self.analyze_threads()
                    self.assertIsNone(record[field])
                    self.assertEqual(result["unresolved_intervals"], 1)
                    self.samples[-1] = before

    def test_disabled_schedstats_cannot_be_accepted_as_measured_wait(self):
        self.samples[-1]["wait_counter_status"] = "DISABLED_OR_UNKNOWN"
        result, record = self.analyze_threads()
        self.assertEqual(record["run_ns"], 50)
        self.assertIsNone(record["wait_ns"])
        self.assertIn("counter_disabled_or_unknown:tid.wait_ns", record["counter_issues"])
        self.assertEqual(result["quality_status"], "INCOMPLETE")

    def test_missing_wait_counter_status_is_unknown(self):
        del self.samples[-1]["wait_counter_status"]
        result, record = self.analyze_threads()
        self.assertIsNone(record["wait_ns"])
        self.assertEqual(result["bracketed_intervals"], 0)

    def test_reused_tid_birth_identity_is_not_joined(self):
        self.samples[-1]["identity"]["thread_start_ticks"] += 1
        result, record = self.analyze_threads()
        self.assertIsNone(record["run_ns"])
        self.assertFalse(record["sample_bracketed"])
        self.assertEqual(result["unresolved_intervals"], 1)


if __name__ == "__main__":
    unittest.main()
