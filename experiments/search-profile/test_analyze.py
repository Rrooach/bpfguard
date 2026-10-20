#!/usr/bin/env python3
"""Deterministic analyzer tests; no privilege, BPF or live cgroup required."""

import importlib.util
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("search_profile_analyze", Path(__file__).with_name("analyze.py"))
ANALYZE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZE)


def group(usage, psi=0, read_bytes=0):
    return {"present": True, "cpu_stat": {"usage_usec": usage, "user_usec": usage, "system_usec": 0, "throttled_usec": 0},
            "psi": {resource: {"some_total_us": psi, "full_total_us": psi // 2} for resource in ("cpu", "memory", "io")},
            "memory_current": 4096, "memory_peak": 8192,
            "memory_stat": {"workingset_refault_file": 0, "workingset_refault_anon": 0, "pgmajfault": 0},
            "memory_events": {"high": 0, "max": 0, "oom": 0, "oom_kill": 0},
            "io_stat_by_device": {"8:0": {"rbytes": read_bytes, "wbytes": 0, "rios": 0, "wios": 0}}}


def sample(seq, stamp, usage, psi=0, read_bytes=0):
    return {"seq": seq, "monotonic_ns": stamp, "collection_end_ns": stamp + 1000000,
            "cgroups": [group(usage, psi, read_bytes)], "stat": {"cpu_total": [seq * 100, 0, 0, seq * 100, 0, 0, 0, 0]},
            "psi": {resource: {"some_total_us": psi, "full_total_us": psi // 2} for resource in ("cpu", "memory", "io")},
            "meminfo_kb": {"MemAvailable": 1024}}


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        (self.directory / "load").mkdir()
        self.cg = {"path": "/sys/fs/cgroup/test/search-0", "inode": 101, "device": 28}
        self.run = {"schema_version": 1, "run_id": "run", "boot_id": "boot", "config": {}, "tasks": [{"task_id": "task-0"}]}
        identity = {"schema_version": 1, "run_id": "run", "boot_id": "boot", "task_id": "task-0", "attempt": 1, "epoch": 1,
                    "tool_call_id": "call-0", "request_id": None, "parent_task_id": None, "dependencies": [], "phase": "search", "priority": 0,
                    "process": {"pid": 202, "start_ticks": 303}, "cgroup": self.cg}
        self.events = [dict(identity, seq=0, event="START", monotonic_ns=1200000000),
                       dict(identity, seq=1, event="COMPLETE", monotonic_ns=1800000000, exit_code=0, output_sha256="abc", output_bytes=0,
                            wall_ns=600000000, user_usec=300000, system_usec=0, max_rss_kb=12)]
        self.meta = {"schema_version": 1, "boot_id": "boot", "interval_ms": 1000, "clk_tck": 100, "cgroups": [self.cg], "kernel_hist": None}
        self.samples = [sample(0, 1000000000, 1000), sample(1, 2000000000, 501000, 200000, 4096)]
        self.stats = {"samples": 2, "read_errors": 0, "missed_ticks": 0, "truncated_process_sets": 0, "stop_reason": "signal", "end_clock": {"monotonic_ns": 2100000000}}

    def tearDown(self):
        self.temp.cleanup()

    def write(self, missing_stats=False):
        for name, value in (("profile-run.json", self.run), ("load/load-meta.json", self.meta)):
            (self.directory / name).write_text(json.dumps(value))
        if not missing_stats:
            (self.directory / "load/load-sampler-stats.json").write_text(json.dumps(self.stats))
        for name, values in (("task-events.jsonl", self.events), ("load/load-samples.jsonl", self.samples)):
            (self.directory / name).write_text("".join(json.dumps(value) + "\n" for value in values))

    def report(self, missing_stats=False):
        self.write(missing_stats)
        return ANALYZE.analyze_trial(self.directory)

    def codes(self, report):
        return {item["code"] for item in report["issues"]}

    def test_valid_actual_interval_and_per_device_rates(self):
        report = self.report()
        self.assertEqual(report["status"], "COMPLETE_WITHIN_DECLARED_MEASUREMENT", report["issues"])
        metrics = report["tasks"][0]["resources"]
        self.assertEqual(metrics["cpu"]["usage_cores"], 0.5)
        self.assertEqual(metrics["io_by_device"]["8:0"]["rbytes_per_second"], 4096)
        self.assertEqual(metrics["boundary"]["before_uncertainty_ns"], 200000000)
        self.assertEqual(metrics["boundary"]["after_uncertainty_ns"], 201000000)
        self.assertEqual(report["execution_makespan_ns"], 600000000)

    def query_fixture(self):
        self.run['config'].update(query_measurement_version=1, passes=2, jobs=1, intervention='none')
        for event in self.events:
            event['agent_id'] = 'agent-0'
        identity = {key: self.events[0][key] for key in
                    ('run_id', 'task_id', 'agent_id', 'tool_call_id', 'attempt', 'epoch', 'cgroup')}
        self.query_job = {'query': 'needle', 'query_index': 0, 'query_identity': identity, 'passes': 2}
        self.query_stats = {'schema_version': 2, 'logical_queries': 2, 'physical_grep_executions': 2,
                            'cache_hits': 0, 'intervention': 'none', 'query_spans': [],
                            'query_timing_contract': 'WORKER_MONOTONIC_PER_LOGICAL_QUERY_V1'}
        for ordinal, (begin, end) in enumerate(((1300000000, 1400000000), (1500000000, 1650000000))):
            self.query_stats['query_spans'].append({**identity, 'schema_version': 1,
                'boot_id': 'boot', 'process': self.events[0]['process'],
                'query_ordinal': ordinal, 'query_id': 'call-0:query-{:06d}'.format(ordinal),
                'query_index': 0, 'query_sha256': hashlib.sha256(b'needle').hexdigest(),
                'mode': 'none', 'execution_kind': 'SCAN', 'returncode': 0, 'status': 'COMPLETE',
                'begin_ns': begin, 'end_ns': end, 'duration_ns': end - begin, 'lock_wait_ns': 0,
                'timing_scope': 'WORKER_QUERY_CALL_INCLUDING_LOCK_CACHE_OUTPUT_AND_SUBPROCESS',
                'identity_scope': 'CALLING_WORKER; GREP_DESCENDANT_NOT_INDIVIDUALLY_RESOLVED'})

    def query_report(self, bind_stats=True):
        if bind_stats:
            self.run['results'] = [{'task_id': 'task-0', 'query_index': 0, 'query_statistics': copy.deepcopy(self.query_stats)}]
        (self.directory / 'task-0-statistics.json').write_text(json.dumps(self.query_stats))
        (self.directory / 'task-0-job.json').write_text(json.dumps(self.query_job))
        return self.report()

    def test_legacy_query_timing_is_not_inferred_from_task_duration(self):
        measurement = self.report()['query_measurements']
        self.assertEqual(measurement['status'], 'NOT_COLLECTED_LEGACY')
        self.assertIsNone(measurement['duration_seconds'])
        self.assertEqual(measurement['queries'], [])

    def test_per_query_spans_reconstruct_raw_stats_and_timeline(self):
        self.query_fixture()
        report = self.query_report()
        self.assertEqual(report['status'], 'COMPLETE_WITHIN_DECLARED_MEASUREMENT', report['issues'])
        query = report['query_measurements']
        self.assertEqual(query['status'], 'OBSERVED')
        self.assertEqual(query['observed_queries'], 2)
        self.assertEqual(query['duration_seconds']['median'], 0.125)
        self.assertIsNone(query['duration_seconds']['mean_ci95_bootstrap'])
        spans = [row for row in ANALYZE.timeline(report)['traceEvents'] if row.get('cat') == 'logical_query:SCAN']
        self.assertEqual([row['dur'] for row in spans], [100000, 150000])
        self.assertEqual(spans[0]['args']['agent_id'], 'agent-0')

    def test_baseline_still_collects_queries_without_claiming_resource_sampling(self):
        self.query_fixture()
        self.run['config']['mode'] = 'baseline'
        report = self.query_report()
        self.assertEqual(report['query_measurements']['status'], 'OBSERVED')
        self.assertEqual(report['sampling_status'], 'NOT_COLLECTED')
        self.assertEqual(report['status'], 'TIMING_ONLY')

    def test_new_query_contract_does_not_accept_missing_raw_statistics(self):
        self.query_fixture()
        report = self.report()
        self.assertEqual(report['query_measurements']['status'], 'INCOMPLETE')
        self.assertIn('MISSING_QUERY_SPANS', self.codes(report))

    def test_query_identity_time_and_sequence_tampering_is_rejected(self):
        changes = [('process', {'pid': 202, 'start_ticks': 999}, 'QUERY_IDENTITY_MISMATCH'),
                   ('duration_ns', -1, 'INVALID_QUERY_DURATION'),
                   ('query_ordinal', 8, 'QUERY_SEQUENCE_OR_CONTENT_MISMATCH'),
                   ('query_sha256', 'bad', 'QUERY_SEQUENCE_OR_CONTENT_MISMATCH'),
                   ('query_id', 'call-0:query-000000', 'QUERY_SEQUENCE_OR_CONTENT_MISMATCH'),
                   ('lock_wait_ns', 999999999, 'INVALID_QUERY_LOCK_WAIT'),
                   ('execution_kind', 'CACHE_HIT', 'QUERY_EXECUTION_INCOMPLETE'),
                   ('returncode', 2, 'QUERY_EXECUTION_INCOMPLETE'),
                   ('returncode', True, 'QUERY_EXECUTION_INCOMPLETE'),
                   ('mode', 'exact-reuse', 'QUERY_EXECUTION_INCOMPLETE')]
        for key, value, code in changes:
            with self.subTest(key=key, value=value):
                self.query_fixture()
                self.query_stats['query_spans'][1][key] = value
                report = self.query_report()
                self.assertEqual(report['query_measurements']['status'], 'INCOMPLETE')
                self.assertIn(code, self.codes(report))

    def test_query_overlap_or_span_outside_task_is_rejected(self):
        for begin, end in ((1390000000, 1500000000), (1600000000, 1900000000)):
            with self.subTest(begin=begin, end=end):
                self.query_fixture()
                self.query_stats['query_spans'][1].update(begin_ns=begin, end_ns=end, duration_ns=end - begin)
                self.assertIn('QUERY_OUTSIDE_TASK_OR_OVERLAP', self.codes(self.query_report()))

    def test_query_statistics_and_declared_results_must_reconstruct(self):
        self.query_fixture()
        self.query_stats['cache_hits'] = 1
        self.assertIn('QUERY_STATISTICS_MISMATCH', self.codes(self.query_report()))
        self.query_fixture()
        self.query_report()
        self.query_stats['query_spans'][0]['duration_ns'] += 1
        self.assertIn('QUERY_DERIVED_STATISTICS_MISMATCH', self.codes(self.query_report(bind_stats=False)))

    def test_partial_query_sequence_stays_incomplete_not_zero(self):
        self.query_fixture()
        self.query_stats['query_spans'].pop()
        report = self.query_report()
        self.assertEqual(report['query_measurements']['status'], 'INCOMPLETE')
        self.assertEqual(report['query_measurements']['expected_queries'], 2)
        self.assertIn('INCOMPLETE_QUERY_SEQUENCE', self.codes(report))

    def test_declared_queries_with_no_task_lifecycle_cannot_be_observed(self):
        self.query_fixture()
        self.events = []
        report = self.query_report()
        self.assertEqual(report['query_measurements']['expected_queries'], 2)
        self.assertEqual(report['query_measurements']['status'], 'INCOMPLETE')
        self.assertEqual(report['query_measurements']['observed_queries'], 0)
        self.assertIn('INCOMPLETE_QUERY_TASK_SET', self.codes(report))

    def test_calibration_does_not_claim_search_queries(self):
        self.run['config'].update(calibration_kind='read', query_measurement_version=1)
        self.assertEqual(self.report()['query_measurements']['status'], 'NOT_APPLICABLE_CALIBRATION')

    def test_exact_reuse_keeps_cache_hit_lock_wait_inside_query_duration(self):
        self.query_fixture()
        self.run['config']['intervention'] = 'exact-reuse'
        self.query_stats.update(intervention='exact-reuse', physical_grep_executions=1, cache_hits=1)
        for row in self.query_stats['query_spans']:
            row['mode'] = 'exact-reuse'
        self.query_stats['query_spans'][1].update(execution_kind='CACHE_HIT', lock_wait_ns=1000)
        report = self.query_report()
        self.assertEqual(report['query_measurements']['status'], 'OBSERVED', report['issues'])
        self.assertEqual(report['query_measurements']['by_execution_kind']['SCAN']['n'], 1)
        self.assertEqual(report['query_measurements']['by_execution_kind']['CACHE_HIT']['n'], 1)

    def test_shared_leaf_never_labels_group_usage_task_exclusive(self):
        self.run['config']['cgroup_layout'] = 'shared-leaf'
        report = self.report()
        task = report['tasks'][0]
        self.assertEqual(task['resource_owner'], 'ALL_TASKS_IN_SHARED_LEAF')
        self.assertEqual(task['resources']['measurement_scope'], 'SHARED_EXECUTION_GROUP_ENCLOSING_INTERVAL_NOT_TASK_EXCLUSIVE')

    def test_observer_only_does_not_invent_missing_sampler(self):
        self.run['config']['mode'] = 'observer'
        self.run['observer_audit'] = 'INDEPENDENTLY_VERIFIED'
        report = self.report(missing_stats=True)
        self.assertEqual(report['sampling_status'], 'NOT_COLLECTED')
        self.assertEqual(report['status'], 'TIMING_ONLY')
        self.assertEqual(report['issues'], [])

    def test_report_writer_preserves_malformed_metadata_as_incomplete(self):
        self.write()
        (self.directory / 'load/load-meta.json').write_text('{bad')
        report = ANALYZE.write_report(self.directory)
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertIn('MISSING_OR_INVALID_ARTIFACT', self.codes(report))

    def test_short_stage_is_retained_and_not_interpolated(self):
        self.events[1]["monotonic_ns"] = 1201000000
        self.events[1]["wall_ns"] = 1000000
        report = self.report()
        task = report["tasks"][0]
        self.assertEqual(task["duration_ns"], 1000000)
        self.assertEqual(task["resources"]["cpu"]["usage_usec_delta"], 500000)
        self.assertEqual(task["resources"]["boundary"]["interpolation"], "NONE")
        self.assertEqual(len(ANALYZE.timeline(report)["traceEvents"]), 2)

    def test_no_bracket_is_unknown_not_zero(self):
        self.events[0]["monotonic_ns"] = 999999999
        report = self.report()
        self.assertIn("NO_BRACKETING_SAMPLES", self.codes(report))
        self.assertIsNone(report["tasks"][0]["resources"])
        self.assertIsNotNone(report["tasks"][0]["duration_ns"])

    def test_collection_overlap_does_not_count_as_before(self):
        self.samples[0]["collection_end_ns"] = 1500000000
        self.assertIn("NO_BRACKETING_SAMPLES", self.codes(self.report()))

    def test_counter_reset_null_not_clamped(self):
        self.samples[1]["cgroups"][0]["cpu_stat"]["usage_usec"] = 1
        report = self.report()
        self.assertIn("COUNTER_RESET", self.codes(report))
        self.assertIsNone(report["tasks"][0]["resources"]["cpu"]["usage_cores"])
        self.assertEqual(report["status"], "INCOMPLETE")

    def test_intermediate_reset_makes_task_incomplete(self):
        self.samples.insert(1, sample(1, 1500000000, 999999))
        self.samples[2]["seq"] = 2
        self.stats["samples"] = 3
        report = self.report()
        self.assertIn("COUNTER_RESET", self.codes(report))
        self.assertEqual(report["tasks"][0]["resource_status"], "INCOMPLETE")

    def test_missing_stats_is_incomplete(self):
        report = self.report(missing_stats=True)
        self.assertIn("MISSING_FINAL_STATS", self.codes(report))
        self.assertEqual(report["tasks"][0]["resource_status"], "INCOMPLETE")

    def test_psi_dimensions_stay_separate_and_may_overlap(self):
        self.samples[1]["cgroups"][0]["psi"] = {resource: {"some_total_us": 800000, "full_total_us": 500000} for resource in ("cpu", "memory", "io")}
        report = self.report()
        psi = report["tasks"][0]["resources"]["psi"]
        self.assertEqual([psi[r]["some_fraction"] for r in ("cpu", "memory", "io")], [0.8, 0.8, 0.8])
        self.assertNotIn("total_wait", report["tasks"][0]["resources"])
        self.assertTrue(all(c["causality"] == "NOT_ESTABLISHED" for c in report["tasks"][0]["candidates"]))

    def test_cgroup_reuse_identity_mismatch(self):
        self.meta["cgroups"] = [dict(self.cg, inode=999)]
        report = self.report()
        self.assertIn("UNMATCHED_TASK_CGROUP", self.codes(report))
        self.assertIsNone(report["tasks"][0]["resources"])

    def test_old_metadata_is_unknown_not_path_match(self):
        self.meta["cgroups"] = [{"path": self.cg["path"]}]
        report = self.report()
        self.assertIn("MISSING_SAMPLER_CGROUP_IDENTITY", self.codes(report))
        self.assertIsNone(report["tasks"][0]["resources"])

    def test_boot_mismatch_prevents_correlation(self):
        self.meta["boot_id"] = "reboot"
        report = self.report()
        self.assertIn("SAMPLER_BOOT_IDENTITY_UNKNOWN_OR_MISMATCH", self.codes(report))
        self.assertIsNone(report["tasks"][0]["resources"])

    def test_mismatched_sampler_run_label_prevents_correlation(self):
        self.meta["label"] = "another-run"
        report = self.report()
        self.assertIn("SAMPLER_RUN_IDENTITY_MISMATCH", self.codes(report))
        self.assertIsNone(report["tasks"][0]["resources"])

    def test_process_birth_identity_changes_rejected(self):
        self.events[1]["process"] = {"pid": 202, "start_ticks": 404}
        report = self.report()
        self.assertIn("LIFECYCLE_IDENTITY_CHANGED", self.codes(report))
        self.assertFalse(report["tasks"][0]["identity_valid"])
        self.assertIsNone(report["tasks"][0]["resources"])

    def test_duplicate_terminal_and_event_gap(self):
        self.events.append(dict(self.events[1], seq=5))
        codes = self.codes(self.report())
        self.assertIn("EVENT_SEQUENCE_GAP", codes)
        self.assertIn("DUPLICATE_OR_ORPHAN_TERMINAL", codes)

    def test_missing_terminal_retained(self):
        self.events.pop()
        report = self.report()
        self.assertEqual(report["task_count"], 1)
        self.assertEqual(report["tasks"][0]["status"], "INCOMPLETE")

    def test_missing_counter_and_new_device_unknown(self):
        del self.samples[1]["cgroups"][0]["psi"]["cpu"]
        self.samples[1]["cgroups"][0]["io_stat_by_device"]["8:1"] = {"rbytes": 100, "wbytes": 0, "rios": 1, "wios": 0}
        report = self.report()
        metrics = report["tasks"][0]["resources"]
        self.assertIsNone(metrics["psi"]["cpu"]["some_fraction"])
        self.assertIsNone(metrics["io_by_device"]["8:1"]["rbytes_delta"])

    def test_gap_uses_actual_interval_not_nominal(self):
        self.meta["interval_ms"] = 100
        report = self.report()
        self.assertIn("SAMPLING_GAP", self.codes(report))
        self.assertEqual(report["tasks"][0]["resources"]["cpu"]["usage_cores"], 0.5)
        self.assertEqual(report["tasks"][0]["resource_status"], "INCOMPLETE")

    def test_malformed_record_keeps_other_tasks(self):
        self.write()
        with (self.directory / "task-events.jsonl").open("a") as stream:
            stream.write('{"broken":\n')
        report = ANALYZE.analyze_trial(self.directory)
        self.assertIn("PARSE_ERROR", self.codes(report))
        self.assertEqual(report["task_count"], 1)

    def test_html_escapes_untrusted_values_and_has_no_external_assets(self):
        self.run["run_id"] = "<script>alert(1)</script>"
        for event in self.events:
            event["run_id"] = self.run["run_id"]
        self.write()
        ANALYZE.write_report(self.directory)
        text = (self.directory / "report.html").read_text()
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertNotIn("https://", text)
        self.assertTrue((self.directory / "report.json").exists())
        self.assertIn("traceEvents", json.loads((self.directory / "timeline.json").read_text()))

    def test_system_metrics_never_copied_to_task(self):
        report = self.report()
        self.assertEqual(report["system_intervals"][0]["scope"], "SYSTEM_ONLY")
        self.assertNotIn("system_cpu", report["tasks"][0]["resources"])

    def test_enabled_process_stream_cannot_silently_disappear(self):
        self.meta["process_interval_ms"] = 1000
        self.stats["process_samples"] = 1
        report = self.report()
        self.assertIn("PROCESS_SAMPLE_COUNT_MISMATCH", self.codes(report))
        self.assertEqual(report["tasks"][0]["resource_status"], "INCOMPLETE")

    def test_negative_completion_counter_is_invalid(self):
        self.events[1]["user_usec"] = -1
        report = self.report()
        self.assertIn("INVALID_COMPLETION_FIELD", self.codes(report))
        self.assertFalse(report["tasks"][0]["identity_valid"])

    def test_lifetime_cpu_is_preserved_separately_from_task_cpu(self):
        self.events[1].update(lifetime_user_usec=400000, lifetime_system_usec=5000,
                              cpu_time_scope="WAIT4_LIFETIME_MINUS_WORKER_PREFLIGHT_RUSAGE",
                              other_rusage_scope="WHOLE_WORKER_LIFETIME_INCLUDING_PREPARATION")
        completion = self.report()["tasks"][0]["completion"]
        self.assertEqual(completion["user_usec"], 300000)
        self.assertEqual(completion["lifetime_user_usec"], 400000)
        self.assertEqual(completion["lifetime_system_usec"], 5000)
        self.assertEqual(completion["cpu_time_scope"], "WAIT4_LIFETIME_MINUS_WORKER_PREFLIGHT_RUSAGE")
        self.assertEqual(completion["other_rusage_scope"], "WHOLE_WORKER_LIFETIME_INCLUDING_PREPARATION")
        self.assertIn("暂停握手", completion["cpu_accounting_note"])

    def test_calibration_labels_and_phase_survive_trial_and_timeline(self):
        for kind, label in (("cpu", "CPU"), ("sleep", "sleep 睡眠"), ("read", "read 文件读取")):
            with self.subTest(kind=kind):
                self.run["config"].update(calibration_kind=kind, calibration_seconds=0.4)
                for event in self.events:
                    event["phase"] = "calibration:" + kind
                report = self.report()
                self.assertEqual(report["tasks"][0]["phase"], "calibration:" + kind)
                event = ANALYZE.timeline(report)["traceEvents"][0]
                self.assertEqual(event["cat"], "calibration:" + kind)
                self.assertEqual(event["args"]["phase"], "calibration:" + kind)
                text = ANALYZE._html(report)
                self.assertIn("<h1>" + label + "校准（不是搜索优化实验）</h1>", text)
                self.assertIn("这是测量校准，不是搜索优化结果", text)
                self.assertIn("空输出的一致性不能证明计量准确", text)
                self.assertIn("暂停握手", text)
                if kind == "read":
                    self.assertIn("calibration_seconds 不控制 read 工作量", text)
                else:
                    self.assertIn("每任务目标约 0.4 秒", text)

    def test_search_report_remains_search_not_calibration(self):
        report = self.report()
        self.assertEqual(ANALYZE.timeline(report)["traceEvents"][0]["cat"], "search")
        text = ANALYZE._html(report)
        self.assertIn("<h1>并发搜索：时间花在哪里？</h1>", text)
        self.assertNotIn("这是测量校准", text)

    def test_malformed_optional_lifetime_cpu_is_not_accepted(self):
        self.events[1]["lifetime_user_usec"] = -1
        report = self.report()
        self.assertIn("INVALID_COMPLETION_FIELD", self.codes(report))
        self.assertFalse(report["tasks"][0]["identity_valid"])

    def test_invalid_process_cgroup_list_is_incomplete_not_crash(self):
        self.meta["process_interval_ms"] = 1000
        self.stats["process_samples"] = 1
        (self.directory / "load/load-processes.jsonl").write_text(json.dumps({
            "seq": 0, "monotonic_ns": 1000000000, "collection_end_ns": 1001000000,
            "cgroups": None}) + "\n")
        self.assertIn("INVALID_PROCESS_GROUP", self.codes(self.report()))

    def test_baseline_intentionally_has_no_resource_stream(self):
        self.run["config"]["mode"] = "baseline"
        self.write(missing_stats=True)
        report = ANALYZE.analyze_trial(self.directory)
        self.assertEqual(report["status"], "TIMING_ONLY")
        self.assertEqual(report["sampling_status"], "NOT_COLLECTED")
        self.assertEqual(report["tasks"][0]["resource_status"], "NOT_COLLECTED")
        self.assertEqual(report["issues"], [])

    def test_invalid_event_timestamp_and_missing_collection_window_do_not_crash(self):
        self.events[0]["monotonic_ns"] = "not-a-time"
        self.samples[1]["collection_end_ns"] = None
        self.meta["interval_ms"] = "bad"
        report = self.report()
        self.assertEqual(report["status"], "INCOMPLETE")

    def hist_fixture(self):
        self.run["config"]["mode"] = "kernel-hist"
        self.meta["kernel_hist"] = {"target_cgroup": self.cg["path"], "groups": ["sched", "blk"],
            "buckets": 2, "metrics": [{"name": "sched_runq", "scope": "target", "subsystem": "sched"},
                                        {"name": "blk_service", "scope": "system", "subsystem": "blk"}],
            "counters": ["wakeups", "storage_miss", "blk_untracked", "unpaired_end"],
            "programs": {"programs": [{"id": 1, "name": "kh_sys_enter", "recursion_misses": 0}]}}
        self.stats["kernel_hist"] = {"programs": [{"id": 1, "name": "kh_sys_enter", "recursion_misses": 0}]}
        self.samples[0]["khist"] = {"m": [[0, 0], [0, 0]], "c": [0, 0, 0, 0]}
        self.samples[1]["khist"] = {"m": [[3, 5, 1, 2], [1, 2, 0, 1]], "c": [3, 0, 0, 0]}

    def test_hist_completed_spans_scoped_and_not_wall_partition(self):
        self.hist_fixture()
        report = self.report()
        hist = report["kernel_hist"]
        self.assertEqual(hist["status"], "NO_REPORTED_LOSS_WITHIN_SELECTED_PROBES")
        self.assertEqual(hist["aggregates"][0]["completed_count"], 3)
        self.assertAlmostEqual(hist["aggregates"][0]["mean_completed_span_ns"], 5 / 3)
        self.assertEqual(hist["aggregates"][0]["scope"], "TARGET_ROOT_CGROUP_AGGREGATE")
        self.assertEqual(hist["aggregates"][1]["scope"], "SYSTEM_ONLY")
        self.assertEqual(hist["percentiles"], "NOT_COMPUTED")
        self.assertNotIn("kernel_hist", report["tasks"][0]["resources"])

    def multi_domain_fixture(self):
        self.hist_fixture()
        sibling = {'path': self.cg['path'] + '-sibling', 'inode': 102, 'device': 28}
        self.meta['cgroups'].append(sibling)
        domains = [dict(self.cg, domain_index=0), dict(sibling, domain_index=1)]
        self.meta['kernel_hist'].update(abi_version=2, domains=domains)
        for event in self.events:
            event['cgroup'] = sibling
        for sample in self.samples:
            sample['cgroups'].append(copy.deepcopy(sample['cgroups'][0]))
            sample['khist']['domains'] = [dict(identity=identity, m=[[0, 0], [0, 0]], c=[0, 0, 0, 0]) for identity in domains]
            sample['khist']['system'] = {'scope': 'SYSTEM_UNATTRIBUTED', 'm': [[0, 0], [0, 0]], 'c': [0, 0, 0, 0]}
        self.samples[1]['khist']['domains'][0]['m'][0] = [3, 3, 3]
        self.samples[1]['khist']['domains'][1]['m'][0] = [7, 7, 7]
        self.samples[1]['khist']['system']['m'][1] = [11, 22, 0, 11]
        self.samples[1]['khist']['m'] = [[999, 999, 999], [888, 888, 888]]

    def test_multi_domain_never_reuses_first_domain_for_sibling_task(self):
        self.multi_domain_fixture()
        report = self.report()
        hist = report['kernel_hist']
        self.assertEqual(hist['aggregates'][0]['completed_count'], 3)
        self.assertEqual(hist['aggregates'][1]['completed_count'], 11)
        self.assertEqual(hist['domains'][1]['aggregates'][0]['completed_count'], 7)
        self.assertEqual(len(hist['domains'][1]['aggregates']), 1)
        self.assertEqual(report['tasks'][0]['kernel_hist_domain_index'], 1)
        self.assertIn('WHOLE_COLLECTION_NOT_EXACT_TASK', report['tasks'][0]['kernel_hist_scope'])

    def test_multi_domain_replaced_identity_is_not_accepted(self):
        self.multi_domain_fixture()
        self.samples[1]['khist']['domains'][1]['identity'] = dict(self.cg, domain_index=1)
        report = self.report()
        self.assertIn('KERNEL_HIST_DOMAIN_IDENTITY_CHANGED', self.codes(report))
        self.assertIsNone(report['kernel_hist']['domains'][1]['aggregates'][0]['completed_count'])

    def test_hist_recursion_misses_degrade_only_diagnostic_layer(self):
        self.hist_fixture()
        self.stats["kernel_hist"]["programs"][0]["recursion_misses"] = 919
        report = self.report()
        self.assertEqual(report["kernel_hist"]["status"], "INCOMPLETE")
        self.assertIn("KERNEL_HIST_RECURSION_MISSES", self.codes(report))
        self.assertEqual(report["sampling_status"], "OBSERVED")
        self.assertEqual(report["kernel_hist"]["programs"][0]["recursion_misses_delta"], 919)
        self.assertIsNotNone(report["kernel_hist"]["aggregates"][0]["completed_count"])

    def test_dispatch_registration_only_misses_are_saved_not_histogram_loss(self):
        self.hist_fixture()
        for program in self.meta['kernel_hist']['programs']['programs'] + self.stats['kernel_hist']['programs']:
            program.update(name='kh_sys_enter_dispatch', role='REGISTRATION_ONLY_NO_HISTOGRAM_PAYLOAD')
        self.stats['kernel_hist']['programs'][0]['recursion_misses'] = 100
        report = self.report()
        self.assertNotIn('KERNEL_HIST_RECURSION_MISSES', self.codes(report))
        self.assertEqual(report['kernel_hist']['programs'][0]['recursion_misses_delta'], 100)

    def test_return_probe_capacity_misses_and_cleanup_fail_are_not_hidden(self):
        self.hist_fixture()
        self.meta['kernel_hist']['groups'].append('mem')
        self.meta['kernel_hist']['memory_backend'] = 'kprobe-tracefs'
        probe = {'name': 'owned-return', 'group': 'owned', 'anchor': 'handle_mm_fault', 'is_return': True,
                 'maxactive': 1024, 'device': 28, 'directory_inode': 55, 'event_id': 66, 'definition': 'fixed',
                 'profile_status': 'OBSERVED', 'hits': 0, 'misses': 0}
        self.meta['kernel_hist']['programs']['memory_return_probe_profiles'] = [probe]
        self.stats['kernel_hist']['memory_return_probe_profiles'] = [dict(probe, hits=20, misses=2)]
        self.stats['kernel_hist']['tracefs_cleanup'] = {'status': 'INCOMPLETE', 'remaining_owned_events': 1, 'errors': ['identity changed'], 'detach_errors': []}
        report = self.report()
        self.assertIn('KERNEL_HIST_RETURN_PROBE_MISSES', self.codes(report))
        self.assertIn('KERNEL_HIST_TRACEFS_CLEANUP_INCOMPLETE', self.codes(report))
        self.assertEqual(report['kernel_hist']['status'], 'INCOMPLETE')

    def block_extension_fixture(self):
        self.hist_fixture()
        names = ('request_read_failed', 'flush_issued', 'flush_completed', 'flush_error',
                 'queue_span_unknown', 'untracked_complete', 'untracked_requeue',
                 'zero_nonflush_unsupported', 'zero_flush_invalid_bytes', 'sample_attempts')
        extension = {'version': 1, 'status': 'OBSERVED_NON_ATOMIC', 'scope': 'SYSTEM_UNATTRIBUTED',
            'counters': dict.fromkeys(names, 0), 'flush_service': {'count': 0, 'sum_ns': 0, 'buckets': [0] * 32},
            'samples': [], 'sample_capacity_per_cpu': 8, 'samples_truncated': 0}
        self.meta['kernel_hist']['programs']['block_diagnostics'] = extension
        self.stats['kernel_hist']['block_diagnostics'] = copy.deepcopy(extension)
        self.meta['kernel_hist']['counters'].append('blk_issue_without_insert')
        for row in self.samples:
            row['khist']['c'].append(0)
        self.samples[1]['khist']['c'][2] = 1
        self.samples[1]['khist']['c'][-1] = 2

    def test_v8_block_bypass_and_untracked_are_unknown_not_proven_loss(self):
        self.block_extension_fixture()
        report = self.report()
        self.assertIn('KERNEL_HIST_BLOCK_QUEUE_UNKNOWN', self.codes(report))
        self.assertIn('KERNEL_HIST_BLOCK_UNTRACKED_UNKNOWN', self.codes(report))
        self.assertNotIn('KERNEL_HIST_COVERAGE_LOSS', self.codes(report))
        self.assertEqual(report['kernel_hist']['status'], 'INCOMPLETE')

    def test_bounded_block_sample_truncation_does_not_invent_histogram_loss(self):
        self.block_extension_fixture()
        extension = self.stats['kernel_hist']['block_diagnostics']
        extension['samples_truncated'] = 37
        extension['counters'].update(flush_issued=18, flush_completed=18, queue_span_unknown=18, untracked_complete=9)
        extension['flush_service'].update(count=18, sum_ns=200, buckets=[18] + [0] * 31)
        report = self.report()
        block = report['kernel_hist']['block_diagnostics']
        self.assertEqual(block['sample_completeness'], 'BOUNDED_SAMPLES_TRUNCATED')
        self.assertEqual(block['counter_deltas']['flush_completed'], 18)
        self.assertNotIn('KERNEL_HIST_COVERAGE_LOSS', self.codes(report))
        self.assertIn('不是 fdatasync 总延迟', ANALYZE._kernel_hist_html(report))

    def test_missing_v8_block_endpoint_does_not_default_to_zero(self):
        self.block_extension_fixture()
        del self.stats['kernel_hist']['block_diagnostics']
        report = self.report()
        self.assertIn('KERNEL_HIST_BLOCK_DIAGNOSTICS_UNKNOWN', self.codes(report))
        self.assertEqual(report['kernel_hist']['block_diagnostics']['status'], 'UNKNOWN')

    def test_legacy_block_labels_are_not_reinterpreted_as_flush(self):
        self.hist_fixture()
        self.samples[1]['khist']['c'][2] = 1
        report = self.report()
        self.assertIn('KERNEL_HIST_COVERAGE_LOSS', self.codes(report))
        self.assertEqual(report['kernel_hist']['block_diagnostics']['status'], 'NOT_AVAILABLE_LEGACY_COLLECTOR')

    def test_hist_counter_loss_and_resets_are_explicit(self):
        self.hist_fixture()
        self.samples[0]["khist"]["m"][0] = [4, 6, 2, 2]
        self.samples[1]["khist"]["c"][1] = 1
        report = self.report()
        self.assertIn("KERNEL_HIST_COUNTER_RESET", self.codes(report))
        self.assertIn("KERNEL_HIST_COVERAGE_LOSS", self.codes(report))
        self.assertIsNone(report["kernel_hist"]["aggregates"][0]["completed_count"])

    def test_hist_missing_sample_not_zero(self):
        self.hist_fixture()
        del self.samples[1]["khist"]
        report = self.report()
        self.assertIn("MISSING_KERNEL_HIST_SAMPLE", self.codes(report))
        self.assertIsNone(report["kernel_hist"]["aggregates"][0]["completed_count"])

    def test_hist_missing_requested_metadata_remains_visible(self):
        self.run["config"]["mode"] = "kernel-hist"
        report = self.report()
        self.assertTrue(report["kernel_hist"]["enabled"])
        self.assertEqual(report["kernel_hist"]["status"], "INCOMPLETE")
        self.assertIn("MISSING_KERNEL_HIST", self.codes(report))

    def test_hist_invalid_metadata_and_registry_do_not_crash(self):
        self.hist_fixture()
        self.meta["cgroups"] = None
        self.meta["kernel_hist"] = "not-an-object"
        report = self.report()
        self.assertIn("INVALID_KERNEL_HIST_SCHEMA", self.codes(report))
        self.assertEqual(report["kernel_hist"]["status"], "INCOMPLETE")

    def test_hist_unbounded_bucket_metadata_is_rejected(self):
        self.hist_fixture()
        self.meta["kernel_hist"]["buckets"] = 2 ** 60
        report = self.report()
        self.assertIn("INVALID_KERNEL_HIST_BUCKETS", self.codes(report))
        self.assertEqual(report["kernel_hist"]["status"], "INCOMPLETE")

    def test_hist_bucket_reset_does_not_publish_mean(self):
        self.hist_fixture()
        self.samples[0]["khist"]["m"][0] = [1, 1, 1, 0]
        self.samples[1]["khist"]["m"][0] = [3, 5, 0, 3]
        report = self.report()
        self.assertIn("KERNEL_HIST_COUNTER_RESET", self.codes(report))
        self.assertIsNone(report["kernel_hist"]["aggregates"][0]["mean_completed_span_ns"])

    def test_hist_nonatomic_bucket_count_does_not_invent_percentiles(self):
        self.hist_fixture()
        self.samples[1]["khist"]["m"][0][2] = 0
        report = self.report()
        self.assertIn("KERNEL_HIST_NONATOMIC_READ", self.codes(report))
        self.assertIsNone(report["kernel_hist"]["aggregates"][0]["mean_completed_span_ns"])

    def test_hist_html_displays_scope_and_losses(self):
        self.hist_fixture()
        self.stats["kernel_hist"]["programs"][0]["recursion_misses"] = 1691
        self.write()
        ANALYZE.write_report(self.directory)
        text = (self.directory / "report.html").read_text()
        self.assertIn("内核延迟探针", text)
        self.assertIn("KERNEL_HIST_RECURSION_MISSES", text)
        self.assertIn("1691", text)
        self.assertIn("SYSTEM_ONLY", text)


class ThreadReportTests(unittest.TestCase):
    def fixture(self):
        identity = {'boot_id': 'boot', 'pid': 42, 'process_start_ticks': 2, 'tid': 77, 'thread_start_ticks': 3}
        meta = {'boot_id': 'boot', 'thread_sampling': {'enabled': True},
                'cgroups': [{'path': '/cg/root', 'inode': 1, 'device': 28}, {'path': '/cg/child', 'inode': 2, 'device': 28}]}
        stats = dict.fromkeys(('thread_read_errors', 'vanished_threads_during_read', 'truncated_thread_samples', 'thread_identity_changes', 'thread_disappeared_between_samples'), 0)
        rows = []
        for seq in range(2):
            thread = {'identity': identity, 'collection_start_ns': 100 + seq * 100,
                'collection_end_ns': 101 + seq * 100, 'utime': seq * 10, 'stime': seq,
                'run_ns': seq * 1000, 'wait_ns': seq * 500, 'timeslices': seq * 2,
                'wait_counter_status': 'ENABLED'}
            group = {'processes': [{'pid': 42, 'start_ticks': 2, 'tid_samples': [thread], 'tid_sampling_issues': []}]}
            rows.append({'seq': seq, 'cgroups': [copy.deepcopy(group), copy.deepcopy(group)]})
        return meta, stats, rows

    def test_overlapping_cgroup_views_do_not_duplicate_thread_deltas(self):
        report = ANALYZE.thread_report(*self.fixture())
        self.assertEqual(report['status'], 'PARTIAL_POLLED')
        self.assertEqual(len(report['instances']), 1)
        thread = report['instances'][0]
        self.assertEqual(thread['observations'], 2)
        self.assertEqual(len(thread['cgroup_views']), 2)
        self.assertEqual(thread['deltas']['utime'], 10)
        self.assertEqual(thread['deltas']['wait_ns'], 500)

    def test_disabled_wait_counter_is_null_not_zero(self):
        meta, stats, rows = self.fixture()
        for row in rows:
            for group in row['cgroups']:
                group['processes'][0]['tid_samples'][0].update(wait_counter_status='DISABLED_OR_UNKNOWN', wait_ns=None, timeslices=None)
        report = ANALYZE.thread_report(meta, stats, rows)
        self.assertIsNone(report['instances'][0]['deltas']['wait_ns'])
        self.assertEqual(report['instances'][0]['deltas']['utime'], 10)

    def test_reused_numeric_tid_is_a_different_instance(self):
        meta, stats, rows = self.fixture()
        for group in rows[1]['cgroups']:
            group['processes'][0]['tid_samples'][0]['identity']['thread_start_ticks'] = 9
        report = ANALYZE.thread_report(meta, stats, rows)
        self.assertEqual(len(report['instances']), 2)
        self.assertTrue(all(item['deltas']['utime'] is None for item in report['instances']))

    def test_foreign_boot_identity_not_correlated(self):
        meta, stats, rows = self.fixture()
        for group in rows[1]['cgroups']:
            group['processes'][0]['tid_samples'][0]['identity']['boot_id'] = 'other'
        report = ANALYZE.thread_report(meta, stats, rows)
        self.assertEqual(report['status'], 'PARTIAL_POLLED_WITH_GAPS')
        self.assertEqual(report['instances'][0]['observations'], 1)


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.campaign = {"campaign_id": "campaign", "status": "COMPLETE", "jobs": 2, "passes": 1,
                         "cache": "warm", "corpus_sha256": "b" * 64, "trials": []}
        for repetition in range(3):
            for mode in ("baseline", "sampler"):
                for concurrency in (1, 4):
                    duration = (2 if concurrency == 1 else 4) * 1e9
                    if mode == "sampler":
                        duration *= 1.1
                    self.campaign["trials"].append({"mode": mode, "concurrency": concurrency,
                        "repetition": repetition, "warmup": False, "makespan_ns": duration,
                        "path": "trials/{}-{}-{}".format(mode, concurrency, repetition),
                        "results": [{"task_id": "task-{}".format(i), "query_index": i,
                                     "exit_code": 0, "output_sha256": "a" * 64, "output_bytes": 10,
                                     "user_usec": 1000, "system_usec": 100, "completion_latency_ns": duration}
                                    for i in range(2)]})

    def test_paired_overhead_and_fixed_high_concurrency_reference(self):
        report = ANALYZE.campaign_report(self.campaign)
        self.assertEqual(report["output_equivalence"], "PASS")
        self.assertEqual(len(report["conditions"]), 4)
        for item in report["paired_overhead"]:
            self.assertEqual(item["relative_makespan"]["n"], 3)
            self.assertAlmostEqual(item["relative_makespan"]["mean"], 0.1)
            self.assertIsNotNone(item["relative_makespan"]["mean_ci95_bootstrap"])
        for item in report["paired_concurrency_interventions"]:
            self.assertEqual(item["reference_concurrency"], 4)
            self.assertEqual(item["intervention_concurrency"], 1)
            self.assertAlmostEqual(item["relative_makespan"]["mean"], -0.5)

    def test_warmups_excluded_and_pooled_tasks_not_independent_ci(self):
        trial = dict(self.campaign["trials"][0], makespan_ns=100000000000, warmup=True)
        self.campaign["trials"].append(trial)
        report = ANALYZE.campaign_report(self.campaign)
        for condition in report["conditions"]:
            self.assertEqual(condition["makespan_seconds"]["n"], 3)
            self.assertIsNone(condition["task_completion_latency_seconds"]["mean_ci95_bootstrap"])

    def test_insufficient_pairs_do_not_get_ci(self):
        self.campaign["trials"] = [trial for trial in self.campaign["trials"] if trial["repetition"] == 0]
        report = ANALYZE.campaign_report(self.campaign)
        self.assertIsNone(report["paired_overhead"][0]["relative_makespan"]["mean_ci95_bootstrap"])

    def test_output_mismatch_is_failure(self):
        self.campaign["trials"][-1]["results"][0]["output_sha256"] = "c" * 64
        report = ANALYZE.campaign_report(self.campaign)
        self.assertEqual(report["output_equivalence"], "FAIL")

    def test_query_distribution_changes_are_not_fixed_work(self):
        self.campaign["trials"][-1]["results"][0]["query_index"] = 1
        report = ANALYZE.campaign_report(self.campaign)
        self.assertEqual(report["output_equivalence"], "FAIL")
        self.assertIn("QUERY_ASSIGNMENT_CHANGED", {issue["code"] for issue in report["issues"]})

    def test_incomplete_work_does_not_pass(self):
        self.campaign["trials"][-1]["results"].pop()
        report = ANALYZE.campaign_report(self.campaign)
        self.assertEqual(report["output_equivalence"], "INDETERMINATE")

    def test_duplicate_repetition_does_not_inflate_sample_count(self):
        self.campaign["trials"].append(dict(self.campaign["trials"][0]))
        report = ANALYZE.campaign_report(self.campaign)
        self.assertEqual(report["conditions"][0]["makespan_seconds"]["n"], 3)
        self.assertIn("DUPLICATE_REPETITION", {issue["code"] for issue in report["issues"]})

    def test_malformed_trial_and_result_keep_other_conditions(self):
        self.campaign["trials"].append(None)
        self.campaign["trials"][0]["results"][0] = None
        report = ANALYZE.campaign_report(self.campaign)
        self.assertEqual(report["output_equivalence"], "INDETERMINATE")
        self.assertEqual(len(report["conditions"]), 4)
        self.assertIn("INVALID_CAMPAIGN_TRIAL", {issue["code"] for issue in report["issues"]})
        self.assertIn("INCOMPLETE_FIXED_WORK", {issue["code"] for issue in report["issues"]})

    def test_malformed_trial_list_is_incomplete_not_crash(self):
        self.campaign["trials"] = None
        report = ANALYZE.campaign_report(self.campaign)
        self.assertEqual(report["output_equivalence"], "INDETERMINATE")
        self.assertEqual(report["conditions"], [])
        self.assertIn("INVALID_CAMPAIGN_TRIALS", {issue["code"] for issue in report["issues"]})

    def test_report_writer_and_safe_links(self):
        self.campaign["trials"][0]["path"] = "javascript:alert(1)"
        with tempfile.TemporaryDirectory() as directory:
            report = ANALYZE.write_campaign_report(Path(directory), self.campaign)
            text = (Path(directory) / "campaign-report.html").read_text()
            self.assertNotIn('href="javascript:', text)
            self.assertIn("只降低并发", text)
            self.assertEqual(json.loads((Path(directory) / "campaign-report.json").read_text())["output_equivalence"], report["output_equivalence"])

    def test_calibration_identity_preserved_in_campaign_json_and_html(self):
        self.campaign["trials"] = [trial for trial in self.campaign["trials"] if trial["repetition"] == 0]
        for kind, label in (("cpu", "CPU"), ("sleep", "sleep 睡眠"), ("read", "read 文件读取")):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                self.campaign.update(calibration_kind=kind, calibration_seconds=0.4)
                report = ANALYZE.write_campaign_report(Path(directory), self.campaign)
                stored = json.loads((Path(directory) / "campaign-report.json").read_text())
                self.assertEqual(stored["fixed_work"]["calibration_kind"], kind)
                self.assertEqual(stored["fixed_work"]["calibration_seconds"], 0.4)
                text = (Path(directory) / "campaign-report.html").read_text()
                self.assertIn("<h1>" + label + "校准（不是搜索优化实验）</h1>", text)
                self.assertIn("空输出的一致性不能证明计量准确", text)
                self.assertIn("暂停握手", text)
                self.assertEqual(report["output_equivalence"], "PASS")

    @staticmethod
    def write_health_report(directory, trial, sampling="OBSERVED", status="COMPLETE_WITHIN_DECLARED_MEASUREMENT", issues=None, hist=None):
        path = directory / trial["path"] / "report.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        report = {"schema_version": 1, "run_id": trial.get("run_id"),
                  "config": {"mode": trial["mode"]}, "status": status,
                  "sampling_status": sampling, "issues": issues or [],
                  "kernel_hist": hist or {"enabled": False, "status": "NOT_COLLECTED", "issues": []}}
        path.write_text(json.dumps(report))
        return path

    def test_old_campaign_has_unknown_sampling_without_changing_output_pass(self):
        report = ANALYZE.campaign_report(self.campaign)
        health = report["observation_health"]
        self.assertEqual(report["output_equivalence"], "PASS")
        self.assertEqual(health["status"], "UNKNOWN")
        self.assertEqual(health["sampling"]["counts"]["UNKNOWN"], 6)
        self.assertEqual(health["sampling"]["counts"]["NOT_COLLECTED"], 6)
        self.assertEqual(health["sampling"]["counts"]["OBSERVED"], 0)
        self.campaign["trials"][2]["analysis_status"] = "INCOMPLETE"
        health = ANALYZE.campaign_report(self.campaign)["observation_health"]
        self.assertEqual(health["status"], "INCOMPLETE")
        self.assertIn("LEGACY_TRIAL_ANALYSIS_INCOMPLETE", {issue["code"] for issue in health["issues"]})

    def test_actual_process_sampling_gap_is_visible_and_output_stays_pass(self):
        fixture = AnalyzeTests()
        fixture.setUp()
        try:
            baseline, sampled = self.campaign["trials"][0], self.campaign["trials"][2]
            self.campaign["trials"] = [baseline, sampled]
            self.campaign["jobs"] = 1
            for trial in self.campaign["trials"]:
                trial["results"] = trial["results"][:1]
            sampled["run_id"] = fixture.run["run_id"]
            sampled["analysis_status"] = "COMPLETE_WITHIN_DECLARED_MEASUREMENT"
            root = Path(fixture.temp.name)
            fixture.directory = root / sampled["path"]
            (fixture.directory / "load").mkdir(parents=True)
            fixture.run["config"]["mode"] = "sampler"
            fixture.stats["vanished_processes"] = 1
            fixture.write()
            ANALYZE.write_report(fixture.directory)
            self.write_health_report(root, baseline, "NOT_COLLECTED", "TIMING_ONLY")
            report = ANALYZE.write_campaign_report(root, self.campaign)
            health = report["observation_health"]
            self.assertEqual(report["output_equivalence"], "PASS")
            self.assertEqual(health["status"], "INCOMPLETE")
            self.assertEqual(health["sampling"]["counts"]["INCOMPLETE"], 1)
            self.assertEqual(health["sampling"]["counts"]["NOT_COLLECTED"], 1)
            self.assertEqual(health["process_sampling_gap_trial_count"], 1)
            self.assertIn("PROCESS_SAMPLING_INCOMPLETE", {issue["code"] for issue in health["issues"]})
            self.assertEqual(health["trials"][1]["analysis_status"], "INCOMPLETE")
            self.assertEqual(health["trials"][1]["basis"], "SAVED_TRIAL_REPORT")
            self.assertIsNotNone(health["trials"][1]["source"]["sha256"])
            text = (root / "campaign-report.html").read_text()
            self.assertIn("观测完整度：<strong>INCOMPLETE</strong>", text)
            self.assertIn("PROCESS_SAMPLING_INCOMPLETE", text)
            self.assertIn("输出一致性：<strong>PASS</strong>", text)
        finally:
            fixture.tearDown()

    def test_probe_loss_is_independent_of_resource_sampling(self):
        self.campaign["trials"] = [self.campaign["trials"][2]]
        trial = self.campaign["trials"][0]
        trial["mode"] = "kernel-hist"
        issue = {"code": "KERNEL_HIST_RECURSION_MISSES", "location": "kh_sys_enter", "detail": "919"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_health_report(root, trial, status="INCOMPLETE", issues=[issue],
                                     hist={"enabled": True, "status": "INCOMPLETE", "issues": [issue]})
            report = ANALYZE.write_campaign_report(root, self.campaign)
            health = report["observation_health"]
            self.assertEqual(report["output_equivalence"], "PASS")
            self.assertEqual(health["status"], "INCOMPLETE")
            self.assertEqual(health["sampling"]["counts"]["OBSERVED"], 1)
            self.assertEqual(health["diagnostic"]["counts"]["INCOMPLETE"], 1)
            self.assertEqual(len(health["issues"]), 1)
            self.assertEqual(health["trials"][0]["diagnostic_issues"], [issue])

    def test_missing_report_cannot_turn_summary_complete_into_observed(self):
        self.campaign["trials"] = [self.campaign["trials"][2]]
        self.campaign["trials"][0]["analysis_status"] = "COMPLETE_WITHIN_DECLARED_MEASUREMENT"
        with tempfile.TemporaryDirectory() as directory:
            report = ANALYZE.write_campaign_report(Path(directory), self.campaign)
        self.assertEqual(report["output_equivalence"], "PASS")
        self.assertEqual(report["observation_health"]["status"], "UNKNOWN")
        self.assertEqual(report["observation_health"]["sampling"]["counts"]["OBSERVED"], 0)

    def test_trial_report_escape_and_symlink_escape_are_not_read(self):
        self.campaign["trials"] = [self.campaign["trials"][2]]
        trial = self.campaign["trials"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "campaign"
            root.mkdir()
            outside = Path(directory) / "outside"
            outside.mkdir()
            (outside / "report.json").write_text('{"schema_version":1,"sampling_status":"OBSERVED"}')
            (root / "escape").symlink_to(outside, target_is_directory=True)
            for path in ("../outside", str(outside), "escape"):
                with self.subTest(path=path):
                    trial["path"] = path
                    report = ANALYZE.write_campaign_report(root, self.campaign)
                    row = report["observation_health"]["trials"][0]
                    self.assertEqual(row["sampling_status"], "UNKNOWN")
                    self.assertIsNone(row["source"])
                    self.assertIn("TRIAL_REPORT_UNAVAILABLE_OR_INVALID", {issue["code"] for issue in row["issues"]})

    def test_different_run_report_cannot_prove_this_trial_complete(self):
        self.campaign["trials"] = [self.campaign["trials"][2]]
        trial = self.campaign["trials"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_health_report(root, trial)
            trial["run_id"] = "different-run"
            report = ANALYZE.write_campaign_report(root, self.campaign)
            self.assertEqual(report["output_equivalence"], "PASS")
            self.assertEqual(report["observation_health"]["sampling"]["status"], "UNKNOWN")
            self.assertIn("TRIAL_REPORT_IDENTITY_MISMATCH", {issue["code"] for issue in report["observation_health"]["issues"]})

    def test_oversized_trial_report_is_unknown_and_output_pass_is_preserved(self):
        self.campaign["trials"] = [self.campaign["trials"][2]]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.write_health_report(root, self.campaign["trials"][0])
            with path.open("wb") as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            report = ANALYZE.write_campaign_report(root, self.campaign)
            self.assertEqual(report["output_equivalence"], "PASS")
            self.assertEqual(report["observation_health"]["status"], "UNKNOWN")
            self.assertIsNone(report["observation_health"]["trials"][0]["source"])

    def test_malformed_trial_remains_in_observation_health_counts(self):
        self.campaign["trials"].append(None)
        health = ANALYZE.campaign_report(self.campaign)["observation_health"]
        self.assertEqual(health["trial_count"], 13)
        self.assertEqual(health["status"], "UNKNOWN")
        self.assertEqual(health["sampling"]["counts"]["UNKNOWN"], 7)
        self.assertIn("INVALID_CAMPAIGN_TRIAL", {issue["code"] for issue in health["issues"]})

    def test_warmup_gaps_are_not_hidden_by_measured_counts(self):
        self.campaign["trials"] = [self.campaign["trials"][2]]
        trial = self.campaign["trials"][0]
        trial["warmup"] = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            issue = {"code": "PROCESS_SAMPLING_INCOMPLETE", "location": "vanished_processes", "detail": "1"}
            self.write_health_report(root, trial, "INCOMPLETE", "INCOMPLETE", [issue])
            health = ANALYZE.write_campaign_report(root, self.campaign)["observation_health"]
            self.assertEqual(health["sampling"]["warmup_counts"]["INCOMPLETE"], 1)
            self.assertEqual(health["sampling"]["measured_counts"]["INCOMPLETE"], 0)
            self.assertEqual(health["process_sampling_gap_trial_count"], 1)
            self.assertEqual(health["status"], "INCOMPLETE")

    def test_campaign_queries_use_saved_validated_spans_not_task_time_division(self):
        evidence = {}
        for index, trial in enumerate(self.campaign['trials']):
            trial['run_id'] = 'run-{}'.format(index)
            evidence[index] = {'report': {'run_id': trial['run_id'],
                'config': {'mode': trial['mode'], 'concurrency': trial['concurrency']},
                'query_measurements': {'status': 'OBSERVED', 'expected_queries': 2, 'observed_queries': 2, 'queries': [
                {'measurement_status': 'OBSERVED', 'duration_ns': 17000000},
                {'measurement_status': 'OBSERVED', 'duration_ns': 17000000}]}}}
        report = ANALYZE.campaign_report(self.campaign, evidence)
        for condition in report['conditions']:
            self.assertEqual(condition['query_measurement_status'], 'OBSERVED')
            self.assertEqual(condition['logical_query_duration_seconds']['median'], 0.017)
            self.assertEqual(condition['logical_query_duration_seconds']['n'], 6)
            self.assertIsNone(condition['logical_query_duration_seconds']['mean_ci95_bootstrap'])
        legacy = ANALYZE.campaign_report(self.campaign)
        self.assertEqual(legacy['conditions'][0]['logical_query_duration_seconds']['n'], 0)
        self.assertEqual(legacy['conditions'][0]['query_measurement_status'], 'NOT_COLLECTED_OR_MIXED')
        evidence[0]['report']['run_id'] = 'foreign-run'
        mismatched = ANALYZE.campaign_report(self.campaign, evidence)
        condition = next(row for row in mismatched['conditions'] if row['mode'] == 'baseline' and row['concurrency'] == 1)
        self.assertEqual(condition['query_measurement_status'], 'INCOMPLETE')
        self.assertEqual(condition['logical_query_duration_seconds']['n'], 4)


if __name__ == "__main__":
    unittest.main()
