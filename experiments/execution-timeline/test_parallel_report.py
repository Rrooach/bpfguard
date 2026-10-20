"""Pure and tiny mocked eight-leaf tests; no VM, API, raw campaign, or deletion."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location("parallel_report_tested", HERE / "parallel_report.py")
parallel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(parallel)


def report(index=0):
    key, tool, agent = "boot:11:1", "job{}-tool".format(index), "job{}-agent".format(index)
    segment = {"begin_ns": 20, "end_ns": 40, "state": "ONCPU", "thread_key": key,
               "evidence": {"quality": "RECORDED_TRANSITIONS"}, "waker_key": "external:99:3"}
    return {"schema_version": 1, "run": {"run_id": "run{}".format(index), "boot_id": "boot",
        "clock": "CLOCK_MONOTONIC", "begin_ns": 10, "end_ns": 50},
        "tools": [{"tool_call_id": tool, "agent_id": agent, "task_id": "fixed-task",
            "root_key": key, "root": {"tid": 11, "birth_ns": 1}, "begin_ns": 20,
            "end_ns": 40, "invocation_ns": 15}],
        "threads": [{"key": key, "tid": 11, "tgid": 11, "birth_ns": 1,
            "process_birth_ns": 1, "agent_id": agent, "tool_call_id": tool,
            "parent_key": None, "begin_ns": 20, "end_ns": 40,
            "segments": [copy.deepcopy(segment)], "calls": [], "comm": "test"}],
        "health": {"status": "COMPLETE_FOR_SELECTED_HOOKS", "records": 4, "ring_drops": 0},
        "findings": [], "totals": {"events": 4, "threads": 1, "tools": 1},
        "critical_path": {"status": parallel.GOOD_PATH, "tools": [{"tool_call_id": tool,
            "status": parallel.GOOD_PATH, "wall_ns": 20, "unknown_ns": 0,
            "accounted_ns": 20, "segments": [copy.deepcopy(segment)],
            "state_totals_ns": {"ONCPU": 20}, "completion_seed_thread": key,
            "dependency_edges": [{"from_thread": key, "to_thread": "external:99:3"}]}]},
        "limitations": ["fixture limitation"]}


def descriptor(index, value):
    return {"job_id": "job{}".format(index), "verification": {"status": "REPLAY_PASSED",
        "manifest_identity": {"sha256": "a" * 64, "size_bytes": 100},
        "report_identity": {"sha256": "b" * 64, "size_bytes": 500},
        "report_semantic_sha256": parallel.semantic_sha256(value)}}


def merge_fixture():
    reports = [report(0), report(1)]
    return reports, [descriptor(i, item) for i, item in enumerate(reports)]


def campaign():
    jobs = [{"job_id": "job{}".format(i), "output": "/old/guest/jobs/job{}".format(i),
             "ready_ns": 12, "release_issued_ns": 14, "agent_return_ns": 40,
             "quiescent_ns": 42, "done_observed_ns": 45, "worker_exit_code": 0}
            for i in range(8)]
    return {"schema_version": 1, "benchmark": "fixture", "boot_id": "boot", "concurrency": 4,
            "total_jobs": 8, "jobs": jobs, "batch_start_ns": 14, "batch_end_ns": 42,
            "batch_wall_ns": 28, "campaign_start_ns": 5, "campaign_end_ns": 70,
            "campaign_wall_ns": 65, "status": "WORKERS_COMPLETED"}


class MergeTests(unittest.TestCase):
    def test_same_numeric_threads_and_processes_are_separate_leaf_instances(self):
        reports, jobs = merge_fixture()
        result = parallel.merge_reports(reports, jobs)
        self.assertEqual(result["authority"], parallel.AUTHORITY)
        self.assertEqual(len({item["key"] for item in result["threads"]}), 2)
        self.assertEqual(len({item["process_key"] for item in result["threads"]}), 2)
        self.assertEqual([item["tid"] for item in result["threads"]], [11, 11])
        self.assertEqual(result["run"]["begin_ns"], 10)
        self.assertEqual(result["run"]["end_ns"], 50)

    def test_sources_are_not_mutated_and_leaf_findings_health_are_preserved(self):
        reports, jobs = merge_fixture()
        reports[1]["health"] = {"status": "INCOMPLETE", "ring_drops": 5}
        reports[1]["findings"] = [{"kind": "COLLECTION_GAP", "thread": "boot:11:1"}]
        reports[1]["critical_path"]["status"] = "INCOMPLETE"
        jobs[1] = descriptor(1, reports[1])
        before = copy.deepcopy((reports, jobs))
        result = parallel.merge_reports(reports, jobs)
        self.assertEqual((reports, jobs), before)
        self.assertEqual(result["health"]["status"], "INCOMPLETE")
        self.assertEqual(result["critical_path"]["status"], "INCOMPLETE")
        self.assertEqual(result["leaves"][1]["health"], reports[1]["health"])
        self.assertEqual(result["leaves"][1]["findings"], reports[1]["findings"])
        self.assertEqual(result["findings"][0]["source_job_id"], "job1")

    def test_all_known_thread_references_are_namespaced_not_cross_linked(self):
        reports, jobs = merge_fixture()
        result = parallel.merge_reports(reports, jobs)
        for index in range(2):
            thread, tool, path = result["threads"][index], result["tools"][index], result["critical_path"]["tools"][index]
            self.assertEqual(tool["root_key"], thread["key"])
            self.assertEqual(path["completion_seed_thread"], thread["key"])
            self.assertEqual(path["segments"][0]["thread_key"], thread["key"])
            self.assertEqual(path["dependency_edges"][0]["from_thread"], thread["key"])
            self.assertEqual(path["dependency_edges"][0]["to_thread"],
                             parallel.namespace("job{}".format(index), "run{}".format(index), "external:99:3"))
            self.assertEqual(path["agent_id"], tool["agent_id"])

    def test_unowned_threads_are_not_assigned_to_the_job_agent(self):
        reports, jobs = merge_fixture()
        reports[1]["threads"][0].update(agent_id=None, tool_call_id=None)
        reports[1]["findings"].append({"kind": "THREAD_NOT_BOUND_TO_TOOL", "thread": "boot:11:1"})
        jobs[1] = descriptor(1, reports[1])
        result = parallel.merge_reports(reports, jobs)
        self.assertIsNone(result["threads"][1]["agent_id"])
        self.assertIsNone(result["threads"][1]["tool_call_id"])
        self.assertEqual(result["totals"]["unowned_thread_rows"], 1)
        self.assertEqual(result["leaves"][1]["unowned_thread_rows"], 1)

    def test_thread_durations_are_not_summed_as_composite_wall(self):
        reports, jobs = merge_fixture()
        result = parallel.merge_reports(reports, jobs)
        self.assertEqual(sum(item["wall_ns"] for item in result["critical_path"]["tools"]), 40)
        self.assertNotIn("wall_ns", result["totals"])
        self.assertIn("NOT_GLOBAL_DISTINCT", result["totals"]["scope"])

    def test_preferred_view_is_only_hint_and_none_invocation_is_not_guessed(self):
        reports, jobs = merge_fixture()
        reports[0]["tools"][0]["invocation_ns"] = None
        jobs[0] = descriptor(0, reports[0])
        result = parallel.merge_reports(reports, jobs)
        self.assertEqual(result["run"]["begin_ns"], 10)
        self.assertEqual(result["preferred_view"]["begin_ns"], 15)
        self.assertIsNone(result["tools"][0]["invocation_ns"])

    def test_mapping_input_and_job_order_are_explicit(self):
        reports, jobs = merge_fixture()
        result = parallel.merge_reports({"job1": reports[1], "job0": reports[0]}, jobs)
        self.assertEqual([leaf["job_id"] for leaf in result["leaves"]], ["job0", "job1"])

    def test_artifact_and_semantic_bindings_are_retained(self):
        reports, jobs = merge_fixture()
        leaf = parallel.merge_reports(reports, jobs)["leaves"][0]
        self.assertEqual(leaf["manifest_identity"], jobs[0]["verification"]["manifest_identity"])
        self.assertEqual(leaf["report_identity"], jobs[0]["verification"]["report_identity"])
        self.assertEqual(leaf["report_semantic_sha256"], parallel.semantic_sha256(reports[0]))

    def test_different_boot_or_clock_must_not_share_absolute_axis(self):
        for key, value in (("boot_id", "other-boot"), ("clock", "CLOCK_REALTIME")):
            reports, jobs = merge_fixture()
            reports[1]["run"][key] = value
            jobs[1] = descriptor(1, reports[1])
            with self.subTest(key=key), self.assertRaises(ValueError):
                parallel.merge_reports(reports, jobs)

    def test_tool_ids_must_be_unique_even_for_different_agents(self):
        reports, jobs = merge_fixture()
        reports[1]["tools"][0]["tool_call_id"] = reports[0]["tools"][0]["tool_call_id"]
        jobs[1] = descriptor(1, reports[1])
        with self.assertRaisesRegex(ValueError, "collision"):
            parallel.merge_reports(reports, jobs)

    def test_unverified_or_mismatched_report_cannot_be_composed(self):
        for mutate in (lambda job: job.pop("verification"),
                       lambda job: job["verification"].update(status="CACHED_JSON_ONLY"),
                       lambda job: job["verification"].update(report_semantic_sha256="a" * 64),
                       lambda job: job["verification"]["manifest_identity"].update(sha256="not-a-digest")):
            reports, jobs = merge_fixture()
            mutate(jobs[0])
            with self.assertRaises(ValueError):
                parallel.merge_reports(reports, jobs)

    def test_duplicate_job_run_or_thread_keys_rejected(self):
        for change in ("job", "run", "thread"):
            reports, jobs = merge_fixture()
            if change == "job":
                jobs[1]["job_id"] = jobs[0]["job_id"]
            elif change == "run":
                reports[1]["run"]["run_id"] = reports[0]["run"]["run_id"]
                jobs[1] = descriptor(1, reports[1])
            else:
                reports[0]["threads"].append(copy.deepcopy(reports[0]["threads"][0]))
                jobs[0] = descriptor(0, reports[0])
            with self.subTest(change=change), self.assertRaises(ValueError):
                parallel.merge_reports(reports, jobs)


class CampaignTests(unittest.TestCase):
    def test_batch_wall_and_full_campaign_wall_are_separate(self):
        result = parallel.campaign_wall(campaign())
        self.assertEqual(result["batch_wall_ns"], 28)
        self.assertEqual(result["campaign_wall_ns"], 65)
        self.assertEqual(result["status"], "COMPLETE")

    def test_return_wall_and_management_tail_are_explicit_not_summed(self):
        value = campaign()
        value.update(agent_return_end_ns=40, agent_return_batch_wall_ns=26)
        result = parallel.campaign_wall(value)
        self.assertEqual(result["agent_return_batch_wall_ns"], 26)
        self.assertEqual(result["last_agent_return_to_last_quiescence_ns"], 2)
        self.assertIn("NOT_SUM", result["management_tail_scope"])
        value["agent_return_batch_wall_ns"] = 25
        with self.assertRaisesRegex(ValueError, "Agent-return wall"):
            parallel.campaign_wall(value)

    def test_old_campaign_without_explicit_return_boundary_stays_unknown(self):
        result = parallel.campaign_wall(campaign())
        self.assertIsNone(result["agent_return_batch_wall_ns"])
        self.assertIsNone(result["last_agent_return_to_last_quiescence_ns"])

    def test_missing_work_bad_wall_or_boolean_cannot_pass(self):
        for key, value in (("total_jobs", 4), ("concurrency", True),
                           ("batch_wall_ns", 65), ("campaign_wall_ns", 28)):
            value_campaign = campaign()
            value_campaign[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                parallel.campaign_wall(value_campaign)

    def test_worker_failure_is_retained_not_green(self):
        value = campaign()
        value["jobs"][3]["worker_exit_code"] = 2
        self.assertEqual(parallel.campaign_wall(value)["status"], "INCOMPLETE")

    def make_campaign(self, root):
        value = campaign()
        for job in value["jobs"]:
            job["ready_metadata"] = {"cgroup_id": 77, "cgroup_root": "/sys/fs/cgroup/test"}
        (root / "campaign.json").write_text(json.dumps(value))
        for job in value["jobs"]:
            output = root / "jobs" / job["job_id"]
            (output / "timeline").mkdir(parents=True)
            (output / "timeline" / "manifest.json").write_text('{}\n')
            worker = {"schema_version": 1, "benchmark": "fixture", "job_id": job["job_id"],
                      "task_id": "fixed-task", "mode": "ORACLE_REFERENCE", "timeline_directory": "timeline",
                      "official_passed": True, "official_result": {"reward": 1},
                      "agent_return_ns": 40, "quiescent_ns": 42, "capture_status": "CAPTURED"}
            (output / "worker-result.json").write_text(json.dumps(worker))
            control = root / "control" / job["job_id"]
            control.mkdir(parents=True)
            for phase, after in (("before", False), ("after", True)):
                snapshot = resource_snapshot(after)
                snapshot.update(begin_ns=43 if after else 16, end_ns=44 if after else 17)
                (control / ("resources-" + phase + ".json")).write_text(json.dumps(snapshot))
        return value

    def test_guest_absolute_paths_are_rebased_by_bound_job_basename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = self.make_campaign(root)
            output, timeline, worker = parallel.resolve_job(root, value["jobs"][0])
            self.assertEqual(output, root / "jobs" / "job0")
            self.assertEqual(timeline, output / "timeline")
            self.assertEqual(worker["job_id"], "job0")

    def test_unsafe_output_worker_mismatch_and_timeline_escape_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = self.make_campaign(root)
            job = value["jobs"][0]
            for bad in ("/old/jobs/other", "/old/notjobs/job0", "/old/jobs/../job0"):
                with self.subTest(output=bad), self.assertRaises(ValueError):
                    parallel.resolve_job(root, {**job, "output": bad})
            path = root / "jobs/job0/worker-result.json"
            worker = json.loads(path.read_text())
            for field, bad in (("job_id", "other"), ("timeline_directory", "../job1/timeline"),
                               ("timeline_directory", "/absolute")):
                path.write_text(json.dumps({**worker, field: bad}))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    parallel.resolve_job(root, job)

    def test_mock_eight_leaf_cli_replays_each_and_writes_html_csv_receipts(self):
        import replay
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_campaign(root)
            output = root / "report-001"
            def verify(path, collector, expected_manifest_sha256):
                self.assertEqual(len(expected_manifest_sha256), 64)
                self.assertEqual(collector, Path("decoder-pinned"))
                return report(int(path.parent.name[3:]))
            with mock.patch.object(replay, "verify_run", side_effect=verify) as checked:
                result = parallel.process_campaign(root, output, Path("decoder-pinned"))
            self.assertEqual(checked.call_count, 8)
            self.assertEqual(result["official_passed_jobs"], 8)
            self.assertEqual(result["independent_replay_passed_jobs"], 8)
            self.assertEqual(result["timing"]["batch_wall_ns"], 28)
            self.assertEqual(len((output / "jobs.csv").read_text().splitlines()), 9)
            self.assertTrue((output / "timeline.html").is_file())
            self.assertTrue((output / "index.html").is_file())
            self.assertEqual(len(list((output / "reports").glob('*/timeline.html'))), 8)
            self.assertEqual(len(list((output / "reports").glob('*/verification.json'))), 8)
            self.assertEqual(len(list((output / "reports").glob('*/reads/reads.csv'))), 8)
            self.assertEqual(len(json.loads((output / "timeline-report.json").read_text())["threads"]), 8)
            self.assertEqual(result["jobs"][0]["cpu_usage_usec"], 2000)
            self.assertEqual(result["jobs"][0]["resource_status"], "COMPLETE_FOR_DECLARED_BOUNDARY_FIELDS")
            self.assertTrue((output / "resources.csv").is_file())
            self.assertEqual(result["jobs"][0]["agent_return_to_quiescence_ns"], 2)
            self.assertEqual(result["display_projection"]["status"], "DISPLAY_ONLY_BOUNDED_PROJECTION")
            self.assertIn("完整合成JSON", (output / "index.html").read_text())
            with self.assertRaises(ValueError):
                parallel.process_campaign(root, output, Path("decoder-pinned"))

    def test_failed_raw_replay_never_produces_group_success_receipt(self):
        import replay
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_campaign(root)
            output = root / "report-001"
            with mock.patch.object(replay, "verify_run", side_effect=ValueError("raw mismatch")):
                with self.assertRaisesRegex(ValueError, "raw mismatch"):
                    parallel.process_campaign(root, output)
            self.assertFalse((output / "result.json").exists())

    def test_large_complete_composite_is_not_blocked_by_input_viewer_limit(self):
        import replay
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_campaign(root)
            output = root / "report-001"
            def verify(path, collector, expected_manifest_sha256):
                value = report(int(path.parent.name[3:]))
                value["threads"][0]["calls"] = [{"call_id": 20, "nr": 1, "name": "write",
                    "start_ns": 20, "end_ns": 21, "result": 0, "files": [], "padding": "x" * 8192}]
                return value
            with mock.patch.object(replay, "verify_run", side_effect=verify), \
                    mock.patch.object(parallel, "MAX_JSON_BYTES", 32768):
                result = parallel.process_campaign(root, output)
            complete = json.loads((output / "timeline-report.json").read_bytes())
            display = json.loads((output / "timeline-display.json").read_bytes())
            self.assertGreater((output / "timeline-report.json").stat().st_size, 32768)
            self.assertEqual(len(complete["threads"][0]["calls"][0]["padding"]), 8192)
            self.assertEqual(display["threads"][0]["calls"], [])
            self.assertEqual(result["display_projection"]["omitted_counts"]["calls"], 8)


class DisplayProjectionTests(unittest.TestCase):
    def composite(self):
        reports, jobs = merge_fixture()
        for value in reports:
            value["threads"][0]["calls"] = [{"call_id": 20, "name": "read", "start_ns": 20,
                "end_ns": 30, "files": [{"path": "/large/source"}], "extra": "x" * 200}]
        jobs = [descriptor(i, item) for i, item in enumerate(reports)]
        return parallel.merge_reports(reports, jobs)

    def test_display_is_explicit_and_keeps_source_unchanged_and_bound(self):
        value = self.composite()
        value["threads"][0].update(capture_observed_begin_ns=12,
            timeline_scope="CAPTURE_CONTEXT_OUTSIDE_EXECUTION_WINDOW", execution_window_intersection={
                "status": "EMPTY_PRE_EXEC_TOOL_SETUP", "begin_ns": None, "end_ns": None})
        original = copy.deepcopy(value)
        identity = {"sha256": "c" * 64, "size_bytes": 50000}
        view = parallel.display_projection(value, identity)
        self.assertEqual(value, original)
        self.assertEqual(view["display_projection"]["source_complete_report_identity"], identity)
        self.assertEqual(view["display_projection"]["omitted_counts"]["calls"], 2)
        self.assertEqual(view["display_projection"]["omitted_counts"]["threads"], 0)
        self.assertTrue(all(not thread["calls"] for thread in view["threads"]))
        self.assertEqual(view["health"], value["health"])
        self.assertEqual(view["critical_path"]["status"], value["critical_path"]["status"])
        self.assertEqual(view["threads"][0]["execution_window_intersection"],
                         value["threads"][0]["execution_window_intersection"])
        self.assertEqual(view["threads"][0]["timeline_scope"], "CAPTURE_CONTEXT_OUTSIDE_EXECUTION_WINDOW")

    def test_longest_intervals_are_selected_without_joining_omitted_gaps(self):
        value = self.composite()
        original_segments = [{"begin_ns": 20 + i, "end_ns": 21 + i, "state": "ONCPU" if i % 2 else "SLEEP"}
                             for i in range(20)]
        for thread in value["threads"]:
            thread["segments"] = copy.deepcopy(original_segments)
        view = parallel.display_projection(value, {"sha256": "c" * 64, "size_bytes": 50000}, budget=12000)
        self.assertLessEqual(len(json.dumps(view, ensure_ascii=False).encode()), 12000)
        self.assertEqual({thread["source_job_id"] for thread in view["threads"]}, {"job0", "job1"})
        self.assertGreater(view["display_projection"]["omitted_counts"]["thread_segments"], 0)
        originals = {(segment["begin_ns"], segment["end_ns"], segment["state"]) for segment in original_segments}
        self.assertTrue(all((segment["begin_ns"], segment["end_ns"], segment["state"]) in originals
            for thread in view["threads"] for segment in thread["segments"]))

    def test_findings_subset_counts_do_not_turn_incomplete_green(self):
        value = self.composite()
        value["health"]["status"] = "INCOMPLETE"
        value["findings"] = [{"kind": "ORIGINAL_GAP", "index": i} for i in range(70)]
        view = parallel.display_projection(value, {"sha256": "c" * 64, "size_bytes": 50000})
        self.assertEqual(view["health"]["status"], "INCOMPLETE")
        self.assertEqual(view["display_projection"]["omitted_counts"]["findings"], 6)

    def test_render_projection_never_calls_its_embedded_subset_full_json(self):
        import render
        view = parallel.display_projection(self.composite(), {"sha256": "c" * 64, "size_bytes": 50000})
        page = render.render_report(view)
        self.assertIn('DISPLAY_ONLY_BOUNDED_PROJECTION', page)
        self.assertIn('href="timeline-report.json"', page)
        self.assertIn('下载当前显示投影 JSON', page)
        self.assertNotIn('下载完整 JSON</button>', page)
        self.assertNotIn('execution-timeline-full.json', page)
        view["display_projection"]["index_href"] = "javascript:alert(1)"
        with self.assertRaisesRegex(ValueError, "navigation"):
            render.render_report(view)

    def test_navigation_links_every_saved_leaf_table_and_receipt_without_directory_listing(self):
        view = parallel.display_projection(self.composite(), {"sha256": "c" * 64, "size_bytes": 50000})
        page = parallel.navigation_index(view)
        for job in ('job0', 'job1'):
            for relative in ('timeline.html', 'report.json', 'reads/reads.csv', 'reads/files.csv',
                             'reads/excluded-reads.csv', 'reads/unassigned-reads.csv', 'reads/receipt.json',
                             'summary.json', 'resources.json', 'verification.json', 'acceptance.json'):
                self.assertIn('href="reports/{}/{}"'.format(job, relative), page)


def resource_snapshot(after=False):
    cpu = {"usage_usec": 3000 if after else 1000, "user_usec": 2000 if after else 700,
           "system_usec": 1000 if after else 300, "nr_periods": 10, "nr_throttled": 0, "throttled_usec": 0}
    memory = {"pgfault": 60 if after else 10, "pgmajfault": 2 if after else 0,
              "workingset_refault_file": 5 if after else 1, "workingset_refault_anon": 0,
              "pgscan": 0, "pgsteal": 0, "anon": 500, "file": 1000, "kernel": 200, "slab": 50}
    files = {"cpu.stat": ''.join('{} {}\n'.format(k, v) for k, v in cpu.items()),
             "memory.stat": ''.join('{} {}\n'.format(k, v) for k, v in memory.items()),
             "memory.current": "2000\n", "memory.peak": "10000\n", "pids.current": "1\n", "pids.events": "max 0\n",
             "io.stat": "8:0 rbytes={} wbytes={} rios=4 wios=1\n".format(5100 if after else 100, 30 if after else 10)}
    for domain in ("cpu", "memory", "io"):
        files[domain + ".pressure"] = "some avg10=0.00 total={}\nfull avg10=0.00 total={}\n".format(
            110 if after else 10, 20 if after else 0)
    return {"status": "CAPTURED_BOUNDARY_COUNTERS", "begin_ns": 40 if after else 10,
            "end_ns": 41 if after else 11, "cgroup_id": 77, "cgroup_root": "/sys/fs/cgroup/test",
            "files": files, "errors": {}}


class ResourceTests(unittest.TestCase):
    def test_known_boundary_counters_and_gauges_do_not_invent_window_peak(self):
        before, after = resource_snapshot(), resource_snapshot(True)
        result = parallel.resource_delta(before, after, 77)
        self.assertEqual(result["status"], "COMPLETE_FOR_DECLARED_BOUNDARY_FIELDS")
        self.assertEqual(result["counters"]["cpu.stat.usage_usec"]["delta"], 2000)
        self.assertEqual(result["counters"]["memory.stat.pgfault"]["delta"], 50)
        self.assertEqual(result["counters"]["io.stat.listed_devices_sum.rbytes"]["delta"], 5000)
        self.assertEqual(result["counters"]["cpu.pressure.some.total_usec"]["delta"], 100)
        self.assertEqual(result["gauges"]["memory.peak"], {"before": 10000, "after": 10000})
        self.assertIn("NOT_THIS_WINDOW_PEAK", result["memory_peak_scope"])
        self.assertNotIn("wall_ns", result)

    def test_reset_is_unknown_never_negative_valid_delta(self):
        before, after = resource_snapshot(), resource_snapshot(True)
        after["files"]["cpu.stat"] = after["files"]["cpu.stat"].replace("usage_usec 3000", "usage_usec 500")
        result = parallel.resource_delta(before, after, 77)
        self.assertIsNone(result["counters"]["cpu.stat.usage_usec"]["delta"])
        self.assertEqual(result["counters"]["cpu.stat.usage_usec"]["status"], "UNKNOWN_COUNTER_RESET")
        self.assertEqual(result["counters"]["cpu.stat.user_usec"]["delta"], 1300)

    def test_missing_io_baseline_is_not_treated_as_zero(self):
        before, after = resource_snapshot(), resource_snapshot(True)
        before["files"]["io.stat"] = ""
        result = parallel.resource_delta(before, after, 77)
        self.assertIsNone(result["counters"]["io.stat.8:0.rbytes"]["delta"])
        self.assertIsNone(result["counters"]["io.stat.listed_devices_sum.rbytes"]["delta"])

    def test_absent_full_psi_missing_files_and_parser_errors_remain_unknown(self):
        before, after = resource_snapshot(), resource_snapshot(True)
        after["files"]["cpu.pressure"] = "some avg10=0.00 total=110\n"
        after["errors"]["memory.stat"] = "PermissionError"
        before["files"]["pids.events"] = "max not-an-integer\n"
        result = parallel.resource_delta(before, after, 77)
        for key in ("cpu.pressure.full.total_usec", "memory.stat.pgfault", "pids.events.max"):
            self.assertIsNone(result["counters"][key]["delta"])
        self.assertIn("PARTIAL", result["status"])

    def test_cgroup_change_or_unordered_snapshot_cannot_make_known_counts(self):
        for change in ("cgroup_id", "time", "missing"):
            before, after = resource_snapshot(), resource_snapshot(True)
            if change == "cgroup_id":
                after["cgroup_id"] = 88
            elif change == "time":
                after["begin_ns"] = 5
            else:
                before = None
            result = parallel.resource_delta(before, after, 77)
            self.assertTrue(all(value["delta"] is None for value in result["counters"].values()))
            self.assertTrue(result["issues"])


def group_result(concurrency, wall):
    return {"authority": parallel.AUTHORITY, "status": "INDEPENDENT_LEAF_REPORTS_COMPOSED", "total_jobs": 8,
            "timing": {"benchmark": "fixture", "concurrency": concurrency, "batch_wall_ns": wall,
                       "campaign_wall_ns": wall + 100, "status": "COMPLETE"},
            "resource_configuration": {"guest_cpus": 32, "guest_memory_gib": 64},
            "jobs": [{"task_id": "task{}".format(i % 2), "mode": "ORACLE_REFERENCE", "resource_status": "PARTIAL"}
                     for i in range(8)], "official_passed_jobs": 8, "independent_replay_passed_jobs": 8,
            "raw_health_statuses": ["COMPLETE_FOR_SELECTED_HOOKS"] * 7 + ["INCOMPLETE"],
            "critical_path_status": "INCOMPLETE"}


class ComparisonTests(unittest.TestCase):
    def test_2468_fixed_eight_jobs_primary_wall_and_failed_coverage_remain_separate(self):
        value = parallel.compare_groups([group_result(c, w) for c, w in ((8, 25), (4, 50), (2, 100), (6, 40))])
        self.assertTrue(value["concurrency_matrix_complete"])
        self.assertEqual([row["concurrency"] for row in value["groups"]], [2, 4, 6, 8])
        self.assertEqual(value["groups"][-1]["batch_speedup_vs_c2"], 4)
        self.assertEqual(value["groups"][-1]["official_passed_jobs"], 8)
        self.assertEqual(value["groups"][-1]["critical_path_status"], "INCOMPLETE")

    def test_different_work_count_task_multiset_or_resources_rejected(self):
        for mutation in (lambda item: item.update(total_jobs=4),
                         lambda item: item["jobs"][0].update(task_id="different"),
                         lambda item: item.update(resource_configuration={"guest_cpus": 8}),
                         lambda item: item["jobs"][0].update(task_id=None)):
            groups = [group_result(2, 100), group_result(4, 50)]
            mutation(groups[1])
            with self.assertRaises(ValueError):
                parallel.compare_groups(groups)

    def test_partial_matrix_has_no_false_complete_status(self):
        value = parallel.compare_groups([group_result(4, 50)])
        self.assertFalse(value["concurrency_matrix_complete"])
        self.assertEqual(value["status"], "PARTIAL_CONCURRENCY_COMPARISON")
        self.assertIsNone(value["groups"][0]["batch_speedup_vs_c2"])

    def test_official_failure_retains_wall_but_does_not_claim_equal_work_speedup(self):
        groups = [group_result(2, 100), group_result(4, 20)]
        groups[1]["official_passed_jobs"] = 7
        value = parallel.compare_groups(groups)
        self.assertEqual(value["groups"][1]["batch_wall_ns"], 20)
        self.assertEqual(value["groups"][1]["official_passed_jobs"], 7)
        self.assertIsNone(value["groups"][1]["batch_speedup_vs_c2"])

    def test_missing_resource_configuration_is_not_a_matching_known_configuration(self):
        groups = [group_result(2, 100), group_result(4, 20)]
        for value in groups:
            value["resource_configuration"] = None
        with self.assertRaises(ValueError):
            parallel.compare_groups(groups)


if __name__ == "__main__":
    unittest.main()
