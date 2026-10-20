#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import tempfile
import unittest

from replay import Symbols, build_report, load_events

BOOT = "test-boot"
PARENT = {"tid": 10, "tgid": 10, "thread_birth_ns": 100, "process_birth_ns": 100, "comm": "shell"}
CHILD = {"tid": 20, "tgid": 20, "thread_birth_ns": 200, "process_birth_ns": 200, "comm": "grep"}


def events(rows):
    exited = set()
    for row in rows:
        key = (row["task"]["tid"], row["task"]["thread_birth_ns"])
        if row["event"] == "EXIT":
            exited.add(key)
        elif row["event"] == "SWITCH_OUT" and key in exited:
            row.setdefault("prev_state", 0x80)
    return [{"schema_version": 1, "cpu": 0, "cpu_seq": index + 1, "root_cgroup_id": 9,
             "caller_cgroup_id": 11, **row} for index, row in enumerate(rows)]


def ev(kind, time, task=PARENT, **extra):
    return {"event": kind, "timestamp_ns": time, "task": task, **extra}


def manifest(end=1000):
    return {"schema_version": 1, "run_id": "r", "boot_id": BOOT, "begin_ns": 0, "end_ns": end,
            "scope": {"kind": "COOPERATIVE_DIRECT_CGROUP_DESCENDANTS"},
            "tools": [{"agent_id": "agent-A", "task_id": "search", "tool_call_id": "search-1",
                       "begin_ns": 10, "end_ns": end, "cgroup_id": 11,
                       "root": {"tid": 10, "birth_ns": 100}}]}


class ReplayTests(unittest.TestCase):
    def basic(self):
        return events([ev("SWITCH_OUT", 1, state="STOPPED"), ev("WAKEUP", 10), ev("SWITCH_IN", 20),
                       ev("SYSCALL_ENTER", 30, syscall_call_id=30, syscall_nr=0, args=[3, 0, 4096]),
                       ev("FILE_OBJECT", 31, syscall_call_id=30,
                          file={"mount_id": 1, "device": 2, "inode": 3, "generation": 4,
                                "path": "/src/a.c", "path_quality": "KERNEL_D_PATH"}),
                       ev("SWITCH_OUT", 40, state="SLEEP_D", syscall_call_id=30,
                          kernel_stack=["filemap_get_pages", "folio_wait_bit_common"]),
                       ev("WAKEUP", 80), ev("SWITCH_IN", 90),
                       ev("FILE_READ", 99, syscall_call_id=30, start_ns=31, end_ns=99,
                          returned_bytes=16, requested_bytes=4096, result=16,
                          file={"mount_id": 1, "device": 2, "inode": 3, "generation": 4}),
                       ev("SYSCALL_EXIT", 100, syscall_call_id=30, syscall_nr=0, result=16),
                       ev("EXIT", 998), ev("SWITCH_OUT", 999, state="SLEEP_D")])

    def test_exact_scheduler_intervals_and_file(self):
        report = build_report(self.basic(), manifest(), {})
        thread = report["threads"][0]
        sleep = next(s for s in thread["segments"] if s["begin_ns"] == 40)
        self.assertEqual((sleep["end_ns"], sleep["state"]), (80, "SLEEP"))
        self.assertEqual(sleep["files"][0]["path"], "/src/a.c")
        self.assertEqual(sleep["syscall"]["result"], 16)
        self.assertIn("页缓存", sleep["reason"])
        totals = report["critical_path"]["tools"][0]["state_totals_ns"]
        self.assertEqual(totals["RUNNABLE"], 20)
        self.assertEqual(totals["SLEEP"], 40)
        self.assertEqual(sum(totals.values()), 990)

    def test_wait4_follows_only_proven_child(self):
        rows = self.wait4_rows()
        report = build_report(events(rows), manifest(200), {})
        path = report["critical_path"]["tools"][0]
        self.assertEqual(len(path["dependency_edges"]), 2)
        self.assertEqual(path["state_totals_ns"]["ONCPU"], 148)
        self.assertEqual(sum(path["state_totals_ns"].values()), 190)
        child = next(t for t in report["threads"] if t["tid"] == 20)
        self.assertEqual(child["tool_call_id"], "search-1")
        # A time-correlated but wrong child must not become a dependency.
        rows[12]["result"] = 21
        negative = build_report(events(rows), manifest(200), {})
        self.assertEqual(negative["critical_path"]["tools"][0]["dependency_edges"], [])

    def wait4_rows(self):
        rows = [ev("SWITCH_OUT", 1, state="STOPPED"), ev("WAKEUP", 10), ev("SWITCH_IN", 11),
                ev("FORK", 20, CHILD, peer=PARENT), ev("WAKEUP", 21, CHILD),
                ev("SYSCALL_ENTER", 30, syscall_call_id=30, syscall_nr=61, args=[20, 0, 0, 0]),
                ev("SWITCH_OUT", 40, state="SLEEP_S", syscall_call_id=30), ev("SWITCH_IN", 50, CHILD),
                ev("EXIT", 99, CHILD), ev("WAKEUP", 100, peer=CHILD),
                ev("SWITCH_OUT", 102, CHILD, state="SLEEP_D"), ev("SWITCH_IN", 110),
                ev("SYSCALL_EXIT", 120, syscall_call_id=30, syscall_nr=61, result=20),
                ev("EXIT", 198), ev("SWITCH_OUT", 199, state="SLEEP_D")]
        return rows

    def test_same_child_wake_before_exit_is_not_an_exit_wait_dependency(self):
        for remote in (False, True):
            with self.subTest(remote=remote):
                rows = self.wait4_rows()
                wakeup = next(row for row in rows if row["event"] == "WAKEUP" and row["timestamp_ns"] == 100)
                if remote:
                    # The remote target is enqueued after EXIT, but the source
                    # woke it earlier for another reason. Use source handoff,
                    # not target delivery, to validate an exit dependency.
                    rows.append(ev("WAKING", 90, peer=CHILD))
                    wakeup.update(wake_attempt_ns=90, peer={"tid": 0})
                else:
                    wakeup["timestamp_ns"] = 90
                rows.sort(key=lambda row: row["timestamp_ns"])
                report = build_report(events(rows), manifest(200), {})
                path = report["critical_path"]["tools"][0]
                self.assertEqual(path["dependency_edges"], [],
                    "a later successful wait4 result does not prove this pre-exit wake was an exit wake")
                self.assertEqual(sum(path["state_totals_ns"].values()), 190)
                self.assertFalse(any(part.get("thread_key", "").split(":")[-2] == "20" for part in path["segments"]))

    def test_transport_gap_not_green(self):
        rows = self.basic()
        rows[4]["cpu_seq"] += 5
        report = build_report(rows, manifest(), {})
        self.assertEqual(report["critical_path"]["status"], "INCOMPLETE")
        self.assertEqual(report["threads"][0]["segments"][0]["evidence"]["quality"], "GAPPED_TRACE_CANDIDATE_ONLY")

    def test_health_drop_not_green(self):
        report = build_report(self.basic(), manifest(), {"cpu_totals": [{"ring_lost": 1}]})
        self.assertEqual(report["critical_path"]["status"], "INCOMPLETE")

    def test_pid_reuse_does_not_merge(self):
        rows = self.basic()
        replacement = {**PARENT, "thread_birth_ns": 900}
        rows += events([ev("SWITCH_IN", 1200, replacement)])
        for index, row in enumerate(rows):
            row["cpu_seq"] = index + 1
        report = build_report(rows, manifest(1500), {})
        self.assertEqual(len(report["threads"]), 2)
        self.assertIsNone(next(t for t in report["threads"] if t["birth_ns"] == 900)["tool_call_id"])

    def test_cgroup_shared_is_not_tool_attribution(self):
        other = {**CHILD, "thread_birth_ns": 501}
        rows = self.basic() + events([ev("SWITCH_IN", 500, other)])
        for index, row in enumerate(rows):
            row["cpu_seq"] = index + 1
        report = build_report(rows, manifest(), {})
        self.assertIsNone(next(t for t in report["threads"] if t["tid"] == 20)["tool_call_id"])

    def test_no_file_from_time_proximity(self):
        rows = self.basic()
        rows[4]["syscall_call_id"] = 777
        report = build_report(rows, manifest(), {})
        self.assertNotIn("path", report["threads"][0]["calls"][0]["files"][0])

    def test_unknown_first_interval_retained(self):
        rows = events([ev("SWITCH_IN", 50), ev("EXIT", 98), ev("SWITCH_OUT", 99, state="SLEEP_D")])
        report = build_report(rows, manifest(100), {})
        self.assertEqual(report["critical_path"]["status"], "INCOMPLETE")
        self.assertEqual(report["critical_path"]["tools"][0]["unknown_ns"], 40)

    def test_tick_enrollment_requires_cgroup_before_gate(self):
        data = manifest()
        data["tools"][0]["root"] = {"tid": 10, "start_ticks": 0, "clock_ticks": 100}
        self.assertIsNotNone(build_report(self.basic(), data, {})["tools"][0]["root_key"])
        data["tools"][0]["cgroup_id"] = 999
        self.assertIsNone(build_report(self.basic(), data, {})["tools"][0]["root_key"])

    def test_truncated_json_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text('{"schema_version":1}')
            with self.assertRaisesRegex(ValueError, "truncated"):
                load_events(path)

    def test_symbols_empty_addresses_stay_unresolved(self):
        self.assertEqual(Symbols().resolve([0x1234]), ["0x1234"])

    def test_duplicate_tool_identity_rejected(self):
        data = manifest()
        data["tools"].append(copy.deepcopy(data["tools"][0]))
        with self.assertRaisesRegex(ValueError, "unique"):
            build_report(self.basic(), data, {})

    def test_post_run_identity_cannot_create_inverted_lane(self):
        late = {**CHILD, "thread_birth_ns": 5000}
        rows = self.basic() + [{**ev("SWITCH_IN", 2000, late), "cpu": 0, "cpu_seq": len(self.basic()) + 1}]
        report = build_report(rows, manifest(), {})
        self.assertEqual(len(report["threads"]), 1)
        self.assertEqual(report["totals"]["outside_run_window_events"], 1)

    def test_cross_boot_event_rejected(self):
        rows = self.basic()
        rows[0]["boot_id"] = "different-boot"
        with self.assertRaisesRegex(ValueError, "boot identity"):
            build_report(rows, manifest(), {})

    def test_disclosed_pre_enrollment_return_not_fabricated_call(self):
        rows = events([ev("SYSCALL_EXIT", 2, syscall_call_id=0, syscall_nr=1, return_value=4, boundary_return=True),
                       ev("SWITCH_OUT", 3, state="STOPPED"), ev("WAKEUP", 10), ev("SWITCH_IN", 20),
                       ev("EXIT", 98), ev("SWITCH_OUT", 99, state="SLEEP_D")])
        report = build_report(rows, manifest(100), {})
        self.assertEqual(report["threads"][0]["calls"], [])
        self.assertFalse(any(f["kind"] == "ORPHAN_SYSCALL_EXIT" for f in report["findings"]))

    def test_backwards_completion_chooses_later_parallel_child_not_first_wait(self):
        b = {**CHILD, "tid": 30, "tgid": 30, "thread_birth_ns": 300, "process_birth_ns": 300, "comm": "B"}
        rows = [ev("SWITCH_OUT", 1, state="STOPPED"), ev("WAKEUP", 10), ev("SWITCH_IN", 11),
                ev("FORK", 20, CHILD, peer=PARENT), ev("WAKEUP", 21, CHILD),
                ev("FORK", 25, b, peer=PARENT), ev("WAKEUP", 26, b),
                ev("SYSCALL_ENTER", 30, syscall_call_id=30, syscall_nr=61),
                ev("SWITCH_OUT", 40, state="SLEEP_S", syscall_call_id=30), ev("SWITCH_IN", 50, CHILD),
                ev("SWITCH_IN", 60, b), ev("EXIT", 99, CHILD), ev("WAKEUP", 100, peer=CHILD),
                ev("SWITCH_OUT", 101, CHILD, state="SLEEP_D"), ev("SWITCH_IN", 110),
                ev("SYSCALL_EXIT", 115, syscall_call_id=30, syscall_nr=61, result=20),
                ev("SYSCALL_ENTER", 120, syscall_call_id=120, syscall_nr=61),
                ev("SWITCH_OUT", 130, state="SLEEP_S", syscall_call_id=120),
                ev("EXIT", 229, b), ev("WAKEUP", 230, peer=b), ev("SWITCH_OUT", 231, b, state="SLEEP_D"),
                ev("SWITCH_IN", 240), ev("SYSCALL_EXIT", 250, syscall_call_id=120, syscall_nr=61, result=30),
                ev("EXIT", 298), ev("SWITCH_OUT", 299, state="SLEEP_D")]
        report = build_report(events(rows), manifest(300), {})
        path = report["critical_path"]["tools"][0]
        self.assertTrue(any(s["thread_key"].split(":")[-2] == "30" for s in path["segments"]))
        self.assertFalse(any(s["thread_key"].split(":")[-2] == "20" for s in path["segments"]))
        self.assertEqual(path["state_totals_ns"].get("SLEEP", 0), 0)
        self.assertEqual(sum(path["state_totals_ns"].values()), 290)

    def test_incomplete_trace_never_builds_wait_dependency(self):
        rows = events([ev("SWITCH_OUT", 1, state="STOPPED"), ev("WAKEUP", 10), ev("SWITCH_IN", 11),
                       ev("FORK", 20, CHILD, peer=PARENT), ev("WAKEUP", 21, CHILD),
                       ev("SYSCALL_ENTER", 30, syscall_call_id=30, syscall_nr=61),
                       ev("SWITCH_OUT", 40, state="SLEEP_S", syscall_call_id=30), ev("SWITCH_IN", 50, CHILD),
                       ev("EXIT", 99, CHILD), ev("WAKEUP", 100, peer=CHILD),
                       ev("SWITCH_OUT", 102, CHILD, state="SLEEP_D"), ev("SWITCH_IN", 110),
                       ev("SYSCALL_EXIT", 120, syscall_call_id=30, syscall_nr=61, result=20)])
        result = build_report(rows, manifest(200), {"ring_drops": 1})
        self.assertEqual(result["critical_path"]["tools"][0]["dependency_edges"], [])

    def test_sigreturn_restored_register_is_not_an_errno_or_ordinary_return(self):
        rows = events([ev("SWITCH_OUT", 1, state="STOPPED"), ev("WAKEUP", 10), ev("SWITCH_IN", 11),
                       ev("SYSCALL_ENTER", 20, syscall_call_id=20, syscall_nr=15),
                       ev("SYSCALL_EXIT", 30, syscall_call_id=20, syscall_nr=-1, syscall_entry_nr=15,
                          sigreturn_restored=True, closure_kind="SIGNAL_FRAME_RESTORED_NOT_ORDINARY_RETURN",
                          return_value=None, restored_register_value=-13),
                       ev("EXIT", 98), ev("SWITCH_OUT", 99, state="SLEEP_D")])
        report = build_report(rows, manifest(100), {})
        call = report["threads"][0]["calls"][0]
        self.assertIsNone(call["result"])
        self.assertEqual(call["restored_register_value"], -13)
        self.assertEqual(call["pairing"], "SIGNAL_FRAME_RESTORED_NOT_ORDINARY_RETURN")
        self.assertFalse(any(f["kind"] == "SYSCALL_NUMBER_MISMATCH" for f in report["findings"]))

    def test_container_wait4_uses_explicit_parent_clone_result_not_host_pid(self):
        rows = [ev("SWITCH_OUT", 1, state="STOPPED"), ev("WAKEUP", 10), ev("SWITCH_IN", 11),
                ev("SYSCALL_ENTER", 15, syscall_call_id=15, syscall_nr=56),
                ev("FORK", 20, CHILD, peer=PARENT, fork_parent_call_id=15, fork_parent_syscall_nr=56),
                ev("WAKEUP", 21, CHILD), ev("SYSCALL_EXIT", 22, syscall_call_id=15, syscall_nr=56, result=5),
                ev("SYSCALL_ENTER", 30, syscall_call_id=30, syscall_nr=61),
                ev("SWITCH_OUT", 40, state="SLEEP_S", syscall_call_id=30), ev("SWITCH_IN", 50, CHILD),
                ev("EXIT", 99, CHILD), ev("WAKEUP", 100, peer=CHILD),
                ev("SWITCH_OUT", 102, CHILD, state="SLEEP_D"), ev("SWITCH_IN", 110),
                ev("SYSCALL_EXIT", 120, syscall_call_id=30, syscall_nr=61, result=5),
                ev("EXIT", 198), ev("SWITCH_OUT", 199, state="SLEEP_D")]
        data = manifest(200)
        data["scope"]["kind"] = "DOCKER_GATED_EXEC"
        report = build_report(events(rows), data, {})
        self.assertTrue(any("WAIT4" in e["basis"] for e in report["critical_path"]["tools"][0]["dependency_edges"]))
        child = next(t for t in report["threads"] if t["tid"] == 20)
        self.assertEqual(child["visible_pid_to_parent"], 5)
        rows[4].pop("fork_parent_call_id")
        negative = build_report(events(rows), data, {})
        self.assertEqual(negative["critical_path"]["tools"][0]["dependency_edges"], [])

    def test_thread_join_requires_matching_exit_clear_child_tid_address(self):
        sibling = {**CHILD, "tgid": 10, "process_birth_ns": 100}
        rows = [ev("SWITCH_OUT", 1, state="STOPPED"), ev("WAKEUP", 10), ev("SWITCH_IN", 11),
                ev("FORK", 20, sibling, peer=PARENT), ev("WAKEUP", 21, sibling),
                ev("SYSCALL_ENTER", 30, syscall_call_id=30, syscall_nr=202, args=[0x1234, 265, 20]),
                ev("SWITCH_OUT", 40, state="SLEEP_S", syscall_call_id=30), ev("SWITCH_IN", 50, sibling),
                ev("EXIT", 99, sibling, clear_child_tid=0x1234), ev("WAKEUP", 100, peer=sibling),
                ev("SWITCH_OUT", 102, sibling, state="SLEEP_D"), ev("SWITCH_IN", 110),
                ev("SYSCALL_EXIT", 120, syscall_call_id=30, syscall_nr=202, result=0),
                ev("EXIT", 198), ev("SWITCH_OUT", 199, state="SLEEP_D")]
        report = build_report(events(rows), manifest(200), {})
        self.assertTrue(any("CLEAR_CHILD_TID" in e["basis"] for e in report["critical_path"]["tools"][0]["dependency_edges"]))
        rows[8]["clear_child_tid"] = 0x9999
        negative = build_report(events(rows), manifest(200), {})
        self.assertEqual(negative["critical_path"]["tools"][0]["dependency_edges"], [])

    def test_remote_wakeup_links_explicit_source_not_idle_context(self):
        sibling = {**CHILD, "tgid": 10, "process_birth_ns": 100}
        rows = [ev("SWITCH_OUT", 1, state="STOPPED"), ev("WAKEUP", 10), ev("SWITCH_IN", 11),
                ev("FORK", 20, sibling, peer=PARENT), ev("WAKEUP", 21, sibling),
                ev("SYSCALL_ENTER", 30, syscall_call_id=30, syscall_nr=202, args=[0x1234, 265, 20]),
                ev("SWITCH_OUT", 40, state="SLEEP_S", syscall_call_id=30), ev("SWITCH_IN", 50, sibling),
                ev("EXIT", 98, sibling, clear_child_tid=0x1234), ev("WAKING", 99, peer=sibling),
                ev("WAKEUP", 100, peer={"tid": 0}, wake_attempt_ns=99),
                ev("SWITCH_OUT", 102, sibling, state="SLEEP_D"), ev("SWITCH_IN", 110),
                ev("SYSCALL_EXIT", 120, syscall_call_id=30, syscall_nr=202, result=0),
                ev("EXIT", 198), ev("SWITCH_OUT", 199, state="SLEEP_D")]
        report = build_report(events(rows), manifest(200), {})
        sleep = next(s for t in report["threads"] if t["tid"] == 10 for s in t["segments"] if s["state"] == "SLEEP")
        self.assertEqual(sleep["wake_evidence"]["quality"], "KERNEL_WAKING_TO_WAKEUP_EXPLICIT_REFERENCE")
        self.assertTrue(any("CLEAR_CHILD_TID" in e["basis"] for e in report["critical_path"]["tools"][0]["dependency_edges"]))
        rows[10]["wake_attempt_ns"] = 77
        negative = build_report(events(rows), manifest(200), {})
        self.assertEqual(negative["critical_path"]["status"], "INCOMPLETE")
        self.assertEqual(negative["critical_path"]["tools"][0]["dependency_edges"], [])

    def test_waking_split_keeps_exact_ordered_thread_and_completion_partitions(self):
        for attempt in (35, 40, 70, 80):
            with self.subTest(attempt=attempt):
                rows = self.basic()
                wakeup = next(row for row in rows if row["event"] == "WAKEUP" and row["timestamp_ns"] == 80)
                wakeup.update(wake_attempt_ns=attempt, peer={"tid": 0})
                rows.append(events([ev("WAKING", attempt, peer=CHILD)])[0])
                rows.sort(key=lambda row: row["timestamp_ns"])
                for index, row in enumerate(rows):
                    row["cpu_seq"] = index + 1
                report = build_report(rows, manifest(), {})
                thread = report["threads"][0]
                path = report["critical_path"]["tools"][0]
                for parts, begin, end in ((thread["segments"], thread["begin_ns"], thread["end_ns"]),
                                          (path["segments"], 10, 1000)):
                    cursor = begin
                    for part in parts:
                        self.assertEqual(part["begin_ns"], cursor)
                        self.assertGreater(part["end_ns"], part["begin_ns"], "no zero-length split artifacts")
                        cursor = part["end_ns"]
                    self.assertEqual(cursor, end)
                self.assertEqual(path["state_totals_ns"].get("WAKING", 0), 80 - max(40, attempt))
                self.assertEqual(path["state_totals_ns"].get("SLEEP", 0), max(0, attempt - 40))
                self.assertEqual(path["unknown_ns"], 0)
                self.assertEqual(sum(path["state_totals_ns"].values()), 990)

    def test_exit_hook_sleep_and_preemption_are_cleanup_not_early_runtime_return(self):
        rows = [ev("SWITCH_OUT", 1, state="STOPPED"), ev("WAKEUP", 10), ev("SWITCH_IN", 20),
                ev("EXIT", 30),
                ev("SWITCH_OUT", 40, state="SLEEP_D", prev_state=2, preempt=False),
                ev("WAKEUP", 50), ev("SWITCH_IN", 60),
                ev("SWITCH_OUT", 70, state="RUNNABLE", prev_state=0, preempt=True),
                ev("SWITCH_IN", 80),
                ev("SWITCH_OUT", 99, state="SLEEP_D", prev_state=0x80, preempt=False)]
        report = build_report(events(rows), manifest(100), {})
        thread = report["threads"][0]
        self.assertEqual(thread["exit_ns"], 30)
        self.assertEqual(thread["terminal_switch_ns"], 99)
        self.assertEqual(thread["end_ns"], 99)
        self.assertTrue(any(part["state"] == "SLEEP" and part["begin_ns"] == 40 and part["end_ns"] == 50
                            for part in thread["segments"]), "exit_files/exit_mm may still block after EXIT")
        self.assertTrue(any(part["state"] == "ONCPU" and part["begin_ns"] == 80 and part["end_ns"] == 99
                            for part in thread["segments"]), "exit cleanup may continue after preemption")
        path = report["critical_path"]["tools"][0]
        self.assertEqual(path["state_totals_ns"]["RUNTIME_RETURN"], 1)
        self.assertFalse(any(part["state"] == "RUNTIME_RETURN" and part["begin_ns"] < 99 for part in path["segments"]))


if __name__ == "__main__":
    unittest.main()
