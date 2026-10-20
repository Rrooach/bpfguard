import dataclasses
import json
import tempfile
import unittest
from pathlib import Path

from semantic import Context, Recorder, verify


class SemanticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "events.jsonl"
        self.recorder = Recorder(self.path, "run")
        self.a = self.recorder.declare(Context("run", "A", "agent-A"))
        self.b = self.recorder.declare(Context("run", "B", "agent-B"))

    def tearDown(self):
        self.recorder.close()
        self.temp.cleanup()

    def request_context(self, base, request):
        context = dataclasses.replace(base, request_id=request)
        for state in ("ACCEPTED", "QUEUED", "SCHEDULED"):
            self.recorder.request(context, state)
        return context

    def test_same_shared_thread_reused_by_two_agents_has_scoped_intervals(self):
        actors = []
        for base, request in ((self.a, "req-A"), (self.b, "req-B")):
            context = self.request_context(base, request)
            with self.recorder.thread_processing(context, "handler-" + request) as actor:
                actors.append(actor)
                self.recorder.request(context, "FIRST_TOKEN")
                self.recorder.batch("batch-" + request, [context], "BEGIN")
                self.recorder.batch("batch-" + request, [context], "END")
                self.recorder.request(context, "COMPLETE")
        self.recorder.close()
        result = verify(self.path)
        self.assertTrue(result["verified"], result)
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["request_count"], 2)
        self.assertEqual(actors[0]["tid"], actors[1]["tid"])
        self.assertFalse(self.recorder.active_threads)

    def test_thread_cannot_belong_to_two_overlapping_requests(self):
        a = self.request_context(self.a, "req-A")
        b = self.request_context(self.b, "req-B")
        with self.recorder.thread_processing(a, "a"):
            with self.assertRaises(ValueError):
                with self.recorder.thread_processing(b, "b"):
                    pass

    def test_priorities_versioned_and_stale_wire_event_rejected(self):
        self.recorder.update_policy(self.a, 10, {"cpus": [0]})
        self.recorder.begin(self.a, "SEARCH", "search")
        self.recorder.end("search")
        self.recorder.close()
        rows = [json.loads(line) for line in self.path.read_text().splitlines()]
        self.assertEqual(rows[-1]["effective_version"], 2)
        rows[-1]["effective_version"] = 1
        self.path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        self.assertFalse(verify(self.path)["verified"])

    def test_request_cannot_skip_queue_or_change_owner(self):
        request = dataclasses.replace(self.a, request_id="request")
        with self.assertRaises(ValueError):
            self.recorder.request(request, "SCHEDULED")
        self.recorder.request(request, "ACCEPTED")
        with self.assertRaises(ValueError):
            self.recorder.request(dataclasses.replace(self.b, request_id="request"), "QUEUED")
        self.recorder.request(request, "CANCELLED")
        with self.assertRaises(ValueError):
            self.recorder.request(request, "QUEUED")

    def test_dependency_requires_successful_prerequisite(self):
        self.recorder.begin(self.a, "SEARCH", "search")
        with self.assertRaises(ValueError):
            self.recorder.begin(self.a, "PREPARE", "prepare", dependency_spans=["search"])
        self.recorder.end("search")
        self.recorder.begin(self.a, "PREPARE", "prepare", dependency_spans=["search"])
        self.recorder.end("prepare", "FAIL")
        self.recorder.close()
        self.assertEqual(verify(self.path)["status"], "COMPLETE")

    def test_incomplete_is_not_zero_work_or_complete(self):
        self.recorder.begin(self.a, "SEARCH", "search")
        self.recorder.close()
        result = verify(self.path)
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["incomplete_spans"], ["search"])

    def test_forged_batch_member_and_boot_identity_rejected(self):
        context = self.request_context(self.a, "req")
        self.recorder.batch("batch", [context], "BEGIN")
        self.recorder.batch("batch", [context], "END")
        self.recorder.request(context, "FIRST_TOKEN")
        self.recorder.request(context, "COMPLETE")
        self.recorder.close()
        rows = [json.loads(line) for line in self.path.read_text().splitlines()]
        batch = next(row for row in rows if row["kind"] == "BATCH_BEGIN")
        batch["details"]["members"][0]["task_id"] = "B"
        self.path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        self.assertFalse(verify(self.path)["verified"])

    def test_missing_actor_zero_tid_and_changed_request_rejected(self):
        context = self.request_context(self.a, "req")
        with self.recorder.thread_processing(context, "handler"):
            self.recorder.request(context, "FIRST_TOKEN")
            self.recorder.request(context, "COMPLETE")
        self.recorder.close()
        originals = [json.loads(line) for line in self.path.read_text().splitlines()]
        for field, value in (("tid", 0), ("boot_id", "wrong"), ("cgroup_inode", 0)):
            rows = json.loads(json.dumps(originals))
            rows[-1]["actor"][field] = value
            self.path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            self.assertFalse(verify(self.path)["verified"], field)
        rows = json.loads(json.dumps(originals))
        rows[-1]["request_id"] = "forged-request"
        self.path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        self.assertFalse(verify(self.path)["verified"])

    def test_parent_cannot_end_before_child_and_cycle_rejected(self):
        self.recorder.begin(self.a, "TASK", "parent")
        self.recorder.begin(self.a, "SEARCH", "child", parent_span_id="parent")
        with self.assertRaises(ValueError):
            self.recorder.end("parent")
        self.recorder.end("child")
        self.recorder.end("parent")
        self.recorder.close()
        rows = [json.loads(line) for line in self.path.read_text().splitlines()]
        rows[0]["parent_task_id"] = "B"
        rows[1]["parent_task_id"] = "A"
        for row in rows[2:]:
            row["parent_task_id"] = "B"
        self.path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        self.assertFalse(verify(self.path)["verified"])


if __name__ == "__main__":
    unittest.main()
