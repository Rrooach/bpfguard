import dataclasses
import sqlite3
import tempfile
import unittest
from pathlib import Path
import json

from gpu_adapter import clock_mapping, parse_nsight
from semantic import Context


class GPUFixtureTests(unittest.TestCase):
    def test_clock_residual_and_excessive_uncertainty_rejected(self):
        anchors = [{"profiler_ns": x, "monotonic_before_ns": x + 990, "monotonic_after_ns": x + 1010}
                   for x in (0, 5000, 10000)]
        self.assertEqual(clock_mapping(anchors)["offset_ns"], 1000)
        anchors[1]["monotonic_before_ns"] += 1000000
        anchors[1]["monotonic_after_ns"] += 1000000
        with self.assertRaises(ValueError):
            clock_mapping(anchors)

    def test_two_members_explicit_cuda_launch_join_and_forgery_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.sqlite"
            connection = sqlite3.connect(path)
            connection.executescript("""
              CREATE TABLE CUPTI_ACTIVITY_KIND_RUNTIME(start,end,globalTid,correlationId);
              CREATE TABLE CUPTI_ACTIVITY_KIND_KERNEL(start,end,globalPid,correlationId,deviceId,contextId,streamId);
              CREATE TABLE NVTX_EVENTS(start,end,globalTid,eventType,text);
              CREATE TABLE CUPTI_ACTIVITY_KIND_MEMCPY(start,end,globalPid,correlationId,deviceId,contextId,streamId,bytes,copyKind);
              CREATE TABLE ENUM_CUDA_MEMCPY_OPER(id,name);
              INSERT INTO CUPTI_ACTIVITY_KIND_RUNTIME VALUES(100,120,7,42);
              INSERT INTO CUPTI_ACTIVITY_KIND_KERNEL VALUES(150,180,3,42,0,2,4);
              INSERT INTO CUPTI_ACTIVITY_KIND_MEMCPY VALUES(180,190,3,42,0,2,4,4096,1);
              INSERT INTO ENUM_CUDA_MEMCPY_OPER VALUES(1,'HTOD');
            """)
            a = dataclasses.asdict(Context("run", "A", "agent-A", request_id="a"))
            b = dataclasses.asdict(Context("run", "B", "agent-B", request_id="b"))
            # JSON round trip normalizes tuple to the actual wire array.
            a, b = json.loads(json.dumps([a, b]))
            payload = {"observer_nvtx_schema": 1, "batch_id": "batch", "members": [a, b]}
            connection.execute("INSERT INTO NVTX_EVENTS VALUES(90,130,7,59,?)", (json.dumps(payload),))
            connection.commit()
            connection.close()
            process = {"boot_id": "boot", "pid": 3, "tid": 7,
                       "process_start_ticks": 4, "thread_start_ticks": 5, "cgroup_inode": 6}
            metadata = {"run_id": "run", "boot_id": "boot", "nsight_version": "fixture-not-hardware",
                "clock_anchors": [{"profiler_ns": x, "monotonic_before_ns": x + 999,
                                   "monotonic_after_ns": x + 1001} for x in (0, 500, 1000)],
                "process_instances_by_global_tid": {"7": process},
                "process_instances_by_global_pid": {"3": process}}
            result = parse_nsight(path, {"a": a, "b": b}, metadata)
            self.assertEqual(result["hardware_validation"], "NOT_RUN")
            self.assertEqual(len(result["activities"][0]["members"]), 2)
            self.assertEqual(result["activities"][0]["start_monotonic_ns"], 1150)
            self.assertEqual(result["activities"][1]["bytes"], 4096)
            self.assertEqual(result["activities"][1]["copy_kind"], "HTOD")
            wrong = json.loads(json.dumps(metadata))
            wrong["process_instances_by_global_pid"]["3"]["process_start_ticks"] = 999
            rejected = parse_nsight(path, {"a": a, "b": b}, wrong)
            self.assertEqual(rejected["activities"], [])
            self.assertTrue(rejected["unresolved"])
            a["agent_id"] = "forged"
            with self.assertRaises(ValueError):
                parse_nsight(path, {"a": a, "b": b}, metadata)


if __name__ == "__main__":
    unittest.main()
