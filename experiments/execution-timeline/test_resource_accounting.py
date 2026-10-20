#!/usr/bin/env python3
import unittest

from resource_accounting import _io_stat, _key_values, tool_accounting


class ResourceAccountingTests(unittest.TestCase):
    def test_parsers_and_monotonic_deltas(self):
        self.assertEqual(_key_values("usage_usec 12\nuser_usec 7\n"),
                         {"usage_usec": 12, "user_usec": 7})
        self.assertEqual(_io_stat("8:0 rbytes=10 wbytes=4\n8:1 rbytes=3 wbytes=2\n")["aggregate"],
                         {"rbytes": 13, "wbytes": 6})
        identity = {"path": "/sys/fs/cgroup/tool", "inode": 2, "device": 1}
        before = {"identity": identity, "status": "COMPLETE", "end_ns": 2,
                  "values": {"cpu.stat": {"usage_usec": 5},
                             "memory.stat": {"pgfault": 10, "pgmajfault": 1},
                             "memory.events": {"oom": 0, "oom_kill": 0},
                             "io.stat": {"aggregate": {"rbytes": 8, "wbytes": 2}}}}
        after = {"identity": identity, "status": "COMPLETE", "begin_ns": 3,
                 "values": {"cpu.stat": {"usage_usec": 15}, "memory.peak": 4096,
                            "memory.current": 0,
                            "memory.stat": {"pgfault": 14, "pgmajfault": 2},
                            "memory.events": {"oom": 0, "oom_kill": 0},
                            "io.stat": {"aggregate": {"rbytes": 108, "wbytes": 12}}}}
        result = tool_accounting(before, after)
        self.assertEqual(result["cpu_usage_usec"], 10)
        self.assertEqual(result["memory_peak_bytes"], 4096)
        self.assertEqual(result["total_faults"], 4)
        self.assertEqual(result["minor_faults"], 3)
        self.assertEqual(result["major_faults"], 1)
        self.assertEqual(result["io_read_bytes"], 100)

    def test_identity_change_and_counter_regression_fail_closed(self):
        before = {"identity": {"inode": 1}, "status": "COMPLETE", "end_ns": 2,
                  "values": {"cpu.stat": {"usage_usec": 10}}}
        after = {"identity": {"inode": 1}, "status": "COMPLETE", "begin_ns": 3,
                 "values": {"cpu.stat": {"usage_usec": 5}}}
        self.assertIsNone(tool_accounting(before, after)["cpu_usage_usec"])
        after["identity"] = {"inode": 2}
        with self.assertRaisesRegex(ValueError, "identity changed"):
            tool_accounting(before, after)


if __name__ == "__main__":
    unittest.main()
