#!/usr/bin/env python3
"""A changed TID after nonleader exec must not manufacture continuity."""
import unittest

from replay import build_report
import test_replay as fixture


class IdentityTransitionTests(unittest.TestCase):
    def test_nonleader_exec_never_guesses_old_birth_or_stays_green(self):
        rows = fixture.ReplayTests().basic()
        rows.append(fixture.ev("EXEC", 150, fixture.PARENT, old_tid=20))
        rows.sort(key=lambda row: row["timestamp_ns"])
        report = build_report(fixture.events(rows), fixture.manifest(), {})
        self.assertTrue(any(f["kind"] == "IDENTITY_TRANSITION_UNRESOLVED" for f in report["findings"]))
        self.assertEqual(report["critical_path"]["status"], "INCOMPLETE")
        self.assertTrue(all(not t.get("exec_predecessor_key") for t in report["threads"]))
        self.assertTrue(all(not p["dependency_edges"] for p in report["critical_path"]["tools"]))


if __name__ == "__main__":
    unittest.main()
