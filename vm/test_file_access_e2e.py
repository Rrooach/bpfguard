#!/usr/bin/env python3
"""Read-only report validation tests; never boot QEMU or load BPF."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("file_access_e2e", Path(__file__).with_name("run-file-access-e2e.py"))
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def report():
    calls = [dict(syscall="read", requested_bytes=32, actual_bytes=13, return_value=13, duration_ns=1),
             dict(syscall="read", requested_bytes=32, actual_bytes=0, return_value=0, duration_ns=1),
             dict(syscall="read", requested_bytes=1, actual_bytes=None, return_value=-9, duration_ns=1)]
    calls += [dict(syscall=name, actual_bytes=5, requested_bytes=None, return_value=5, duration_ns=1)
              for name in ("readv", "preadv", "preadv2", "writev", "pwritev", "pwritev2")]
    return dict(profile="file-access", unmatched_attempts=0, unmatched_results=0,
                truncated_wal_tail=False, event_sequence_gap_runs=0,
                disclosed_correlation_failure_events=0, disclosed_object_failure_events=0,
                recorded_pairing_status="PAIRED_RECORDED_EVENTS_ONLY_NOT_COVERAGE_PROOF",
                run_verification="NOT_PERFORMED", calls=calls, totals=dict(failed_calls=2),
                unique_file_objects=0)


class ReportValidation(unittest.TestCase):
    def test_user_input_preserves_bytes_without_inventing_objects(self):
        MOD.validate_report(report(), "user-input")

    def test_gaps_failures_and_truncated_tail_are_never_a_pass(self):
        for key in ("unmatched_attempts", "unmatched_results", "event_sequence_gap_runs",
                    "disclosed_correlation_failure_events", "disclosed_object_failure_events",
                    "truncated_wal_tail", "unique_file_objects"):
            value = report()
            value[key] = 1
            with self.subTest(field=key), self.assertRaises(ValueError):
                MOD.validate_report(value, "user-input")

    def test_byte_latency_and_vector_contracts_are_required(self):
        for index, key, replacement in ((0, "actual_bytes", 32), (1, "actual_bytes", None),
                                        (2, "actual_bytes", 0), (0, "duration_ns", -1),
                                        (3, "requested_bytes", 2)):
            value = report()
            value["calls"][index][key] = replacement
            with self.subTest(index=index, field=key), self.assertRaises(ValueError):
                MOD.validate_report(value, "user-input")

    def test_hard_link_aliases_deduplicate_and_fd_reuse_does_not(self):
        value = report()
        first = dict(observed_paths=[dict(display="/tmp/file-access/a"), dict(display="/tmp/file-access/alias")],
                     totals=dict(bytes_read=37, bytes_written=25))
        second = dict(observed_paths=[dict(display="/tmp/file-access/b")], totals=dict(bytes_read=3, bytes_written=3))
        value.update(files=[first, second], unique_files=2, unique_file_objects=3,
                     unique_anonymous_pseudo_files=1, anonymous_file_totals=dict(bytes_written=23))
        MOD.validate_report(value, "kernel-file-open-write-partial")
        changed = copy.deepcopy(value)
        changed["files"][1]["observed_paths"] += [dict(display="/tmp/file-access/alias")]
        with self.assertRaises(ValueError):
            MOD.validate_report(changed, "kernel-file-open-write-partial")

    def test_diagnostic_cannot_claim_run_verification_or_unknown_mode(self):
        value = report()
        value["run_verification"] = "COMPLETE"
        with self.assertRaises(ValueError):
            MOD.validate_report(value, "user-input")
        with self.assertRaises(ValueError):
            MOD.validate_report(report(), "unknown")


if __name__ == "__main__":
    unittest.main()
