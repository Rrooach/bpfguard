"""Tiny synthetic ABI/decoder tests: no BPF load, Guest, or campaign data.

Build the opt-in native collector first; override EXECUTION_TIMELINE_COLLECTOR
to test a particular frozen executable. These fixtures verify raw projection,
not live hook coverage or the truth of a kernel-supplied event.
"""
from __future__ import annotations

import ctypes as c
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class Identity(c.LittleEndianStructure):
    _fields_ = [("thread_birth_ns", c.c_uint64), ("process_birth_ns", c.c_uint64),
                ("cgroup_id", c.c_uint64), ("tid", c.c_uint32),
                ("tgid", c.c_uint32), ("comm", c.c_char * 16)]


class File(c.LittleEndianStructure):
    _fields_ = [("mount_id", c.c_uint64), ("inode", c.c_uint64),
                ("size", c.c_int64), ("device", c.c_uint32),
                ("generation", c.c_uint32)]


class Event(c.LittleEndianStructure):
    _fields_ = [("magic", c.c_uint32), ("version", c.c_uint16),
                ("kind", c.c_uint16), ("size", c.c_uint32),
                ("flags", c.c_uint32), ("boot_id", c.c_uint8 * 16),
                ("timestamp_ns", c.c_uint64), ("cpu_seq", c.c_uint64),
                ("root_cgroup_id", c.c_uint64), ("task", Identity),
                ("peer", Identity), ("syscall_call_id", c.c_uint64),
                ("start_ns", c.c_uint64), ("end_ns", c.c_uint64),
                ("requested_bytes", c.c_uint64), ("result", c.c_int64),
                ("args", c.c_uint64 * 6), ("file", File),
                ("cpu", c.c_uint32), ("state", c.c_uint32),
                ("prev_state", c.c_uint32), ("preempt", c.c_uint32),
                ("syscall_nr", c.c_int32), ("stack_bytes", c.c_int32),
                ("path_bytes", c.c_int32), ("old_tid", c.c_uint32),
                ("kernel_stack", c.c_uint64 * 16), ("path", c.c_char * 256)]


PROJECT = Path(__file__).resolve().parents[2]
COLLECTOR = Path(os.environ.get("EXECUTION_TIMELINE_COLLECTOR", str(
    PROJECT / ".output/execution-timeline-native/collect")))


def event(kind=1, **fields):
    value = Event(magic=0x45544C31, version=1, kind=kind, size=688,
                  timestamp_ns=100, cpu_seq=1, root_cgroup_id=20,
                  task=Identity(thread_birth_ns=2, process_birth_ns=2,
                                cgroup_id=20, tid=3, tgid=3, comm=b"task"),
                  syscall_nr=-1)
    value.boot_id[:] = range(16)
    for key, item in fields.items():
        setattr(value, key, item)
    return value


@unittest.skipUnless(COLLECTOR.is_file(), "build native collector or set EXECUTION_TIMELINE_COLLECTOR")
class NativeDecodeTests(unittest.TestCase):
    def decode(self, *records, tail=b"", options=(), preexisting=None):
        with tempfile.TemporaryDirectory(prefix="timeline-native-test-") as directory:
            root = Path(directory)
            source, output = root / "raw.bin", root / "events.jsonl"
            source.write_bytes(b"".join(bytes(record) for record in records) + tail)
            if preexisting is not None:
                output.write_text(preexisting)
            process = subprocess.run([str(COLLECTOR), "--decode", str(source),
                                      "--output", str(output), *options],
                                     capture_output=True, text=True, check=False)
            contents = output.read_text() if output.exists() else ""
            rows = [json.loads(line) for line in contents.splitlines()] if preexisting is None else []
            receipt = json.loads(process.stderr.splitlines()[-1]) if process.stderr.startswith("{") else None
            return process.returncode, rows, receipt, contents

    def test_fixed_abi_and_self_test(self):
        self.assertEqual(c.sizeof(Event), 688)
        self.assertEqual(Event.args.offset, 192)
        self.assertEqual(Event.path.offset, 432)
        process = subprocess.run([str(COLLECTOR), "--self-test"], capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["event_bytes"], 688)

    def test_seccomp_skip_raw_records_preserve_no_entry_duration_and_unknown_action(self):
        proof=event(12,syscall_nr=435,result=-38,timestamp_ns=50)
        result=event(8,flags=8388608,syscall_nr=435,result=-38,cpu_seq=2)
        result.args[0]=50
        code,rows,_,_=self.decode(proof,result)
        self.assertEqual(code,0)
        self.assertEqual(rows[0]['event'],'SECCOMP_SKIP')
        self.assertEqual(rows[0]['seccomp_skip_proof'],'KERNEL_FEXIT_FILTER_FALSE_AND_SAVED_REGISTERS')
        self.assertEqual(rows[0]['return_value'],-38)
        self.assertEqual(rows[1]['seccomp_skip_reference_ns'],50)
        self.assertEqual(rows[1]['closure_kind'],'SECCOMP_SKIPPED_WITHOUT_RAW_ENTRY')
        for row in rows:
            self.assertIsNone(row['start_ns'])
            self.assertIsNone(row['duration_ns'])
            self.assertEqual(row['syscall_call_id'],0)
            self.assertEqual(row['seccomp_action'],'UNKNOWN_NOT_OBSERVED')

    def test_successful_exec_keeps_filename_separate_from_canonical_path_and_object(self):
        value=event(5,flags=16777216|4|128,file=File(mount_id=7,inode=8,device=9,generation=10),old_tid=3)
        value.path=b'./relative-symlink';value.path_bytes=19
        code,rows,_,_=self.decode(value)
        self.assertEqual(code,0)
        self.assertEqual(rows[0]['exec_filename'],'./relative-symlink')
        self.assertEqual(rows[0]['exec_filename_quality'],'KERNEL_EXEC_FILENAME_NOT_CANONICAL_PATH')
        self.assertEqual(rows[0]['file']['path_quality'],'KERNEL_EXEC_FILENAME_NOT_CANONICAL_PATH')
        self.assertEqual(rows[0]['exec_object_quality'],'KERNEL_BPRM_FILE_IDENTITY')
        self.assertEqual(rows[0]['file']['inode'],8)

    def test_legacy_exec_does_not_gain_filename_or_executable_object(self):
        code,rows,_,_=self.decode(event(5))
        self.assertEqual(code,0)
        self.assertIsNone(rows[0]['exec_filename'])
        self.assertEqual(rows[0]['exec_filename_quality'],'NOT_CAPTURED')
        self.assertEqual(rows[0]['exec_object_quality'],'NOT_CAPTURED')

    def test_exec_origin_requires_exec_and_unambiguous_path_and_object_quality(self):
        for kind,flags in ((1,16777216|4|128),(5,16777216),(5,16777216|4|8|128),(5,16777216|4|128|256)):
            with self.subTest(kind=kind,flags=flags):
                value=event(kind,flags=flags,file=File(mount_id=7,inode=8,device=9))
                value.path=b'/bin/sh';value.path_bytes=8
                self.assertEqual(self.decode(value)[0],1)

    def test_seccomp_shapes_reject_fabricated_entry_duration_or_flags(self):
        for kind,fields in ((12,{'start_ns':50}),(12,{'syscall_call_id':50}),(12,{'flags':512}),
                            (12,{'syscall_nr':-1}),(8,{'start_ns':50}),(8,{'syscall_call_id':50}),
                            (8,{'flags':8388608|512}),(8,{'timestamp_ns':50})):
            with self.subTest(kind=kind,fields=fields):
                base=dict(syscall_nr=435,result=-38,flags=8388608 if kind==8 else 0)
                base.update(fields);value=event(kind,**base)
                if kind==8:value.args[0]=50
                self.assertEqual(self.decode(value)[0],1)

    def test_deferred_projection_byte_identity_stopped_boundary_and_changed_source(self):
        process = subprocess.run([str(COLLECTOR), "--self-test"], capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        receipt = json.loads(process.stdout)
        self.assertEqual(receipt["deferred_projection"], "BYTE_IDENTICAL_TO_LIVE_PROJECTOR_SYNTHETIC_ONLY")
        self.assertEqual(receipt["stopped_boundary_projection"], "ALL_RECORDS_PRESERVED")
        self.assertEqual(receipt["changed_raw_identity"], "REJECTED")

    def test_live_json_is_explicit_and_not_an_offline_decode_option(self):
        process = subprocess.run([str(COLLECTOR), "--help"], capture_output=True, text=True)
        self.assertEqual(process.returncode, 0)
        self.assertIn("--live-json", process.stdout)
        self.assertIn("after disable/detach/drain", process.stdout)
        code, _, _, _ = self.decode(event(), options=("--live-json",))
        self.assertEqual(code, 2)

    def test_boot_identity_and_peer_not_applicable(self):
        code, rows, receipt, _ = self.decode(event(6))
        self.assertEqual(code, 0)
        self.assertEqual(rows[0]["boot_id"], "00010203-0405-0607-0809-0a0b0c0d0e0f")
        self.assertEqual(rows[0]["task"]["thread_birth_ns"], 2)
        self.assertEqual(rows[0]["peer_quality"], "NOT_APPLICABLE")
        self.assertIn("NOT_RUN_VERIFICATION", receipt["status"])

    def test_scalar_read_bytes_and_duration(self):
        code, rows, _, _ = self.decode(event(9, flags=16, syscall_call_id=50,
                                               start_ns=60, end_ns=100,
                                               requested_bytes=20, result=17))
        self.assertEqual(code, 0)
        self.assertEqual((rows[0]["requested_bytes"], rows[0]["returned_bytes"],
                          rows[0]["duration_ns"]), (20, 17, 40))

    def test_vector_requested_is_unknown_not_vector_count(self):
        code, rows, _, _ = self.decode(event(9, syscall_nr=19, syscall_call_id=50,
                                               start_ns=60, end_ns=100, result=17))
        self.assertEqual(code, 0)
        self.assertIsNone(rows[0]["requested_bytes"])
        self.assertEqual(rows[0]["returned_bytes"], 17)

    def test_eof_and_failure_are_distinct(self):
        for result, returned in [(0, 0), (-13, None)]:
            with self.subTest(result=result):
                code, rows, _, _ = self.decode(event(9, syscall_call_id=50,
                                                       start_ns=60, end_ns=100, result=result))
                self.assertEqual(code, 0)
                self.assertEqual(rows[0]["returned_bytes"], returned)
                self.assertEqual(rows[0]["return_value"], result)

    def test_read_over_request_is_rejected(self):
        code, _, receipt, _ = self.decode(event(9, flags=16, syscall_call_id=50,
                                                  start_ns=60, end_ns=100,
                                                  requested_bytes=1, result=2))
        self.assertEqual(code, 1)
        self.assertEqual(receipt["parse_errors"], 1)

    def test_sigreturn_restored_register_is_not_errno_or_return(self):
        for register in (0, 1, -13):
            with self.subTest(register=register):
                code, rows, _, _ = self.decode(event(8, flags=16384, syscall_call_id=50,
                                                       start_ns=50, end_ns=100, result=register))
                self.assertEqual(code, 0)
                row = rows[0]
                self.assertEqual(row["syscall_nr"], -1)
                self.assertEqual(row["syscall_entry_nr"], 15)
                self.assertEqual(row["observed_exit_syscall_nr"], -1)
                self.assertEqual(row["restored_register_value"], register)
                self.assertIsNone(row["return_value"])
                self.assertEqual(row["closure_kind"], "SIGNAL_FRAME_RESTORED_NOT_ORDINARY_RETURN")

    def test_sigreturn_flag_requires_exact_raw_shape(self):
        for fields in ({"kind": 1}, {"syscall_nr": 15}, {"syscall_call_id": 0},
                       {"start_ns": 49}, {"end_ns": 99}):
            with self.subTest(fields=fields):
                value = event(8, flags=16384, syscall_call_id=50, start_ns=50, end_ns=100)
                for key, item in fields.items():
                    setattr(value, key, item)
                self.assertEqual(self.decode(value)[0], 1)

    def test_ordinary_denial_remains_return_value(self):
        code, rows, _, _ = self.decode(event(8, syscall_nr=2, result=-13))
        self.assertEqual(code, 0)
        self.assertEqual(rows[0]["return_value"], -13)
        self.assertIsNone(rows[0]["restored_register_value"])

    def test_clear_child_tid_zero_is_valid_not_missing(self):
        code, rows, _, _ = self.decode(event(6, flags=32768))
        self.assertEqual(code, 0)
        self.assertEqual(rows[0]["clear_child_tid"], 0)
        self.assertIn("NOT_WAKE_PROOF", rows[0]["clear_child_tid_quality"])

    def test_clear_child_tid_address_is_not_buffer_contents(self):
        value = event(6, flags=32768)
        value.args[0] = 0x7FFFABCD0100
        code, rows, _, _ = self.decode(value)
        self.assertEqual(code, 0)
        self.assertEqual(rows[0]["clear_child_tid"], 0x7FFFABCD0100)

    def test_clear_child_tid_failed_or_not_captured_remains_null(self):
        for flags, quality in ((65536, "READ_FAILED"), (0, "NOT_CAPTURED")):
            with self.subTest(flags=flags):
                code, rows, _, _ = self.decode(event(6, flags=flags))
                self.assertEqual(code, 0)
                self.assertIsNone(rows[0]["clear_child_tid"])
                self.assertEqual(rows[0]["clear_child_tid_quality"], quality)

    def test_clear_child_tid_flags_reject_non_exit_or_contradiction(self):
        for value in (event(1, flags=32768), event(1, flags=65536), event(6, flags=98304)):
            with self.subTest(kind=value.kind, flags=value.flags):
                self.assertEqual(self.decode(value)[0], 1)

    def test_fork_parent_call_is_explicit_reference_not_child_interval(self):
        for number in (56, 57, 58, 435):
            with self.subTest(syscall_nr=number):
                value = event(4, flags=131072, start_ns=50, syscall_nr=number)
                value.peer = Identity(thread_birth_ns=1, process_birth_ns=1,
                                      cgroup_id=20, tid=2, tgid=2, comm=b"parent")
                code, rows, _, _ = self.decode(value)
                self.assertEqual(code, 0)
                row = rows[0]
                self.assertEqual((row["fork_parent_call_id"], row["fork_parent_syscall_nr"]),
                                 (50, number))
                self.assertEqual(row["peer"]["tid"], 2)
                self.assertIsNone(row["start_ns"])
                self.assertIsNone(row["end_ns"])
                self.assertIsNone(row["duration_ns"])
                self.assertIn("NOT_CHILD_INTERVAL", row["fork_parent_call_quality"])

    def test_unobserved_fork_parent_call_remains_unknown(self):
        code, rows, _, _ = self.decode(event(4))
        self.assertEqual(code, 0)
        self.assertIsNone(rows[0]["fork_parent_call_id"])
        self.assertIsNone(rows[0]["fork_parent_syscall_nr"])
        self.assertEqual(rows[0]["fork_parent_call_quality"], "NOT_CAPTURED")

    def test_fork_register_source_proves_number_but_not_parent_entry_or_duration(self):
        for number in (56, 57, 58, 435):
            with self.subTest(syscall_nr=number):
                value = event(4, flags=4194304, syscall_nr=number)
                value.peer = Identity(thread_birth_ns=1, process_birth_ns=1,
                                      cgroup_id=20, tid=2, tgid=2, comm=b"parent")
                code, rows, _, _ = self.decode(value)
                self.assertEqual(code, 0)
                self.assertEqual(rows[0]["fork_parent_syscall_nr"], number)
                self.assertEqual(rows[0]["fork_parent_syscall_source"], "KERNEL_PT_REGS_AT_FORK_NO_ENTRY_EVENT")
                for field in ("fork_parent_call_id", "start_ns", "end_ns", "duration_ns"):
                    self.assertIsNone(rows[0][field])
                self.assertEqual(rows[0]["syscall_call_id"], 0)
                self.assertEqual(rows[0]["fork_parent_call_quality"], "NOT_CAPTURED")

    def test_fork_register_source_rejects_ordinary_events_guessed_entry_or_bad_number(self):
        for values in ({"kind": 8}, {"syscall_nr": -1}, {"syscall_nr": 1}, {"syscall_nr": 0x40000038},
                       {"start_ns": 50}, {"end_ns": 100}, {"syscall_call_id": 50},
                       {"flags": 4194304 | 131072, "start_ns": 50}, {"flags": 4194304 | 2}):
            with self.subTest(values=values):
                fields = {"flags": 4194304, "syscall_nr": 435}
                fields.update(values)
                self.assertEqual(self.decode(event(fields.pop("kind", 4), **fields))[0], 1)
    def test_waking_records_source_cpu_peer_and_target_identity(self):
        value = event(11, cpu=2)
        value.peer = Identity(thread_birth_ns=7, process_birth_ns=7,
                              cgroup_id=30, tid=9, tgid=9, comm=b"source")
        code, rows, _, _ = self.decode(value)
        self.assertEqual(code, 0)
        row = rows[0]
        self.assertEqual(row["event"], "WAKING")
        self.assertEqual((row["task"]["tid"], row["peer"]["tid"], row["cpu"]), (3, 9, 2))
        self.assertEqual(row["wake_attempt_ns"], row["timestamp_ns"])
        self.assertEqual(row["wake_attempt_quality"], "SOURCE_CPU_CURRENT_WAKER")
        self.assertIsNone(row["start_ns"])
        self.assertIsNone(row["duration_ns"])

    def test_remote_wakeup_reference_preserves_immediate_idle_peer(self):
        value = event(3, flags=262144 | 8192, start_ns=50, cpu=3)
        value.peer.comm = b"swapper/3"
        code, rows, _, _ = self.decode(value)
        self.assertEqual(code, 0)
        row = rows[0]
        self.assertEqual(row["wake_attempt_ns"], 50)
        self.assertEqual(row["peer_quality"], "KNOWN_IDLE_NO_USER_THREAD_ID")
        self.assertEqual(row["peer"]["tid"], 0)
        self.assertIsNone(row["start_ns"])
        self.assertIsNone(row["end_ns"])
        self.assertIsNone(row["duration_ns"])
        self.assertIn("NOT_LOCK_OWNER_PROOF", row["wake_attempt_quality"])

    def test_new_task_wakeup_normally_has_no_waking_reference(self):
        code, rows, _, _ = self.decode(event(3, flags=524288))
        self.assertEqual(code, 0)
        self.assertIsNone(rows[0]["wake_attempt_ns"])
        self.assertEqual(rows[0]["wake_kind"], "NEW_TASK_NO_WAKING_REQUIRED")
        self.assertEqual(rows[0]["wake_attempt_quality"], "NOT_APPLICABLE_NEW_TASK")

    def test_missing_existing_task_reference_is_explicit(self):
        code, rows, _, _ = self.decode(event(3, flags=1048576))
        self.assertEqual(code, 0)
        self.assertIsNone(rows[0]["wake_attempt_ns"])
        self.assertEqual(rows[0]["wake_kind"], "EXISTING_TASK")
        self.assertEqual(rows[0]["wake_attempt_quality"], "SOURCE_WAKING_NOT_CAPTURED_OR_IDENTITY_MISMATCH")

    def test_waking_references_reject_wrong_event_future_time_or_interval(self):
        values = [event(1, flags=262144, start_ns=50), event(3, flags=262144),
                  event(3, flags=262144, start_ns=101),
                  event(3, flags=262144, start_ns=50, end_ns=100),
                  event(11, start_ns=50), event(11, end_ns=100)]
        for value in values:
            with self.subTest(kind=value.kind, flags=value.flags, start=value.start_ns, end=value.end_ns):
                self.assertEqual(self.decode(value)[0], 1)

    def test_wake_new_valid_and_missing_are_mutually_exclusive(self):
        for flags in (262144 | 524288, 262144 | 1048576, 524288 | 1048576):
            with self.subTest(flags=flags):
                self.assertEqual(self.decode(event(3, flags=flags, start_ns=50))[0], 1)

    def test_fork_parent_call_flag_rejects_invalid_type_number_or_interval(self):
        for fields in ({"kind": 1}, {"syscall_nr": 0}, {"start_ns": 0},
                       {"start_ns": 101}, {"end_ns": 100}):
            with self.subTest(fields=fields):
                value = event(4, flags=131072, start_ns=50, syscall_nr=56)
                for key, item in fields.items():
                    setattr(value, key, item)
                self.assertEqual(self.decode(value)[0], 1)

    def test_raw_path_preserves_bytes_and_not_success_claim(self):
        value = event(10, flags=4 | 128, file=File(mount_id=7, inode=8, device=9))
        value.path = b"/tmp/a\xff\"\n"
        value.path_bytes = 10
        code, rows, _, _ = self.decode(value)
        self.assertEqual(code, 0)
        self.assertEqual(rows[0]["file"]["path_raw_hex"], b"/tmp/a\xff\"\n".hex())
        self.assertIn("PERMISSION_CANDIDATE", rows[0]["file"]["path_quality"])

    def test_lsm_path_source_and_chain_return_are_preserved_not_read_success(self):
        for result in (0, -13):
            with self.subTest(result=result):
                value = event(10, flags=4 | 128 | 2097152, result=result,
                              file=File(mount_id=7, inode=8, device=9))
                value.path = b"/tmp/input"
                value.path_bytes = len(b"/tmp/input") + 1
                code, rows, _, _ = self.decode(value)
                self.assertEqual(code, 0)
                row = rows[0]
                self.assertEqual(row["file"]["path_quality"], "KERNEL_PATH_AT_LSM_PERMISSION_CANDIDATE")
                self.assertEqual(row["lsm_chain_return_value_at_observer"], result)
                self.assertEqual(row["lsm_policy_effect"], "RETURN_INPUT_UNCHANGED")
                self.assertIsNone(row["return_value"])
                self.assertIsNone(row["returned_bytes"])

    def test_legacy_fentry_path_does_not_gain_lsm_provenance(self):
        value = event(10, flags=4 | 128, file=File(mount_id=7, inode=8, device=9))
        value.path = b"/tmp/input"
        value.path_bytes = len(b"/tmp/input") + 1
        code, rows, _, _ = self.decode(value)
        self.assertEqual(code, 0)
        self.assertEqual(rows[0]["file"]["path_quality"], "KERNEL_PATH_AT_PERMISSION_CANDIDATE")
        self.assertIsNone(rows[0]["lsm_chain_return_value_at_observer"])
        self.assertEqual(rows[0]["lsm_policy_effect"], "NOT_APPLICABLE")

    def test_lsm_path_origin_flag_is_rejected_on_non_object_events(self):
        for kind in (1, 3, 9, 11):
            with self.subTest(kind=kind):
                self.assertEqual(self.decode(event(kind, flags=2097152))[0], 1)

    def test_full_stack_length_is_only_possible_truncation(self):
        value = event(flags=32, stack_bytes=128)
        value.kernel_stack[0] = 0xFFFFFFFFDEADBEEF
        code, rows, _, _ = self.decode(value)
        self.assertEqual(code, 0)
        self.assertTrue(rows[0]["kernel_stack_truncated_possible"])
        self.assertIn("NOT_PROVEN_CAUSE", rows[0]["stack_quality"])

    def test_sequence_gap_is_preserved_and_disclosed_not_false_hard_fail(self):
        code, rows, receipt, _ = self.decode(event(cpu_seq=1), event(cpu_seq=3))
        self.assertEqual(code, 0)
        self.assertEqual(len(rows), 2)
        self.assertEqual(receipt["sequence_gaps"], 1)
        self.assertIn("WITH_SEQUENCE_GAPS", receipt["status"])

    def test_out_of_order_delivery_is_not_sequence_loss(self):
        code, rows, receipt, _ = self.decode(event(cpu_seq=2), event(cpu_seq=1))
        self.assertEqual(code, 0)
        self.assertEqual([row["cpu_seq"] for row in rows], [2, 1])
        self.assertEqual(receipt["sequence_errors"], 0)

    def test_per_cpu_sequences_are_independent(self):
        code, _, receipt, _ = self.decode(event(cpu=0), event(cpu=1))
        self.assertEqual(code, 0)
        self.assertEqual(receipt["sequence_errors"], 0)

    def test_duplicate_sequence_is_hard_failure(self):
        code, _, receipt, _ = self.decode(event(), event())
        self.assertEqual(code, 1)
        self.assertEqual(receipt["duplicate_sequences"], 1)

    def test_partial_tail_is_hard_failure(self):
        code, rows, receipt, _ = self.decode(event(), tail=b"partial")
        self.assertEqual(code, 1)
        self.assertEqual(len(rows), 1)
        self.assertTrue(receipt["truncated_tail"])

    def test_unknown_flag_or_bad_magic_is_hard_failure(self):
        for fields in ({"flags": 8388608}, {"magic": 0}):
            with self.subTest(fields=fields):
                self.assertEqual(self.decode(event(**fields))[0], 1)

    def test_cap_reached_is_disclosed_failure(self):
        code, rows, receipt, _ = self.decode(event(), event(cpu_seq=2),
                                             options=("--max-records", "1"))
        self.assertEqual(code, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(receipt["cap_discarded"], 1)

    def test_existing_output_is_not_overwritten(self):
        code, _, _, contents = self.decode(event(), preexisting="preserve me\n")
        self.assertEqual(code, 1)
        self.assertEqual(contents, "preserve me\n")


class NativeIdentitySourceTests(unittest.TestCase):
    """Guard the native failure accounting paths without injecting kernel faults."""

    def test_every_direct_identity_call_accounts_its_failure(self):
        source = (PROJECT / "bpf/execution_timeline.bpf.c").read_text()
        calls = [line.strip() for line in source.splitlines()
                 if "identity(" in line and "int identity(" not in line]
        self.assertEqual(len(calls), 12)
        for line in calls:
            with self.subTest(line=line):
                self.assertIn("count(ET_ID_READ_ERRORS)", line)

    def test_idle_peer_comm_read_failure_also_accounts_identity_failure(self):
        source = (PROJECT / "bpf/execution_timeline.bpf.c").read_text()
        self.assertIn("if(bpf_core_read(&e->peer.comm,sizeof(e->peer.comm),&task->comm)){\n"
                      "            e->flags|=ET_PEER_FAILED;count(ET_ID_READ_ERRORS);\n", source)

    def test_lsm_identity_failure_returns_input_policy_result(self):
        source = (PROJECT / "bpf/execution_timeline.bpf.c").read_text()
        hook = source[source.index('SEC("lsm/file_permission")'):]
        self.assertIn("if(identity(&id,task)){count(ET_ID_READ_ERRORS);return ret;}", hook)
        self.assertNotIn("return 0", hook)


if __name__ == "__main__":
    unittest.main()
