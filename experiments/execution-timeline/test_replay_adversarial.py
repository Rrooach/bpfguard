#!/usr/bin/env python3
"""Adversarial synthetic timeline contracts; no VM or real evidence is used."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from common import canonical, digest
from replay import build_report, check_tool_ledger, identity_key, load_events, verify_run


BOOT = 'adversarial-boot'
ROOT = {'tid': 10, 'tgid': 10, 'thread_birth_ns': 1, 'process_birth_ns': 1, 'comm': 'parent'}
A = {'tid': 20, 'tgid': 20, 'thread_birth_ns': 20, 'process_birth_ns': 20, 'comm': 'child-A'}
B = {'tid': 30, 'tgid': 30, 'thread_birth_ns': 25, 'process_birth_ns': 25, 'comm': 'child-B'}
GREEN = 'RECONSTRUCTED_WITHIN_SELECTED_MODEL'


def ev(kind, timestamp, task=ROOT, cpu=0, **extra):
    return {'schema_version': 1, 'event': kind, 'timestamp_ns': timestamp,
            'task': dict(task), 'cpu': cpu, 'root_cgroup_id': 9, 'caller_cgroup_id': 11, **extra}


def stream(rows):
    sequence = {}
    output = []
    def task_key(row):
        task = row['task']
        return task['tid'], task['thread_birth_ns'], task['process_birth_ns']
    # Older synthetic fixtures used only the coarse SLEEP_D display state for
    # their final switch. Explicitly declare TASK_DEAD for that final switch;
    # EXIT itself is an early lifecycle hook and is not descheduling proof.
    final_switch = {task_key(row): row['timestamp_ns'] for row in rows if row['event'] == 'SWITCH_OUT'}
    exited = set()
    for row in rows:
        key = task_key(row)
        if row['event'] == 'EXIT':
            exited.add(key)
        if (row['event'] == 'SWITCH_OUT' and key in exited
                and row['timestamp_ns'] == final_switch[key] and 'prev_state' not in row):
            row = dict(row, prev_state=0x80)
        cpu = row['cpu']
        sequence[cpu] = sequence.get(cpu, 0) + 1
        output.append(dict(row, cpu_seq=sequence[cpu]))
    return output


def manifest(end=100):
    return {'schema_version': 1, 'run_id': 'r', 'boot_id': BOOT, 'begin_ns': 0, 'end_ns': end,
        'scope': {'kind': 'COOPERATIVE_DIRECT_CGROUP_DESCENDANTS'},
        'tools': [{'agent_id': 'agent-A', 'task_id': 'task-A', 'tool_call_id': 'tool-A',
            'begin_ns': 10, 'end_ns': end, 'cgroup_id': 11,
            'command': ['/bin/true'], 'gate': 'SIGSTOP_AFTER_CGROUP_ENTRY_BEFORE_EXEC',
            'root': {'tid': ROOT['tid'], 'birth_ns': ROOT['thread_birth_ns']}}]}


def base():
    return [ev('SWITCH_OUT', 1, state='STOPPED'), ev('WAKEUP', 10), ev('SWITCH_IN', 11)]


def finish(timestamp=98):
    return [ev('EXIT', timestamp), ev('SWITCH_OUT', timestamp + 1, state='SLEEP_D')]


def dual_wait(serial=False, early_b=False, missing_b_waker=False, wrong_b_result=False):
    b = dict(B, thread_birth_ns=65, process_birth_ns=65) if serial else B
    rows = base() + [ev('FORK', 20, A, peer=ROOT), ev('WAKEUP', 21, A), ev('SWITCH_IN', 30, A, cpu=1)]
    if not serial:
        rows += [ev('FORK', 25, b, peer=ROOT), ev('WAKEUP', 26, b), ev('SWITCH_IN', 31, b, cpu=2)]
    rows += [ev('SYSCALL_ENTER', 40, syscall_nr=61, syscall_call_id=40, args=[20, 0, 0, 0]),
        ev('SWITCH_OUT', 41, state='SLEEP_S', syscall_call_id=40),
        ev('EXIT', 60, A, cpu=1), ev('SWITCH_OUT', 61, A, cpu=1, state='SLEEP_D'),
        ev('WAKEUP', 62, peer=A), ev('SWITCH_IN', 63),
        ev('SYSCALL_EXIT', 64, syscall_nr=61, syscall_call_id=40, result=20)]
    if serial:
        rows += [ev('FORK', 65, b, peer=ROOT), ev('WAKEUP', 66, b), ev('SWITCH_IN', 68, b, cpu=2)]
    if early_b:
        rows += [ev('EXIT', 50, b, cpu=2), ev('SWITCH_OUT', 51, b, cpu=2, state='SLEEP_D'),
            ev('SYSCALL_ENTER', 65, syscall_nr=61, syscall_call_id=65, args=[30, 0, 0, 0]),
            ev('SYSCALL_EXIT', 66, syscall_nr=61, syscall_call_id=65, result=30)]
    else:
        rows += [ev('SYSCALL_ENTER', 70, syscall_nr=61, syscall_call_id=70, args=[30, 0, 0, 0]),
            ev('SWITCH_OUT', 71, state='SLEEP_S', syscall_call_id=70),
            ev('EXIT', 90, b, cpu=2), ev('SWITCH_OUT', 91, b, cpu=2, state='SLEEP_D'),
            ev('WAKEUP', 92, **({} if missing_b_waker else {'peer': b})), ev('SWITCH_IN', 93),
            ev('SYSCALL_EXIT', 94, syscall_nr=61, syscall_call_id=70, result=20 if wrong_b_result else 30)]
    rows += finish()
    rows.sort(key=lambda row: (row['timestamp_ns'], row['cpu']))
    return stream(rows), b


class BackwardCompletionContracts(unittest.TestCase):
    def test_pre_release_dead_descendant_keeps_capture_context_not_negative_tool_lifetime(self):
        child = dict(A, thread_birth_ns=2, process_birth_ns=2, comm='runc:[2:INIT]')
        rows = [ev('SWITCH_OUT', 1, state='STOPPED'), ev('FORK', 2, child, peer=ROOT),
            ev('WAKEUP', 3, child), ev('SWITCH_IN', 4, child),
            ev('SYSCALL_ENTER', 5, child, syscall_call_id=5, syscall_nr=0, args=[3, 0, 4]),
            ev('FILE_OBJECT', 6, child, syscall_call_id=5,
                file={'mount_id': 1, 'device': 2, 'inode': 3, 'generation': 4,
                      'path': '/runtime/setup', 'path_quality': 'KERNEL_D_PATH'}),
            ev('FILE_READ', 7, child, syscall_call_id=5, start_ns=5, end_ns=7,
                requested_bytes=4, returned_bytes=4, result=4,
                file={'mount_id': 1, 'device': 2, 'inode': 3, 'generation': 4}),
            ev('SYSCALL_EXIT', 7, child, syscall_call_id=5, syscall_nr=0, result=4),
            ev('EXIT', 8, child), ev('SWITCH_OUT', 9, child, state='SLEEP_D', prev_state=0x80),
            ev('WAKEUP', 10), ev('SWITCH_IN', 11)] + finish()
        report = build_report(stream(rows), manifest(), {})
        setup = next(thread for thread in report['threads'] if thread['tid'] == child['tid'])
        self.assertEqual((setup['begin_ns'], setup['end_ns']), (2, 9))
        self.assertEqual(setup['capture_observed_begin_ns'], 2)
        self.assertEqual(setup['timeline_scope'], 'CAPTURE_CONTEXT_OUTSIDE_EXECUTION_WINDOW')
        self.assertEqual(setup['execution_window_intersection']['status'], 'EMPTY_PRE_EXEC_TOOL_SETUP')
        self.assertIsNone(setup['execution_window_intersection']['begin_ns'])
        self.assertIsNone(setup['execution_window_intersection']['end_ns'])
        self.assertEqual(len(setup['calls']), 1, 'pre-exec history must not be deleted to get a green view')
        self.assertEqual(setup['calls'][0]['files'][0]['read']['returned_bytes'], 4)
        self.assertEqual(sum(setup['state_totals_ns'].values()), 7)
        self.assertTrue(all(part['begin_ns'] < part['end_ns'] <= 9 for part in setup['segments']))
        completion = report['critical_path']['tools'][0]
        self.assertEqual(completion['wall_ns'], 90)
        self.assertEqual(sum(part['end_ns'] - part['begin_ns'] for part in completion['segments']), 90)
        self.assertFalse(any(part.get('thread_key') == setup['key'] for part in completion['segments']))
        # The complete renderer must accept this preserved prelude context.
        from render import render_report
        self.assertIn('Agent', render_report(report))
        # The file export preserves this real setup read as excluded, not an
        # Agent execution read or silently lost record.
        from export_reads import export_report
        with tempfile.TemporaryDirectory() as directory:
            receipt = export_report(report, Path(directory) / 'reads')
            self.assertEqual(receipt['counts']['report_read_records'], 1)
            self.assertEqual(receipt['counts']['WITHIN_TOOL_EXECUTION_WINDOW'], 0)
            self.assertEqual(receipt['counts']['excluded_owned_read_records'], 1)

    def test_later_parallel_child_replaces_hidden_earlier_wait(self):
        rows, b = dual_wait()
        report = build_report(rows, manifest(), {})
        path = report['critical_path']['tools'][0]
        self.assertTrue(any(part.get('thread_key') == identity_key(b, BOOT) for part in path['segments']))
        self.assertFalse(any(part.get('thread_key') == identity_key(A, BOOT) for part in path['segments']))
        self.assertEqual(sum(part['end_ns'] - part['begin_ns'] for part in path['segments']), 90)

    def test_child_fork_after_first_join_keeps_serial_prefix(self):
        rows, b = dual_wait(serial=True)
        path = build_report(rows, manifest(), {})['critical_path']['tools'][0]
        self.assertTrue(any(part.get('thread_key') == identity_key(A, BOOT) for part in path['segments']))
        self.assertTrue(any(part.get('thread_key') == identity_key(b, BOOT) for part in path['segments']))

    def test_already_completed_second_child_does_not_replace_decisive_first(self):
        rows, b = dual_wait(early_b=True)
        path = build_report(rows, manifest(), {})['critical_path']['tools'][0]
        self.assertTrue(any(part.get('thread_key') == identity_key(A, BOOT) for part in path['segments']))
        self.assertFalse(any(part.get('thread_key') == identity_key(b, BOOT) for part in path['segments']))

    def test_missing_waker_never_creates_wait4_dependency(self):
        rows, _ = dual_wait(missing_b_waker=True)
        edges = build_report(rows, manifest(), {})['critical_path']['tools'][0]['dependency_edges']
        self.assertFalse(any(edge.get('call_id') == 70 for edge in edges))

    def test_wrong_wait4_return_never_creates_matching_child_dependency(self):
        rows, _ = dual_wait(wrong_b_result=True)
        edges = build_report(rows, manifest(), {})['critical_path']['tools'][0]['dependency_edges']
        self.assertFalse(any(edge.get('call_id') == 70 for edge in edges))

    def test_wrong_syscall_exit_number_cannot_confirm_wait4_dependency(self):
        rows, _ = dual_wait()
        for row in rows:
            if row['event'] == 'SYSCALL_EXIT' and row.get('syscall_call_id') == 70:
                row['syscall_nr'] = 0
        try:
            report = build_report(rows, manifest(), {})
        except ValueError:
            return
        self.assertFalse(any(edge.get('call_id') == 70 for edge in
                             report['critical_path']['tools'][0]['dependency_edges']),
                         'a read exit must not complete a wait4 entry and establish its child dependency')

    def test_transport_gap_prevents_backward_causal_edges(self):
        rows, _ = dual_wait()
        report = build_report(rows, manifest(), {'cpu_totals': [{'ring_lost': 1}]})
        self.assertEqual(report['critical_path']['status'], 'INCOMPLETE')
        self.assertFalse(any('WAIT4' in edge['basis'] for edge in report['critical_path']['tools'][0]['dependency_edges']))

    def test_live_descendant_after_root_exit_is_not_pure_runtime_return(self):
        rows = base() + [ev('FORK', 20, A, peer=ROOT), ev('WAKEUP', 21, A),
            ev('SWITCH_IN', 30, A, cpu=1), ev('EXIT', 40), ev('SWITCH_OUT', 41, state='SLEEP_D'),
            ev('EXIT', 151, A, cpu=1), ev('SWITCH_OUT', 152, A, cpu=1, state='SLEEP_D')]
        report = build_report(stream(rows), manifest(200), {})
        parts = [part for part in report['critical_path']['tools'][0]['segments']
                 if part['begin_ns'] < 151 and part['end_ns'] > 41]
        self.assertTrue(any(part['state'] != 'RUNTIME_RETURN' for part in parts),
            'tool end waits whole cgroup; a live child cannot be hidden as control-return time')

    def test_group_empty_completion_follows_last_owned_exit_not_early_root(self):
        rows = base() + [ev('FORK', 20, A, peer=ROOT), ev('WAKEUP', 21, A),
            ev('SWITCH_IN', 30, A, cpu=1), ev('EXIT', 40), ev('SWITCH_OUT', 41, state='SLEEP_D'),
            ev('EXIT', 151, A, cpu=1), ev('SWITCH_OUT', 152, A, cpu=1, state='SLEEP_D')]
        data = manifest(200)
        data['tools'][0]['cgroup_empty'] = True
        path = build_report(stream(rows), data, {})['critical_path']['tools'][0]
        self.assertEqual(path['completion_seed_thread'], identity_key(A, BOOT))
        self.assertTrue(any(part.get('thread_key') == identity_key(A, BOOT) and part['state'] == 'ONCPU'
                            and part['end_ns'] > 41 for part in path['segments']))

    def test_unscoped_numeric_pid_cannot_establish_cross_namespace_wait_target(self):
        rows, _ = dual_wait()
        data = manifest()
        data.pop('scope')
        path = build_report(rows, data, {})['critical_path']['tools'][0]
        self.assertFalse(any('WAIT4' in edge['basis'] for edge in path['dependency_edges']),
                         'without namespace mapping, coincident PID numbers are not a valid join')


class ReplayGapContracts(unittest.TestCase):
    def test_exit_hook_preemption_keeps_cleanup_running_until_task_dead_switch(self):
        rows = base() + [ev('EXIT', 40),
            ev('SWITCH_OUT', 50, state='RUNNABLE', prev_state=0, preempt=True),
            ev('SWITCH_IN', 60),
            ev('SWITCH_OUT', 90, state='SLEEP_D', prev_state=0x80, preempt=False)]
        report = build_report(stream(rows), manifest(), {})
        thread = next(thread for thread in report['threads'] if thread['tid'] == ROOT['tid'])
        self.assertEqual(thread['exit_ns'], 40, 'EXIT is the early exit hook, not task death')
        self.assertEqual(thread['terminal_switch_ns'], 90)
        self.assertEqual(thread['end_ns'], 90)
        self.assertTrue(any(part['state'] == 'ONCPU' and part['begin_ns'] <= 60 and part['end_ns'] >= 90
                            for part in thread['segments']), 'post-exit kernel cleanup must remain visible')
        self.assertTrue(any(part['state'] == 'RUNNABLE' and part['begin_ns'] == 50 and part['end_ns'] == 60
                            for part in thread['segments']), 'preempted cleanup must preserve CPU queue time')
        path = report['critical_path']['tools'][0]
        self.assertFalse(any(part['state'] == 'RUNTIME_RETURN' and part['begin_ns'] < 90 for part in path['segments']))

    def test_unknown_file_identities_cannot_join_a_path_by_null_equality(self):
        rows = base() + [ev('SYSCALL_ENTER', 20, syscall_nr=0, syscall_call_id=20, args=[3, 0, 100]),
            ev('FILE_OBJECT', 21, syscall_call_id=20, file={'path': '/invented', 'path_quality': 'KERNEL_D_PATH'}),
            ev('SWITCH_OUT', 30, state='SLEEP_D', syscall_call_id=20), ev('WAKEUP', 40), ev('SWITCH_IN', 50),
            ev('FILE_READ', 59, syscall_call_id=20, start_ns=21, end_ns=59,
                requested_bytes=100, returned_bytes=10, result=10, file={}),
            ev('SYSCALL_EXIT', 60, syscall_nr=0, syscall_call_id=20, result=10)] + finish()
        try:
            report = build_report(stream(rows), manifest(), {})
        except ValueError:
            return
        for thread in report['threads']:
            for segment in thread['segments']:
                self.assertFalse(any(file.get('path') == '/invented' for file in segment['files']),
                                 'missing/zero identities are not an object join key')

    def test_missing_wakeup_cannot_turn_runqueue_wait_into_proven_sleep(self):
        rows = base() + [ev('SWITCH_OUT', 30, state='SLEEP_S'), ev('SWITCH_IN', 80)] + finish()
        report = build_report(stream(rows), manifest(), {})
        self.assertNotEqual(report['critical_path']['status'], GREEN,
            'sleep-to-running without observed wakeup has an unknown wake boundary')

    def test_duplicate_switch_in_is_not_a_verified_transition_sequence(self):
        report = build_report(stream(base() + [ev('SWITCH_IN', 30)] + finish()), manifest(), {})
        self.assertNotEqual(report['critical_path']['status'], GREEN,
            'ONCPU to ONCPU is not a second valid scheduler transition')

    def test_conflicting_process_identity_for_same_thread_birth_is_rejected_or_incomplete(self):
        conflicting = dict(ROOT, tgid=999, process_birth_ns=777)
        rows = stream(base() + [ev('FILE_OBJECT', 25, conflicting, syscall_call_id=0,
            file={'mount_id': 1, 'device': 2, 'inode': 3, 'generation': 4})] + finish())
        try:
            report = build_report(rows, manifest(), {})
        except ValueError:
            return
        self.assertNotEqual(report['critical_path']['status'], GREEN,
            'a stable tid/birth must not silently absorb a conflicting process identity')

    def test_truncated_line_cannot_be_replayed_as_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'events.jsonl'
            path.write_bytes(json.dumps(stream(base())[0]).encode())
            with self.assertRaisesRegex(ValueError, 'truncated'):
                load_events(path)


class LedgerBindingContracts(unittest.TestCase):
    def test_final_tool_payload_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = manifest()
            enrolled = copy.deepcopy(value['tools'][0])
            enrolled.update(begin_ns=None, end_ns=None)
            started = dict(value['tools'][0], end_ns=None)
            ended = dict(value['tools'][0], end_ns=999)
            rows = [dict(enrolled, event='TOOL_ENROLLED'), dict(started, event='TOOL_START'), dict(ended, event='TOOL_END')]
            (root / 'tool-spans.jsonl').write_bytes(b''.join(canonical(row) for row in rows))
            with self.assertRaisesRegex(ValueError, 'final span'):
                check_tool_ledger(root, value)

    def test_consumer_cannot_use_unbound_health_raw_and_ledger(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / 'capture'
            capture.mkdir()
            native = root / 'fake-native'
            native.write_bytes(b'synthetic decoder identity only')
            value = manifest()
            raw = b''.join(canonical(row) for row in stream(base() + finish()))
            (capture / 'events.jsonl').write_bytes(raw)
            (capture / 'events.bin').write_bytes(b'synthetic')
            (capture / 'health.json').write_bytes(b'{}\n')
            (root / 'enrollment.json').write_bytes(canonical(value['tools']))
            value.update(collector_binary=str(native), collector_identity=digest(native),
                         capture_directory='capture', artifacts={'enrollment.json': digest(root / 'enrollment.json')})
            (root / 'manifest.json').write_bytes(canonical(value))
            def fake_decode(command, **kwargs):
                Path(command[command.index('--output') + 1]).write_bytes(raw)
                return mock.Mock(returncode=0)
            with mock.patch('replay.subprocess.run', side_effect=fake_decode):
                with self.assertRaisesRegex(ValueError, 'bound|artifact|evidence|missing|required'):
                    verify_run(root)


if __name__ == '__main__':
    unittest.main()
