"""Adversarial zero-paid seccomp proof reconstruction, not live coverage."""
import copy
import unittest

from replay import build_report, seccomp_skip_closures
from test_replay import BOOT, PARENT, ev, events, manifest


def pair(number=435, result=-38):
    task = dict(PARENT, cgroup_id=11)
    return events([
        ev('SWITCH_OUT', 1, task, state='STOPPED'), ev('WAKEUP', 10, task), ev('SWITCH_IN', 20, task),
        ev('SECCOMP_SKIP', 30, task, flags=0, syscall_call_id=0, syscall_nr=number,
           return_value=result, start_ns=None, end_ns=None, duration_ns=None,
           args=[0, 0, 0, 0, 0, 0], seccomp_recheck_after_trace=False,
           seccomp_skip_proof='KERNEL_FEXIT_FILTER_FALSE_AND_SAVED_REGISTERS', seccomp_action='UNKNOWN_NOT_OBSERVED'),
        ev('SYSCALL_EXIT', 40, task, flags=8388608, syscall_call_id=0, syscall_nr=number,
           return_value=result, start_ns=None, end_ns=None, duration_ns=None,
           args=[30, 0, 0, 0, 0, 0], seccomp_skipped_exit=True, seccomp_skip_reference_ns=30,
           closure_kind='SECCOMP_SKIPPED_WITHOUT_RAW_ENTRY'),
        ev('EXIT', 998, task), ev('SWITCH_OUT', 999, task, state='SLEEP_D')])


class SeccompSkipTests(unittest.TestCase):
    def test_skip_proof_does_not_invent_call_duration_or_filter_action(self):
        for number, result in ((435, -38), (110, -13), (102, 0), (1, 123)):
            with self.subTest(number=number, result=result):
                closures, findings = seccomp_skip_closures(pair(number, result), BOOT)
                self.assertEqual(len(closures), 1)
                self.assertFalse(findings)
                report = build_report(pair(number, result), manifest(), {})
                self.assertFalse([f for f in report['findings'] if 'SYSCALL' in f['kind'] or 'SECCOMP' in f['kind']])
                thread = report['threads'][0]
                self.assertEqual(thread['calls'], [])
                self.assertEqual(thread['seccomp_skips'][0]['syscall_duration_ns'], None)
                self.assertEqual(thread['seccomp_skips'][0]['action'], 'UNKNOWN_NOT_OBSERVED')

    def test_errno_alone_and_old_unpaired_records_stay_incomplete(self):
        rows = pair()
        rows.pop(3)
        rows[3].update(flags=512, seccomp_skipped_exit=False, seccomp_skip_reference_ns=None)
        report = build_report(events(rows), manifest(), {'status': 'INCOMPLETE', 'counters': {'unpaired_results': 17}})
        self.assertTrue(any(f['kind'] == 'ORPHAN_SYSCALL_EXIT' for f in report['findings']))
        self.assertTrue(any(f['kind'] == 'COLLECTION_GAP' for f in report['findings']))

    def test_missing_duplicate_future_cross_thread_or_changed_proof_rejected(self):
        mutations = [
            lambda r: r.pop(3),
            lambda r: r.insert(4, copy.deepcopy(r[3])),
            lambda r: r[4].update(seccomp_skip_reference_ns=31),
            lambda r: r[4].update(syscall_nr=110),
            lambda r: r[4].update(return_value=-1),
            lambda r: r[4].update(task=dict(r[4]['task'],cgroup_id=12)),
            lambda r: r[4].update(task=dict(r[4]['task'],process_birth_ns=101)),
            lambda r: r[4].update(task=dict(r[4]['task'],thread_birth_ns=101)),
            lambda r: r[3].update(seccomp_skip_proof='USERSPACE_ERRNO_GUESS'),
            lambda r: r[3].update(seccomp_action='ERRNO'),
            lambda r: r[4].update(start_ns=30, end_ns=40, duration_ns=10),
            lambda r: r[4].update(syscall_call_id=30),
            lambda r: r[4].update(flags=8388608|512),
            lambda r: r[4].update(args=[31,0,0,0,0,0]),
            lambda r: r[4].update(timestamp_ns=29),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                rows=copy.deepcopy(pair());mutate(rows)
                rows.sort(key=lambda e:e['timestamp_ns'])
                closures, findings=seccomp_skip_closures(rows,BOOT)
                self.assertTrue(findings)

    def test_intervening_raw_entry_invalidates_skip_pair(self):
        rows=pair()
        rows.insert(4, ev('SYSCALL_ENTER',35,dict(PARENT,cgroup_id=11),syscall_nr=435,syscall_call_id=35))
        closures, findings=seccomp_skip_closures(events(rows),BOOT)
        self.assertFalse(closures)
        self.assertTrue(any(f['kind']=='SECCOMP_SKIP_HAS_RAW_ENTRY' for f in findings))


if __name__ == '__main__':
    unittest.main()
