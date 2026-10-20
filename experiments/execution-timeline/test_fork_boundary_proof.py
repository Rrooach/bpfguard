"""No entry duration/PID binding is invented for an observed fork return."""
import unittest

from replay import build_report
from test_replay_adversarial import A, ROOT, ev, manifest, stream


class BoundaryForkTests(unittest.TestCase):
    def report(self, source='KERNEL_PT_REGS_AT_FORK_NO_ENTRY_EVENT', fork_nr=435, result=0, call_id=None):
        fork = ev('FORK', 20, A, peer=ROOT, fork_parent_syscall_source=source,
                  fork_parent_syscall_nr=fork_nr, fork_parent_call_id=call_id)
        rows = stream([ev('SWITCH_OUT', 1, state='STOPPED'), ev('WAKEUP', 10),
            ev('SWITCH_IN', 11), fork, ev('WAKEUP', 21, A), ev('SWITCH_IN', 22, A),
            ev('SYSCALL_EXIT', 23, A, syscall_nr=435, syscall_call_id=0,
               return_value=result, fork_child_return=True),
            ev('EXIT', 80, A), ev('SWITCH_OUT', 81, A, prev_state=128),
            ev('EXIT', 98), ev('SWITCH_OUT', 99, prev_state=128)])
        return build_report(rows, manifest(), {})

    def test_register_proof_does_not_fabricate_entry_or_pid_binding(self):
        report = self.report()
        child = next(thread for thread in report['threads'] if thread['tid'] == A['tid'])
        self.assertEqual(child['calls'], [])
        self.assertNotIn('pid_binding', child)
        self.assertFalse(any(item['kind'] == 'ORPHAN_SYSCALL_EXIT' for item in report['findings']))

    def test_mismatched_unknown_or_nonzero_child_return_stays_gap(self):
        for options in ({'source': None}, {'fork_nr': 56}, {'result': 2}):
            with self.subTest(options=options):
                self.assertTrue(any(item['kind'] == 'ORPHAN_SYSCALL_EXIT' for item in self.report(**options)['findings']))

    def test_exact_pending_parent_entry_proof_remains_supported(self):
        report = self.report(source='KERNEL_PARENT_PENDING_SYSCALL_ENTRY', call_id=19)
        self.assertFalse(any(item['kind'] == 'ORPHAN_SYSCALL_EXIT' for item in report['findings']))


if __name__ == '__main__':
    unittest.main()
