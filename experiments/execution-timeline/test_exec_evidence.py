"""Successful exec evidence stays distinct from comm, argv, and canonical path."""
import unittest
from replay import build_report
from test_replay import events, ev, PARENT, manifest


class ExecEvidenceTests(unittest.TestCase):
    def test_execs_keep_actual_success_and_filename_object(self):
        rows=events([ev('SWITCH_OUT',1,state='STOPPED'),ev('WAKEUP',10),ev('SWITCH_IN',20),
            ev('EXEC',30,old_tid=10,exec_filename='./runner',
               exec_filename_quality='KERNEL_EXEC_FILENAME_NOT_CANONICAL_PATH',
               exec_object_quality='KERNEL_BPRM_FILE_IDENTITY',
               file={'mount_id':7,'device':2,'inode':3,'generation':0,'path':'./runner',
                     'path_quality':'KERNEL_EXEC_FILENAME_NOT_CANONICAL_PATH'}),
            ev('EXIT',998),ev('SWITCH_OUT',999,state='SLEEP_D')])
        entry=build_report(rows,manifest(),{})['threads'][0]['execs'][0]
        self.assertEqual(entry['timestamp_ns'],30)
        self.assertEqual(entry['filename'],'./runner')
        self.assertEqual(entry['file']['inode'],3)
        self.assertEqual(entry['evidence'],'KERNEL_SCHED_PROCESS_EXEC_SUCCESS')
        self.assertIsNone(entry['argv'])
        self.assertEqual(entry['argv_quality'],'NOT_CAPTURED')

    def test_legacy_or_failed_filename_remains_unknown_not_comm(self):
        for quality in (None,'NOT_CAPTURED','READ_FAILED_OR_TRUNCATED'):
            extra={} if quality is None else {'exec_filename_quality':quality,'exec_filename':'untrusted'}
            rows=events([ev('EXEC',30,**extra),ev('EXIT',998),ev('SWITCH_OUT',999,state='SLEEP_D')])
            entry=build_report(rows,manifest(),{})['threads'][0]['execs'][0]
            self.assertIsNone(entry['filename'])
            self.assertEqual(entry['executable_identity_quality'],'NOT_CAPTURED')


if __name__=='__main__':unittest.main()
