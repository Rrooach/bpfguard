import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import diagnostics


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cgroot = self.root / 'cgroup'
        self.cgroup = self.cgroot / 'container-exact-id'
        self.cgroup.mkdir(parents=True)
        (self.cgroup / 'cgroup.controllers').write_text('cpu memory io\n')
        (self.cgroup / 'cgroup.events').write_text('populated 1\nfrozen 1\n')
        self.schedstats = self.root / 'schedstats'
        self.schedstats.write_text('1\n')
        self.boot = self.root / 'boot_id'
        self.boot.write_text('test-boot\n')
        self.patchers = [patch.object(diagnostics, 'CGROUP_ROOT', self.cgroot),
                         patch.object(diagnostics, 'SCHEDSTATS', self.schedstats),
                         patch.object(diagnostics, 'BOOT_ID', self.boot)]
        for patcher in self.patchers:
            patcher.start()
        self.object = self.root / 'profile.bpf.o'
        self.object.write_bytes(b'fixture object, never loaded into kernel')

    def tearDown(self):
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temp.cleanup()

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def config(self, mode='baseline', **values):
        return {'mode': mode, **values}

    def create(self, config=None, name='diagnostic'):
        return diagnostics.Diagnostics(config, self.root / name, self.cgroup, 'run-id')

    def file_config(self, *, mismatch=False, health='COMPLETE_FOR_SELECTED_HOOKS', exit_code=0):
        script = self.root / 'file-profiler'
        script.write_text('#!' + sys.executable + '\n' + '''
import argparse,json,os,pathlib,signal,time,sys
p=argparse.ArgumentParser()
for key in ('output-dir','bpf-object','bpf-sha256','cgroup','label','max-seconds','max-file-records'):
 p.add_argument('--'+key)
a=p.parse_args()
out=pathlib.Path(a.output_dir); out.mkdir()
cg=pathlib.Path(a.cgroup); stat=cg.stat()
meta={'label':a.label,'boot_id':'test-boot','bpf_sha256':a.bpf_sha256,
      'domains':[{'path':str(cg),'inode':stat.st_ino+MISMATCH,'device':stat.st_dev}]}
(out/'file-profile-meta.json').write_text(json.dumps(meta))
def done(*_):
 (out/'file-profile.json').write_text(json.dumps({'boot_id':'test-boot','timed_out':False,
   'observation_health':HEALTH,'health':{'fixture':True},'records':[]}))
 sys.exit(EXIT_CODE)
signal.signal(signal.SIGTERM,done)
print('READY',flush=True)
while True: time.sleep(.02)
'''.replace('MISMATCH', str(int(mismatch))).replace('HEALTH', repr(health)).replace('EXIT_CODE', str(exit_code)))
        script.chmod(0o700)
        return self.config('files', file_profiler_binary=str(script), file_profiler_sha256=self.sha(script),
            file_profiler_object=str(self.object), file_profiler_object_sha256=self.sha(self.object))

    def perf_config(self, *, bad_ack=False, report_code=0, reraise_signal=False):
        script = self.root / 'perf'
        script.write_text('#!' + sys.executable + '\n' + '''
import os,pathlib,signal,sys,time
if sys.argv[1]=='report':
 print('fixture-symbol candidate, not exact accounting')
 sys.exit(REPORT_CODE)
args=sys.argv
control=args[args.index('--control')+1]
read_fd,write_fd=map(int,control.split(':')[1].split(','))
data=pathlib.Path(args[args.index('-o')+1])
data.write_bytes(b'fixture-perf-not-real-profile')
def done(*_):
 if RERAISE_SIGNAL:
  signal.signal(signal.SIGINT,signal.SIG_DFL)
  os.kill(os.getpid(),signal.SIGINT)
 sys.exit(0)
signal.signal(signal.SIGINT,done)
with os.fdopen(read_fd,'rb',buffering=0) as incoming:
 while True:
  command=incoming.readline()
  if not command: break
  os.write(write_fd,b'BAD_ACK\\n' if BAD_ACK else b'ack\\n\\0')
'''.replace('BAD_ACK else', str(bad_ack) + ' else').replace('REPORT_CODE', str(report_code))
    .replace('RERAISE_SIGNAL', str(reraise_signal)))
        script.chmod(0o700)
        return self.config('perf', perf_binary=str(script), perf_sha256=self.sha(script))

    def test_default_baseline_has_no_extra_sampler_or_collector(self):
        self.assertEqual(diagnostics.sampler_options(None), [])
        item = self.create()
        ready = item.start()
        self.assertEqual(ready['status'], 'READY')
        result = item.finish()
        self.assertEqual(result['status'], 'COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE')
        self.assertIsNone(result['collector_usage'])
        self.assertEqual(item.finish(), result)
        self.assertTrue((item.output / 'diagnostics.json').is_file())

    def test_unknown_mode_rejected(self):
        with self.assertRaises(ValueError):
            diagnostics.sampler_options({'mode': 'silently-fallback'})

    def test_threads_require_schedstats_and_explicit_sampling(self):
        self.assertEqual(diagnostics.sampler_options({'mode': 'threads'}), ['--sample-threads'])
        self.schedstats.write_text('0\n')
        with self.assertRaisesRegex(RuntimeError, 'sched_schedstats=1'):
            diagnostics.sampler_options({'mode': 'threads'})
        item = self.create({'mode': 'threads'})
        with self.assertRaises(RuntimeError):
            item.start()
        self.assertEqual(json.loads((item.output / 'diagnostics.json').read_text())['status'], 'START_FAILED')

    def test_kernel_uses_all_groups_and_frozen_pinned_object(self):
        config = self.config('kernel', kernel_hist_object=str(self.object), kernel_hist_sha256=self.sha(self.object))
        options = diagnostics.sampler_options(config)
        self.assertIn('--sample-threads', options)
        self.assertEqual(options[options.index('--kernel-hist-groups') + 1], diagnostics.KERNEL_GROUPS)
        item = self.create(config)
        item.start()
        self.assertEqual(item.finish()['status'], 'COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE')

    def test_pinned_object_change_is_not_accepted(self):
        config = self.config('kernel', kernel_hist_object=str(self.object), kernel_hist_sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            diagnostics.sampler_options(config)

    def test_nonbaseline_requires_frozen_workload_at_both_boundaries(self):
        item = self.create({'mode': 'threads'})
        item.start()
        (self.cgroup / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
        with self.assertRaisesRegex(RuntimeError, 'frozen=1'):
            item.finish()
        result = json.loads((item.output / 'diagnostics.json').read_text())
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertTrue(result['issues'])

    def test_schedstats_cannot_be_disabled_during_threads_run(self):
        item = self.create({'mode': 'threads'})
        item.start()
        self.schedstats.write_text('0\n')
        with self.assertRaisesRegex(RuntimeError, 'remain enabled'):
            item.finish()
        self.assertEqual(item.report['status'], 'INCOMPLETE')

    def test_cgroup_root_and_symlink_targets_rejected(self):
        for target in (self.cgroot, self.root / 'link'):
            with self.subTest(target=target):
                if target.name == 'link':
                    target.symlink_to(self.cgroup)
                with self.assertRaises(ValueError):
                    diagnostics._identity(target)

    def test_cgroup_replacement_is_rejected(self):
        item = self.create({'mode': 'threads'})
        item.start()
        self.cgroup.rename(self.cgroup.with_name('old-container'))
        self.cgroup.mkdir()
        (self.cgroup / 'cgroup.controllers').write_text('cpu\n')
        (self.cgroup / 'cgroup.events').write_text('frozen 1\n')
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            item.finish()

    def test_file_profiler_real_child_ready_binding_and_usage_preserved(self):
        item = self.create(self.file_config())
        self.assertTrue(item.start()['file_metadata_binding_validated'])
        result = item.finish()
        self.assertEqual(result['status'], 'COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE')
        self.assertEqual(result['file_observation_health'], 'COMPLETE_FOR_SELECTED_HOOKS')
        self.assertEqual(result['collector_usage']['returncode'], 0)
        self.assertEqual(result['collector_usage']['usage_status'], 'COMPLETE')
        self.assertGreater(result['collector_usage']['max_rss_kib'], 0)
        self.assertGreater(result['evidence_bytes_excluding_this_summary'], 0)
        self.assertTrue((item.output / 'collector.stderr').is_file())

    def test_file_profiler_metadata_wrong_cgroup_fails_closed_and_reaps_child(self):
        item = self.create(self.file_config(mismatch=True))
        with self.assertRaisesRegex(RuntimeError, 'exact cgroup binding'):
            item.start()
        self.assertIsNotNone(item.process.returncode)
        self.assertEqual(item.report['status'], 'START_FAILED')
        self.assertTrue((item.output / 'files/file-profile-meta.json').is_file())

    def test_file_profiler_missing_ready_does_not_silently_fallback(self):
        config = self.file_config()
        binary = Path(config['file_profiler_binary'])
        binary.write_text('#!' + sys.executable + '\nraise SystemExit(0)\n')
        config['file_profiler_sha256'] = self.sha(binary)
        item = self.create(config)
        with self.assertRaisesRegex(RuntimeError, 'closed its readiness'):
            item.start()
        self.assertEqual(item.report['status'], 'START_FAILED')
        self.assertIsNotNone(item.process.returncode)
        self.assertTrue((item.output / 'collector.stderr').is_file())

    def test_file_ready_timeout_retains_failure_and_reaps_child(self):
        item = self.create(self.file_config())
        with patch.object(diagnostics, '_line', side_effect=TimeoutError('fixture-ready-timeout')):
            with self.assertRaisesRegex(TimeoutError, 'fixture-ready-timeout'):
                item.start()
        self.assertEqual(item.report['status'], 'START_FAILED')
        self.assertIsNotNone(item.process.returncode)

    def test_file_metadata_tampering_at_finish_is_detected(self):
        item = self.create(self.file_config())
        item.start()
        path = item.output / 'files/file-profile-meta.json'
        value = json.loads(path.read_text())
        value['boot_id'] = 'another-boot'
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError, 'run/boot/object binding'):
            item.finish()
        self.assertEqual(item.report['status'], 'INCOMPLETE')

    def test_file_health_incomplete_is_reported_not_hidden(self):
        item = self.create(self.file_config(health='INCOMPLETE'))
        item.start()
        result = item.finish()
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['file_observation_health'], 'INCOMPLETE')
        self.assertIn('file_profile_incomplete_for_selected_hooks', result['issues'])

    def test_file_nonzero_exit_raises_after_persisting_failure(self):
        item = self.create(self.file_config(exit_code=7))
        item.start()
        with self.assertRaisesRegex(RuntimeError, 'failure: 7'):
            item.finish()
        self.assertEqual(item.report['collector_usage']['returncode'], 7)
        self.assertEqual(item.report['status'], 'INCOMPLETE')

    def test_perf_real_child_enable_disable_ack_exact_cgroup_and_report(self):
        item = self.create(self.perf_config())
        ready = item.start()
        command = ready['command']
        self.assertEqual(command[command.index('-G') + 1], self.cgroup.name)
        self.assertIn('--delay=-1', command)
        self.assertIn('dwarf,8192', command)
        result = item.finish()
        self.assertEqual(result['status'], 'COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE')
        controls = [json.loads(row) for row in (item.output / 'perf-control.jsonl').read_text().splitlines()]
        self.assertEqual([row['command'] for row in controls], ['enable', 'disable'])
        self.assertEqual(result['collector_usage']['usage_status'], 'COMPLETE')
        self.assertIn('fixture-symbol', (item.output / 'perf-report.txt').read_text())

    def test_perf_ack_accepts_old_and_nul_padded_perf_protocol(self):
        for payload in (b'ack\n', b'ack\n\0', b'\0ack\n\0'):
            with self.subTest(payload=payload):
                read_fd, write_fd = os.pipe()
                try:
                    os.write(write_fd, payload)
                    value = diagnostics._line(read_fd, 1, allow_nul_padding=True)
                    self.assertEqual(value.strip(b'\0\r\n'), b'ack')
                finally:
                    os.close(read_fd)
                    os.close(write_fd)

    def test_file_ready_does_not_accept_perf_nul_padding(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'READY\n\0')
            with self.assertRaisesRegex(RuntimeError, 'unexpected diagnostic'):
                diagnostics._line(read_fd, 1)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_perf_bad_ack_fails_before_releasing_workload(self):
        item = self.create(self.perf_config(bad_ack=True))
        with self.assertRaisesRegex(RuntimeError, 'acknowledge enable'):
            item.start()
        self.assertEqual(item.report['status'], 'START_FAILED')
        self.assertIsNotNone(item.process.returncode)

    def test_perf_report_failure_preserved_and_raised(self):
        item = self.create(self.perf_config(report_code=4))
        item.start()
        with self.assertRaisesRegex(RuntimeError, 'perf report failed'):
            item.finish()
        self.assertEqual(item.report['perf_report_returncode'], 4)
        self.assertEqual(item.report['status'], 'INCOMPLETE')
        self.assertTrue((item.output / 'perf-report.stderr').is_file())

    def test_perf_expected_sigint_is_raw_preserved_and_requires_valid_report(self):
        item = self.create(self.perf_config(reraise_signal=True))
        item.start()
        result = item.finish()
        self.assertEqual(result['collector_usage']['returncode'], -2)
        self.assertEqual(result['collector_termination'], 'EXPECTED_PERF_SIGINT_REQUIRES_VALID_REPORT')
        self.assertEqual(result['perf_report_returncode'], 0)
        self.assertEqual(result['status'], 'COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE')

    def test_perf_missing_enable_ack_cannot_mark_ready(self):
        item = self.create(self.perf_config())
        with patch.object(diagnostics, '_line', side_effect=TimeoutError('fixture-ack-timeout')):
            with self.assertRaisesRegex(TimeoutError, 'fixture-ack-timeout'):
                item.start()
        self.assertEqual(item.report['status'], 'START_FAILED')
        self.assertIsNotNone(item.process.returncode)

    def test_start_and_finish_order_is_enforced(self):
        item = self.create()
        with self.assertRaises(RuntimeError):
            item.finish()
        item.start()
        try:
            with self.assertRaises(RuntimeError):
                item.start()
        finally:
            item.finish()


if __name__ == '__main__':
    unittest.main()
