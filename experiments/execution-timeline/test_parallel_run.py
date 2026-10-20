#!/usr/bin/env python3
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import parallel_run
import phase_control
from common import write_new
from parallel_run import complete_sample, done_times, load_plan, run
from phase_control import CampaignAborted, Control, cgroup_snapshot, publish, read_record


def fake_worker(argv):
    output, control, name, mode = Path(argv[0]), Path(argv[1]), argv[2], argv[3]
    if mode == "fail" and name == "job-0":
        return 7
    metadata = {"boot": "synthetic-only"}
    if mode.startswith('sampler-'):
        metadata.update(cgroup_root='/sys/fs/cgroup/offline-unit-' + name, cgroup_id=999)
        # This subprocess is a unit fixture, never a real cgroup/resource claim.
        phase_control.cgroup_snapshot = lambda value: {'status': 'SYNTHETIC_ONLY'}
    instance = Control(control, name, timeout=10)
    try:
        instance.ready_sync(metadata)
        time.sleep(0.02)
        returned = time.monotonic_ns()
        quiet = time.monotonic_ns()
        instance.done_sync({"agent_return_ns": returned, "quiescent_ns": quiet, "quiescent": True})
        output.mkdir()
        write_new(output / "worker-result.json", {"job_id": name, "synthetic_only": True})
        return 0
    except CampaignAborted:
        return 8


class PhaseTests(unittest.TestCase):
    def test_publish_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record"
            publish(path, {"first": True})
            with self.assertRaises(FileExistsError):
                publish(path, {"first": False})
            self.assertEqual(read_record(path), {"first": True})
            self.assertEqual(list(Path(directory).glob('.pending-*')), [])

    def test_abort_first_wins_and_breaks_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a').mkdir()
            control = Control(root, 'a', timeout=.1)
            control.fail('original')
            control.fail('replacement')
            self.assertEqual(read_record(root / 'abort.json')['error'], 'original')
            with self.assertRaises(CampaignAborted):
                control.ready_sync({})

    def test_done_without_release_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a').mkdir()
            with self.assertRaises(ValueError):
                Control(root, 'a').done_sync({})

    def test_missing_release_times_out_instead_of_green(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a').mkdir()
            with self.assertRaises(TimeoutError):
                Control(root, 'a', timeout=.02).ready_sync({})
            self.assertTrue((root / 'abort.json').is_file())

    def test_path_unsafe_job_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a').symlink_to(root, target_is_directory=True)
            for name in ('../a', 'a/b', '', 'a'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    Control(root, name)

    def test_return_and_quiescence_must_be_ordered(self):
        good = {'monotonic_ns': 100, 'metadata': {'agent_return_ns': 70, 'quiescent_ns': 80, 'quiescent': True}}
        self.assertEqual(done_times(good, 60), (70,80))
        for field,value in (('agent_return_ns',59),('quiescent_ns',69),('quiescent',False)):
            bad=json.loads(json.dumps(good));bad['metadata'][field]=value
            with self.assertRaises(ValueError):
                done_times(bad,60)


class SamplerRecordTests(unittest.TestCase):
    def row(self, seq=0, begin=10, end=12):
        return {'seq': seq, 'monotonic_ns': begin, 'collection_end_ns': end}

    def test_missing_and_partial_first_sample_do_not_satisfy_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'samples.jsonl'
            self.assertIsNone(complete_sample(path))
            path.write_text(json.dumps(self.row()))
            self.assertIsNone(complete_sample(path))
            path.write_text(json.dumps(self.row()) + '\n')
            self.assertEqual(complete_sample(path), self.row())

    def test_last_sample_ignores_partial_tail_and_returns_last_complete_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'samples.jsonl'
            rows = [self.row(), self.row(1, 20, 22)]
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows) + '{"seq":2')
            self.assertEqual(complete_sample(path), rows[0])
            self.assertEqual(complete_sample(path, last=True), rows[1])

    def test_invalid_sequence_clock_types_and_malformed_json_are_rejected(self):
        values = [None, [], {}, self.row(True), self.row(-1), self.row(1),
                  self.row(0, -1, 2), self.row(0, 13, 12), self.row(0, True, 12),
                  self.row(0, 10, 12.0), {'seq': 0, 'monotonic_ns': 10}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'samples.jsonl'
            for row in values:
                path.write_text(json.dumps(row) + '\n')
                with self.subTest(row=row), self.assertRaises(ValueError):
                    complete_sample(path)
            path.write_text('{broken}\n')
            with self.assertRaises(ValueError):
                complete_sample(path, last=True)

    def test_negative_final_sequence_is_not_a_valid_enclosing_sample(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'samples.jsonl'
            path.write_text(json.dumps(self.row(-1, 100, 102)) + '\n')
            with self.assertRaises(ValueError):
                complete_sample(path, last=True)

    def test_bounded_tail_can_find_final_record_without_loading_whole_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'samples.jsonl'
            wanted = self.row(100000, 100, 101)
            path.write_bytes((json.dumps(self.row()).encode() + b'\n') * 40000
                             + json.dumps(wanted).encode() + b'\n')
            self.assertGreater(path.stat().st_size, 1024 * 1024)
            self.assertEqual(complete_sample(path, last=True), wanted)

    def test_oversized_first_line_and_symlink_or_directory_never_satisfy_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'samples.jsonl'
            path.write_bytes(b'x' * (1024 * 1024 + 1) + b'\n')
            with self.assertRaises(ValueError):
                complete_sample(path)
            self.assertIsNone(complete_sample(path, last=True))
            link = root / 'link'
            link.symlink_to(path)
            for candidate in (link, root):
                with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                    complete_sample(candidate)


class FrozenResourceTests(unittest.TestCase):
    def fixture(self, root):
        group = root / 'group'
        group.mkdir()
        (group / 'cgroup.events').write_text('populated 1\nfrozen 1\n')
        for name in ('cpu.stat', 'memory.current', 'memory.peak', 'memory.stat', 'cpu.pressure',
                     'memory.pressure', 'io.pressure', 'io.stat', 'pids.current', 'pids.events'):
            (group / name).write_text('unit-fixture-only\n')
        return group, {'cgroup_root': str(group), 'cgroup_id': group.stat().st_ino}

    def redirected_root(self, root):
        original = Path.resolve
        def resolve(path, *args, **kwargs):
            return root if path == Path('/sys/fs/cgroup') else original(path, *args, **kwargs)
        return mock.patch.object(Path, 'resolve', resolve)

    def test_real_frozen_before_and_after_are_preserved_with_exact_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group, metadata = self.fixture(root)
            with self.redirected_root(root):
                result = cgroup_snapshot(metadata)
            self.assertEqual(result['status'], 'CAPTURED_BOUNDARY_COUNTERS')
            self.assertEqual(result['cgroup_id'], group.stat().st_ino)
            self.assertEqual(result['frozen_before']['frozen'], '1')
            self.assertEqual(result['frozen_after']['frozen'], '1')
            self.assertLessEqual(result['begin_ns'], result['end_ns'])
            self.assertEqual(len(result['files']), 10)

    def test_unfrozen_or_missing_frozen_before_counters_is_rejected(self):
        for events in ('populated 1\nfrozen 0\n', 'populated 1\n'):
            with self.subTest(events=events), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                group, metadata = self.fixture(root)
                (group / 'cgroup.events').write_text(events)
                with self.redirected_root(root), self.assertRaisesRegex(ValueError, 'not actually frozen'):
                    cgroup_snapshot(metadata)

    def test_thaw_during_counter_reads_is_not_a_completed_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group, metadata = self.fixture(root)
            original = Path.read_text
            def read(path, *args, **kwargs):
                value = original(path, *args, **kwargs)
                if path == group / 'cpu.stat':
                    (group / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
                return value
            with self.redirected_root(root), mock.patch.object(Path, 'read_text', read), \
                    self.assertRaisesRegex(ValueError, 'not actually frozen'):
                cgroup_snapshot(metadata)

    def test_changed_inode_after_counter_reads_is_not_a_completed_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group, metadata = self.fixture(root)
            original = Path.stat
            calls = []
            def stat(path, *args, **kwargs):
                value = original(path, *args, **kwargs)
                if path == group:
                    calls.append(path)
                    if len(calls) >= 4:
                        return SimpleNamespace(st_ino=value.st_ino + 1)
                return value
            with self.redirected_root(root), mock.patch.object(Path, 'stat', stat), \
                    self.assertRaisesRegex(ValueError, 'not actually frozen'):
                cgroup_snapshot(metadata)

    def test_missing_counter_is_partial_not_complete_and_identity_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group, metadata = self.fixture(root)
            (group / 'memory.peak').unlink()
            with self.redirected_root(root):
                result = cgroup_snapshot(metadata)
                with self.assertRaisesRegex(ValueError, 'identity differs'):
                    cgroup_snapshot(dict(metadata, cgroup_id=metadata['cgroup_id'] + 1))
            self.assertEqual(result['status'], 'PARTIAL_BOUNDARY_COUNTERS')
            self.assertIn('memory.peak', result['errors'])
            self.assertEqual(cgroup_snapshot({})['status'], 'NOT_SELECTED')


class ParallelRunTests(unittest.TestCase):
    def campaign(self, root, concurrency, mode='ok', sampler=None):
        plan = {'schema_version':1,'benchmark':'SYNTHETIC_CONTROLLER_TEST_ONLY','jobs':[
            {'job_id':f'job-{index}','task_id':'fixed-task', 'command':[
                sys.executable, '-B', str(Path(__file__).resolve()), '--fake-worker',
                '@JOB_OUTPUT@','@CONTROL_DIR@','@JOB_ID@', mode]} for index in range(8)]}
        path=root/'plan.json';write_new(path,plan)
        args=SimpleNamespace(plan=path,output=root/'result',concurrency=concurrency,
                             setup_timeout=10,task_timeout=10,finalize_timeout=10, sampler=sampler)
        result=run(args)
        return result,json.loads((args.output/'campaign.json').read_bytes()),args.output

    def test_same_eight_jobs_and_all_ready_in_two_and_eight_slots(self):
        for concurrency in (2,8):
            with self.subTest(concurrency=concurrency), tempfile.TemporaryDirectory() as directory:
                code,result,root=self.campaign(Path(directory),concurrency)
                self.assertEqual(code,0)
                self.assertEqual(result['status'],'WORKERS_COMPLETED')
                self.assertEqual(result['max_admitted_observed'],concurrency)
                self.assertEqual(len(result['jobs']),8)
                self.assertTrue(all(j['ready_ns']<=result['all_ready_ns']<=j['release_issued_ns']
                                    <=j['agent_return_ns']<=j['quiescent_ns'] for j in result['jobs']))
                self.assertGreaterEqual(result['postprocessing_released_ns'],result['batch_end_ns'])
                self.assertEqual(len(list((root/'jobs').glob('*/worker-result.json'))),8)

    def test_setup_failure_aborts_other_workers_without_deadlock(self):
        with tempfile.TemporaryDirectory() as directory:
            start=time.monotonic()
            code,result,root=self.campaign(Path(directory),2,'fail')
            self.assertEqual(code,1)
            self.assertEqual(result['status'],'ABORTED')
            self.assertNotIn('batch_wall_ns',result)
            self.assertTrue((root/'control/abort.json').exists())
            self.assertLess(time.monotonic()-start,10)

    def test_plan_refuses_changed_total_work_or_colliding_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'plan.json'
            path.write_text(json.dumps({'schema_version':1,'jobs':[]}))
            with self.assertRaises(ValueError):
                load_plan(path)


class SamplerLoopTests(unittest.TestCase):
    # These tests run only Python unit-fixture children. No native collector,
    # real cgroup, Docker, VM, benchmark or resource measurement is started.
    campaign = ParallelRunTests.campaign

    def sampler(self, root, mode):
        path = root / 'fake-sampler'
        code = '''import json,signal,sys,time
from pathlib import Path
mode=MODE
if mode=='exit-before-first':
    raise SystemExit(7)
output=Path(sys.argv[sys.argv.index('--output-dir')+1]);output.mkdir()
stopping=False
def stop(*args):
    global stopping
    stopping=True
signal.signal(signal.SIGTERM,stop)
with (output/'load-samples.jsonl').open('x') as stream:
    seq=0
    while not stopping:
        begin=time.monotonic_ns()
        stream.write(json.dumps({'seq':seq,'monotonic_ns':begin,'collection_end_ns':time.monotonic_ns()})+'\\n')
        stream.flush();seq+=1
        if mode=='exit-after-first':
            raise SystemExit(7)
        time.sleep(.01)
'''
        path.write_text('#!' + sys.executable + '\n' + code.replace('MODE', repr(mode)))
        path.chmod(0o700)
        return path

    def sampled_campaign(self, root, mode='ok'):
        original_resolve, original_stat = Path.resolve, Path.stat
        prefix = '/sys/fs/cgroup/offline-unit-'
        def resolve(path, *args, **kwargs):
            return path if str(path).startswith(prefix) else original_resolve(path, *args, **kwargs)
        def stat(path, *args, **kwargs):
            return SimpleNamespace(st_ino=999) if str(path).startswith(prefix) else original_stat(path, *args, **kwargs)
        with mock.patch.object(Path, 'resolve', resolve), mock.patch.object(Path, 'stat', stat), \
                mock.patch.object(parallel_run, 'cgroup_snapshot', return_value={
                    'status': 'SYNTHETIC_ONLY', 'frozen_before': {'frozen': '1'},
                    'frozen_after': {'frozen': '1'}}) as frozen_check:
            result = self.campaign(root, 2, 'sampler-ok', self.sampler(root, mode))
        return result, frozen_check.call_count

    def test_live_sampler_complete_first_and_last_samples_enclose_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            (code, result, root), frozen_checks = self.sampled_campaign(Path(directory))
            self.assertEqual(code, 0)
            self.assertEqual(frozen_checks, 8)
            self.assertEqual(result['sampler_return_code'], 0)
            self.assertLessEqual(result['sampler_first_sample_ns'], result['batch_start_ns'])
            self.assertGreaterEqual(result['sampler_last_sample_ns'], result['batch_end_ns'])
            self.assertLessEqual(result['sampler_stopped_ns'], result['postprocessing_released_ns'])
            samples = root / 'load/load-samples.jsonl'
            self.assertEqual(complete_sample(samples)['seq'], 0)
            self.assertEqual(complete_sample(samples, last=True)['monotonic_ns'], result['sampler_last_sample_ns'])
            self.assertEqual(len(list((root / 'control').glob('*/all-ready-frozen-check.json'))), 8)

    def test_sampler_dead_before_first_or_after_first_never_releases_postprocessing(self):
        for mode, message in (('exit-before-first', 'before its first sample'),
                              ('exit-after-first', 'before the final quiescence barrier')):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                (code, result, root), _checks = self.sampled_campaign(Path(directory), mode)
                self.assertEqual(code, 1)
                self.assertEqual(result['status'], 'ABORTED')
                self.assertIn(message, result['error'])
                self.assertNotIn('postprocessing_released_ns', result)
                self.assertFalse((root / 'control/all-agents-done.json').exists())

    def test_stale_complete_final_sample_does_not_satisfy_quiescence_barrier(self):
        observed = {'first': None, 'last_calls': 0}
        original = complete_sample
        def sample(path, last=False):
            row = original(path, last=last)
            if not last and row is not None:
                observed['first'] = row
            if last:
                observed['last_calls'] += 1
                self.assertFalse((Path(path).parent.parent / 'control/all-agents-done.json').exists())
                if observed['last_calls'] == 1:
                    return observed['first']
            return row
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(parallel_run, 'complete_sample', sample):
            (code, result, _root), _checks = self.sampled_campaign(Path(directory))
            self.assertEqual(code, 0)
            self.assertGreaterEqual(observed['last_calls'], 2)
            self.assertLess(observed['first']['monotonic_ns'], result['batch_end_ns'])
            self.assertGreaterEqual(result['sampler_last_sample_ns'], result['batch_end_ns'])


if __name__ == '__main__':
    if sys.argv[1:2] == ['--fake-worker']:
        raise SystemExit(fake_worker(sys.argv[2:]))
    unittest.main()
