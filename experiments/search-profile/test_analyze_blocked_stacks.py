"""Bounded saved-text fixtures; no live perf, Guest, or privileged interfaces."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location('blocked_stacks_test', Path(__file__).with_name('analyze_blocked_stacks.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
WINDOWS = [{'run_id': 'search-one', 'release_ns': 10_000_000_000, 'end_ns': 10_999_999_999}]


def header(time='10.000000001', pid=101, tid=101, prev_pid=None, mode='K', state='D', comm='grep'):
    return (' {}/{} {} {}: sched:sched_switch: prev_comm={} prev_pid={} prev_prio=120 '
            'prev_state={} ==> next_comm=swapper/1 next_pid=0 next_prio=120').format(
                pid, tid, mode, time, comm, tid if prev_pid is None else prev_pid, state)


def frame(name, dso='[kernel.kallsyms]'):
    return '\tffffffff12345678 {} ({})'.format(name, dso)


def payload(*records):
    return ('\n\n'.join('\n'.join(record) for record in records) + '\n').encode()


def parse(raw, windows=None):
    return M.parse_stream(io.BytesIO(raw), WINDOWS if windows is None else windows, len(raw), hashlib.sha256(raw).hexdigest())


class BlockedTextTests(unittest.TestCase):
    def test_one_record_not_one_frame_and_overlapping_labels_not_durations(self):
        result = parse(payload([header(), frame('__schedule'), frame('io_schedule'),
                                frame('folio_wait_bit_common'), frame('filemap_read')]))
        row = result['windows'][0]
        self.assertEqual(result['status'], 'OBSERVED_D_STATE_STACK_CANDIDATES_ONLY')
        self.assertEqual(row['records'], 1)
        self.assertEqual(row['valid_d_records'], 1)
        self.assertEqual(row['candidate_counts']['folio_wait_filemap_read'], 1)
        self.assertEqual(row['candidate_counts']['io_schedule_context'], 1)
        self.assertEqual(row['comm_counts'], {'grep': 1})
        self.assertNotIn('wait_ns', result)

    def test_exact_closed_integer_crop_excludes_preflight_and_between_windows(self):
        windows = WINDOWS + [{'run_id': 'search-two', 'release_ns': 12_000_000_000, 'end_ns': 12_999_999_999}]
        result = parse(payload([header('9.999999999', comm='dd'), frame('submit_bio_wait')],
                               [header('10.0'), frame('io_schedule')],
                               [header('10.999999999'), frame('io_schedule')],
                               [header('11.000000000', comm='python3'), frame('submit_bio_wait')],
                               [header('12.0'), frame('io_schedule')],
                               [header('13.000000000', comm='dd'), frame('submit_bio_wait')]), windows)
        self.assertEqual([row['records'] for row in result['windows']], [2, 1])
        self.assertEqual(result['counts']['outside_execution_windows'], 3)
        self.assertEqual(result['outside_window_comm_counts'], {'dd': 2, 'python3': 1})
        self.assertEqual(result['windows'][0]['candidate_counts']['direct_block_io_wait_context'], 0)

    def test_tgid_may_differ_from_tid_but_prev_pid_must_equal_tid(self):
        result = parse(payload([header(pid=100, tid=101), frame('io_schedule')],
                               [header(pid=100, tid=102, prev_pid=100), frame('io_schedule')]))
        self.assertEqual(result['windows'][0]['valid_d_records'], 1)
        self.assertEqual(result['windows'][0]['invalid_header_records'], 1)
        self.assertEqual(result['status'], 'INCOMPLETE')

    def test_non_d_or_user_mode_never_accepted_as_blocked_kernel_stack(self):
        for kwargs in ({'state': 'R'}, {'state': 'D|K'}, {'mode': 'U'}, {'pid': 0, 'tid': 0}):
            with self.subTest(kwargs=kwargs):
                result = parse(payload([header(**kwargs), frame('io_schedule')]))
                self.assertEqual(result['windows'][0]['valid_d_records'], 0)
                self.assertEqual(result['windows'][0]['candidate_counts']['io_schedule_context'], 0)

    def test_unknown_user_tail_does_not_erase_positive_kernel_frames(self):
        result = parse(payload([header(), frame('io_schedule'), frame('[unknown]', '[unknown]')]))
        row = result['windows'][0]
        self.assertEqual(row['unknown_user_tail_records'], 1)
        self.assertEqual(row['unknown_kernel_stack_records'], 0)
        self.assertEqual(row['candidate_counts']['io_schedule_context'], 1)

    def test_unknown_or_missing_kernel_stack_remains_unknown(self):
        result = parse(payload([header(), frame('[unknown]')], [header('10.2')]))
        row = result['windows'][0]
        self.assertEqual(row['records'], 2)
        self.assertEqual(row['unknown_kernel_stack_records'], 2)
        self.assertEqual(sum(row['candidate_counts'].values()), 0)

    def test_only_exact_kernel_dso_and_real_wait_pair_form_candidate(self):
        for frames in ([frame('folio_wait_bit_common'), frame('filemap_read', '/tmp/file')],
                       [frame('folio_wait_bit_common', '[kernel.kallsyms-impostor]'), frame('filemap_read')],
                       [frame('filemap_read')]):
            result = parse(payload([header()] + frames))
            self.assertEqual(result['windows'][0]['candidate_counts']['folio_wait_filemap_read'], 0)
        result = parse(payload([header(), frame('folio_wait_bit_common.constprop.0'), frame('filemap_read+0xab/0xff')]))
        self.assertEqual(result['windows'][0]['candidate_counts']['folio_wait_filemap_read'], 1)

    def test_malformed_stack_preserves_record_but_never_classifies(self):
        for bad in (' [unwind error]', ' callchain truncated', ' nonsense frame'):
            with self.subTest(bad=bad):
                result = parse(payload([header(), frame('io_schedule'), bad]))
                self.assertEqual(result['status'], 'INCOMPLETE')
                self.assertEqual(result['windows'][0]['malformed_stack_records'], 1)
                self.assertEqual(result['windows'][0]['candidate_counts']['io_schedule_context'], 0)

    def test_lost_orphan_invalid_utf8_and_unparsed_headers_preserved(self):
        for raw, code in ((b'PERF_RECORD_LOST 4 events\n', 'REPORTED_LOST_RECORD'),
                         (b'\xff\n', 'INVALID_UTF8_RECORD'),
                         (b'\tffffffff io_schedule ([kernel.kallsyms])\n', 'ORPHAN_OR_UNPARSED_LINE'),
                         (payload([header('10.0000000001')]), 'UNPARSED_SCHED_HEADER')):
            with self.subTest(code=code):
                result = parse(raw)
                self.assertEqual(result['status'], 'INCOMPLETE')
                self.assertIn(code, result['issues'])

    def test_single_pass_bytes_and_digest_must_match(self):
        raw = payload([header(), frame('io_schedule')])
        for count, digest in ((len(raw) + 1, hashlib.sha256(raw).hexdigest()), (len(raw), '0' * 64)):
            with self.subTest(count=count, digest=digest), self.assertRaisesRegex(ValueError, 'bytes/SHA256'):
                M.parse_stream(io.BytesIO(raw), WINDOWS, count, digest)

    def test_reject_empty_overlapping_unordered_boolean_or_duplicate_windows(self):
        for windows in ([], [dict(WINDOWS[0], release_ns=True)],
                        WINDOWS + [dict(WINDOWS[0], run_id='two')],
                        WINDOWS + [dict(WINDOWS[0], run_id='two', release_ns=10_999_999_999)],
                        WINDOWS + [dict(WINDOWS[0], release_ns=12_000_000_000, end_ns=13_000_000_000)]):
            with self.subTest(windows=windows), self.assertRaises(ValueError):
                parse(b'\n', windows)

    def test_bounded_frames_and_lines_are_not_silently_truncated_to_valid(self):
        result = parse(payload([header()] + [frame('io_schedule')] * (M.MAX_FRAMES + 1)))
        self.assertEqual(result['windows'][0]['malformed_stack_records'], 1)
        self.assertEqual(sum(result['windows'][0]['candidate_counts'].values()), 0)
        result = parse(b'x' * (M.MAX_LINE + 1) + b'\n')
        self.assertIn('LINE_SIZE_LIMIT_EXCEEDED', result['issues'])


class BlockedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cg = {'path': '/sys/fs/cgroup/diagnosis', 'inode': 100, 'device': 28}
        self.child = dict(self.cg, path=self.cg['path'] + '/search-one', inode=101)
        self.scope = {'event': 'sched:sched_switch', 'clock': 'CLOCK_MONOTONIC', 'trace_filter': 'prev_state & 2',
                      'call_graph': 'fp', 'period': 1, 'frequency_hz': None, 'cgroup_relative_path': 'diagnosis',
                      'enable_ack_received': True}
        self.command = ['/usr/bin/perf', 'record', '--no-buildid-cache', '-e', 'sched:sched_switch', '-c', '1',
                        '--filter', 'prev_state & 2', '--call-graph', 'fp', '-a', '-G', 'diagnosis', '--clockid',
                        'mono', '--delay=-1', '--control', 'fd:3,6', '-o', '/guest/perf.data']
        def boundary(value):
            return {'monotonic_ns': value, 'cgroup_events': {'frozen': '1', 'populated': '0'}}
        self.collector = {'schema_version': 1, 'mode': 'perf', 'status': 'COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE',
                          'issues': [], 'boot_id': 'boot', 'cgroup': self.cg, 'perf_scope': self.scope,
                          'command': self.command, 'start_boundary': boundary(1), 'ready_boundary': boundary(3),
                          'finish_boundary': boundary(11_000_000_000), 'perf_acknowledged_commands': ['enable', 'disable']}
        self.ready = dict(self.collector, status='READY')
        self.controls = [{'command': 'enable', 'ack': 'ack\n', 'monotonic_ns': 2},
                         {'command': 'disable', 'ack': 'ack\n', 'monotonic_ns': 12_000_000_000}]
        self.raw = payload([header('9.9', comm='dd'), frame('submit_bio_wait')],
                           [header(), frame('io_schedule'), frame('folio_wait_bit_common'), frame('filemap_read')])
        self.diagnosis = {'schema_version': 1, 'diagnosis_only': True, 'not_formal_timing_or_overhead': True,
                          'perf_event': 'sched-switch', 'runner_returncode': 0, 'collector': self.collector,
                          'cgroup': self.cg, 'boot_id': 'boot', 'grep_sha256': 'a' * 64,
                          'status': 'RAW_SCHED_TRACE_RECORDED_LOSS_NOT_ESTABLISHED', 'issues': [],
                          'sched_switch': {'status': 'RAW_TRACE_EXPORTED_NOT_CLASSIFIED', 'returncode': 0,
                              'event': 'sched:sched_switch', 'filter': 'prev_state & 2', 'call_graph': 'fp',
                              'path': 'sched-switch-callchains.txt', 'bytes': len(self.raw),
                              'sha256': hashlib.sha256(self.raw).hexdigest(),
                              'command': ['/usr/bin/perf', 'script', '--ns', '--show-lost-events', '-F',
                                          'pid,tid,misc,time,event,trace,ip,sym,dso', '-i', '/guest/perf.data']}}
        raw_output = b'./a\0'
        self.profile = dict(WINDOWS[0], status='COMPLETE', cleanup_errors=[], boot_id='boot', root_cgroup=self.child,
                            makespan_ns=999_999_999, config={'concurrency': 8}, tasks=[{'task_id': 'task-0000'}],
                            results=[{'task_id': 'task-0000', 'query_index': 0,
                                      'output_sha256': hashlib.sha256(raw_output).hexdigest(),
                                      'output_bytes': len(raw_output), 'exit_code': 0}])
        self.campaign = {'schema_version': 1, 'status': 'COMPLETE', 'intervention': 'none', 'jobs': 1,
                         'binaries': {'grep_sha256': 'a' * 64},
                         'trials': [{'path': 'trials/one', 'run_id': 'search-one'}]}
        self.persist()
        (self.root / 'sched-switch-callchains.txt').write_bytes(self.raw)
        (self.root / 'runner/trials/one/task-0000.stdout').write_bytes(raw_output)
        (self.root / 'sched-switch-script.stderr').write_text('')
        (self.root / 'collector/collector.stderr').write_text('captured records; this is not a loss guarantee\n')

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def persist(self):
        self.write('diagnosis.json', self.diagnosis)
        self.write('collector/diagnostics.json', self.collector)
        self.write('collector/diagnostics-ready.json', self.ready)
        path = self.root / 'collector/perf-control.jsonl'
        path.write_text(''.join(json.dumps(row) + '\n' for row in self.controls))
        self.write('runner/campaign.json', self.campaign)
        self.write('runner/trials/one/profile-run.json', self.profile)
        self.write('runner/trials/one/load/load-meta.json', {'boot_id': 'boot', 'label': 'search-one', 'cgroups': [self.child]})

    def test_real_receipt_shapes_crop_dd_and_preserve_loss_unknown(self):
        result = M.analyze_diagnosis(self.root)
        self.assertEqual(result['counts']['recognized_headers'], 2)
        self.assertEqual(result['outside_window_comm_counts'], {'dd': 1})
        self.assertEqual(result['windows'][0]['comm_counts'], {'grep': 1})
        self.assertEqual(result['windows'][0]['candidate_counts']['folio_wait_filemap_read'], 1)
        self.assertIn('NOT_ESTABLISHED', result['collector_health'])
        self.assertTrue(result['export_warnings']['collector/collector.stderr']['nonempty'])

    def test_boolean_returncode_changed_event_filter_or_clock_rejected(self):
        original = copy.deepcopy(self.diagnosis)
        for field, value in (('clock', 'CLOCK_REALTIME'), ('event', 'cpu-clock'),
                             ('trace_filter', 'prev_state & 1'), ('enable_ack_received', False)):
            self.collector['perf_scope'][field] = value
            self.persist()
            with self.subTest(field=field), self.assertRaises(ValueError):
                M.analyze_diagnosis(self.root)
            self.collector['perf_scope'] = copy.deepcopy(original['collector']['perf_scope'])
        self.diagnosis['runner_returncode'] = False
        self.persist()
        with self.assertRaises(ValueError):
            M.analyze_diagnosis(self.root)

    def test_ready_and_acks_must_be_exact_and_ordered(self):
        for mutate in (lambda: self.ready.update(boot_id='other'),
                       lambda: self.controls[0].update(ack='not ack'),
                       lambda: self.controls[1].update(monotonic_ns=4)):
            old_ready, old_controls = copy.deepcopy(self.ready), copy.deepcopy(self.controls)
            mutate()
            self.persist()
            with self.assertRaises(ValueError):
                M.analyze_diagnosis(self.root)
            self.ready, self.controls = old_ready, old_controls

    def test_changed_boot_cgroup_birth_raw_output_and_grep_digest_rejected(self):
        for field, value in (('boot_id', 'other'), ('root_cgroup', dict(self.child, inode=999)),
                             ('root_cgroup', dict(self.child, path='/sys/fs/cgroup/unrelated/search-one'))):
            previous = copy.deepcopy(self.profile)
            self.profile[field] = value
            self.persist()
            with self.subTest(field=field), self.assertRaises(ValueError):
                M.analyze_diagnosis(self.root)
            self.profile = previous
        self.persist()
        source = self.root / 'runner/trials/one/task-0000.stdout'
        source.write_bytes(b'./b\0')
        with self.assertRaisesRegex(ValueError, 'raw search output mismatch'):
            M.analyze_diagnosis(self.root)
        source.write_bytes(b'./a\0')
        self.campaign['binaries']['grep_sha256'] = 'b' * 64
        self.persist()
        with self.assertRaisesRegex(ValueError, 'pinned grep'):
            M.analyze_diagnosis(self.root)

    def test_digest_changed_bytes_and_failed_export_rejected(self):
        receipt = copy.deepcopy(self.diagnosis['sched_switch'])
        for field, value in (('sha256', 'f' * 64), ('bytes', len(self.raw) + 1), ('returncode', False),
                             ('path', '../sched-switch-callchains.txt')):
            self.diagnosis['sched_switch'] = dict(receipt, **{field: value})
            self.persist()
            with self.subTest(field=field), self.assertRaises(ValueError):
                M.analyze_diagnosis(self.root)


if __name__ == '__main__':
    unittest.main()
