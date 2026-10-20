"""Saved-text callchain tests only: no live perf, Guest, or privileged APIs."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location('test_callchain_analysis', Path(__file__).with_name('analyze_callchains.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
GREP = '/usr/bin/grep'
WINDOWS = [{'run_id': 'search-one', 'release_ns': 10_000_000_000, 'end_ns': 10_999_999_999}]


def header(time='10.000000001', mode='U', period=10):
    return ' 101/101 {} {}: {}'.format(mode, time, period)


def frame(symbol, dso='/usr/bin/grep', ip='7abc'):
    return '\t{} {} ({})'.format(ip, symbol, dso)


def inline(time='10.000000001', mode='U', period=10, symbol='__memchr_avx2', dso='/lib/libc.so.6'):
    return header(time, mode, period) + ' 7abc {} ({})'.format(symbol, dso)


def parse(lines, **kwargs):
    return M.analyze_text(lines, WINDOWS, GREP, **kwargs)


class CallchainTextTests(unittest.TestCase):
    def test_real_perf_multiline_header_and_matching_ancestor_not_libc_leaf(self):
        result = parse([header(), frame('__memchr_avx2', '/lib/libc.so.6'),
                        frame('kwsexec+0x12', 'grep'), frame('Fexecute', 'grep'), ''])
        self.assertEqual(result['sample_count'], 1)
        self.assertEqual(result['categories'][M.MATCHING]['samples'], 1)
        self.assertEqual(result['categories'][M.MATCHING]['fraction_of_observed_period'], 1)
        self.assertEqual(result['top_semantic_anchors'][0]['symbol'], 'kwsexec+0x12')
        self.assertIn('SHORT_DSO', result['examples'][M.MATCHING][0]['basis'])

    def test_inline_header_and_frames_are_one_sample_not_four(self):
        result = parse([inline(), frame('kwsexec', GREP), frame('Fexecute', GREP), frame('main', GREP)])
        self.assertEqual(result['sample_count'], 1)
        self.assertEqual(sum(row['samples'] for row in result['categories'].values()), 1)
        self.assertEqual(result['period_weight'], 10)
        self.assertEqual(result['examples'][M.MATCHING][0]['frame_count'], 4)

    def test_unknown_does_not_disappear_from_sample_or_period_denominator(self):
        result = parse([header(period=10), frame('Fexecute'), '', header(time='10.2', period=30),
                        frame('[unknown]', '[unknown]'), ''])
        self.assertEqual(result['sample_count'], 2)
        self.assertEqual(result['categories'][M.MATCHING]['fraction_of_observed_samples'], .5)
        self.assertEqual(result['categories'][M.MATCHING]['fraction_of_observed_period'], .25)
        self.assertEqual(result['categories'][M.UNKNOWN]['fraction_of_observed_period'], .75)

    def test_generic_memchr_and_impostor_grep_path_not_established_as_matching(self):
        for lines in ([inline()], [header(), frame('Fexecute', '/unrelated/grep')],
                      [header(), '\t7abc Fexecute']):
            with self.subTest(lines=lines):
                result = parse(lines)
                self.assertEqual(result['categories'][M.MATCHING]['samples'], 0)
        self.assertEqual(parse([inline()])['categories'][M.OTHER]['samples'], 1)

    def test_unresolved_leaf_can_use_resolved_ancestor_but_missing_dso_cannot(self):
        result = parse([header(), frame('[unknown]', '[unknown]'), frame('bmexec', GREP)])
        self.assertEqual(result['categories'][M.MATCHING]['samples'], 1)
        result = parse([header(), frame('[unknown]', '[unknown]'), '\t7abc bmexec'])
        self.assertEqual(result['categories'][M.UNKNOWN]['samples'], 1)

    def test_malformed_or_explicitly_failed_stack_is_unknown_even_with_matcher(self):
        for bad in (' [unwind error]', ' callchain truncated', ' cannot parse this frame',
                    ' <not enough memory for the callchain cursor>'):
            with self.subTest(bad=bad):
                result = parse([header(), frame('Fexecute'), bad])
                self.assertEqual(result['categories'][M.UNKNOWN]['samples'], 1)
                self.assertEqual(result['categories'][M.MATCHING]['samples'], 0)
                self.assertEqual(result['status'], 'INCOMPLETE')

    def test_exact_nanosecond_window_crop_and_fractional_padding(self):
        result = parse([header(time='9.999999999'), frame('Fexecute'), '',
                        header(time='10.0'), frame('Fexecute'), '',
                        header(time='10.999999999'), frame('kwsexec'), '',
                        header(time='11.000000000'), frame('Fexecute')])
        self.assertEqual(result['sample_count'], 2)
        self.assertEqual(result['outside_search_windows'], 2)
        self.assertEqual(result['per_window']['search-one']['sample_count'], 2)

    def test_excess_precision_or_floating_timestamp_never_gets_rounded_into_window(self):
        for time in ('10.0000000001', '1e1', '10', '-10.123'):
            result = parse([header(time=time), frame('Fexecute')])
            self.assertEqual(result['sample_count'], 0)
            self.assertEqual(result['status'], 'INCOMPLETE')

    def test_directories_and_metadata_separate_from_matching(self):
        for mode, symbol, dso, expected in (
                ('U', 'fts_read', GREP, M.DIRECTORY),
                ('U', 'readdir64', '/lib/libc.so.6', M.DIRECTORY),
                ('K', 'iterate_dir', '[kernel.kallsyms]', M.DIRECTORY),
                ('K', 'btrfs_real_readdir', 'btrfs', M.DIRECTORY),
                ('U', '__open64_nocancel', '/lib/libc.so.6', M.METADATA),
                ('K', 'do_filp_open', '[kernel.kallsyms]', M.METADATA),
                ('K', 'vfs_statx', '[kernel.kallsyms]', M.METADATA),
                ('K', 'filp_close', '[kernel.kallsyms]', M.METADATA)):
            with self.subTest(symbol=symbol):
                result = parse([header(mode=mode), frame(symbol, dso), frame('Fexecute', GREP)])
                self.assertEqual(result['categories'][expected]['samples'], 1)
                self.assertEqual(result['categories'][M.MATCHING]['samples'], 0)

    def test_pinned_grep_real_gnulib_traversal_names_and_transformed_matcher(self):
        # Verified against guest-grep / grep.debuginfo's identical build-id:
        # b1c639c3724b99f5e502ce5bb35bbf99872e8a67. No source/BPF/VM execution.
        for symbol in ('rpl_fts_open', 'rpl_fts_read', 'rpl_fts_read.cold',
                       'rpl_fts_children', 'rpl_fts_close', 'rpl_fts_set', 'fts_safe_changedir',
                       'fts_sort', 'fts_compare_ino'):
            with self.subTest(symbol=symbol):
                result = parse([header(), frame('__memchr_avx2', '/lib/libc.so.6'), frame(symbol, 'grep')])
                self.assertEqual(result['categories'][M.DIRECTORY]['samples'], 1)
        result = parse([header(), frame('__memchr_avx2', '/lib/libc.so.6'), frame('bmexec_trans', 'grep')])
        self.assertEqual(result['categories'][M.MATCHING]['samples'], 1)
        result = parse([header(), frame('rpl_fts_invented_other', 'grep')])
        self.assertEqual(result['categories'][M.DIRECTORY]['samples'], 0)

    def test_specific_kernel_context_priority_and_no_kernel_sample_as_user_matching(self):
        for symbols, expected in ((['copy_user_enhanced_fast_string', 'filemap_read'], M.READ_COPY),
                (['copy_user_enhanced_fast_string', 'iterate_dir'], M.DIRECTORY),
                (['filemap_read', 'shrink_lruvec'], M.RECLAIM)):
            result = parse([header(mode='K')] + [frame(symbol, '[kernel.kallsyms]') for symbol in symbols]
                           + [frame('Fexecute', GREP)])
            self.assertEqual(result['categories'][expected]['samples'], 1)
            self.assertEqual(result['categories'][M.MATCHING]['samples'], 0)
        result = parse([header(mode='K'), frame('Fexecute', GREP)])
        self.assertEqual(result['categories'][M.MATCHING]['samples'], 0)

    def test_lock_annotation_overlaps_but_never_adds_primary_sample(self):
        result = parse([header(mode='K'), frame('queued_spin_lock_slowpath', '[kernel.kallsyms]'),
                        frame('iterate_dir', '[kernel.kallsyms]')])
        self.assertEqual(result['categories'][M.DIRECTORY]['samples'], 1)
        self.assertEqual(result['orthogonal_lock_annotation']['sample_count'], 1)
        self.assertTrue(result['orthogonal_lock_annotation']['not_additive'])
        self.assertEqual(sum(row['period_weight'] for row in result['categories'].values()), 10)

    def test_lost_or_orphan_frames_mark_incomplete_without_counting_frames_as_samples(self):
        result = parse([frame('Fexecute'), 'PERF_RECORD_LOST 4 events', header(), frame('Fexecute')])
        self.assertEqual(result['sample_count'], 1)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual({row['code'] for row in result['issues']}, {'LOST_PERF_RECORD', 'ORPHAN_FRAME_OR_UNPARSED_RECORD'})

    def test_missing_stack_and_unsupported_mode_preserve_unknown(self):
        result = parse([header(mode='G'), frame('Fexecute'), '', header(time='10.2')])
        self.assertEqual(result['categories'][M.UNKNOWN]['samples'], 2)

    def test_invalid_period_retains_sample_unknown_and_disables_all_weight_fractions(self):
        result = parse([header(period=0), frame('Fexecute'), '', header(time='10.2'), frame('Fexecute')])
        self.assertEqual(result['sample_count'], 2)
        self.assertIsNone(result['period_weight'])
        self.assertIsNone(result['categories'][M.MATCHING]['fraction_of_observed_period'])
        self.assertEqual(result['categories'][M.UNKNOWN]['fraction_of_observed_samples'], .5)

    def test_leaf_multiset_binding_preserves_duplicate_samples_and_does_not_use_symbols(self):
        lines = [header(), frame('Fexecute'), '', header(), frame('Fexecute')]
        leaf = [inline(symbol='Fexecute', dso='grep'), inline(symbol='[unknown]', dso='[unknown]')]
        result = parse(lines, leaf_lines=leaf)
        self.assertEqual(result['sample_count'], 2)
        self.assertEqual(result['sample_stream_binding'], 'MATCHED_PID_TID_MODE_TIMESTAMP_PERIOD_MULTISET')
        result = parse(lines, leaf_lines=leaf[:1])
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['sample_stream_binding'], 'INCOMPLETE_SAMPLE_STREAM_MISMATCH')

    def test_overlapping_or_unbound_windows_rejected(self):
        for windows in ([], [dict(WINDOWS[0], release_ns=True)],
                        WINDOWS + [dict(WINDOWS[0], run_id='other')],
                        WINDOWS + [dict(WINDOWS[0], run_id='other', release_ns=10_999_999_999, end_ns=12_000_000_000)]):
            with self.subTest(windows=windows), self.assertRaises(ValueError):
                M.analyze_text([], windows, GREP)


class CallchainEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cg = {'path': '/sys/fs/cgroup/diagnosis', 'inode': 100, 'device': 28}
        self.child = dict(self.cg, path=self.cg['path'] + '/search-one', inode=101)
        self.collector = {'mode': 'perf', 'status': 'INCOMPLETE', 'issues': ['preserved raw gap'],
            'cgroup': self.cg, 'boot_id': 'boot',
            'perf_scope': {'clock': 'CLOCK_MONOTONIC', 'event': 'software cpu-clock', 'cgroup_relative_path': 'diagnosis'}}
        self.chains = '\n'.join([header(), frame('__memchr_avx2', '/lib/libc.so.6'), frame('Fexecute', GREP), ''])
        self.diagnosis = {'schema_version': 1, 'diagnosis_only': True, 'not_formal_timing_or_overhead': True,
            'runner_returncode': 0, 'status': 'INCOMPLETE', 'issues': [], 'boot_id': 'boot', 'cgroup': self.cg,
            'collector': self.collector, 'command': ['python3', 'run.py', '--grep', GREP], 'grep_sha256': 'a' * 64,
            'perf_callchains': {'status': 'EXPORTED_RAW_NOT_CLASSIFIED', 'returncode': 0,
                'path': 'perf-callchains.txt', 'sha256': hashlib.sha256(self.chains.encode()).hexdigest(),
                'bytes': len(self.chains.encode()), 'call_graph': 'dwarf'}}
        raw = b'./a\0'
        self.profile = {'status': 'COMPLETE', 'cleanup_errors': [], 'run_id': 'search-one', 'boot_id': 'boot',
            **{key: WINDOWS[0][key] for key in ('release_ns', 'end_ns')}, 'makespan_ns': 999999999,
            'root_cgroup': self.child, 'tasks': [{'task_id': 'task-0000'}],
            'results': [{'task_id': 'task-0000', 'query_index': 0, 'output_sha256': hashlib.sha256(raw).hexdigest(),
                         'output_bytes': len(raw), 'exit_code': 0}]}
        self.campaign = {'schema_version': 1, 'status': 'COMPLETE', 'intervention': 'none', 'jobs': 1,
            'binaries': {'grep_sha256': 'a' * 64}, 'trials': [{'path': 'trials/one', 'run_id': 'search-one'}]}
        self.write('diagnosis.json', self.diagnosis)
        self.write('collector/diagnostics.json', self.collector)
        self.write('runner/campaign.json', self.campaign)
        self.write('runner/trials/one/profile-run.json', self.profile)
        self.write('runner/trials/one/load/load-meta.json', {'boot_id': 'boot', 'label': 'search-one', 'cgroups': [self.child]})
        (self.root / 'runner/trials/one/task-0000.stdout').write_bytes(raw)
        (self.root / 'perf-callchains.txt').write_text(self.chains)
        (self.root / 'perf-samples.txt').write_text(inline() + '\n')

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def test_saved_diagnosis_rechecks_sources_windows_and_preserves_collection_gaps(self):
        result = M.analyze_diagnosis(self.root)
        self.assertEqual(result['categories'][M.MATCHING]['samples'], 1)
        self.assertEqual(result['sample_stream_binding'], 'MATCHED_PID_TID_MODE_TIMESTAMP_PERIOD_MULTISET')
        self.assertEqual(result['raw_diagnosis_status'], 'INCOMPLETE')
        self.assertEqual(result['raw_collector_issues'], ['preserved raw gap'])
        self.assertIn('NOT_ESTABLISHED', result['collection_health'])
        self.assertEqual(result['sources']['perf-callchains.txt']['sha256'], self.diagnosis['perf_callchains']['sha256'])
        self.assertIn('runner/trials/one/profile-run.json', result['sources'])
        self.assertIn('collector/diagnostics.json', result['sources'])

    def test_tampered_callchain_digest_or_byte_count_rejected(self):
        for field, bad in (('sha256', 'f' * 64), ('bytes', 0)):
            original = copy.deepcopy(self.diagnosis)
            self.diagnosis['perf_callchains'][field] = bad
            self.write('diagnosis.json', self.diagnosis)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'differs from export receipt'):
                M.analyze_diagnosis(self.root)
            self.diagnosis = original

    def test_changed_boot_or_scope_and_collector_copy_rejected(self):
        for field, value in (('boot_id', 'other'), ('cgroup', dict(self.cg, inode=999))):
            changed = dict(self.diagnosis, **{field: value})
            self.write('diagnosis.json', changed)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'identity is unbound'):
                M.analyze_diagnosis(self.root)
        self.diagnosis['collector'] = dict(self.collector, status='COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE')
        self.write('diagnosis.json', self.diagnosis)
        with self.assertRaisesRegex(ValueError, 'original diagnostics artifact'):
            M.analyze_diagnosis(self.root)

    def test_sched_switch_offcpu_or_other_clock_cannot_be_counted_as_cpu_samples(self):
        original = copy.deepcopy(self.collector['perf_scope'])
        for scope in (dict(original, event='sched:sched_switch'), dict(original, clock='CLOCK_REALTIME')):
            self.collector['perf_scope'] = scope
            self.write('collector/diagnostics.json', self.collector)
            self.write('diagnosis.json', self.diagnosis)
            with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, 'clock, boot or registered cgroup identity is unbound'):
                M.analyze_diagnosis(self.root)

    def test_wrong_profile_cgroup_birth_or_boot_rejected(self):
        for field, value in (('boot_id', 'other'), ('root_cgroup', dict(self.child, inode=999)),
                             ('root_cgroup', dict(self.child, path='/sys/fs/cgroup/unrelated/search-one'))):
            changed = dict(self.profile, **{field: value})
            self.write('runner/trials/one/profile-run.json', changed)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                M.analyze_diagnosis(self.root)

    def test_binary_digest_or_raw_query_output_change_rejected(self):
        self.campaign['binaries']['grep_sha256'] = 'b' * 64
        self.write('runner/campaign.json', self.campaign)
        with self.assertRaisesRegex(ValueError, 'binary digest differs'):
            M.analyze_diagnosis(self.root)
        self.campaign['binaries']['grep_sha256'] = 'a' * 64
        self.write('runner/campaign.json', self.campaign)
        (self.root / 'runner/trials/one/task-0000.stdout').write_bytes(b'./b\0')
        with self.assertRaisesRegex(ValueError, 'raw search output mismatch'):
            M.analyze_diagnosis(self.root)

    def test_failed_export_boolean_success_or_escaping_path_rejected(self):
        for field, value in (('path', '../perf-callchains.txt'), ('returncode', False), ('status', 'INCOMPLETE')):
            self.diagnosis['perf_callchains'] = {**self.diagnosis['perf_callchains'], field: value}
            self.write('diagnosis.json', self.diagnosis)
            with self.subTest(field=field), self.assertRaises(ValueError):
                M.analyze_diagnosis(self.root)


if __name__ == '__main__':
    unittest.main()
