import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from diagnose import (cache_flags, candidate_summary, classify_symbol, collector_class, compare_work, counter,
                      kernel_symbol_receipt, output_signature, parse_samples, perf_event_flags,
                      perf_script_command, resource_envelope, sched_switch_script_command, validate_cache_receipt)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class DiagnoseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_matchers_need_grep_dso_generic_libc_is_not_proven_matching(self):
        self.assertEqual(classify_symbol('U', 'Fexecute+0x19', '/usr/bin/grep', '/usr/bin/grep'), 'GREP_MATCHER_CANDIDATE')
        self.assertEqual(classify_symbol('U', 'Fexecute', '/lib/libother.so', '/usr/bin/grep'), 'USER_OTHER_NOT_ESTABLISHED_AS_MATCHING')
        self.assertEqual(classify_symbol('U', 'Fexecute', '/unrelated/grep', '/usr/bin/grep'), 'USER_OTHER_NOT_ESTABLISHED_AS_MATCHING')
        self.assertEqual(classify_symbol('U', 'Fexecute', 'grep', '/usr/bin/grep'), 'GREP_MATCHER_CANDIDATE')
        self.assertEqual(classify_symbol('U', '__memchr_avx2', '/lib/libc.so', '/usr/bin/grep'), 'USER_OTHER_NOT_ESTABLISHED_AS_MATCHING')
        self.assertEqual(classify_symbol('K', 'lookup_fast+0x1a', '[kernel.kallsyms]', '/usr/bin/grep'), 'KERNEL_DIRECTORY_METADATA_CANDIDATE')
        self.assertEqual(classify_symbol('K', 'filemap_read', '[kernel.kallsyms]', '/usr/bin/grep'), 'KERNEL_FILE_READ_PATH_CANDIDATE_NOT_STORAGE_WAIT')
        self.assertEqual(classify_symbol('K', 'shrink_lruvec', '[kernel.kallsyms]', '/usr/bin/grep'), 'KERNEL_RECLAIM_CANDIDATE')
        self.assertEqual(classify_symbol('U', '0x1234', '/usr/bin/grep', '/usr/bin/grep'), 'UNKNOWN_SYMBOL')

    def test_optional_cache_proofs_default_off_and_forward_exact_block_device(self):
        self.assertEqual(cache_flags(), [])
        self.assertEqual(cache_flags(True), ['--verify-cache-residency'])
        self.assertEqual(cache_flags(io_prime_device=Path('/dev/vdb')), ['--io-prime-device', '/dev/vdb'])
        self.assertEqual(cache_flags(True, Path('/dev/vdb')),
            ['--verify-cache-residency', '--io-prime-device', '/dev/vdb'])
        self.assertEqual(cache_flags(True, [Path('/dev/vda'), Path('/dev/sda')]),
            ['--verify-cache-residency', '--io-prime-device', '/dev/vda', '--io-prime-device', '/dev/sda'])

    def test_perf_monotonic_ns_crop_and_unknown_stays_in_denominator(self):
        lines = [' 101/101 U 10.000000001: 10 7abc Fexecute+0x1 (/usr/bin/grep)',
                 ' 101/101 K 10.000000002: 20 0 [unknown] ([kernel.kallsyms])',
                 ' 101/101 U 11.000000001: 40 0x7abc Fexecute (/usr/bin/grep)']
        result = parse_samples(lines, [(10_000_000_000, 10_000_000_010)], '/usr/bin/grep')
        self.assertEqual(result['status'], 'OBSERVED')
        self.assertEqual(result['sample_count'], 2)
        self.assertEqual(result['outside_search_windows'], 1)
        self.assertAlmostEqual(result['categories']['GREP_MATCHER_CANDIDATE']['fraction_of_observed_period'], 1 / 3)
        self.assertAlmostEqual(result['categories']['UNKNOWN_SYMBOL']['fraction_of_observed_period'], 2 / 3)

    def test_unparsed_or_lost_perf_records_do_not_silently_disappear(self):
        result = parse_samples(['PERF_RECORD_LOST 12 events'], [(1, 10)], '/usr/bin/grep')
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['issues'][0]['code'], 'UNPARSED_OR_LOST_PERF_RECORD')
        self.assertEqual(parse_samples([], [(1, 10)], '/usr/bin/grep')['status'], 'NO_SAMPLES_IN_SEARCH_WINDOWS')

    def test_missing_and_interior_reset_are_not_zero_or_valid_positive_work(self):
        for values in ([None, 4096], [100, 150, 120, 200], [2, 1], [True, 10]):
            issues = []
            self.assertIsNone(counter(values, 'counter', issues))
            self.assertTrue(issues)
        self.assertEqual(counter([0, 0], 'counter', []), 0)

    def resource_fixture(self):
        path = self.root / 'trial'
        parent = Path('/sys/fs/cgroup/search-diagnosis-fixture')
        profile = dict(run_id='search-fixture', boot_id='boot', release_ns=20, end_ns=80)
        profile['root_cgroup'] = {'path': str(parent / profile['run_id']), 'inode': 9, 'device': 28}
        write(path / 'load/load-meta.json', {'label': profile['run_id'], 'boot_id': 'boot',
            'cgroups': [{'path': str(parent / profile['run_id']), 'inode': 9, 'device': 28}]})
        write(path / 'load/load-sampler-stats.json', {'samples': 3, **{key: 0 for key in ('read_errors', 'missed_ticks',
            'truncated_process_sets', 'truncated_cgroup_traversals', 'cgroup_traversal_read_errors')}})
        rows = []
        for index, stamp in enumerate((10, 50, 90)):
            group = {'present': True, 'cpu_stat': {key: index * 100 for key in ('usage_usec', 'user_usec', 'system_usec', 'throttled_usec')},
                'memory_stat': {key: index for key in ('pgmajfault', 'workingset_refault_file', 'pgscan', 'pgsteal')},
                'memory_events': {key: 0 for key in ('high', 'max', 'oom', 'oom_kill')},
                'psi': {resource: {kind + '_total_us': index for kind in ('some', 'full')} for resource in ('cpu', 'memory', 'io')},
                'io_stat_by_device': {}}
            rows.append({'seq': index, 'monotonic_ns': stamp, 'collection_end_ns': stamp + 1, 'cgroups': [group]})
        sample = path / 'load/load-samples.jsonl'
        sample.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return path, profile, parent, rows, sample

    def test_resource_new_device_missing_previous_baseline_is_unknown(self):
        path, profile, parent, rows, sample = self.resource_fixture()
        complete = resource_envelope(path, profile, parent)
        self.assertEqual(complete['status'], 'OBSERVED_WITHIN_SCOPE')
        for row in rows[1:]:
            row['cgroups'][0]['io_stat_by_device'] = {'8:0': {'rbytes': 4096, 'wbytes': 0, 'rios': 1, 'wios': 0}}
        sample.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        result = resource_envelope(path, profile, parent)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertIsNone(result['counter_deltas']['io_by_device']['8:0']['rbytes'])

    def test_missing_sampler_identity_never_becomes_zero_resource_use(self):
        path, profile, parent, _, _ = self.resource_fixture()
        result = resource_envelope(path, {**profile, 'boot_id': 'different'}, parent)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertNotIn('counter_deltas', result)
        profile['root_cgroup']['inode'] += 1
        self.assertEqual(resource_envelope(path, profile, parent)['status'], 'INCOMPLETE')

    def test_resource_windows_preserved_for_independent_raw_stack_review(self):
        path, profile, parent, _, _ = self.resource_fixture()
        result = resource_envelope(path, profile, parent)
        self.assertEqual(result['run_id'], profile['run_id'])
        self.assertEqual(result['release_ns'], 20)
        self.assertEqual(result['end_ns'], 80)
        self.assertEqual(result['cgroup'], profile['root_cgroup'])

    def test_candidate_summary_never_infers_storage_wait_from_read_cpu(self):
        result = candidate_summary({'categories': {'KERNEL_FILE_READ_PATH_CANDIDATE_NOT_STORAGE_WAIT': {'samples': 100}}}, [])
        self.assertEqual(result['matching_cpu']['status'], 'UNKNOWN_NO_IDENTIFIED_SAMPLE_NOT_PROOF_OF_ABSENCE')
        self.assertIn('REVIEW_', result['storage_read_and_wait']['status'])
        self.assertIn('not measure disk blocking', result['storage_read_and_wait']['not_claimed'])

    def test_perf_command_is_cgroup_scoped_clock_bound_and_separate_output(self):
        class Base:
            def __init__(self):
                self.config = {'frequency_hz': 99}
                self.cgroup = Path('/sys/fs/cgroup/owned-diagnosis')
                self.output = self_root
                self.report = {}
                self.acks = []
            def _spawn(self, command, **kwargs):
                self.command, self.kwargs = command, kwargs
            def _perf_control(self, command):
                self.acks.append(command)
        self_root = self.root
        module = SimpleNamespace(Diagnostics=Base, CGROUP_ROOT=Path('/sys/fs/cgroup'),
            _pinned=lambda *unused: '/usr/bin/perf')
        collector = collector_class(module)()
        try:
            collector._start_perf()
            self.assertEqual(collector.command[collector.command.index('-G') + 1], 'owned-diagnosis')
            self.assertLess(collector.command.index('-e'), collector.command.index('-G'))
            self.assertEqual(collector.command[collector.command.index('--clockid') + 1], 'mono')
            self.assertIn('--no-buildid-cache', collector.command)
            self.assertEqual(collector.command[collector.command.index('-o') + 1], str(self.root / 'perf.data'))
            self.assertEqual(collector.kwargs['cwd'], str(self.root))
            self.assertEqual(collector.acks, ['enable'])
        finally:
            os.close(collector.control_write)
            os.close(collector.ack_read)

        collector = collector_class(module)()
        collector.config['perf_event'] = 'sched-switch'
        try:
            collector._start_perf()
            self.assertLess(collector.command.index('-e'), collector.command.index('-G'))
            self.assertLess(collector.command.index('--filter'), collector.command.index('-G'))
            self.assertNotIn('-F', collector.command)
            self.assertEqual(collector.report['perf_scope']['event'], 'sched:sched_switch')
            self.assertIsNone(collector.report['perf_scope']['frequency_hz'])
        finally:
            os.close(collector.control_write)
            os.close(collector.ack_read)

        collector = collector_class(module)()
        collector.config['call_graph'] = 'dwarf'
        try:
            collector._start_perf()
            self.assertEqual(collector.command[collector.command.index('--call-graph') + 1], 'dwarf,16384')
            self.assertEqual(collector.report['perf_scope']['dwarf_stack_bytes'], 16384)
            self.assertEqual(collector.report['perf_scope']['call_graph'], 'dwarf')
        finally:
            os.close(collector.control_write)
            os.close(collector.ack_read)

    def test_callchains_are_a_separate_uncropped_export_not_leaf_sample_input(self):
        leaf = perf_script_command('/usr/bin/perf', '/owned/collector/perf.data')
        chains = perf_script_command('/usr/bin/perf', '/owned/collector/perf.data', callchains=True)
        self.assertIn('-G', leaf)
        self.assertNotIn('-G', chains)
        self.assertEqual([value for value in leaf if value != '-G'], chains)
        self.assertIn('--ns', chains)
        self.assertEqual(chains[-2:], ['-i', '/owned/collector/perf.data'])

    def test_sched_switch_d_state_filter_is_separate_from_cpu_sampling(self):
        flags = perf_event_flags('sched-switch', 99, 'fp')
        self.assertEqual(flags, ['-e', 'sched:sched_switch', '-c', '1', '--filter', 'prev_state & 2', '--call-graph', 'fp'])
        self.assertNotIn('-F', flags)
        with self.assertRaisesRegex(ValueError, 'per-switch DWARF'):
            perf_event_flags('sched-switch', 99, 'dwarf')
        with self.assertRaisesRegex(ValueError, 'unsupported diagnostic perf event'):
            perf_event_flags('unknown', 99, 'fp')
        script = sched_switch_script_command('/usr/bin/perf', '/owned/perf.data')
        self.assertIn('event,trace,', script[script.index('-F') + 1])
        self.assertNotIn('period', script[script.index('-F') + 1].split(','))
        self.assertNotIn('-G', script)
        self.assertEqual(perf_event_flags('cpu-clock', 99, 'dwarf'),
            ['-e', 'cpu-clock', '-F', '99', '--call-graph', 'dwarf,16384'])

    def test_kernel_symbol_probe_does_not_claim_unwinding_or_emit_addresses(self):
        path = self.root / 'kallsyms'
        sysctl = self.root / 'sysctl'
        sysctl.mkdir()
        (sysctl / 'kptr_restrict').write_text('1\n')
        path.write_text('0000000000000000 T masked\nffffffff81000000 T example\n')
        result = kernel_symbol_receipt(path, sysctl)
        self.assertEqual(result['status'], 'NONZERO_ADDRESSES_OBSERVED')
        self.assertEqual(result['nonzero_address_lines'], 1)
        self.assertEqual(result['sysctls'], {'kptr_restrict': '1', 'perf_event_paranoid': None})
        self.assertNotIn('ffffffff81000000', json.dumps(result))
        path.write_text('0000000000000000 T masked\n')
        self.assertEqual(kernel_symbol_receipt(path, sysctl)['status'], 'NO_NONZERO_ADDRESSES_OBSERVED')
        self.assertEqual(kernel_symbol_receipt(self.root / 'missing', sysctl)['status'], 'UNKNOWN')

    def test_cache_receipt_rejects_unknown_wrong_scope_or_cold_condition_without_rereading_corpus(self):
        directory = self.root / 'trial'
        directory.mkdir()
        details = directory / 'cache-residency-files.json.gz'
        details.write_bytes(b'opaque retained compressed per-file evidence')
        corpus = Path('/immutable/not-mounted-on-this-host')
        row = {'status': 'OBSERVED_NON_ATOMIC', 'errors': [], 'root': str(corpus), 'inventory_sha256': 'corpus-digest',
            'declared_file_count': 2, 'observed_file_count': 2, 'unknown_file_count': 0, 'total_pages': 3,
            'observed_total_pages': 3, 'start_monotonic_ns': 10, 'end_monotonic_ns': 20, 'resident_fraction': 1.0}
        proof = {'status': 'OBSERVED_NON_ATOMIC', 'roots': [row],
            'file_details': {'path': details.name, 'sha256': hashlib.sha256(details.read_bytes()).hexdigest()}}
        path = directory / 'cache-residency.json'
        profile = {'release_ns': 30, 'config': {'corpus_sha256': 'corpus-digest'}}
        def update():
            path.write_text(json.dumps(proof))
            profile['cache_residency'] = {'path': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        update()
        self.assertEqual(validate_cache_receipt(directory, profile, 'warm', corpus)['status'],
            'OBSERVED_WITHIN_DECLARED_NON_ATOMIC_CONDITION')
        self.assertEqual(validate_cache_receipt(directory, profile, 'guest-cold', corpus)['status'], 'INCOMPLETE')
        row['resident_fraction'] = 0.0
        update()
        self.assertEqual(validate_cache_receipt(directory, profile, 'guest-cold', corpus)['status'],
            'OBSERVED_WITHIN_DECLARED_NON_ATOMIC_CONDITION')
        row['unknown_file_count'] = 1
        update()
        self.assertEqual(validate_cache_receipt(directory, profile, 'guest-cold', corpus)['status'], 'INCOMPLETE')
        row['unknown_file_count'] = 0
        update()
        self.assertEqual(validate_cache_receipt(directory, profile, 'guest-cold', Path('/different'))['status'], 'INCOMPLETE')
        path.write_text(path.read_text() + ' ')
        self.assertEqual(validate_cache_receipt(directory, profile, 'guest-cold', corpus)['issues'], ['CACHE_PROOF_SHA256_MISMATCH'])

    def test_fixed_output_reference_is_rehashed_and_missing_task_rejected(self):
        root = self.root / 'campaign'
        manifest = {'schema_version': 1, 'status': 'COMPLETE', 'intervention': 'none', 'jobs': 1,
            'trials': [{'path': 'trials/one', 'run_id': 'run-one'}]}
        raw = b'./two\0./one\0'
        digest = hashlib.sha256(b'./one\0./two\0').hexdigest()
        profile = {'status': 'COMPLETE', 'cleanup_errors': [], 'run_id': 'run-one', 'release_ns': 10, 'end_ns': 20,
            'makespan_ns': 10, 'tasks': [{'task_id': 'task-0000'}], 'results': [{'task_id': 'task-0000',
                'query_index': 0, 'exit_code': 0, 'output_bytes': len(raw), 'output_sha256': digest}]}
        write(root / 'campaign.json', manifest)
        write(root / 'trials/one/profile-run.json', profile)
        (root / 'trials/one/task-0000.stdout').write_bytes(raw)
        _, result, _ = output_signature(root)
        self.assertEqual(result[0], (digest, len(raw), 0))
        (root / 'trials/one/task-0000.stdout').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'raw search output mismatch'):
            output_signature(root)
        profile['results'] = []
        write(root / 'trials/one/profile-run.json', profile)
        with self.assertRaisesRegex(ValueError, 'execution/cleanup incomplete'):
            output_signature(root)

    def test_changed_query_or_binary_cannot_reuse_reference_label(self):
        left = {'queries': ['one'], 'binaries': {'grep_sha256': 'old'}}
        right = copy.deepcopy(left)
        compare_work(left, right)
        right['queries'] = ['other']
        with self.assertRaises(ValueError):
            compare_work(left, right)
        right = copy.deepcopy(left)
        right['binaries']['grep_sha256'] = 'changed'
        with self.assertRaises(ValueError):
            compare_work(left, right)


if __name__ == '__main__':
    unittest.main()
