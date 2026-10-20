#!/usr/bin/env python3
"""Pure resource-unit checks and temporary-file export; no VM or sampler."""
import copy
import csv
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import load_view as M


def fixture(enabled=True):
    group = {'path': '/sys/fs/cgroup/test-only', 'inode': 99, 'device': 28}
    meta = {'schema_version': 1, 'boot_id': 'boot', 'online_cpus': 2, 'clk_tck': 100,
        'interval_ms': 100, 'block_devices': ['sda'], 'cgroups': [group],
        'thread_sampling': {'schedstats_runtime_enabled_at_start': enabled}}
    job = {'job_id': 'job-0', 'release_issued_ns': 1100000000, 'agent_return_ns': 1180000000,
        'quiescent_ns': 1200000000, 'ready_metadata': {'cgroup_root': group['path'], 'cgroup_id': 99, 'agent_id': 'oracle-reference'}}
    campaign = {'schema_version': 1, 'boot_id': 'boot', 'benchmark': 'SYNTHETIC_UNIT_ONLY',
        'concurrency': 2, 'total_jobs': 1, 'batch_start_ns': 1100000000, 'batch_end_ns': 1200000000, 'jobs': [job]}
    samples = []
    for index in range(3):
        samples.append({'seq': index, 'monotonic_ns': 1000000000 + index * 100000000,
            'collection_end_ns': 1001000000 + index * 100000000,
            'stat': {'cpu_total': [100 + index * 2, 50, 10 + index, 1000, index, 0, index, 0],
                'cpu_ids': [0, 1], 'procs_running': 2, 'procs_blocked': 1,
                'ctxt': 100 + 5 * index, 'processes': 50 + index},
            'meminfo_kb': {'MemTotal': 2097152, 'MemAvailable': 1048576, 'Cached': 524288, 'Buffers': 0, 'AnonPages': 262144},
            'psi': {name: {'some_total_us': 100 + index * 10000, 'full_total_us': index * 1000}
                    for name in ('cpu', 'memory', 'io')},
            'schedstat': [[1000000 + index * 1000000, 5000000 + index * 5000000, index + 1] for _ in range(2)],
            'diskstats': {'sda': [10 + index, 0, 100 + index * 2048, 0, 20 + index, 0, 200 + index * 1024, 0, 0, 0, 0]},
            'net_dev': {'eth0': [index * 1048576, 0, 0, 0, index * 2097152, 0, 0, 0],
                        'veth0': [index * 1048576, 0, 0, 0, index * 2097152, 0, 0, 0]},
            'vmstat': {'pgfault': 100 + index * 5, 'pgmajfault': index,
                       'workingset_refault_file': index, 'workingset_refault_anon': 0},
            'cgroups': [{'present': True, 'cpu_stat': {'usage_usec': index * 100000,
                'user_usec': index * 60000, 'system_usec': index * 40000, 'throttled_usec': 0},
                'memory_current': 1073741824, 'memory_peak': 2147483648,
                'memory_stat': {'file': 536870912, 'anon': 268435456, 'pgfault': index * 3,
                    'pgmajfault': index, 'workingset_refault_file': 0, 'workingset_refault_anon': 0,
                    'pgscan': 0, 'pgsteal': 0},
                'psi': {name: {'some_total_us': index * 10000, 'full_total_us': 0} for name in ('cpu', 'memory', 'io')},
                'io_stat_by_device': {'8:0': {'rbytes': index * 65536, 'wbytes': index * 32768}},
                'pids_current': 2}]})
    stats = {'schema_version': 1, 'samples': 3, 'read_errors': 0, 'missed_ticks': 0}
    return meta, samples, campaign, stats


def point(view, metric, scope='GUEST', entity='guest', index=1):
    return next(series for series in view['series'] if series['scope'] == scope
                and series['entity'] == entity and series['metric'] == metric)['points'][index]


class DerivationTests(unittest.TestCase):
    def test_adjacent_counter_formulas_and_units_are_exact_not_nominal_intervals(self):
        args = fixture()
        before = copy.deepcopy(args)
        view = M.build_series(*args)
        self.assertEqual(args, before)
        for metric, scope, entity, expected in (
            ('cpu.user', 'GUEST', 'guest', 10), ('cpu.system', 'GUEST', 'guest', 5),
            ('psi.io.some', 'GUEST', 'guest', 10), ('disk.read', 'GUEST', 'sda', 10),
            ('network.rx', 'GUEST', 'eth0', 10), ('network.tx', 'GUEST', 'eth0', 20),
            ('tasks.ctxt', 'GUEST', 'guest', 50), ('tasks.processes', 'GUEST', 'guest', 10),
            ('faults.pgfault', 'GUEST', 'guest', 50), ('faults.pgmajfault', 'GUEST', 'guest', 10),
            ('scheduler.validated_run_delay_tasks', 'GUEST', 'guest', .1),
            ('cpu.usage', 'CGROUP', 'job-0', 1), ('io.8:0.rbytes', 'CGROUP', 'job-0', .625)):
            self.assertAlmostEqual(point(view, metric, scope, entity)['value'], expected)
        self.assertEqual(point(view, 'memory.Cached')['value'], .5)
        self.assertEqual(point(view, 'memory.used_estimate')['value'], 1)
        self.assertEqual(point(view, 'memory.Buffers')['value'], 0)
        self.assertEqual(point(view, 'cpu.user', index=0)['status'], 'NO_PREVIOUS_SAMPLE')
        self.assertIsNone(point(view, 'cpu.user', index=0)['value'])
        self.assertEqual(view['run']['batch_wall_ns'], 100000000)

    def test_counter_resets_are_unknown_even_when_aggregate_sum_increases(self):
        args = fixture()
        args[1][1]['stat']['cpu_total'][0:2] = [90, 100]
        args[1][1]['cgroups'][0]['cpu_stat']['usage_usec'] = -1
        view = M.build_series(*args)
        self.assertEqual(point(view, 'cpu.user')['status'], 'COUNTER_RESET')
        self.assertIsNone(point(view, 'cpu.user')['value'])
        self.assertEqual(point(view, 'cpu.user')['previous_raw'], [100, 50])
        self.assertEqual(point(view, 'cpu.user')['current_raw'], [90, 100])
        self.assertEqual(point(view, 'cpu.usage', 'CGROUP', 'job-0')['status'], 'MISSING_OR_INVALID_COUNTER')

    def test_rates_use_actual_120ms_not_nominal_100ms(self):
        args = fixture()
        for index, row in enumerate(args[1]):
            row['monotonic_ns'] = 1000000000 + index * 120000000
            row['collection_end_ns'] = row['monotonic_ns'] + 1000000
        view = M.build_series(*args)
        self.assertAlmostEqual(point(view, 'cpu.user')['value'], 100 * 2 / (100 * 2 * .12))
        self.assertAlmostEqual(point(view, 'cpu.usage', 'CGROUP', 'job-0')['value'], .1 / .12)
        self.assertEqual(point(view, 'cpu.user')['interval_ns'], 120000000)

    def test_missing_previous_device_is_not_assumed_zero(self):
        args = fixture()
        args[1][0]['cgroups'][0]['io_stat_by_device'] = {}
        view = M.build_series(*args)
        self.assertIsNone(point(view, 'io.8:0.rbytes', 'CGROUP', 'job-0')['value'])
        self.assertEqual(point(view, 'io.8:0.rbytes', 'CGROUP', 'job-0')['status'], 'MISSING_OR_INVALID_COUNTER')
        self.assertAlmostEqual(point(view, 'io.8:0.rbytes', 'CGROUP', 'job-0', 2)['value'], .625)

    def test_missing_and_boolean_gauges_and_removed_cgroups_stay_unknown(self):
        args = fixture()
        args[1][1]['meminfo_kb']['Cached'] = False
        args[1][1]['cgroups'][0] = {'present': False}
        view = M.build_series(*args)
        self.assertIsNone(point(view, 'memory.Cached')['value'])
        self.assertIsNone(point(view, 'memory.current', 'CGROUP', 'job-0')['value'])
        self.assertIsNone(point(view, 'cpu.usage', 'CGROUP', 'job-0', 2)['value'])

    def test_no_positional_reassignment_when_cgroup_array_length_changes(self):
        args = fixture()
        args[1][1]['cgroups'] = [args[1][1]['cgroups'][0], copy.deepcopy(args[1][1]['cgroups'][0])]
        view = M.build_series(*args)
        self.assertIsNone(point(view, 'memory.current', 'CGROUP', 'job-0')['value'])
        self.assertTrue(any('INDEX_LENGTH_MISMATCH' in f['kind'] for f in view['findings']))

    def test_disabled_or_unrecorded_schedstats_is_not_zero_wait(self):
        for enabled in (False, None):
            with self.subTest(enabled=enabled):
                view = M.build_series(*fixture(enabled))
                self.assertIsNone(point(view, 'scheduler.validated_run_delay_tasks')['value'])
                self.assertIn('DISABLED' if enabled is False else 'NOT_RECORDED', point(view, 'scheduler.validated_run_delay_tasks')['status'])
                self.assertAlmostEqual(point(view, 'scheduler.raw_run_delay_tasks')['value'], .1)

    def test_missing_seq_long_gap_and_overlapping_collection_break_rate(self):
        for mode, expected in (('seq', 'SAMPLE_SEQUENCE_GAP'), ('long', 'SAMPLING_GAP'),
                               ('overlap', 'NON_ATOMIC_COLLECTION_OVERLAP')):
            with self.subTest(mode=mode):
                args = fixture()
                if mode == 'seq':
                    args[1][1]['seq'], args[1][2]['seq'] = 2, 3
                elif mode == 'long':
                    for row in args[1][1:]:
                        row['monotonic_ns'] += 100000000
                        row['collection_end_ns'] += 100000000
                else:
                    args[1][0]['collection_end_ns'] = args[1][1]['monotonic_ns']
                view = M.build_series(*args)
                self.assertEqual(point(view, 'cpu.user')['status'], expected)
                self.assertIsNone(point(view, 'cpu.user')['value'])

    def test_source_error_affects_only_that_source_not_unrelated_cgroup(self):
        args = fixture()
        args[1][1]['errors'] = [{'path': '/proc/stat', 'error': 'synthetic failure'}]
        view = M.build_series(*args)
        self.assertEqual(point(view, 'cpu.user')['status'], 'SOURCE_READ_ERROR')
        self.assertAlmostEqual(point(view, 'cpu.usage', 'CGROUP', 'job-0')['value'], 1)

    def test_wrong_boot_cgroup_and_backwards_time_are_rejected(self):
        for mode in ('boot', 'inode', 'path', 'time'):
            with self.subTest(mode=mode):
                args = fixture()
                if mode == 'boot': args[2]['boot_id'] = 'other'
                elif mode == 'inode': args[0]['cgroups'][0]['inode'] = 100
                elif mode == 'path': args[0]['cgroups'][0]['path'] = '/other'
                else: args[1][1]['monotonic_ns'] = args[1][0]['monotonic_ns']
                with self.assertRaises(ValueError): M.build_series(*args)

    def test_never_sum_network_interfaces_or_label_guest_as_agent_traffic(self):
        view = M.build_series(*fixture())
        rx = [s for s in view['series'] if s['metric'] == 'network.rx']
        self.assertEqual({s['entity'] for s in rx}, {'eth0', 'veth0'})
        self.assertTrue(all(s['scope'] == 'GUEST' and s['job_id'] is None for s in rx))
        self.assertFalse(any(s['scope'] == 'CGROUP' and s['metric'].startswith('network.') for s in view['series']))
        self.assertTrue(any('PSI' in note and '墙钟' in note for note in view['limits']))


class ExportTests(unittest.TestCase):
    def prepare(self, directory):
        root = Path(directory) / 'campaign'
        (root / 'load').mkdir(parents=True)
        meta, samples, campaign, stats = fixture()
        for name, data in (('campaign.json', campaign), ('load/load-meta.json', meta), ('load/load-sampler-stats.json', stats)):
            (root / name).write_text(json.dumps(data))
        (root / 'load/load-samples.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in samples))
        return root

    def test_fresh_full_csv_html_svg_sources_are_bound_and_not_mutated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.prepare(directory)
            output = Path(directory) / 'view'
            source_bytes = {str(path): path.read_bytes() for path in root.rglob('*') if path.is_file()}
            receipt = M.export_view(root, output)
            self.assertEqual({str(path): path.read_bytes() for path in root.rglob('*') if path.is_file()}, source_bytes)
            self.assertEqual(set(receipt['artifacts']), {'series.json', 'guest-series.csv', 'cgroup-series.csv', 'guest.svg', 'cgroup-00.svg', 'index.html'})
            for name, identity in receipt['artifacts'].items():
                self.assertEqual(M.digest(output / name), identity)
                if name.endswith('.svg'):
                    ET.parse(output / name)
            series = json.loads((output / 'series.json').read_bytes())
            count = 0
            for name in ('guest-series.csv', 'cgroup-series.csv'):
                with (output / name).open(newline='') as stream:
                    rows = list(csv.DictReader(stream))
                count += len(rows)
                self.assertTrue(all(row['scope'] == ('GUEST' if name.startswith('guest') else 'CGROUP') for row in rows))
                first = next(row for row in rows if row['metric'].startswith('cpu.') and row['sample_seq'] == '0')
                self.assertEqual(first['value'], '')
                self.assertEqual(first['status'], 'NO_PREVIOUS_SAMPLE')
                self.assertEqual(first['raw_unit'], 'USER_HZ_ticks' if name.startswith('guest') else 'microseconds')
            self.assertEqual(count, receipt['all_series_points'])
            self.assertEqual(count, len(series['series']) * 3)
            before = (output / 'guest-series.csv').read_bytes()
            with self.assertRaisesRegex(ValueError, 'fresh'): M.export_view(root, output)
            self.assertEqual(before, (output / 'guest-series.csv').read_bytes())

    def test_html_svg_escape_untrusted_labels_without_scripts_or_network(self):
        args = fixture(None)
        args[2]['benchmark'] = '</title><script>alert(1)</script>'
        view = M.build_series(*args)
        document, plots = M.render_view(view)
        self.assertNotIn('<script', document)
        self.assertNotIn('src="http', document)
        self.assertIn('&lt;script&gt;', document)
        self.assertIn('UNKNOWN_RUNTIME_ENABLEMENT_NOT_RECORDED', plots['guest.svg'])
        self.assertIn('NOT_COLLECTED', M.render_view(view, device='not-recorded')[1]['guest.svg'])

    def test_truncated_oversized_duplicate_and_nonfinite_sources_rejected_before_output(self):
        for mode in ('truncated', 'duplicate', 'nonfinite', 'oversized'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = self.prepare(directory)
                output = Path(directory) / 'view'
                path = root / 'load/load-samples.jsonl'
                if mode == 'truncated': path.write_text('{}')
                elif mode == 'duplicate': path.write_text('{"seq":0,"seq":1}\n')
                elif mode == 'nonfinite': path.write_text('{"seq":NaN}\n')
                else: path.write_bytes(b'x' * (M.MAX_LINE_BYTES + 1) + b'\n')
                with self.assertRaises(ValueError): M.export_view(root, output)
                self.assertFalse(output.exists())

    def test_cli_and_symlink_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.prepare(directory)
            output = Path(directory) / 'view'
            with redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(M.main(['--campaign', str(root), '--output', str(output)]), 0)
            self.assertIn('PSI不加墙钟', stdout.getvalue())
            linked = Path(directory) / 'linked'
            linked.symlink_to(Path(directory) / 'not-created')
            with self.assertRaisesRegex(ValueError, 'fresh'): M.export_view(root, linked)
            self.assertFalse((Path(directory) / 'not-created').exists())


if __name__ == '__main__':
    unittest.main()
