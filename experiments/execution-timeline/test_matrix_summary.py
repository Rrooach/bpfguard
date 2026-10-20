#!/usr/bin/env python3
"""Tiny receipt/CSV fixtures only; no VM, native collector or large evidence."""
import copy
import csv
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import matrix_summary as M
from common import digest, write_new


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    write_new(path, value)


def read_example(job='swe-0'):
    read = {'start_ns': 25, 'end_ns': 35, 'requested_bytes': 8, 'returned_bytes': 3, 'result': 3}
    file = {'mount_id': 1, 'device': 0, 'inode': 10, 'generation': 0,
        'path': '/lib/test.so', 'path_quality': 'KERNEL_PATH_AT_LSM_PERMISSION_CANDIDATE', 'read': read}
    key, tool = job + ':thread', job + '-tool0'
    part = {'begin_ns': 20, 'end_ns': 40, 'state': 'SLEEP', 'thread_key': key,
        'syscall': {'name': 'read', 'call_id': 1}, 'files': [copy.deepcopy(file)],
        'stack': ['folio_wait_bit_common', '0x123 (UNRESOLVED_DYNAMIC_JIT_OR_MODULE_RANGE)'],
        'reason': '页等待候选', 'evidence': {'quality': 'RECORDED_TRANSITIONS'}}
    report = {'schema_version': 1, 'run': {'run_id': 'run-' + job, 'boot_id': 'boot'},
        'threads': [{'key': key, 'tid': 10, 'calls': [{'call_id': 1, 'files': [file]}]}],
        'critical_path': {'status': M.GOOD_PATH, 'tools': [{'tool_call_id': tool, 'status': M.GOOD_PATH, 'segments': [part]}]}}
    candidate = {'benchmark': M.BENCHMARKS[0], 'concurrency': 2, 'job_id': job,
        'report_path': '/example/report.json', 'verification': {'report_identity': {'sha256': 'a'*64, 'size_bytes': 1}},
        'thread_key': key, 'tool_call_id': tool, 'wait_begin_ns': 20, 'wait_end_ns': 40}
    return report, candidate


def make_group(root, benchmark=M.BENCHMARKS[0], concurrency=2, *, unknown=False, gap=False):
    slug = ('swe' if benchmark == M.BENCHMARKS[0] else 'terminal') + '-c' + str(concurrency)
    report_root, raw_root, resource_root = [root / (slug + suffix) for suffix in ('-report', '-raw', '-resource')]
    report_root.mkdir(); raw_root.mkdir(); resource_root.mkdir()
    jobs, bindings = [], []
    for index in range(8):
        name = ('swe' if benchmark == M.BENCHMARKS[0] else 'terminal') + '-' + str(index)
        leaf = report_root / 'reports' / name
        leaf.mkdir(parents=True)
        report, candidate = read_example(name)
        dump(leaf / 'report.json', report)
        run = report['run']
        manifest = raw_root / 'jobs' / name / 'manifest.json'
        dump(manifest, {'run_id': run['run_id'], 'boot_id': 'boot', 'synthetic_only': True})
        verification = {'status': 'REPLAY_PASSED', 'source_manifest': str(manifest),
            'manifest_identity': digest(manifest), 'report_identity': digest(leaf / 'report.json')}
        dump(leaf / 'verification.json', verification)
        selected_status = 'INCOMPLETE' if gap and index == 0 else M.GOOD_SELECTED
        tools = [{'tool_call_id': name + '-tool' + str(i), 'owned': {'thread_count': 1},
            'longest_waits': [{'state': 'SLEEP', 'syscall': {'name': 'read'}, 'files': [{'path': '/lib/test.so'}],
                'thread_key': candidate['thread_key'], 'begin_ns': 20, 'end_ns': 40, 'elapsed_ns': 20}] if i == 0 else []}
            for i in range(2)]
        summary = {'run': run, 'tools': tools, 'unassigned_threads': {'count': 1, 'keys': ['infra'], 'details': [{'key': 'infra'}]},
            'selected_tool_timeline_status': selected_status, 'whole_capture_attribution_status': 'UNASSIGNED_EVENTS_PRESENT'}
        dump(leaf / 'summary.json', summary)
        reads = leaf / 'reads'; reads.mkdir()
        with (reads / 'files.csv').open('x', newline='') as stream:
            fields = ('run_id', 'boot_id', 'tool_call_id', 'identity_status', 'mount_id', 'device', 'inode', 'generation',
                      'read_calls', 'actual_returned_bytes', 'actual_returned_bytes_known_sum',
                      'positive_calls', 'eof_calls', 'error_calls', 'unknown_outcome_calls')
            writer = csv.DictWriter(stream, fields); writer.writeheader()
            for i in range(2):
                writer.writerow(dict(run_id=run['run_id'], boot_id='boot', tool_call_id=name+'-tool'+str(i),
                    identity_status='VALID_BOOT_LOCAL_IDENTITY', mount_id=1, device=0, inode=10, generation=0,
                    read_calls=1, actual_returned_bytes=None if unknown and index == 0 and i == 0 else 3,
                    actual_returned_bytes_known_sum=0 if unknown and index == 0 and i == 0 else 3,
                    positive_calls=0 if unknown and index == 0 and i == 0 else 1, eof_calls=0, error_calls=0,
                    unknown_outcome_calls=1 if unknown and index == 0 and i == 0 else 0))
        for filename in ('reads.csv', 'excluded-reads.csv', 'unassigned-reads.csv'):
            dump(reads / filename, b'unit-fixture-only\n')
        reading = {'run_id': run['run_id'], 'boot_id': 'boot', 'counts': {'report_read_records': 4,
            'partitioned_read_records': 4, 'WITHIN_TOOL_EXECUTION_WINDOW': 2,
            'excluded_owned_read_records': 1, 'unassigned_read_records': 1},
            'artifacts': {filename: digest(reads / filename) for filename in ('reads.csv', 'files.csv', 'excluded-reads.csv', 'unassigned-reads.csv')}}
        dump(reads / 'receipt.json', reading)
        counters = {'cpu.stat.user_usec': {'delta': None if unknown and index == 0 else 100},
            'cpu.stat.system_usec': {'delta': 50}, 'memory.stat.pgfault': {'delta': 3}, 'memory.stat.pgmajfault': {'delta': 0}}
        dump(leaf / 'resources.json', {'delta': {'counters': counters}})
        acceptance = {'job_id': name, 'benchmark': benchmark, 'official_passed': True,
            'verification': verification, 'health': {'records': 10, 'status': 'COMPLETE_FOR_SELECTED_HOOKS'},
            'reads_receipt': digest(reads / 'receipt.json'), 'resource_receipt': digest(leaf / 'resources.json')}
        dump(leaf / 'acceptance.json', acceptance)
        bindings.append({'job_id': name, 'identity': digest(leaf / 'acceptance.json')})
        jobs.append({'job_id': name, 'task_id': ('requests-1142' if benchmark == M.BENCHMARKS[0] else 'terminal-task'+str(index % 2)),
            'mode': 'ORACLE_REFERENCE', 'official_passed': True, 'source_run_id': run['run_id'],
            'agent_return_ns': 99, 'read_calls': 2, 'returned_bytes': None if unknown and index == 0 else 6,
            'returned_bytes_known_sum': 3 if unknown and index == 0 else 6, 'cpu_user_usec': counters['cpu.stat.user_usec']['delta'],
            'cpu_system_usec': 50, 'pgfault': 3, 'pgmajfault': 0})
        dump(leaf / 'timeline.html', b'<html>unit fixture</html>')
    timing = {'benchmark': benchmark, 'concurrency': concurrency, 'total_jobs': 8,
        'batch_start_ns': 14, 'batch_end_ns': 100, 'batch_wall_ns': 86,
        'campaign_start_ns': 5, 'campaign_end_ns': 200, 'campaign_wall_ns': 195,
        'agent_return_batch_wall_ns': 85}
    campaign = dict(timing, schema_version=1, boot_id='boot')
    dump(raw_root / 'campaign.json', campaign)
    config = {'collector_identity': {'sha256': 'a'*64, 'size_bytes': 100},
        'bpf_object_identity': {'sha256': 'b'*64, 'size_bytes': 100}, 'cpus': 16}
    result = {'schema_version': 1, 'authority': 'COMPOSITE_VIEW_OF_INDEPENDENTLY_VERIFIED_STREAMS',
        'status': 'INDEPENDENT_LEAF_REPORTS_COMPOSED', 'timing': timing,
        'source_campaign': {'path': str(raw_root / 'campaign.json'), **digest(raw_root / 'campaign.json')},
        'jobs': jobs, 'total_jobs': 8, 'official_passed_jobs': 8, 'independent_replay_passed_jobs': 8,
        'leaf_acceptance': bindings, 'resource_configuration': config}
    dump(report_root / 'result.json', result)
    resource = {'run': {'boot_id': 'boot', 'benchmark': benchmark, 'concurrency': concurrency,
        'total_jobs': 8, 'begin_ns': 14, 'end_ns': 100}, 'findings': [],
        'sources': {'campaign.json': {'sha256': digest(raw_root / 'campaign.json')['sha256']}}}
    dump(resource_root / 'receipt.json', resource)
    for root_path, names in ((report_root, ('index.html', 'timeline.html', 'timeline-report.json', 'jobs.csv')),
                             (resource_root, ('index.html', 'guest-series.csv', 'cgroup-series.csv'))):
        for name in names: dump(root_path / name, b'unit fixture only\n')
    return report_root, resource_root


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_partial_smoke_keeps_each_benchmark_separate_and_never_reads_large_report(self):
        groups = [make_group(self.root, benchmark) for benchmark in M.BENCHMARKS]
        original = M.Sources.read
        def read(sources, path, *args, **kwargs):
            self.assertNotEqual(Path(path).name, 'report.json', 'smoke must avoid full leaf JSON I/O')
            return original(sources, path, *args, **kwargs)
        with mock.patch.object(M.Sources, 'read', read):
            result = M.export_matrix(groups, self.root / 'output', allow_partial=True, skip_example=True)
        self.assertEqual(result['status'], 'SMOKE_NOT_FORMAL')
        self.assertEqual(len(result['groups']), 2)
        self.assertEqual([entry['capture_order_in_boot'] for entry in result['capture_order']], [1, 1],
                         'equal timestamps must not invent an execution order')
        self.assertEqual(result['file_wait_example']['status'], 'NOT_SEARCHED_SMOKE_AVOIDS_LARGE_REPORT_IO')
        self.assertNotIn('speedup', result)
        for group in result['groups']:
            row = group['totals']
            self.assertEqual((row['batch_wall_ns'], row['agent_return_batch_wall_ns'], row['campaign_wall_ns']), (86, 85, 195))
            self.assertEqual((row['official_passed_jobs'], row['independent_replay_passed_jobs'], row['complete_selected_tool_jobs']), (8,8,8))
            self.assertEqual((row['events'], row['tools'], row['thread_rows'], row['unassigned_thread_rows']), (80,16,24,8))
            self.assertEqual((row['selected_read_calls'], row['actual_returned_bytes']), (16,48))

    def test_objects_dedup_across_tools_but_never_across_jobs(self):
        group = M.load_group(*make_group(self.root), M.Sources())
        self.assertEqual(group['totals']['sum_per_job_observed_object_identities'], 8)
        self.assertEqual(group['totals']['generation_zero_file_rows'], 16)
        self.assertEqual(group['totals']['sum_per_job_success_or_eof_objects'], 8)
        self.assertEqual(group['totals']['sum_per_job_failed_only_objects'], 0)
        self.assertTrue(all(job['object_counts']['observed_identity_count'] == 1 for job in group['jobs']))

    def test_actual_capture_order_is_bound_to_timestamps_not_input_or_concurrency_sort(self):
        earlier = make_group(self.root, concurrency=8)
        later = make_group(self.root, concurrency=2)
        result_path = later[0] / 'result.json'
        result = json.loads(result_path.read_bytes())
        campaign_path = Path(result['source_campaign']['path'])
        campaign = json.loads(campaign_path.read_bytes())
        for field in ('campaign_start_ns', 'campaign_end_ns', 'batch_start_ns', 'batch_end_ns'):
            campaign[field] += 1000
            result['timing'][field] += 1000
        for job in result['jobs']:
            job['agent_return_ns'] += 1000
        campaign_path.write_text(json.dumps(campaign))
        result['source_campaign'].update(digest(campaign_path))
        result_path.write_text(json.dumps(result))
        resource_path = later[1] / 'receipt.json'
        resource = json.loads(resource_path.read_bytes())
        resource['run']['begin_ns'] += 1000
        resource['run']['end_ns'] += 1000
        resource['sources']['campaign.json']['sha256'] = digest(campaign_path)['sha256']
        resource_path.write_text(json.dumps(resource))
        output = self.root / 'chronology'
        summary = M.export_matrix([later, earlier], output, True, True)
        self.assertEqual([group['totals']['concurrency'] for group in summary['groups']], [2, 8])
        self.assertEqual([row['concurrency'] for row in summary['capture_order']], [8, 2])
        self.assertEqual([row['capture_order_in_boot'] for row in summary['capture_order']], [1, 2])
        self.assertEqual([row['campaign_start_ns'] for row in summary['capture_order']], [5, 1005])
        with (output / 'summary.csv').open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual([row['capture_order_in_boot'] for row in rows], ['2', '1'])
        self.assertIn('实际采集顺序', (output / 'index.html').read_text())

    def test_object_outcomes_merge_across_tools_and_failed_null_byte_is_not_unknown(self):
        pair = make_group(self.root)
        original = pair[0] / 'reports/swe-0/reads/files.csv'
        with original.open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        rows[0].update(positive_calls='0', eof_calls='0', error_calls='1', unknown_outcome_calls='0',
                       actual_returned_bytes='0', actual_returned_bytes_known_sum='0')
        rows[1].update(positive_calls='0', eof_calls='1', error_calls='0', unknown_outcome_calls='0',
                       actual_returned_bytes='0', actual_returned_bytes_known_sum='0')
        # Distinct object with an EAGAIN-only attempt; the per-file positive
        # byte aggregate is known zero even though raw per-read bytes is null.
        failure = dict(rows[0], inode='11')
        unknown = dict(rows[0], inode='12', error_calls='0', unknown_outcome_calls='1', actual_returned_bytes='')
        eof = dict(rows[1], inode='13')
        path = self.root / 'outcome-files.csv'
        with path.open('x', newline='') as stream:
            writer = csv.DictWriter(stream, list(rows[0])); writer.writeheader(); writer.writerows(rows + [failure, unknown, eof])
        value = M.observed_objects(path, digest(path), {'run_id': 'run-swe-0', 'boot_id': 'boot'}, M.Sources())
        self.assertEqual(value['observed_identity_count'], 4)
        self.assertEqual(value['success_or_eof_objects'], 2)
        self.assertEqual(value['failed_only_objects'], 1)
        self.assertEqual(value['unknown_outcome_objects'], 1)
        self.assertEqual(value['actual_returned_bytes_known_sum'], 0)
        self.assertIsNone(value['actual_returned_bytes'])

    def test_one_unknown_total_stays_unknown_with_labeled_known_subset(self):
        group = M.load_group(*make_group(self.root, unknown=True), M.Sources())
        self.assertIsNone(group['totals']['actual_returned_bytes'])
        self.assertEqual(group['totals']['actual_returned_bytes_known_sum'], 45)
        self.assertEqual(group['totals']['unknown_return_jobs'], 1)
        self.assertIsNone(group['totals']['cpu_user_usec_sum'])
        self.assertEqual(group['aggregate_quality']['cpu_user_usec_sum'], {'value': None, 'known_sum': 700, 'known_values': 7, 'unknown_values': 1})
        page = M.render_index({'groups': [group], 'status': 'SMOKE_NOT_FORMAL', 'limits': [],
            'file_wait_example': {'status': 'NOT_SEARCHED'}}, self.root / 'unknown-display')
        self.assertIn('UNKNOWN', page)

    def test_partial_coverage_does_not_hide_official_or_replay_result(self):
        group = M.load_group(*make_group(self.root, gap=True), M.Sources())
        self.assertEqual(group['totals']['complete_selected_tool_jobs'], 7)
        self.assertEqual(group['totals']['official_passed_jobs'], 8)
        self.assertEqual(group['totals']['independent_replay_passed_jobs'], 8)

    def test_actual_summary_count_keys_details_contract_is_strict(self):
        pair = make_group(self.root)
        path = pair[0] / 'reports/swe-0/summary.json'
        value = json.loads(path.read_bytes())
        value['unassigned_threads']['count'] = 99
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'unassigned count/keys/details differ'):
            M.load_group(*pair, M.Sources())

    def test_formal_requires_both_complete2468_sets_and_uniform_native_profile(self):
        one = make_group(self.root)
        with self.assertRaisesRegex(ValueError, 'exactly2/4/6/8'):
            M.export_matrix([one], self.root / 'incomplete')
        self.assertFalse((self.root / 'incomplete').exists())
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            M.export_matrix([one,one], self.root / 'duplicate', allow_partial=True, skip_example=True)
        groups = [one] + [make_group(self.root, benchmark, concurrency)
            for benchmark in M.BENCHMARKS for concurrency in (2,4,6,8) if not(benchmark == M.BENCHMARKS[0] and concurrency == 2)]
        selection = self.root / 'formal-selection.json'
        members = [{'benchmark': benchmark, 'concurrency': concurrency,
            'host_directory': str(self.root / (('swe' if benchmark == M.BENCHMARKS[0] else 'terminal') + '-c' + str(concurrency) + '-raw'))}
            for benchmark in M.BENCHMARKS for concurrency in (2,4,6,8)]
        dump(selection, {'status': 'EIGHT_FORMAL_REFERENCE_GROUPS_CAPTURED_EXPORTED_FSYNCED_AND_GUEST_QUIET',
            'boot_id': 'boot', 'groups_in_actual_capture_order': members})
        context = self.root / 'vm-stop.json'
        dump(context, {'status': 'VM_STOPPED_SYNTHETIC_TEST_CONTEXT'})
        result = M.export_matrix(groups, self.root / 'formal', selection=selection, context_receipts=[context])
        self.assertEqual(result['status'], 'FORMAL_FIXED_EIGHT_REFERENCE_MATRIX')
        self.assertEqual(result['file_wait_example']['status'], 'PROVEN_SELECTED_COMPLETION_SLEEP_INTERSECTS_SAME_CALL_VFS_READ')
        self.assertTrue(Path(result['file_wait_example']['source_timeline']).is_file())
        self.assertEqual(result['file_wait_example']['source_timeline_status'], 'EXISTENCE_CHECKED_PRESENTATION_ONLY_NOT_CONTENT_VERIFIED')
        self.assertIn('打开该例的完整时间线HTML', (self.root / 'formal/index.html').read_text())
        self.assertEqual(len(result['groups']), 8)
        self.assertEqual(len(result['bound_context']), 2)
        self.assertIn('vm-stop.json', (self.root / 'formal/index.html').read_text())
        self.assertEqual(result['bound_context'][0]['identity'], digest(selection))
        wrong = json.loads(selection.read_bytes())
        wrong['boot_id'] = 'unrelated-boot'
        other = self.root / 'other-selection.json'
        dump(other, wrong)
        with self.assertRaisesRegex(ValueError, 'boot differs'):
            M.export_matrix(groups, self.root / 'wrong-boot', selection=other)
        wrong['boot_id'] = 'boot'
        wrong['groups_in_actual_capture_order'][0]['host_directory'] = wrong['groups_in_actual_capture_order'][1]['host_directory']
        other.write_text(json.dumps(wrong))
        with self.assertRaisesRegex(ValueError, 'inputs differ'):
            M.export_matrix(groups, self.root / 'wrong-members', selection=other)
        changed = groups[-1][0] / 'result.json'
        value = json.loads(changed.read_bytes())
        value['resource_configuration']['collector_identity']['sha256'] = 'c'*64
        changed.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'mix collector/BPF'):
            M.export_matrix(groups, self.root / 'mixed-native')

    def test_bound_file_tampering_or_resource_identity_mismatch_is_rejected(self):
        pair = make_group(self.root)
        path = pair[0] / 'reports/swe-0/reads/files.csv'
        path.write_bytes(path.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'saved receipt|size differs'):
            M.load_group(*pair, M.Sources())
        other = make_group(self.root, M.BENCHMARKS[1])
        with self.assertRaisesRegex(ValueError, 'resource-view/campaign'):
            M.load_group(pair[0], other[1], M.Sources())

    def test_fresh_cli_and_all_evidence_links_and_source_bindings(self):
        pair = make_group(self.root)
        output = self.root / 'display'
        with redirect_stdout(io.StringIO()):
            self.assertEqual(M.main(['--group', str(pair[0]), str(pair[1]), '--output', str(output), '--allow-partial', '--skip-example']), 0)
        receipt = json.loads((output / 'receipt.json').read_bytes())
        for name, identity in receipt['artifacts'].items(): self.assertEqual(digest(output / name), identity)
        page = (output / 'index.html').read_text()
        for text in ('未归属read', '窗外read', '原始manifest', '资源图', 'SMOKE_NOT_FORMAL', 'n=1',
                     '官方参考任务', '不是新模型执行成绩', '任务做对了', '原始证据与独立复算一致',
                     '不等于全部Linux活动完整覆盖', 'ONCPU / ON_CPU', 'RUNNABLE', '还在等CPU',
                     'SLEEP', '线程阻塞或睡眠', 'VFS累计耗时 / PSI', '都不能加到墙钟',
                     '不是全局不同文件数', '不是逐文件归因'):
            self.assertIn(text, page)
        before = (output / 'summary.csv').read_bytes()
        with self.assertRaisesRegex(ValueError, 'fresh'): M.export_matrix([pair], output, True, True)
        self.assertEqual((output / 'summary.csv').read_bytes(), before)


class ExampleTests(unittest.TestCase):
    def test_real_active_read_interval_with_same_call_is_required(self):
        report, candidate = read_example()
        example = M.proven_file_wait(report, candidate)
        self.assertEqual(example['actual_returned_bytes'], 3)
        self.assertEqual(example['requested_bytes'], 8)
        self.assertEqual(example['active_read_sleep_intersection_ns'], 10)
        self.assertEqual(example['wait_elapsed_ns'], 20)
        self.assertIn('UNRESOLVED', example['stack'][1])
        self.assertIn('INODE_MODE_NOT_CAPTURED', example['limits'])
        self.assertIsNone(example['source_timeline'])
        self.assertEqual(example['source_timeline_status'], 'NOT_PRESENT_OR_NOT_REGULAR')

    def test_annotation_only_stop_barrier_pipe_outside_read_or_incomplete_never_becomes_file_wait(self):
        for mode in ('annotation', 'stopped', 'stopped-sleep', 'pipe', 'proc', 'outside', 'wrong-call', 'incomplete'):
            with self.subTest(mode=mode):
                report, candidate = read_example()
                part = report['critical_path']['tools'][0]['segments'][0]
                if mode == 'annotation': part['files'][0].pop('read')
                elif mode == 'stopped': part['state'] = 'STOPPED'
                elif mode == 'stopped-sleep': part['sleep_state'] = 'STOPPED'
                elif mode == 'pipe': part['files'][0]['path'] = 'pipe:[1]'
                elif mode == 'proc': part['files'][0]['path'] = '/proc/self/status'
                elif mode == 'outside': part['files'][0]['read'].update(start_ns=50,end_ns=60)
                elif mode == 'wrong-call': part['syscall']['call_id'] = 999
                else: report['critical_path']['status'] = 'INCOMPLETE'
                self.assertIsNone(M.proven_file_wait(report, candidate))


if __name__ == '__main__': unittest.main()
