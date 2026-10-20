#!/usr/bin/env python3
"""Small report-only exporter contracts; no VM or raw evidence is used."""
import copy
import csv
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import export_reads
import test_summarize as fixtures


def rows(path):
    with path.open(encoding='utf-8', newline='') as stream:
        return list(csv.DictReader(stream))


class ExportReadsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'export'

    def export(self, report=None):
        report = fixtures.fixture() if report is None else report
        before = copy.deepcopy(report)
        receipt = export_reads.export_report(report, self.output)
        self.assertEqual(report, before, 'export must not mutate independently replayed report')
        return receipt, rows(self.output / 'reads.csv'), rows(self.output / 'files.csv')

    def test_actual_bytes_not_request_and_no_segment_recount(self):
        receipt, reads, files = self.export()
        self.assertEqual(receipt['status'], 'COMPLETE_FOR_SELECTED_REPORT_RECORDS')
        self.assertEqual(len(reads), 3)
        self.assertEqual(len(files), 2)
        self.assertEqual(sum(int(read['actual_returned_bytes']) for read in reads), 8)
        self.assertEqual(sum(int(read['requested_bytes']) for read in reads), 48)
        first = next(file for file in files if file['inode'] == '10')
        self.assertEqual(first['read_calls'], '2')
        self.assertEqual(first['actual_returned_bytes'], '8')
        self.assertEqual((first['positive_calls'], first['eof_calls'], first['error_calls']), ('1', '1', '0'))
        self.assertEqual(first['elapsed_sum_ns'], '200')
        self.assertEqual(first['elapsed_mean_ns'], '100')
        self.assertEqual(first['elapsed_max_ns'], '100')
        self.assertEqual(json.loads(first['path_candidates_json']), ['/src/a.c', '/src/hardlink.c'])
        self.assertEqual(first['path_observation_status'], 'MULTIPLE_OBSERVED_CANDIDATES')

    def test_same_inode_in_different_tools_is_not_merged(self):
        report = fixtures.fixture()
        tool = copy.deepcopy(report['tools'][0])
        tool.update(agent_id='B', task_id='task-B', tool_call_id='tool-B', root_key='B-root')
        report['tools'].append(tool)
        for original in report['threads'][:]:
            other = copy.deepcopy(original)
            other.update(key='B-' + original['key'], agent_id='B', tool_call_id='tool-B',
                parent_key='B-' + original['parent_key'] if original['parent_key'] else None)
            report['threads'].append(other)
        _, reads, files = self.export(report)
        self.assertEqual(len(reads), 6)
        self.assertEqual(len(files), 4)
        objects = [file for file in files if file['inode'] == '10']
        self.assertEqual({file['tool_call_id'] for file in objects}, {'tool-A', 'tool-B'})
        self.assertTrue(all(file['actual_returned_bytes'] == '8' for file in objects))

    def test_same_name_different_object_identity_is_not_merged(self):
        report = fixtures.fixture()
        report['threads'][1]['calls'][1]['files'][0].update(inode=777, path='/src/a.c')
        _, _, files = self.export(report)
        self.assertEqual(len(files), 3)
        self.assertEqual({file['inode'] for file in files}, {'10', '11', '777'})

    def test_parallel_cumulative_elapsed_can_exceed_tool_wall(self):
        report = fixtures.fixture()
        for sequence in range(20):
            call = copy.deepcopy(report['threads'][1]['calls'][0])
            call['call_id'] = sequence + 100
            report['threads'][1]['calls'].append(call)
        receipt, reads, files = self.export(report)
        first = next(file for file in files if file['inode'] == '10')
        self.assertEqual(len(reads), 23)
        self.assertEqual(first['elapsed_sum_ns'], '2200')
        self.assertGreater(int(first['elapsed_sum_ns']), report['tools'][0]['end_ns'] - report['tools'][0]['begin_ns'])
        self.assertEqual(first['elapsed_mean_ns'], '100')
        self.assertIn('NOT_WALL', first['timing_scope'])
        self.assertIn('NOT_WALL', receipt['scope']['time'])

    def test_failed_null_return_remains_empty_not_success_or_eof(self):
        report = fixtures.fixture()
        report['threads'][2]['calls'][0]['files'][0]['read']['returned_bytes'] = None
        receipt, reads, files = self.export(report)
        failed = next(read for read in reads if read['signed_result'] == '-13')
        self.assertEqual(failed['actual_returned_bytes'], '')
        self.assertEqual(failed['read_outcome'], 'ERROR')
        self.assertEqual(failed['bytes_status'], 'FAILED_NO_POSITIVE_RETURN')
        file = next(file for file in files if file['inode'] == '11')
        self.assertEqual((file['positive_calls'], file['eof_calls'], file['error_calls']), ('0', '0', '1'))
        self.assertEqual(file['actual_returned_bytes'], '0')
        self.assertEqual(receipt['status'], 'COMPLETE_FOR_SELECTED_REPORT_RECORDS')

    def test_unknown_return_is_not_zero_and_known_subset_is_labeled(self):
        report = fixtures.fixture()
        report['threads'][1]['calls'][0]['files'][0]['read']['returned_bytes'] = None
        receipt, reads, files = self.export(report)
        unknown = next(read for read in reads if read['signed_result'] == '8')
        self.assertEqual(unknown['actual_returned_bytes'], '')
        self.assertEqual(unknown['read_outcome'], 'UNKNOWN')
        first = next(file for file in files if file['inode'] == '10')
        self.assertEqual(first['actual_returned_bytes'], '')
        self.assertEqual(first['actual_returned_bytes_known_sum'], '0')
        self.assertEqual(first['unknown_bytes_calls'], '1')
        self.assertEqual(receipt['status'], 'EXPORTED_WITH_DECLARED_GAPS')

    def test_inconsistent_and_boolean_return_are_not_validated(self):
        for returned, result in ((17, 17), (9, 8), (False, -13)):
            with self.subTest(returned=returned, result=result):
                report = fixtures.fixture()
                file = report['threads'][1]['calls'][0]['files'][0]
                file['read'].update(returned_bytes=returned, result=result)
                row, known = export_reads.read_row(report['tools'][0], 'root', report['threads'][1],
                    report['threads'][1]['calls'][0], file, 1, report['run'])
                self.assertIsNone(known)
                self.assertNotIn(row['bytes_status'], ('CONSISTENT_SIGNED_VFS_RETURN', 'FAILED_NO_POSITIVE_RETURN'))

    def test_missing_object_identity_never_merges_different_unknown_reads(self):
        report = fixtures.fixture()
        for call in report['threads'][1]['calls']:
            call['files'][0].pop('inode')
        receipt, reads, files = self.export(report)
        unresolved = [file for file in files if file['identity_status'] == 'UNRESOLVED']
        self.assertEqual(len(unresolved), 2)
        self.assertEqual(len({file['object_key'] for file in unresolved}), 2)
        self.assertEqual(receipt['unresolved_identity_file_rows'], 2)
        self.assertTrue(all(file['read_calls'] == '1' for file in unresolved))
        self.assertEqual(receipt['status'], 'EXPORTED_WITH_DECLARED_GAPS')
        self.assertEqual(sum(read['identity_status'] == 'UNRESOLVED' for read in reads), 2)

    def test_missing_call_id_never_uses_read_record_id_as_fake_unique_syscall(self):
        report = fixtures.fixture()
        for call in report['threads'][1]['calls']:
            call.pop('call_id')
        receipt, reads, files = self.export(report)
        first = next(file for file in files if file['inode'] == '10')
        self.assertEqual(first['read_calls'], '2')
        self.assertEqual(first['unique_syscall_calls'], '')
        self.assertEqual(first['known_unique_syscall_calls'], '0')
        self.assertEqual(first['unknown_call_id_records'], '2')
        self.assertEqual(receipt['counts']['unknown_call_id_records'], 2)
        self.assertEqual(receipt['status'], 'EXPORTED_WITH_DECLARED_GAPS')
        self.assertTrue(all(read['call_id'] == '' for read in reads if read['inode'] == '10'))

    def test_missing_path_stays_empty_and_identity_is_not_a_guessed_path(self):
        report = fixtures.fixture()
        report['threads'][1]['calls'][0]['files'][0].pop('path')
        receipt, reads, _ = self.export(report)
        self.assertEqual(reads[0]['path'], '')
        self.assertEqual(reads[0]['identity_status'], 'VALID_BOOT_LOCAL_IDENTITY')
        self.assertTrue(reads[0]['object_key'].startswith('OBJECT:'))
        self.assertEqual(receipt['counts']['unresolved_path_records'], 1)

    def test_csv_escaping_preserves_unicode_quotes_commas_newlines_and_formula_text(self):
        report = fixtures.fixture()
        path = '=test,"世界\n源码.c'
        report['threads'][1]['calls'][0]['files'][0]['path'] = path
        receipt, reads, files = self.export(report)
        self.assertEqual(reads[0]['path'], path)
        self.assertIn(path, json.loads(next(file for file in files if file['inode'] == '10')['path_candidates_json']))
        self.assertIn('IMPORT_AS_TEXT', receipt['scope']['csv'])

    def test_ambiguous_observed_paths_preserve_candidates_and_gap(self):
        report = fixtures.fixture()
        file = report['threads'][1]['calls'][0]['files'][0]
        file.update(path=None, path_quality='AMBIGUOUS_PATH_OBSERVATIONS', observed_paths=[
            {'path': '/old/name'}, {'path': '/new/name'}, {'path': '/old/name'}])
        receipt, reads, files = self.export(report)
        self.assertEqual(reads[0]['path'], '')
        self.assertEqual(json.loads(reads[0]['path_candidates_json']), ['/new/name', '/old/name'])
        first = next(file for file in files if file['inode'] == '10')
        self.assertEqual(json.loads(first['path_candidates_json']), ['/new/name', '/old/name', '/src/hardlink.c'])
        self.assertEqual(receipt['status'], 'EXPORTED_WITH_DECLARED_GAPS')

    def test_crossing_unknown_and_outside_reads_are_not_silently_added(self):
        report = fixtures.fixture()
        for start, end in ((50, 150), (1050, 1150), (10, 50), (1200, 1300), (None, 150)):
            call = copy.deepcopy(report['threads'][1]['calls'][0])
            call['files'][0]['read'].update(start_ns=start, end_ns=end)
            report['threads'][1]['calls'].append(call)
        receipt, reads, files = self.export(report)
        self.assertEqual(len(reads), 3)
        excluded = rows(self.output / 'excluded-reads.csv')
        self.assertEqual(len(excluded), 5)
        self.assertEqual(sum(row['scope_status'] == 'CROSSES_TOOL_WINDOW_UNALLOCATED' for row in excluded), 2)
        self.assertEqual(sum(row['scope_status'] == 'OUTSIDE_TOOL_EXECUTION_WINDOW' for row in excluded), 2)
        self.assertEqual(sum(row['scope_status'] == 'UNRESOLVED_READ_INTERVAL' for row in excluded), 1)
        self.assertEqual(sum(int(file['read_calls']) for file in files), 3)
        self.assertEqual(receipt['status'], 'EXPORTED_WITH_DECLARED_GAPS')

    def test_unowned_threads_are_not_assigned_by_time_or_cgroup(self):
        report = fixtures.fixture(infra=True)
        report['findings'].append({'kind': 'THREAD_NOT_BOUND_TO_TOOL', 'thread': 'infra'})
        receipt, reads, _ = self.export(report)
        self.assertEqual(len(reads), 3)
        self.assertEqual(receipt['unassigned_thread_keys'], ['infra'])
        self.assertEqual(receipt['status'], 'COMPLETE_FOR_SELECTED_REPORT_RECORDS')
        self.assertIn('NOT_RAW_VERIFICATION', receipt['authority'])

    def test_unassigned_reads_are_preserved_separately_and_partition_all_report_records(self):
        report = fixtures.fixture(infra=True)
        infra = report['threads'][-1]
        infra['calls'] = copy.deepcopy(report['threads'][1]['calls'] + report['threads'][2]['calls'])
        # Identical object/path/time is not ownership and cannot be merged
        # into the selected Agent's file totals.
        receipt, reads, files = self.export(report)
        unassigned = rows(self.output / 'unassigned-reads.csv')
        self.assertEqual((len(reads), len(files), len(unassigned)), (3, 2, 3))
        self.assertEqual(receipt['counts']['report_read_records'], 6)
        self.assertEqual(receipt['counts']['partitioned_read_records'], 6)
        self.assertEqual(receipt['counts']['unassigned_read_records'], 3)
        self.assertEqual(receipt['read_partition_status'], 'ALL_REPORT_READ_RECORDS_EXPORTED_ONCE')
        self.assertEqual(receipt['whole_capture_attribution_status'], 'UNASSIGNED_EVENTS_PRESENT')
        self.assertEqual(receipt['status'], 'COMPLETE_FOR_SELECTED_REPORT_RECORDS')
        for row in unassigned:
            self.assertEqual(row['scope_status'], 'UNASSIGNED_NOT_ATTRIBUTED')
            self.assertEqual(row['attribution_status'], 'UNASSIGNED_NOT_ATTRIBUTED')
            self.assertEqual(row['thread_key'], 'infra')
            self.assertEqual([row[key] for key in ('agent_id', 'task_id', 'tool_call_id', 'root_key')], ['', '', '', ''])
        identifiers = [row['read_record_id'] for row in reads + unassigned]
        self.assertEqual(len(set(identifiers)), 6)
        self.assertEqual(sum(int(row['actual_returned_bytes']) for row in reads), 8)
        self.assertEqual(sum(int(row['actual_returned_bytes']) for row in unassigned), 8)
        self.assertEqual({row['read_outcome'] for row in unassigned}, {'POSITIVE', 'EOF', 'ERROR'})

    def test_unassigned_declared_tags_without_ancestry_are_not_verified_identity(self):
        report = fixtures.fixture(infra=True)
        infra = report['threads'][-1]
        infra.update(agent_id='A', task_id='declared-task', tool_call_id='tool-A')
        infra['calls'] = copy.deepcopy(report['threads'][1]['calls'][:1])
        receipt, reads, _files = self.export(report)
        row = rows(self.output / 'unassigned-reads.csv')[0]
        self.assertEqual((row['agent_id'], row['tool_call_id'], row['root_key']), ('', '', ''))
        self.assertEqual((row['declared_agent_id'], row['declared_task_id'], row['declared_tool_call_id']),
                         ('A', 'declared-task', 'tool-A'))
        self.assertEqual(row['attribution_status'], 'UNASSIGNED_NOT_ATTRIBUTED')
        self.assertEqual(len(reads), 3)
        self.assertEqual(receipt['status'], 'EXPORTED_WITH_DECLARED_GAPS')

    def test_unassigned_unknown_invalid_and_failed_values_are_retained_without_guessing(self):
        report = fixtures.fixture(infra=True)
        infra = report['threads'][-1]
        infra['calls'] = []
        intervals = ((None, 150), (4950, 5050), (5100, 5200), (-1, 150))
        for start, end in intervals:
            call = copy.deepcopy(report['threads'][1]['calls'][0])
            file = call['files'][0]
            file.pop('inode')
            file['path'] = '=test,"世界\n未归属.c'
            file['read'].update(start_ns=start, end_ns=end, returned_bytes=None, result=-13,
                                original_unknown_field={'keep': True})
            infra['calls'].append(call)
        receipt, reads, _files = self.export(report)
        unassigned = rows(self.output / 'unassigned-reads.csv')
        self.assertEqual(len(unassigned), 4)
        self.assertEqual({row['run_window_status'] for row in unassigned},
                         {'UNRESOLVED_READ_INTERVAL', 'CROSSES_RUN_WINDOW_UNALLOCATED', 'OUTSIDE_DECLARED_RUN_WINDOW'})
        for row, call in zip(unassigned, infra['calls']):
            self.assertEqual(row['path'], call['files'][0]['path'])
            self.assertEqual(row['actual_returned_bytes'], '')
            self.assertEqual(row['signed_result'], '-13')
            self.assertEqual(row['read_outcome'], 'ERROR')
            self.assertEqual(row['identity_status'], 'UNRESOLVED')
            self.assertEqual(json.loads(row['read_evidence_json']), call['files'][0])
        self.assertEqual(len({row['object_key'] for row in unassigned}), 4)
        self.assertEqual(receipt['counts']['report_read_records'], 7)
        self.assertEqual(len(reads), 3)

    def test_no_selected_tools_still_exports_every_unassigned_report_read(self):
        report = fixtures.fixture()
        report['tools'] = []
        receipt, reads, files = self.export(report)
        unassigned = rows(self.output / 'unassigned-reads.csv')
        self.assertEqual((len(reads), len(files), len(unassigned)), (0, 0, 3))
        self.assertEqual(receipt['counts']['report_read_records'], 3)
        self.assertEqual(receipt['counts']['partitioned_read_records'], 3)
        self.assertEqual(receipt['status'], 'EXPORTED_WITH_DECLARED_GAPS')
        self.assertIn('NO_SELECTED_TOOLS', {issue['kind'] for issue in receipt['issues']})

    def test_selected_excluded_unassigned_partition_counts_do_not_count_segment_annotations(self):
        report = fixtures.fixture(infra=True)
        infra = report['threads'][-1]
        infra['calls'] = copy.deepcopy(report['threads'][1]['calls'][:1])
        outside = copy.deepcopy(report['threads'][1]['calls'][0])
        outside['files'][0]['read'].update(start_ns=10, end_ns=50)
        report['threads'][1]['calls'].append(outside)
        receipt, reads, _files = self.export(report)
        excluded = rows(self.output / 'excluded-reads.csv')
        unassigned = rows(self.output / 'unassigned-reads.csv')
        self.assertEqual((len(reads), len(excluded), len(unassigned)), (3, 1, 1))
        self.assertEqual(receipt['counts']['report_read_records'], 5)
        self.assertEqual(receipt['counts']['excluded_owned_read_records'], 1)
        self.assertEqual(receipt['counts']['owned_read_records_seen'], 4)
        self.assertEqual(receipt['counts']['partitioned_read_records'], 5)
        self.assertIn('NO_ABI_UNSELECTED_INTERFACE_COMPLETENESS_CLAIM', receipt['scope']['partition'])

    def test_tag_without_verified_root_ancestry_is_rejected(self):
        report = fixtures.fixture(infra=True)
        report['threads'][-1].update(agent_id='A', tool_call_id='tool-A')
        receipt, reads, _ = self.export(report)
        self.assertEqual(len(reads), 3)
        self.assertEqual(receipt['unassigned_thread_keys'], ['infra'])
        self.assertEqual(receipt['status'], 'EXPORTED_WITH_DECLARED_GAPS')

    def test_source_incomplete_or_selected_findings_stay_gaps(self):
        report = fixtures.fixture()
        report['critical_path']['status'] = 'INCOMPLETE'
        report['findings'].append({'kind': 'COLLECTION_GAP'})
        receipt, reads, _ = self.export(report)
        self.assertEqual(len(reads), 3)
        self.assertEqual(receipt['status'], 'EXPORTED_WITH_DECLARED_GAPS')

    def test_receipt_independently_binds_all_csv_artifacts(self):
        receipt, _, _ = self.export()
        self.assertEqual(set(receipt['artifacts']), {'reads.csv', 'files.csv', 'excluded-reads.csv', 'unassigned-reads.csv'})
        for name, binding in receipt['artifacts'].items():
            data = (self.output / name).read_bytes()
            self.assertEqual(binding, {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        self.assertEqual(json.loads((self.output / 'receipt.json').read_bytes()), receipt)

    def test_current_independent_replay_projection_exports_exact_read(self):
        import replay
        import test_replay as replay_fixtures
        report = replay.build_report(replay_fixtures.ReplayTests().basic(), replay_fixtures.manifest(), {})
        receipt, reads, files = self.export(report)
        self.assertEqual(receipt['status'], 'COMPLETE_FOR_SELECTED_REPORT_RECORDS')
        self.assertEqual(len(reads), 1)
        self.assertEqual(len(files), 1)
        self.assertEqual(reads[0]['actual_returned_bytes'], '16')
        self.assertEqual(reads[0]['requested_bytes'], '4096')
        self.assertEqual(reads[0]['duration_ns'], '68')
        self.assertEqual(reads[0]['signed_result'], '16')
        self.assertEqual(files[0]['elapsed_sum_ns'], '68')
        self.assertEqual(receipt['tools'][0]['begin_ns'], 10)
        self.assertEqual(receipt['tools'][0]['end_ns'], 1000)
        self.assertEqual(receipt['counts']['UNRESOLVED_READ_INTERVAL'], 0)

    def test_tool_window_outside_run_is_rejected_before_creating_directory(self):
        report = fixtures.fixture()
        report['tools'][0]['end_ns'] = 9999
        with self.assertRaisesRegex(ValueError, 'within declared run'):
            export_reads.export_report(report, self.output)
        self.assertFalse(self.output.exists())

    def test_cli_is_readonly_fresh_and_binds_source_sha(self):
        source = self.root / 'report.json'
        data = json.dumps(fixtures.fixture()).encode()
        source.write_bytes(data)
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(export_reads.main(['--report', str(source), '--output', str(self.output)]), 0)
        self.assertEqual(source.read_bytes(), data)
        receipt = json.loads((self.output / 'receipt.json').read_bytes())
        self.assertEqual(receipt['source_report']['sha256'], hashlib.sha256(data).hexdigest())
        before = (self.output / 'reads.csv').read_bytes()
        with self.assertRaisesRegex(ValueError, 'fresh'):
            export_reads.main(['--report', str(source), '--output', str(self.output)])
        self.assertEqual((self.output / 'reads.csv').read_bytes(), before)
        self.assertIn('并行累计读取时长不能当墙钟', stdout.getvalue())

    def test_input_and_output_symlinks_are_rejected(self):
        source = self.root / 'report.json'
        source.write_text(json.dumps(fixtures.fixture()))
        linked = self.root / 'input-link'
        linked.symlink_to(source)
        with self.assertRaisesRegex(ValueError, 'non-symlink'):
            export_reads.main(['--report', str(linked), '--output', str(self.output)])
        self.output.symlink_to(self.root / 'not-created')
        with self.assertRaisesRegex(ValueError, 'fresh'):
            export_reads.export_report(fixtures.fixture(), self.output)
        self.assertFalse((self.root / 'not-created').exists())

    def test_duplicate_json_nonfinite_and_bounded_inputs_are_rejected(self):
        source = self.root / 'report.json'
        for text in ('{"schema_version":1,"schema_version":1}', '{"value":NaN}'):
            source.write_text(text)
            with self.assertRaises(ValueError):
                export_reads.main(['--report', str(source), '--output', str(self.output)])
        source.write_text(json.dumps(fixtures.fixture()))
        with mock.patch.object(export_reads, 'MAX_BYTES', 10):
            with self.assertRaisesRegex(ValueError, 'bounded'):
                export_reads.main(['--report', str(source), '--output', str(self.output)])
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
