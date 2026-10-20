#!/usr/bin/env python3
"""Synthetic summaries: no VM, raw stream, SQLite or external service."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
import io

from summarize import completion, file_key, format_chinese, main, summarize_report, union_ns


GOOD = 'RECONSTRUCTED_WITHIN_SELECTED_MODEL'


def read_file(inode=10, start=250, end=350, returned=8, result=8, path='/src/a.c'):
    value = {'mount_id': 1, 'device': 0, 'inode': inode, 'generation': 0,
        'path_quality': 'KERNEL_D_PATH', 'read': {'start_ns': start, 'end_ns': end,
            'requested_bytes': 16, 'returned_bytes': returned, 'result': result}}
    if path is not None:
        value['path'] = path
    return value


def fixture(infra=False):
    first, eof, error = read_file(), read_file(start=450, end=550, returned=0, result=0, path='/src/hardlink.c'), read_file(
        inode=11, start=400, end=430, returned=0, result=-13, path='/src/b.c')
    root = {'key': 'root', 'tid': 10, 'tgid': 10, 'birth_ns': 1, 'process_birth_ns': 1,
        'parent_key': None, 'agent_id': 'A', 'tool_call_id': 'tool-A', 'comm': 'shell', 'calls': [],
        'begin_ns': 100, 'end_ns': 1000}
    child = {'key': 'child', 'tid': 20, 'tgid': 20, 'birth_ns': 200, 'process_birth_ns': 200,
        'parent_key': 'root', 'agent_id': 'A', 'tool_call_id': 'tool-A', 'comm': 'reader',
        'begin_ns': 200, 'end_ns': 1000,
        'calls': [{'call_id': 1, 'name': 'read', 'start_ns': 250, 'end_ns': 350, 'files': [first]},
                  {'call_id': 2, 'name': 'read', 'start_ns': 450, 'end_ns': 550, 'files': [eof]}]}
    sibling = {'key': 'sibling', 'tid': 21, 'tgid': 20, 'birth_ns': 220, 'process_birth_ns': 200,
        'parent_key': 'child', 'agent_id': 'A', 'tool_call_id': 'tool-A', 'comm': 'helper',
        'begin_ns': 220, 'end_ns': 1000,
        'calls': [{'call_id': 3, 'name': 'read', 'start_ns': 400, 'end_ns': 430, 'files': [error]}]}
    parts = []
    for begin, end, state, key, files in (
        (100, 200, 'ONCPU', 'root', []), (200, 210, 'NEWBORN', 'child', []),
        (210, 300, 'SLEEP', 'child', [first, copy.deepcopy(first)]),
        (300, 400, 'RUNNABLE', 'child', []), (400, 500, 'SLEEP', 'sibling', [error]),
        (500, 600, 'SLEEP', 'child', [eof]), (600, 1000, 'ONCPU', 'root', []),
        (1000, 1100, 'RUNTIME_RETURN', 'root', [])):
        parts.append({'begin_ns': begin, 'end_ns': end, 'state': state, 'thread_key': key,
            'files': copy.deepcopy(files), 'stack': ['frame-' + str(i) for i in range(8)],
            'syscall': {'name': 'read', 'result': 8}, 'reason': '栈只提供原因候选',
            'evidence': {'quality': 'RECORDED_TRANSITIONS', 'sources': ['SCHEDULER_EVENT_STREAM']}})
    totals = {}
    for part in parts:
        totals[part['state']] = totals.get(part['state'], 0) + part['end_ns'] - part['begin_ns']
    report = {'schema_version': 1, 'run': {'run_id': 'r', 'boot_id': 'b', 'begin_ns': 0, 'end_ns': 5000},
        'tools': [{'agent_id': 'A', 'task_id': 'task-A', 'tool_call_id': 'tool-A', 'root_key': 'root',
            'root': {'tid': 10, 'birth_ns': 1}, 'begin_ns': 100, 'end_ns': 1100}],
        'threads': [root, child, sibling],
        'critical_path': {'status': GOOD, 'tools': [{'tool_call_id': 'tool-A', 'status': GOOD,
            'wall_ns': 1000, 'unknown_ns': 0, 'state_totals_ns': totals, 'segments': parts}]},
        'health': {'status': 'COMPLETE'}, 'findings': []}
    # Copies in state annotations must never cause a read to be counted again.
    child['segments'] = copy.deepcopy(parts)
    if infra:
        extra = copy.deepcopy(root)
        extra.update(key='infra', tid=99, tgid=99, birth_ns=2, process_birth_ns=2,
            tool_call_id=None, agent_id=None, calls=[{'name': 'read', 'start_ns': 250, 'end_ns': 350,
                'files': [read_file(inode=999, returned=16, result=16)]}])
        report['threads'].append(extra)
    return report


class SummaryTests(unittest.TestCase):
    def test_reads_are_counted_from_calls_only_not_state_copies(self):
        report = fixture()
        before = copy.deepcopy(report)
        summary = summarize_report(report)
        self.assertEqual(report, before)
        tool = summary['tools'][0]
        self.assertEqual(tool['summary_status'], 'OBSERVED_WITH_DECLARED_LIMITS')
        reads = tool['reads']
        self.assertEqual((reads['read_calls'], reads['selected_read_syscalls']), (3, 3))
        self.assertEqual(reads['returned_bytes'], 8)
        self.assertEqual((reads['positive_reads'], reads['zero_reads'], reads['error_reads']), (1, 1, 1))
        self.assertEqual(reads['selected_vfs_object_count'], 2)
        self.assertEqual(reads['read_elapsed_sum_ns'], 230)
        self.assertAlmostEqual(reads['read_elapsed_mean_ns'], 230 / 3)
        self.assertEqual(reads['read_elapsed_max_ns'], 100)

    def test_process_identity_and_thread_counts_are_stable_instances(self):
        owned = summarize_report(fixture())['tools'][0]['owned']
        self.assertEqual(owned['thread_count'], 3)
        self.assertEqual(owned['process_count_known'], 2)
        self.assertEqual(owned['unresolved_process_identity_threads'], 0)

    def test_valid_zero_device_and_generation_are_not_unresolved(self):
        self.assertEqual(file_key(read_file()), (1, 0, 10, 0))
        self.assertIsNone(file_key({'mount_id': 0, 'device': 1, 'inode': 1, 'generation': 1}))

    def test_file_sleep_is_intersection_union_not_repeated_annotation_sum(self):
        tool = summarize_report(fixture())['tools'][0]
        self.assertEqual(tool['on_path_file_sleep_union_ns'], 130)
        self.assertEqual(tool['on_path_file_annotated_sleep_union_ns'], 290)
        self.assertEqual(union_ns([(1, 10), (1, 10), (5, 20), (21, 23)]), 21)

    def test_runtime_return_and_newborn_are_separate_not_cpu_or_sleep(self):
        path = summarize_report(fixture())['tools'][0]['completion_path']
        self.assertEqual(path['runtime_return_ns'], 100)
        self.assertEqual(path['newborn_ns'], 10)
        self.assertEqual(path['state_totals_ns']['ONCPU'], 500)
        self.assertEqual(sum(path['state_totals_ns'].values()), 1000)

    def test_recorded_invocation_discloses_dispatch_without_changing_completion_wall(self):
        report = fixture()
        report['tools'][0]['invocation_ns'] = 40
        before = copy.deepcopy(report)
        result = summarize_report(report)
        tool = result['tools'][0]
        self.assertEqual(report, before)
        self.assertEqual(tool['invocation_status'], 'RECORDED')
        self.assertEqual(tool['tool_call_wall_ns'], 1060)
        self.assertEqual(tool['execution_window_ns'], 1000)
        self.assertEqual(tool['wall_ns'], 1000)
        self.assertEqual(tool['dispatch_prelude_ns'], 60)
        self.assertEqual(sum(tool['completion_path']['state_totals_ns'].values()), 1000)
        self.assertEqual(result['tool_span_envelope']['wall_ns'], 1000)
        text = format_chinese(result)
        self.assertIn('完整工具调用墙钟：1.060 微秒', text)
        self.assertIn('派发／启动／登记前奏：60 ns', text)

    def test_invocation_absent_is_not_guessed_as_begin(self):
        tool = summarize_report(fixture())['tools'][0]
        self.assertEqual(tool['invocation_status'], 'NOT_RECORDED')
        self.assertIsNone(tool['tool_call_wall_ns'])
        self.assertIsNone(tool['dispatch_prelude_ns'])
        self.assertEqual(tool['execution_window_ns'], 1000)
        self.assertEqual(tool['summary_status'], 'OBSERVED_WITH_DECLARED_LIMITS')
        self.assertIn('invocation=NOT_RECORDED', format_chinese(summarize_report(fixture())))

    def test_invalid_invocation_never_becomes_negative_dispatch_or_fake_zero(self):
        for value in (-1, 101, True, '40'):
            report = fixture()
            report['tools'][0]['invocation_ns'] = value
            tool = summarize_report(report)['tools'][0]
            self.assertEqual(tool['invocation_status'], 'INVALID_INVOCATION_BOUNDARY')
            self.assertIsNone(tool['tool_call_wall_ns'])
            self.assertIsNone(tool['dispatch_prelude_ns'])
            self.assertEqual(tool['wall_ns'], 1000)
            self.assertEqual(tool['summary_status'], 'INCOMPLETE')

    def test_zero_dispatch_prelude_is_recorded_not_missing(self):
        report = fixture()
        report['tools'][0]['invocation_ns'] = report['tools'][0]['begin_ns']
        tool = summarize_report(report)['tools'][0]
        self.assertEqual(tool['invocation_status'], 'RECORDED')
        self.assertEqual(tool['dispatch_prelude_ns'], 0)
        self.assertEqual(tool['tool_call_wall_ns'], tool['execution_window_ns'])

    def test_waking_has_its_own_bucket(self):
        report = fixture()
        entry = report['critical_path']['tools'][0]
        entry['segments'][3]['state'] = 'WAKING'
        entry['state_totals_ns']['WAKING'] = entry['state_totals_ns'].pop('RUNNABLE')
        path = summarize_report(report)['tools'][0]['completion_path']
        self.assertEqual(path['waking_ns'], 100)
        self.assertEqual(path['state_totals_ns']['RUNNABLE'], 0)

    def test_unassigned_infrastructure_is_not_allocated_to_agent(self):
        result = summarize_report(fixture(infra=True))
        self.assertEqual(result['tools'][0]['owned']['thread_count'], 3)
        self.assertEqual(result['tools'][0]['reads']['read_calls'], 3)
        self.assertEqual(result['unassigned_threads']['keys'], ['infra'])
        self.assertEqual(result['summary_status'], 'INCOMPLETE')

    def test_selected_tool_completeness_is_separate_from_unassigned_capture_events(self):
        report = fixture(infra=True)
        finding = {'kind': 'THREAD_NOT_BOUND_TO_TOOL', 'thread': 'infra'}
        report['findings'].append(finding)
        result = summarize_report(report)
        self.assertEqual(result['selected_tool_timeline_status'], 'COMPLETE_WITHIN_SELECTED_TOOL_SCOPE')
        self.assertEqual(result['tools'][0]['selected_tool_timeline_status'], 'COMPLETE_WITHIN_SELECTED_TOOL_SCOPE')
        self.assertEqual(result['whole_capture_attribution_status'], 'UNASSIGNED_EVENTS_PRESENT')
        self.assertEqual(result['summary_status'], 'INCOMPLETE', 'legacy whole capture must not be made green')
        self.assertEqual(result['unassigned_threads']['count'], 1)
        self.assertEqual(result['unassigned_threads']['keys'], ['infra'])
        self.assertEqual(result['unassigned_threads']['details'][0]['tid'], 99)
        self.assertIsNone(result['unassigned_threads']['details'][0]['agent_id'])
        self.assertEqual(result['unassigned_threads']['report_findings'], [finding])
        self.assertEqual(result['tools'][0]['reads']['read_calls'], 3)
        text = format_chinese(result)
        self.assertIn('选定工具时间线：COMPLETE_WITHIN_SELECTED_TOOL_SCOPE', text)
        self.assertIn('整个采集范围归因：UNASSIGNED_EVENTS_PRESENT', text)
        self.assertIn('选定工具完整不代表整个cgroup的活动均已归属', text)

    def test_split_status_never_hides_a_selected_tools_real_resolution_gap(self):
        report = fixture(infra=True)
        report['threads'][1]['calls'][0]['files'][0].pop('path')
        result = summarize_report(report)
        self.assertEqual(result['selected_tool_timeline_status'], 'INCOMPLETE')
        self.assertEqual(result['tools'][0]['selected_tool_timeline_status'], 'INCOMPLETE')
        self.assertEqual(result['whole_capture_attribution_status'], 'UNASSIGNED_EVENTS_PRESENT')
        self.assertIn('UNRESOLVED_SELECTED_READ_FIELDS', result['tools'][0]['issues'])

    def test_global_collection_gap_still_invalidates_selected_tool_status(self):
        report = fixture(infra=True)
        report['health']['status'] = 'PARTIAL'
        result = summarize_report(report)
        self.assertEqual(result['selected_tool_timeline_status'], 'INCOMPLETE')
        self.assertEqual(result['tools'][0]['selected_tool_timeline_status'], 'INCOMPLETE')
        self.assertEqual(result['whole_capture_attribution_status'], 'UNASSIGNED_EVENTS_PRESENT')
        self.assertIn('TERMINAL_HEALTH_NOT_COMPLETE', result['global_issues'])

    def test_all_reported_threads_assigned_is_bounded_not_whole_kernel_completeness(self):
        result = summarize_report(fixture())
        self.assertEqual(result['selected_tool_timeline_status'], 'COMPLETE_WITHIN_SELECTED_TOOL_SCOPE')
        self.assertEqual(result['whole_capture_attribution_status'], 'ALL_REPORTED_THREADS_ASSOCIATED_WITH_SELECTED_TOOLS')
        self.assertIn('NOT_PROOF_OF_ALL_CGROUP_ACTIVITY', result['whole_capture_attribution_scope'])
        self.assertEqual(result['unassigned_threads']['details'], [])

    def test_unknown_task_identity_cannot_make_whole_capture_attribution_complete(self):
        report = fixture()
        report['findings'].append({'kind': 'UNRESOLVED_TASK_IDENTITY', 'event': 'SWITCH_IN'})
        result = summarize_report(report)
        self.assertEqual(result['whole_capture_attribution_status'], 'UNRESOLVED_ATTRIBUTION_EVIDENCE')
        self.assertEqual(result['selected_tool_timeline_status'], 'INCOMPLETE')
        self.assertEqual(len(result['whole_capture_attribution_findings']), 1)

    def test_nonleader_exec_transition_is_not_complete_attribution(self):
        report = fixture()
        report['findings'].append({'kind': 'IDENTITY_TRANSITION_UNRESOLVED', 'thread': 'child'})
        result = summarize_report(report)
        self.assertEqual(result['whole_capture_attribution_status'], 'UNRESOLVED_ATTRIBUTION_EVIDENCE')
        self.assertEqual(result['selected_tool_timeline_status'], 'INCOMPLETE')

    def test_same_tag_without_root_ancestry_is_not_an_agent_thread(self):
        report = fixture(infra=True)
        report['threads'][-1].update(agent_id='A', tool_call_id='tool-A')
        result = summarize_report(report)['tools'][0]
        self.assertEqual(result['owned']['thread_count'], 3)
        self.assertEqual(result['owned']['tagged_unverified_threads'], ['infra'])
        self.assertEqual(result['summary_status'], 'INCOMPLETE')

    def test_wrong_agent_or_root_is_not_joined_by_pid_or_time(self):
        for change in ({'agent_id': 'wrong'}, {'root_key': 'missing'}):
            report = fixture()
            report['tools'][0].update(change)
            result = summarize_report(report)['tools'][0]
            self.assertEqual(result['owned']['thread_count'], 0)
            self.assertEqual(result['summary_status'], 'INCOMPLETE')

    def test_backward_compatibility_uses_only_exact_declared_birth(self):
        report = fixture()
        report['tools'][0].pop('root_key')
        self.assertEqual(summarize_report(report)['tools'][0]['owned']['thread_count'], 3)
        report['tools'][0]['root'].pop('birth_ns')
        self.assertEqual(summarize_report(report)['tools'][0]['owned']['thread_count'], 0)

    def test_missing_path_shows_identity_without_inventing_name(self):
        report = fixture()
        report['threads'][1]['calls'][0]['files'][0].pop('path')
        for part in report['critical_path']['tools'][0]['segments']:
            for file in part['files']:
                file.pop('path', None)
        tool = summarize_report(report)['tools'][0]
        self.assertEqual(tool['summary_status'], 'INCOMPLETE')
        shown = [file for wait in tool['longest_waits'] for file in wait['files']]
        self.assertTrue(shown)
        self.assertTrue(all(file['path'] is None and file['display'].startswith('identity=') for file in shown))

    def test_unknown_object_is_not_included_as_a_unique_file(self):
        report = fixture()
        report['threads'][1]['calls'][0]['files'][0]['inode'] = 0
        tool = summarize_report(report)['tools'][0]
        self.assertEqual(tool['reads']['unresolved_object_read_records'], 1)
        self.assertEqual(tool['summary_status'], 'INCOMPLETE')

    def test_unknown_returned_bytes_are_not_successful_zeroes(self):
        report = fixture()
        report['threads'][1]['calls'][0]['files'][0]['read']['returned_bytes'] = None
        reads = summarize_report(report)['tools'][0]['reads']
        self.assertIsNone(reads['returned_bytes'])
        self.assertEqual(reads['unknown_or_inconsistent_returned_bytes'], 1)

    def test_native_negative_return_null_bytes_is_error_not_unknown_or_eof(self):
        report = fixture()
        report['threads'][2]['calls'][0]['files'][0]['read']['returned_bytes'] = None
        tool = summarize_report(report)['tools'][0]
        self.assertEqual(tool['reads']['returned_bytes'], 8)
        self.assertEqual(tool['reads']['error_reads'], 1)
        self.assertEqual(tool['reads']['zero_reads'], 1)
        self.assertEqual(tool['reads']['failed_reads_with_no_positive_return'], 1)
        self.assertEqual(tool['reads']['unknown_or_inconsistent_returned_bytes'], 0)
        self.assertEqual(tool['summary_status'], 'OBSERVED_WITH_DECLARED_LIMITS')

    def test_path_text_does_not_hide_unresolved_resolution_quality(self):
        for quality in ('UNRESOLVED', 'AMBIGUOUS_PATH_OBSERVATIONS', 'FAILED_OR_TRUNCATED', None):
            report = fixture()
            report['threads'][1]['calls'][0]['files'][0]['path_quality'] = quality
            tool = summarize_report(report)['tools'][0]
            self.assertEqual(tool['reads']['unresolved_path_quality_records'], 1)
            self.assertEqual(tool['summary_status'], 'INCOMPLETE')

    def test_current_native_candidate_path_qualities_remain_declared_candidates(self):
        for quality in ('KERNEL_PATH_AT_LSM_PERMISSION_CANDIDATE', 'KERNEL_PATH_AT_PERMISSION_CANDIDATE'):
            report = fixture()
            report['threads'][1]['calls'][0]['files'][0]['path_quality'] = quality
            self.assertEqual(summarize_report(report)['tools'][0]['reads']['unresolved_path_quality_records'], 0)

    def test_missing_time_and_crossing_scope_are_disclosed(self):
        report = fixture()
        report['threads'][1]['calls'][0]['files'][0]['read']['start_ns'] = None
        tool = summarize_report(report)['tools'][0]
        self.assertIsNone(tool['reads']['read_elapsed_sum_ns'])
        self.assertEqual(tool['reads']['unresolved_read_intervals'], 1)
        self.assertEqual(tool['summary_status'], 'INCOMPLETE')
        report = fixture()
        report['threads'][1]['calls'][0]['files'][0]['read']['start_ns'] = 50
        tool = summarize_report(report)['tools'][0]
        self.assertEqual(tool['reads']['crossing_tool_span_read_records'], 1)
        self.assertEqual(tool['reads']['read_calls'], 2)

    def test_malformed_completion_partition_does_not_silently_turn_green(self):
        report = fixture()
        report['critical_path']['tools'][0]['segments'][1]['begin_ns'] = 190
        tool = summarize_report(report)['tools'][0]
        self.assertEqual(tool['summary_status'], 'INCOMPLETE')
        self.assertIsNone(tool['completion_path']['state_totals_ns'])
        self.assertIsNone(tool['on_path_file_sleep_union_ns'])

    def test_wrong_declared_totals_are_independently_detected(self):
        report = fixture()
        report['critical_path']['tools'][0]['state_totals_ns']['ONCPU'] += 1
        self.assertEqual(summarize_report(report)['tools'][0]['completion_path']['integrity_status'], 'INCOMPLETE')

    def test_unowned_critical_path_cannot_be_attributed_to_agent(self):
        report = fixture(infra=True)
        report['critical_path']['tools'][0]['segments'][0]['thread_key'] = 'infra'
        tool = summarize_report(report)['tools'][0]
        self.assertIn('COMPLETION_SEGMENT_THREAD_NOT_OWNED', tool['issues'])
        self.assertIsNone(tool['completion_path']['state_totals_ns'])

    def test_unknown_state_keeps_unknown_coverage(self):
        report = fixture()
        entry = report['critical_path']['tools'][0]
        entry['segments'][0]['state'] = 'UNKNOWN'
        entry['state_totals_ns']['ONCPU'] -= 100
        entry['state_totals_ns']['UNKNOWN'] = 100
        entry['status'] = 'INCOMPLETE'
        tool = summarize_report(report)['tools'][0]
        self.assertEqual(tool['completion_path']['unknown_ns'], 100)
        self.assertEqual(tool['summary_status'], 'INCOMPLETE')

    def test_waits_are_limited_to_ten_and_stack_to_six(self):
        tool = summarize_report(fixture())['tools'][0]
        self.assertLessEqual(len(tool['longest_waits']), 10)
        self.assertTrue(all(len(wait['stack_first6']) == 6 and wait['stack_frame_count'] == 8 for wait in tool['longest_waits']))
        self.assertTrue(all(wait['state'] != 'RUNTIME_RETURN' for wait in tool['longest_waits']))

    def test_envelope_is_not_sum_of_tools_or_full_manifest_run(self):
        report = fixture()
        other = copy.deepcopy(report['tools'][0])
        other.update(tool_call_id='tool-B', agent_id='B', begin_ns=200, end_ns=2100, root_key='missing')
        report['tools'].append(other)
        result = summarize_report(report)
        self.assertEqual(result['tool_span_envelope']['wall_ns'], 2000)
        self.assertNotEqual(result['tool_span_envelope']['wall_ns'], sum(tool['wall_ns'] for tool in result['tools']))
        self.assertNotEqual(result['tool_span_envelope']['wall_ns'], 5000)

    def test_missing_process_birth_keeps_process_count_partial(self):
        report = fixture()
        report['threads'][1]['process_birth_ns'] = None
        tool = summarize_report(report)['tools'][0]
        self.assertEqual(tool['owned']['unresolved_process_identity_threads'], 1)
        self.assertEqual(tool['summary_status'], 'INCOMPLETE')

    def test_global_unresolved_status_is_not_green(self):
        report = fixture()
        report['critical_path']['status'] = 'INCOMPLETE'
        self.assertEqual(summarize_report(report)['summary_status'], 'INCOMPLETE')

    def test_no_tools_means_unknown_envelope_not_zero_success(self):
        result = summarize_report({'schema_version': 1, 'tools': [], 'threads': [], 'critical_path': {}})
        self.assertIsNone(result['tool_span_envelope']['wall_ns'])
        self.assertEqual(result['summary_status'], 'INCOMPLETE')
        self.assertEqual(result['selected_tool_timeline_status'], 'NO_SELECTED_TOOLS')
        self.assertEqual(result['whole_capture_attribution_status'], 'NO_REPORTED_THREADS')

    def test_chinese_output_has_units_and_scope_not_fake_paths(self):
        text = format_chinese(summarize_report(fixture()))
        self.assertIn('TOOL_SPAN_ENVELOPE', text)
        self.assertIn('RUNTIME_RETURN单列', text)
        self.assertIn('不是整个manifest运行时长', text)
        self.assertIn('并行累计，不能当墙钟', text)
        self.assertIn('原因候选', text)
        self.assertIn('ns', text)

    def test_current_replay_projection_interoperates_without_schema_guessing(self):
        import replay
        import test_replay as replay_fixtures
        report = replay.build_report(replay_fixtures.ReplayTests().basic(), replay_fixtures.manifest(), {})
        tool = summarize_report(report)['tools'][0]
        self.assertEqual(tool['wall_ns'], 990)
        self.assertEqual(tool['owned']['thread_count'], 1)
        self.assertEqual(tool['owned']['process_count_known'], 1)
        self.assertEqual(tool['reads']['read_calls'], 1)
        self.assertEqual(tool['reads']['returned_bytes'], 16)
        self.assertEqual(tool['reads']['read_elapsed_sum_ns'], 68)
        self.assertEqual(tool['on_path_file_sleep_union_ns'], 40)
        self.assertEqual(tool['summary_status'], 'OBSERVED_WITH_DECLARED_LIMITS')

    def test_cli_is_fresh_readonly_and_binds_source_sha(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'report.json', root / 'summary.json'
            raw = json.dumps(fixture()).encode()
            source.write_bytes(raw)
            captured = io.StringIO()
            with redirect_stdout(captured):
                self.assertEqual(main(['--report', str(source), '--output', str(output)]), 0)
            result = json.loads(output.read_bytes())
            self.assertEqual(result['source_report']['sha256'], hashlib.sha256(raw).hexdigest())
            before = output.read_bytes()
            with self.assertRaisesRegex(ValueError, 'fresh'):
                main(['--report', str(source), '--output', str(output)])
            self.assertEqual(source.read_bytes(), raw)
            self.assertEqual(output.read_bytes(), before)
            self.assertIn('执行时间线摘要', captured.getvalue())


if __name__ == '__main__':
    unittest.main()
