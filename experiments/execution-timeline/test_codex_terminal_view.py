import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import codex_terminal_view as view
from tool_events import replay_tool_events


class ViewTests(unittest.TestCase):
    def boundaries(self, root, a, b):
        for phase, files in (('before', a), ('after', b)):
            (root/f'resources-{phase}.json').write_text(json.dumps({'cgroup_id': 20,
                'cgroup_root': '/sys/fs/cgroup/owned', 'files': files}))

    def test_delta_never_interprets_missing_or_reset_counter_as_zero(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.boundaries(root, {'cpu.stat': 'user_usec 10\nsystem_usec 8\n',
                'memory.stat': 'pgfault 100\n'}, {'cpu.stat': 'user_usec 30\nsystem_usec 2\n',
                'memory.stat': 'pgfault 110\npgmajfault 4\n'})
            value = view.resource_delta(root)
            self.assertEqual(value['cpu.stat:user_usec'], 20)
            self.assertIsNone(value['cpu.stat:system_usec'])
            self.assertEqual(value['memory.stat:pgfault'], 10)
            self.assertIsNone(value['memory.stat:pgmajfault'])
            self.assertIsNone(value['io.pressure:some.total'])

    def test_rejects_identity_change(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.boundaries(root, {}, {})
            row = view.read(root/'resources-after.json')
            row['cgroup_id'] = 21
            (root/'resources-after.json').write_text(json.dumps(row))
            with self.assertRaisesRegex(ValueError, 'identity'):
                view.resource_delta(root)

    def test_psi_total_only_no_avg_as_additive_wall(self):
        self.assertEqual(view.counters({'files': {'cpu.pressure':
            'some avg10=2.0 avg60=0.1 avg300=0.2 total=125\nfull avg10=0 total=10\n'}},
            'cpu.pressure'), {'some.total': 125, 'full.total': 10})

    def test_plain_task_page_escapes_commands_and_shows_concrete_calls(self):
        job = {'task_id': 'terminal-bench/html-js-filter', 'job_id': 'terminal-01',
            'official_passed': False, 'official_evaluated': True, 'agent_status': 'failed', 'prompt': 'task <unsafe>',
            'wall_seconds': 2.0, 'native_page': '/tmp/native/timeline-readable.html',
            'health': 'COMPLETE_FOR_SELECTED_HOOKS', 'final_answers': [],
            'steps': [{'tool_call_id': 't1', 'exit_code': 0, 'wall_seconds': .1,
                'command': '<script>alert(1)</script>', 'stdout': 'actual output',
                'root': {'tid': 12}, 'observed_syscall_counts': {'openat': 2, 'write': 1},
                'kernel': None}]}
        page = view.task_page(job, Path('/tmp/output'))
        self.assertNotIn('<script>alert', page)
        self.assertIn('&lt;script&gt;', page)
        self.assertIn('openat × 2', page)
        self.assertIn('write × 1', page)
        self.assertIn('tool=t1', page)
        self.assertIn('未通过', page)
        self.assertIn('本轮没有收到正常的最终回答', page)

    def test_failure_explanation_is_plain_and_does_not_guess_429_billing_source(self):
        output = view.failure_summary({'status': 'failed', 'errors': [{'error': {'message': 'HTTP 429 Too Many Requests'}}]}, 'CODEX_FAILED')
        self.assertIn('接口或预算代理', output['explanation'])
        self.assertIn('不能仅凭 429', output['explanation'])
        output = view.failure_summary({'status': 'failed', 'errors': [{'error': {'message': 'Incomplete max_output_tokens'}}]}, 'CODEX_FAILED')
        self.assertIn('输出长度上限', output['explanation'])
        self.assertIn('不是完成任务的有效性能样本', output['explanation'])

    def test_missing_grading_is_not_displayed_as_official_failure(self):
        job = {'task_id': 'task', 'job_id': 'job', 'official_passed': False, 'official_evaluated': False,
            'agent_status': 'failed', 'prompt': 'task', 'wall_seconds': 1, 'health': 'INCOMPLETE',
            'steps': [], 'final_answers': []}
        page = view.task_page(job, Path('/tmp/output'))
        self.assertIn('尚未完成判题', page)
        self.assertNotIn('官方判题：未通过', page)

    def test_failed_batch_cannot_be_advertised_as_completed_equal_work(self):
        with tempfile.TemporaryDirectory() as temp:
            group = {'concurrency': 2, 'total_jobs': 8, 'codex_completed': 0, 'official_passed': 0,
                'batch_wall_seconds': 1, 'jobs': [], 'resource_counters': {},
                'read_metrics': {'selected_read_calls': 20, 'actual_returned_bytes': 300, 'observed_identity_count': 4}}
            page = view.render([group], Path(temp))
            self.assertIn('不可作为完成相同有效工作量的性能结论', page)
            self.assertIn('8次尝试全部停止', page)
            self.assertIn('不是整个批次全局不同文件数', page)
            self.assertIn('实际返回字节', page)
            self.assertNotIn('全部8次尝试完成', page)
            self.assertIn('已知接入问题：工作目录没有正确映射', page)
            self.assertIn('修正映射后需要重新评测', page)

    def fixture(self, root):
        (root/'app').mkdir()
        command = 'printf hello'
        gate = {'tool_call_id': 'tool-1', 'root': {'tid': 10}, 'cgroup_id': 20, 'command': command,
            'agent_id': 'agent', 'task_id': 'task',
            'begin_ns': 1, 'end_ns': 2, 'docker_exec_id': 'd'*64,
            'result': {'return_code': 0, 'stdout_bytes': 5, 'stderr_bytes': 0}}
        mapping = {'thread_id': 'thread', 'turn_id': 'turn', 'call_id': 'call', 'rpc_request_id': 0,
            'agent_id': 'agent', 'task_id': 'task', 'boot_id': 'boot',
            'tool': 'observer_bash', 'tool_call_id': 'tool-1', 'command': command, 'root': gate['root'],
            'root_pid': 10, 'cgroup_id': 20, 'begin_ns': 1, 'end_ns': 2,
            'gate_result': gate['result'], 'docker_exec_id': gate['docker_exec_id'],
            'stdout_artifact': 'app/stdout', 'stderr_artifact': 'app/stderr',
            'binding_basis': view.BINDING, 'gate_binding_basis': view.BINDING,
            'command_sha256': view.hashlib.sha256(command.encode()).hexdigest()}
        docker = dict(mapping)
        app = {'thread_id': 'thread', 'turn_id': 'turn', 'status': 'completed', 'function_bindings': [mapping],
            'steps': [{'kind': 'TOOL_CALL', **mapping, 'exit_code': 0, 'stdout': 'hello', 'stderr': '', 'output_truncated': False}]}
        settings = {'function_bindings': [docker]}
        (root/'app/stdout').write_text('hello'); (root/'app/stderr').write_text('')
        (root/'app/function-bindings.jsonl').write_text(json.dumps(mapping)+'\n')
        (root/'app/docker-function-bindings.jsonl').write_text(json.dumps(docker)+'\n')
        artifacts = {'app/'+path.name: view.digest(path) for path in (root/'app').iterdir()}
        manifest = {'tools': [gate], 'artifacts': artifacts, 'agent_id': 'agent', 'task_id': 'task', 'boot_id': 'boot',
            'codex_application': {'artifacts': dict(artifacts)}}
        return manifest, app, settings

    def test_exact_codex_to_docker_mapping_checks_and_keeps_zero_request_id(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); manifest, app, settings = self.fixture(root)
            gates, calls = view.validate_application(root, manifest, app, settings)
            self.assertEqual(calls[0]['rpc_request_id'], 0)
            self.assertEqual(set(gates), {'tool-1'})

    def test_v2_tool_lifecycle_is_verified_and_rendered_as_tool_not_syscall(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); manifest, app, settings = self.fixture(root)
            common = {'schema_version':1, 'clock':'CLOCK_MONOTONIC', 'agent_id':'agent',
                'task_id':'task', 'call_id':'call', 'tool_name':'observer_bash',
                'thread_id':'thread', 'turn_id':'turn', 'rpc_request_id':0}
            arguments = {'command':'printf hello'}
            arguments_digest = view.hashlib.sha256(json.dumps(arguments, sort_keys=True,
                ensure_ascii=False, separators=(',',':')).encode()).hexdigest()
            events = [
                {**common, 'sequence':1, 'event':'TOOL_REQUESTED', 'occurred_ns':0, 'recorded_ns':0,
                    'status':'REQUESTED', 'arguments':arguments, 'arguments_sha256':arguments_digest,
                    'arguments_capture':'FULL_BOUNDED_PUBLIC_COMMAND'},
                {**common, 'sequence':2, 'event':'TOOL_DISPATCHED', 'occurred_ns':0, 'recorded_ns':0,
                    'status':'RUNNING', 'execution_kind':'STOPPED_PROCESS_GATE'},
                {**common, 'sequence':3, 'event':'TOOL_COMPLETED', 'occurred_ns':3, 'recorded_ns':3,
                    'status':'SUCCEEDED', 'exit_code':0, 'output_truncated':False,
                    'semantic_result':'NOT_VERIFIED_BY_TOOL_TRANSPORT',
                    'execution_tool_call_id':'tool-1', 'execution_begin_ns':1, 'execution_end_ns':2,
                    'execution_duration_ns':1, 'timing_quality':'EXPLICIT_EXECUTION_BOUNDARIES',
                    'root':{'tid':10}, 'cgroup_id':20, 'stdout_artifact':'app/stdout',
                    'stderr_artifact':'app/stderr'},
                {**common, 'sequence':4, 'event':'TOOL_RESULT_DELIVERED', 'occurred_ns':4, 'recorded_ns':4,
                    'status':'SUCCEEDED', 'execution_tool_call_id':'tool-1'},
            ]
            path = root/'app/tool-events.jsonl'
            path.write_text(''.join(json.dumps(row)+'\n' for row in events))
            calls = replay_tool_events(events)
            app.update(schema_version=2, tool_event_schema='APPLICATION_TOOL_LIFECYCLE_V1', tool_calls=calls)
            app['steps'][0].update(tool_name='observer_bash', tool_status='SUCCEEDED', requested_ns=0,
                result_delivered_ns=4, semantic_result='NOT_VERIFIED_BY_TOOL_TRANSPORT',
                request_to_execution_ns=1, request_to_result_delivery_ns=4)
            identity = view.digest(path); manifest['artifacts']['app/tool-events.jsonl'] = identity
            manifest['codex_application']['artifacts']['app/tool-events.jsonl'] = identity
            view.validate_application(root, manifest, app, settings)
            job = {'task_id':'task', 'job_id':'job', 'official_passed':True, 'official_evaluated':True,
                'agent_status':'completed', 'prompt':'task', 'wall_seconds':1, 'native_page':'/tmp/native.html',
                'health':'COMPLETE_FOR_SELECTED_HOOKS', 'final_answers':['done'], 'steps':[{**app['steps'][0],
                    'wall_seconds':1e-9, 'observed_syscall_counts':{}, 'kernel':None}],
                'raw_replay_status':'REPLAY_PASSED', 'critical_path_status':'RECONSTRUCTED_WITHIN_SELECTED_MODEL'}
            page = view.task_page(job, root)
            self.assertIn('工具调用 1', page); self.assertIn('observer_bash', page)
            self.assertIn('请求到实际执行', page)
            self.assertIn('工具执行成功只表示接口／命令正常返回', page)

    def test_missing_application_artifact_membership_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); manifest, app, settings = self.fixture(root)
            del manifest['artifacts']['app/function-bindings.jsonl']
            with self.assertRaisesRegex(ValueError, 'missing or unbound'):
                view.validate_application(root, manifest, app, settings)

    def test_unbound_nested_application_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); manifest, app, settings = self.fixture(root)
            del manifest['codex_application']['artifacts']['app/stdout']
            with self.assertRaisesRegex(ValueError, 'artifact binding differs'):
                view.validate_application(root, manifest, app, settings)

    def test_gate_result_or_step_exit_mismatch_rejected(self):
        for mutation in ('result', 'exit'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); manifest, app, settings = self.fixture(root)
                if mutation == 'result': manifest['tools'][0]['result'] = {'return_code': 7}
                else: app['steps'][0]['exit_code'] = 7
                with self.assertRaisesRegex(ValueError, 'result|exit'):
                    view.validate_application(root, manifest, app, settings)

    def test_function_call_id_or_rpc_different_from_journal_is_rejected(self):
        for key in ('call_id', 'rpc_request_id'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); manifest, app, settings = self.fixture(root)
                app['function_bindings'][0][key] = 'other'
                with self.assertRaisesRegex(ValueError, 'ledger differs'):
                    view.validate_application(root, manifest, app, settings)

    def test_changed_display_output_or_agent_is_rejected(self):
        for mutation in ('stdout', 'agent'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); manifest, app, settings = self.fixture(root)
                if mutation == 'stdout': app['steps'][0]['stdout'] = 'invented output'
                else: manifest['tools'][0]['agent_id'] = 'other-agent'
                with self.assertRaisesRegex(ValueError, 'output differs|identity differs'):
                    view.validate_application(root, manifest, app, settings)

    def test_zero_tool_failure_needs_no_fabricated_function_ledger(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            gates, calls = view.validate_application(root, {'tools': [], 'artifacts': {}},
                {'steps': [], 'function_bindings': []}, {'function_bindings': []})
            self.assertEqual((gates, calls), ({}, []))

    def test_explicit_partial_receipt_is_accepted_without_turning_green(self):
        receipt = {'status': 'EXPORTED_WITH_DECLARED_GAPS', 'run_id': 'run', 'boot_id': 'boot',
            'issues': [{'kind': 'SOURCE_TIMELINE_COVERAGE_NOT_RECONSTRUCTED'}],
            'counts': {'unknown_bytes_records': 2, 'UNRESOLVED_READ_INTERVAL': 1},
            'read_partition_status': 'ALL_REPORT_READ_RECORDS_EXPORTED_ONCE'}
        quality = view.receipt_quality(receipt, {'run_id': 'run', 'boot_id': 'boot'})
        self.assertEqual(quality['export_status'], 'EXPORTED_WITH_DECLARED_GAPS')
        self.assertEqual(quality['unknown_bytes_records'], 2)
        self.assertEqual(quality['unresolved_read_intervals'], 1)
        self.assertEqual(quality['export_issues'], receipt['issues'])
        self.assertIn('DECLARED_GAPS_RETAINED', quality['scope'])

    def test_receipt_unknown_status_identity_change_or_false_complete_rejected(self):
        base = {'status': 'COMPLETE_FOR_SELECTED_REPORT_RECORDS', 'run_id': 'run', 'boot_id': 'boot', 'issues': []}
        for changes in ({'status': 'MADE_UP_GREEN'}, {'run_id': 'other'}, {'boot_id': 'other'},
                        {'issues': [{'kind': 'ACTUAL_GAP'}]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                view.receipt_quality({**base, **changes}, {'run_id': 'run', 'boot_id': 'boot'})

    def test_partial_quality_and_unknown_bytes_are_plain_and_not_promoted(self):
        job = {'task_id': 'task', 'job_id': 'job', 'official_passed': False, 'official_evaluated': True,
            'agent_status': 'failed', 'prompt': 'task', 'wall_seconds': 1, 'health': 'COMPLETE_FOR_SELECTED_HOOKS',
            'raw_replay_status': 'REPLAY_PASSED', 'critical_path_status': 'INCOMPLETE',
            'steps': [], 'final_answers': [], 'read_metrics': {'selected_read_calls': 3,
                'actual_returned_bytes': None, 'actual_returned_bytes_known_sum': 15, 'observed_identity_count': 2,
                'export_status': 'EXPORTED_WITH_DECLARED_GAPS', 'export_issues': [{'kind': 'KNOWN_GAP'}],
                'reads_csv': '/tmp/reads.csv', 'files_csv': '/tmp/files.csv'}}
        page = view.task_page(job, Path('/tmp/output'))
        self.assertIn('原始证据：重放通过', page)
        self.assertIn('选定记录传输：未检测到丢失', page)
        self.assertIn('等待路径：尚未完整重建', page)
        self.assertIn('读取导出：存在声明缺口', page)
        self.assertIn('总字节数未完整确认', page)
        self.assertIn('已知部分的返回字节之和：15', page)
        self.assertNotIn('返回 15 字节', page)
        self.assertIn('KNOWN_GAP', page)

    def test_official_timeout_is_unscored_not_failed_grade(self):
        job = {'task_id': 'task', 'job_id': 'job', 'official_passed': None, 'official_evaluated': False,
            'grading_status': 'OFFICIAL_VERIFIER_TIMEOUT_NOT_SCORED', 'agent_status': 'failed',
            'prompt': 'task', 'wall_seconds': 1, 'health': 'COMPLETE_FOR_SELECTED_HOOKS',
            'steps': [], 'final_answers': []}
        page = view.task_page(job, Path('/tmp/output'))
        self.assertIn('官方判题：判题超时，未计分（不是 0 分）', page)
        self.assertIn('原始 1800 秒上限', page)
        self.assertNotIn('官方判题：未通过', page)

    def test_timeout_group_preserves_aborted_and_uses_seven_graded_denominator(self):
        with tempfile.TemporaryDirectory() as temp:
            group = {'concurrency': 4, 'total_jobs': 8, 'codex_completed': 0, 'official_passed': 0,
                'official_evaluated': 7, 'official_verifier_timeouts': 1,
                'original_campaign_status': 'ABORTED', 'post_timing_exception_admission': {'status': 'BOUND_TEST'},
                'batch_wall_seconds': 2, 'jobs': [], 'resource_counters': {}, 'read_metrics': {}}
            page = view.render([group], Path(temp))
            self.assertIn('0/7 已判题；1 超时未计分', page)
            self.assertIn('ABORTED', page)
            self.assertIn('原样保留，未改成成功', page)
            self.assertNotIn('0/8 已判题', page)

    def test_flat_metrics_keep_seconds_counts_and_overlap_totals_distinct(self):
        jobs = [{'steps': [1], 'command_wall_seconds_sum': .2, 'wall_seconds': 2.0},
                {'steps': [1, 2], 'command_wall_seconds_sum': .5, 'wall_seconds': 3.0}]
        metrics = view.flat_group_metrics(jobs, {'cpu.stat:user_usec': 1000000, 'cpu.stat:system_usec': 250000,
            'memory.stat:pgfault': 40, 'memory.stat:pgmajfault': 0, 'cpu.pressure:some.total': 1200,
            'memory.pressure:some.total': 0, 'io.pressure:some.total': 2500000})
        self.assertEqual(metrics['cpu_user_seconds'], 1.0)
        self.assertEqual(metrics['cpu_system_seconds'], .25)
        self.assertEqual(metrics['pgfault'], 40); self.assertEqual(metrics['pgmajfault'], 0)
        self.assertEqual(metrics['cpu_psi_some_seconds'], .0012)
        self.assertEqual(metrics['memory_psi_some_seconds'], 0)
        self.assertEqual(metrics['io_psi_some_seconds'], 2.5)
        self.assertEqual(metrics['actual_command_count'], 3)
        self.assertAlmostEqual(metrics['sum_command_wall_seconds'], .7)
        self.assertEqual(metrics['sum_attempt_wall_seconds'], 5.0)
        self.assertNotIn('batch_wall_seconds', metrics)

    def test_flat_metrics_missing_invalid_or_nonfinite_stay_null(self):
        self.assertTrue(all(value is None for value in view.flat_group_metrics([], {}).values()))
        invalid = view.flat_group_metrics([{'steps': [], 'wall_seconds': float('nan'),
            'command_wall_seconds_sum': None}], {'cpu.stat:user_usec': -1, 'cpu.pressure:some.total': True})
        self.assertIsNone(invalid['sum_attempt_wall_seconds'])
        self.assertIsNone(invalid['sum_command_wall_seconds'])
        self.assertIsNone(invalid['cpu_user_seconds'])
        self.assertIsNone(invalid['cpu_psi_some_seconds'])
        self.assertEqual(invalid['actual_command_count'], 0)

    def test_complete_csv_has_numeric_resource_columns_and_null_is_blank(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'comparison.csv'
            view.write_comparison_csv(path, [{'concurrency': 2, 'batch_wall_seconds': 3.0,
                **view.flat_group_metrics([{'steps': [], 'wall_seconds': 4, 'command_wall_seconds_sum': 0}],
                    {'cpu.stat:user_usec': 500000, 'memory.stat:pgfault': 7})}])
            with path.open(newline='') as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row['cpu_user_seconds'], '0.5')
            self.assertEqual(row['cpu_system_seconds'], '')
            self.assertEqual(row['pgfault'], '7'); self.assertEqual(row['pgmajfault'], '')
            self.assertEqual(row['actual_command_count'], '0')
            self.assertEqual(row['sum_attempt_wall_seconds'], '4')
            self.assertEqual(row['sum_command_wall_seconds'], '0')
            self.assertIn('io_psi_some_seconds', row)

    def test_command_windows_are_bounded_sequential_and_complement_is_exact(self):
        timing = view.command_timing([{'tool_call_id': 't1', 'begin_ns': 200, 'end_ns': 201},
            {'tool_call_id': 't2', 'begin_ns': 500, 'end_ns': 700}], 100, 1000)
        self.assertEqual(timing['attempt_wall_ns'], 900)
        self.assertEqual(timing['sum_command_window_ns'], 201)
        self.assertEqual(timing['non_command_window_ns'], 699)
        self.assertEqual(timing['windows'][0]['relative_begin_ns'], 100)
        self.assertIn('BACKGROUND_WORK', timing['scope'])
        self.assertIn('NOT_ALL_DESCENDANT_EXECUTION', timing['scope'])

    def test_overlapping_reordered_or_out_of_attempt_commands_cannot_create_wait_time(self):
        examples = [[{'tool_call_id': 't', 'begin_ns': 99, 'end_ns': 200}],
            [{'tool_call_id': 't', 'begin_ns': 200, 'end_ns': 1001}],
            [{'tool_call_id': 't', 'begin_ns': 400, 'end_ns': 300}],
            [{'tool_call_id': 't1', 'begin_ns': 200, 'end_ns': 500},
             {'tool_call_id': 't2', 'begin_ns': 400, 'end_ns': 600}],
            [{'tool_call_id': 't', 'command': 'Agent text claims a command ran'}]]
        for example in examples:
            with self.subTest(example=example), self.assertRaises(ValueError):
                view.command_timing(example, 100, 1000)

    def test_short_command_marker_does_not_inflate_real_duration_and_escapes_tool_text(self):
        timing = view.command_timing([{'tool_call_id': 't1', 'begin_ns': 500000000, 'end_ns': 500000001}], 0, 1000000000)
        markup = view.command_window_markup(timing['windows'][0], 0, 1000000000,
            '#command-1', '<script>alert("unsafe")</script>')
        self.assertIn('width:0.000000100000%', markup)
        self.assertIn('data-duration-ns="1"', markup)
        self.assertIn('START_INSTANT_NOT_DURATION', markup)
        self.assertIn('细线仅标记开始时刻，不代表耗时宽度', markup)
        self.assertIn('href="#command-1"', markup)
        self.assertNotIn('min-width', markup)
        self.assertNotIn('<script>', markup)
        self.assertIn('&lt;script&gt;', markup)

    def test_no_commands_means_no_fake_bars_and_no_pure_api_wait_claim(self):
        timing = view.command_timing([], 100, 1100)
        self.assertEqual(timing['windows'], [])
        self.assertEqual(timing['sum_command_window_ns'], 0)
        self.assertEqual(timing['non_command_window_ns'], 1000)
        job = {'task_id': 'task', 'job_id': 'job', 'official_passed': False, 'official_evaluated': True,
            'agent_status': 'failed', 'prompt': 'task', 'wall_seconds': .000001, 'health': 'COMPLETE_FOR_SELECTED_HOOKS',
            'steps': [], 'final_answers': [], 'release_ns': 100, 'end_ns': 1100, 'command_timeline': timing}
        page = view.task_page(job, Path('/tmp/output'))
        self.assertIn('不能自动解释为 API 等待或 CPU 空闲', page)
        self.assertIn('模型、通信、控制和后台进程工作', page)
        self.assertIn('<div class="command-track"></div>', page)
        self.assertNotIn('href="#command-1"', page)

    def test_task_mini_timeline_links_actual_command_article(self):
        step = {'tool_call_id': 't1', 'begin_ns': 200, 'end_ns': 400, 'exit_code': 0,
            'wall_seconds': .0000002, 'command': 'printf ok', 'stdout': 'ok', 'root': {'tid': 10},
            'observed_syscall_counts': {}, 'kernel': None}
        job = {'task_id': 'task', 'job_id': 'job', 'official_passed': False, 'official_evaluated': True,
            'agent_status': 'completed', 'prompt': 'task', 'wall_seconds': .000001,
            'health': 'COMPLETE_FOR_SELECTED_HOOKS', 'steps': [step], 'final_answers': [],
            'release_ns': 100, 'end_ns': 1100, 'command_timeline': view.command_timing([step], 100, 1100),
            'native_page': '/tmp/native.html'}
        page = view.task_page(job, Path('/tmp/output'))
        self.assertIn('href="#command-1"', page)
        self.assertIn('<article id="command-1">', page)
        self.assertIn('width:20.000000000000%', page)


if __name__ == '__main__':
    unittest.main()
