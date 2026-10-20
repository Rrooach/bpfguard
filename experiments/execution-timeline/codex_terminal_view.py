#!/usr/bin/env python3
"""Readable fixed-eight Codex/Terminal-Bench comparison; offline, no API calls."""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import html
import json
import math
import os
from pathlib import Path
from urllib.parse import quote

from codex_tool_adapter import verify_codex_tool_sources
from common import check_artifacts, digest, write_new
from codex_view import ledger_object, native_evidence
from matrix_summary import Sources, observed_objects
from syscall_catalog import describe
from tool_events import read_events, replay_tool_events

TASK_TITLES = {'terminal-bench/bun-sourcemap-leak': '修复 Bun 发布产物中的源码映射泄漏',
    'terminal-bench/html-js-filter': '实现 HTML／JavaScript 过滤器'}
TASK_SHORT = {'terminal-bench/bun-sourcemap-leak': 'Bun 发布修复', 'terminal-bench/html-js-filter': 'HTML 过滤器'}
BINDING = 'EXPLICIT_CODEX_REQUEST_TO_DOCKER_EXEC_STOPPED_ROOT_NOT_TIMESTAMP_MATCHING'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_bytes())


def number(value):
    return type(value) is int and value >= 0


def bound_app_path(root, manifest, name):
    require(isinstance(name, str) and name.startswith('app/') and not Path(name).is_absolute()
        and '..' not in Path(name).parts, 'safe application artifact required')
    identity = manifest.get('artifacts', {}).get(name)
    require(isinstance(identity, dict), 'application artifact is not manifest-bound: '+name)
    require(manifest.get('codex_application', {}).get('artifacts', {}).get(name) == identity,
        'Codex application artifact binding differs: '+name)
    path = root/name
    require(not path.is_symlink() and root.resolve() in path.resolve(strict=True).parents
        and digest(path) == identity, 'application artifact digest or path differs: '+name)
    return path


def app_rows(root, manifest, name, optional_empty=False):
    if name not in manifest.get('artifacts', {}):
        require(optional_empty and not (root/name).exists(), 'application ledger is missing or unbound: '+name)
        return []
    path = bound_app_path(root, manifest, name)
    require(path.stat().st_size <= 16*1024*1024, 'application ledger exceeds display limit')
    lines = path.read_bytes().splitlines(keepends=True)
    require(all(line.endswith(b'\n') for line in lines), 'truncated application ledger')
    return [ledger_object(line) for line in lines]


def validate_application(root, manifest, app, settings):
    """Check the two independent app ledgers against immutable Docker gates."""
    gates = {tool['tool_call_id']: tool for tool in manifest['tools']}
    require(len(gates) == len(manifest['tools']), 'duplicate tool span')
    mappings = app.get('function_bindings', [])
    require(isinstance(mappings, list) and len(mappings) <= 8, 'bounded Codex mappings required')
    function_rows = app_rows(root, manifest, 'app/function-bindings.jsonl', optional_empty=not mappings)
    docker_rows = app_rows(root, manifest, 'app/docker-function-bindings.jsonl', optional_empty=not mappings)
    require(function_rows == mappings, 'Codex function ledger differs from result')
    require(docker_rows == settings.get('function_bindings', []), 'Docker function ledger differs from settings')
    require(len(mappings) == len(docker_rows) == len(gates), 'application/kernel tool count differs')
    calls = [step for step in app.get('steps', []) if step.get('kind') == 'TOOL_CALL']
    require(len(calls) == len(mappings), 'application steps/mappings count differs')
    by_step = {step.get('tool_call_id'): step for step in calls}
    by_docker = {row.get('tool_call_id'): row for row in docker_rows}
    require(set(by_step) == set(by_docker) == set(gates), 'application/gate tool set differs')
    seen_calls, seen_rpc = set(), set()
    for mapping in mappings:
        key = mapping.get('tool_call_id'); gate, step, docker = gates[key], by_step[key], by_docker[key]
        require(isinstance(mapping.get('call_id'), str) and mapping['call_id']
            and type(mapping.get('rpc_request_id')) in (str, int), 'explicit Codex call/RPC ID required')
        require(mapping['call_id'] not in seen_calls and mapping['rpc_request_id'] not in seen_rpc,
            'duplicate Codex call/RPC ID')
        seen_calls.add(mapping['call_id']); seen_rpc.add(mapping['rpc_request_id'])
        require(mapping.get('thread_id') == app.get('thread_id') and mapping.get('turn_id') == app.get('turn_id')
            and all(isinstance(mapping.get(key), str) and mapping[key] for key in ('thread_id', 'turn_id')),
            'Codex thread/turn binding differs')
        require(mapping.get('binding_basis') == BINDING and mapping.get('gate_binding_basis') == BINDING
            and mapping.get('tool') == 'observer_bash', 'Docker dynamic-tool contract differs')
        require(all(step.get(name) == value for name, value in mapping.items()), 'Codex step/mapping differs')
        for name in ('call_id', 'rpc_request_id', 'command', 'tool_call_id', 'root', 'cgroup_id',
                'begin_ns', 'end_ns', 'gate_result', 'stdout_artifact', 'stderr_artifact'):
            require(docker.get(name) == mapping.get(name), 'Docker/Codex function ledger differs: '+name)
        require(all(gate.get(name) == mapping.get(name) for name in ('root', 'cgroup_id', 'command', 'begin_ns', 'end_ns'))
            and gate.get('result') == mapping.get('gate_result'), 'Codex request/root/result binding differs')
        require(gate.get('agent_id') == mapping.get('agent_id') == manifest.get('agent_id')
            and gate.get('task_id') == mapping.get('task_id') == manifest.get('task_id')
            and mapping.get('boot_id') == manifest.get('boot_id'), 'mapped Agent/task/boot identity differs')
        require(mapping.get('root_pid') == gate['root'].get('tid')
            and mapping.get('docker_exec_id') == gate.get('docker_exec_id'), 'Docker Exec PID/ID binding differs')
        require(mapping.get('command_sha256') == hashlib.sha256(gate['command'].encode()).hexdigest(),
            'command text digest differs')
        result = gate.get('result', {})
        require((type(result.get('return_code')) is int and step.get('exit_code') == result['return_code'])
            or (isinstance(result.get('error'), str) and result['error'].startswith('TimeoutError:')
                and step.get('exit_code') == 124), 'tool exit/result differs')
        require(number(gate.get('begin_ns')) and number(gate.get('end_ns')) and gate['end_ns'] >= gate['begin_ns'],
            'ordered tool boundaries required')
        stdout = bound_app_path(root, manifest, mapping.get('stdout_artifact')).read_bytes().decode('utf-8')
        stderr = bound_app_path(root, manifest, mapping.get('stderr_artifact')).read_bytes().decode('utf-8')
        require(step.get('stdout') == stdout[:3500] and step.get('stderr') == stderr[:1000],
            'displayed tool output differs from bound full output')
        require(step.get('output_truncated') is (len(stdout) > 3500 or len(stderr) > 1000),
            'tool output truncation marker differs')
        if 'return_code' in result:
            require(result.get('stdout_bytes') == len(stdout.encode()) and result.get('stderr_bytes') == len(stderr.encode()),
                'Docker output byte count differs')
    if app.get('schema_version') == 2:
        require(app.get('tool_event_schema') == 'APPLICATION_TOOL_LIFECYCLE_V1',
                'tool lifecycle schema missing')
        event_path = bound_app_path(root, manifest, 'app/tool-events.jsonl')
        require(event_path.stat().st_size <= 1024 * 1024, 'tool lifecycle ledger exceeds limit')
        replayed = replay_tool_events(read_events(event_path))
        require(replayed == app.get('tool_calls'), 'tool lifecycle ledger/result differs')
        by_call = {row['call_id']: row for row in replayed}
        require(len(by_call) == len(replayed), 'duplicate tool lifecycle call ID')
        if app.get('tool_event_source_scope') == 'RAW_CODEX_RPC_REPLAY_REQUIRED; LINUX_BINDING_SEPARATE':
            source = verify_codex_tool_sources(app_rows(root, manifest, 'app/rpc.jsonl'), read_events(event_path))
            require(source.get('status') == 'RAW_RPC_TOOL_EVENTS_REPLAYED', 'Codex raw tool source replay failed')
        for mapping in mappings:
            lifecycle = by_call.get(mapping['call_id'])
            step = by_step[mapping['tool_call_id']]
            require(lifecycle is not None and lifecycle.get('tool_name') == 'observer_bash'
                    and lifecycle.get('execution_tool_call_id') == mapping['tool_call_id']
                    and lifecycle.get('execution_begin_ns') == mapping['begin_ns']
                    and lifecycle.get('execution_end_ns') == mapping['end_ns']
                    and lifecycle.get('root') == mapping.get('root')
                    and lifecycle.get('cgroup_id') == mapping.get('cgroup_id')
                    and lifecycle.get('stdout_artifact') == mapping.get('stdout_artifact')
                    and lifecycle.get('stderr_artifact') == mapping.get('stderr_artifact'),
                    'tool lifecycle execution binding differs')
            require(step.get('tool_status') == lifecycle.get('status')
                    and step.get('exit_code') == lifecycle.get('exit_code')
                    and step.get('requested_ns') == lifecycle.get('requested_ns')
                    and step.get('result_delivered_ns') == lifecycle.get('result_delivered_ns')
                    and step.get('semantic_result') == lifecycle.get('semantic_result'),
                    'tool lifecycle displayed step differs')
        require({row['call_id'] for row in replayed
            if row.get('execution_binding') == 'TOOL_GATE_EXECUTION_BOUND'} == seen_calls,
            'process-bound tool lifecycle/function mapping set differs')
        reported = [row for row in replayed if row.get('execution_binding') == 'NOT_ESTABLISHED']
        reported_steps = {row.get('call_id'): row for row in app.get('steps', [])
            if row.get('kind') == 'APPLICATION_TOOL_CALL'}
        require(set(reported_steps) == {row['call_id'] for row in reported},
            'application-reported tool steps/lifecycle differ')
        for lifecycle in reported:
            step = reported_steps[lifecycle['call_id']]
            require(step.get('tool_status') == lifecycle.get('status')
                and all(step.get(key) == lifecycle.get(key) for key in ('tool_name', 'arguments', 'result_summary',
                    'application_evidence', 'execution_binding', 'linux_effect_evidence', 'remote_effect')),
                'application-reported tool display differs')
    return gates, calls


def failure_summary(app, termination):
    """Explain only recorded errors; never infer provider billing from HTTP 429."""
    messages = [str(app['error'])] if app.get('error') else []
    for row in app.get('errors', []):
        value = row.get('error', row) if isinstance(row, dict) else row
        messages.append(str(value.get('message', value)) if isinstance(value, dict) else str(value))
    joined = '\n'.join(messages)
    if app.get('status') == 'completed':
        explanation = 'Codex 正常提交了最终状态；是否解题成功仍以官方判题为准。'
    elif 'max_output_tokens' in joined:
        explanation = '模型响应达到输出长度上限，未能完整提交本轮回答。已执行的命令仍保留，但这不是完成任务的有效性能样本。'
    elif '429' in joined:
        explanation = '模型请求被接口或预算代理以 HTTP 429 拒绝。具体拒绝来源需查看代理回执，不能仅凭 429 判断远程限流或实际费用。'
    elif termination == 'CODEX_TOOL_CALL_LIMIT':
        explanation = '已达到本轮工具调用上限，Codex 未正常完成任务。'
    elif termination == 'CODEX_RUNTIME_TIMEOUT_OR_EOF':
        explanation = 'Codex 运行超时或通信流提前关闭；不能将停止等待当成任务提速。'
    else:
        explanation = 'Codex 未正常完成本轮任务。已记录的命令和官方判题结果仍可分别查看。'
    return {'explanation': explanation, 'recorded_messages': messages, 'termination': termination}


def relative_link(path, output):
    return quote(os.path.relpath(path, output), safe='/.-_')


def counters(record, name):
    text = record.get('files', {}).get(name, '')
    if name.endswith('.pressure'):
        return {parts[0]+'.'+key: int(value) for line in text.splitlines()
            for parts in [line.split()] for key, value in (part.split('=', 1) for part in parts[1:]) if key == 'total'}
    return {parts[0]: int(parts[1]) for line in text.splitlines() for parts in [line.split()]
        if len(parts) == 2 and parts[1].isdigit()}


def resource_delta(control):
    before, after = read(control/'resources-before.json'), read(control/'resources-after.json')
    require(before['cgroup_id'] == after['cgroup_id'] and before['cgroup_root'] == after['cgroup_root'],
        'resource boundary identity changed')
    mapping = {'cpu.stat': ('user_usec', 'system_usec'), 'memory.stat': ('pgfault', 'pgmajfault'),
        'cpu.pressure': ('some.total',), 'memory.pressure': ('some.total',), 'io.pressure': ('some.total',)}
    result = {}
    for name, fields in mapping.items():
        a, b = counters(before, name), counters(after, name)
        for field in fields:
            key = name+':'+field
            result[key] = b[field]-a[field] if field in a and field in b and b[field] >= a[field] else None
    return result


def receipt_quality(receipt, manifest):
    """Declared coverage gaps are evidence, not malformed or corrupt evidence."""
    require(receipt.get('status') in ('COMPLETE_FOR_SELECTED_REPORT_RECORDS', 'EXPORTED_WITH_DECLARED_GAPS')
        and receipt.get('run_id') == manifest['run_id'] and receipt.get('boot_id') == manifest['boot_id'],
        'read receipt run/boot or unsupported export status differs')
    require(isinstance(receipt.get('issues'), list), 'explicit read-export quality issues required')
    require(receipt.get('status') != 'COMPLETE_FOR_SELECTED_REPORT_RECORDS' or not receipt['issues'],
        'complete read-export status contradicts declared issues')
    return {'export_status': receipt['status'], 'export_issues': receipt['issues'],
        'read_partition_status': receipt.get('read_partition_status'),
        'unknown_bytes_records': receipt.get('counts', {}).get('unknown_bytes_records'),
        'unresolved_read_intervals': receipt.get('counts', {}).get('UNRESOLVED_READ_INTERVAL'),
        'scope': 'COUNTS_FOR_OBSERVED_SELECTED_RECORDS; DECLARED_GAPS_RETAINED_NOT_FULL_AGENT_HISTORY'}


def exported_reads(analysis, manifest, report):
    if report is None:
        return None
    sources = Sources()
    verification = sources.read(analysis/'verification.json')
    require(verification.get('verification_status') == 'REPLAY_PASSED'
        and verification.get('report_identity') == digest(analysis/'report-host.json'),
        'read exporter verification/report binding differs')
    receipt_binding = verification.get('artifacts', {}).get('reads/receipt.json')
    require(isinstance(receipt_binding, dict) and receipt_binding.get('sha256'), 'read receipt must be verification-bound')
    receipt = sources.read(analysis/'reads/receipt.json', receipt_binding)
    quality = receipt_quality(receipt, manifest)
    sources.bind(analysis/'report-host.json', receipt.get('source_report'))
    files_binding = receipt.get('artifacts', {}).get('files.csv')
    require(isinstance(files_binding, dict) and files_binding.get('sha256')
        == verification.get('artifacts', {}).get('reads/files.csv', {}).get('sha256'), 'files.csv receipt binding differs')
    result = observed_objects(analysis/'reads/files.csv', files_binding,
        {'run_id': manifest['run_id'], 'boot_id': manifest['boot_id']}, sources)
    for name in ('reads.csv', 'files.csv', 'excluded-reads.csv', 'unassigned-reads.csv'):
        binding = receipt.get('artifacts', {}).get(name)
        require(isinstance(binding, dict) and binding.get('sha256')
            == verification.get('artifacts', {}).get('reads/'+name, {}).get('sha256'), 'read CSV binding differs: '+name)
        sources.bind(analysis/'reads'/name, binding)
    sources.unchanged()
    return {**result, **quality, 'files_csv': str(analysis/'reads/files.csv'), 'reads_csv': str(analysis/'reads/reads.csv'),
        'receipt': str(analysis/'reads/receipt.json'), 'source_identities': sources.identities}


def flat_group_metrics(jobs, resources):
    """CSV-friendly units; missing values remain unknown, never implicit zero."""
    def seconds(key):
        value = resources.get(key)
        return value/1e6 if number(value) else None
    def elapsed_sum(key):
        values = [job.get(key) for job in jobs]
        return sum(values) if values and all(type(value) in (int, float) and math.isfinite(value)
            and value >= 0 for value in values) else None
    return {'cpu_user_seconds': seconds('cpu.stat:user_usec'),
        'cpu_system_seconds': seconds('cpu.stat:system_usec'),
        'pgfault': resources.get('memory.stat:pgfault') if number(resources.get('memory.stat:pgfault')) else None,
        'pgmajfault': resources.get('memory.stat:pgmajfault') if number(resources.get('memory.stat:pgmajfault')) else None,
        'cpu_psi_some_seconds': seconds('cpu.pressure:some.total'),
        'memory_psi_some_seconds': seconds('memory.pressure:some.total'),
        'io_psi_some_seconds': seconds('io.pressure:some.total'),
        'actual_command_count': sum(len(job['steps']) for job in jobs)
            if jobs and all(isinstance(job.get('steps'), list) for job in jobs) else None,
        'sum_command_wall_seconds': elapsed_sum('command_wall_seconds_sum'),
        'sum_attempt_wall_seconds': elapsed_sum('wall_seconds'),
        'sum_non_command_window_seconds': elapsed_sum('non_command_window_seconds')}


def command_timing(steps, release, quiet):
    """Observed sequential supervisor windows, not inferred model/API spans."""
    require(number(release) and number(quiet) and quiet > release, 'ordered positive Agent window required')
    windows, previous_end = [], release
    for index, step in enumerate(steps, 1):
        begin, end = step.get('begin_ns'), step.get('end_ns')
        require(number(begin) and number(end) and release <= begin <= end <= quiet,
            'command window escapes measured Agent attempt')
        require(begin >= previous_end, 'overlapping or reordered command windows cannot be subtracted as sequential time')
        previous_end = end
        windows.append({'command_index': index, 'tool_call_id': step['tool_call_id'],
            'begin_ns': begin, 'end_ns': end, 'duration_ns': end-begin,
            'relative_begin_ns': begin-release, 'relative_end_ns': end-release})
    command_ns = sum(window['duration_ns'] for window in windows)
    require(command_ns <= quiet-release, 'command durations exceed Agent attempt')
    return {'windows': windows, 'attempt_wall_ns': quiet-release, 'sum_command_window_ns': command_ns,
        'non_command_window_ns': quiet-release-command_ns,
        'scope': 'SUPERVISOR_DOCKER_EXEC_ROOT_WINDOWS_NOT_ALL_DESCENDANT_EXECUTION_OR_CPU_TIME; COMPLEMENT_CAN_INCLUDE_MODEL_COMMUNICATION_CONTROL_AND_BACKGROUND_WORK_NOT_PURE_API_WAIT'}


def job_view(group, row, official_outcome=None):
    job = group/'jobs'/row['job_id']
    worker = read(job/'worker-result.json')
    relative = Path(worker['timeline_directory'])
    require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe timeline directory')
    timeline = job/relative
    manifest = read(timeline/'manifest.json')
    check_artifacts(timeline, manifest)
    app = read(bound_app_path(timeline, manifest, 'app/steps.json'))
    settings = read(bound_app_path(timeline, manifest, 'app/codex-agent.json'))
    outcome = read(bound_app_path(timeline, manifest, 'app/codex-result.json'))
    require(app == outcome, 'Codex application outcome differs')
    require(app.get('mode') == 'REAL_CODEX_APP_SERVER_DYNAMIC_TOOLS'
        and app.get('agent_loop') == 'OFFICIAL_CODEX_NOT_IMPLEMENTED_BY_THIS_CLIENT', 'official Codex result contract required')
    require(settings['agent_implementation'] == 'OFFICIAL_CODEX_APP_SERVER_DYNAMIC_TOOLS'
        and manifest['agent_id'] == settings['agent_id'] == worker['agent_id'], 'official Codex Agent identity differs')
    require(manifest['task_id'] == worker['task_id'] == settings['task_id']
        and manifest['boot_id'] == settings['boot_id'], 'application task/boot identity differs')
    require(settings.get('termination') == worker.get('model_termination')
        == manifest.get('codex_application', {}).get('termination'), 'Codex termination binding differs')
    gates, calls = validate_application(timeline, manifest, app, settings)
    analysis = group.parent/'analysis'/group.name/row['job_id']
    host_report = analysis/'report-host.json'
    report = read(host_report) if host_report.exists() else None
    if report is not None:
        replay = read(analysis/'raw-replay.json')
        require(replay['verification_status'] == 'REPLAY_PASSED'
            and replay['manifest_identity'] == digest(timeline/'manifest.json')
            and replay['report_identity'] == digest(host_report), 'independent report receipt differs')
    steps = []
    for step in calls:
        gate = gates.get(step['tool_call_id'])
        require(gate is not None and gate['root'] == step['root'] and gate['command'] == step['command']
            and gate['begin_ns'] == step['begin_ns'] and gate['end_ns'] == step['end_ns'], 'Codex request/root binding differs')
        item = {**step, 'wall_seconds': (gate['end_ns']-gate['begin_ns'])/1e9,
            'gate_result': gate.get('result'), 'cwd': gate.get('cwd')}
        for name in ('stdout_artifact', 'stderr_artifact'):
            item[name+'_path'] = str(bound_app_path(timeline, manifest, step[name]))
        item['kernel'] = native_evidence(report, gate, workspace=gate.get('cwd')) if report else None
        call_counts = Counter()
        if report is not None:
            for thread in report.get('threads', []):
                if thread.get('tool_call_id') != gate['tool_call_id']:
                    continue
                for call in thread.get('calls', []):
                    if (number(call.get('start_ns')) and number(call.get('end_ns'))
                            and gate['begin_ns'] <= call['start_ns'] <= call['end_ns'] <= gate['end_ns']):
                        call_counts[describe(call.get('nr'), call.get('name'))['name']] += 1
        item['observed_syscall_counts'] = dict(call_counts)
        steps.append(item)
    health = read(timeline/'capture/health.json')
    metrics = resource_delta(group/'control'/row['job_id'])
    require(number(row.get('release_issued_ns')) and number(row.get('quiescent_ns'))
        and row['quiescent_ns'] >= row['release_issued_ns'], 'invalid measured task boundaries')
    timing = command_timing(steps, row['release_issued_ns'], row['quiescent_ns'])
    if official_outcome is None:
        official_outcome = {'official_evaluated': worker.get('official_evaluated') is True,
            'official_passed': worker.get('official_passed') if worker.get('official_evaluated') is True else None,
            'grading_status': 'OFFICIAL_GRADED' if worker.get('official_evaluated') is True else 'NOT_EVALUATED',
            'raw_worker_official_passed': worker.get('official_passed')}
    return {'job_id': row['job_id'], 'task_id': worker['task_id'], 'agent_id': worker['agent_id'],
        'timeline': str(timeline), 'native_page': str(analysis/'timeline-readable.html'),
        **official_outcome,
        'agent_status': app.get('status'), 'termination': worker.get('model_termination'),
        'release_ns': row['release_issued_ns'], 'end_ns': row['quiescent_ns'],
        'wall_seconds': (row['quiescent_ns']-row['release_issued_ns'])/1e9,
        'command_wall_seconds_sum': sum(step['wall_seconds'] for step in steps),
        'command_timeline': timing, 'non_command_window_seconds': timing['non_command_window_ns']/1e9,
        'health': health['status'], 'native_events': health.get('events', health.get('event_count')),
        'critical_path_status': report.get('critical_path', {}).get('status') if report else 'NOT_REPLAYED',
        'raw_replay_status': 'REPLAY_PASSED' if report else 'NOT_REPLAYED',
        'manifest_identity': digest(timeline/'manifest.json'), 'resource_counters': metrics,
        'prompt': bound_app_path(timeline, manifest, 'app/prompt.txt').read_text(),
        'failure': failure_summary(app, worker.get('model_termination')),
        'read_metrics': exported_reads(analysis, manifest, report),
        'steps': steps, 'final_answers': [step.get('text', '') for step in app.get('steps', [])
            if step.get('kind') == 'AGENT_MESSAGE'], 'report_available': report is not None}


def group_view(path):
    root = Path(path).resolve(strict=True)
    campaign = read(root/'campaign.json')
    require(campaign['total_jobs'] == 8 and campaign['concurrency'] in (2, 4, 6, 8),
        'a fixed-eight declared concurrency campaign is required')
    admission = None
    if campaign['status'] != 'WORKERS_COMPLETED':
        from official_timeout_view import validate_timeout_admission
        admission = validate_timeout_admission(root, campaign)
    require(campaign['batch_wall_ns'] == campaign['batch_end_ns']-campaign['batch_start_ns'] > 0,
        'batch wall subtraction differs')
    jobs = [job_view(root, row, admission['official_outcomes'][row['job_id']] if admission else None)
        for row in campaign['jobs']]
    require(all(campaign['batch_start_ns'] <= job['release_ns'] < job['end_ns'] <= campaign['batch_end_ns'] for job in jobs)
        and min(job['release_ns'] for job in jobs) == campaign['batch_start_ns']
        and max(job['end_ns'] for job in jobs) == campaign['batch_end_ns'], 'batch/attempt timing endpoints differ')
    require(admission is not None or all(job['official_evaluated'] is True for job in jobs),
        'normal completed campaign must have eight official evaluations')
    require(len({job['job_id'] for job in jobs}) == 8, 'eight distinct attempts are required')
    require(Counter(job['task_id'] for job in jobs) == {'terminal-bench/bun-sourcemap-leak': 4,
        'terminal-bench/html-js-filter': 4}, 'task multiset changed across conditions')
    metrics = {}
    for key in jobs[0]['resource_counters']:
        values = [job['resource_counters'][key] for job in jobs]
        metrics[key] = sum(values) if all(number(value) for value in values) else None
    read_metrics = {}
    for name in ('selected_read_calls', 'actual_returned_bytes', 'actual_returned_bytes_known_sum',
            'observed_identity_count', 'unresolved_identity_rows'):
        values = [job['read_metrics'].get(name) if job['read_metrics'] else None for job in jobs]
        read_metrics[name] = sum(values) if all(number(value) for value in values) else None
    resource_page = root.parent/'resources'/root.name/'index.html'
    return {'concurrency': campaign['concurrency'], 'jobs': jobs, 'total_jobs': 8,
        **flat_group_metrics(jobs, metrics),
        'original_campaign_status': campaign['status'], 'post_timing_exception_admission': admission,
        'batch_wall_seconds': campaign['batch_wall_ns']/1e9,
        'batch_start_ns': campaign['batch_start_ns'], 'batch_end_ns': campaign['batch_end_ns'],
        'campaign_wall_seconds': campaign['campaign_wall_ns']/1e9,
        'official_passed': sum(job['official_passed'] is True for job in jobs),
        'official_evaluated': sum(job['official_evaluated'] is True for job in jobs),
        'official_verifier_timeouts': sum(job.get('grading_status') == 'OFFICIAL_VERIFIER_TIMEOUT_NOT_SCORED' for job in jobs),
        'codex_completed': sum(job['agent_status'] == 'completed' for job in jobs),
        'codex_failed_or_interrupted': sum(job['agent_status'] != 'completed' for job in jobs),
        'raw_replay_passed_jobs': sum(job['raw_replay_status'] == 'REPLAY_PASSED' for job in jobs),
        'transport_complete_jobs': sum(job['health'] == 'COMPLETE_FOR_SELECTED_HOOKS' for job in jobs),
        'critical_path_reconstructed_jobs': sum(job['critical_path_status'] == 'RECONSTRUCTED_WITHIN_SELECTED_MODEL' for job in jobs),
        'read_export_without_declared_gaps_jobs': sum(job['read_metrics'] is not None
            and job['read_metrics']['export_status'] == 'COMPLETE_FOR_SELECTED_REPORT_RECORDS' for job in jobs),
        'resource_page': str(resource_page) if resource_page.is_file() else None,
        'resource_page_identity': digest(resource_page) if resource_page.is_file() else None,
        'resource_counters': metrics, 'read_metrics': read_metrics, 'source_campaign_identity': digest(root/'campaign.json')}


STYLE = '''body{font:16px/1.65 system-ui,sans-serif;color:#19283b;background:#f6f8fb;margin:auto;max-width:1200px;padding:24px}h1,h2,h3{line-height:1.3}section,article{background:white;border:1px solid #dce3eb;border-radius:12px;padding:20px;margin:18px 0}table{border-collapse:collapse;width:100%;font-size:14px}td,th{padding:10px;border-bottom:1px solid #e3e8ef;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f8;padding:14px;border-radius:8px;font:13px/1.6 monospace}a{color:#1460ae}summary{cursor:pointer}small,.muted{color:#53667c}.track{height:22px;background:#f1f4f8;position:relative;margin:5px 0}.bar{position:absolute;height:22px;background:#3983d4;border-radius:3px}.bar.failed{background:#bf7b30}.label{display:inline-block;width:270px;font-size:14px}.lane{display:flex;align-items:center}.lane .track{flex:1}.warn{background:#fff7e4;border:1px solid #ecd59e;padding:12px;border-radius:8px}'''
STYLE += '''.command-track{height:38px;position:relative;background:#e9edf2;margin:10px 0}.command-window{position:absolute;top:7px;height:24px;background:#153b6a;z-index:2}.command-start{position:absolute;top:3px;height:32px;width:0;border-left:1px solid #153b6a;z-index:3}.track .command-window{top:6px;height:10px}.track .command-start{top:3px;height:16px}.timeline-labels{display:flex;justify-content:space-between;font-size:13px;color:#53667c}article[id]{scroll-margin-top:20px}'''


def command_window_markup(window, begin, end, href, command):
    """A marker represents a start instant, never an expanded duration bar."""
    require(number(begin) and number(end) and begin < end
        and number(window.get('begin_ns')) and number(window.get('end_ns')) and number(window.get('duration_ns'))
        and begin <= window['begin_ns'] <= window['end_ns'] <= end
        and window['duration_ns'] == window['end_ns']-window['begin_ns'], 'display command interval outside timeline')
    left = (window['begin_ns']-begin)/(end-begin)*100
    width = (window['end_ns']-window['begin_ns'])/(end-begin)*100
    esc = lambda value: html.escape(str(value), quote=True)
    label = (f'命令 {window["command_index"]} 根进程窗口：{window["duration_ns"]/1e6:.6f} ms '
        f'（{window["duration_ns"]} ns）；开始于此时间线 {(window["begin_ns"]-begin)/1e9:.9f} 秒。'
        + str(command).split('\n', 1)[0][:180])
    result = '<a class="command-window" href="'+esc(href)+'" title="'+esc(label)+'" aria-label="'+esc(label)+'" style="left:'+format(left,'.12f')+'%;width:'+format(width,'.12f')+'%;" data-duration-ns="'+str(window['duration_ns'])+'"></a>'
    if width < .25:
        result += '<a class="command-start" href="'+esc(href)+'" title="'+esc(label+'；细线仅标记开始时刻，不代表耗时宽度。')+'" aria-label="'+esc('命令 '+str(window['command_index'])+' 开始时刻标记')+'" style="left:'+format(left,'.12f')+'%;" data-marker="START_INSTANT_NOT_DURATION"></a>'
    return result


def page(title, body):
    return '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+html.escape(title)+'</title><style>'+STYLE+'</style><h1>'+html.escape(title)+'</h1>'+body+'</html>'


def task_page(job, output):
    e = lambda value: html.escape(str(value))
    official = ('判题超时，未计分（不是 0 分）' if job.get('grading_status') == 'OFFICIAL_VERIFIER_TIMEOUT_NOT_SCORED'
        else '通过' if job['official_passed'] else '未通过' if job.get('official_evaluated') else '尚未完成判题')
    state = '正常结束' if job['agent_status'] == 'completed' else '未正常完成'
    body = f'<p>任务：{e(TASK_TITLES.get(job["task_id"], job["task_id"]))} · 官方判题：{official} · Codex：{state}</p>'
    if job.get('grading_status') == 'OFFICIAL_VERIFIER_TIMEOUT_NOT_SCORED':
        body += '<p class="warn">Agent 运行和内核采集已经结束，之后的官方判题器达到原始 1800 秒上限。该任务没有官方分数；它既不是通过，也不能被填成 0 分。下方命令和计时证据仍保留。</p>'
    failure = job.get('failure', {'explanation': '本轮没有可用的详细终止说明。', 'recorded_messages': []})
    body += '<section'+(' class="warn"' if job['agent_status'] != 'completed' else '')+'><h2>这次执行的结果</h2><p>'+e(failure['explanation'])+'</p>'
    if job['agent_status'] != 'completed':
        body += f'<p>已经执行了 {len(job["steps"])} 次工具调用，下面展示真实调用与输出；停止等待不等于完成任务。</p>'
    if failure.get('recorded_messages'):
        body += '<details><summary>查看原始错误信息</summary><pre>'+e('\n'.join(failure['recorded_messages']))+'</pre></details>'
    body += '</section>'
    body += '<details><summary>查看交给 Codex 的任务原文</summary><pre>'+e(job['prompt'])+'</pre></details>'
    body += f'<p>本次任务耗时 <b>{job["wall_seconds"]:.3f} 秒</b>；实际执行 {len(job["steps"])} 次工具调用。任务耗时包含模型思考、API 等待、工具执行和协调，不等于 CPU 时间。</p>'
    timing = job.get('command_timeline')
    if timing is not None:
        body += '<section><h2>这一轮：命令什么时候启动和返回</h2><p>尝试总窗口 '+format(timing['attempt_wall_ns']/1e9,'.6f')+' 秒；登记的命令根进程窗口合计 '+format(timing['sum_command_window_ns']/1e9,'.6f')+' 秒；这些根进程窗口以外 '+format(timing['non_command_window_ns']/1e9,'.6f')+' 秒。</p>'
        body += '<div class="command-track">'
        for window in timing['windows']:
            body += command_window_markup(window, job['release_ns'], job['end_ns'], '#command-'+str(window['command_index']),
                job['steps'][window['command_index']-1]['command'])
        body += '</div><div class="timeline-labels"><span>Agent 放行：0 秒</span><span>任务静止：'+format(job['wall_seconds'],'.6f')+' 秒</span></div>'
        body += '<p>深蓝段从登记根进程放行到 Docker Exec 根进程返回；短命令的细线只标记开始时刻，悬停可看精确耗时，点击跳到对应命令。灰底仅表示本轮任务仍在进行，<strong>不能自动解释为 API 等待或 CPU 空闲</strong>。</p>'
        body += '<p>根进程返回后，后台后代仍可能继续工作，因此窗口外时间可以包含模型、通信、控制和后台进程工作；深蓝段不保证覆盖所有后代的执行。整棵任务进程树只在 Agent 结束时确认静止。窗口是墙钟区间，不是 CPU 时间。</p></section>'
    reads = job.get('read_metrics')
    if reads:
        byte_text = str(reads['actual_returned_bytes'])+' 字节' if number(reads.get('actual_returned_bytes')) else '总字节数未完整确认'
        body += '<section><h2>实际读取记录</h2><p>已记录的选定 VFS 读取 '+e(reads['selected_read_calls'])+' 次，返回 '+e(byte_text)+'；本任务内去重后观察到 '+e(reads['observed_identity_count'])+' 个对象身份。</p>'
        if reads.get('actual_returned_bytes') is None:
            body += '<p>已知部分的返回字节之和：'+e(reads.get('actual_returned_bytes_known_sum'))+'；它不是完整总量。</p>'
        body += '<p>包含源码、运行库、管道和设备等，不是“不同源码文件数”；缺页计数不能据此逐文件分配。</p>'
        body += '<p><a href="'+relative_link(Path(reads['reads_csv']), output)+'">每次读取：字节数与耗时 CSV</a> · <a href="'+relative_link(Path(reads['files_csv']), output)+'">逐对象累计／平均／最大读取耗时 CSV</a></p></section>'
    path_status = '在选定模型内重建完成' if job.get('critical_path_status') == 'RECONSTRUCTED_WITHIN_SELECTED_MODEL' else '尚未完整重建'
    export_status = '已记录的选定记录无声明缺口' if reads and reads.get('export_status') == 'COMPLETE_FOR_SELECTED_REPORT_RECORDS' else '存在声明缺口或未完成导出'
    body += '<section'+(' class="warn"' if path_status == '尚未完整重建' else '')+'><h2>这份证据能说明到哪一步</h2><p>原始证据：'+('重放通过' if job.get('raw_replay_status') == 'REPLAY_PASSED' else '尚未通过重放')+'；选定记录传输：'+('未检测到丢失' if job['health'] == 'COMPLETE_FOR_SELECTED_HOOKS' else '不完整或未知')+'；等待路径：'+path_status+'；读取导出：'+export_status+'。</p>'
    body += '<p>重放通过只表示能够按原始证据复算，不会把缺失的等待区间、对象解析或未选择接口变成完整观测。</p>'
    if reads and reads.get('export_issues'):
        body += '<details><summary>查看保留的原始读取缺口</summary><pre>'+e(json.dumps(reads['export_issues'],ensure_ascii=False,indent=2))+'</pre></details>'
    body += '</section>'
    for index, step in enumerate(job['steps'], 1):
        native = relative_link(Path(job['native_page']), output)+'?tool='+quote(step['tool_call_id'])+'&kind=filesystem#operations'
        command = step['command']
        preview = '\n'.join(command.splitlines()[:8])[:1200]
        tool_result = step.get('gate_result') or {}
        status_names = {'SUCCEEDED':'成功', 'FAILED':'执行失败', 'TIMED_OUT':'执行超时',
            'CANCELLED':'已取消', 'TRANSPORT_ERROR':'工具通信失败', 'UNKNOWN':'状态未知'}
        status = status_names.get(step.get('tool_status'),
            '执行超时' if 'error' in tool_result else '成功' if step.get('exit_code') == 0 else '执行失败')
        tool_name = e(step.get('tool_name', 'observer_bash'))
        body += f'<article id="command-{index}"><h2>工具调用 {index}：<code>{tool_name}</code> · {status} · 退出码 {e(step["exit_code"])} · 实际执行 {step["wall_seconds"]:.3f} 秒</h2><pre>{e(preview)}</pre>'
        queue, total = step.get('request_to_execution_ns'), step.get('request_to_result_delivery_ns')
        if type(queue) is int or type(total) is int:
            body += '<p>'+('请求到实际执行 '+format(queue/1e6,'.3f')+' ms；' if type(queue) is int else '请求到实际执行耗时未确认；')+('请求到结果交回 Agent '+format(total/1e6,'.3f')+' ms。' if type(total) is int else '请求到结果交回耗时未确认。')+'</p>'
        body += '<p class="muted">工具执行成功只表示接口／命令正常返回；任务是否正确仍以官方判题或 verifier 为准。</p>'
        if preview != command:
            body += '<details><summary>展开完整命令</summary><pre>'+e(command)+'</pre></details>'
        stdout = step.get('stdout', '')
        preview_out = '\n'.join(stdout.splitlines()[:12])[:1200]
        body += '<h3>实际输出</h3><pre>'+e(preview_out or '（无标准输出）')+'</pre>'
        if preview_out != stdout:
            body += '<details><summary>展开返回给模型的完整输出</summary><pre>'+e(stdout)+'</pre></details>'
        if step.get('stderr'): body += '<pre>'+e(step['stderr'])+'</pre>'
        if step.get('output_truncated'): body += '<p>模型看到的输出已截断，完整输出保存在原始 app 文件中。</p>'
        if step.get('stdout_artifact_path') and step.get('stderr_artifact_path'):
            body += '<p><a href="'+relative_link(Path(step['stdout_artifact_path']), output)+'">原始完整 stdout</a> · <a href="'+relative_link(Path(step['stderr_artifact_path']), output)+'">原始完整 stderr</a></p>'
        calls = step.get('observed_syscall_counts', {})
        file_calls = {name: count for name, count in calls.items() if name in
            ('open', 'openat', 'openat2', 'read', 'pread64', 'readv', 'write', 'pwrite64', 'writev',
             'rename', 'renameat', 'renameat2', 'unlink', 'unlinkat', 'chmod', 'fchmod', 'fchmodat',
             'mkdir', 'mkdirat', 'getdents64', 'mmap', 'execve', 'execveat')}
        if file_calls:
            body += '<h3>实际记录的 syscall</h3><p>'+e('、'.join(f'{name} × {count}' for name, count in file_calls.items()))+'</p>'
        kernel = step.get('kernel')
        if kernel is not None:
            mutations = kernel['successful_mutation_syscalls']
            body += '<p>内核记录的成功文件操作：'+(e('、'.join(f'{name} × {count}' for name, count in mutations.items())) or '本条命令没有这类已记录操作')+'。</p>'
        body += f'<p><a href="{native}">查看这条命令的文件操作和具体 syscall</a> · 根进程 PID {e(step["root"]["tid"])}</p></article>'
    body += '<section><h2>Codex 最终回答</h2>'+(''.join('<pre>'+e(answer)+'</pre>' for answer in job['final_answers'])
        if job['final_answers'] else '<p>本轮没有收到正常的最终回答。实际执行过的命令不因此删除。</p>')+'</section>'
    body += '<p class="warn">内核采集范围是实际任务容器中的命令及其后代。Codex 控制进程在容器外，只记录其应用调用关系。路径未解析、未覆盖接口和不完整证据仍保留，不从命令文本猜成内核事实。</p>'
    return page('Terminal-Bench：'+job['job_id'], body)


def render(groups, output):
    e = lambda value: html.escape(str(value))
    body = '<p>真正 Codex + DeepSeek，受控 observer_bash 工具模式；每组相同 8 次任务尝试（两个题目各 4 次），只改变并发上限。官方参考解未交给 Agent。</p>'
    body += '<p><a href="comparison.csv" download>下载完整分组对比 CSV</a> · <a href="data.json">查看全部任务／命令 JSON</a></p>'
    body += '<p class="warn"><strong>已知接入问题：工作目录没有正确映射。</strong>Codex 控制进程在容器外，收到的是其私有 <code>/tmp/observer-codex-terminal-private-…</code> 工作目录；工具实际在任务容器的 <code>/app</code> 执行。记录中有命令尝试进入该容器外路径，并报“目录不存在”。这会浪费工具调用、影响解题，不能把本轮当成无此问题的 Codex 能力或优化成绩。本轮保持各组同一配置，未中途修改或替换 Agent 命令；修正映射后需要重新评测。'
    example = next(((group, job, index) for group in groups for job in group['jobs']
        for index, step in enumerate(job['steps'], 1) if 'observer-codex-terminal-private-' in step.get('stderr', '')
        and 'No such file or directory' in step.get('stderr', '')), None)
    if example:
        group, job, index = example
        body += ' <a href="c'+str(group['concurrency'])+'-'+e(job['job_id'])+'.html#command-'+str(index)+'">查看实际命令和错误输出</a>。'
    body += '</p>'
    body += '<p class="warn">每种并发仅一批；模型生成的命令、成功率和远程 API 延迟可能不同。这是实际运行对比，不是已隔离随机因素的调度加速证明。耗时主要指标是首任务放行至最后任务静止的墙钟时间，官方测试和重放在计时后执行。</p>'
    failed = sum(group['total_jobs']-group['codex_completed'] for group in groups)
    if failed:
        body += '<p class="warn"><strong>存在 '+str(failed)+' 次 Codex 未正常完成的尝试。</strong>下表是“每批尝试停止”的耗时，不是“所有题目做完”的耗时；不可作为完成相同有效工作量的性能结论，也不能据此宣称并发提速。请同时比较正常结束和官方通过数量。</p>'
    for group in groups:
        if group.get('post_timing_exception_admission'):
            body += '<p class="warn">'+str(group['concurrency'])+' 并发：已核验八项 Agent 的计时、静止和采集结束，之后有 '+str(group.get('official_verifier_timeouts', 0))+' 项官方判题达到原始 1800 秒上限。原始控制器状态 <code>'+e(group.get('original_campaign_status'))+'</code> 原样保留，未改成成功。超时任务未计分，不填成 0 分，也不放入已判题分母。</p>'
    body += '<section><h2>2／4／6／8 并发对比</h2><table><tr><th>并发上限</th><th>8次尝试全部停止</th><th>官方通过</th><th>Codex正常结束／未完成</th><th>任务CPU user+system</th><th>缺页／major</th></tr>'
    for group in groups:
        metric = group['resource_counters']
        cpu = [metric.get('cpu.stat:'+key) for key in ('user_usec', 'system_usec')]
        cpu_text = f'{sum(cpu)/1e6:.3f} 秒' if all(number(value) for value in cpu) else '未完整采集'
        graded = group.get('official_evaluated', 8)
        score_text = f'{group["official_passed"]}/{graded} 已判题'
        if group.get('official_verifier_timeouts'):
            score_text += f'；{group["official_verifier_timeouts"]} 超时未计分'
        body += f'<tr><td>{group["concurrency"]}</td><td>{group["batch_wall_seconds"]:.3f} 秒</td><td>{score_text}</td><td>{group["codex_completed"]}/8 ／ {8-group["codex_completed"]}/8</td><td>{cpu_text}</td><td>{e(metric.get("memory.stat:pgfault"))}／{e(metric.get("memory.stat:pgmajfault"))}</td></tr>'
    body += '</table><p>CPU 时间可并行累计，PSI 和读取耗时不能直接加到墙钟时间。CSV 另含 CPU user／system、缺页、PSI、实际命令数、Σ命令根进程窗口和Σ任务尝试耗时；两个 Σ 都可能跨 Agent 重叠，<strong>都不是整批墙钟时间，也不能替代或加到整批墙钟时间</strong>。根进程窗口外仍可能有后台后代工作，不能算作纯模型等待或 CPU 空闲。缺失值在 JSON 保持 null、CSV 留空，不填 0。</p></section>'
    body += '<section><h2>证据完整度：与解题成绩分开看</h2><table><tr><th>并发</th><th>原始证据重放通过</th><th>选定传输未检测到丢失</th><th>等待路径重建完成</th><th>读取导出无声明缺口</th></tr>'
    for group in groups:
        body += '<tr><td>'+str(group['concurrency'])+'</td>'+''.join('<td>'+str(group.get(name, 0))+'/8</td>' for name in
            ('raw_replay_passed_jobs', 'transport_complete_jobs', 'critical_path_reconstructed_jobs', 'read_export_without_declared_gaps_jobs'))+'</tr>'
    body += '</table><p>原始重放通过，不等于全部行为已覆盖；传输未丢失，不等于每段等待都已解释。等待路径或读取导出有缺口时，下面的访问数和字节数只描述已经记录的选定读取，不能充当完整 Agent 历史。CPU、缺页和 PSI 仅来自任务容器边界，不包含容器外 Codex 控制进程或远端模型资源。</p></section>'
    body += '<section><h2>实际读取与资源压力</h2><table><tr><th>并发</th><th>选定 VFS 读取次数</th><th>实际返回字节</th><th>各任务内去重对象数之和</th><th>CPU／内存／I/O PSI some</th></tr>'
    for group in groups:
        metrics = group.get('read_metrics', {}); resource = group['resource_counters']
        pressure = [resource.get(name+'.pressure:some.total') for name in ('cpu', 'memory', 'io')]
        pressure_text = ' ／ '.join(f'{value/1e6:.6f} 秒' if number(value) else '未完整采集' for value in pressure)
        def observed(name):
            value = metrics.get(name)
            return str(value) if number(value) else '未完整采集'
        body += '<tr><td>'+str(group['concurrency'])+'</td><td>'+observed('selected_read_calls')+'</td><td>'+observed('actual_returned_bytes')+'</td><td>'+observed('observed_identity_count')+'</td><td>'+pressure_text+'</td></tr>'
    body += '</table><p>对象按每个任务的 boot／mount／device／inode／generation 去重后再相加，<strong>不是整个批次全局不同文件数，也不是只统计源码</strong>；包含运行库、管道及设备。generation=0 无完整生命周期证明。读取字节来自选定 VFS 路径的真实返回值，不是申请字节数，也不是物理磁盘读取量。PSI 是任务组边界计数之和，不与墙钟相加。</p></section>'
    for group in groups:
        if group.get('read_metrics', {}).get('actual_returned_bytes') is None:
            body += '<p class="warn">'+str(group['concurrency'])+' 并发：返回总字节数未完整确认。已知部分字节之和为 '+e(group.get('read_metrics', {}).get('actual_returned_bytes_known_sum'))+'，不把该已知部分冒充完整总量。</p>'
    for group in groups:
        body += f'<section><h2>{group["concurrency"]} 并发：谁在什么时候执行</h2><p>每条泳道表示一次 Agent 尝试。蓝色背景表示 Codex 正常结束，橙色背景表示未正常完成；深蓝段是登记命令根进程窗口，细线仅标记短命令的开始。窗口外仍可能有后台进程工作，不是已证实的 API 等待或 CPU 空闲。点击任务或命令窗口查看具体执行；是否解题正确仍看官方判题。</p>'
        if group.get('resource_page'):
            body += '<p><a href="'+relative_link(Path(group['resource_page']), output)+'">查看本组 100 ms 资源曲线：CPU、内存／页缓存、PSI、调度等待、磁盘、网络、上下文切换、任务创建和缺页</a></p>'
        for index, job in enumerate(group['jobs'], 1):
            start = (job['release_ns']-group['batch_start_ns'])/(group['batch_end_ns']-group['batch_start_ns'])*100
            width = (job['end_ns']-job['release_ns'])/(group['batch_end_ns']-group['batch_start_ns'])*100
            name = f'c{group["concurrency"]}-{job["job_id"]}.html'
            colour = '' if job['agent_status'] == 'completed' else ' failed'
            label = f'Agent {index} · {TASK_SHORT.get(job["task_id"], job["job_id"])} · {job["wall_seconds"]:.2f}s'
            body += f'<div class="lane"><a class="label" href="{name}">{e(label)}</a><div class="track"><a href="{name}" title="{e(TASK_TITLES.get(job["task_id"], job["task_id"]))}"><span class="bar{colour}" style="left:{start:.4f}%;width:{width:.4f}%"></span></a>'
            for window in (job.get('command_timeline') or {}).get('windows', []):
                body += command_window_markup(window, group['batch_start_ns'], group['batch_end_ns'],
                    name+'#command-'+str(window['command_index']), job['steps'][window['command_index']-1]['command'])
            body += '</div></div>'
            write_new(output/name, task_page(job, output).encode())
        body += '</section>'
    body += '<p>原始文件和完整 syscall／逐次读取仍在各任务的详细页。本页面只重排展示，不修改原始证据或将未知改为通过。</p>'
    return page('Terminal-Bench：Codex＋DeepSeek 并发对比', body)


COMPARISON_COLUMNS = ['concurrency', 'batch_wall_seconds', 'official_passed', 'official_evaluated',
    'official_verifier_timeouts', 'codex_completed', 'selected_read_calls', 'actual_returned_bytes',
    'actual_returned_bytes_known_sum', 'observed_identity_count', 'cpu_user_seconds', 'cpu_system_seconds',
    'pgfault', 'pgmajfault', 'cpu_psi_some_seconds', 'memory_psi_some_seconds', 'io_psi_some_seconds',
    'actual_command_count', 'sum_command_wall_seconds', 'sum_attempt_wall_seconds',
    'sum_non_command_window_seconds',
    'raw_replay_passed_jobs', 'transport_complete_jobs', 'critical_path_reconstructed_jobs',
    'read_export_without_declared_gaps_jobs']


def write_comparison_csv(path, groups):
    with Path(path).open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=COMPARISON_COLUMNS)
        writer.writeheader()
        writer.writerows({key: group.get(key, group.get('read_metrics', {}).get(key))
            for key in COMPARISON_COLUMNS} for group in groups)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', required=True, action='append', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    groups = sorted((group_view(path) for path in args.group), key=lambda group: group['concurrency'])
    require(len({group['concurrency'] for group in groups}) == len(groups), 'duplicate condition')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_new(args.output/'data.json', {'schema_version': 1, 'groups': groups})
    write_new(args.output/'index.html', render(groups, args.output).encode())
    write_comparison_csv(args.output/'comparison.csv', groups)
    print(json.dumps({'status': 'READABLE_VIEW_GENERATED', 'groups': len(groups), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
