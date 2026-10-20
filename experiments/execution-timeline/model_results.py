#!/usr/bin/env python3
"""Offline real-model application waits and eight-group result navigation.

Only manifest-bound application evidence is associated with native tools, by
explicit request/function/gate/root identities, never timestamp proximity.
Native verification remains the independent leaf replay receipt's authority.
"""
from __future__ import annotations
import argparse
import copy
import csv
from decimal import Decimal
import hashlib
import html
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

from common import digest, write_new
from matrix_summary import Sources

MODE = 'MODEL_AGENT'
BENCHMARKS = ('SWE-bench Verified', 'Terminal-Bench')
LIMITS = [
    '这里是真实模型尝试，不是官方参考解；官方得分0、预算终止和错误响应均保留，不当作采集失败删掉。',
    '每个条件一轮n=1；SWE为1题的8份复本，Terminal为2题组成的8个job，不是完整榜单成绩。',
    'API蓝条是目标Linux协调器的客户端等待，包括代理、网络和服务响应；不能解释远端GPU执行或GPU队列。',
    '工具橙条由显式request/function→gate工具/root映射建立；线程CPU等待请打开原生线程页，不按时间相近猜归属。',
    'ONCPU=正在CPU运行；RUNNABLE=已可运行但等CPU；SLEEP=阻塞或睡眠，不能一律说成磁盘等待。',
    'API累计、完成路径RUNNABLE累计、VFS累计、PSI都不能直接加到任务墙钟；模型可能产生不同命令，不宣称并发优化收益。',
    '官方结果、原始重放、选定工具覆盖、整个capture归因和费用证据相互独立；UNKNOWN及未归属活动保留。',
    '费用使用Host预算账本按请求ID/label关联，Host与Guest单调时钟不能直接比较；预算预留不是provider发票。',
    '读取对象包括库、管道、设备等，不等于源码文件数；缺页边界计数不提供逐文件归因。']
LIMITS += ['本轮sda是Agent/Docker根盘，sdb是Observer持久WAL盘；资源CSV保留双盘，但sdb吞吐不能当作Agent文件读写。',
    '本轮双盘配置不能与旧单盘Oracle直接比较模型成本或Observer开销；同benchmark不同并发也只是不同模型行为下的描述。']


def require(condition, message):
    if not condition: raise ValueError(message)


def integer(value):
    return type(value) is int and value >= 0


def wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_line(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def jsonl(path, sources, expected=None):
    path = sources.bind(path, expected)
    require(path.stat().st_size <= 16 * 1024 * 1024, 'application/ledger JSONL exceeds bounded reader')
    rows = []
    with path.open('rb') as stream:
        for raw in stream:
            require(raw.endswith(b'\n') and len(raw) <= 4 * 1024 * 1024, 'truncated or oversized JSONL record')
            value = strict_line(raw)
            require(isinstance(value, dict), 'JSONL object required')
            rows.append(value)
    return rows


def artifact(root, name, manifest):
    relative = Path(name)
    require(isinstance(name, str) and name and not relative.is_absolute() and '..' not in relative.parts,
            'safe manifest application path required')
    path = root / relative
    require(not path.is_symlink() and root in path.resolve(strict=True).parents, 'application artifact escapes timeline')
    binding = manifest.get('artifacts', {}).get(name)
    require(isinstance(binding, dict) and binding.get('sha256'), 'application artifact is not manifest-bound: ' + name)
    return path, binding


def application_requests(events, transcript, boot, label):
    starts, ends, transcript_requests, responses = {}, {}, {}, {}
    for event in transcript:
        event_type, key = event.get('event'), event.get('request_id')
        require(isinstance(key, str), 'transcript request identity required')
        target = transcript_requests if event_type == 'REQUEST' else responses if event_type == 'RESPONSE' else None
        require(target is not None and key not in target, 'duplicate/unknown transcript event')
        target[key] = event.get('payload' if event_type == 'REQUEST' else 'response')
    for event in events:
        key, step, kind = event.get('request_id'), event.get('step'), event.get('event')
        require(event.get('schema_version') == 1 and event.get('boot_id') == boot and event.get('clock') == 'CLOCK_MONOTONIC'
            and event.get('budget_label') == label and event.get('model') == 'deepseek-flash'
            and integer(step) and step < 4 and key == label + '-step-' + str(step), 'application boot/clock/label/request identity differs')
        target = starts if kind == 'MODEL_REQUEST_START' else ends if kind == 'MODEL_REQUEST_END' else None
        require(target is not None and key not in target and integer(event.get('begin_ns')), 'duplicate or invalid request event')
        target[key] = event
    rows = []
    for key in sorted(set(starts) | set(ends)):
        start, end = starts.get(key), ends.get(key)
        value = start or end
        issues = []
        if start is None or end is None: issues.append('UNPAIRED_APPLICATION_REQUEST_EVENT')
        if start and end:
            require(end.get('begin_ns') == start['begin_ns'] and end.get('request_sha256') == start.get('request_sha256')
                and integer(end.get('end_ns')) and end['end_ns'] >= start['begin_ns'], 'request end/start identity or clock order differs')
        payload = transcript_requests.get(key)
        require(isinstance(payload, dict) and payload.get('model') == 'deepseek-flash' and payload.get('n') == 1
            and payload.get('stream') is False and payload.get('thinking') == {'type': 'disabled'}
            and integer(payload.get('max_tokens')) and 1 <= payload['max_tokens'] <= 1024, 'bound transcript request policy differs')
        normalized = copy.deepcopy(payload)
        for message in normalized.get('messages', []):
            if isinstance(message, dict) and message.get('reasoning_content') in (None, ''):
                message.pop('reasoning_content', None)
        normalized_raw = wire(normalized)
        status = end.get('status') if end else 'UNKNOWN_NO_END'
        if status != 'RECEIVED': issues.append('MODEL_REQUEST_NOT_RECEIVED')
        response = responses.get(key)
        if status == 'RECEIVED':
            require(isinstance(response, dict) and response.get('usage') == end.get('usage')
                and response.get('model') == end.get('response_model'), 'received response usage/model/transcript differs')
        functions = {}
        choices = response.get('choices') if isinstance(response, dict) else None
        if isinstance(choices, list) and len(choices) == 1:
            for call in (choices[0].get('message') or {}).get('tool_calls') or []:
                if isinstance(call, dict) and isinstance(call.get('id'), str):
                    require(call['id'] not in functions, 'duplicate provider function ID within request')
                    functions[call['id']] = call.get('function')
        rows.append({'request_id': key, 'budget_label': label, 'step': value['step'], 'begin_ns': value['begin_ns'],
            'end_ns': end.get('end_ns') if end else None,
            'client_wait_ns': end['end_ns'] - start['begin_ns'] if start and end else None,
            'status': status, 'usage': end.get('usage') if end else None,
            'response_model': end.get('response_model') if end else None, 'failure_kind': end.get('failure_kind') if end else None,
            'application_status': 'PAIRED_DECLARED_CLIENT_WAIT' if start and end else 'UNPAIRED_APPLICATION_EVENT', 'issues': issues,
            'client_wire_request_sha256': value.get('request_sha256'), 'normalized_payload_sha256': sha(normalized_raw),
            'normalized_input_tokens_bound': len(normalized_raw) + 8192, 'max_output_tokens': payload['max_tokens'],
            'provider_functions': functions, 'tool_mappings': []})
    require(set(transcript_requests) == set(starts) | set(ends), 'transcript contains unrepresented request')
    require(set(responses) <= set(transcript_requests), 'response has no request')
    return rows


def union_ns(spans):
    spans = sorted(spans)
    total, right = 0, None
    for begin, end in spans:
        total += max(0, end - max(begin, right if right is not None else begin))
        right = max(end, right if right is not None else end)
    return total


def bound_application(timeline, manifest, summary, worker, sources):
    terminal = worker['benchmark'] == 'Terminal-Bench'
    prefix = 'model-evidence' if terminal else 'application/api'
    result_name = 'model-evidence/model-agent.json' if terminal else 'application/agent-result.json'
    app_path, binding = artifact(timeline, result_name, manifest)
    app = sources.read(app_path, binding)
    boot, label = manifest['boot_id'], worker.get('budget_label')
    require(worker.get('mode') == app.get('mode') == manifest.get('mode') == MODE
        and re.fullmatch(r'model-(swe|terminal)-c(2|4|6|8)-0[0-7]', label or '') is not None
        and manifest.get('budget_label') == app.get('budget_label') == label
        and app.get('boot_id') == boot and app.get('clock') == 'CLOCK_MONOTONIC', 'model application scope/identity differs')
    paths = {name: artifact(timeline, prefix + '/' + name, manifest) for name in ('model-requests.jsonl', 'model-transcript.jsonl')}
    events = jsonl(paths['model-requests.jsonl'][0], sources, paths['model-requests.jsonl'][1])
    transcript = jsonl(paths['model-transcript.jsonl'][0], sources, paths['model-transcript.jsonl'][1])
    requests = application_requests(events, transcript, boot, label)
    for request in requests:
        require(integer(manifest.get('begin_ns')) and integer(manifest.get('end_ns'))
            and manifest['begin_ns'] <= request['begin_ns'] <= manifest['end_ns']
            and (request['end_ns'] is None or request['end_ns'] <= manifest['end_ns']), 'application request lies outside native capture clock window')
    by_id = {row['request_id']: row for row in requests}
    native = {tool['tool_call_id']: tool for tool in manifest.get('tools', [])}
    summarized = {tool['tool_call_id']: tool for tool in summary.get('tools', [])}
    require(len(native) == len(manifest.get('tools', [])) and set(native) == set(summarized), 'summary/manifest tool registry differs')
    mappings = app.get('function_bindings' if terminal else 'mappings')
    require(isinstance(mappings, list), 'explicit application function mapping list required')
    if terminal:
        path, identity = artifact(timeline, 'model-evidence/model-function-bindings.jsonl', manifest)
        ledger = jsonl(path, sources, identity)
        require([row for row in ledger if row.get('event') == 'MODEL_FUNCTION_BOUND'] == mappings,
                'Terminal function ledger/result bindings differ')
    seen = set()
    for mapping in mappings:
        request_id = mapping.get('request_id')
        require(request_id in by_id and by_id[request_id]['status'] == 'RECEIVED', 'mapped function has no received request')
        tool_id = mapping.get('observer_tool_call_id' if terminal else 'tool_call_id')
        provider = mapping.get('provider_function_call_id' if terminal else 'provider_tool_call_id')
        require(tool_id in native and tool_id not in seen, 'mapping has missing/duplicate native gate tool')
        seen.add(tool_id)
        gate, measure = native[tool_id], summarized[tool_id]
        require(mapping.get('root') == gate.get('root') and mapping.get('begin_ns') == gate.get('begin_ns')
            and mapping.get('end_ns') == gate.get('end_ns') and gate.get('agent_id') == manifest.get('agent_id')
            and measure.get('agent_id') == gate.get('agent_id'), 'application mapping/gate root or timing differs')
        require(by_id[request_id]['end_ns'] <= gate['begin_ns'], 'tool dispatched before application response ended')
        function = by_id[request_id]['provider_functions'].get(provider)
        require(isinstance(function, dict) and function.get('name') == 'bash', 'mapping has no matching provider bash function')
        arguments = strict_line(function.get('arguments', '{}'))
        command = arguments.get('command') if isinstance(arguments, dict) else None
        require(isinstance(command, str), 'provider bash command required')
        if terminal:
            require(mapping.get('boot_id') == boot and mapping.get('budget_label') == label
                and mapping.get('agent_id') == manifest.get('agent_id') and mapping.get('cgroup_id') == gate.get('cgroup_id')
                and mapping.get('command_sha256') == sha(command.encode()), 'Terminal explicit function binding differs')
        else:
            require(mapping.get('command') == command and mapping.get('docker_exec_id') == gate.get('docker_exec_id'),
                    'SWE explicit function/exec binding differs')
        by_id[request_id]['tool_mappings'].append({'tool_call_id': tool_id, 'provider_function_call_id': provider,
            'root': gate['root'], 'root_key': measure.get('root_key'), 'begin_ns': gate['begin_ns'], 'end_ns': gate['end_ns'],
            'invocation_ns': gate.get('invocation_ns'), 'agent_id': gate.get('agent_id'),
            'selected_tool_timeline_status': measure.get('selected_tool_timeline_status'),
            'completion_path': measure.get('completion_path'), 'scope': 'EXPLICIT_APPLICATION_DISPATCH_TO_NATIVE_GATE_ROOT'})
    for row in requests: row.pop('provider_functions', None)
    request_count = app.get('client_request_attempts' if terminal else 'request_attempts')
    require(request_count == len(requests), 'application request count differs')
    if terminal:
        declared = manifest.get('model_application', {})
        require(declared.get('budget_label') == label and declared.get('request_count') == len(requests)
            and declared.get('function_bindings') == len(mappings), 'Terminal manifest application counts differ')
    return {'budget_label': label, 'termination': app.get('termination', 'UNKNOWN'), 'client_usage': app.get('usage'),
        'requests': requests, 'request_attempts': len(requests),
        'client_wait_union_ns': union_ns([(row['begin_ns'], row['end_ns']) for row in requests])
            if all(integer(row['client_wait_ns']) for row in requests) else None,
        'known_client_wait_union_ns': union_ns([(row['begin_ns'], row['end_ns']) for row in requests if integer(row['client_wait_ns'])]),
        'client_wait_sum_ns': sum(row['client_wait_ns'] for row in requests) if all(integer(row['client_wait_ns']) for row in requests) else None,
        'unmapped_native_tools': [{'tool_call_id': key, 'declared_kind': value.get('kind'),
            'scope': 'NOT_EXPLICITLY_MAPPED_TO_MODEL_FUNCTION_NO_INFERRED_API_CAUSE'} for key, value in native.items() if key not in seen],
        'evidence_links': {'agent_result': str(app_path), 'requests': str(paths['model-requests.jsonl'][0]),
            'transcript': str(paths['model-transcript.jsonl'][0])}}


def read_public_ledger(path, sources):
    events = jsonl(path, sources)
    require(events and events[0].get('event') == 'CONFIGURED', 'public broker ledger CONFIGURED header required')
    config = events[0].get('config')
    require(isinstance(config, dict) and events[0].get('config_sha256') == sha(wire(config))
        and config.get('schema_version') == 2 and Decimal(config.get('global_limit_rmb')) <= Decimal('4.2'), 'public ledger config binding differs')
    price = config.get('pricing', {})
    require(price.get('model') == 'deepseek-flash' and price.get('currency') == 'CNY'
        and price.get('input_rmb_per_million') == '2' and price.get('output_rmb_per_million') == '8', 'broker approved CNY price differs')
    labels = {row['label']: row for row in config['labels']}
    require(len(labels) == len(config['labels']), 'duplicate ledger label')
    rows = {}
    for event in events[1:]:
        key, label, kind = event.get('request_id'), event.get('task_label'), event.get('event')
        require(event.get('config_sha256') == events[0]['config_sha256'] and label in labels
            and isinstance(key, str) and key.startswith(label + '-step-'), 'broker event identity/config differs')
        cost = Decimal(event.get('cost_rmb_bound'))
        require(cost.is_finite() and cost >= 0, 'invalid broker cost')
        if kind == 'RESERVED':
            require(key not in rows and event.get('pricing') == price, 'duplicate/unpriced broker reservation')
            prompt, completion = event.get('input_tokens_bound'), event.get('output_tokens_bound')
            require(integer(prompt) and integer(completion) and 1 <= completion <= 1024
                and cost == (Decimal(prompt) * 2 + Decimal(completion) * 8) / 1000000, 'reservation arithmetic differs')
            rows[key] = {'reservation': event, 'final': event}
            require(sum((Decimal(row['final']['cost_rmb_bound']) for row in rows.values()), Decimal(0)) <= Decimal(config['global_limit_rmb'])
                and sum((Decimal(row['final']['cost_rmb_bound']) for row in rows.values() if row['reservation']['task_label'] == label), Decimal(0)) <= Decimal(labels[label]['cap_rmb']),
                'broker reservation exceeded global or registered job cap')
        else:
            require(key in rows and rows[key]['final']['event'] == 'RESERVED'
                and rows[key]['reservation']['task_label'] == label, 'broker settlement without unique reservation')
            reserved = rows[key]['reservation']
            if kind == 'UNKNOWN_CHARGE': require(cost == Decimal(reserved['cost_rmb_bound']), 'unknown charge freed budget')
            else:
                prompt, completion = event.get('prompt_tokens'), event.get('completion_tokens')
                require(kind in ('SETTLED', 'BOUND_EXCEEDED') and integer(prompt) and integer(completion), 'invalid broker settlement')
                bounded = prompt <= reserved['input_tokens_bound'] and completion <= reserved['output_tokens_bound']
                expected = (Decimal(prompt) * 2 + Decimal(completion) * 8) / 1000000
                require((kind == 'SETTLED') is bounded and cost == (expected if bounded else max(expected, Decimal(reserved['cost_rmb_bound']))),
                    'broker settled cost/status differs')
            rows[key]['final'] = event
    total = sum((Decimal(row['final']['cost_rmb_bound']) for row in rows.values()), Decimal(0))
    return {'config': config, 'requests': rows, 'accounted_cost_rmb_bound': str(total),
        'combined_historical_bound_rmb': str(total + Decimal(config['historical_bound_rmb'])),
        'path': str(Path(path).resolve()), 'identity': sources.identities[str(Path(path).resolve())]}


def attach_accounting(jobs, ledger):
    represented, issues = set(), []
    for job in jobs:
        label, cost, known = job['application']['budget_label'], Decimal(0), True
        for request in job['application']['requests']:
            key = request['request_id']; represented.add(key)
            entry = ledger['requests'].get(key) if ledger else None
            if entry is None:
                rejected = request['status'] == 'BUDGET_OR_REQUEST_LIMIT'
                request['broker_status'] = 'REJECTED_BEFORE_RESERVATION' if rejected else 'UNKNOWN_NO_MATCHING_LEDGER'
                request['accounted_cost_rmb_bound'] = '0' if rejected else None
                known &= rejected
            else:
                reserved, final = entry['reservation'], entry['final']
                require(reserved['task_label'] == label and reserved['request_sha256'] == request['normalized_payload_sha256']
                    and reserved['input_tokens_bound'] == request['normalized_input_tokens_bound']
                    and reserved['output_tokens_bound'] == request['max_output_tokens'], 'client/transcript/broker explicit request binding differs')
                request['broker_status'], request['accounted_cost_rmb_bound'] = final['event'], final['cost_rmb_bound']
                if final['event'] == 'SETTLED' and request['status'] == 'RECEIVED':
                    require(isinstance(request['usage'], dict) and all(request['usage'].get(key) == final.get(key)
                        for key in ('prompt_tokens', 'completion_tokens')), 'client usage differs from settled broker usage')
                cost += Decimal(final['cost_rmb_bound'])
                if final['event'] in ('RESERVED', 'UNKNOWN_CHARGE', 'BOUND_EXCEEDED'):
                    issues.append({'request_id': key, 'kind': final['event']})
        job['accounting'] = {'cost_rmb_bound': str(cost) if known else None, 'known_cost_rmb_bound': str(cost),
            'status': 'EXPLICIT_BROKER_REQUEST_ID_MATCH' if known else 'INCONCLUSIVE_MISSING_LEDGER_MATCH',
            'scope': 'RESERVATIONS_AND_USAGE_ACCOUNTING_NOT_PROVIDER_INVOICE_OR_CALL_COUNT_PROOF'}
    if ledger:
        for key, value in ledger['requests'].items():
            if key not in represented and value['reservation']['task_label'].startswith('model-'):
                issues.append({'request_id': key, 'kind': 'FORMAL_LEDGER_REQUEST_OUTSIDE_SELECTED_APPLICATIONS'})
    return issues


def compose_group(reportdir, sourcecampaign, resources, sources):
    root, reportdir, resources = Path(sourcecampaign).resolve(strict=True), Path(reportdir).resolve(strict=True), Path(resources).resolve(strict=True)
    campaign = sources.read(root / 'campaign.json')
    result = sources.read(reportdir / 'result.json')
    require(result.get('status') == 'INDEPENDENT_LEAF_REPORTS_COMPOSED' and result.get('total_jobs') == 8
        and len(result.get('jobs', [])) == 8 and campaign.get('total_jobs') == 8, 'complete eight-job native report required')
    require(result['source_campaign']['sha256'] == sources.identities[str(root / 'campaign.json')]['sha256'], 'native report source campaign differs')
    benchmark, concurrency, boot = campaign.get('benchmark'), campaign.get('concurrency'), campaign.get('boot_id')
    require(benchmark in BENCHMARKS and concurrency in (2, 4, 6, 8), 'supported model benchmark/concurrency required')
    resource_receipt = sources.read(resources / 'receipt.json')
    rr = resource_receipt.get('run', {})
    require(rr.get('boot_id') == boot and rr.get('benchmark') == benchmark and rr.get('concurrency') == concurrency
        and rr.get('total_jobs') == 8 and rr.get('begin_ns') == campaign.get('batch_start_ns') and rr.get('end_ns') == campaign.get('batch_end_ns')
        and resource_receipt.get('sources', {}).get('campaign.json', {}).get('sha256') == result['source_campaign']['sha256'], 'resource campaign window/source differs')
    acceptance = {row['job_id']: row['identity'] for row in result.get('leaf_acceptance', [])}
    originals = {row['job_id']: row for row in campaign['jobs']}
    require(len(acceptance) == len(originals) == 8 and set(acceptance) == set(originals)
        == {row.get('job_id') for row in result['jobs']}, 'all eight unique jobs/acceptances required')
    jobs = []
    for row in result['jobs']:
        name = row['job_id']
        require(re.fullmatch(r'(swe|terminal)-0[0-7]', name or '') and name in originals and row.get('mode') == MODE, 'model-only job registry required; no Oracle mixing')
        directory = root / 'jobs' / name
        worker = sources.read(directory / 'worker-result.json')
        leaf = reportdir / 'reports' / name
        accepted = sources.read(leaf / 'acceptance.json', acceptance[name])
        verification = sources.read(leaf / 'verification.json')
        summary = sources.read(leaf / 'summary.json')
        require(worker.get('mode') == accepted.get('mode') == MODE and worker.get('budget_label') == f'model-{"swe" if benchmark == BENCHMARKS[0] else "terminal"}-c{concurrency}-{name[-2:]}'
            and accepted.get('verification') == verification and verification.get('status') == 'REPLAY_PASSED'
            and digest(directory / 'worker-result.json') == verification.get('worker_result_identity'), 'worker/model/independent verification differs')
        relative = Path(worker.get('timeline_directory', ''))
        require(str(relative) and not relative.is_absolute() and '..' not in relative.parts, 'safe worker timeline required')
        timeline = (directory / relative).resolve(strict=True)
        require(directory.resolve() in timeline.parents, 'timeline escapes job')
        manifest = sources.read(timeline / 'manifest.json', verification['manifest_identity'])
        require(manifest.get('boot_id') == summary.get('run', {}).get('boot_id') == boot
            and manifest.get('run_id') == summary['run'].get('run_id') == row.get('source_run_id'), 'native/application boot/run differs')
        app = bound_application(timeline, manifest, summary, worker, sources)
        require(not any(isinstance(request.get('response_model'), str) and request['response_model'].startswith('FAKE_')
            for request in app['requests']), 'fake provider transport smoke cannot enter formal model group')
        require(type(worker.get('official_passed')) is bool and accepted.get('official_passed') == worker['official_passed'] == row.get('official_passed'), 'official score result differs')
        evaluated = worker.get('official_evaluated')
        if evaluated is None: evaluated = isinstance(worker.get('official_result'), dict) and type(worker['official_result'].get('resolved')) is bool
        for key in ('agent_return_ns', 'quiescent_ns'):
            require(worker.get(key) == originals[name].get(key), 'worker/controller lifecycle differs')
        jobs.append({'job_id': name, 'task_id': worker.get('task_id'), 'mode': MODE, 'agent_id': manifest.get('agent_id'),
            'boot_id': boot, 'official_evaluated': evaluated, 'official_passed': worker['official_passed'],
            'official_result': worker.get('official_result'), 'application': app, 'agent_return_ns': worker['agent_return_ns'],
            'model_return_ns': worker.get('model_return_ns'), 'release_issued_ns': originals[name].get('release_issued_ns'),
            'selected_tool_timeline_status': summary.get('selected_tool_timeline_status'),
            'whole_capture_attribution_status': summary.get('whole_capture_attribution_status'),
            'native_health_status': accepted.get('health', {}).get('status'), 'replay_status': verification['status'],
            'native_tools': summary.get('tools', []), 'native_counts': row,
            'links': {'native_timeline': str(leaf / 'timeline.html'), 'native_report': str(leaf / 'report.json'),
                'native_summary': str(leaf / 'summary.json'), 'verification': str(leaf / 'verification.json'),
                'manifest': str(timeline / 'manifest.json'), **{name: str(leaf / 'reads' / name) for name in
                    ('reads.csv', 'files.csv', 'excluded-reads.csv', 'unassigned-reads.csv')}}})
    return {'schema_version': 1, 'mode': MODE, 'status': 'MODEL_GROUP_APPLICATION_EVIDENCE_COMPOSED', 'benchmark': benchmark,
        'concurrency': concurrency, 'boot_id': boot, 'total_jobs': 8, 'jobs': jobs, 'timing': result.get('timing'),
        'resource_configuration': result.get('resource_configuration'), 'links': {'native_index': str(reportdir / 'index.html'),
            'native_timeline': str(reportdir / 'timeline.html'), 'resources': str(resources / 'index.html'),
            'jobs_csv': str(reportdir / 'jobs.csv'), 'resources_csv': str(reportdir / 'resources.csv'),
            'guest_resources_csv': str(resources / 'guest-series.csv'), 'cgroup_resources_csv': str(resources / 'cgroup-series.csv')}, 'limits': LIMITS}


def render(result, output):
    esc = lambda value: html.escape(str(value), quote=True)
    def link(path, label): return '<a href="{}">{}</a>'.format(esc(quote(os.path.relpath(path, output), safe='/.-_')), esc(label))
    def val(value): return 'UNKNOWN' if value is None else esc(value)
    groups = result.get('groups', [result])
    out = ['<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>真实模型：任务、API与内核时间线</title>',
        '<style>body{font-family:system-ui,sans-serif;max-width:1550px;margin:24px auto;padding:0 12px;line-height:1.6}table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #ddd;padding:5px;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere}.note{background:#fff3ce;padding:10px}.scroll{overflow-x:auto}svg{min-width:850px;width:100%}summary{cursor:pointer}code{overflow-wrap:anywhere}</style>',
        '<h1>真实模型任务：API等待 → 显式工具映射 → 原生线程</h1><p>状态：<code>{}</code> · <a href="result.json">完整JSON</a> · <a href="summary.csv">组间汇总CSV</a> · <a href="jobs.csv">全部任务CSV</a> · <a href="requests.csv">逐次模型请求CSV</a></p>'.format(esc(result['status'])),
        '<div class="note">' + '<br>'.join(esc(note) for note in LIMITS) + '</div>']
    if result.get('ledger'):
        out.append('<p>统一预算账本：{}；累计上界{}元，含历史{}元。</p>'.format(link(result['ledger']['path'], '公开账本副本'), val(result['ledger']['accounted_cost_rmb_bound']), val(result['ledger']['combined_historical_bound_rmb'])))
    for group in groups:
        out.append('<h2>{} / 并发{} / 固定8个任务</h2>'.format(esc(group['benchmark']), group['concurrency']))
        timing = group.get('timing') or {}
        out.append('<p>执行batch墙钟：{} 秒；全流程墙钟：{} 秒（另含准备及后处理，不与batch相加）。{} · {}</p>'.format(
            val(timing.get('batch_wall_ns') / 1e9 if integer(timing.get('batch_wall_ns')) else None),
            val(timing.get('campaign_wall_ns') / 1e9 if integer(timing.get('campaign_wall_ns')) else None),
            link(group['links']['native_index'], '完整原生/读取入口'), link(group['links']['resources'], '100ms资源图')))
        group_spans = [(request['begin_ns'], request['end_ns']) for job in group['jobs']
            for request in job['application']['requests'] if integer(request['client_wait_ns'])]
        group_spans += [(mapping['begin_ns'], mapping['end_ns']) for job in group['jobs']
            for request in job['application']['requests'] for mapping in request['tool_mappings']]
        if group_spans:
            a, b = timing.get('batch_start_ns'), timing.get('batch_end_ns')
            if not (integer(a) and integer(b) and b > a):
                a, b = min(span[0] for span in group_spans), max(span[1] for span in group_spans)
            width = max(1, b - a)
            out.append('<p>八个Agent共用同一Guest时轴：蓝色为API客户端等待，橙色为显式模型工具。空白不推断为CPU空闲；完整线程状态在原生页。</p><div class="scroll"><svg viewBox="0 0 1100 315" role="img" aria-label="八个Agent共享时轴API与工具泳道">')
            for index, job in enumerate(group['jobs']):
                y = 20 + index * 34
                out.append('<text x="0" y="{}">{}</text><line x1="160" x2="1090" y1="{}" y2="{}" stroke="#ddd"/>'.format(y + 10, esc(job['job_id']), y + 20, y + 20))
                for request in job['application']['requests']:
                    if integer(request['client_wait_ns']):
                        anchor = 'req-' + sha(request['request_id'].encode())[:20]
                        out.append('<a href="#{}"><rect x="{}" y="{}" width="{}" height="10" fill="{}"><title>{}</title></rect></a>'.format(
                            anchor, 160 + (request['begin_ns'] - a) / width * 930, y,
                            max(.8, request['client_wait_ns'] / width * 930), '#3487cc' if request['status'] == 'RECEIVED' else '#ba6f25', esc(request['request_id'])))
                    for mapping in request['tool_mappings']:
                        out.append('<a href="{}"><rect x="{}" y="{}" width="{}" height="8" fill="#d18b24"><title>{}</title></rect></a>'.format(
                            esc(quote(os.path.relpath(job['links']['native_timeline'], output), safe='/.-_')),
                            160 + (mapping['begin_ns'] - a) / width * 930, y + 12,
                            max(.8, (mapping['end_ns'] - mapping['begin_ns']) / width * 930), esc(mapping['tool_call_id'])))
            out.append('<text x="160" y="305">0 → {} 秒（全组共同时间窗口，非逐行归一化）</text></svg></div>'.format(esc((b - a) / 1e9)))
        out.append('<div class="scroll"><table><tr><th>job / task</th><th>官方结果</th><th>终止原因 / 请求尝试</th><th>API客户端等待并集ms</th><th>费用上界元</th><th>重放 / 覆盖 / 整体归因</th><th>完整读取数据</th></tr>')
        for job in group['jobs']:
            app = job['application']; score = '通过' if job['official_passed'] else '未通过（原始得分保留）' if job['official_evaluated'] else '未判题/UNKNOWN'
            out.append('<tr><td>{}<br>{}</td><td>{}</td><td>{}<br>{}</td><td>{}</td><td>{}</td><td>{}<br>{}<br>{}</td><td>{}</td></tr>'.format(
                esc(job['job_id']), esc(job['task_id']), score + '<br><code>' + esc(json.dumps(job['official_result'], ensure_ascii=False)) + '</code>', esc(app['termination']), app['request_attempts'],
                val(app['client_wait_union_ns'] / 1e6 if integer(app['client_wait_union_ns']) else None), val(job.get('accounting', {}).get('cost_rmb_bound')),
                esc(job['replay_status']), esc(job['selected_tool_timeline_status']), esc(job['whole_capture_attribution_status']),
                ' · '.join(link(job['links'][name], label) for name, label in (('native_timeline', '线程'), ('reads.csv', '每次读'),
                    ('files.csv', '每对象'), ('excluded-reads.csv', '窗外'), ('unassigned-reads.csv', '未归属')))))
        out.append('</table></div>')
        for job in group['jobs']:
            app = job['application']; requests = app['requests']
            out.append('<details><summary>{}：应用/API泳道及显式工具映射</summary><p>{} · {} · {}</p>'.format(esc(app['budget_label']),
                link(app['evidence_links']['requests'], 'manifest绑定API事件'), link(app['evidence_links']['transcript'], '完整模型往返记录'),
                link(job['links']['native_timeline'], '完整进程/线程页')))
            spans = [(row['begin_ns'], row['end_ns']) for row in requests if integer(row['end_ns'])]
            spans.extend((mapping['begin_ns'], mapping['end_ns']) for row in requests for mapping in row['tool_mappings'])
            if spans:
                begin, end = min(x[0] for x in spans), max(x[1] for x in spans)
                width = max(1, end - begin)
                out.append('<div class="scroll"><svg viewBox="0 0 1100 110" role="img" aria-label="API客户端等待与模型工具分离泳道"><text x="0" y="22">API客户端等待</text><text x="0" y="72">显式模型工具</text>')
                for request in requests:
                    anchor = 'req-' + sha(request['request_id'].encode())[:20]
                    if integer(request['end_ns']):
                        out.append('<a href="#{}"><rect x="{}" y="8" width="{}" height="27" fill="{}"><title>{}</title></rect></a>'.format(anchor,
                            165 + (request['begin_ns'] - begin) / width * 930, max(.8, (request['end_ns'] - request['begin_ns']) / width * 930),
                            '#3487cc' if request['status'] == 'RECEIVED' else '#ba6f25', esc(request['request_id'] + ' / ' + request['status'])))
                    for mapping in request['tool_mappings']:
                        out.append('<a href="{}"><rect x="{}" y="58" width="{}" height="27" fill="#d18b24"><title>{}</title></rect></a>'.format(
                            esc(quote(os.path.relpath(job['links']['native_timeline'], output), safe='/.-_')),
                            165 + (mapping['begin_ns'] - begin) / width * 930, max(.8, (mapping['end_ns'] - mapping['begin_ns']) / width * 930),
                            esc(mapping['tool_call_id'] + ' / root=' + json.dumps(mapping['root'], sort_keys=True))))
                out.append('</svg></div>')
            for request in requests:
                out.append('<div id="req-{}"><h4>{}</h4><p>客户端等待{}ms；应用状态{}；账本{}；费用上界{}元。</p>'.format(
                    sha(request['request_id'].encode())[:20], esc(request['request_id']),
                    val(request['client_wait_ns'] / 1e6 if integer(request['client_wait_ns']) else None), esc(request['status']),
                    esc(request.get('broker_status', 'UNKNOWN_NO_LEDGER')), val(request.get('accounted_cost_rmb_bound'))))
                if not request['tool_mappings']: out.append('<p>没有已执行的显式bash映射（可能finish、文本响应、拒绝或失败）；不补造进程。</p>')
                for mapping in request['tool_mappings']:
                    states = (mapping.get('completion_path') or {}).get('state_totals_ns') or {}
                    out.append('<p>provider function <code>{}</code> → gate <code>{}</code> → root <code>{}</code> / native key <code>{}</code>；完成路径RUNNABLE={}ns（非API等待、非任务墙钟）。{}</p>'.format(
                        esc(mapping['provider_function_call_id']), esc(mapping['tool_call_id']), esc(json.dumps(mapping['root'], sort_keys=True)),
                        val(mapping.get('root_key')), val(states.get('RUNNABLE')), link(job['links']['native_timeline'], '打开原生线程时间线')))
                out.append('</div>')
            out.append('<p>未映射原生工具（保留而不推断API原因）：<code>{}</code></p></details>'.format(esc(json.dumps(app['unmapped_native_tools'], ensure_ascii=False))))
    out.append('<h2>账本/完整性说明</h2><pre>' + esc(json.dumps(result.get('accounting_findings', []), ensure_ascii=False, indent=2)) + '</pre></html>')
    return '\n'.join(out)


def save(result, output, sources):
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'fresh model result output required; never overwrite')
    result['sources'], result['exporter_identity'] = sources.identities, digest(__file__)
    output.mkdir(mode=0o700, parents=True)
    write_new(output / 'result.json', result)
    groups = result.get('groups', [result])
    job_rows, request_rows, group_rows = [], [], []
    for group in groups:
        values = [job.get('accounting', {}).get('cost_rmb_bound') for job in group['jobs']]
        timing = group.get('timing') or {}
        group_rows.append({'benchmark': group['benchmark'], 'concurrency': group['concurrency'], 'total_jobs': 8, 'mode': MODE,
            'n_per_condition': 1, 'batch_wall_ns': timing.get('batch_wall_ns'), 'campaign_wall_ns': timing.get('campaign_wall_ns'),
            'official_evaluated_jobs': sum(job['official_evaluated'] is True for job in group['jobs']),
            'official_passed_jobs': sum(job['official_passed'] is True for job in group['jobs']),
            'replay_passed_jobs': sum(job['replay_status'] == 'REPLAY_PASSED' for job in group['jobs']),
            'client_request_attempts': sum(job['application']['request_attempts'] for job in group['jobs']),
            'cost_rmb_bound': str(sum((Decimal(value) for value in values), Decimal(0))) if all(value is not None for value in values) else None,
            'api_wait_sum_over_jobs_not_batch_wall_ns': sum(job['application']['client_wait_union_ns'] for job in group['jobs'])
                if all(integer(job['application']['client_wait_union_ns']) for job in group['jobs']) else None})
        for job in group['jobs']:
            app = job['application']
            common = {'benchmark': group['benchmark'], 'concurrency': group['concurrency'], 'job_id': job['job_id'],
                'task_id': job['task_id'], 'budget_label': app['budget_label']}
            job_rows.append({**common, 'official_evaluated': job['official_evaluated'], 'official_passed': job['official_passed'],
                'termination': app['termination'], 'request_attempts': app['request_attempts'], 'api_client_wait_union_ns': app['client_wait_union_ns'],
                'cost_rmb_bound': job.get('accounting', {}).get('cost_rmb_bound'), 'selected_tool_timeline_status': job['selected_tool_timeline_status'],
                'whole_capture_attribution_status': job['whole_capture_attribution_status'], 'replay_status': job['replay_status']})
            for row in app['requests']:
                request_rows.append({**common, **{key: row.get(key) for key in ('request_id', 'step', 'begin_ns', 'end_ns', 'client_wait_ns',
                    'status', 'broker_status', 'accounted_cost_rmb_bound')}, 'mapped_tool_ids': json.dumps([item['tool_call_id'] for item in row['tool_mappings']]),
                    'usage': json.dumps(row['usage'], sort_keys=True)})
    for name, rows in (('summary.csv', group_rows), ('jobs.csv', job_rows), ('requests.csv', request_rows)):
        with (output / name).open('x', newline='', encoding='utf-8') as stream:
            fields = list(rows[0]) if rows else ['request_id', 'status']
            writer = csv.DictWriter(stream, fields); writer.writeheader(); writer.writerows(rows)
    write_new(output / 'index.html', render(result, output).encode())
    sources.unchanged()
    write_new(output / 'receipt.json', {'schema_version': 1, 'mode': MODE, 'status': result['status'], 'exporter_identity': result['exporter_identity'],
        'sources': sources.identities, 'artifacts': {name: digest(output / name) for name in ('result.json', 'summary.csv', 'jobs.csv', 'requests.csv', 'index.html')}})
    return result


def export_group(reportdir, sourcecampaign, resources, output, ledger_public=None):
    sources = Sources(); result = compose_group(reportdir, sourcecampaign, resources, sources)
    ledger = read_public_ledger(ledger_public, sources) if ledger_public else None
    result['accounting_findings'] = attach_accounting(result['jobs'], ledger)
    result['ledger'] = {key: value for key, value in ledger.items() if key != 'requests'} if ledger else None
    return save(result, output, sources)


def export_matrix(groups, ledger_public, output):
    require(len(groups) == 8, 'formal model matrix requires exactly eight group directories; no partial')
    sources = Sources(); values = []
    for directory in groups:
        directory = Path(directory).resolve(strict=True)
        receipt = sources.read(directory / 'receipt.json')
        value = sources.read(directory / 'result.json', receipt['artifacts']['result.json'])
        require(value.get('mode') == MODE and value.get('status') == 'MODEL_GROUP_APPLICATION_EVIDENCE_COMPOSED'
            and value.get('total_jobs') == len(value.get('jobs', [])) == 8, 'completed model-only group required')
        require(not any(isinstance(request.get('response_model'), str) and request['response_model'].startswith('FAKE_')
            for job in value['jobs'] for request in job['application']['requests']), 'fake provider cannot enter formal matrix')
        for path, identity in value.get('sources', {}).items(): sources.bind(path, identity)
        values.append(value)
    require({(row['benchmark'], row['concurrency']) for row in values} == {(benchmark, concurrency) for benchmark in BENCHMARKS for concurrency in (2, 4, 6, 8)},
            'model matrix membership differs')
    for benchmark in BENCHMARKS:
        selected = [row for row in values if row['benchmark'] == benchmark]
        baseline = sorted(job['task_id'] for job in selected[0]['jobs'])
        require(all(sorted(job['task_id'] for job in row['jobs']) == baseline for row in selected), 'same benchmark task multiset differs')
    ledger = read_public_ledger(ledger_public, sources)
    jobs = [job for value in values for job in value['jobs']]
    labels = {job['application']['budget_label'] for job in jobs}
    require(len(labels) == 64 and labels == {row['label'] for row in ledger['config']['labels'] if row.get('kind') == 'FORMAL'}, 'matrix/public broker formal label registry differs')
    findings = attach_accounting(jobs, ledger)
    values.sort(key=lambda row: (BENCHMARKS.index(row['benchmark']), row['concurrency']))
    result = {'schema_version': 1, 'mode': MODE, 'status': 'COMPLETE_EIGHT_GROUP_MODEL_MATRIX_WITH_DECLARED_FINDINGS',
        'groups': values, 'job_rows': 64, 'accounting_findings': findings,
        'ledger': {key: value for key, value in ledger.items() if key != 'requests'}, 'limits': LIMITS}
    return save(result, output, sources)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reportdir', type=Path)
    parser.add_argument('--sourcecampaign', type=Path)
    parser.add_argument('--resources', type=Path)
    parser.add_argument('--matrix8groups', type=Path, nargs=8)
    parser.add_argument('--ledger-public', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.matrix8groups:
        require(args.ledger_public is not None and not any((args.reportdir, args.sourcecampaign, args.resources)), 'matrix needs public ledger and group outputs only')
        result = export_matrix(args.matrix8groups, args.ledger_public, args.output)
    else:
        require(all((args.reportdir, args.sourcecampaign, args.resources)), 'group needs reportdir/sourcecampaign/resources')
        result = export_group(args.reportdir, args.sourcecampaign, args.resources, args.output, args.ledger_public)
    print('真实模型离线结果入口：{}；{}。官方失败/预算终止保留，API等待不是GPU队列。'.format((args.output / 'index.html').absolute(), result['status']))
    return 0


if __name__ == '__main__': raise SystemExit(main())
