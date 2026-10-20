#!/usr/bin/env python3
"""Offline Codex/Terminal provider bindings and conservative CNY accounting.

No API calls or execution. This checks the trusted local proxy's original SSE,
not a provider signature, and is separate from native timeline replay, coverage
and official task grading. A failed Codex turn stays failed; uncertain charges
stay charged and make the provider/accounting conclusion INCONCLUSIVE.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import fcntl
import json
import os
from pathlib import Path
import sys

from codex_tool_adapter import verify_codex_tool_sources
from common import check_artifacts, digest, write_new
from parallel_report import resolve_job
from replay import check_tool_ledger
from tool_events import read_events, replay_tool_events

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'agent-benchmarks'))
import codex_response_budget as proxy
import model_budget_v2 as budget

IMPLEMENTATION = 'OFFICIAL_CODEX_APP_SERVER_DYNAMIC_TOOLS'
AGENT_LOOP = 'OFFICIAL_CODEX_NOT_IMPLEMENTED_BY_THIS_CLIENT'
CODEX_SHA256 = '3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path, limit=16 * 1024 * 1024):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
        'bounded regular evidence file required: ' + str(path))
    raw = path.read_bytes()
    require(len(raw) <= limit, 'evidence grew beyond limit')
    return raw


def load(path):
    return budget.parse_json(read(path))


def jsonl(path):
    raw = read(path)
    require(not raw or raw.endswith(b'\n'), 'truncated JSONL evidence')
    return [budget.parse_json(line) for line in raw.splitlines()]


def terminal(raw):
    values = []
    for part in raw.replace(b'\r\n', b'\n').split(b'\n\n'):
        data = b'\n'.join(line[5:].lstrip(b' ') for line in part.splitlines() if line.startswith(b'data:'))
        if not data or data == b'[DONE]':
            continue
        row = budget.parse_json(data)
        if row.get('type') in ('response.completed', 'response.incomplete', 'response.failed'):
            require(isinstance(row.get('response'), dict), 'terminal provider response required')
            values.append(row['response'])
    require(len(values) == 1, 'exactly one terminal provider response required')
    return values[0]


def replay_budget(path):
    """Replay every durable transition, without opening/writing a broker ledger."""
    path = Path(path).resolve(strict=True)
    raw = read(path, budget.MAX_LEDGER)
    require(raw and raw.endswith(b'\n'), 'nonempty complete budget ledger required')
    identity = {'sha256': budget.sha(raw), 'size_bytes': len(raw)}
    rows = [budget.parse_json(line) for line in raw.splitlines()]
    first = rows[0]
    require(first.get('event') == 'CONFIGURED' and isinstance(first.get('config'), dict), 'configured ledger required')
    config, configured_sha = first['config'], first.get('config_sha256')
    require(configured_sha == budget.sha(budget.canonical(config)), 'budget configuration digest differs')
    require(config.get('schema_version') == 2
        and config.get('registration_kind') in ('CODEX_TERMINAL_2468', 'CODEX_TERMINAL_2468_V2')
        and config.get('provider_endpoint') == proxy.ENDPOINT
        and config.get('max_output_tokens') == budget.configured_output_limit(config),
        'registered real Responses Terminal campaign required')
    if config['registration_kind'] == 'CODEX_TERMINAL_2468_V2':
        require(config.get('reasoning_effort') == 'none', 'Terminal V2 explicit no-thinking policy missing')
    pricing = config.get('pricing', {})
    require(pricing.get('model') == budget.MODEL and pricing.get('currency') == 'CNY'
        and budget.money(pricing.get('input_rmb_per_million')) == budget.INPUT_RATE
        and budget.money(pricing.get('output_rmb_per_million')) == budget.OUTPUT_RATE,
        'approved model/currency/rates required')
    history, limit = budget.money(config.get('historical_bound_rmb')), budget.money(config.get('global_limit_rmb'))
    require(history >= budget.HISTORY_RMB and limit == Decimal('4.0') and history + limit <= Decimal(5),
        'historical plus campaign cap exceeds approved five CNY contract')
    replay = object.__new__(budget.Ledger)
    replay.config, replay.config_sha256, replay.limit = config, configured_sha, limit
    replay.campaign_id, replay.labels = budget.registry(dict(config, schema_version=1))
    replay.requests, replay.blocked = {}, False
    reservations = {}
    for row in rows[1:]:
        replay._apply(row)
        if row['event'] == 'RESERVED':
            reservations[row['request_id']] = row
    sources = {}
    for key, record in replay.requests.items():
        reservation = reservations[key]
        request_identity = None
        if config['registration_kind'] == 'CODEX_TERMINAL_2468_V2':
            request_path = path.parent / (key + '-request.json')
            if request_path.exists():
                outgoing = read(request_path, budget.MAX_BODY)
                request = budget.parse_json(outgoing)
                require(budget.sha(outgoing) == reservation['request_sha256'] and outgoing == budget.canonical(request)
                    and request.get('model') == budget.MODEL and request.get('max_output_tokens') == 4096
                    and request.get('reasoning', {}).get('effort') == 'none'
                    and request.get('stream') is True and request.get('store') is False
                    and isinstance(request.get('tools'), list) and len(request['tools']) == 1
                    and request['tools'][0].get('type') == 'function' and request['tools'][0].get('name') == 'observer_bash',
                    'V2 normalized request digest/output/no-thinking/tool contract differs')
                request_identity = {'sha256': budget.sha(outgoing), 'size_bytes': len(outgoing)}
            else:
                require(record['event'] not in ('SETTLED', 'BOUND_EXCEEDED'), 'settled V2 normalized request is missing')
        receipt_path, source_path = path.parent / (key + '-response.json'), path.parent / (key + '-upstream.sse')
        if not receipt_path.exists() or not source_path.exists():
            require(record['event'] != 'SETTLED', 'settled provider response/receipt is missing')
            continue
        receipt, body = load(receipt_path), read(source_path, proxy.MAX_RESPONSE)
        require(receipt.get('request_id') == key and receipt.get('request_sha256') == reservation['request_sha256']
            and receipt.get('response_file') == source_path.name and receipt.get('response_sha256') == budget.sha(body)
            and receipt.get('response_bytes') == len(body) and receipt.get('upstream_endpoint') == proxy.ENDPOINT,
            'provider source binding differs: ' + key)
        value = terminal(body)
        usage, model = proxy.response_usage(body)
        if record['event'] in ('SETTLED', 'BOUND_EXCEEDED'):
            require(isinstance(usage, dict) and usage.get('prompt_tokens') == record['prompt_tokens']
                and usage.get('completion_tokens') == record['completion_tokens']
                and ('total_tokens' not in usage or usage['total_tokens'] == record['prompt_tokens'] + record['completion_tokens'])
                and str(model)[:128] == record.get('provider_model'), 'provider usage/model differs from ledger')
        sources[key] = {'request_id': key, 'task_label': record['task_label'], 'value': value,
            'source_identity': {'sha256': budget.sha(body), 'size_bytes': len(body)},
            'response_receipt_identity': digest(receipt_path), 'tool_policy_passed': proxy.controlled_output(body),
            'normalized_request_identity': request_identity,
            'source': str(source_path), 'cost_rmb_upper_bound': record['cost_rmb_bound'], 'accounting_status': record['event']}
    return replay, reservations, sources, identity, history


def mapping(rows, key, description):
    require(isinstance(rows, list) and all(isinstance(row, dict) and isinstance(row.get(key), (str, int)) for row in rows),
        'invalid ' + description)
    result = {row[key]: row for row in rows}
    require(len(result) == len(rows), 'duplicate ' + description)
    return result


def bind_application(timeline, worker, controller, boot_id, policy=None):
    manifest = load(timeline / 'manifest.json')
    bound = check_artifacts(timeline, manifest)
    check_tool_ledger(timeline, manifest)
    app = manifest.get('codex_application', {})
    label = worker.get('budget_label')
    expected = {'agent_id': worker.get('agent_id'), 'task_id': worker.get('task_id'), 'boot_id': boot_id,
        'budget_label': label, 'mode': 'MODEL_AGENT', 'agent_implementation': IMPLEMENTATION, 'model': budget.MODEL}
    require(worker.get('benchmark') == 'Terminal-Bench' and worker.get('agent_implementation') == IMPLEMENTATION
        and controller.get('task_id') == worker.get('task_id'), 'worker/controller Codex task identity differs')
    require(all(app.get(key) == value for key, value in expected.items()), 'manifest Codex application identity differs')
    require(manifest.get('boot_id') == boot_id and manifest.get('agent_id') == worker.get('agent_id')
        and manifest.get('budget_label') == label and manifest.get('mode') == 'MODEL_AGENT', 'manifest Agent/boot/budget binding differs')
    required = {'app/codex-agent.json', 'app/steps.json', 'app/codex-result.json', 'app/rpc.jsonl',
        'app/config.public.json', 'app/model-catalog.json'}
    require(required <= bound.keys() and required <= app.get('artifacts', {}).keys(), 'Codex application evidence not manifest-bound')
    require(all(bound.get(name) == value for name, value in app.get('artifacts', {}).items()), 'Codex nested artifact bindings differ')
    state, steps = load(timeline / 'app/codex-agent.json'), load(timeline / 'app/steps.json')
    require(all(state.get(key) == value for key, value in expected.items()), 'Codex state identity differs')
    require(load(timeline / 'app/codex-result.json') == steps and steps.get('agent_loop') == AGENT_LOOP
        and app.get('agent_loop') == AGENT_LOOP and steps.get('model') == budget.MODEL,
        'Codex result/Agent-loop evidence differs')
    require(state.get('termination') == app.get('termination') == worker.get('model_termination'), 'Codex termination differs')
    require(steps.get('status') in ('completed', 'failed', 'interrupted'), 'explicit Codex terminal turn status required')
    public = load(timeline / 'app/config.public.json')
    binary, runtime = public.get('codex_identity', {}), state.get('runtime', {})
    require(binary.get('sha256') == CODEX_SHA256 and runtime.get('binary_identity') == binary
        and app.get('runtime') == runtime and runtime.get('kernel_observed') is False
        and public.get('agent_loop') == IMPLEMENTATION and public.get('budget_label') == label
        and public.get('http_headers') == {'X-Benchmark-Task': label}
        and public.get('model_catalog_identity') == bound['app/model-catalog.json']
        and public.get('config', {}).get('model') == budget.MODEL
        and public.get('config', {}).get('model_providers.observer_proxy.wire_api') == 'responses',
        'pinned official Codex binary/config/catalog/runtime identity differs')
    if (policy or {}).get('registration_kind') == 'CODEX_TERMINAL_2468_V2':
        require(public.get('config', {}).get('model_reasoning_effort') == 'none'
            and state.get('max_output_tokens_enforced_by_external_broker') == 4096,
            'Terminal V2 app must explicitly use none reasoning and4096 output')
    calls = mapping(steps.get('function_bindings', []), 'call_id', 'Codex function call')
    docker = mapping(state.get('function_bindings', []), 'call_id', 'Docker function call')
    tools = mapping(manifest.get('tools', []), 'tool_call_id', 'manifest tool')
    require(calls.keys() == docker.keys() and len(tools) == len(calls) == app.get('function_bindings'),
        'Codex calls and stopped Docker roots are not one-to-one')
    rpc_rows = jsonl(timeline / 'app/rpc.jsonl')
    require(all(row.get('boot_id') == boot_id and row.get('clock') == 'CLOCK_MONOTONIC' for row in rpc_rows),
        'Codex RPC boot/clock differs')
    requests = [row['message'] for row in rpc_rows if row.get('direction') == 'CODEX_TO_CLIENT'
        and row.get('message', {}).get('method') == 'item/tool/call']
    by_call = mapping([dict(row.get('params', {}), _rpc_id=row.get('id')) for row in requests], 'callId', 'RPC dynamic call')
    tool_steps = mapping([row for row in steps.get('steps', []) if row.get('kind') == 'TOOL_CALL'], 'call_id', 'tool result')
    require(calls.keys() == tool_steps.keys() and calls.keys() <= by_call.keys(), 'Codex RPC/tool result binding missing')
    if steps.get('schema_version') == 2:
        require(steps.get('tool_event_schema') == 'APPLICATION_TOOL_LIFECYCLE_V1'
            and 'app/tool-events.jsonl' in bound, 'bound tool lifecycle evidence required')
        tool_events_path = timeline / 'app/tool-events.jsonl'
        require(tool_events_path.stat().st_size <= 1024 * 1024, 'tool lifecycle ledger exceeds limit')
        replayed = replay_tool_events(read_events(tool_events_path))
        require(replayed == steps.get('tool_calls'), 'tool lifecycle ledger/result differs')
        if steps.get('tool_event_source_scope') == 'RAW_CODEX_RPC_REPLAY_REQUIRED; LINUX_BINDING_SEPARATE':
            source = verify_codex_tool_sources(rpc_rows, read_events(tool_events_path))
            require(source.get('status') == 'RAW_RPC_TOOL_EVENTS_REPLAYED', 'Codex raw tool source replay failed')
        lifecycle = mapping(replayed, 'call_id', 'tool lifecycle call')
        require(calls.keys() <= lifecycle.keys(), 'function call is missing from tool lifecycle')
        for call_id, function in calls.items():
            row = lifecycle[call_id]
            step = tool_steps[call_id]
            require(row.get('tool_name') == 'observer_bash'
                and row.get('execution_tool_call_id') == function.get('tool_call_id')
                and row.get('execution_begin_ns') == function.get('begin_ns')
                and row.get('execution_end_ns') == function.get('end_ns')
                and row.get('root') == function.get('root') and row.get('cgroup_id') == function.get('cgroup_id')
                and row.get('stdout_artifact') == function.get('stdout_artifact')
                and row.get('stderr_artifact') == function.get('stderr_artifact')
                and row.get('status') == step.get('tool_status')
                and row.get('exit_code') == step.get('exit_code')
                and row.get('result_delivered_ns') == step.get('result_delivered_ns'),
                'tool lifecycle execution/result binding differs')
        require({key for key, value in lifecycle.items()
            if value.get('execution_binding') == 'TOOL_GATE_EXECUTION_BOUND'} == calls.keys(),
            'process-bound tool lifecycle/function mapping set differs')
        reported = {key: value for key, value in lifecycle.items()
            if value.get('execution_binding') == 'NOT_ESTABLISHED'}
        reported_steps = mapping([row for row in steps.get('steps', [])
            if row.get('kind') == 'APPLICATION_TOOL_CALL'], 'call_id', 'application-reported tool result')
        require(reported.keys() == reported_steps.keys(), 'application-reported tool lifecycle/step set differs')
    if calls:
        require({'app/function-bindings.jsonl', 'app/docker-function-bindings.jsonl'} <= bound.keys(),
            'separate application function ledgers missing')
        require(jsonl(timeline / 'app/function-bindings.jsonl') == list(calls.values())
            and jsonl(timeline / 'app/docker-function-bindings.jsonl') == list(docker.values()),
            'separate application function ledgers differ')
    for call_id, row in calls.items():
        lower, rpc, tool_step = docker[call_id], by_call[call_id], tool_steps[call_id]
        span = tools.get(row.get('tool_call_id'), {})
        require(all(row.get(key) == lower.get(key) for key in ('rpc_request_id', 'command', 'root', 'tool_call_id',
            'cgroup_id', 'begin_ns', 'end_ns', 'stdout_artifact', 'stderr_artifact', 'command_sha256', 'gate_result')),
            'Codex/Docker function ledgers differ')
        require(all(row.get(key) == span.get(key) for key in ('command', 'root', 'tool_call_id', 'cgroup_id', 'begin_ns', 'end_ns'))
            and row.get('gate_result') == span.get('result') and row.get('agent_id') == span.get('agent_id') == worker['agent_id']
            and row.get('boot_id') == boot_id and row.get('budget_label') == label
            and row.get('command_sha256') == budget.sha(row['command'].encode()), 'stopped Docker span differs from Codex binding')
        require(rpc.get('tool') == 'observer_bash' and rpc.get('namespace') in (None, '')
            and rpc.get('arguments') == {'command': row['command']} and rpc.get('threadId') == steps.get('thread_id') == row.get('thread_id')
            and rpc.get('turnId') == steps.get('turn_id') == row.get('turn_id') and rpc.get('_rpc_id') == row.get('rpc_request_id')
            and type(rpc.get('_rpc_id')) is type(row.get('rpc_request_id')), 'explicit Codex RPC command/ID differs')
        for name, field, limit in ((row['stdout_artifact'], 'stdout', 3500), (row['stderr_artifact'], 'stderr', 1000)):
            require(name in bound and read(timeline / name).decode()[:limit] == tool_step.get(field), 'recorded tool output differs')
        require(all(tool_step.get(key) == value for key, value in row.items()), 'tool step differs from enriched function binding')
        gate_result = span.get('result', {})
        if 'return_code' in gate_result:
            require(type(gate_result['return_code']) is int and tool_step.get('exit_code') == gate_result['return_code'],
                'Codex tool exit code differs from Docker result')
        else:
            require(isinstance(gate_result.get('error'), str) and gate_result['error'].startswith('TimeoutError:')
                and tool_step.get('exit_code') == 124, 'unclassified Docker failure is not a normal tool result')
    return manifest, steps, calls


def verify(group_root, ledger_path):
    root, ledger_path = Path(group_root).resolve(strict=True), Path(ledger_path).resolve(strict=True)
    campaign_path = root / 'campaign.json'
    campaign_identity, campaign = digest(campaign_path), load(campaign_path)
    concurrency = campaign.get('concurrency')
    require(campaign.get('schema_version') == 1 and campaign.get('benchmark') == 'Terminal-Bench'
        and concurrency in (2, 4, 6, 8) and len(campaign.get('jobs', [])) == 8, 'one equal-eight Terminal group required')
    replay, reservations, sources, ledger_identity, history = replay_budget(ledger_path)
    jobs, used_labels = [], set()
    for controller in campaign['jobs']:
        job_dir, timeline, worker = resolve_job(root, controller)
        worker_identity, manifest_identity = digest(job_dir / 'worker-result.json'), digest(timeline / 'manifest.json')
        label = worker.get('budget_label')
        require(label in replay.labels and label.startswith(f'codex-terminal-c{concurrency}-') and label not in used_labels,
            'worker must have its distinct registered concurrency/job budget label')
        require(worker.get('job_id') == replay.labels[label]['job_id'], 'worker job ID differs from registered budget job')
        used_labels.add(label)
        manifest, app, calls = bind_application(timeline, worker, controller, campaign.get('boot_id'), replay.config)
        records = {key: row for key, row in replay.requests.items() if row['task_label'] == label}
        expected_answers = [row['text'] for row in app.get('steps', []) if row.get('kind') == 'AGENT_MESSAGE' and row.get('text')]
        matched, answers, matched_sources, issues = {}, set(), [], []
        for key, record in records.items():
            source = sources.get(key)
            if record['event'] != 'SETTLED': issues.append('UNCERTAIN_OR_BOUND_EXCEEDED_PROVIDER_ACCOUNTING:' + key)
            if source is None:
                issues.append('PROVIDER_ORIGINAL_SSE_UNAVAILABLE:' + key); continue
            require(source['task_label'] == label, 'cross-job provider source')
            source_calls, source_answers = [], []
            for item in source['value'].get('output', []):
                if item.get('type') == 'function_call' and item.get('call_id') in calls:
                    call_id = item['call_id']
                    require(source['tool_policy_passed'] and item.get('name') == 'observer_bash'
                        and budget.parse_json(item['arguments']) == {'command': calls[call_id]['command']}, 'provider command differs from actual gated call')
                    require(call_id not in matched, 'duplicate provider function call')
                    matched[call_id] = key; source_calls.append(call_id)
                elif item.get('type') == 'message':
                    text = ''.join(part.get('text', '') for part in item.get('content', []) if part.get('type') == 'output_text')
                    if text in expected_answers:
                        answers.add(text); source_answers.append(text)
            matched_sources.append({**{key: value for key, value in source.items() if key != 'value'},
                'provider_response_id': source['value'].get('id'), 'model': source['value'].get('model'),
                'function_call_ids': source_calls, 'agent_message_matched': bool(source_answers)})
        if set(matched) != calls.keys(): issues.append('EXACT_PROVIDER_CALL_EVIDENCE_MISSING')
        if app.get('status') == 'completed' and (not expected_answers or not set(expected_answers) <= answers):
            issues.append('COMPLETED_TURN_FINAL_ANSWER_EVIDENCE_MISSING')
        if not records: issues.append('NO_PROVIDER_REQUEST_EVIDENCE')
        require(digest(job_dir / 'worker-result.json') == worker_identity and digest(timeline / 'manifest.json') == manifest_identity,
            'worker or manifest changed during provider verification')
        jobs.append({'job_id': worker['job_id'], 'task_id': worker['task_id'], 'budget_label': label,
            'agent_id': worker['agent_id'], 'run_id': manifest.get('run_id'), 'boot_id': manifest.get('boot_id'),
            'status': 'PROVIDER_BINDING_VERIFIED' if not issues else 'INCONCLUSIVE', 'issues': issues,
            'agent_turn_status': app.get('status'), 'model_termination': worker.get('model_termination'),
            'official_evaluated': worker.get('official_evaluated'), 'official_passed': worker.get('official_passed'),
            'official_result': worker.get('official_result'),
            'official_scoring_status': 'SCORED' if worker.get('official_evaluated') is True else 'UNSCORED',
            'manifest_identity': manifest_identity, 'worker_result_identity': worker_identity,
            'codex_binary_identity': manifest['codex_application']['runtime']['binary_identity'],
            'explicit_provider_call_ids': sorted(calls), 'matched_provider_call_ids': matched,
            'completed_final_answer_matched': app.get('status') == 'completed' and bool(expected_answers) and set(expected_answers) <= answers,
            'requests': len(records), 'cost_rmb_upper_bound': str(sum((budget.money(row['cost_rmb_bound']) for row in records.values()), Decimal(0))),
            'outstanding_or_unknown_requests': sum(row['event'] in ('RESERVED', 'UNKNOWN_CHARGE') for row in records.values()),
            'matched_provider_sources': matched_sources,
            'runtime_kernel_scope': 'CODEX_RUNTIME_NOT_CAPTURED; ONLY_GATED_TASK_CONTAINER_TOOL_TREES'})
    expected_labels = {f'codex-terminal-c{concurrency}-{index:02d}' for index in range(8)}
    require(used_labels == expected_labels, 'not all eight registered group jobs are present')
    groups = {}
    for count in (2, 4, 6, 8):
        records = [row for row in replay.requests.values() if row['task_label'].startswith(f'codex-terminal-c{count}-')]
        groups[str(count)] = {'requests': len(records), 'cost_rmb_upper_bound': str(sum(
            (budget.money(row['cost_rmb_bound']) for row in records), Decimal(0))),
            'outstanding_or_unknown_requests': sum(row['event'] in ('RESERVED', 'UNKNOWN_CHARGE') for row in records)}
    total = replay._committed()
    require(total <= replay.limit and history + total <= Decimal(5), 'provider budget exceeded')
    unknown = sum(row['event'] in ('RESERVED', 'UNKNOWN_CHARGE') for row in replay.requests.values())
    require(digest(ledger_path) == ledger_identity and digest(campaign_path) == campaign_identity,
        'ledger/campaign changed during verification; use one immutable final ledger')
    return {'schema_version': 1, 'status': 'PROVIDER_BINDING_VERIFIED' if not unknown and not replay.blocked
        and all(row['status'] == 'PROVIDER_BINDING_VERIFIED' for row in jobs) else 'INCONCLUSIVE',
        'benchmark': 'Terminal-Bench', 'concurrency': concurrency, 'jobs': jobs,
        'verifier_identity': digest(Path(__file__)), 'budget_verifier_identity': digest(Path(budget.__file__)),
        'campaign_identity': campaign_identity, 'budget_ledger_identity': ledger_identity,
        'campaign_id': replay.campaign_id, 'group_cost_rmb_upper_bound': groups[str(concurrency)]['cost_rmb_upper_bound'],
        'registration_kind': replay.config['registration_kind'], 'model_max_output_tokens': replay.config['max_output_tokens'],
        'reasoning_effort': replay.config.get('reasoning_effort'),
        'all_terminal_campaign_cost_rmb_upper_bound': str(total), 'historical_bound_rmb': str(history),
        'combined_cost_upper_bound_rmb': str(history + total), 'groups_accounting': groups,
        'outstanding_or_unknown_requests': unknown, 'budget_bound_exceeded': replay.blocked,
        'native_replay': 'SEPARATE_REQUIRED_CHECK_NOT_PERFORMED_BY_THIS_PROVIDER_VERIFIER',
        'raw_evidence_rewritten': False, 'official_result_reinterpreted': False,
        'trust_boundary': 'TRUSTED_LOCAL_PROXY_TLS_CAPTURE_AND_KERNEL; NOT_PROVIDER_SIGNATURE_OR_COMPROMISED_KERNEL_PROOF'}


def chain_ledger(path):
    """Read-only transition replay for the finite, explicitly supplied ancestry."""
    path = Path(path).resolve(strict=True)
    raw = read(path, budget.MAX_LEDGER)
    require(raw and raw.endswith(b'\n'), 'nonempty complete ancestry ledger required')
    rows = [budget.parse_json(line) for line in raw.splitlines()]
    config = rows[0].get('config', {})
    require(rows[0].get('event') == 'CONFIGURED' and config.get('schema_version') == 2
        and rows[0].get('config_sha256') == budget.sha(budget.canonical(config)), 'ancestry configuration digest differs')
    require(config.get('max_output_tokens') == budget.configured_output_limit(config)
        and config.get('provider_endpoint') in (proxy.ENDPOINT, 'https://api.deepseek.com/chat/completions'),
        'ancestry model/output contract differs')
    if config.get('registration_kind') == 'CODEX_TERMINAL_2468_V2':
        require(config.get('reasoning_effort') == 'none', 'ancestry V2 reasoning contract differs')
    pricing = config.get('pricing', {})
    require(pricing.get('model') == budget.MODEL and pricing.get('currency') == 'CNY'
        and budget.money(pricing.get('input_rmb_per_million')) == budget.INPUT_RATE
        and budget.money(pricing.get('output_rmb_per_million')) == budget.OUTPUT_RATE, 'ancestry rates differ')
    replay = object.__new__(budget.Ledger)
    replay.config, replay.config_sha256 = config, rows[0]['config_sha256']
    replay.limit = budget.money(config.get('global_limit_rmb'))
    history = budget.money(config.get('historical_bound_rmb'))
    require(history >= budget.HISTORY_RMB and Decimal(0) < replay.limit <= budget.GLOBAL_MAX
        and history + replay.limit <= Decimal(5), 'ancestry cumulative cap differs')
    registration = dict(config, schema_version=1)
    if not config.get('registration_kind'):
        registration['global_limit_rmb'] = str(budget.GLOBAL_MAX)
    replay.campaign_id, replay.labels = budget.registry(registration)
    replay.requests, replay.blocked = {}, False
    for event in rows[1:]: replay._apply(event)
    require(not replay.blocked and all(row['event'] == 'SETTLED' for row in replay.requests.values()),
        'ancestry retains uncertain/unsettled or bound-exceeded requests')
    cost = replay._committed()
    receipt = {'schema_version': 1, 'ledger_sha256': budget.sha(raw), 'ledger_bytes': len(raw),
        'campaign_id': replay.campaign_id, 'config_sha256': replay.config_sha256,
        'historical_bound_rmb': str(history), 'accounted_cost_rmb_upper_bound': str(cost),
        'combined_bound_rmb': str(history + cost), 'requests': len(replay.requests), 'outstanding_or_unknown_requests': 0}
    return replay, receipt, {'sha256': budget.sha(raw), 'size_bytes': len(raw)}


def seal_campaign(campaign_root, ledger_path, prior_ledgers, provider_receipts, closed_summary):
    """Fresh final receipt; never retires/reopens a broker or alters evidence."""
    root, ledger_path = Path(campaign_root).resolve(strict=True), Path(ledger_path).resolve(strict=True)
    ancestry = [ledger_path] + [Path(path).resolve(strict=True) for path in prior_ledgers]
    require(len(set(ancestry)) == len(ancestry), 'duplicate/cyclic ancestry ledger')
    locks = []
    try:
        for path in ancestry:
            descriptor = budget.private_fd(path.parent / 'broker.lock', os.O_RDONLY)
            locks.append(descriptor)
            try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise ValueError('broker is still active; cannot seal ledger') from None
        entries = [chain_ledger(path) for path in ancestry]
        chain = []
        for index, (replay, receipt, identity) in enumerate(entries):
            path = ancestry[index]
            if index + 1 < len(entries):
                prior_receipt = entries[index + 1][1]
                require(replay.config.get('prior_budget_evidence') == prior_receipt
                    and budget.money(receipt['historical_bound_rmb']) == budget.money(prior_receipt['combined_bound_rmb']),
                    'ancestry inherited receipt/cost differs')
                marker_path = ancestry[index + 1].parent / 'successor.json'
                marker = load(marker_path)
                require(marker == {'schema_version': 1, 'event': 'BUDGET_LEDGER_RETIRED_TO_EXACT_SUCCESSOR',
                    'prior_ledger_sha256': prior_receipt['ledger_sha256'], 'successor_directory': str(path.parent),
                    'successor_config_sha256': replay.config_sha256}, 'ancestry retirement marker differs')
            else:
                require(replay.config.get('prior_budget_evidence') is None
                    and budget.money(receipt['historical_bound_rmb']) == budget.HISTORY_RMB,
                    'supplied ancestry does not reach the explicit historical reserve')
            chain.append({'path': str(path), 'identity': identity, 'registration_kind': replay.config.get('registration_kind'),
                'replayed_budget_receipt': receipt})
        replay, _, sources, identity, history = replay_budget(ledger_path)
        require(replay.config.get('registration_kind') == 'CODEX_TERMINAL_2468_V2'
            and set(row['task_label'] for row in replay.requests.values()) == set(replay.labels),
            'final V2 ledger must contain all32 registered jobs')
        summary_path = Path(closed_summary).resolve(strict=True)
        require(summary_path.parent == ledger_path.parent, 'final summary must be from this broker directory')
        summary = load(summary_path)
        require(summary.get('config_sha256') == replay.config_sha256 and summary.get('campaign_id') == replay.campaign_id
            and summary.get('requests') == len(replay.requests) and summary.get('outstanding_or_unknown_requests') == 0
            and summary.get('blocked') is False and budget.money(summary.get('accounted_cost_rmb_upper_bound')) == replay._committed()
            and budget.money(summary.get('historical_bound_rmb')) == history
            and budget.money(summary.get('combined_bound_rmb')) == history + replay._committed(),
            'closed broker summary differs from independent final replay')
        receipts, groups, job_labels, request_ids = [], {}, set(), set()
        require(len(provider_receipts) == 4, 'four final group provider receipts required')
        for receipt_path in provider_receipts:
            receipt_path = Path(receipt_path).resolve(strict=True)
            value = load(receipt_path); count = value.get('concurrency')
            require(count in (2, 4, 6, 8) and count not in groups and value.get('status') == 'PROVIDER_BINDING_VERIFIED'
                and value.get('budget_ledger_identity') == identity and value.get('campaign_id') == replay.campaign_id,
                'group provider receipt is interim, incomplete or for another final ledger')
            group_root = root / f'terminal-c{count}-r001'
            require(digest(group_root / 'campaign.json') == value.get('campaign_identity') and len(value.get('jobs', [])) == 8,
                'group provider receipt campaign identity differs')
            unscored, passed, scored, request_count, cost = [], 0, 0, 0, Decimal(0)
            for job in value['jobs']:
                label = job.get('budget_label')
                require(label in replay.labels and label not in job_labels and job.get('status') == 'PROVIDER_BINDING_VERIFIED',
                    'final provider job missing/duplicated')
                job_labels.add(label)
                worker_path = group_root / 'jobs' / job['job_id'] / 'worker-result.json'
                worker = load(worker_path)
                timeline = worker_path.parent / worker['timeline_directory']
                require(digest(worker_path) == job['worker_result_identity']
                    and digest(timeline / 'manifest.json') == job['manifest_identity']
                    and job.get('official_result') == worker.get('official_result')
                    and job.get('official_evaluated') == worker.get('official_evaluated')
                    and job.get('official_passed') == worker.get('official_passed'),
                    'final provider job/official score source changed')
                if worker.get('official_evaluated') is True:
                    scored += 1; passed += worker.get('official_passed') is True
                else:
                    exception = (worker.get('official_result') or {}).get('harbor_exception') or {}
                    unscored.append({'job_id': job['job_id'], 'task_id': job['task_id'], 'score': None,
                        'exception_type': exception.get('exception_type'), 'exception_message': exception.get('exception_message')})
                request_count += job['requests']; cost += budget.money(job['cost_rmb_upper_bound'])
                for source in job['matched_provider_sources']:
                    key = source['request_id']
                    require(key not in request_ids and sources[key]['task_label'] == label
                        and source['source_identity'] == sources[key]['source_identity']
                        and source['normalized_request_identity'] == sources[key]['normalized_request_identity'],
                        'final provider request evidence duplicate/cross-job/digest mismatch')
                    request_ids.add(key)
            require(budget.money(value['group_cost_rmb_upper_bound']) == cost, 'final provider group fee differs')
            groups[str(count)] = {'jobs': 8, 'requests': request_count, 'cost_rmb_upper_bound': str(cost),
                'official_scored': scored, 'official_passed': passed, 'official_unscored': unscored,
                'score_note': 'UNSCORED_IS_NOT_A_ZERO_SCORE; PROVIDER_BINDING_IS_NOT_TASK_SUCCESS'}
            receipts.append({'concurrency': count, 'path': str(receipt_path), 'identity': digest(receipt_path)})
        require(job_labels == set(replay.labels) and request_ids == set(replay.requests), 'final32jobs/request coverage incomplete')
        for path, (_, _, expected) in zip(ancestry, entries):
            require(digest(path) == expected, 'ancestry ledger changed while sealed')
        costs = replay._committed()
        evidence = [{'request_id': key, 'task_label': replay.requests[key]['task_label'],
            'request_sha256': sources[key]['normalized_request_identity']['sha256'],
            'request_identity': sources[key]['normalized_request_identity'], 'provider_sse_identity': sources[key]['source_identity'],
            'response_receipt_identity': sources[key]['response_receipt_identity'],
            'prompt_tokens': replay.requests[key]['prompt_tokens'], 'completion_tokens': replay.requests[key]['completion_tokens'],
            'cost_rmb_upper_bound': replay.requests[key]['cost_rmb_bound']} for key in sorted(request_ids)]
        return {'schema_version': 1, 'status': 'CLOSED_LEDGER_CHAIN_AND_FOUR_GROUP_PROVIDER_BINDINGS_VERIFIED',
            'verifier_identity': digest(Path(__file__)), 'budget_verifier_identity': digest(Path(budget.__file__)),
            'campaign_id': replay.campaign_id, 'budget_ledger_identity': identity, 'closed_summary_identity': digest(summary_path),
            'closed_summary_path': str(summary_path), 'closed_broker_lock_available_at_verification': True,
            'closure_scope': 'POINT_IN_TIME_EXCLUSIVE_ADVISORY_LOCK; NOT_PERMANENT_BROKER_DISABLEMENT',
            'formal_jobs': len(job_labels), 'formal_reserved_requests': len(request_ids), 'formal_settled_requests': len(request_ids),
            'outstanding_or_unknown_requests': 0, 'formal_cost_rmb_upper_bound': str(costs), 'historical_bound_rmb': str(history),
            'combined_cost_rmb_upper_bound': str(history + costs), 'remaining_user_budget_rmb': str(Decimal(5) - history - costs),
            'replayed_ancestry_newest_first': chain, 'unreplayed_preexisting_historical_reserve_rmb': str(budget.HISTORY_RMB),
            'group_provider_receipts': sorted(receipts, key=lambda row: row['concurrency']), 'groups': groups,
            'formal_request_evidence': evidence, 'api_calls_performed_by_verifier': 0,
            'raw_evidence_rewritten': False, 'official_result_reinterpreted': False,
            'native_replay': 'SEPARATE_REQUIRED_CHECK_NOT_PERFORMED_BY_THIS_PROVIDER_VERIFIER',
            'trust_boundary': 'TRUSTED_LOCAL_PROXY_TLS_CAPTURE_AND_KERNEL; NOT_PROVIDER_SIGNATURE_OR_COMPROMISED_KERNEL_PROOF'}
    finally:
        for descriptor in reversed(locks): os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--group-root', type=Path)
    source.add_argument('--seal-campaign-root', type=Path)
    parser.add_argument('--budget-ledger', required=True, type=Path)
    parser.add_argument('--prior-ledger', type=Path, action='append', default=[])
    parser.add_argument('--provider-receipt', type=Path, action='append', default=[])
    parser.add_argument('--closed-summary', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.seal_campaign_root:
        require(args.closed_summary is not None, 'explicit closed broker summary required')
        result = seal_campaign(args.seal_campaign_root, args.budget_ledger, args.prior_ledger,
            args.provider_receipt, args.closed_summary)
    else:
        require(not args.prior_ledger and not args.provider_receipt and args.closed_summary is None, 'seal arguments require seal mode')
        result = verify(args.group_root, args.budget_ledger)
    write_new(args.output, result)
    print(json.dumps({key: result[key] for key in ('status', 'concurrency', 'group_cost_rmb_upper_bound',
        'all_terminal_campaign_cost_rmb_upper_bound', 'combined_cost_upper_bound_rmb', 'outstanding_or_unknown_requests',
        'formal_jobs', 'formal_reserved_requests', 'formal_cost_rmb_upper_bound', 'combined_cost_rmb_upper_bound') if key in result}))


if __name__ == '__main__':
    main()
