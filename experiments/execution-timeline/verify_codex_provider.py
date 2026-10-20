#!/usr/bin/env python3
"""Bind a small real Codex run to the trusted local proxy's saved provider SSE.

No API call, no execution, no rewrite of original evidence. Native replay is a
separate prerequisite. The proxy/TLS collector and source kernel remain trust
assumptions; this is not a cryptographic proof of provider or kernel honesty.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import json
from pathlib import Path
import sys

from codex_view import compose
from common import digest, write_new

sys.path.insert(0, str(Path(__file__).resolve().parent.parent/'agent-benchmarks'))
import model_budget_v2 as budget


def require(condition, message):
    if not condition: raise ValueError(message)


def terminals(raw):
    values = []
    for part in raw.replace(b'\r\n', b'\n').split(b'\n\n'):
        data = b'\n'.join(line[5:].lstrip(b' ') for line in part.splitlines() if line.startswith(b'data:'))
        if not data or data == b'[DONE]': continue
        item = json.loads(data)
        if item.get('type') in ('response.completed', 'response.incomplete', 'response.failed'):
            values.append(item['response'])
    require(len(values) == 1, 'one terminal provider response required')
    return values[0]


def verify(run_dir, ledger_path):
    root, ledger_path = Path(run_dir).resolve(strict=True), Path(ledger_path).resolve(strict=True)
    compose(root)  # Checks manifest-bound steps, gate roots, output and replay digest.
    manifest = json.loads((root/'manifest.json').read_bytes())
    app = json.loads((root/'app/steps.json').read_bytes())
    require(app['status'] == 'completed', 'Codex turn did not complete')
    required_calls = {row['call_id'] for row in app['function_bindings']}
    require(required_calls, 'no actual command was dispatched')
    expected_answers = [row['text'] for row in app['steps'] if row['kind'] == 'AGENT_MESSAGE' and row.get('text')]
    rows = [json.loads(line) for line in ledger_path.read_bytes().splitlines()]
    require(rows and rows[0]['event'] == 'CONFIGURED', 'configured proxy budget ledger required')
    config = rows[0]['config']
    require(config.get('registration_kind') == 'CODEX_OBSERVER_DEMO'
        and config.get('provider_endpoint') == 'https://api.deepseek.com/responses', 'real provider proxy contract differs')
    configured_sha = rows[0]['config_sha256']
    require(configured_sha == budget.sha(budget.canonical(config)), 'budget configuration digest differs')
    replay = object.__new__(budget.Ledger)
    replay.config, replay.config_sha256 = config, configured_sha
    replay.limit = budget.money(config['global_limit_rmb'])
    replay.campaign_id, replay.labels = budget.registry(dict(config, schema_version=1))
    replay.requests, replay.blocked = {}, False
    for row in rows[1:]: replay._apply(row)
    reserved, settled = {}, {}
    for row in rows[1:]:
        require(row['config_sha256'] == configured_sha, 'ledger configuration binding differs')
        key = row['request_id']
        if row['event'] == 'RESERVED':
            require(key not in reserved, 'duplicate reservation')
            reserved[key] = row
        else:
            require(key in reserved and key not in settled, 'missing/duplicate reservation settlement')
            settled[key] = row
    require(reserved.keys() == settled.keys() and all(row['event'] == 'SETTLED' for row in settled.values()),
            'unsettled or uncertain provider fee remains')
    matched_calls, matched_answers, sources = {}, {}, []
    for key, record in settled.items():
        receipt_file = ledger_path.parent/(key+'-response.json')
        receipt = json.loads(receipt_file.read_bytes())
        source = ledger_path.parent/(key+'-upstream.sse')
        require(receipt['response_sha256'] == digest(source)['sha256'] and receipt['response_bytes'] == source.stat().st_size
            and receipt['request_sha256'] == reserved[key]['request_sha256']
            and receipt['upstream_endpoint'] == config['provider_endpoint'], 'provider source binding differs')
        value = terminals(source.read_bytes())
        require(value['usage']['input_tokens'] == record['prompt_tokens']
            and value['usage']['output_tokens'] == record['completion_tokens'], 'provider usage differs from ledger')
        calls, answers = [], []
        for item in value.get('output', []):
            if item.get('type') == 'function_call' and item.get('call_id') in required_calls:
                require(item.get('name') == 'observer_bash', 'provider selected an unapproved tool')
                binding = next(row for row in app['function_bindings'] if row['call_id'] == item['call_id'])
                require(json.loads(item['arguments']) == {'command': binding['command']}, 'provider command differs from actual gated command')
                require(item['call_id'] not in matched_calls, 'same provider call appears twice')
                matched_calls[item['call_id']] = key; calls.append(item['call_id'])
            if item.get('type') == 'message':
                text = ''.join(part.get('text', '') for part in item.get('content', []) if part.get('type') == 'output_text')
                if text in expected_answers:
                    matched_answers[text] = key; answers.append(text)
        if calls or answers:
            sources.append({'request_id': key, 'function_call_ids': calls, 'final_answer_matched': bool(answers),
                'provider_response_id': value.get('id'), 'model': value.get('model'), 'source': str(source),
                'source_identity': digest(source), 'response_receipt_identity': digest(receipt_file),
                'request_sha256': record.get('request_sha256', reserved[key]['request_sha256']),
                'cost_rmb_upper_bound': record['cost_rmb_bound']})
    require(set(matched_calls) == required_calls and expected_answers and set(expected_answers) <= matched_answers.keys(),
        'missing exact provider function/answer evidence; configuration alone cannot prove real inference')
    total = sum((Decimal(row['cost_rmb_bound']) for row in settled.values()), Decimal(0))
    history = Decimal(config['historical_bound_rmb'])
    require(total <= Decimal(config['global_limit_rmb']) and history+total <= Decimal(5), 'budget exceeded')
    return {'schema_version': 1, 'status': 'REAL_CODEX_PROVIDER_COMMAND_AND_FINAL_ANSWER_BOUND',
        'verifier_identity': digest(Path(__file__)), 'budget_verifier_identity': digest(Path(budget.__file__)),
        'run_id': manifest['run_id'], 'manifest_identity': digest(root/'manifest.json'),
        'codex_binary_identity': manifest['codex_identity'], 'agent_loop': app['agent_loop'],
        'tool_mode': 'OFFICIAL_CODEX_APP_SERVER_WITH_CONTROLLED_OBSERVER_BASH_DYNAMIC_TOOL',
        'explicit_provider_call_ids': sorted(required_calls), 'matched_provider_sources': sources,
        'budget_ledger_identity': digest(ledger_path), 'this_completed_run_cost_upper_bound_rmb': str(sum(
            (Decimal(row['cost_rmb_upper_bound']) for row in sources), Decimal(0))),
        'all_demo_attempts_cost_upper_bound_rmb': str(total), 'historical_bound_rmb': str(history),
        'combined_cost_upper_bound_rmb': str(history+total), 'outstanding_or_unknown_requests': 0,
        'benchmark_run': False, 'raw_evidence_rewritten': False,
        'trust_boundary': 'TRUSTED_LOCAL_PROXY_TLS_CAPTURE_AND_KERNEL; NOT_PROVIDER_SIGNATURE_OR_COMPROMISED_KERNEL_PROOF'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', required=True, type=Path)
    parser.add_argument('--budget-ledger', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = verify(args.run_dir, args.budget_ledger); write_new(args.output, result)
    print(json.dumps({key: result[key] for key in ('status', 'this_completed_run_cost_upper_bound_rmb',
        'all_demo_attempts_cost_upper_bound_rmb', 'combined_cost_upper_bound_rmb')}))


if __name__ == '__main__': main()
