#!/usr/bin/env python3
"""Direct Responses proxy for genuine Codex; no custom Agent loop.

Only this Host process reads the DeepSeek key. All requests are durably
reserved before a single upstream invocation. Demo mode is three requests/.4
CNY. Terminal mode fixes32 jobs across2/4/6/8,12 requests/.125 CNY per job and
4 CNY total. Terminal-v2 uses4096 output tokens and reasoning.effort=none,
.2 CNY per job, while retaining the same4 CNY shared cap (not32*.2). A closed
predecessor is charged and exclusively locked, and
history plus the new cap may never exceed5 CNY. SSE is buffered (not
synthesized) until final usage is accounted.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
import time
import urllib.request

import model_budget_v2 as B

LABEL = 'codex-smoke-001'
ENDPOINT = 'https://api.deepseek.com/responses'
MAX_REQUESTS, MAX_RESPONSE = 3, 4 * 1024 * 1024
TERMINAL_MAX_REQUESTS, TERMINAL_LIMIT = 12, '4.0'
ALLOWED = {'model', 'input', 'instructions', 'tools', 'tool_choice', 'parallel_tool_calls',
    'stream', 'store', 'max_output_tokens', 'reasoning', 'text', 'include', 'previous_response_id',
    'service_tier', 'prompt_cache_key', 'metadata', 'client_metadata', 'temperature', 'top_p', 'truncation'}


def registration(campaign_id, mode='demo'):
    if mode in ('terminal', 'terminal-v2'):
        return {'schema_version': 1, 'campaign_id': campaign_id,
            'registration_kind': 'CODEX_TERMINAL_2468_V2' if mode == 'terminal-v2' else 'CODEX_TERMINAL_2468',
            'global_limit_rmb': TERMINAL_LIMIT,
            'labels': [{'label': f'codex-terminal-c{concurrency}-{index:02d}', 'kind': 'CODEX_TERMINAL',
                'group_id': f'codex-terminal-c{concurrency}', 'job_id': f'terminal-{index:02d}',
                'cap_rmb': '.2' if mode == 'terminal-v2' else '.125'}
                for concurrency in (2, 4, 6, 8) for index in range(8)]}
    B.require(mode == 'demo', 'explicit demo, terminal or terminal-v2 mode required')
    return {'schema_version': 1, 'campaign_id': campaign_id,
        'registration_kind': 'CODEX_OBSERVER_DEMO', 'global_limit_rmb': '.4',
        'labels': [{'label': LABEL, 'kind': 'CODEX_DEMO', 'group_id': 'codex-demo',
                    'job_id': 'demo-001', 'cap_rmb': '.4'}]}


def normalize(raw, known_reasoning=None, *, max_output_tokens=1024, reasoning_effort=None):
    known_reasoning = known_reasoning or {}
    B.require(0 < len(raw) <= B.MAX_BODY, 'bounded Responses body required')
    data = B.parse_json(raw)
    B.require(isinstance(data, dict) and not set(data) - ALLOWED and data.get('model') == B.MODEL,
        'unapproved Responses parameter/model')
    B.require((max_output_tokens, reasoning_effort) in ((1024, None), (4096, 'none')),
        'explicit versioned output/reasoning policy required')
    if reasoning_effort is not None:
        B.require(isinstance(data.get('reasoning'), dict) and data['reasoning'].get('effort') == reasoning_effort,
            'Terminal V2 requires explicit reasoning.effort=none; low/missing effort is rejected')
    B.require(isinstance(data.get('input'), (str, list)) and (not isinstance(data['input'], list) or len(data['input']) <= 256)
        and data.get('stream', True) is True
        and data.get('store', False) is False and data.get('previous_response_id') is None,
        'stateless streamed local conversation required')
    B.require(data.get('service_tier') in (None, 'default'), 'unpriced service tier rejected')
    if 'client_metadata' in data:
        metadata = data['client_metadata']
        B.require(isinstance(metadata, dict) and len(metadata) <= 64
            and all(isinstance(key, str) and type(value) in (str, int, float, bool, type(None))
                    for key, value in metadata.items()), 'bounded scalar client metadata required')
    # A short image/file/URL descriptor can expand into arbitrarily many paid
    # tokens. Only explicit inline text and local tool history are admissible.
    def text_content(value, allowed):
        if isinstance(value, str): return True
        return isinstance(value, list) and all(isinstance(part, dict) and part.get('type') in allowed
            and isinstance(part.get('text'), str)
            and not set(part) - {'type', 'text', 'annotations', 'logprobs'} for part in value)
    def input_item(item):
        if not isinstance(item, dict): return False
        kind = item.get('type', 'message')
        if kind == 'message':
            return (not set(item) - {'type', 'id', 'role', 'content', 'status', 'phase'}
                and item.get('role') in ('user', 'assistant', 'system', 'developer')
                and text_content(item.get('content'), {'input_text', 'output_text'}))
        if kind == 'function_call':
            return (not set(item) - {'type', 'id', 'call_id', 'name', 'arguments', 'status', 'namespace'}
                and isinstance(item.get('name'), str) and isinstance(item.get('arguments'), str))
        if kind == 'custom_tool_call':
            return (not set(item) - {'type', 'id', 'call_id', 'name', 'input', 'status', 'namespace'}
                and isinstance(item.get('name'), str) and isinstance(item.get('input'), str))
        if kind in ('function_call_output', 'custom_tool_call_output'):
            return (not set(item) - {'type', 'id', 'call_id', 'output', 'status'}
                and isinstance(item.get('call_id'), str) and text_content(item.get('output'), {'input_text', 'output_text'}))
        if kind == 'reasoning':
            opaque = item.get('encrypted_content')
            binding = known_reasoning.get(opaque) if isinstance(opaque, str) else None
            known = (opaque is None or isinstance(binding, dict) and item.get('id') in (None, binding.get('id'))
                and type(binding.get('context_tokens_bound')) is int and 0 < binding['context_tokens_bound'] <= 262144)
            return (not set(item) - {'type', 'id', 'summary', 'content', 'status', 'encrypted_content'}
                and known and text_content(item.get('summary') or [], {'summary_text'})
                and text_content(item.get('content') or [], {'reasoning_text'}))
        return False
    B.require(isinstance(data['input'], str) or all(input_item(item) for item in data['input']),
        'inline text/local tool history only; opaque history must match this ledger provider response')
    tools = data.get('tools', [])
    B.require(isinstance(tools, list) and len(tools) <= 16, 'bounded local tools required')
    # Codex can expose local function/custom tools. Never admit a provider-side
    # web/search/image/MCP/hosted tool with a separate charging model.
    def local(tool, depth=0):
        if not isinstance(tool, dict): return False
        if depth > 4: return False
        if tool.get('type') == 'namespace':
            return isinstance(tool.get('tools'), list) and len(tool['tools']) <= 16 and all(local(item, depth+1) for item in tool['tools'])
        return tool.get('type') in ('function', 'custom')
    B.require(all(local(tool) for tool in tools), 'only locally executed Codex tools permitted')
    selected = [tool for tool in tools if tool.get('type') == 'function' and tool.get('name') == 'observer_bash']
    B.require(len(selected) == 1, 'exactly one observer_bash dynamic function required')
    # Codex still advertises some built-ins even when feature flags are off.
    # This application-owned mode intentionally exposes one controlled tool,
    # not the CLI's complete default toolset. Codex still owns the Agent loop.
    data['tools'] = selected
    data.update(stream=True, store=False, max_output_tokens=max_output_tokens)
    data.pop('previous_response_id', None)
    data.pop('service_tier', None)
    # No encrypted or remote state is admitted on later calls either.
    data.pop('include', None)
    # The selected provider's saved model catalog supports low reasoning. Its
    # output (including reasoning) is bounded by max_output_tokens; do not count
    # reasoning tokens twice when settling usage.
    payload = B.canonical(data)
    B.require(len(payload) <= B.MAX_BODY, 'normalized body exceeds bound')
    return payload


def response_usage(raw):
    """Return a single genuine terminal response; reject conflicting terminals."""
    terminals = []
    for event in raw.replace(b'\r\n', b'\n').split(b'\n\n'):
        data = b'\n'.join(line[5:].lstrip(b' ') for line in event.splitlines() if line.startswith(b'data:'))
        if not data or data == b'[DONE]': continue
        value = B.parse_json(data)
        if value.get('type') in ('response.completed', 'response.incomplete', 'response.failed'):
            response = value.get('response')
            B.require(isinstance(response, dict), 'terminal response object required')
            terminals.append(response)
    B.require(len(terminals) == 1, 'exactly one terminal response required')
    result = terminals[0]; usage = result.get('usage')
    if not isinstance(usage, dict): return None, result.get('model')
    mapped = {'prompt_tokens': usage.get('input_tokens'), 'completion_tokens': usage.get('output_tokens')}
    if 'total_tokens' in usage: mapped['total_tokens'] = usage['total_tokens']
    return mapped, result.get('model')


def controlled_output(raw):
    """Check the complete buffered stream before Codex can execute any tool."""
    for event in raw.replace(b'\r\n', b'\n').split(b'\n\n'):
        data = b'\n'.join(line[5:].lstrip(b' ') for line in event.splitlines() if line.startswith(b'data:'))
        if not data or data == b'[DONE]': continue
        value = B.parse_json(data)
        items = []
        if isinstance(value.get('item'), dict): items.append(value['item'])
        if isinstance(value.get('response'), dict): items.extend(value['response'].get('output', []))
        for item in items:
            if not isinstance(item, dict): return False
            kind = item.get('type')
            if kind == 'function_call':
                if item.get('name') != 'observer_bash': return False
            elif kind not in ('message', 'reasoning'): return False
    return True


def reasoning_handles(raw):
    """Only handles emitted in a genuine, bounded, terminal provider response."""
    handles = {}
    for event in raw.replace(b'\r\n', b'\n').split(b'\n\n'):
        data = b'\n'.join(line[5:].lstrip(b' ') for line in event.splitlines() if line.startswith(b'data:'))
        if not data or data == b'[DONE]': continue
        value = B.parse_json(data)
        if value.get('type') not in ('response.completed', 'response.incomplete'): continue
        for item in value.get('response', {}).get('output') or []:
            if item.get('type') == 'reasoning' and isinstance(item.get('encrypted_content'), str) and isinstance(item.get('id'), str):
                handles[item['encrypted_content']] = item['id']
    return handles


class Broker(B.Broker):
    def __init__(self, address, ledger, provider_key, client_token):
        self.ledger, self.provider_key, self.client_token = ledger, provider_key, client_token
        kind = ledger.config.get('registration_kind')
        B.require(kind in ('CODEX_OBSERVER_DEMO', 'CODEX_TERMINAL_2468', 'CODEX_TERMINAL_2468_V2'), 'explicit Codex registry required')
        B.require(ledger.config.get('provider_endpoint') == ENDPOINT, 'real Responses endpoint ledger required')
        self.max_requests_per_job = MAX_REQUESTS if kind == 'CODEX_OBSERVER_DEMO' else TERMINAL_MAX_REQUESTS
        self.max_output_tokens = B.configured_output_limit(ledger.config)
        self.reasoning_effort = 'none' if kind == 'CODEX_TERMINAL_2468_V2' else None
        B.require(ledger.config.get('max_output_tokens') == self.max_output_tokens
            and (self.reasoning_effort is None or ledger.config.get('reasoning_effort') == self.reasoning_effort),
            'ledger output/reasoning contract differs')
        self.demo_lock = threading.Lock()
        reservations = {row['request_id']: row for row in
            (B.parse_json(line) for line in ledger.path.read_bytes().splitlines()) if row.get('event') == 'RESERVED'}
        self.demo_hashes = {(row['task_label'], row['request_sha256']) for row in reservations.values()}
        self.known_reasoning = {}
        for key, record in ledger.requests.items():
            if record['event'] != 'SETTLED': continue
            evidence = ledger.directory/(key+'-response.json')
            raw_file = ledger.directory/(key+'-upstream.sse')
            if not evidence.exists() or not raw_file.exists(): continue
            meta = B.parse_json(evidence.read_bytes()); raw = raw_file.read_bytes()
            B.require(len(raw) <= MAX_RESPONSE and B.sha(raw) == meta.get('response_sha256'), 'prior provider SSE changed')
            if controlled_output(raw): self.remember_reasoning(raw, reservations[key])
        B.ThreadingHTTPServer.__init__(self, address, Handler)

    def remember_reasoning(self, raw, reservation):
        # Do not assume an opaque handle contains ONLY visible output. Reserve
        # its entire source request context PLUS its capped output. A nested
        # source's input bound already contains every earlier opaque expansion.
        bound = reservation['input_tokens_bound'] + reservation['output_tokens_bound']
        for handle, item_id in reasoning_handles(raw).items():
            existing = self.known_reasoning.get(handle)
            B.require(existing is None or existing['id'] == item_id
                and existing['task_label'] == reservation.get('task_label', LABEL),
                'ambiguous provider reasoning handle or cross-job reuse')
            if existing is not None and existing['context_tokens_bound'] >= bound: continue
            self.known_reasoning[handle] = {'id': item_id, 'context_tokens_bound': bound,
                'task_label': reservation.get('task_label', LABEL),
                'source_request_id': reservation['request_id'], 'source_response_sha256': B.sha(raw)}

    def upstream(self, payload):
        request = urllib.request.Request(ENDPOINT, data=payload, method='POST',
            headers={'Authorization': 'Bearer '+self.provider_key, 'Content-Type': 'application/json',
                     'Accept': 'text/event-stream'})
        # No retry, redirect or implicit environment proxy. The model account
        # is contacted only once for each prior durable reservation.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), B.NoRedirect())
        with opener.open(request, timeout=180) as response:
            body = response.read(MAX_RESPONSE+1)
            B.require(response.headers.get_content_type() == 'text/event-stream', 'provider must return SSE')
        B.require(len(body) <= MAX_RESPONSE, 'provider SSE exceeds bound')
        return body

    def persist_request(self, item, payload):
        """V2 only: preserve the exact normalized bytes before any paid call."""
        if self.reasoning_effort is None:
            return
        B.require(B.sha(payload) == item['request_sha256'], 'outbound request differs from durable reservation')
        path = self.ledger.directory / (item['request_id'] + '-request.json')
        descriptor = B.private_fd(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        directory_fd = os.open(self.ledger.directory, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)


class Handler(B.Handler):
    def do_POST(self):
        if self.path != '/v1/responses': return self.reply(404, {'error': 'RESPONSES_ONLY'})
        if not secrets.compare_digest(self.headers.get('Authorization', ''), 'Bearer '+self.server.client_token):
            return self.reply(401, {'error': 'invalid local broker credential'})
        raw = b''
        try:
            B.require(len(self.headers.get_all('Content-Length', [])) == 1 and not self.headers.get('Transfer-Encoding'), 'unambiguous length required')
            length = int(self.headers.get('Content-Length', '0'))
            label = self.headers.get('X-Benchmark-Task', '')
            B.require(0 < length <= B.MAX_BODY and len(self.headers.get_all('X-Benchmark-Task', [])) == 1
                and label in self.server.ledger.labels, 'one registered bounded Codex task label required')
            self.connection.settimeout(15)
            raw = self.rfile.read(length)
            B.require(len(raw) == length, 'incomplete request')
            ledger = self.server.ledger
            with self.server.demo_lock:
                known = {handle: binding for handle, binding in self.server.known_reasoning.items()
                    if binding['task_label'] == label}
                payload = normalize(raw, known, max_output_tokens=self.server.max_output_tokens,
                    reasoning_effort=self.server.reasoning_effort)
                items = B.parse_json(payload)['input']
                references = [item['encrypted_content'] for item in items
                    if isinstance(item, dict) and item.get('type') == 'reasoning' and item.get('encrypted_content')] if isinstance(items, list) else []
                previous = [row for row in ledger.requests.values() if row['task_label'] == label]
                B.require(len(previous) < self.server.max_requests_per_job, 'registered per-job request limit reached')
                B.require((label, B.sha(payload)) not in self.server.demo_hashes, 'duplicate request never retransmitted')
                step = len(previous)
                # Count the full bounded source context+output per occurrence,
                # including duplicates. Unknown handles can never reach here.
                extra = sum(known[handle]['context_tokens_bound'] for handle in references)
                item = ledger.reserve(payload, self.server.max_output_tokens, label, label+'-step-'+str(step),
                    extra_input_tokens=extra)
                self.server.demo_hashes.add((label, B.sha(payload)))
        except (ValueError, B.BudgetError, TimeoutError) as error:
            # A rejected request never reaches upstream; preserve the bounded
            # body privately (no HTTP Authorization header) for offline fixes.
            if raw and len(raw) <= B.MAX_BODY:
                try:
                    B.write_new_private(self.server.ledger.directory/('request-rejected-'+str(time.time_ns())+'.json'),
                        {'schema_version': 1, 'forwarded_or_charged': False, 'reason': str(error)[:256],
                         'request_sha256': B.sha(raw), 'request_body': B.parse_json(raw)})
                except (ValueError, OSError): pass
            return self.reply(429, {'error': 'CODEX_POLICY_OR_BUDGET_LIMIT', 'retry_allowed': False})
        try:
            self.server.persist_request(item, payload)
            body = self.server.upstream(payload)
            # Preserve exactly the bounded upstream SSE before settlement and
            # delivery. It contains model text, never the Authorization header.
            response_file = ledger.directory/(item['request_id']+'-upstream.sse')
            descriptor = B.private_fd(response_file, os.O_WRONLY|os.O_CREAT|os.O_EXCL)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(body); stream.flush(); os.fsync(stream.fileno())
            B.write_new_private(ledger.directory/(item['request_id']+'-response.json'),
                {'schema_version': 1, 'request_id': item['request_id'], 'request_sha256': item['request_sha256'],
                 'response_file': response_file.name, 'response_sha256': B.sha(body), 'response_bytes': len(body),
                 'upstream_endpoint': ENDPOINT, 'forwarding': 'IDENTICAL_SSE_BYTES_NO_AGENT_LOOP_OR_TOOL_EXECUTION'})
            directory_fd = os.open(ledger.directory, os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
            usage, model = response_usage(body)
        except Exception as error:
            ledger.unknown(item, type(error).__name__)
            return self.reply(502, {'error': 'UPSTREAM_UNKNOWN_RESERVATION_RETAINED', 'retry_allowed': False})
        status = ledger.settle(item, usage, model)
        if status == 'BOUND_EXCEEDED': return self.reply(502, {'error': 'TOKEN_BOUND_EXCEEDED_STOPPED'})
        if not controlled_output(body):
            return self.reply(502, {'error': 'UNAPPROVED_MODEL_TOOL_NOT_DELIVERED_TO_CODEX', 'retry_allowed': False})
        if status == 'SETTLED':
            with self.server.demo_lock: self.server.remember_reasoning(body, item)
        self.send_response(200); self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--api-key-file', type=Path, required=True)
    parser.add_argument('--pricing-evidence', type=Path, required=True)
    parser.add_argument('--prior-ledger', type=Path, required=True)
    parser.add_argument('--campaign-id', required=True)
    parser.add_argument('--mode', choices=('demo', 'terminal', 'terminal-v2'), default='demo',
        help='demo:3calls/.4 CNY; terminal:32jobs/1024 output/.125 perjob; terminal-v2:4096 output/none/.2 perjob; both terminal modes4 CNY shared/12calls perjob')
    parser.add_argument('--port', type=int, default=10091)
    args = parser.parse_args()
    limit = '.4' if args.mode == 'demo' else TERMINAL_LIMIT
    ledger = B.Ledger(args.output_dir, registration(args.campaign_id, args.mode), B.read_pricing(args.pricing_evidence), limit, args.prior_ledger,
        provider_endpoint=ENDPOINT)
    # Record the exact Responses protocol/endpoint and broker source before any
    # paid call; these do not alter the genuine Codex Agent loop.
    stamp = str(time.time_ns()); server = None
    try:
        token_file = args.output_dir/'client-token'
        if not token_file.exists():
            descriptor = B.private_fd(token_file, os.O_WRONLY|os.O_CREAT|os.O_EXCL)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(secrets.token_hex(32)+'\n'); stream.flush(); os.fsync(stream.fileno())
        B.write_new_private(args.output_dir/('response-proxy-'+stamp+'.json'),
            {'schema_version': 1, 'upstream_endpoint': ENDPOINT, 'wire_api': 'responses', 'mode': args.mode,
             'max_requests_per_job': MAX_REQUESTS if args.mode == 'demo' else TERMINAL_MAX_REQUESTS,
             'max_requests': MAX_REQUESTS if args.mode == 'demo' else 32 * TERMINAL_MAX_REQUESTS,
             'max_output_tokens': B.configured_output_limit(ledger.config), 'reasoning_effort': ledger.config.get('reasoning_effort'),
             'normalized_request_evidence': 'V2_ONLY_DURABLE_EXACT_BYTES_BEFORE_UPSTREAM' if args.mode == 'terminal-v2' else 'NOT_CAPTURED',
             'limit_rmb': limit, 'ledger_config_sha256': ledger.config_sha256,
             'broker_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'tool_policy': 'OUTBOUND_OBSERVER_BASH_ONLY; BUFFERED_INBOUND_TOOL_ALLOWLIST_BEFORE_CODEX_DELIVERY',
             'opaque_history_policy': 'ONLY_THIS_LEDGER_SETTLED_PROVIDER_HANDLES; PLUS_FULL_SOURCE_INPUT_AND_OUTPUT_BOUND_PER_REFERENCE_INCLUDING_NESTED_HISTORY',
             'sse_delivery': 'GENUINE_PROVIDER_SSE_BUFFERED_UNTIL_TERMINAL_USAGE_SETTLED', 'summary': ledger.summary()})
        server = Broker(('127.0.0.1', args.port), ledger, B.private_read(args.api_key_file), B.private_read(token_file))
        print(json.dumps({'status': 'READY', 'port': args.port, 'api': 'responses', 'summary': ledger.summary()}), flush=True)
        try: server.serve_forever(poll_interval=.25)
        except KeyboardInterrupt: pass
    finally:
        if server is not None: server.server_close()
        B.write_new_private(args.output_dir/('budget-summary-'+stamp+'.json'), ledger.summary())
        ledger.close()


if __name__ == '__main__': main()
