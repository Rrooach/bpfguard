#!/usr/bin/env python3
"""Direct Responses proxy for genuine Codex; no custom Agent loop.

Only this Host process reads the DeepSeek key. All requests are durably
reserved before a single upstream invocation. Demo mode is three requests/.4
CNY. Terminal mode fixes32 jobs across2/4/6/8,12 requests/.125 CNY per job and
4 CNY total. Terminal-v2 uses4096 output tokens and reasoning.effort=none,
.2 CNY per job, while retaining the same4 CNY shared cap (not32*.2). A closed
benchmark-smoke mode admits exactly one Terminal and one SWE task with a
combined .8 CNY hard cap. A closed
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
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import model_budget_v2 as B
import native_provider_wire as NativeWire

LABEL = 'codex-smoke-001'
ENDPOINT = 'https://api.deepseek.com/responses'
MAX_REQUESTS, MAX_RESPONSE = 3, 4 * 1024 * 1024
TERMINAL_MAX_REQUESTS, TERMINAL_LIMIT = 12, '4.0'
ALLOWED = {'model', 'input', 'instructions', 'tools', 'tool_choice', 'parallel_tool_calls',
    'stream', 'store', 'max_output_tokens', 'reasoning', 'text', 'include', 'previous_response_id',
    'service_tier', 'prompt_cache_key', 'metadata', 'client_metadata', 'temperature', 'top_p', 'truncation'}
TIMING_FILENAME = 'model-request-timing.jsonl'
OPAQUE_ID = re.compile(r'[A-Za-z0-9_.:-]{1,256}\Z')


class ModelRequestTimings:
    """Append-only exportable metadata; never write model content or credentials.

    This file is intentionally separate from the private request/SSE and budget
    evidence. Events are fsynced at each boundary. A consumer can detect a
    broker crash from a request with no MODEL_REQUEST_FINISHED event.
    """
    def __init__(self, directory):
        self.path = directory / TIMING_FILENAME
        self.lock = threading.Lock()
        self.boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        B.require(re.fullmatch(r'[0-9a-f-]{36}', self.boot_id) is not None,
            'Linux boot identity required for request timing')
        descriptor = B.private_fd(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT)
        try:
            size = os.fstat(descriptor).st_size
            B.require(size == 0 or os.pread(descriptor, 1, size - 1) == b'\n',
                'truncated model timing ledger requires inspection before restart')
            os.fsync(descriptor)
        finally: os.close(descriptor)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)

    def append(self, record):
        encoded = B.canonical(record) + b'\n'
        with self.lock:
            descriptor = B.private_fd(self.path, os.O_WRONLY | os.O_APPEND)
            try:
                offset = 0
                while offset < len(encoded):
                    written = os.write(descriptor, encoded[offset:])
                    if written <= 0: raise OSError('short model timing write')
                    offset += written
                os.fsync(descriptor)
            finally: os.close(descriptor)

    def start(self, task_label):
        return ModelRequestTiming(self, task_label)

    def export_task(self, task_label):
        with self.lock:
            descriptor = B.private_fd(self.path, os.O_RDONLY)
            with os.fdopen(descriptor, 'rb') as stream:
                B.require(os.fstat(stream.fileno()).st_size <= 32 * 1024 * 1024,
                    'model timing export exceeds bounded ledger size')
                raw = stream.read(32 * 1024 * 1024 + 1)
            B.require(not raw or raw.endswith(b'\n'), 'truncated model timing export')
            rows = [B.parse_json(line) for line in raw.splitlines()]
        selected = [row for row in rows if row.get('kind') == 'MODEL_REQUEST_TIMING'
            and row.get('task_label') == task_label]
        finished = [row for row in selected if row.get('event') == 'MODEL_REQUEST_FINISHED']
        complete_ids = {row['request_id'] for row in finished}
        unfinished = sorted({row['request_id'] for row in selected} - complete_ids)
        return {'schema_version': 1, 'kind': 'MODEL_REQUEST_TIMING_EXPORT',
            'task_label': task_label, 'clock': 'CLOCK_MONOTONIC', 'boot_id': self.boot_id,
            'status': 'PARTIAL' if unfinished else 'COMPLETE', 'requests': finished,
            'unfinished_request_ids': unfinished}


class ModelRequestTiming:
    def __init__(self, ledger, task_label):
        self.ledger = ledger
        self.request_id = 'mrq-' + secrets.token_hex(16)
        self.task_label = task_label
        self.budget_request_id = None
        self.timestamps = {}
        self.outcome = 'INTERRUPTED'
        self.error_class = None
        self.http_status = None
        self.upstream_http_status = None
        self.budget_status = None
        self.usage = None
        self.provider_response_id = None
        self.output_tool_call_ids = []
        self.output_link_status = 'NOT_RECEIVED'
        self.wire_adapter_version = None
        self.provider_sse_sha256 = None
        self.delivered_sse_sha256 = None
        self.mark('MODEL_REQUEST_ACCEPTED', 'accepted')

    def base(self, event, timestamp):
        return {'schema_version': 1, 'kind': 'MODEL_REQUEST_TIMING', 'event': event,
            'request_id': self.request_id, 'task_label': self.task_label,
            'budget_request_id': self.budget_request_id, 'clock': 'CLOCK_MONOTONIC',
            'boot_id': self.ledger.boot_id, 'timestamp_ns': timestamp}

    def mark(self, event, stage):
        timestamp = time.monotonic_ns()
        self.timestamps[stage] = timestamp
        self.ledger.append(self.base(event, timestamp))

    def finish(self):
        timestamp = time.monotonic_ns()
        self.timestamps['request_end'] = timestamp
        pairs = {'request_total': ('accepted', 'request_end'),
            'local_before_dispatch': ('accepted', 'upstream_dispatch'),
            'upstream_total': ('upstream_dispatch', 'upstream_end'),
            'time_to_headers': ('upstream_dispatch', 'upstream_headers'),
            'time_to_first_byte': ('upstream_dispatch', 'upstream_first_byte'),
            'first_byte_to_end': ('upstream_first_byte', 'upstream_end'),
            'settle_and_validate': ('upstream_end', 'response_delivery_start'),
            'delivery': ('response_delivery_start', 'response_delivery_end')}
        durations = {key: self.timestamps[end] - self.timestamps[start]
            if start in self.timestamps and end in self.timestamps else None
            for key, (start, end) in pairs.items()}
        self.ledger.append(dict(self.base('MODEL_REQUEST_FINISHED', timestamp),
            timestamps_ns=dict(self.timestamps), durations_ns=durations,
            outcome=self.outcome, error_class=self.error_class, http_status=self.http_status,
            upstream_http_status=self.upstream_http_status, budget_status=self.budget_status,
            usage=self.usage, provider_response_id=self.provider_response_id,
            output_tool_call_ids=self.output_tool_call_ids, output_link_status=self.output_link_status,
            wire_adapter_version=self.wire_adapter_version,provider_sse_sha256=self.provider_sse_sha256,
            delivered_sse_sha256=self.delivered_sse_sha256,
            upstream_timing_scope='BROKER_TRANSPORT_AND_PROVIDER; NOT_PROVIDER_QUEUE_OR_GPU_TIME',
            first_byte_timing_scope='FIRST_UPSTREAM_BODY_BYTE; MAY_BE_SSE_METADATA_NOT_FIRST_MODEL_TOKEN',
            delivery_timing_scope='LOCAL_SOCKET_WRITE_AND_FLUSH; NOT_CLIENT_RECEIPT',
            sse_delivery=('EXPLICIT_NATIVE_TOOL_WIRE_TRANSLATION_AFTER_BUDGET_SETTLEMENT'
                if self.wire_adapter_version else 'BUFFERED_UNTIL_BUDGET_SETTLEMENT')))


def registration(campaign_id, mode='demo'):
    if mode in ('native-profile','native-final'):
        final = mode == 'native-final'
        return {'schema_version': 1, 'campaign_id': campaign_id,
            'registration_kind': 'CODEX_NATIVE_FINAL_V2' if final else 'CODEX_NATIVE_PROFILE_V1',
            'global_limit_rmb': '.4' if final else '.8',
            'labels': [{'label': label, 'kind': 'CODEX_NATIVE_PROFILE', 'group_id': 'codex-native',
                'job_id': label, 'cap_rmb': '.4'} for label in (('codex-native-final-001',) if final else
                    ('codex-native-001', 'codex-native-002'))]}
    if mode in ('benchmark-smoke', 'benchmark-smoke-2'):
        suffix = '001' if mode == 'benchmark-smoke' else '002'
        return {'schema_version': 1, 'campaign_id': campaign_id,
            'registration_kind': 'CODEX_BENCHMARK_SMOKE_V1' if suffix == '001' else 'CODEX_BENCHMARK_SMOKE_V2',
            'global_limit_rmb': '.8',
            'labels': [
                {'label': 'codex-terminal-smoke-' + suffix, 'kind': 'CODEX_BENCHMARK_SMOKE',
                 'group_id': 'terminal-smoke', 'job_id': 'terminal-' + suffix, 'cap_rmb': '.4'},
                {'label': 'codex-swe-smoke-' + suffix, 'kind': 'CODEX_BENCHMARK_SMOKE',
                 'group_id': 'swe-smoke', 'job_id': 'swe-' + suffix, 'cap_rmb': '.4'},
            ]}
    if mode in ('terminal', 'terminal-v2'):
        return {'schema_version': 1, 'campaign_id': campaign_id,
            'registration_kind': 'CODEX_TERMINAL_2468_V2' if mode == 'terminal-v2' else 'CODEX_TERMINAL_2468',
            'global_limit_rmb': TERMINAL_LIMIT,
            'labels': [{'label': f'codex-terminal-c{concurrency}-{index:02d}', 'kind': 'CODEX_TERMINAL',
                'group_id': f'codex-terminal-c{concurrency}', 'job_id': f'terminal-{index:02d}',
                'cap_rmb': '.2' if mode == 'terminal-v2' else '.125'}
                for concurrency in (2, 4, 6, 8) for index in range(8)]}
    B.require(mode == 'demo', 'explicit demo, benchmark-smoke, terminal or terminal-v2 mode required')
    return {'schema_version': 1, 'campaign_id': campaign_id,
        'registration_kind': 'CODEX_OBSERVER_DEMO', 'global_limit_rmb': '.4',
        'labels': [{'label': LABEL, 'kind': 'CODEX_DEMO', 'group_id': 'codex-demo',
                    'job_id': 'demo-001', 'cap_rmb': '.4'}]}


def normalize(raw, known_reasoning=None, *, max_output_tokens=1024, reasoning_effort=None,
              tool_policy='OBSERVER_BASH_ONLY'):
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
    B.require(tool_policy in ('OBSERVER_BASH_ONLY', 'NATIVE_LOCAL_TOOLS'), 'versioned tool policy required')
    B.require(isinstance(tools, list) and len(tools) <= (128 if tool_policy == 'NATIVE_LOCAL_TOOLS' else 16),
        'bounded local tools required')
    # Codex can expose local function/custom tools. Never admit a provider-side
    # web/search/image/MCP/hosted tool with a separate charging model.
    def local(tool, depth=0):
        if not isinstance(tool, dict): return False
        if depth > 4: return False
        if tool.get('type') == 'namespace':
            return (isinstance(tool.get('name'), str) or tool_policy == 'OBSERVER_BASH_ONLY') and isinstance(tool.get('tools'), list) and len(tool['tools']) <= 128 and all(local(item, depth+1) for item in tool['tools'])
        return tool.get('type') in ('function', 'custom')
    B.require(all(local(tool) for tool in tools), 'only locally executed Codex tools permitted')
    selected = [tool for tool in tools if tool.get('type') == 'function' and tool.get('name') == 'observer_bash']
    if tool_policy == 'OBSERVER_BASH_ONLY':
        B.require(len(selected) == 1, 'exactly one observer_bash dynamic function required')
    else:
        native_tool_catalog(tools)  # validate names/ambiguity without replacing the declared tools
    # Codex still advertises some built-ins even when feature flags are off.
    # This application-owned mode intentionally exposes one controlled tool,
    # not the CLI's complete default toolset. Codex still owns the Agent loop.
    data['tools'] = selected if tool_policy == 'OBSERVER_BASH_ONLY' else tools
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


def terminal_response(raw):
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
    return terminals[0]


def response_usage(raw):
    result = terminal_response(raw)
    usage = result.get('usage')
    if not isinstance(usage, dict): return None, result.get('model')
    mapped = {'prompt_tokens': usage.get('input_tokens'), 'completion_tokens': usage.get('output_tokens')}
    if 'total_tokens' in usage: mapped['total_tokens'] = usage['total_tokens']
    return mapped, result.get('model')


def response_timing_metadata(raw):
    """Only opaque correlation IDs and numeric counts enter the public ledger."""
    response = terminal_response(raw)
    response_id = response.get('id')
    valid_response_id = isinstance(response_id, str) and OPAQUE_ID.fullmatch(response_id) is not None
    output = response.get('output')
    calls, complete = [], valid_response_id and isinstance(output, list)
    for item in output if isinstance(output, list) else []:
        if not isinstance(item, dict):
            complete = False
            continue
        if item.get('type') not in ('function_call', 'custom_tool_call'): continue
        call_id = item.get('call_id')
        if isinstance(call_id, str) and OPAQUE_ID.fullmatch(call_id) and len(calls) < 256:
            calls.append(call_id)
        else: complete = False
    raw_usage = response.get('usage')
    usage = {key: value for key in ('input_tokens', 'output_tokens', 'total_tokens')
        if isinstance(raw_usage, dict) and type(value := raw_usage.get(key)) is int and 0 <= value <= 10**12}
    return {'provider_response_id': response_id if valid_response_id else None,
        'output_tool_call_ids': calls, 'output_link_status': 'COMPLETE' if complete else 'PARTIAL',
        'usage': usage or None}


def native_tool_catalog(tools):
    """Names advertised by this exact request; no hosted/provider tools.

    Keep namespaces in the allowlist. A bare name is admissible only if unique
    across the request, never by stripping a provider-selected namespace.
    """
    result = []
    def visit(items, prefix=(), depth=0):
        B.require(depth <= 4 and isinstance(items, list) and len(items) <= 128,
            'bounded native tool namespace required')
        for tool in items:
            B.require(isinstance(tool, dict) and tool.get('type') in ('namespace', 'function', 'custom'),
                'only native local function/custom tools permitted')
            name = tool.get('name')
            B.require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', name),
                'bounded native tool name required')
            if tool['type'] == 'namespace':
                visit(tool.get('tools'), (*prefix, name), depth + 1)
            else:
                key = ('.'.join(prefix), name, tool['type'])
                B.require(key not in result, 'duplicate native tool declaration')
                result.append(key)
    visit(tools)
    B.require(len(result) <= 256, 'native tool catalog exceeds bound')
    return result


def controlled_output(raw, native_catalog=None):
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
            if kind in ('function_call', 'custom_tool_call'):
                if native_catalog is None:
                    if kind != 'function_call' or item.get('name') != 'observer_bash': return False
                    continue
                native_kind = 'function' if kind == 'function_call' else 'custom'
                name, namespace = item.get('name'), item.get('namespace')
                if not isinstance(name, str) or namespace is not None and not isinstance(namespace, str):
                    return False
                candidates = [(scope, declared, form) for scope, declared, form in native_catalog
                    if form == native_kind and ((namespace is not None and scope == namespace and declared == name)
                        or namespace is None and (declared == name or '.'.join(filter(None, (scope, declared))) == name))]
                if len(candidates) != 1: return False
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
        B.require(kind in ('CODEX_OBSERVER_DEMO', 'CODEX_BENCHMARK_SMOKE_V1', 'CODEX_BENCHMARK_SMOKE_V2',
            'CODEX_TERMINAL_2468', 'CODEX_TERMINAL_2468_V2', 'CODEX_NATIVE_PROFILE_V1', 'CODEX_NATIVE_FINAL_V2'), 'explicit Codex registry required')
        B.require(ledger.config.get('provider_endpoint') == ENDPOINT, 'real Responses endpoint ledger required')
        self.max_requests_per_job = MAX_REQUESTS if kind == 'CODEX_OBSERVER_DEMO' else TERMINAL_MAX_REQUESTS
        self.max_output_tokens = B.configured_output_limit(ledger.config)
        self.reasoning_effort = 'none' if kind in ('CODEX_TERMINAL_2468_V2',
            'CODEX_BENCHMARK_SMOKE_V1', 'CODEX_BENCHMARK_SMOKE_V2', 'CODEX_NATIVE_PROFILE_V1', 'CODEX_NATIVE_FINAL_V2') else None
        self.tool_policy = 'NATIVE_LOCAL_TOOLS' if kind in ('CODEX_NATIVE_PROFILE_V1', 'CODEX_NATIVE_FINAL_V2') else 'OBSERVER_BASH_ONLY'
        B.require(ledger.config.get('max_output_tokens') == self.max_output_tokens
            and (self.reasoning_effort is None or ledger.config.get('reasoning_effort') == self.reasoning_effort),
            'ledger output/reasoning contract differs')
        self.demo_lock = threading.Lock()
        self.model_timings = ModelRequestTimings(ledger.directory)
        self.timing_context = threading.local()
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
            catalog = None
            if self.tool_policy == 'NATIVE_LOCAL_TOOLS':
                request_file = ledger.directory / (key + '-native-request.json')
                B.require(request_file.is_file(), 'native replay requires exact original declared tools')
                catalog = native_tool_catalog(B.parse_json(request_file.read_bytes()).get('tools', []))
                wire_file = ledger.directory / (key + '-wire-adapter.json')
                if wire_file.is_file(): raw = NativeWire.restore_response(raw, B.parse_json(wire_file.read_bytes()))
            if controlled_output(raw, catalog): self.remember_reasoning(raw, reservations[key])
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
        timing = getattr(self.timing_context, 'record', None)
        with opener.open(request, timeout=180) as response:
            if timing is not None:
                timing.upstream_http_status = response.status
                timing.mark('MODEL_UPSTREAM_HEADERS', 'upstream_headers')
            B.require(response.headers.get_content_type() == 'text/event-stream', 'provider must return SSE')
            chunks, size = [], 0
            while size <= MAX_RESPONSE:
                # read1 returns the first available transport bytes, rather
                # than waiting for read(MAX_RESPONSE) to fill or reach EOF.
                chunk = response.read1(min(65536, MAX_RESPONSE + 1 - size))
                if not chunk: break
                if timing is not None and not chunks:
                    timing.mark('MODEL_UPSTREAM_FIRST_BYTE', 'upstream_first_byte')
                chunks.append(chunk); size += len(chunk)
            body = b''.join(chunks)
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
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != '/v1/observer/model-request-timing': return super().do_GET()
        if not secrets.compare_digest(self.headers.get('Authorization', ''), 'Bearer '+self.server.client_token):
            return self.reply(401, {'error': 'invalid local broker credential'})
        try:
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True,
                strict_parsing=True, max_num_fields=4)
            B.require(set(query) == {'task_label'} and len(query['task_label']) == 1
                and query['task_label'][0] in self.server.ledger.labels,
                'one registered task label required')
        except (ValueError, B.BudgetError):
            return self.reply(400, {'error': 'REGISTERED_TASK_LABEL_REQUIRED'})
        try: result = self.server.model_timings.export_task(query['task_label'][0])
        except (ValueError, B.BudgetError, OSError):
            return self.reply(503, {'error': 'MODEL_REQUEST_TIMING_EXPORT_UNAVAILABLE'})
        return self.reply(200, result)

    def reply(self, status, value):
        timing = getattr(self, 'model_timing', None)
        if timing is not None:
            timing.http_status = status
            timing.mark('MODEL_RESPONSE_DELIVERY_STARTED', 'response_delivery_start')
        result = super().reply(status, value)
        self.wfile.flush()
        if timing is not None:
            timing.mark('MODEL_RESPONSE_DELIVERY_END', 'response_delivery_end')
        return result

    def do_POST(self):
        if self.path != '/v1/responses': return self.reply(404, {'error': 'RESPONSES_ONLY'})
        if not secrets.compare_digest(self.headers.get('Authorization', ''), 'Bearer '+self.server.client_token):
            return self.reply(401, {'error': 'invalid local broker credential'})
        label = self.headers.get('X-Benchmark-Task', '')
        # Only registered metadata is exportable; arbitrary rejected header
        # values must not turn this ledger into a content-exfiltration path.
        self.model_timing = self.server.model_timings.start(
            label if len(self.headers.get_all('X-Benchmark-Task', [])) == 1
                and label in self.server.ledger.labels else None)
        self.server.timing_context.record = self.model_timing
        try:
            return self.handle_model_request()
        except Exception as error:
            self.model_timing.error_class = type(error).__name__
            self.model_timing.outcome = 'HANDLER_OR_DELIVERY_FAILED'
            raise
        finally:
            try: self.model_timing.finish()
            finally: del self.server.timing_context.record

    def handle_model_request(self):
        timing = self.model_timing
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
                    reasoning_effort=self.server.reasoning_effort, tool_policy=self.server.tool_policy)
                native_catalog = native_tool_catalog(B.parse_json(payload).get('tools', [])) \
                    if self.server.tool_policy == 'NATIVE_LOCAL_TOOLS' else None
                native_payload, wire_receipt = payload, None
                if native_catalog is not None:
                    provider_payload, wire_receipt = NativeWire.prepare_request(B.parse_json(payload))
                    payload = B.canonical(provider_payload)
                    B.require(len(payload) <= B.MAX_BODY, 'native provider adaptation exceeds input budget bound')
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
                timing.budget_request_id = item['request_id']
                timing.mark('MODEL_REQUEST_RESERVED', 'reserved')
        except (ValueError, B.BudgetError, TimeoutError) as error:
            timing.outcome = 'POLICY_OR_BUDGET_REJECTED'
            timing.error_class = type(error).__name__
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
            if wire_receipt is not None:
                B.write_new_private(ledger.directory/(item['request_id']+'-native-request.json'), B.parse_json(native_payload))
                B.write_new_private(ledger.directory/(item['request_id']+'-wire-adapter.json'), wire_receipt)
            timing.mark('MODEL_UPSTREAM_DISPATCHED', 'upstream_dispatch')
            try:
                body = self.server.upstream(payload)
            except Exception as error:
                timing.error_class = type(error).__name__
                if isinstance(error, urllib.error.HTTPError):
                    timing.upstream_http_status = error.code
                    if 'upstream_headers' not in timing.timestamps:
                        timing.mark('MODEL_UPSTREAM_HEADERS', 'upstream_headers')
                    detail = error.read(65537)
                    B.write_new_private(ledger.directory/(item['request_id']+'-upstream-error.json'),
                        {'http_status':error.code,'body':detail[:65536].decode(errors='replace'),
                         'truncated':len(detail)>65536,'charging':'UNKNOWN_RESERVATION_RETAINED'})
                raise
            finally:
                timing.mark('MODEL_UPSTREAM_END', 'upstream_end')
            # Preserve exactly the bounded upstream SSE before settlement and
            # delivery. It contains model text, never the Authorization header.
            response_file = ledger.directory/(item['request_id']+'-upstream.sse')
            descriptor = B.private_fd(response_file, os.O_WRONLY|os.O_CREAT|os.O_EXCL)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(body); stream.flush(); os.fsync(stream.fileno())
            B.write_new_private(ledger.directory/(item['request_id']+'-response.json'),
                {'schema_version': 1, 'request_id': item['request_id'], 'request_sha256': item['request_sha256'],
                 'response_file': response_file.name, 'response_sha256': B.sha(body), 'response_bytes': len(body),
                 'upstream_endpoint': ENDPOINT, 'forwarding': (
                     'ORIGINAL_PROVIDER_SSE; NATIVE_WIRE_RESTORATION_BEFORE_CODEX_DELIVERY'
                     if wire_receipt is not None else 'IDENTICAL_SSE_BYTES_NO_AGENT_LOOP_OR_TOOL_EXECUTION')})
            directory_fd = os.open(ledger.directory, os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
            usage, model = response_usage(body)
            for key, value in response_timing_metadata(body).items(): setattr(timing, key, value)
        except Exception as error:
            timing.outcome = 'UPSTREAM_OR_EVIDENCE_UNKNOWN'
            timing.error_class = type(error).__name__
            ledger.unknown(item, type(error).__name__)
            return self.reply(502, {'error': 'UPSTREAM_UNKNOWN_RESERVATION_RETAINED', 'retry_allowed': False})
        status = ledger.settle(item, usage, model)
        timing.budget_status = status
        if status == 'BOUND_EXCEEDED':
            timing.outcome = 'TOKEN_BOUND_EXCEEDED'
            return self.reply(502, {'error': 'TOKEN_BOUND_EXCEEDED_STOPPED'})
        delivered_body = NativeWire.restore_response(body,wire_receipt) if wire_receipt is not None else body
        timing.wire_adapter_version = NativeWire.VERSION if wire_receipt is not None else None
        timing.provider_sse_sha256 = B.sha(body)
        timing.delivered_sse_sha256 = B.sha(delivered_body)
        if wire_receipt is not None:
            B.write_new_private(ledger.directory/(item['request_id']+'-delivery.json'),
                {'wire_adapter':NativeWire.VERSION,'upstream_sha256':B.sha(body),
                 'delivered_sha256':B.sha(delivered_body),'delivered_bytes':len(delivered_body),
                 'usage_unchanged':True,'tool_execution':'OFFICIAL_CODEX_ONLY_NO_BROKER_EXECUTION'})
            descriptor = B.private_fd(ledger.directory/(item['request_id']+'-delivered.sse'),os.O_WRONLY|os.O_CREAT|os.O_EXCL)
            with os.fdopen(descriptor,'wb') as stream:
                stream.write(delivered_body);stream.flush();os.fsync(stream.fileno())
        if not controlled_output(delivered_body, native_catalog):
            timing.outcome = 'UNAPPROVED_TOOL_OUTPUT_WITHHELD'
            return self.reply(502, {'error': 'UNAPPROVED_MODEL_TOOL_NOT_DELIVERED_TO_CODEX', 'retry_allowed': False})
        if status == 'SETTLED':
            with self.server.demo_lock: self.server.remember_reasoning(body, item)
        timing.http_status = 200
        timing.mark('MODEL_RESPONSE_DELIVERY_STARTED', 'response_delivery_start')
        self.send_response(200); self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Content-Length', str(len(delivered_body))); self.end_headers(); self.wfile.write(delivered_body)
        self.wfile.flush()
        timing.mark('MODEL_RESPONSE_DELIVERY_END', 'response_delivery_end')
        timing.outcome = 'DELIVERED'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--api-key-file', type=Path, required=True)
    parser.add_argument('--pricing-evidence', type=Path, required=True)
    parser.add_argument('--prior-ledger', type=Path, required=True)
    parser.add_argument('--campaign-id', required=True)
    parser.add_argument('--mode', choices=('demo', 'benchmark-smoke', 'benchmark-smoke-2', 'terminal', 'terminal-v2', 'native-profile', 'native-final'), default='demo',
        help='demo:3calls/.4 CNY; terminal:32jobs/1024 output/.125 perjob; terminal-v2:4096 output/none/.2 perjob; both terminal modes4 CNY shared/12calls perjob')
    parser.add_argument('--port', type=int, default=10091)
    args = parser.parse_args()
    limit = '.4' if args.mode in ('demo','native-final') else '.8' if args.mode.startswith('benchmark-smoke') or args.mode == 'native-profile' else TERMINAL_LIMIT
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
             'normalized_request_evidence': 'V2_ONLY_DURABLE_EXACT_BYTES_BEFORE_UPSTREAM'
                if args.mode in ('terminal-v2', 'benchmark-smoke', 'benchmark-smoke-2', 'native-profile', 'native-final') else 'NOT_CAPTURED',
             'limit_rmb': limit, 'ledger_config_sha256': ledger.config_sha256,
             'broker_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'tool_policy': ('NATIVE_TOOL_EXECUTION_PRESERVED; EXPLICIT_REVERSIBLE_PROVIDER_WIRE_ADAPTER'
                if args.mode in ('native-profile','native-final') else 'OUTBOUND_OBSERVER_BASH_ONLY; BUFFERED_INBOUND_TOOL_ALLOWLIST_BEFORE_CODEX_DELIVERY'),
             'native_wire_version': NativeWire.VERSION if args.mode in ('native-profile','native-final') else None,
             'opaque_history_policy': 'ONLY_THIS_LEDGER_SETTLED_PROVIDER_HANDLES; PLUS_FULL_SOURCE_INPUT_AND_OUTPUT_BOUND_PER_REFERENCE_INCLUDING_NESTED_HISTORY',
             'model_request_timing': {'file': TIMING_FILENAME, 'schema_version': 1,
                'clock': 'CLOCK_MONOTONIC', 'boot_id_required': True,
                'privacy': 'IDENTIFIERS_TIMESTAMPS_COUNTS_STATUS_ONLY; NO_PROMPTS_OR_SSE',
                'upstream_timing_scope': 'BROKER_TRANSPORT_AND_PROVIDER; NOT_PROVIDER_QUEUE_OR_GPU_TIME'},
             'sse_delivery': ('PROVIDER_SSE_SAVED; VERSIONED_NATIVE_TOOL_WIRE_RESTORATION_AFTER_SETTLEMENT'
                if args.mode in ('native-profile','native-final') else
                    'GENUINE_PROVIDER_SSE_BUFFERED_UNTIL_TERMINAL_USAGE_SETTLED'), 'summary': ledger.summary()})
        server = Broker(('127.0.0.1', args.port), ledger, B.private_read(args.api_key_file), B.private_read(token_file))
        print(json.dumps({'status': 'READY', 'port': args.port, 'api': 'responses',
            'model_request_timing_file': str(server.model_timings.path),
            'summary': ledger.summary()}), flush=True)
        try: server.serve_forever(poll_interval=.25)
        except KeyboardInterrupt: pass
    finally:
        if server is not None: server.server_close()
        B.write_new_private(args.output_dir/('budget-summary-'+stamp+'.json'), ledger.summary())
        ledger.close()


if __name__ == '__main__': main()
