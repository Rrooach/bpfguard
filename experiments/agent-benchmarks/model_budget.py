#!/usr/bin/env python3
"""A bounded local chat-completions broker for this benchmark campaign."""
from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time
import urllib.error
import urllib.request

MODEL = 'deepseek-flash'
INPUT_RATE = Decimal('2')  # RMB / million tokens, official peak cache-miss price.
OUTPUT_RATE = Decimal('8')  # RMB / million tokens, official peak price.
MILLION = Decimal(1000000)
MAX_BODY = 192 * 1024
MAX_OUTPUT = 2048


class BudgetError(ValueError):
    pass


def token_cost(prompt, completion):
    return (Decimal(prompt) * INPUT_RATE + Decimal(completion) * OUTPUT_RATE) / MILLION


def private_read(path):
    path = Path(path)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise BudgetError('credential file must be an owned private regular file')
    value = path.read_text().strip()
    if not value or len(value) > 512 or any(c.isspace() for c in value):
        raise BudgetError('credential has invalid shape')
    return value


class Ledger:
    def __init__(self, directory, limit):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / 'budget-ledger.jsonl'
        self.limit = Decimal(str(limit))
        if self.limit <= 0 or self.limit > Decimal('4.8'):
            raise BudgetError('new campaign limit must be positive and <=4.8 RMB')
        self.lock = threading.Lock()
        self.requests = {}
        self.blocked = False
        if self.path.exists():
            st = self.path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_size > 16 * 1024 * 1024:
                raise BudgetError('invalid ledger')
            for line in self.path.read_text().splitlines():
                self._apply(json.loads(line))
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
        self.stream = os.fdopen(os.open(str(self.path), flags, 0o600), 'a', encoding='utf-8')

    def _apply(self, event):
        kind, key = event['event'], event['request_id']
        if kind == 'RESERVED':
            if key in self.requests:
                raise BudgetError('duplicate reservation in ledger')
            self.requests[key] = event
        elif kind in ('SETTLED', 'UNKNOWN_CHARGE', 'BOUND_EXCEEDED'):
            previous = self.requests.get(key)
            if not previous or previous['event'] != 'RESERVED':
                raise BudgetError('settlement without outstanding reservation')
            self.requests[key] = event
            if kind == 'BOUND_EXCEEDED':
                self.blocked = True
        else:
            raise BudgetError('unknown ledger event')

    def _append(self, event):
        event['monotonic_ns'] = time.monotonic_ns()
        self.stream.write(json.dumps(event, sort_keys=True) + '\n')
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self._apply(event)

    def _committed(self):
        return sum((Decimal(row['cost_rmb_bound']) for row in self.requests.values()), Decimal(0))

    def reserve(self, raw, output_tokens, label):
        # UTF-8 request bytes are an intentionally loose input-token bound;
        # extra space covers chat framing. Actual reported usage settles it.
        input_bound = len(raw) + 8192
        cost = token_cost(input_bound, output_tokens)
        with self.lock:
            if self.blocked or self._committed() + cost > self.limit:
                raise BudgetError('campaign budget cannot cover this request')
            event = {'event': 'RESERVED', 'request_id': secrets.token_hex(12),
                     'task_label': label, 'input_tokens_bound': input_bound,
                     'output_tokens_bound': output_tokens, 'cost_rmb_bound': str(cost),
                     'request_sha256': hashlib.sha256(raw).hexdigest()}
            self._append(event)
            return dict(event)

    def settle(self, reservation, usage):
        with self.lock:
            prompt = usage.get('prompt_tokens') if isinstance(usage, dict) else None
            completion = usage.get('completion_tokens') if isinstance(usage, dict) else None
            valid = type(prompt) is int and prompt >= 0 and type(completion) is int and completion >= 0
            bounded = valid and prompt <= reservation['input_tokens_bound'] and completion <= reservation['output_tokens_bound']
            if not valid:
                event = {'event': 'UNKNOWN_CHARGE', 'reason': 'usage unavailable',
                         'cost_rmb_bound': reservation['cost_rmb_bound']}
            else:
                event = {'event': 'SETTLED' if bounded else 'BOUND_EXCEEDED',
                         'prompt_tokens': prompt, 'completion_tokens': completion,
                         'cost_rmb_bound': str(max(token_cost(prompt, completion),
                                                   Decimal(reservation['cost_rmb_bound']) if not bounded else Decimal(0)))}
            event.update(request_id=reservation['request_id'], task_label=reservation['task_label'])
            self._append(event)
            return event['event']

    def unknown(self, reservation, reason):
        with self.lock:
            self._append({'event': 'UNKNOWN_CHARGE', 'request_id': reservation['request_id'],
                          'task_label': reservation['task_label'], 'reason': reason,
                          'cost_rmb_bound': reservation['cost_rmb_bound']})

    def summary(self):
        with self.lock:
            cost = self._committed()
            return {'model': MODEL, 'new_campaign_limit_rmb': str(self.limit),
                    'accounted_cost_rmb_upper_bound': str(cost),
                    'remaining_rmb': str(max(Decimal(0), self.limit - cost)),
                    'requests': len(self.requests), 'blocked': self.blocked,
                    'outstanding_or_unknown_requests': sum(row['event'] != 'SETTLED' for row in self.requests.values()),
                    'pricing': {'input_rmb_per_million': str(INPUT_RATE),
                                'output_rmb_per_million': str(OUTPUT_RATE),
                                'source': 'https://api-docs.deepseek.com/zh-cn/quick_start/pricing/',
                                'basis': 'peak rates; all input charged as cache miss; reasoning not double-counted'},
                    'previous_campaign_reserve_rmb': '0.1',
                    'note': 'Provider billing may be lower due to caching/off-peak. Unknown charges retain reservation.'}


class Broker(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, ledger, provider_key, client_token):
        self.ledger, self.provider_key, self.client_token = ledger, provider_key, client_token
        super().__init__(address, Handler)

    def upstream(self, payload):
        request = urllib.request.Request('https://api.deepseek.com/chat/completions',
                                         data=payload, method='POST',
                                         headers={'Authorization': 'Bearer ' + self.provider_key,
                                                  'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=180) as response:
            body = response.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise BudgetError('upstream response exceeds bound')
            return json.loads(body)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # URLs, credentials and request bodies are never access-logged.

    def reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/health':
            self.reply(200, self.server.ledger.summary())
        elif self.path == '/v1/models':
            self.reply(200, {'object': 'list', 'data': [{'id': MODEL, 'object': 'model'}]})
        else:
            self.reply(404, {'error': 'unsupported endpoint'})

    def do_POST(self):
        if self.path != '/v1/chat/completions':
            return self.reply(404, {'error': 'only non-streaming chat completions are supported'})
        authorization = self.headers.get('Authorization', '')
        if not secrets.compare_digest(authorization, 'Bearer ' + self.server.client_token):
            return self.reply(401, {'error': 'invalid local broker credential'})
        reservation = None
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > MAX_BODY:
                raise BudgetError('request exceeds bounded body size')
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise BudgetError('incomplete request')
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get('model') != MODEL or data.get('stream', False):
                raise BudgetError('only deepseek-flash, non-streaming requests are allowed')
            messages = data.get('messages')
            if not isinstance(messages, list) or not 1 <= len(messages) <= 128:
                raise BudgetError('messages must contain 1..128 entries')
            output = data.get('max_tokens', data.get('max_completion_tokens', MAX_OUTPUT))
            if type(output) is not int or not 1 <= output <= MAX_OUTPUT:
                raise BudgetError('output token limit must be 1..2048')
            data.pop('max_completion_tokens', None)
            data['max_tokens'] = output
            data['thinking'] = {'type': 'disabled'}
            payload = json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode()
            if len(payload) > MAX_BODY:
                raise BudgetError('normalized request exceeds bound')
            label = self.headers.get('X-Benchmark-Task', 'unspecified')[:128]
            reservation = self.server.ledger.reserve(payload, output, label)
        except (ValueError, BudgetError):
            return self.reply(429, {'error': 'request rejected by campaign bounds or budget'})
        try:
            result = self.server.upstream(payload)
            status = self.server.ledger.settle(reservation, result.get('usage'))
            if status == 'BOUND_EXCEEDED':
                return self.reply(502, {'error': 'upstream token bound exceeded; campaign stopped'})
        except Exception as error:
            # A failed connection can still correspond to a billed request.
            self.server.ledger.unknown(reservation, type(error).__name__)
            return self.reply(502, {'error': 'provider request failed; reservation retained'})
        return self.reply(200, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--api-key-file', type=Path, required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=10090)
    parser.add_argument('--limit-rmb', default='4.8')
    args = parser.parse_args()
    if args.host != '127.0.0.1':
        parser.error('broker binds loopback only')
    ledger = Ledger(args.output_dir, args.limit_rmb)
    token_file = args.output_dir / 'client-token'
    if not token_file.exists():
        descriptor = os.open(str(token_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(secrets.token_hex(32) + '\n')
    server = Broker((args.host, args.port), ledger, private_read(args.api_key_file), private_read(token_file))
    ready = {'base_url': 'http://127.0.0.1:%d/v1' % server.server_port,
             'guest_base_url': 'http://10.0.2.2:%d/v1' % server.server_port,
             'model': MODEL, 'client_token_file': str(token_file), **ledger.summary()}
    (args.output_dir / 'broker-ready.json').write_text(json.dumps(ready, indent=2) + '\n')
    print(json.dumps({'status': 'READY', 'port': server.server_port, 'model': MODEL}), flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        (args.output_dir / 'budget-summary.json').write_text(json.dumps(ledger.summary(), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
