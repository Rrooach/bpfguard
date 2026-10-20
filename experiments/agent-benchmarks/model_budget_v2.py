#!/usr/bin/env python3
"""Single-process, durable, per-job CNY budget broker; never retries upstream.

Only this broker reads the provider key. Clients receive a distinct local token.
The ceiling assumes the saved public price and provider token-limit contract;
unknown charges keep their entire reservation. No promise of provider invoicing.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
import urllib.request

MODEL = 'deepseek-flash'
MODEL_VERSION = 'DeepSeek-V4.1-Flash-1017'
INPUT_RATE, OUTPUT_RATE = Decimal('2'), Decimal('8')
MAX_BODY, MAX_OUTPUT, MAX_LEDGER = 192 * 1024, 1024, 16 * 1024 * 1024
HISTORY_RMB, GLOBAL_MAX = Decimal('0.468350'), Decimal('4.2')
SAFE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}\Z')


class BudgetError(ValueError):
    pass


class DuplicateRequest(BudgetError):
    pass


def require(condition, message):
    if not condition: raise BudgetError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(BudgetError('nonfinite JSON')))


def money(value):
    try: result = Decimal(str(value))
    except (InvalidOperation, ValueError): raise BudgetError('invalid CNY amount') from None
    require(result.is_finite() and result >= 0, 'finite nonnegative CNY amount required')
    return result


def token_cost(prompt, completion):
    return (Decimal(prompt) * INPUT_RATE + Decimal(completion) * OUTPUT_RATE) / Decimal(1000000)


def configured_output_limit(config):
    """Only the separately registered Terminal V2 contract allows4096 output."""
    return 4096 if config.get('registration_kind') == 'CODEX_TERMINAL_2468_V2' else MAX_OUTPUT


def private_fd(path, flags):
    descriptor = os.open(str(path), flags | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        current = os.fstat(descriptor)
        require(stat.S_ISREG(current.st_mode) and current.st_uid == os.geteuid() and not current.st_mode & 0o077,
                'owned private regular file required')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def private_read(path):
    descriptor = private_fd(path, os.O_RDONLY)
    try:
        require(os.fstat(descriptor).st_size <= 514, 'credential exceeds byte limit')
        value = os.read(descriptor, 514).decode().strip()
        require(value and len(value) <= 512 and not any(character.isspace() for character in value), 'invalid credential shape')
        return value
    finally: os.close(descriptor)


def write_new_private(path, value):
    descriptor = private_fd(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(canonical(value) + b'\n'); stream.flush(); os.fsync(stream.fileno())


def read_pricing(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536, 'bounded pricing evidence required')
    raw = path.read_bytes(); value = parse_json(raw)
    require(value.get('schema_version') == 1 and value.get('source_url') == 'https://api-docs.deepseek.com/zh-cn/quick_start/pricing/'
        and value.get('model') == MODEL and value.get('model_version') == MODEL_VERSION and value.get('currency') == 'CNY'
        and money(value.get('input_rmb_per_million')) == INPUT_RATE and money(value.get('output_rmb_per_million')) == OUTPUT_RATE,
        'pricing evidence differs from approved model/rates')
    html_name = value.get('source_html_path')
    require(isinstance(html_name, str) and SAFE.fullmatch(html_name), 'pricing HTML must be a sibling filename')
    html = path.parent / html_name
    require(html.is_file() and not html.is_symlink() and html.stat().st_size <= 2 * 1024 * 1024,
            'bounded public pricing HTML required')
    content = html.read_bytes()
    require(len(content) == value.get('source_html_size_bytes') and sha(content) == value.get('source_html_sha256'),
            'public pricing HTML digest differs')
    return {'evidence_sha256': sha(raw), 'html_sha256': sha(content), 'model': MODEL, 'model_version': MODEL_VERSION,
        'currency': 'CNY', 'input_rmb_per_million': str(INPUT_RATE), 'output_rmb_per_million': str(OUTPUT_RATE),
        'source_url': value['source_url'], 'retrieved_at_utc': value.get('retrieved_at_utc')}


def registry(value):
    require(isinstance(value, dict) and value.get('schema_version') == 1 and SAFE.fullmatch(value.get('campaign_id', '')),
            'schema1 campaign registry required')
    rows = value.get('labels')
    require(isinstance(rows, list), 'registered labels required')
    if value.get('registration_kind') == 'CODEX_OBSERVER_DEMO':
        require(len(rows) == 1 and rows[0].get('kind') == 'CODEX_DEMO'
            and rows[0].get('label') == 'codex-smoke-001'
            and rows[0].get('group_id') == 'codex-demo' and rows[0].get('job_id') == 'demo-001'
            and money(rows[0].get('cap_rmb')) == Decimal('.4')
            and money(value.get('global_limit_rmb')) == Decimal('.4'), 'one explicitly registered .4 CNY Codex demo required')
        return value['campaign_id'], {rows[0]['label']: dict(rows[0], cap_rmb='0.4')}
    if value.get('registration_kind') in ('CODEX_TERMINAL_2468', 'CODEX_TERMINAL_2468_V2'):
        cap = Decimal('.2') if value['registration_kind'] == 'CODEX_TERMINAL_2468_V2' else Decimal('.125')
        require(money(value.get('global_limit_rmb')) == Decimal('4.0'),
            'Codex Terminal campaign cap must be exactly4.0 CNY')
        labels = {}
        expected = {f'codex-terminal-c{concurrency}-{index:02d}'
            for concurrency in (2, 4, 6, 8) for index in range(8)}
        for row in rows:
            require(isinstance(row, dict) and row.get('label') in expected
                and row.get('kind') == 'CODEX_TERMINAL'
                and row.get('group_id') == row['label'].rsplit('-', 1)[0]
                and row.get('job_id') == 'terminal-' + row['label'].rsplit('-', 1)[1]
                and money(row.get('cap_rmb')) == cap,
                'fixed Codex Terminal label/group/job and registered job cap required')
            require(row['label'] not in labels, 'duplicate registered label')
            labels[row['label']] = dict(row, cap_rmb=str(cap))
        require(set(labels) == expected and len(rows) == 32,
            'exactly32 Codex Terminal jobs across2/4/6/8 required')
        return value['campaign_id'], labels
    require(value.get('registration_kind') is None, 'unsupported registration kind')
    labels, formal, pilot_sum = {}, set(), Decimal(0)
    for row in rows:
        require(isinstance(row, dict) and all(isinstance(row.get(key), str) and SAFE.fullmatch(row[key])
            for key in ('label', 'group_id', 'job_id')), 'path-safe registered label/group/job required')
        require(row['label'] not in labels, 'duplicate registered label')
        cap = money(row.get('cap_rmb'))
        if row.get('kind') == 'FORMAL':
            match = re.fullmatch(r'(swe|terminal)-c(2|4|6|8)', row['group_id'])
            require(match is not None and cap == Decimal('0.065'), 'formal job cap must be .065 CNY')
            require(re.fullmatch(match[1] + r'-0[0-7]', row['job_id']) is not None
                and row['label'] == 'model-' + row['group_id'] + '-' + row['job_id'].rsplit('-', 1)[1], 'formal label/job binding differs')
            formal.add((row['group_id'], row['job_id']))
        else:
            require(row.get('kind') == 'PILOT' and row['label'] in ('pilot-model-swe', 'pilot-model-terminal')
                and Decimal(0) < cap <= Decimal('0.02'), 'pilot requires explicit approved .02-or-less registration')
            pilot_sum += cap
        labels[row['label']] = dict(row, cap_rmb=str(cap))
    expected = {(f'{benchmark}-c{concurrency}', f'{benchmark}-{index:02d}')
        for benchmark in ('swe', 'terminal') for concurrency in (2, 4, 6, 8) for index in range(8)}
    require(formal == expected and len(formal) == 64 and pilot_sum <= Decimal('.04'), 'exactly64 formal jobs plus at most .04 pilot required')
    require(sum((money(row['cap_rmb']) for row in labels.values()), Decimal(0)) <= GLOBAL_MAX, 'registered caps exceed4.2 CNY')
    if 'global_limit_rmb' in value: require(money(value['global_limit_rmb']) == GLOBAL_MAX, 'registry global cap differs')
    return value['campaign_id'], labels


def prior_budget(path, pricing, successor_directory=None):
    """Replay a closed predecessor while retaining its exclusive broker lock.

    A new trial is not a new budget: unsettled reservations remain charged and
    its digest, history and committed amount become part of the new CONFIGURED.
    Holding the old lock also prevents two generations from forwarding at once.
    """
    path = Path(path).absolute()
    require(path.name == 'budget-ledger.jsonl' and not path.is_symlink(), 'prior broker ledger required')
    lock_fd = private_fd(path.parent / 'broker.lock', os.O_RDWR)
    try:
        try: fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise BudgetError('prior broker is still active') from None
        descriptor = private_fd(path, os.O_RDONLY)
        with os.fdopen(descriptor, 'rb') as stream:
            require(os.fstat(stream.fileno()).st_size <= MAX_LEDGER, 'prior ledger exceeds replay budget')
            raw = stream.read(MAX_LEDGER + 1)
        require(raw and len(raw) <= MAX_LEDGER and raw.endswith(b'\n'), 'empty or truncated prior ledger')
        events = [parse_json(line) for line in raw.splitlines()]
        marker = path.parent / 'successor.json'
        if marker.exists():
            descriptor = private_fd(marker, os.O_RDONLY)
            with os.fdopen(descriptor, 'rb') as stream: marked = parse_json(stream.read(16385))
            require(successor_directory is not None and marked.get('successor_directory') == str(Path(successor_directory).absolute())
                and marked.get('prior_ledger_sha256') == sha(raw), 'prior ledger already retired to a different successor')
        first = events[0]; config = first.get('config')
        require(first.get('event') == 'CONFIGURED' and isinstance(config, dict)
            and first.get('config_sha256') == sha(canonical(config)), 'prior configuration digest differs')
        require(config.get('schema_version') == 2 and config.get('pricing') == pricing
            and config.get('max_output_tokens') == configured_output_limit(config)
            and config.get('provider_endpoint') in ('https://api.deepseek.com/chat/completions', 'https://api.deepseek.com/responses'), 'prior model/pricing contract differs')
        if config.get('registration_kind') == 'CODEX_TERMINAL_2468_V2':
            require(config.get('reasoning_effort') == 'none' and config.get('provider_endpoint') == 'https://api.deepseek.com/responses',
                'prior Terminal V2 reasoning/endpoint contract differs')
        historical = money(config.get('historical_bound_rmb'))
        limit = money(config.get('global_limit_rmb'))
        require(historical >= HISTORY_RMB and Decimal(0) < limit <= GLOBAL_MAX
            and historical + limit <= Decimal(5), 'prior total budget exceeds five CNY')
        replay = object.__new__(Ledger)
        replay.config, replay.config_sha256, replay.limit = config, first['config_sha256'], limit
        replay.campaign_id, replay.labels = registry(dict(config, schema_version=1,
            global_limit_rmb=str(limit if config.get('registration_kind') else GLOBAL_MAX)))
        replay.requests, replay.blocked = {}, False
        for event in events[1:]: replay._apply(event)
        require(not replay.blocked, 'prior provider exceeded token bound; manual accounting required')
        cost = replay._committed()
        receipt = {'schema_version': 1, 'ledger_sha256': sha(raw), 'ledger_bytes': len(raw),
            'campaign_id': replay.campaign_id, 'config_sha256': replay.config_sha256,
            'historical_bound_rmb': str(historical), 'accounted_cost_rmb_upper_bound': str(cost),
            'combined_bound_rmb': str(historical + cost), 'requests': len(replay.requests),
            'outstanding_or_unknown_requests': sum(event['event'] in ('RESERVED', 'UNKNOWN_CHARGE')
                for event in replay.requests.values())}
        return receipt, lock_fd
    except BaseException:
        os.close(lock_fd)
        raise


class Ledger:
    def __init__(self, directory, registration, pricing, limit='4.2', prior_ledger=None,
            provider_endpoint='https://api.deepseek.com/chat/completions'):
        require(provider_endpoint in ('https://api.deepseek.com/chat/completions', 'https://api.deepseek.com/responses'),
            'only explicitly supported DeepSeek endpoints allowed')
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        current = self.directory.lstat()
        require(stat.S_ISDIR(current.st_mode) and current.st_uid == os.geteuid() and not current.st_mode & 0o077,
                'owned private output directory required')
        require(not (self.directory / 'successor.json').exists(), 'broker ledger retired to successor; cannot reopen')
        self.limit = money(limit)
        require(Decimal(0) < self.limit <= GLOBAL_MAX, 'global cap must be positive and <=4.2 CNY')
        self.campaign_id, self.labels = registry(registration)
        if registration.get('registration_kind'):
            require(self.limit == money(registration.get('global_limit_rmb')),
                'explicit registration cap must match ledger limit')
        self.prior_lock_fd = None
        prior = None
        if prior_ledger is not None:
            require(Path(prior_ledger).absolute().parent != self.directory.absolute(), 'prior ledger cannot be current ledger')
            prior, self.prior_lock_fd = prior_budget(prior_ledger, pricing, self.directory)
        self.historical_bound = HISTORY_RMB if prior is None else money(prior['combined_bound_rmb'])
        if self.historical_bound + self.limit > Decimal(5):
            if self.prior_lock_fd is not None: os.close(self.prior_lock_fd); self.prior_lock_fd = None
            raise BudgetError('historical plus new cap exceeds five CNY')
        self.config = {'schema_version': 2, 'campaign_id': self.campaign_id, 'global_limit_rmb': str(self.limit),
            'historical_bound_rmb': str(self.historical_bound), 'pricing': pricing,
            'labels': [self.labels[key] for key in sorted(self.labels)], 'max_output_tokens': configured_output_limit(registration),
            'token_bound_basis': 'NORMALIZED_UTF8_BYTES_PLUS8192_FRAMING; PROVIDER_MAX_OUTPUT_CONTRACT',
            'provider_endpoint': provider_endpoint}
        if prior is not None: self.config['prior_budget_evidence'] = prior
        if registration.get('registration_kind'):
            self.config['registration_kind'] = registration['registration_kind']
        if registration.get('registration_kind') == 'CODEX_TERMINAL_2468_V2':
            self.config['reasoning_effort'] = 'none'
        self.config_sha256 = sha(canonical(self.config))
        self.lock, self.requests, self.blocked = threading.Lock(), {}, False
        self.path, self.stream, self.lock_fd = self.directory / 'budget-ledger.jsonl', None, None
        try:
            self.lock_fd = private_fd(self.directory / 'broker.lock', os.O_RDWR | os.O_CREAT)
            try: fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise BudgetError('another broker owns this ledger') from None
            require(not (self.directory / 'successor.json').exists(), 'broker ledger retired to successor; cannot reopen')
            descriptor = private_fd(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT)
            self.stream = os.fdopen(descriptor, 'a+', encoding='utf-8')
            require(os.fstat(descriptor).st_size <= MAX_LEDGER, 'ledger exceeds replay budget')
            self.stream.seek(0); raw = self.stream.read()
            require(not raw or raw.endswith('\n'), 'truncated ledger; fail closed')
            events = [parse_json(line) for line in raw.splitlines()]
            if events:
                require(events[0].get('event') == 'CONFIGURED' and events[0].get('config') == self.config
                    and events[0].get('config_sha256') == self.config_sha256, 'ledger configuration/pricing/labels changed')
                for event in events[1:]: self._apply(event)
            else:
                self._write({'event': 'CONFIGURED', 'config': self.config, 'config_sha256': self.config_sha256})
            self.stream.seek(0, os.SEEK_END)
            directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
            if prior_ledger is not None:
                parent = Path(prior_ledger).absolute().parent
                marker = parent / 'successor.json'
                expected = {'schema_version': 1, 'event': 'BUDGET_LEDGER_RETIRED_TO_EXACT_SUCCESSOR',
                    'prior_ledger_sha256': prior['ledger_sha256'], 'successor_directory': str(self.directory.absolute()),
                    'successor_config_sha256': self.config_sha256}
                if marker.exists():
                    descriptor = private_fd(marker, os.O_RDONLY)
                    with os.fdopen(descriptor, 'rb') as stream: actual = parse_json(stream.read(16385))
                    require(actual == expected, 'prior successor binding differs')
                else: write_new_private(marker, expected)
                parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(parent_fd)
                finally: os.close(parent_fd)
        except BaseException:
            self.close(); raise

    def close(self):
        if self.stream is not None: self.stream.close(); self.stream = None
        if self.lock_fd is not None: os.close(self.lock_fd); self.lock_fd = None
        if self.prior_lock_fd is not None: os.close(self.prior_lock_fd); self.prior_lock_fd = None

    def _committed(self, label=None):
        return sum((money(row['cost_rmb_bound']) for row in self.requests.values()
            if label is None or row['task_label'] == label), Decimal(0))

    def _write(self, event):
        event = dict(event, monotonic_ns=time.monotonic_ns(), recorded_at_unix_ns=time.time_ns())
        try:
            self.stream.write(canonical(event).decode() + '\n'); self.stream.flush(); os.fsync(self.stream.fileno())
        except BaseException:
            self.blocked = True
            raise

    def _validate(self, event):
        require(isinstance(event, dict) and event.get('config_sha256') == self.config_sha256, 'event config binding differs')
        kind, key, label = event.get('event'), event.get('request_id'), event.get('task_label')
        require(isinstance(key, str) and SAFE.fullmatch(key) and label in self.labels, 'invalid event request/label')
        cost = money(event.get('cost_rmb_bound'))
        if kind == 'RESERVED':
            require(not self.blocked, 'reservation follows a stopped campaign')
            require(key not in self.requests, 'duplicate ledger reservation')
            registration_kind = self.config.get('registration_kind')
            request_limit = {'CODEX_OBSERVER_DEMO': 3, 'CODEX_TERMINAL_2468': 12,
                'CODEX_TERMINAL_2468_V2': 12}.get(registration_kind)
            if request_limit is not None:
                require(sum(row['task_label'] == label for row in self.requests.values()) < request_limit,
                    'registered per-job request limit reached')
            require(key.startswith(label + '-step-') and key[len(label + '-step-'):].isdigit(), 'request ID must bind registered label and step')
            require(type(event.get('input_tokens_bound')) is int and event['input_tokens_bound'] >= 8192
                and type(event.get('output_tokens_bound')) is int
                and 1 <= event['output_tokens_bound'] <= configured_output_limit(self.config),
                'invalid reservation token bounds')
            extra = event.get('extra_input_tokens_bound', 0)
            require(type(extra) is int and 0 <= extra <= 262144 and event['input_tokens_bound'] >= 8192 + extra,
                'invalid additional bounded context')
            require(cost == token_cost(event['input_tokens_bound'], event['output_tokens_bound'])
                and event.get('pricing') == self.config['pricing'], 'reservation price differs')
            require(isinstance(event.get('request_sha256'), str) and re.fullmatch('[0-9a-f]{64}', event['request_sha256']), 'request payload digest required')
            require(self._committed() + cost <= self.limit and self._committed(label) + cost <= money(self.labels[label]['cap_rmb']),
                    'reservation exceeds global or job budget')
        else:
            previous = self.requests.get(key)
            require(previous and previous['event'] == 'RESERVED' and previous['task_label'] == label, 'settlement without outstanding reservation')
            if kind == 'UNKNOWN_CHARGE': require(cost == money(previous['cost_rmb_bound']), 'unknown charge must retain reservation')
            else:
                prompt, completion = event.get('prompt_tokens'), event.get('completion_tokens')
                require(kind in ('SETTLED', 'BOUND_EXCEEDED') and type(prompt) is int and prompt >= 0
                    and type(completion) is int and completion >= 0, 'invalid settlement')
                bounded = prompt <= previous['input_tokens_bound'] and completion <= previous['output_tokens_bound']
                require((kind == 'SETTLED') is bounded, 'settlement bound status differs')
                expected = token_cost(prompt, completion)
                if not bounded: expected = max(expected, money(previous['cost_rmb_bound']))
                require(cost == expected, 'settlement cost differs')

    def _apply(self, event):
        self._validate(event)
        self.requests[event['request_id']] = event
        if event['event'] == 'BOUND_EXCEEDED': self.blocked = True

    def _append(self, event):
        self._validate(event)  # Never append a corrupt/double transition.
        self._write(event)
        self._apply(event)

    def reserve(self, raw, output_tokens, label, request_id, extra_input_tokens=0):
        with self.lock:
            require(type(extra_input_tokens) is int and 0 <= extra_input_tokens <= 262144,
                'bounded explicit additional context tokens required')
            require(label in self.labels, 'unregistered task label')
            if request_id in self.requests: raise DuplicateRequest('request ID already consumed; never retransmitted')
            require(not self.blocked, 'campaign stopped after accounting error')
            event = {'event': 'RESERVED', 'request_id': request_id, 'task_label': label,
                'input_tokens_bound': len(raw) + 8192 + extra_input_tokens, 'output_tokens_bound': output_tokens,
                'request_sha256': sha(raw), 'pricing': self.config['pricing'], 'config_sha256': self.config_sha256,
                'cost_rmb_bound': str(token_cost(len(raw) + 8192, output_tokens))}
            if extra_input_tokens:
                event['extra_input_tokens_bound'] = extra_input_tokens
                event['cost_rmb_bound'] = str(token_cost(event['input_tokens_bound'], output_tokens))
            self._append(event)
            return dict(event)

    def settle(self, reservation, usage, provider_model=None):
        with self.lock:
            prompt = usage.get('prompt_tokens') if isinstance(usage, dict) else None
            completion = usage.get('completion_tokens') if isinstance(usage, dict) else None
            valid = type(prompt) is int and prompt >= 0 and type(completion) is int and completion >= 0
            if valid and 'total_tokens' in usage:
                valid = type(usage['total_tokens']) is int and usage['total_tokens'] == prompt + completion
            if not valid: return self._unknown(reservation, 'usage unavailable or inconsistent')
            bounded = prompt <= reservation['input_tokens_bound'] and completion <= reservation['output_tokens_bound']
            cost = token_cost(prompt, completion)
            event = {'event': 'SETTLED' if bounded else 'BOUND_EXCEEDED', 'request_id': reservation['request_id'],
                'task_label': reservation['task_label'], 'config_sha256': self.config_sha256,
                'prompt_tokens': prompt, 'completion_tokens': completion,
                'cost_rmb_bound': str(cost if bounded else max(cost, money(reservation['cost_rmb_bound']))),
                'provider_model': str(provider_model)[:128]}
            self._append(event)
            return event['event']

    def _unknown(self, reservation, reason):
        self._append({'event': 'UNKNOWN_CHARGE', 'request_id': reservation['request_id'],
            'task_label': reservation['task_label'], 'config_sha256': self.config_sha256,
            'cost_rmb_bound': reservation['cost_rmb_bound'], 'reason': reason[:128]})
        return 'UNKNOWN_CHARGE'

    def unknown(self, reservation, reason):
        with self.lock: return self._unknown(reservation, reason)

    def summary(self):
        with self.lock:
            cost = self._committed()
            return {'schema_version': 2, 'model': MODEL, 'campaign_id': self.campaign_id, 'global_limit_rmb': str(self.limit),
                'accounted_cost_rmb_upper_bound': str(cost), 'remaining_rmb': str(max(Decimal(0), self.limit - cost)),
                'historical_bound_rmb': str(self.historical_bound), 'combined_bound_rmb': str(self.historical_bound + cost),
                'requests': len(self.requests), 'blocked': self.blocked, 'config_sha256': self.config_sha256,
                'outstanding_or_unknown_requests': sum(row['event'] in ('RESERVED', 'UNKNOWN_CHARGE') for row in self.requests.values()),
                'pricing': self.config['pricing'], 'labels': {label: {'cap_rmb': row['cap_rmb'],
                    'accounted_cost_rmb_upper_bound': str(self._committed(label)),
                    'remaining_rmb': str(max(Decimal(0), money(row['cap_rmb']) - self._committed(label)))} for label, row in self.labels.items()},
                'note': 'Estimated CNY upper bound under saved price/provider token contract, not invoice; no upstream retry; unknown charges retained.'}


ALLOWED = {'model', 'messages', 'max_tokens', 'max_completion_tokens', 'temperature', 'top_p', 'response_format',
    'tools', 'tool_choice', 'parallel_tool_calls', 'stream', 'n', 'thinking'}


def normalize(raw):
    require(0 < len(raw) <= MAX_BODY, 'bounded request body required')
    data = parse_json(raw)
    require(isinstance(data, dict) and not set(data) - ALLOWED and data.get('model') == MODEL, 'unapproved parameter/model')
    require(data.get('stream', False) is False and type(data.get('n', 1)) is int and data.get('n', 1) == 1, 'only nonstreaming n=1 allowed')
    output = data.get('max_tokens', data.get('max_completion_tokens', MAX_OUTPUT))
    require(type(output) is int and 1 <= output <= MAX_OUTPUT, 'output must be1..1024 tokens')
    require('max_tokens' not in data or 'max_completion_tokens' not in data or data['max_tokens'] == data['max_completion_tokens'], 'conflicting output limits')
    messages = data.get('messages')
    require(isinstance(messages, list) and 1 <= len(messages) <= 128, '1..128 text messages required')
    for message in messages:
        require(isinstance(message, dict) and not set(message) - {'role', 'content', 'tool_calls', 'tool_call_id', 'name', 'reasoning_content'}
            and message.get('role') in ('system', 'user', 'assistant', 'tool')
            and (isinstance(message.get('content'), str) or message.get('content') is None), 'only text/function messages allowed')
        require(message.get('reasoning_content') in (None, ''), 'thinking content is not supported')
        message.pop('reasoning_content', None)
    tools = data.get('tools', [])
    require(isinstance(tools, list) and len(tools) <= 8, 'at most8 local functions allowed')
    for tool in tools:
        require(isinstance(tool, dict) and set(tool) == {'type', 'function'} and tool['type'] == 'function'
            and isinstance(tool['function'], dict) and not set(tool['function']) - {'name', 'description', 'parameters', 'strict'}
            and isinstance(tool['function'].get('name'), str) and SAFE.fullmatch(tool['function']['name']),
            'only declared local function tools; no provider Search/Fetch/vision')
    for name, lower, upper in (('temperature', 0, 2), ('top_p', 0, 1)):
        if name in data: require(type(data[name]) in (int, float) and math.isfinite(data[name]) and lower <= data[name] <= upper, 'invalid sampling parameter')
    if 'response_format' in data: require(data['response_format'] in ({'type': 'json_object'}, {'type': 'text'}), 'unsupported response format')
    if 'tool_choice' in data: require(data['tool_choice'] in ('auto', 'none', 'required'), 'only standard local function selection allowed')
    if 'parallel_tool_calls' in data: require(type(data['parallel_tool_calls']) is bool, 'parallel_tool_calls must be boolean')
    data.pop('max_completion_tokens', None)
    data.update(max_tokens=output, n=1, stream=False, thinking={'type': 'disabled'})
    payload = canonical(data)
    require(len(payload) <= MAX_BODY, 'normalized request exceeds body limit')
    return payload, output


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BudgetError('provider redirect rejected; never forward the same paid request twice')


class Broker(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    def __init__(self, address, ledger, provider_key, client_token):
        self.ledger, self.provider_key, self.client_token = ledger, provider_key, client_token
        super().__init__(address, Handler)

    def upstream(self, payload):
        request = urllib.request.Request(self.ledger.config['provider_endpoint'], data=payload, method='POST',
            headers={'Authorization': 'Bearer ' + self.provider_key, 'Content-Type': 'application/json'})
        # Exactly one invocation. No retry/backoff path, even on timeout/HTTP error.
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=180) as response:
            body = response.read(4 * 1024 * 1024 + 1)
        require(len(body) <= 4 * 1024 * 1024, 'provider response exceeds bound')
        return parse_json(body)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self, status, value):
        body = canonical(value)
        self.send_response(status); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        if self.path == '/health': self.reply(200, self.server.ledger.summary())
        elif self.path == '/v1/models': self.reply(200, {'object': 'list', 'data': [{'id': MODEL, 'object': 'model'}]})
        else: self.reply(404, {'error': 'unsupported endpoint'})

    def do_POST(self):
        if self.path != '/v1/chat/completions': return self.reply(404, {'error': 'unsupported endpoint'})
        if not secrets.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + self.server.client_token):
            return self.reply(401, {'error': 'invalid local broker credential'})
        try:
            require(len(self.headers.get_all('Content-Length', [])) == 1 and not self.headers.get('Transfer-Encoding'), 'unambiguous length required')
            length = int(self.headers.get('Content-Length', '0'))
            require(0 < length <= MAX_BODY, 'bounded body required')
            self.connection.settimeout(15)
            raw = self.rfile.read(length)
            require(len(raw) == length, 'incomplete body')
            payload, output = normalize(raw)
            label, request_id = self.headers.get('X-Benchmark-Task', ''), self.headers.get('X-Request-ID', '')
            reservation = self.server.ledger.reserve(payload, output, label, request_id)
        except DuplicateRequest:
            return self.reply(409, {'error': 'DUPLICATE_REQUEST_ID', 'retry_allowed': False})
        except (ValueError, BudgetError, TimeoutError):
            return self.reply(429, {'error': 'REQUEST_REJECTED_BY_POLICY_OR_BUDGET', 'retry_allowed': False})
        try:
            result = self.server.upstream(payload)
        except Exception as error:
            self.server.ledger.unknown(reservation, type(error).__name__)
            return self.reply(502, {'error': 'PROVIDER_RESULT_UNKNOWN_RESERVATION_RETAINED', 'retry_allowed': False})
        if not isinstance(result, dict) or not isinstance(result.get('choices'), list) or len(result['choices']) != 1:
            self.server.ledger.unknown(reservation, 'provider response must have exactly one choice')
            return self.reply(502, {'error': 'PROVIDER_SHAPE_UNKNOWN_RESERVATION_RETAINED', 'retry_allowed': False})
        status = self.server.ledger.settle(reservation, result.get('usage'), result.get('model'))
        if status == 'BOUND_EXCEEDED': return self.reply(502, {'error': 'TOKEN_BOUND_EXCEEDED_CAMPAIGN_STOPPED', 'retry_allowed': False})
        return self.reply(200, result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--api-key-file', type=Path, required=True)
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--pricing-evidence', type=Path, required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=10091)
    parser.add_argument('--limit-rmb', default='4.2')
    parser.add_argument('--prior-ledger', type=Path, help='Closed predecessor; replay all costs and retain its exclusive lock')
    args = parser.parse_args(argv)
    require(args.host == '127.0.0.1', 'broker binds loopback only')
    require(args.labels.is_file() and not args.labels.is_symlink() and args.labels.stat().st_size <= 65536, 'bounded registration file required')
    ledger = Ledger(args.output_dir, parse_json(args.labels.read_bytes()), read_pricing(args.pricing_evidence), args.limit_rmb, args.prior_ledger)
    server = None
    try:
        token_file = args.output_dir / 'client-token'
        if not token_file.exists():
            descriptor = private_fd(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(secrets.token_hex(32) + '\n'); stream.flush(); os.fsync(stream.fileno())
        server = Broker((args.host, args.port), ledger, private_read(args.api_key_file), private_read(token_file))
        ready = {'base_url': f'http://127.0.0.1:{server.server_port}/v1',
            'guest_base_url': f'http://10.0.2.2:{server.server_port}/v1', 'client_token_file': str(token_file), **ledger.summary()}
        # Each launch writes a fresh receipt; never overwrites prior startup/final evidence.
        suffix = str(time.time_ns())
        write_new_private(args.output_dir / ('broker-ready-' + suffix + '.json'), ready)
        print(canonical({'status': 'READY', 'port': server.server_port, 'model': MODEL, 'config_sha256': ledger.config_sha256}).decode(), flush=True)
        try: server.serve_forever(poll_interval=.25)
        except KeyboardInterrupt: pass
        finally: write_new_private(args.output_dir / ('budget-summary-' + suffix + '.json'), ledger.summary())
    finally:
        if server is not None: server.server_close()
        ledger.close()
    return 0


if __name__ == '__main__': raise SystemExit(main())
