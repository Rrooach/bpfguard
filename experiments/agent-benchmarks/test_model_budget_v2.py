"""Offline budget tests; every provider call is mocked, never paid/networked."""
from decimal import Decimal
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

SPEC = importlib.util.spec_from_file_location('model_budget_v2', Path(__file__).with_name('model_budget_v2.py'))
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)


def registration(pilots=True):
    labels = [{'label': f'model-{benchmark}-c{concurrency}-{index:02d}',
        'group_id': f'{benchmark}-c{concurrency}', 'job_id': f'{benchmark}-{index:02d}',
        'kind': 'FORMAL', 'cap_rmb': '.065'}
        for benchmark in ('swe', 'terminal') for concurrency in (2, 4, 6, 8) for index in range(8)]
    if pilots:
        labels.extend({'label': f'pilot-model-{benchmark}', 'group_id': f'pilot-{benchmark}',
            'job_id': f'pilot-{benchmark}', 'kind': 'PILOT', 'cap_rmb': '.02'} for benchmark in ('swe', 'terminal'))
    return {'schema_version': 1, 'campaign_id': 'model-timeline-2468-20261018-001', 'global_limit_rmb': '4.2', 'labels': labels}


def pricing():
    return {'evidence_sha256': 'a' * 64, 'html_sha256': 'b' * 64, 'model': B.MODEL,
        'model_version': B.MODEL_VERSION, 'currency': 'CNY', 'input_rmb_per_million': '2', 'output_rmb_per_million': '8'}


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def ledger(self, **kwargs):
        value = B.Ledger(self.root, registration(), pricing(), **kwargs)
        self.addCleanup(value.close)
        return value

    def test_registry_exact64_and_two_explicit_pilot_caps(self):
        _, rows = B.registry(registration())
        self.assertEqual(len(rows), 66)
        self.assertEqual(sum((Decimal(row['cap_rmb']) for row in rows.values()), Decimal(0)), Decimal('4.20'))
        for change in ('missing', 'duplicate', 'wrong-job', 'cap', 'pilot-over', 'unknown-pilot'):
            with self.subTest(change=change):
                value = registration()
                if change == 'missing': value['labels'].pop(0)
                elif change == 'duplicate': value['labels'].append(value['labels'][0])
                elif change == 'wrong-job': value['labels'][0]['job_id'] = 'terminal-00'
                elif change == 'cap': value['labels'][0]['cap_rmb'] = '.1'
                elif change == 'pilot-over': value['labels'][-1]['cap_rmb'] = '.04'
                else: value['labels'][-1]['label'] = 'other-pilot'
                with self.assertRaises(B.BudgetError): B.registry(value)

    def test_threaded_global_reservation_never_overcommits(self):
        ledger = self.ledger(limit='.06')
        accepted, rejected = [], []
        def request(index):
            label = f'model-swe-c2-{index:02d}'
            try: accepted.append(ledger.reserve(b'x', 1, label, label + '-step-0'))
            except B.BudgetError: rejected.append(index)
        workers = [threading.Thread(target=request, args=(index,)) for index in range(8)]
        for worker in workers: worker.start()
        for worker in workers: worker.join()
        self.assertEqual(len(accepted), 3)
        self.assertEqual(len(accepted) + len(rejected), 8)
        self.assertLessEqual(Decimal(ledger.summary()['accounted_cost_rmb_upper_bound']), Decimal('.06'))

    def test_per_job_cap_prevents_one_worker_spending_global_budget(self):
        ledger = self.ledger(); label = 'model-swe-c2-00'
        ledger.reserve(b'{}', 1024, label, label + '-step-0')
        ledger.reserve(b'{}', 1024, label, label + '-step-1')
        with self.assertRaisesRegex(B.BudgetError, 'job budget'): ledger.reserve(b'{}', 1024, label, label + '-step-2')
        other = 'model-swe-c2-01'
        ledger.reserve(b'{}', 1024, other, other + '-step-0')
        self.assertEqual(ledger.summary()['requests'], 3)

    def test_single_owner_flock_also_excludes_another_instance(self):
        ledger = self.ledger()
        with self.assertRaisesRegex(B.BudgetError, 'another broker'): B.Ledger(self.root, registration(), pricing())
        ledger.close()
        self.ledger().summary()

    def test_flock_excludes_another_actual_process(self):
        self.ledger()
        program = 'import runpy,sys; B=runpy.run_path(sys.argv[1]); D=B["B"]; R=B["registration"]; P=B["pricing"];\ntry: D.Ledger(sys.argv[2],R(),P())\nexcept D.BudgetError: print("EXCLUSIVE_LOCK_REJECTED")\nelse: raise SystemExit("lock failed")'
        result = subprocess.run([sys.executable, '-B', '-c', program, str(Path(__file__).resolve()), str(self.root)],
            capture_output=True, text=True, timeout=5, check=True)
        self.assertEqual(result.stdout.strip(), 'EXCLUSIVE_LOCK_REJECTED')

    def test_restart_preserves_unknown_and_unsettled_cost_and_ids(self):
        ledger = self.ledger(); label = 'model-swe-c2-00'
        first = ledger.reserve(b'{}', 100, label, label + '-step-0')
        ledger.unknown(first, 'TimeoutError')
        ledger.reserve(b'{}', 100, label, label + '-step-1')
        before = ledger.summary(); ledger.close()
        recovered = self.ledger()
        self.assertEqual(recovered.summary(), before)
        for step in range(2):
            with self.assertRaises(B.DuplicateRequest): recovered.reserve(b'different', 1, label, label + f'-step-{step}')

    def test_usage_settlement_releases_only_unused_prepaid_bound(self):
        ledger = self.ledger(); label = 'model-swe-c2-00'
        item = ledger.reserve(b'{}', 1024, label, label + '-step-0')
        ledger.settle(item, {'prompt_tokens': 100, 'completion_tokens': 50, 'total_tokens': 150}, B.MODEL)
        result = ledger.summary()
        self.assertEqual(result['accounted_cost_rmb_upper_bound'], '0.0006')
        self.assertEqual(result['combined_bound_rmb'], '0.468950')
        self.assertEqual(result['outstanding_or_unknown_requests'], 0)

    def test_missing_inconsistent_and_negative_usage_retain_full_reservation(self):
        ledger = self.ledger()
        for index, usage in enumerate((None, {}, {'prompt_tokens': -1, 'completion_tokens': 1},
                {'prompt_tokens': 10, 'completion_tokens': 1, 'total_tokens': 99})):
            label = f'model-swe-c2-{index:02d}'
            item = ledger.reserve(b'{}', 1, label, label + '-step-0')
            self.assertEqual(ledger.settle(item, usage), 'UNKNOWN_CHARGE')
            self.assertEqual(ledger.requests[item['request_id']]['cost_rmb_bound'], item['cost_rmb_bound'])

    def test_exceeded_bound_stops_all_new_calls_and_survives_restart(self):
        ledger = self.ledger(); label = 'model-swe-c2-00'
        item = ledger.reserve(b'{}', 1, label, label + '-step-0')
        self.assertEqual(ledger.settle(item, {'prompt_tokens': 10, 'completion_tokens': 2}), 'BOUND_EXCEEDED')
        self.assertTrue(ledger.summary()['blocked'])
        ledger.close(); recovered = self.ledger()
        with self.assertRaisesRegex(B.BudgetError, 'stopped'): recovered.reserve(b'{}', 1, label, label + '-step-1')

    def test_no_duplicate_settlement_written_to_wal(self):
        ledger = self.ledger(); label = 'model-swe-c2-00'
        item = ledger.reserve(b'{}', 1, label, label + '-step-0')
        ledger.unknown(item, 'Disconnected')
        before = ledger.path.read_bytes()
        with self.assertRaisesRegex(B.BudgetError, 'without outstanding'): ledger.unknown(item, 'Again')
        self.assertEqual(before, ledger.path.read_bytes())

    def test_repricing_relabeling_or_limit_change_cannot_reset_old_budget(self):
        ledger = self.ledger(); ledger.close()
        changed_price = dict(pricing(), evidence_sha256='c' * 64)
        with self.assertRaisesRegex(B.BudgetError, 'configuration'): B.Ledger(self.root, registration(), changed_price)
        with self.assertRaisesRegex(B.BudgetError, 'configuration'): B.Ledger(self.root, registration(), pricing(), '4.1')

    def test_truncated_or_corrupted_ledger_fails_closed(self):
        ledger = self.ledger(); ledger.close()
        path = self.root / 'budget-ledger.jsonl'
        original = path.read_bytes()
        path.write_bytes(original + b'{"event":')
        with self.assertRaisesRegex(B.BudgetError, 'truncated'): B.Ledger(self.root, registration(), pricing())
        path.write_bytes(original + B.canonical({'event': 'RESERVED', 'request_id': 'bad'}) + b'\n')
        with self.assertRaises(B.BudgetError): B.Ledger(self.root, registration(), pricing())

    def test_reservation_contains_pricing_and_config_binding(self):
        ledger = self.ledger(); label = 'model-swe-c2-00'
        item = ledger.reserve(b'{}', 1, label, label + '-step-0')
        self.assertEqual(item['pricing'], pricing())
        self.assertEqual(item['config_sha256'], ledger.config_sha256)
        self.assertEqual(json.loads(ledger.path.read_text().splitlines()[0])['config'], ledger.config)

    def test_private_files_and_unsafe_amounts_are_rejected(self):
        for limit in ('NaN', 'Infinity', '-1', '4.200001'):
            with self.subTest(limit=limit), self.assertRaises(B.BudgetError): B.Ledger(self.root, registration(), pricing(), limit)
        secret = self.root / 'not-a-real-key'
        secret.write_text('dummy')
        secret.chmod(0o644)
        with self.assertRaises(B.BudgetError): B.private_read(secret)
        secret.chmod(0o600)
        self.assertEqual(B.private_read(secret), 'dummy')
        link = self.root / 'link'; link.symlink_to(secret)
        with self.assertRaises(OSError): B.private_read(link)
        secret.write_text('x' * 512 + '\n\n' + 'ignored-tail')
        with self.assertRaises(B.BudgetError): B.private_read(secret)

    def test_fsync_failure_never_authorizes_upstream(self):
        ledger = self.ledger(); label = 'model-swe-c2-00'
        with mock.patch.object(B.os, 'fsync', side_effect=OSError('fake disk full')):
            with self.assertRaises(OSError): ledger.reserve(b'{}', 1, label, label + '-step-0')
        self.assertTrue(ledger.blocked)
        self.assertEqual(ledger.requests, {})


class PolicyTests(unittest.TestCase):
    def request(self, **changes):
        payload = {'model': B.MODEL, 'messages': [{'role': 'user', 'content': 'hello'}], 'max_tokens': 32}
        payload.update(changes)
        return B.canonical(payload)

    def test_forced_n1_nonstreaming_thinking_disabled(self):
        raw, limit = B.normalize(self.request(thinking={'type': 'enabled'}))
        data = json.loads(raw)
        self.assertEqual((data['n'], data['stream'], data['thinking'], limit), (1, False, {'type': 'disabled'}, 32))

    def test_n_multiple_unknown_charge_fields_model_vision_server_tools_rejected(self):
        for changes in ({'n': 2}, {'n': True}, {'best_of': 10}, {'model': 'deepseek-v4-pro'}, {'stream': True},
                {'max_tokens': 1025}, {'messages': [{'role': 'user', 'content': [{'type': 'image_url'}]}]},
                {'tools': [{'type': 'web_search'}]}, {'service_tier': 'priority'}):
            with self.subTest(changes=changes), self.assertRaises(B.BudgetError): B.normalize(self.request(**changes))

    def test_duplicate_json_fields_and_nonfinite_are_rejected(self):
        with self.assertRaises(B.BudgetError): B.normalize(b'{"model":"deepseek-flash","model":"deepseek-flash"}')
        with self.assertRaises(B.BudgetError): B.normalize(b'{"temperature":NaN}')

    def test_supported_shell_function_and_json_mode(self):
        raw, _ = B.normalize(self.request(response_format={'type': 'json_object'}, tools=[{'type': 'function',
            'function': {'name': 'bash', 'parameters': {'type': 'object', 'properties': {'command': {'type': 'string'}}}}}]))
        self.assertEqual(json.loads(raw)['tools'][0]['function']['name'], 'bash')

    def test_redirect_is_rejected_without_followup(self):
        with self.assertRaises(B.BudgetError): B.NoRedirect().redirect_request(None, None, 307, '', {}, 'https://elsewhere/')

    def test_pricing_html_and_rates_are_bound_and_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); html = root / 'pricing.html'; html.write_bytes(b'public fixture, not fetched')
            data = {'schema_version': 1, 'source_url': 'https://api-docs.deepseek.com/zh-cn/quick_start/pricing/',
                'model': B.MODEL, 'model_version': B.MODEL_VERSION, 'currency': 'CNY',
                'input_rmb_per_million': '2', 'output_rmb_per_million': '8',
                'source_html_path': html.name, 'source_html_sha256': B.sha(html.read_bytes()),
                'source_html_size_bytes': html.stat().st_size}
            path = root / 'pricing.json'; path.write_bytes(B.canonical(data))
            value = B.read_pricing(path)
            self.assertEqual(value['evidence_sha256'], B.sha(path.read_bytes()))
            html.write_bytes(b'tampered')
            with self.assertRaisesRegex(B.BudgetError, 'digest differs'): B.read_pricing(path)
            data['output_rmb_per_million'] = '4'; path.write_bytes(B.canonical(data))
            with self.assertRaisesRegex(B.BudgetError, 'approved model/rates'): B.read_pricing(path)
            data['output_rmb_per_million'] = '8'; data['source_html_path'] = '../unrelated'
            path.write_bytes(B.canonical(data))
            with self.assertRaisesRegex(B.BudgetError, 'sibling filename'): B.read_pricing(path)


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = B.Ledger(self.temp.name, registration(), pricing())
        self.provider = mock.patch.object(B.Broker, 'upstream', return_value={
            'model': B.MODEL, 'choices': [{'message': {'role': 'assistant', 'content': 'OK'}}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 1}})
        self.upstream = self.provider.start()
        self.server = B.Broker(('127.0.0.1', 0), self.ledger, 'fake-provider-never-sent', 'local-dummy-token')
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01})
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.provider.stop(); self.ledger.close(); self.temp.cleanup()

    def call(self, changes=None, request_id='model-swe-c2-00-step-0', label='model-swe-c2-00', token='local-dummy-token'):
        data = {'model': B.MODEL, 'messages': [{'role': 'user', 'content': 'hello'}], 'max_tokens': 32}
        data.update(changes or {})
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token, 'X-Benchmark-Task': label}
        if request_id is not None: headers['X-Request-ID'] = request_id
        request = urllib.request.Request(f'http://127.0.0.1:{self.server.server_port}/v1/chat/completions',
            data=B.canonical(data), headers=headers)
        with urllib.request.urlopen(request, timeout=3) as response: return json.load(response)

    def test_success_is_reserved_and_fsynced_before_provider_and_settled_once(self):
        def provider(payload):
            event = json.loads(self.ledger.path.read_text().splitlines()[-1])
            self.assertEqual(event['event'], 'RESERVED')
            self.assertEqual(event['request_id'], 'model-swe-c2-00-step-0')
            self.assertEqual(event['request_sha256'], B.sha(payload))
            return {'choices': [{'message': {'content': 'ok'}}], 'usage': {'prompt_tokens': 10, 'completion_tokens': 1}}
        self.upstream.side_effect = provider
        self.call()
        self.assertEqual(self.upstream.call_count, 1)
        self.assertEqual(self.ledger.requests['model-swe-c2-00-step-0']['event'], 'SETTLED')

    def test_duplicate_id_different_body_never_forwards_again(self):
        self.call()
        with self.assertRaises(urllib.error.HTTPError) as raised: self.call({'messages': [{'role': 'user', 'content': 'changed'}]})
        self.assertEqual(raised.exception.code, 409)
        self.assertEqual(self.upstream.call_count, 1)

    def test_failure_unknown_is_accounted_and_same_id_cannot_retry(self):
        self.upstream.side_effect = TimeoutError('fake no provider contacted')
        with self.assertRaises(urllib.error.HTTPError) as raised: self.call()
        self.assertEqual(raised.exception.code, 502)
        self.assertEqual(self.ledger.summary()['outstanding_or_unknown_requests'], 1)
        self.assertGreater(Decimal(self.ledger.summary()['accounted_cost_rmb_upper_bound']), 0)
        with self.assertRaises(urllib.error.HTTPError) as raised: self.call()
        self.assertEqual(raised.exception.code, 409)
        self.assertEqual(self.upstream.call_count, 1)

    def test_missing_usage_keeps_reservation(self):
        self.upstream.return_value = {'choices': [{'message': {'content': 'OK'}}]}
        self.call()
        self.assertEqual(self.ledger.requests['model-swe-c2-00-step-0']['event'], 'UNKNOWN_CHARGE')

    def test_multiple_provider_choices_do_not_free_reservation(self):
        self.upstream.return_value = {'choices': [{}, {}], 'usage': {'prompt_tokens': 1, 'completion_tokens': 1}}
        with self.assertRaises(urllib.error.HTTPError) as raised: self.call()
        self.assertEqual(raised.exception.code, 502)
        self.assertEqual(self.ledger.requests['model-swe-c2-00-step-0']['event'], 'UNKNOWN_CHARGE')

    def test_concurrent_http_duplicate_does_not_forward_while_first_is_inflight(self):
        entered, finish = threading.Event(), threading.Event()
        failures = []
        def provider(payload):
            entered.set(); self.assertTrue(finish.wait(2))
            return {'choices': [{}], 'usage': {'prompt_tokens': 1, 'completion_tokens': 1}}
        self.upstream.side_effect = provider
        def first():
            try: self.call()
            except Exception as error: failures.append(error)
        thread = threading.Thread(target=first); thread.start()
        try:
            self.assertTrue(entered.wait(2))
            with self.assertRaises(urllib.error.HTTPError) as raised: self.call()
            self.assertEqual(raised.exception.code, 409)
            self.assertEqual(self.upstream.call_count, 1)
        finally:
            finish.set(); thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])

    def test_unknown_label_missing_id_wrong_credential_and_multin_do_not_call_provider(self):
        for kwargs in ({'label': 'not-registered'}, {'request_id': None}, {'token': 'wrong'}, {'changes': {'n': 2}},
                {'request_id': 'model-swe-c2-01-step-0'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(urllib.error.HTTPError): self.call(**kwargs)
        self.upstream.assert_not_called()
        self.assertEqual(self.ledger.summary()['requests'], 0)

    def test_health_does_not_reveal_either_credential(self):
        with urllib.request.urlopen(f'http://127.0.0.1:{self.server.server_port}/health') as response: body = response.read()
        self.assertNotIn(b'fake-provider-never-sent', body)
        self.assertNotIn(b'local-dummy-token', body)
        self.assertEqual(json.loads(body)['global_limit_rmb'], '4.2')


if __name__ == '__main__': unittest.main()
