"""Responses accounting tests; every upstream invocation is mocked, not paid."""
import importlib.util
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

import codex_response_budget as C
from test_model_budget_v2 import pricing


def sse(kind='response.completed', usage=None):
    result = {'type': kind, 'response': {'model': C.B.MODEL, 'usage': usage or {'input_tokens': 50, 'output_tokens': 10}}}
    return b'event: '+kind.encode()+b'\ndata: '+C.B.canonical(result)+b'\n\n'


TOOL = {'type': 'function', 'name': 'observer_bash', 'parameters': {}}


class CodexBudgetTests(unittest.TestCase):
    def test_real_responses_not_chat_and_no_hosted_tools(self):
        raw = C.normalize(C.B.canonical({'model': C.B.MODEL, 'input': [], 'stream': True,
            'tools': [TOOL, {'type': 'function', 'name': 'request_user_input'}, {'type': 'custom', 'name': 'apply_patch'}],
            'client_metadata': {'source': 'codex-app-server'}}))
        self.assertEqual(json.loads(raw)['max_output_tokens'], 1024)
        self.assertEqual(json.loads(raw)['tools'], [TOOL])
        for tool in ({'type': 'web_search'}, {'type': 'mcp'}, {'type': 'image_generation'},
                     {'type': 'namespace', 'tools': [{'type': 'web_search'}]}):
            with self.subTest(tool=tool), self.assertRaises(C.B.BudgetError):
                C.normalize(C.B.canonical({'model': C.B.MODEL, 'input': [], 'tools': [tool]}))

    def test_terminal_usage_only_no_reasoning_double_count(self):
        usage, model = C.response_usage(sse(usage={'input_tokens': 15, 'output_tokens': 7,
            'output_tokens_details': {'reasoning_tokens': 6}}))
        self.assertEqual(usage, {'prompt_tokens': 15, 'completion_tokens': 7})
        self.assertEqual(model, C.B.MODEL)
        with self.assertRaises(C.B.BudgetError): C.response_usage(sse()+sse())
        with self.assertRaises(C.B.BudgetError): C.response_usage(b'data: [DONE]\n\n')
        usage, _ = C.response_usage(sse(usage={'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 999}))
        self.assertEqual(usage['total_tokens'], 999)

    def test_unpriced_tier_and_implicit_large_input_rejected(self):
        inputs = [[{'role': 'user', 'content': [{'type': 'input_image', 'image_url': 'https://example.invalid/a.png'}]}],
            [{'type': 'item_reference', 'id': 'hidden-large-history'}],
            [{'type': 'message', 'role': 'user', 'content': [{'type': 'input_file', 'file_id': 'file-big'}]}],
            [{'type': 'reasoning', 'encrypted_content': 'hidden', 'summary': []}]]
        for value in inputs:
            with self.subTest(value=value), self.assertRaises(C.B.BudgetError):
                C.normalize(C.B.canonical({'model': C.B.MODEL, 'input': value}))
        with self.assertRaises(C.B.BudgetError):
            C.normalize(C.B.canonical({'model': C.B.MODEL, 'input': 'hi', 'service_tier': 'priority'}))
        for value in ([{'role': 'user', 'content': [{'type': 'input_text', 'text': 'hi'}]}],
                [{'type': 'function_call', 'name': 'observer_bash', 'call_id': 'a', 'arguments': '{}'},
                 {'type': 'function_call_output', 'call_id': 'a', 'output': 'text'}]):
            self.assertTrue(C.normalize(C.B.canonical({'model': C.B.MODEL, 'input': value, 'tools': [TOOL]})))

    def test_builtin_function_or_patch_not_delivered_to_codex(self):
        for kind, name in (('function_call', 'exec_command'), ('custom_tool_call', 'apply_patch'),
                           ('function_call', 'spawn_agent'), ('function_call', 'request_user_input')):
            raw = b'data: '+C.B.canonical({'type': 'response.completed', 'response': {'output': [{'type': kind, 'name': name}]}})+b'\n'
            self.assertFalse(C.controlled_output(raw))
        raw = b'data: '+C.B.canonical({'type': 'response.completed', 'response': {'output': [{'type': 'function_call', 'name': 'observer_bash'}]}})+b'\n'
        self.assertTrue(C.controlled_output(raw))

    def test_only_known_prior_reasoning_handle_may_be_reused(self):
        payload = {'model': C.B.MODEL, 'tools': [TOOL], 'input': [
            {'type': 'reasoning', 'id': 'known-id', 'encrypted_content': 'provider-handle', 'summary': []}]}
        with self.assertRaises(C.B.BudgetError): C.normalize(C.B.canonical(payload))
        self.assertTrue(C.normalize(C.B.canonical(payload), {'provider-handle': {'id': 'known-id', 'context_tokens_bound': 20000}}))
        with self.assertRaises(C.B.BudgetError):
            C.normalize(C.B.canonical(payload), {'provider-handle': {'id': 'different-id', 'context_tokens_bound': 20000}})

    def test_known_handle_is_extracted_only_from_terminal_provider_output(self):
        value = {'type': 'response.completed', 'response': {'output': [
            {'type': 'reasoning', 'id': 'r1', 'encrypted_content': 'h1'}]}}
        self.assertEqual(C.reasoning_handles(b'data: '+C.B.canonical(value)+b'\n'), {'h1': 'r1'})
        value['type'] = 'response.output_item.added'
        self.assertEqual(C.reasoning_handles(b'data: '+C.B.canonical(value)+b'\n'), {})

    def test_explicit_single_demo_registry_not_64_job_experiment(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = C.B.Ledger(directory, C.registration('fixture'), pricing(), '.4', provider_endpoint=C.ENDPOINT)
            try:
                self.assertEqual(list(ledger.labels), [C.LABEL])
                self.assertEqual(ledger.config['provider_endpoint'], C.ENDPOINT)
                self.assertEqual(ledger.config['registration_kind'], 'CODEX_OBSERVER_DEMO')
            finally: ledger.close()

    def test_terminal_registry_is_exact32_not_an_unbounded_label_mode(self):
        value = C.registration('terminal-fixture', 'terminal')
        campaign, labels = C.B.registry(value)
        self.assertEqual(campaign, 'terminal-fixture')
        self.assertEqual(len(labels), 32)
        self.assertEqual(sum(C.B.money(row['cap_rmb']) for row in labels.values()), C.B.money('4.0'))
        self.assertEqual(set(labels), {f'codex-terminal-c{concurrency}-{index:02d}'
            for concurrency in (2, 4, 6, 8) for index in range(8)})
        corruptions = []
        for field, changed in (('cap_rmb', '.126'), ('job_id', 'terminal-08'),
                ('group_id', 'codex-terminal-c3'), ('kind', 'FORMAL'), ('label', 'codex-terminal-c2-08')):
            bad = json.loads(json.dumps(value)); bad['labels'][0][field] = changed; corruptions.append(bad)
        bad = json.loads(json.dumps(value)); bad['labels'].pop(); corruptions.append(bad)
        bad = json.loads(json.dumps(value)); bad['labels'][-1] = bad['labels'][0]; corruptions.append(bad)
        bad = json.loads(json.dumps(value)); bad['global_limit_rmb'] = '4.2'; corruptions.append(bad)
        for bad in corruptions:
            with self.subTest(bad=bad), self.assertRaises(C.B.BudgetError): C.B.registry(bad)
        with self.assertRaises(C.B.BudgetError): C.registration('bad', 'unlimited')


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = C.B.Ledger(self.temp.name, C.registration('fixture'), pricing(), '.4', provider_endpoint=C.ENDPOINT)
        self.patch = mock.patch.object(C.Broker, 'upstream', return_value=sse())
        self.upstream = self.patch.start()
        self.server = C.Broker(('127.0.0.1', 0), self.ledger, 'dummy-provider', 'dummy-client')
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01})
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.patch.stop(); self.ledger.close(); self.temp.cleanup()

    def request(self, text='hello', tools=None, label=None, reasoning=None):
        payload = {'model': C.B.MODEL, 'input': text, 'stream': True, 'store': False,
            'tools': tools if tools is not None else [TOOL]}
        if reasoning is not None: payload['reasoning'] = reasoning
        raw = C.B.canonical(payload)
        request = urllib.request.Request(f'http://127.0.0.1:{self.server.server_port}/v1/responses', data=raw,
            headers={'Authorization': 'Bearer dummy-client', 'Content-Type': 'application/json', 'X-Benchmark-Task': label or C.LABEL})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as result:
            return result.read()

    def test_three_calls_and_duplicate_never_contact_provider_again(self):
        self.assertEqual(self.request(), sse())
        with self.assertRaises(urllib.error.HTTPError) as error: self.request()
        self.assertEqual(error.exception.code, 429)
        self.assertEqual(self.upstream.call_count, 1)
        self.request('next'); self.request('last')
        with self.assertRaises(urllib.error.HTTPError): self.request('too many')
        self.assertEqual(self.upstream.call_count, 3)
        self.assertEqual(self.ledger.summary()['outstanding_or_unknown_requests'], 0)

    def test_accounted_before_bytes_returned_and_unknown_keeps_reservation(self):
        self.request()
        self.assertEqual(self.ledger.summary()['accounted_cost_rmb_upper_bound'], '0.00018')
        self.upstream.side_effect = TimeoutError('fixture only')
        with self.assertRaises(urllib.error.HTTPError): self.request('unknown')
        summary = self.ledger.summary()
        self.assertEqual(summary['outstanding_or_unknown_requests'], 1)
        self.assertGreater(float(summary['accounted_cost_rmb_upper_bound']), .016)

    def test_hosted_tools_rejected_before_reservation_or_network(self):
        with self.assertRaises(urllib.error.HTTPError): self.request(tools=[{'type': 'web_search'}])
        self.assertEqual(self.ledger.summary()['requests'], 0)
        self.upstream.assert_not_called()

    def test_inconsistent_total_retains_entire_reservation(self):
        self.upstream.return_value = sse(usage={'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 999})
        self.request()
        self.assertEqual(self.ledger.summary()['outstanding_or_unknown_requests'], 1)
        self.assertGreater(float(self.ledger.summary()['accounted_cost_rmb_upper_bound']), .016)

    def test_opaque_repeated_references_charge_full_source_context_and_output(self):
        response = {'type': 'response.completed', 'response': {'model': C.B.MODEL,
            'usage': {'input_tokens': 100, 'output_tokens': 10, 'total_tokens': 110},
            'output': [{'type': 'reasoning', 'id': 'r1', 'encrypted_content': 'h1', 'summary': []}]}}
        self.upstream.return_value = b'data: '+C.B.canonical(response)+b'\n'
        self.request('first')
        source = json.loads(self.ledger.path.read_text().splitlines()[1])
        bound = source['input_tokens_bound']+source['output_tokens_bound']
        self.assertEqual(self.server.known_reasoning['h1']['context_tokens_bound'], bound)
        self.upstream.return_value = sse()
        self.request([{'type': 'reasoning', 'id': 'r1', 'encrypted_content': 'h1', 'summary': []}]*2)
        records = [json.loads(row) for row in self.ledger.path.read_text().splitlines()]
        second = [row for row in records if row.get('event') == 'RESERVED'][1]
        self.assertEqual(second['extra_input_tokens_bound'], 2*bound)

    def test_reused_handle_never_shrinks_context_bound(self):
        raw = b'data: '+C.B.canonical({'type': 'response.completed', 'response': {
            'output': [{'type': 'reasoning', 'id': 'r1', 'encrypted_content': 'h1'}]}})+b'\n'
        self.server.remember_reasoning(raw, {'request_id': 'a', 'input_tokens_bound': 20000, 'output_tokens_bound': 1024})
        self.server.remember_reasoning(raw, {'request_id': 'b', 'input_tokens_bound': 10000, 'output_tokens_bound': 1024})
        self.assertEqual(self.server.known_reasoning['h1']['context_tokens_bound'], 21024)


class TerminalBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = C.B.Ledger(self.temp.name, C.registration('terminal-fixture', 'terminal'),
            pricing(), '4.0', provider_endpoint=C.ENDPOINT)
        self.patch = mock.patch.object(C.Broker, 'upstream', return_value=sse())
        self.upstream = self.patch.start()
        self.server = C.Broker(('127.0.0.1', 0), self.ledger, 'dummy-provider', 'dummy-client')
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01})
        self.thread.start()

    tearDown = BrokerTests.tearDown
    request = BrokerTests.request

    def test_same_prompt_distinct_registered_jobs_and32_concurrent_accounting(self):
        labels = sorted(self.ledger.labels)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda label: self.request(label=label), labels))
        self.assertEqual(results, [sse()] * 32)
        self.assertEqual(self.upstream.call_count, 32)
        self.assertEqual(self.ledger.summary()['requests'], 32)
        for label in labels:
            self.assertIn(label+'-step-0', self.ledger.requests)
        self.assertEqual(self.ledger.summary()['outstanding_or_unknown_requests'], 0)

    def test_per_job12_call_limit_and_duplicate_are_not_global(self):
        first, second = sorted(self.ledger.labels)[:2]
        for index in range(12): self.request(str(index), label=first)
        for text in ('0', 'thirteenth'):
            with self.assertRaises(urllib.error.HTTPError) as error: self.request(text, label=first)
            self.assertEqual(error.exception.code, 429)
        self.request('0', label=second)
        self.assertEqual(self.upstream.call_count, 13)
        self.assertIn(second+'-step-0', self.ledger.requests)

    def test_unregistered_label_cannot_reserve_or_contact_provider(self):
        for label in (C.LABEL, 'codex-terminal-c3-00', 'codex-terminal-c2-08', 'model-terminal-c2-00'):
            with self.subTest(label=label), self.assertRaises(urllib.error.HTTPError): self.request(label=label)
        self.upstream.assert_not_called()
        self.assertEqual(self.ledger.summary()['requests'], 0)

    def test_opaque_context_is_not_shared_between_jobs(self):
        first, second = sorted(self.ledger.labels)[:2]
        response = {'type': 'response.completed', 'response': {'model': C.B.MODEL,
            'usage': {'input_tokens': 100, 'output_tokens': 10, 'total_tokens': 110},
            'output': [{'type': 'reasoning', 'id': 'r1', 'encrypted_content': 'h1', 'summary': []}]}}
        self.upstream.return_value = b'data: '+C.B.canonical(response)+b'\n'
        self.request('first', label=first)
        history = [{'type': 'reasoning', 'id': 'r1', 'encrypted_content': 'h1', 'summary': []}]
        with self.assertRaises(urllib.error.HTTPError): self.request(history, label=second)
        self.assertEqual(self.upstream.call_count, 1)
        self.upstream.return_value = sse()
        self.request(history, label=first)
        self.assertEqual(self.upstream.call_count, 2)

    def test_job_cap_cannot_borrow_the_other31_job_caps(self):
        label = sorted(self.ledger.labels)[0]
        with self.assertRaises(urllib.error.HTTPError): self.request('x' * 120000, label=label)
        self.upstream.assert_not_called()
        self.assertEqual(self.ledger.summary()['requests'], 0)

    def test_ledger_itself_replays_per_job_limit(self):
        label = sorted(self.ledger.labels)[0]
        for index in range(12):
            item = self.ledger.reserve(b'{}', 1024, label, label+'-step-'+str(index))
            self.ledger.settle(item, {'prompt_tokens': 1, 'completion_tokens': 1})
        with self.assertRaisesRegex(C.B.BudgetError, 'per-job request limit'):
            self.ledger.reserve(b'{}', 1024, label, label+'-step-12')

    def test_restarted_broker_keeps_per_job_duplicate_guard(self):
        label = sorted(self.ledger.labels)[0]
        self.request(label=label)
        second = C.Broker(('127.0.0.1', 0), self.ledger, 'dummy-provider', 'dummy-client')
        try:
            body = {'model': C.B.MODEL, 'input': 'hello', 'stream': True, 'store': False, 'tools': [TOOL]}
            if self.server.reasoning_effort is not None: body['reasoning'] = {'effort': self.server.reasoning_effort}
            payload = C.normalize(C.B.canonical(body), max_output_tokens=self.server.max_output_tokens,
                reasoning_effort=self.server.reasoning_effort)
            self.assertIn((label, C.B.sha(payload)), second.demo_hashes)
            self.assertEqual(second.max_requests_per_job, 12)
        finally: second.server_close()


class TerminalV2BrokerTests(TerminalBrokerTests):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = C.B.Ledger(self.temp.name, C.registration('terminal-v2-fixture', 'terminal-v2'),
            pricing(), '4.0', provider_endpoint=C.ENDPOINT)
        self.patch = mock.patch.object(C.Broker, 'upstream', return_value=sse())
        self.upstream = self.patch.start()
        self.server = C.Broker(('127.0.0.1', 0), self.ledger, 'dummy-provider', 'dummy-client')
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}); self.thread.start()

    def request(self, text='hello', tools=None, label=None, reasoning=None):
        return BrokerTests.request(self, text, tools, label, {'effort': 'none'} if reasoning is None else reasoning)

    def test_v2_explicit4096_and_none_sent_to_provider_and_durably_reserved(self):
        label = sorted(self.ledger.labels)[0]
        self.upstream.return_value = sse(usage={'input_tokens': 100, 'output_tokens': 4096, 'total_tokens': 4196})
        self.request(label=label)
        payload = json.loads(self.upstream.call_args[0][0])
        self.assertEqual(payload['reasoning']['effort'], 'none')
        self.assertEqual(payload['max_output_tokens'], 4096)
        rows = [json.loads(line) for line in self.ledger.path.read_bytes().splitlines()]
        self.assertEqual(rows[0]['config']['max_output_tokens'], 4096)
        self.assertEqual(rows[0]['config']['reasoning_effort'], 'none')
        self.assertEqual(rows[1]['output_tokens_bound'], 4096)
        self.assertEqual(self.ledger.summary()['accounted_cost_rmb_upper_bound'], '0.032968')
        request_file = self.ledger.directory / (label + '-step-0-request.json')
        self.assertEqual(request_file.read_bytes(), self.upstream.call_args[0][0])
        self.assertEqual(C.B.sha(request_file.read_bytes()), rows[1]['request_sha256'])

    def test_v2_request_bytes_are_durable_before_upstream_can_be_called(self):
        label = sorted(self.ledger.labels)[0]
        def check(payload):
            path = self.ledger.directory / (label + '-step-0-request.json')
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(self.ledger.requests[label + '-step-0']['event'], 'RESERVED')
            return sse()
        self.upstream.side_effect = check
        self.request(label=label)

    def test_v2_failed_request_persistence_never_contacts_provider(self):
        label = sorted(self.ledger.labels)[0]
        with mock.patch.object(self.server, 'persist_request', side_effect=OSError('offline fixture')):
            with self.assertRaises(urllib.error.HTTPError): self.request(label=label)
        self.upstream.assert_not_called()
        self.assertEqual(self.ledger.summary()['outstanding_or_unknown_requests'], 1)

    def test_v2_missing_low_or_auto_reasoning_never_contact_provider(self):
        label = sorted(self.ledger.labels)[0]
        for reasoning in (None, {}, {'effort': 'low'}, {'effort': 'auto'}):
            with self.subTest(reasoning=reasoning), self.assertRaises(urllib.error.HTTPError):
                BrokerTests.request(self, label=label, reasoning=reasoning)
        self.upstream.assert_not_called()
        self.assertEqual(self.ledger.summary()['requests'], 0)

    def test_v2_jobcaps_may_sum6point4_but_global_reservation_cap_still4(self):
        self.assertEqual(sum(C.B.money(row['cap_rmb']) for row in self.ledger.labels.values()), C.B.money('6.4'))
        self.assertEqual(self.ledger.limit, C.B.money('4.0'))
        labels = sorted(self.ledger.labels)
        for label in labels[:21]:
            item = self.ledger.reserve(b'x' * 66808, 4096, label, label+'-step-0')
            self.ledger.settle(item, {'prompt_tokens': 75000, 'completion_tokens': 4096})
        with self.assertRaisesRegex(C.B.BudgetError, 'exceeds global or job budget'):
            self.ledger.reserve(b'x' * 66808, 4096, labels[21], labels[21]+'-step-0')
        self.assertLessEqual(C.B.money(self.ledger.summary()['accounted_cost_rmb_upper_bound']), C.B.money('4.0'))

    def test_v1_cannot_silently_raise_its_output_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            old = C.B.Ledger(directory, C.registration('old-terminal', 'terminal'), pricing(), '4.0', provider_endpoint=C.ENDPOINT)
            try:
                label = sorted(old.labels)[0]
                with self.assertRaisesRegex(C.B.BudgetError, 'invalid reservation token bounds'):
                    old.reserve(b'{}', 4096, label, label+'-step-0')
            finally: old.close()


if __name__ == '__main__': unittest.main()
