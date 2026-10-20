import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

SPEC = importlib.util.spec_from_file_location('model_budget', Path(__file__).with_name('model_budget.py'))
budget = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(budget)


class BudgetTests(unittest.TestCase):
    def test_concurrent_reservations_never_overcommit(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = budget.Ledger(directory, '0.1')
            accepted = []
            def reserve():
                try:
                    accepted.append(ledger.reserve(b'x' * 10000, 2048, 'task'))
                except budget.BudgetError:
                    pass
            workers = [threading.Thread(target=reserve) for _ in range(20)]
            for thread in workers:
                thread.start()
            for thread in workers:
                thread.join()
            self.assertGreater(len(accepted), 0)
            self.assertLessEqual(float(ledger.summary()['accounted_cost_rmb_upper_bound']), 0.1)
            self.assertEqual(len(ledger.path.read_text().splitlines()), len(accepted))
            ledger.stream.close()

    def test_restart_retains_an_inflight_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = budget.Ledger(directory, '0.1')
            reservation = ledger.reserve(b'{}', 100, 'swe-task')
            ledger.stream.close()
            recovered = budget.Ledger(directory, '0.1')
            self.assertEqual(recovered.summary()['accounted_cost_rmb_upper_bound'], reservation['cost_rmb_bound'])
            self.assertEqual(recovered.summary()['outstanding_or_unknown_requests'], 1)
            recovered.stream.close()

    def test_actual_usage_settles_and_frees_unused_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = budget.Ledger(directory, '0.1')
            reservation = ledger.reserve(b'{}', 2048, 'terminal-task')
            ledger.settle(reservation, {'prompt_tokens': 100, 'completion_tokens': 50})
            self.assertEqual(ledger.summary()['accounted_cost_rmb_upper_bound'], '0.0006')
            self.assertEqual(ledger.summary()['outstanding_or_unknown_requests'], 0)
            ledger.stream.close()

    def test_missing_usage_keeps_full_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = budget.Ledger(directory, '0.1')
            reservation = ledger.reserve(b'{}', 2048, 'agentbench-task')
            self.assertEqual(ledger.settle(reservation, None), 'UNKNOWN_CHARGE')
            self.assertEqual(ledger.summary()['accounted_cost_rmb_upper_bound'], reservation['cost_rmb_bound'])
            ledger.stream.close()

    def test_service_exceeding_output_bound_stops_future_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = budget.Ledger(directory, '0.1')
            reservation = ledger.reserve(b'{}', 10, 'task')
            self.assertEqual(ledger.settle(reservation, {'prompt_tokens': 1, 'completion_tokens': 11}), 'BOUND_EXCEEDED')
            with self.assertRaises(budget.BudgetError):
                ledger.reserve(b'{}', 1, 'next')
            ledger.stream.close()

    def test_fake_settlement_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = budget.Ledger(directory, '0.1')
            with self.assertRaises(budget.BudgetError):
                ledger._apply({'event': 'SETTLED', 'request_id': 'not-reserved', 'cost_rmb_bound': '0'})
            ledger.stream.close()


class BrokerHttpTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.ledger = budget.Ledger(self.directory.name, '0.1')
        self.provider = mock.patch.object(budget.Broker, 'upstream', return_value={
            'choices': [{'message': {'role': 'assistant', 'content': 'OK'}}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 1}})
        self.upstream = self.provider.start()
        self.server = budget.Broker(('127.0.0.1', 0), self.ledger, 'never-sent-provider-key', 'local-token')
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01})
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.provider.stop()
        self.ledger.stream.close()
        self.directory.cleanup()

    def call(self, changes=None, token='local-token'):
        data = {'model': budget.MODEL, 'messages': [{'role': 'user', 'content': 'Hello'}], 'max_tokens': 32}
        data.update(changes or {})
        request = urllib.request.Request('http://127.0.0.1:%d/v1/chat/completions' % self.server.server_port,
            data=json.dumps(data).encode(), headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
        with urllib.request.urlopen(request, timeout=3) as response:
            return json.load(response)

    def test_missing_credential_never_reaches_provider(self):
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.call(token='wrong')
        self.assertEqual(raised.exception.code, 401)
        self.upstream.assert_not_called()
        self.assertEqual(self.ledger.summary()['requests'], 0)

    def test_unapproved_model_and_output_bound_are_rejected_before_provider(self):
        for changes in ({'model': 'deepseek-v4-pro'}, {'max_tokens': 2049}, {'stream': True}):
            with self.subTest(changes=changes), self.assertRaises(urllib.error.HTTPError) as raised:
                self.call(changes)
            self.assertEqual(raised.exception.code, 429)
        self.upstream.assert_not_called()
        self.assertEqual(self.ledger.summary()['requests'], 0)

    def test_successful_response_is_settled_and_thinking_is_disabled(self):
        self.assertEqual(self.call({'thinking': {'type': 'enabled'}})['choices'][0]['message']['content'], 'OK')
        forwarded = json.loads(self.upstream.call_args[0][0])
        self.assertEqual(forwarded['thinking'], {'type': 'disabled'})
        self.assertEqual(self.ledger.summary()['outstanding_or_unknown_requests'], 0)


if __name__ == '__main__':
    unittest.main()
