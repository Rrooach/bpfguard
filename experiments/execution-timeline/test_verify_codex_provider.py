"""Offline binding fixtures, not real provider/Observer success claims."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from common import write_new
import verify_codex_provider as V


class ProviderBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.run = self.root/'run'; (self.run/'app').mkdir(parents=True)
        self.compose = mock.patch.object(V, 'compose'); self.compose.start(); self.addCleanup(self.compose.stop)
        B = V.budget
        registration = {'schema_version': 1, 'campaign_id': 'FAKE_OFFLINE_FIXTURE_ONLY',
            'registration_kind': 'CODEX_OBSERVER_DEMO', 'global_limit_rmb': '.4', 'labels': [{
                'kind': 'CODEX_DEMO', 'label': 'codex-smoke-001', 'group_id': 'codex-demo', 'job_id': 'demo-001', 'cap_rmb': '.4'}]}
        pricing = {'model': B.MODEL, 'currency': 'CNY', 'input_rmb_per_million': '2', 'output_rmb_per_million': '8'}
        self.ledger = B.Ledger(self.root/'ledger', registration, pricing, '.4', provider_endpoint='https://api.deepseek.com/responses')
        self.addCleanup(self.ledger.close)
        self.key = 'codex-smoke-001-step-0'
        item = self.ledger.reserve(b'fixture only', 1024, 'codex-smoke-001', self.key)
        self.ledger.settle(item, {'prompt_tokens': 100, 'completion_tokens': 10})
        self.response = {'type': 'response.completed', 'response': {'model': B.MODEL, 'id': 'FAKE_OFFLINE',
            'usage': {'input_tokens': 100, 'output_tokens': 10}, 'output': [
                {'type': 'function_call', 'name': 'observer_bash', 'call_id': 'call1', 'arguments': '{"command":"printf ok"}'},
                {'type': 'message', 'content': [{'type': 'output_text', 'text': 'done'}]}]}}
        self.source = self.root/'ledger'/(self.key+'-upstream.sse')
        self.receipt = self.root/'ledger'/(self.key+'-response.json')
        self.item = item; self.save_response()
        write_new(self.run/'manifest.json', {'run_id': 'fixture', 'codex_identity': {'sha256': '0'*64}})
        self.app = {'status': 'completed', 'agent_loop': 'OFFICIAL_CODEX_NOT_IMPLEMENTED_BY_THIS_CLIENT',
            'function_bindings': [{'call_id': 'call1', 'command': 'printf ok'}],
            'steps': [{'kind': 'AGENT_MESSAGE', 'text': 'done'}]}
        write_new(self.run/'app/steps.json', self.app)

    def save_response(self):
        raw = b'data: '+V.budget.canonical(self.response)+b'\n'
        self.source.write_bytes(raw)
        self.receipt.write_bytes(V.budget.canonical({'response_sha256': V.budget.sha(raw), 'response_bytes': len(raw),
            'request_sha256': self.item['request_sha256'], 'upstream_endpoint': 'https://api.deepseek.com/responses'}))

    def verify(self): return V.verify(self.run, self.ledger.path)

    def test_exact_function_command_answer_usage_and_cost_bound(self):
        result = self.verify()
        self.assertEqual(result['explicit_provider_call_ids'], ['call1'])
        self.assertEqual(result['this_completed_run_cost_upper_bound_rmb'], '0.00028')
        self.assertFalse(result['benchmark_run'])

    def test_config_alone_cannot_prove_inference(self):
        self.response['response']['output'][0]['call_id'] = 'somebody-else'
        self.save_response()
        with self.assertRaisesRegex(ValueError, 'missing exact provider'): self.verify()

    def test_altered_command_rejected(self):
        self.response['response']['output'][0]['arguments'] = '{"command":"different"}'
        self.save_response()
        with self.assertRaisesRegex(ValueError, 'command differs'): self.verify()

    def test_altered_usage_rejected_even_with_new_source_digest(self):
        self.response['response']['usage']['output_tokens'] = 1
        self.save_response()
        with self.assertRaisesRegex(ValueError, 'usage differs'): self.verify()

    def test_corrupt_source_rejected(self):
        self.source.write_bytes(self.source.read_bytes()+b'changed')
        with self.assertRaisesRegex(ValueError, 'source binding'): self.verify()

    def test_failed_agent_turn_cannot_become_completed(self):
        self.app['status'] = 'failed'
        (self.run/'app/steps.json').write_bytes(V.budget.canonical(self.app))
        with self.assertRaisesRegex(ValueError, 'did not complete'): self.verify()

    def test_ledger_wrong_cost_rejected_by_independent_budget_replay(self):
        rows = [json.loads(row) for row in self.ledger.path.read_bytes().splitlines()]
        rows[-1]['cost_rmb_bound'] = '0'
        self.ledger.path.write_bytes(b''.join(V.budget.canonical(row)+b'\n' for row in rows))
        with self.assertRaisesRegex(ValueError, 'settlement cost'): self.verify()


if __name__ == '__main__': unittest.main()
