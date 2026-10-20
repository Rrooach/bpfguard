"""Offline real-model adapter boundary tests; never invoke provider/Docker/BPF."""
import asyncio
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from model_swe import command_argument, solve_model


class ModelSWETests(unittest.TestCase):
    def test_command_protocol(self):
        def call(name, args):
            return {'id': 'provider-1', 'function': {'name': name, 'arguments': json.dumps(args)}}
        self.assertEqual(command_argument(call('bash', {'command': 'pwd'})), 'pwd')
        self.assertIsNone(command_argument(call('finish', {})))
        for value in (call('bash', {'command': ''}), call('bash', {'command': 'a\0b'}),
                      call('bash', {'command': 'pwd', 'extra': 1}), call('unknown', {}), call('finish', {'command': 'pwd'})):
            with self.assertRaises(ValueError): command_argument(value)

    def test_no_reference_or_test_patch_and_empty_model_submission_not_replaced(self):
        seen = []
        class FakeClient:
            def __init__(self, *args, **kwargs):
                self.usage = {'prompt_tokens': 1, 'completion_tokens': 1}
                self.events = []
            async def request(self, messages, tools, step):
                seen.append(json.dumps(messages))
                return {'choices': [{'message': {'role': 'assistant', 'tool_calls': [
                    {'id': 'finish-id', 'function': {'name': 'finish', 'arguments': '{}'}}]}}]}
        class FakeProxy:
            infrastructure_error = None
            def exec_run(self, command, **kwargs):
                assert command == ['bash', '-lc', 'git add -N -- . && git diff --binary HEAD']
                return SimpleNamespace(exit_code=0, output=b'')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = SimpleNamespace(directory=root, manifest={'boot_id': 'test', 'tools': []})
            args = SimpleNamespace(broker_base_url='http://127.0.0.1:10091/v1', broker_token_file=root/'token',
                budget_label='model-swe-c2-00', max_output=1024, max_rounds=4, output=root, tool_timeout=45)
            row = {'instance_id': 'task', 'problem_statement': 'PUBLIC ISSUE', 'patch': 'SECRET_GOLD', 'test_patch': 'SECRET_TEST'}
            with patch('model_swe.ModelClient', FakeClient):
                submission, result = solve_model(row, session, FakeProxy(), args)
            self.assertEqual(submission, '')
            self.assertEqual((root/'agent.patch').read_bytes(), b'')
            self.assertEqual(result['termination'], 'MODEL_FINISHED')
            self.assertNotIn('SECRET_GOLD', seen[0]); self.assertNotIn('SECRET_TEST', seen[0])
            self.assertFalse(result['gold_patch_exposed']); self.assertFalse(result['test_patch_exposed'])

    def test_budget_exhaustion_is_retained_model_termination(self):
        from model_client import ModelRequestError
        class Refused:
            def __init__(self, *args, **kwargs): self.usage, self.events = {}, []
            async def request(self, *args): raise ModelRequestError('BUDGET_OR_REQUEST_LIMIT', 'request', 429)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = SimpleNamespace(directory=root, manifest={'boot_id': 'test', 'tools': []})
            args = SimpleNamespace(broker_base_url='local', broker_token_file=root/'token', budget_label='model-swe-c2-00',
                max_output=1024, max_rounds=4, output=root, tool_timeout=45)
            proxy = SimpleNamespace(infrastructure_error=None, exec_run=lambda *a, **k: SimpleNamespace(exit_code=0, output=b''))
            with patch('model_swe.ModelClient', Refused):
                submission, result = solve_model({'instance_id': 'task', 'problem_statement': 'public'}, session, proxy, args)
            self.assertEqual(submission, '')
            self.assertIn('BUDGET_OR_REQUEST_LIMIT', result['termination'])


if __name__ == '__main__': unittest.main()
