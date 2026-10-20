"""Regression: malformed model tool JSON must not execute a partial command."""
import asyncio
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class ModelResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def read(self, *args):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class MalformedToolTests(unittest.TestCase):
    def test_truncated_json_is_rejected_then_finish_is_accepted(self):
        fake_harbor = {"harbor": SimpleNamespace(), "harbor.agents": SimpleNamespace(),
                       "harbor.agents.base": SimpleNamespace(BaseAgent=object)}
        path = Path(__file__).with_name("budget_agent.py")
        spec = importlib.util.spec_from_file_location("tested_budget_agent", path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, fake_harbor):
            spec.loader.exec_module(module)
        replies = [
            {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [{"id": "bad",
                "function": {"name": "bash", "arguments": '{"command":"touch /tmp/partial'}}]}, "finish_reason": "length"}],
             "usage": {"prompt_tokens": 10, "completion_tokens": 20}},
            {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [{"id": "done",
                "function": {"name": "finish", "arguments": "{}"}}]}, "finish_reason": "tool_calls"}],
             "usage": {"prompt_tokens": 11, "completion_tokens": 2}}]
        requests = []

        def urlopen(request, **kwargs):
            requests.append(json.loads(request.data))
            return ModelResponse(replies.pop(0))

        async def execute(**kwargs):
            self.fail("Malformed tool output executed a command")

        async def offload(function):
            return function()

        with tempfile.TemporaryDirectory() as directory:
            agent = module.BudgetShellAgent()
            agent.logs_dir = Path(directory)
            agent.session_id, agent.context_id = "test-task", None
            context = SimpleNamespace()
            with patch.object(module.urllib.request, "urlopen", urlopen), \
                    patch.object(module.Path, "read_text", return_value="test-client-token"), \
                    patch.object(module.asyncio, "to_thread", offload, create=True):
                asyncio.run(agent.run("Task", SimpleNamespace(exec=execute), context))
            self.assertEqual(len(requests), 2)
            feedback = requests[1]["messages"][-1]
            self.assertEqual(feedback["tool_call_id"], "bad")
            self.assertIn("no command executed", feedback["content"])
            intervals = json.loads((Path(directory) / "tool-intervals.json").read_text())
            self.assertEqual(sum(row["kind"] == "tool_rejected" for row in intervals), 1)
            self.assertEqual(context.n_input_tokens, 21)
            self.assertEqual(context.n_output_tokens, 22)


if __name__ == "__main__":
    unittest.main()
