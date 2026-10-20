"""Real-model adapter contracts using fake responses only: no API/VM/Docker."""
import asyncio
import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import model_client as C
import model_terminal as M
import test_parallel_terminal as P


def agent_module():
    name = "tested_timeline_model_harbor_agent"
    spec = importlib.util.spec_from_file_location(name, HERE / "model_harbor_agent.py")
    module = importlib.util.module_from_spec(spec)
    fake = {"harbor": SimpleNamespace(), "harbor.agents": SimpleNamespace(),
            "harbor.agents.base": SimpleNamespace(BaseAgent=object), name: module}
    with patch.dict(sys.modules, fake):
        spec.loader.exec_module(module)
    return module


A = agent_module()


def response(calls=None, usage=None):
    return {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": calls or []}}],
            "usage": usage or {"prompt_tokens": 10, "completion_tokens": 20}, "model": "deepseek-flash"}


def call(name="finish", arguments="{}", identity="call-1"):
    return {"id": identity, "type": "function", "function": {"name": name, "arguments": arguments}}


class ClientTests(unittest.TestCase):
    def client(self, root, transport):
        token = Path(root) / "private-token"
        token.write_text("local-client-secret\n"); token.chmod(0o600)
        return C.ModelClient("http://10.0.2.2:10091/v1", token, "model-terminal-c2-00",
                             Path(root) / "application", transport=transport, boot_id="boot")

    def test_headers_fixed_bounds_and_durable_spans(self):
        seen = []
        with tempfile.TemporaryDirectory() as root:
            client = self.client(root, lambda request: seen.append(request) or response())
            self.assertEqual(asyncio.run(client.request([{"role": "user", "content": "Task"}], [], 0))["model"], "deepseek-flash")
            request = seen[0]
            headers = {key.lower(): value for key, value in request.header_items()}
            self.assertEqual(headers["x-request-id"], "model-terminal-c2-00-step-0")
            self.assertEqual(headers["x-benchmark-task"], "model-terminal-c2-00")
            body = json.loads(request.data)
            self.assertEqual((body["max_tokens"], body["n"], body["temperature"], body["stream"]), (1024, 1, 0, False))
            self.assertEqual(body["thinking"], {"type": "disabled"})
            spans = [json.loads(row) for row in (client.directory / "model-requests.jsonl").read_text().splitlines()]
            self.assertEqual([row["event"] for row in spans], ["MODEL_REQUEST_START", "MODEL_REQUEST_END"])
            self.assertLessEqual(spans[0]["begin_ns"], spans[1]["end_ns"])
            self.assertEqual(client.usage, {"prompt_tokens": 10, "completion_tokens": 20})
            self.assertNotIn("local-client-secret", "".join(path.read_text() for path in client.directory.iterdir()))
            self.assertEqual(len(client.artifacts()), 2)

    def test_no_retry_on_budget_timeout_http_network_or_malformed_response(self):
        failures = [
            (urllib.error.HTTPError("local", 429, "denied", {}, None), "BUDGET_OR_REQUEST_LIMIT"),
            (urllib.error.HTTPError("local", 409, "duplicate", {}, None), "BROKER_HTTP_ERROR"),
            (TimeoutError(), "TIMEOUT_UNKNOWN_CHARGE"),
            (ConnectionResetError(), "NETWORK_ERROR_UNKNOWN_CHARGE"),
            ({"choices": []}, "MALFORMED_RESPONSE"),
            (response(usage={"prompt_tokens": -1, "completion_tokens": 0}), "MALFORMED_RESPONSE"),
        ]
        for failure, expected in failures:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as root:
                calls = []
                def transport(request):
                    calls.append(request)
                    if isinstance(failure, BaseException):
                        raise failure
                    return failure
                client = self.client(root, transport)
                with self.assertRaises(C.ModelRequestError) as raised:
                    asyncio.run(client.request([], [], 0))
                self.assertEqual(raised.exception.kind, expected)
                self.assertEqual(len(calls), 1)
                self.assertEqual(client.events[0]["status"], expected)
                with self.assertRaises(ValueError):
                    asyncio.run(client.request([], [], 0))

    def test_private_token_and_local_endpoint_required(self):
        with tempfile.TemporaryDirectory() as root:
            token = Path(root) / "token"; token.write_text("secret"); token.chmod(0o644)
            with self.assertRaises(ValueError):
                C.private_token(token)
            token.chmod(0o600)
            link = Path(root) / "link"; link.symlink_to(token)
            with self.assertRaises(OSError):
                C.private_token(link)
            for url in ("https://api.deepseek.com/v1", "http://user:pass@localhost:10091/v1", "http://localhost:10091/v1?token=x"):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    C.ModelClient(url, token, "model-terminal-c2-00", Path(root) / "evidence")

    def test_four_rounds_and_one_attempt_per_step(self):
        with tempfile.TemporaryDirectory() as root:
            client = self.client(root, lambda request: response())
            for step in range(4):
                asyncio.run(client.request([], [], step))
            with self.assertRaises(ValueError):
                asyncio.run(client.request([], [], 4))
            self.assertEqual(len(client.events), 4)

    def test_context_bound_rejects_before_network_and_redirects_are_disabled(self):
        with tempfile.TemporaryDirectory() as root:
            seen = []
            client = self.client(root, lambda request: seen.append(request) or response())
            with self.assertRaises(C.ModelRequestError) as raised:
                asyncio.run(client.request([{"role": "user", "content": "x" * C.MAX_REQUEST}], [], 0))
            self.assertEqual(raised.exception.kind, "REQUEST_BOUNDS")
            self.assertEqual(seen, [])
            self.assertEqual(client.events, [])
            self.assertIsNone(C.NoRedirect().redirect_request(None, None, 302, "moved", {}, "https://external.invalid"))


class FakeGate:
    def __init__(self, agent_id, wrong=False):
        self.manifest = {"tools": []}
        self.agent_id, self.wrong = agent_id, wrong

    async def __call__(self, command, timeout_sec):
        self.manifest["tools"].append({"agent_id": "wrong" if self.wrong else self.agent_id,
            "command": command, "tool_call_id": "job-exec-0001", "root": {"tid": 12, "start_ticks": 4, "clock_ticks": 100},
            "cgroup_id": 10, "begin_ns": 100, "end_ns": 200, "result": {"return_code": 0}})
        return SimpleNamespace(stdout="ok", stderr="", return_code=0)


class AgentTests(unittest.TestCase):
    def settings(self, root, replies):
        values = list(replies)
        class FakeClient:
            def __init__(self, *args, **kwargs):
                self.directory = Path(args[3]); self.directory.mkdir(parents=True)
                self.events, self.steps = [], set()
                self.usage = {"prompt_tokens": 0, "completion_tokens": 0}
            async def request(self, messages, tools, step):
                self.events.append({"step": step}); self.steps.add(step)
                value = values.pop(0)
                if isinstance(value, BaseException):
                    raise value
                return value
        settings = A.ModelSettings("http://10.0.2.2:10091/v1", Path(root) / "not-read", "model-terminal-c2-00",
            Path(root) / "model-evidence", "agent", "task", "boot", client_factory=FakeClient)
        settings.gate = FakeGate(settings.agent_id)
        return settings

    def execute(self, settings):
        context = SimpleNamespace()
        with A.configured(settings):
            asyncio.run(A.BoundedModelAgent().run("Public task only", SimpleNamespace(exec=settings.gate), context))
        return context

    def test_real_function_id_binds_exact_new_gate_root(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root, [response([call("bash", '{"command":"printf ok"}')]), response([call(identity="finish")])])
            self.execute(settings)
            binding = settings.function_bindings[0]
            self.assertEqual(binding["provider_function_call_id"], "call-1")
            self.assertEqual(binding["observer_tool_call_id"], "job-exec-0001")
            self.assertEqual(binding["root"], settings.gate.manifest["tools"][0]["root"])
            self.assertEqual(settings.termination, "MODEL_FINISH")

    def test_budget_error_is_terminal_model_result_not_infrastructure_exception(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root, [C.ModelRequestError("BUDGET_OR_REQUEST_LIMIT", "request")])
            context = self.execute(settings)
            self.assertEqual(settings.termination, "MODEL_BUDGET_OR_REQUEST_LIMIT")
            self.assertEqual(len(settings.gate.manifest["tools"]), 0)
            self.assertEqual(context.metadata["termination"], settings.termination)

    def test_zero_tool_finish_and_round_limit_do_not_invent_shell_commands(self):
        for replies, expected in (([response([call()])], "MODEL_FINISH"), ([response()] * 4, "ROUND_LIMIT")):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as root:
                settings = self.settings(root, replies)
                self.execute(settings)
                self.assertEqual(settings.termination, expected)
                self.assertEqual(settings.function_bindings, [])

    def test_malformed_arguments_never_execute_partial_command(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root, [response([call("bash", '{"command":"touch /tmp/partial')]), response([call(identity="done")])])
            self.execute(settings)
            self.assertEqual(settings.gate.manifest["tools"], [])
            self.assertIn("MODEL_FUNCTION_REJECTED", (settings.evidence_directory / "model-function-bindings.jsonl").read_text())

    def test_wrong_gate_identity_remains_infrastructure_error(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root, [response([call("bash", '{"command":"true"}')])])
            settings.gate.wrong = True
            with self.assertRaises(A.ObserverBindingError):
                self.execute(settings)


class WorkerTests(unittest.TestCase):
    def test_model_reward_zero_completes_real_phase_hooks_and_binds_application_artifacts(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "job"
            target = SimpleNamespace(container_id="container", cgroup_id=100,
                                     cgroup_directory=Path(root) / "cgroup")
            events = []
            finder = P.FakeFinder(target, events)
            control = P.FakeControl(finder, events)

            async def campaign(args, *, agent_config, agent_identity, paid_call_info):
                self.assertEqual(agent_config.import_path, "model_harbor_agent:BoundedModelAgent")
                self.assertEqual(agent_identity["mode"], "MODEL_AGENT")
                output.mkdir(); directory = output / "timelines/task"; directory.mkdir(parents=True)
                trial = P.FakeTrial()
                settings = A.ACTIVE.get()

                async def start(event):
                    trial.agent_environment.exec = P.FakeAdapter(directory, target)
                    trial.agent_environment.exec.manifest["boot_id"] = settings.boot_id

                async def finish(event):
                    self.assertIn("all-agents-done", events)
                    self.assertFalse(finder.paused)
                    manifest = trial.agent_environment.exec.manifest
                    self.assertEqual(manifest["model_application"]["mode"], "MODEL_AGENT")
                    self.assertIn("model-evidence/model-agent.json", manifest["artifacts"])
                    self.assertEqual(manifest["agent_scope"], M.MODEL_SCOPE)

                trial.add_hook("start", start); trial.add_hook("end", finish)
                await trial.hooks["start"]("start")
                self.assertIs(settings.gate, trial.agent_environment.exec)
                settings.client = SimpleNamespace(events=[], usage={"prompt_tokens": 0, "completion_tokens": 0})
                settings.termination = "MODEL_FINISH"
                await trial.hooks["end"]("end")
                P.T.write_json(output / "campaign-summary.json", {"mode": "MODEL_AGENT", "tasks": [{
                    "task": "task", "timeline_directory": str(directory), "task_reward_passed": False,
                    "harbor_rewards": {"reward": 0}, "harbor_exception": None,
                    "harbor_result": "official.json", "timeline_acceptance": "PENDING_INDEPENDENT_REPLAY"}]})
                self.assertIsNone(paid_call_info()["paid_api_calls"])
                return 1  # The unchanged capture campaign returns 1 for score 0.

            terminal = SimpleNamespace(__name__=__name__, GatedExec=P.FakeAdapter, campaign=campaign,
                write_json=P.T.write_json, sha256=P.T.sha256,
                frozen_baseline_threads=lambda path: [{"tid": 10, "start_ticks": 100, "clock_ticks": 100}])
            args = SimpleNamespace(job_id="terminal-00", task=["task"], phase_timeout=7200.0,
                output=output, control_dir=Path(root) / "control", capture_only=True,
                budget_label="model-terminal-c2-00", max_rounds=4, max_output=1024,
                broker_base_url="http://10.0.2.2:10091/v1", broker_token_file=Path(root) / "not-read")
            original = P.FakeTrial.add_hook
            with patch.dict(sys.modules, {"model_harbor_agent": A}):
                code = asyncio.run(M.run_worker(args, control=control, terminal=terminal,
                    trial_class=P.FakeTrial, trial_events=SimpleNamespace(AGENT_START="start", AGENT_END="end"),
                    finder_factory=lambda trial: finder, agent_config_factory=SimpleNamespace))
            self.assertEqual(code, 0)
            self.assertEqual(control.failures, [])
            self.assertEqual(control.ready_metadata["agent_scope"], M.MODEL_SCOPE)
            self.assertTrue(control.done_metadata["quiescent"])
            self.assertIs(P.FakeTrial.add_hook, original)
            worker = json.loads((output / "worker-result.json").read_text())
            self.assertFalse(worker["official_passed"])
            self.assertTrue(worker["official_evaluated"])
            self.assertIsNone(worker["model_accounting"]["paid_api_calls"])

    def test_explicit_model_hooks_keep_reference_defaults(self):
        with tempfile.TemporaryDirectory() as root:
            settings = SimpleNamespace(agent_id="model-agent:model-terminal-c2-00", budget_label="model-terminal-c2-00")
            reference = P.M.WorkerHooks(job_id="job", task="task", control=None, terminal=None, finder_factory=None, baseline_reader=lambda path: [])
            model = M.ModelWorkerHooks(settings=settings, job_id="job", task="task", control=None, terminal=None, finder_factory=None, baseline_reader=lambda path: [])
            self.assertEqual(reference.agent_scope, P.M.ORACLE_SCOPE)
            self.assertEqual(reference.agent_id, "official-oracle:job")
            self.assertEqual(model.agent_scope, M.MODEL_SCOPE)
            self.assertEqual(model.agent_id, settings.agent_id)

    def test_model_options_require_long_gates_and_capture_only(self):
        with tempfile.TemporaryDirectory() as root:
            args = SimpleNamespace(job_id="terminal-00", task=["task"], phase_timeout=7200,
                output=Path(root) / "fresh", budget_label="model-terminal-c2-00", max_rounds=4, max_output=1024, capture_only=True)
            M.validate_model_options(args)
            args.phase_timeout = 1800
            with self.assertRaises(ValueError):
                M.validate_model_options(args)

    def test_model_score_zero_is_retained_not_reported_as_infrastructure_failure(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root); directory = output / "timelines/task"; directory.mkdir(parents=True)
            P.T.write_json(output / "campaign-summary.json", {"tasks": [{"task": "task", "timeline_directory": str(directory),
                "task_reward_passed": False, "harbor_rewards": {"reward": 0}, "harbor_exception": None}]})
            settings = SimpleNamespace(client=None, termination="ROUND_LIMIT", budget_label="model-terminal-c2-00")
            hooks = SimpleNamespace(agent_id="agent", agent_return_ns=100, quiescent_ns=101, settings=settings)
            args = SimpleNamespace(output=output, task=["task"], job_id="terminal-00", budget_label=settings.budget_label)
            worker, row = M.write_worker_result(args, hooks, P.T)
            self.assertFalse(worker["official_passed"])
            self.assertTrue(worker["official_evaluated"])
            self.assertEqual(worker["mode"], "MODEL_AGENT")
            self.assertIsNone(worker["error"])


if __name__ == "__main__":
    unittest.main()
