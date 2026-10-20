"""Codex/Harbor boundary tests, synthetic transport only; no model or Docker."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import codex_terminal as W
import test_parallel_terminal as P

HERE = Path(__file__).parent


def load_agent():
    name = "tested_timeline_codex_harbor_agent"
    spec = importlib.util.spec_from_file_location(name, HERE / "codex_harbor_agent.py")
    module = importlib.util.module_from_spec(spec)
    fake = {"harbor": SimpleNamespace(), "harbor.agents": SimpleNamespace(),
            "harbor.agents.base": SimpleNamespace(BaseAgent=object), name: module}
    with patch.dict(sys.modules, fake):
        spec.loader.exec_module(module)
    return module


A = load_agent()


class FakeGate:
    def __init__(self, agent_id="codex-agent", wrong=False, failure=None):
        self.agent_id, self.wrong, self.failure = agent_id, wrong, failure
        self.manifest = {"tools": []}
        self.persisted = 0

    def persist(self):
        self.persisted += 1

    async def __call__(self, command, timeout_sec):
        self.manifest["tools"].append({"agent_id": "wrong" if self.wrong else self.agent_id,
            "command": command, "tool_call_id": "codex-terminal-c2-00-exec-0001",
            "root": {"tid": 12, "start_ticks": 4, "clock_ticks": 100},
            "cgroup_id": 10, "begin_ns": 100, "end_ns": 200, "docker_exec_id": "f" * 64,
            "result": {"return_code": 0} if self.failure is None else {"error": "synthetic timeout"}})
        if self.failure is not None:
            raise self.failure
        return SimpleNamespace(stdout="ok", stderr="", return_code=0)


class ConfigTests(unittest.TestCase):
    def settings(self, root):
        root = Path(root)
        codex, catalog = root / "codex", root / "models.json"
        codex.write_bytes(b"SYNTHETIC_NOT_EXECUTABLE"); catalog.write_text("{}")
        return A.CodexSettings("http://127.0.0.1:10091/v1", root / "private-token", "codex-terminal-c2-00",
            root / "app", "codex-agent", "terminal-bench/task", "boot", codex, catalog)

    def test_only_distinct_explicit_concurrency_labels_and_loopback_endpoint(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root)
            command, config = A.app_server_command(settings, settings.catalog)
            self.assertEqual(command[1], "app-server")
            self.assertIn('"X-Benchmark-Task"="codex-terminal-c2-00"', command[-1])
            self.assertEqual(config["model_providers.observer_proxy.wire_api"], "responses")
            self.assertEqual(config["model_providers.observer_proxy.request_max_retries"], 0)
            self.assertEqual(config["features.code_mode"], False)
            self.assertEqual(config["model_reasoning_effort"], "none")
            for label in ("model-terminal-c2-00", "codex-smoke-001", "codex-terminal-c3-00", "codex-terminal-c2-08"):
                settings.budget_label = label
                with self.subTest(label=label), self.assertRaises(ValueError):
                    A.app_server_command(settings, settings.catalog)
            settings.budget_label = "codex-terminal-c8-07"
            A.app_server_command(settings, settings.catalog)
            settings.base_url = "https://api.deepseek.com/responses"
            with self.assertRaises(ValueError):
                A.app_server_command(settings, settings.catalog)

    def test_runtime_does_not_claim_model_loop_or_kernel_capture(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root)
            value = settings.persist()
            self.assertEqual(value["agent_implementation"], W.IMPLEMENTATION)
            self.assertIsNone(value["paid_api_calls"])
            self.assertIn("CODEX_RUNTIME_NOT_CAPTURED", value["runtime_kernel_scope"])
            self.assertEqual(value["max_requests_enforced_by_external_broker"], 12)

    def test_one_request_binds_one_stopped_exec_with_full_output_artifacts(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root); settings.persist(); settings.gate = FakeGate()
            result = asyncio.run(A.bound_tool(settings, SimpleNamespace(exec=settings.gate), "printf ok", "call-1", "rpc-1"))
            binding = settings.function_bindings[0]
            self.assertEqual(binding["root"], settings.gate.manifest["tools"][0]["root"])
            self.assertEqual(binding["call_id"], "call-1")
            self.assertEqual(binding["rpc_request_id"], "rpc-1")
            self.assertEqual(result["exit_code"], 0)
            self.assertIsNone(binding["cgroup_empty"])
            self.assertEqual((settings.evidence_directory / "tool-0001.stdout").read_text(), "ok")
            self.assertNotIn("codex_call_id", settings.gate.manifest["tools"][0])
            self.assertEqual(settings.gate.persisted, 0)

    def test_wrong_agent_is_not_converted_to_task_failure(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root); settings.persist(); settings.gate = FakeGate(wrong=True)
            with self.assertRaises(A.ObserverBindingError):
                asyncio.run(A.bound_tool(settings, SimpleNamespace(exec=settings.gate), "true", "call-1", "rpc-1"))
            self.assertEqual(settings.function_bindings, [])

    def test_bounded_tool_timeout_is_recorded_as_tool_failure_without_fake_exit(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root); settings.persist(); settings.gate = FakeGate(failure=TimeoutError("synthetic"))
            result = asyncio.run(A.bound_tool(settings, SimpleNamespace(exec=settings.gate), "sleep 99", "call-1", "rpc-1"))
            self.assertEqual(result["exit_code"], 124)
            self.assertIn("error", result["binding"]["gate_result"])
            self.assertNotIn("return_code", result["binding"]["gate_result"])

    def test_unclassified_transport_failure_stays_infrastructure_error(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root); settings.persist(); settings.gate = FakeGate(failure=ConnectionError("synthetic"))
            with self.assertRaises(A.ObserverBindingError):
                asyncio.run(A.bound_tool(settings, SimpleNamespace(exec=settings.gate), "true", "call-1", "rpc-1"))

    def test_sync_official_transport_dispatches_async_gate_on_owner_loop(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root); settings.persist(); settings.gate = FakeGate()
            def fake_runner(settings, instruction, executor):
                self.assertEqual(instruction, "public task")
                output = executor("printf ok", "call-1", "rpc-1")
                self.assertEqual(output["stdout"], "ok")
                settings.termination = "CODEX_COMPLETED"
                settings.outcome = {"status": "completed"}
                return settings.outcome
            settings.runner = fake_runner
            context = SimpleNamespace()
            with A.configured(settings):
                asyncio.run(A.CodexObserverAgent().run("public task", SimpleNamespace(exec=settings.gate), context))
            self.assertEqual(context.metadata["agent_implementation"], W.IMPLEMENTATION)
            self.assertEqual(len(settings.function_bindings), 1)


class WorkerTests(ConfigTests):
    def test_score_zero_and_failed_codex_turn_are_still_officially_evaluated(self):
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root)
            output = Path(root) / "job"
            target = SimpleNamespace(container_id="container", cgroup_id=100, cgroup_directory=Path(root) / "cgroup")
            events = []; finder = P.FakeFinder(target, events); control = P.FakeControl(finder, events)
            async def campaign(args, *, agent_config, agent_identity, paid_call_info):
                self.assertEqual(agent_config.import_path, "codex_harbor_agent:CodexObserverAgent")
                self.assertEqual(agent_identity["agent_implementation"], W.IMPLEMENTATION)
                output.mkdir(); directory = output / "timelines/task"; directory.mkdir(parents=True)
                trial = P.FakeTrial(); actual = A.ACTIVE.get()
                async def start(event):
                    trial.agent_environment.exec = P.FakeAdapter(directory, target)
                    trial.agent_environment.exec.manifest["boot_id"] = actual.boot_id
                async def finish(event):
                    manifest = trial.agent_environment.exec.manifest
                    self.assertIn("all-agents-done", events)
                    self.assertEqual(manifest["codex_application"]["agent_implementation"], W.IMPLEMENTATION)
                    self.assertIn("app/codex-agent.json", manifest["artifacts"])
                trial.add_hook("start", start); trial.add_hook("end", finish)
                await trial.hooks["start"]("start")
                actual.termination = "CODEX_FAILED"; actual.outcome = {"status": "failed"}
                await trial.hooks["end"]("end")
                P.T.write_json(output / "campaign-summary.json", {"mode": "MODEL_AGENT", "tasks": [{
                    "task": "task", "timeline_directory": str(directory), "task_reward_passed": False,
                    "harbor_rewards": {"reward": 0}, "harbor_exception": None, "harbor_result": "official.json",
                    "timeline_acceptance": "PENDING_INDEPENDENT_REPLAY"}]})
                return 1
            terminal = SimpleNamespace(__name__=__name__, GatedExec=P.FakeAdapter, campaign=campaign,
                write_json=P.T.write_json, sha256=P.T.sha256,
                frozen_baseline_threads=lambda path: [{"tid": 10, "start_ticks": 100, "clock_ticks": 100}])
            args = SimpleNamespace(job_id="terminal-00", task=["task"], phase_timeout=7200.0,
                output=output, control_dir=Path(root) / "control", capture_only=True,
                budget_label="codex-terminal-c2-00", max_calls=8, max_requests=12, max_output=4096,
                broker_base_url="http://127.0.0.1:10091/v1", broker_token_file=Path(root) / "not-read",
                codex=settings.codex, catalog=settings.catalog)
            with patch.dict(sys.modules, {"codex_harbor_agent": A}):
                code = asyncio.run(W.run_worker(args, control=control, terminal=terminal,
                    trial_class=P.FakeTrial, trial_events=SimpleNamespace(AGENT_START="start", AGENT_END="end"),
                    finder_factory=lambda trial: finder, agent_config_factory=SimpleNamespace))
            self.assertEqual(code, 0); self.assertEqual(control.failures, [])
            worker = json.loads((output / "worker-result.json").read_text())
            self.assertFalse(worker["official_passed"]); self.assertTrue(worker["official_evaluated"])
            self.assertEqual(worker["model_termination"], "CODEX_FAILED")


@unittest.skipUnless(os.environ.get("CODEX_TEST_BINARY") and os.environ.get("CODEX_TEST_CATALOG"),
                     "opt-in official Codex + local fake provider; no paid API/Docker/BPF")
class OfficialCodexFakeProviderTests(ConfigTests):
    def test_new_harbor_adapter_uses_real_official_loop_and_async_gate(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from test_codex_fake import fake_events
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.assert_request()
                index = len(self.server.requests)
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                self.server.requests.append(body)
                if body.get("reasoning", {}).get("effort") != "none":
                    self.send_error(400, "FAKE_ONLY_REASONING_MUST_BE_NONE"); return
                matches = [tool["name"] for tool in body.get("tools", [])
                    if tool.get("type") == "function" and "observer_bash" in tool.get("name", "")]
                if len(matches) != 1 or index > 1:
                    self.send_error(400, "FAKE_ONLY_INVALID_PROTOCOL"); return
                raw = fake_events(index, matches[0])
                self.send_response(200); self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(raw))); self.end_headers()
                self.wfile.write(raw); self.wfile.flush()
            def assert_request(self):
                assert self.path == "/v1/responses"
                assert self.headers.get("X-Benchmark-Task") == "codex-terminal-c2-00"
                assert self.headers.get("Authorization") == "Bearer FAKE_PROVIDER_NO_API"
            def log_message(self, *args):
                pass
        with tempfile.TemporaryDirectory() as root:
            settings = self.settings(root)
            settings.codex = Path(os.environ["CODEX_TEST_BINARY"]).resolve(strict=True)
            settings.catalog = Path(os.environ["CODEX_TEST_CATALOG"]).resolve(strict=True)
            settings.token_file.write_text("FAKE_PROVIDER_NO_API"); settings.token_file.chmod(0o600)
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler); server.requests = []
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
            settings.base_url = f"http://127.0.0.1:{server.server_port}/v1"
            settings.gate = FakeGate()
            context = SimpleNamespace()
            with A.configured(settings):
                asyncio.run(A.CodexObserverAgent().run("Execute the harmless requested protocol fixture, then finish.",
                    SimpleNamespace(exec=settings.gate), context))
            self.assertEqual(settings.termination, "CODEX_COMPLETED")
            self.assertEqual(len(server.requests), 2)
            self.assertTrue(all(row.get("reasoning", {}).get("effort") == "none" for row in server.requests))
            self.assertEqual(len(settings.function_bindings), 1)
            self.assertEqual(settings.outcome["function_bindings"][0]["binding_basis"], A.BINDING)
            self.assertIn("DOCKER_EXEC_ROOT_RETURN", settings.outcome["steps"][0]["timing_scope"])
            self.assertFalse(settings.runtime["kernel_observed"])
            self.assertTrue((settings.evidence_directory / "codex-result.json").exists())
            print("REAL_CODEX_HARBOR_ADAPTER_FAKE_PROVIDER_ZERO_PAID_PROTOCOL_PASS", flush=True)


if __name__ == "__main__":
    unittest.main()
