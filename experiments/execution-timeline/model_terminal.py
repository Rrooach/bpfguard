#!/usr/bin/env python3
"""One bounded, real-model Terminal trial; independent from Oracle contracts."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from common import digest
from model_client import LABEL
from parallel_terminal import WorkerHooks, parser as reference_parser, validate_options

MODE = "MODEL_AGENT"
MODEL_SCOPE = "REAL_MODEL_AGENT_PUBLIC_INSTRUCTION_AND_GATED_TOOLS_NOT_ORACLE"


class ModelWorkerHooks(WorkerHooks):
    def __init__(self, *, settings, **kwargs):
        super().__init__(agent_id=settings.agent_id, agent_scope=MODEL_SCOPE, **kwargs)
        self.settings = settings

    async def start(self, trial, callback, *args, **kwargs):
        result = await super().start(trial, callback, *args, **kwargs)
        self.adapter.tool_prefix = self.settings.budget_label + "-exec"
        self.adapter.kind = "REAL_MODEL_FUNCTION_EXEC"
        self.settings.gate = self.adapter
        self.adapter.manifest.update(mode=MODE, budget_label=self.settings.budget_label, model="deepseek-flash")
        self.adapter.persist()
        return result

    def bind_application_evidence(self):
        settings, manifest = self.settings, self.adapter.manifest
        if settings.boot_id != manifest["boot_id"] or settings.agent_id != manifest["agent_id"]:
            raise RuntimeError("application/collector boot and Agent identity differ")
        if settings.client is None:
            raise RuntimeError("released model agent did not establish its application evidence client")
        settings.persist()
        spans = {row["tool_call_id"]: row for row in manifest["tools"]}
        bound = settings.function_bindings
        if (len(bound) != len(spans) or len({row["observer_tool_call_id"] for row in bound}) != len(bound)
                or any(row["observer_tool_call_id"] not in spans
                       or row["root"] != spans[row["observer_tool_call_id"]]["root"]
                       or row["agent_id"] != self.agent_id for row in bound)):
            raise RuntimeError("provider function-call ledger does not bind every recorded model tool exactly once")
        artifacts = {}
        for path in sorted(settings.evidence_directory.iterdir()):
            if not path.is_file() or path.is_symlink():
                raise RuntimeError("application evidence must contain only regular files")
            name = str(path.relative_to(self.adapter.directory))
            artifacts[name] = digest(path)
            manifest["artifacts"][name] = artifacts[name]
        manifest["model_application"] = {
            "schema_version": 1, "mode": MODE, "budget_label": settings.budget_label,
            "model": "deepseek-flash", "boot_id": settings.boot_id, "clock": "CLOCK_MONOTONIC",
            "agent_id": settings.agent_id, "task_id": settings.task_id,
            "termination": settings.termination, "request_count": len(settings.client.events),
            "function_bindings": len(bound), "artifacts": artifacts,
            "evidence_scope": "APPLICATION_REQUEST_SPANS_AND_EXPLICIT_FUNCTION_TO_GATE_ROOT_BINDINGS; NOT_GPU_OR_DAEMON_CAUSAL_PROOF"}
        self.adapter.persist()

    async def finish(self, trial, callback, *args, **kwargs):
        # The base freezes immediately at Agent return and waits for every job.
        # Hashing transcripts runs only after ALL_AGENTS_DONE, before STOP.
        async def capture_after_binding(*values, **options):
            self.bind_application_evidence()
            return await callback(*values, **options)
        return await super().finish(trial, capture_after_binding, *args, **kwargs)


def accounting(settings):
    return {"paid_api_calls": None, "client_request_attempts": len(settings.client.events) if settings.client else 0,
            "budget_label": settings.budget_label, "model": "deepseek-flash",
            "termination": settings.termination,
            "usage": dict(settings.client.usage) if settings.client else {"prompt_tokens": 0, "completion_tokens": 0},
            "cost_authority": "SHARED_HOST_BROKER_LEDGER_NOT_CLIENT_ESTIMATE"}


def write_worker_result(args, hooks, terminal, error=None):
    path = args.output / "campaign-summary.json"
    rows = json.loads(path.read_text()).get("tasks", []) if path.exists() else []
    if rows and (len(rows) != 1 or rows[0].get("task") != args.task[0]):
        raise ValueError("single model worker cannot contain another official task")
    row = rows[0] if rows else {}
    directory = Path(row.get("timeline_directory", args.output / "timelines" / args.task[0]))
    result = {"schema_version": 1, "benchmark": "Terminal-Bench", "job_id": args.job_id,
        "task_id": "terminal-bench/" + args.task[0], "mode": MODE, "agent_id": hooks.agent_id,
        "budget_label": args.budget_label, "model": "deepseek-flash",
        "timeline_directory": str(directory.resolve().relative_to(args.output.resolve())),
        "official_evaluated": row.get("harbor_rewards") is not None and not row.get("harbor_exception"),
        "official_passed": row.get("task_reward_passed") is True and not row.get("harbor_exception"),
        "official_result": {key: row.get(key) for key in ("harbor_rewards", "harbor_exception", "harbor_result")},
        "agent_return_ns": hooks.agent_return_ns, "quiescent_ns": hooks.quiescent_ns,
        "capture_status": row.get("timeline_acceptance", "INCOMPLETE"),
        "model_accounting": accounting(hooks.settings), "model_termination": hooks.settings.termination,
        "error": error}
    terminal.write_json(args.output / "worker-result.json", result)
    return result, row


def validate_model_options(args):
    validate_options(args)
    if (args.phase_timeout != 7200 or not LABEL.fullmatch(args.budget_label)
            or not args.budget_label.startswith("model-terminal-")
            or args.max_rounds != 4 or args.max_output != 1024 or not args.capture_only):
        raise ValueError("model campaign requires explicit terminal label, 7200s phase gates, capture-only and fixed 4x1024 bounds")


async def run_worker(args, *, control=None, terminal=None, trial_class=None, trial_events=None,
                     finder_factory=None, agent_config_factory=None, settings_factory=None):
    validate_model_options(args)
    from model_harbor_agent import ModelSettings, configured
    if terminal is None:
        import terminal_validate as terminal
    if control is None:
        from phase_control import Control
        control = Control(args.control_dir, args.job_id, timeout=args.phase_timeout)
    if trial_class is None or trial_events is None:
        from harbor.trial.trial import Trial
        from harbor.trial.hooks import TrialEvent
        trial_class, trial_events = Trial, TrialEvent
    if agent_config_factory is None:
        from harbor.models.trial.config import AgentConfig
        agent_config_factory = AgentConfig
    if finder_factory is None:
        bridge = terminal.load_bridge(args.bridge)
        finder_factory = lambda trial: bridge.TrialObserverBridge(
            trial=trial, options=SimpleNamespace(docker_timeout=30), task_label=args.task[0])
    settings = (settings_factory or ModelSettings)(
        base_url=args.broker_base_url, token_file=args.broker_token_file,
        budget_label=args.budget_label, evidence_directory=args.output / "timelines" / args.task[0] / "model-evidence",
        agent_id="model-agent:" + args.budget_label, task_id="terminal-bench/" + args.task[0],
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip())
    hooks = ModelWorkerHooks(settings=settings, job_id=args.job_id, task=args.task[0], control=control,
                             terminal=terminal, finder_factory=finder_factory)
    args.search_probe = False
    try:
        configuration = agent_config_factory(import_path="model_harbor_agent:BoundedModelAgent",
            model_name="deepseek-flash", override_timeout_sec=1800)
        identity = {"agent_id": settings.agent_id, "agent_scope": MODEL_SCOPE,
                    "mode": MODE, "budget_label": args.budget_label, "model": "deepseek-flash"}
        with configured(settings), hooks.install(trial_class, trial_events.AGENT_START, trial_events.AGENT_END):
            code = await terminal.campaign(args, agent_config=configuration, agent_identity=identity,
                                           paid_call_info=lambda: accounting(settings))
        worker, row = write_worker_result(args, hooks, terminal)
        if (not hooks.ended or (hooks.start_hooks, hooks.end_hooks) != (1, 1) or code not in (0, 1)
                or any(row.get(key) for key in ("error", "collector_error", "replay_error", "harbor_exception"))
                or not worker["official_evaluated"]):
            raise RuntimeError("model infrastructure or official evaluation did not complete; score failure alone is permitted")
        if any(tool.get("agent_id") != hooks.agent_id or not tool.get("tool_call_id", "").startswith(args.budget_label + "-exec-")
               for tool in hooks.adapter.manifest.get("tools", [])):
            raise RuntimeError("model tool attribution differs from its explicit job")
        return 0
    except BaseException as error:
        hooks.abort(error)
        if args.output.is_dir() and not (args.output / "worker-result.json").exists():
            try:
                write_worker_result(args, hooks, terminal, type(error).__name__ + ": " + str(error))
            except Exception:
                pass
        raise


def parser():
    result = reference_parser()
    result.description = __doc__
    result.set_defaults(phase_timeout=7200.0)
    result.add_argument("--budget-label", required=True)
    result.add_argument("--broker-base-url", default="http://10.0.2.2:10091/v1")
    result.add_argument("--broker-token-file", type=Path, required=True)
    result.add_argument("--max-rounds", type=int, default=4)
    result.add_argument("--max-output", type=int, default=1024)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return asyncio.run(run_worker(args))
    except Exception as error:
        print(json.dumps({"job_id": args.job_id, "mode": MODE, "error_type": type(error).__name__,
                          "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
