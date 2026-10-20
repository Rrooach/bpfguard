#!/usr/bin/env python3
"""One real official-Codex + DeepSeek Terminal-Bench parallel worker."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from common import digest
from parallel_terminal import WorkerHooks, parser as reference_parser, validate_options

MODE = "MODEL_AGENT"
IMPLEMENTATION = "OFFICIAL_CODEX_APP_SERVER_DYNAMIC_TOOLS"
SCOPE = "OFFICIAL_CODEX_PUBLIC_TASK_AND_GATED_DOCKER_TOOLS; CODEX_RUNTIME_OUTSIDE_CONTAINER_CAPTURE"


class CodexWorkerHooks(WorkerHooks):
    def __init__(self, *, settings, **kwargs):
        super().__init__(agent_id=settings.agent_id, agent_scope=SCOPE, **kwargs)
        self.settings = settings

    async def start(self, trial, callback, *args, **kwargs):
        result = await super().start(trial, callback, *args, **kwargs)
        self.adapter.tool_prefix = self.settings.budget_label + "-exec"
        self.adapter.kind = "OFFICIAL_CODEX_DYNAMIC_FUNCTION_EXEC"
        self.settings.gate = self.adapter
        self.adapter.manifest.update(mode=MODE, budget_label=self.settings.budget_label, model="deepseek-flash",
            agent_implementation=IMPLEMENTATION)
        self.adapter.persist()
        return result

    def bind_application_evidence(self):
        settings, manifest = self.settings, self.adapter.manifest
        if settings.boot_id != manifest["boot_id"] or settings.agent_id != manifest["agent_id"]:
            raise RuntimeError("Codex application/capture boot or Agent identity differs")
        settings.persist()
        spans = {row["tool_call_id"]: row for row in manifest["tools"]}
        if len(spans) != len(manifest["tools"]):
            raise RuntimeError("duplicate Docker tool span")
        bound = settings.function_bindings
        if (len(bound) != len(spans) or len({row["tool_call_id"] for row in bound}) != len(bound)
                or any(row["tool_call_id"] not in spans or row["root"] != spans[row["tool_call_id"]]["root"]
                       or row["agent_id"] != self.agent_id for row in bound)):
            raise RuntimeError("every Codex call must bind exactly one recorded stopped Docker Exec")
        if settings.outcome is None:
            raise RuntimeError("Codex runtime did not produce a final application result")
        application = settings.outcome.get("function_bindings", [])
        by_call = {row["call_id"]: row for row in application}
        if len(by_call) != len(application) or len(application) != len(bound):
            raise RuntimeError("Codex result and Docker function ledger have different calls")
        for row in bound:
            exact = by_call.get(row["call_id"], {})
            if any(exact.get(key) != row.get(key) for key in ("rpc_request_id", "command", "root", "tool_call_id",
                    "cgroup_id", "begin_ns", "end_ns", "stdout_artifact", "stderr_artifact")):
                raise RuntimeError("Codex app result differs from exact Docker enrollment")
        artifacts = {}
        for path in sorted(settings.evidence_directory.iterdir()):
            if not path.is_file() or path.is_symlink():
                raise RuntimeError("Codex app evidence must contain only regular files")
            name = str(path.relative_to(self.adapter.directory))
            artifacts[name] = digest(path)
            manifest["artifacts"][name] = artifacts[name]
        manifest["codex_application"] = {"schema_version": 1, "mode": MODE,
            "agent_implementation": IMPLEMENTATION, "budget_label": settings.budget_label,
            "agent_id": settings.agent_id, "task_id": settings.task_id, "boot_id": settings.boot_id,
            "clock": "CLOCK_MONOTONIC", "model": "deepseek-flash", "termination": settings.termination,
            "function_bindings": len(bound), "runtime": settings.runtime, "artifacts": artifacts,
            "agent_loop": "OFFICIAL_CODEX_NOT_IMPLEMENTED_BY_THIS_CLIENT",
            "evidence_scope": "CODEX_RPC_TO_STOPPED_DOCKER_ROOTS; CODEX_RUNTIME_OUTSIDE_KERNEL_CAPTURE"}
        self.adapter.persist()

    async def finish(self, trial, callback, *args, **kwargs):
        async def after_binding(*values, **options):
            self.bind_application_evidence()
            return await callback(*values, **options)
        return await super().finish(trial, after_binding, *args, **kwargs)


def accounting(settings):
    return {"paid_api_calls": None, "client_request_attempts": 0,
        "client_request_attempts_scope": "SEE_RAW_CODEX_RPC_AND_SHARED_BROKER; CLIENT_DOES_NOT_OWN_MODEL_LOOP",
        "budget_label": settings.budget_label, "model": "deepseek-flash",
        "agent_implementation": IMPLEMENTATION, "termination": settings.termination,
        "cost_authority": "SHARED_HOST_RESPONSES_BROKER_LEDGER_NOT_CLIENT_ESTIMATE"}


def write_worker_result(args, hooks, terminal, error=None):
    path = args.output / "campaign-summary.json"
    rows = json.loads(path.read_text()).get("tasks", []) if path.exists() else []
    if rows and (len(rows) != 1 or rows[0].get("task") != args.task[0]):
        raise ValueError("one Codex worker must contain exactly its official task")
    row = rows[0] if rows else {}
    directory = Path(row.get("timeline_directory", args.output / "timelines" / args.task[0]))
    result = {"schema_version": 1, "benchmark": "Terminal-Bench", "job_id": args.job_id,
        "task_id": "terminal-bench/" + args.task[0], "mode": MODE, "agent_implementation": IMPLEMENTATION,
        "agent_id": hooks.agent_id, "budget_label": args.budget_label, "model": "deepseek-flash",
        "timeline_directory": str(directory.resolve().relative_to(args.output.resolve())),
        "official_evaluated": row.get("harbor_rewards") is not None and not row.get("harbor_exception"),
        "official_passed": row.get("task_reward_passed") is True and not row.get("harbor_exception"),
        "official_result": {key: row.get(key) for key in ("harbor_rewards", "harbor_exception", "harbor_result")},
        "agent_return_ns": hooks.agent_return_ns, "quiescent_ns": hooks.quiescent_ns,
        "capture_status": row.get("timeline_acceptance", "INCOMPLETE"),
        "model_accounting": accounting(hooks.settings), "model_termination": hooks.settings.termination,
        "codex_runtime": hooks.settings.runtime, "error": error}
    terminal.write_json(args.output / "worker-result.json", result)
    return result, row


def validate_codex_options(args):
    from codex_harbor_agent import LABEL
    validate_options(args)
    if (args.phase_timeout != 7200 or not LABEL.fullmatch(args.budget_label) or not args.capture_only
            or (args.max_calls, args.max_requests, args.max_output) != (8, 12, 4096)):
        raise ValueError("Codex requires registered terminal label, capture-only, 7200s phase gates and 8/12/4096 bounds")
    for name in ("codex", "catalog"):
        path = getattr(args, name)
        if not path.is_file() or path.is_symlink():
            raise ValueError("explicit regular Codex binary/catalog required")


async def run_worker(args, *, control=None, terminal=None, trial_class=None, trial_events=None,
                     finder_factory=None, agent_config_factory=None, settings_factory=None):
    from codex_harbor_agent import CodexSettings, configured
    validate_codex_options(args)
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
    settings = (settings_factory or CodexSettings)(base_url=args.broker_base_url,
        token_file=args.broker_token_file, budget_label=args.budget_label,
        evidence_directory=args.output / "timelines" / args.task[0] / "app",
        agent_id="codex-agent:" + args.budget_label, task_id="terminal-bench/" + args.task[0],
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        codex=args.codex.resolve(strict=True), catalog=args.catalog.resolve(strict=True))
    hooks = CodexWorkerHooks(settings=settings, job_id=args.job_id, task=args.task[0], control=control,
                             terminal=terminal, finder_factory=finder_factory)
    args.search_probe = False
    try:
        configuration = agent_config_factory(import_path="codex_harbor_agent:CodexObserverAgent",
            model_name="deepseek-flash", override_timeout_sec=1950)
        identity = {"agent_id": settings.agent_id, "agent_scope": SCOPE, "mode": MODE,
                    "agent_implementation": IMPLEMENTATION, "budget_label": args.budget_label, "model": "deepseek-flash"}
        with configured(settings), hooks.install(trial_class, trial_events.AGENT_START, trial_events.AGENT_END):
            code = await terminal.campaign(args, agent_config=configuration, agent_identity=identity,
                                           paid_call_info=lambda: accounting(settings))
        worker, row = write_worker_result(args, hooks, terminal)
        if (not hooks.ended or (hooks.start_hooks, hooks.end_hooks) != (1, 1) or code not in (0, 1)
                or any(row.get(key) for key in ("error", "collector_error", "replay_error", "harbor_exception"))
                or not worker["official_evaluated"]):
            raise RuntimeError("Codex infrastructure/official grading did not complete; score 0 alone is allowed")
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
    result.add_argument("--broker-base-url", default="http://127.0.0.1:10091/v1")
    result.add_argument("--broker-token-file", type=Path, required=True)
    result.add_argument("--codex", type=Path, required=True)
    result.add_argument("--catalog", type=Path, required=True)
    result.add_argument("--max-calls", type=int, default=8)
    result.add_argument("--max-requests", type=int, default=12)
    result.add_argument("--max-output", type=int, default=4096)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return asyncio.run(run_worker(args))
    except Exception as error:
        print(json.dumps({"job_id": args.job_id, "mode": MODE, "agent_implementation": IMPLEMENTATION,
            "error_type": type(error).__name__, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
