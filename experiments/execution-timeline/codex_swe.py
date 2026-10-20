#!/usr/bin/env python3
"""One genuine Codex app-server + DeepSeek SWE-bench Verified smoke worker.

Codex owns the Agent loop.  Its only admitted tool is observer_bash; every
request is mapped to one stopped Docker Exec root in the pinned SWE task
container before that process is released.  The official SWE-bench evaluator
receives only the resulting repository diff.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile

from codex_harbor_agent import BINDING, CodexSettings, run_runtime
from common import write_new
import model_swe as M


INSTRUCTIONS = (
    "You are Codex, a coding agent solving one SWE-bench Verified task. "
    "Use only observer_bash to inspect, edit, or test the repository in /testbed; "
    "commands execute in the actual task container. Do not use any other tool, "
    "network service, background process, /solution, hidden tests, Docker sockets, "
    "host files, or credentials. Keep the patch focused. When done, give a brief final answer."
)


class CodexSWESession(M.ModelSession):
    def prepare(self):
        proxy = super().prepare()
        agent = "codex-agent:" + self.args.budget_label
        self.manifest.update(agent_id=agent,
            agent_scope="OFFICIAL_CODEX_PUBLIC_SWE_TASK_AND_GATED_DOCKER_TOOLS; CODEX_RUNTIME_OUTSIDE_CONTAINER_CAPTURE",
            agent_implementation="OFFICIAL_CODEX_APP_SERVER_DYNAMIC_TOOLS", model="deepseek-flash")
        proxy.gate.agent_id = proxy.test_gate.agent_id = agent
        proxy.gate.kind = "OFFICIAL_CODEX_DYNAMIC_FUNCTION_EXEC"
        self.persist()
        return proxy


def solve_codex(row, session, proxy, args):
    application = session.directory / "application"
    settings = CodexSettings(base_url=args.broker_base_url,
        token_file=args.broker_token_file, budget_label=args.budget_label,
        evidence_directory=application, agent_id=session.manifest["agent_id"],
        task_id=M.INSTANCE, boot_id=session.manifest["boot_id"],
        codex=args.codex.resolve(strict=True), catalog=args.catalog.resolve(strict=True),
        max_calls=args.max_calls, base_instructions=INSTRUCTIONS, thread_cwd=Path("/testbed"),
        benchmark_kind="SWE_BENCH_VERIFIED")
    settings.gate = proxy.gate

    def execute(command, call_id, rpc_request_id):
        before = len(session.manifest["tools"])
        executed = proxy.exec_run(["timeout", "--kill-after=5s", str(args.tool_timeout),
            "/bin/bash", "-lc", "source /opt/miniconda3/bin/activate && conda activate testbed && " + command],
            workdir="/testbed")
        M.require(len(session.manifest["tools"]) == before + 1,
            "one Codex request must enroll exactly one stopped Docker root")
        span = session.manifest["tools"][-1]
        M.require(span.get("command") and span.get("agent_id") == settings.agent_id,
            "Codex Docker span identity differs")
        output = executed.output.decode("utf-8", "replace")
        number = len(settings.function_bindings) + 1
        stdout_name, stderr_name = f"tool-{number:04d}.stdout", f"tool-{number:04d}.stderr"
        write_new(application / stdout_name, output.encode())
        write_new(application / stderr_name, b"")
        binding = {"tool_call_id": span["tool_call_id"], "observer_tool_call_id": span["tool_call_id"],
            "agent_id": settings.agent_id, "task_id": settings.task_id, "boot_id": settings.boot_id,
            "budget_label": settings.budget_label, "root_pid": span["root"]["tid"], "root": dict(span["root"]),
            "cgroup_id": span["cgroup_id"], "begin_ns": span["begin_ns"], "end_ns": span["end_ns"],
            "gate_binding_basis": BINDING, "cgroup_empty": None,
            "quiescence_scope": "PER_TOOL_ROOT_FINISHED; FULL_CONTAINER_CLOSURE_ONLY_AT_AGENT_END",
            "stdout_artifact": "application/" + stdout_name, "stderr_artifact": "application/" + stderr_name,
            "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
            "docker_exec_id": span.get("docker_exec_id"), "gate_result": span.get("result")}
        settings.function_bindings.append({"thread_id": None, "turn_id": None, "call_id": call_id,
            "rpc_request_id": rpc_request_id, "command": command, **binding})
        settings.persist()
        return {"exit_code": executed.exit_code, "stdout": output[:3500], "stderr": "",
            "output_truncated": len(output) > 3500, "binding": binding}

    outcome = run_runtime(settings, row["problem_statement"], execute)
    M.require(proxy.infrastructure_error is None,
        "Codex transport/identity failure: " + str(proxy.infrastructure_error))

    submitted = proxy.exec_run(["bash", "-lc", "git add -N -- . && git diff --binary HEAD"], workdir="/testbed")
    M.require(submitted.exit_code == 0 and len(submitted.output) <= 1024 * 1024,
        "bounded Codex diff extraction failed")
    patch = submitted.output.decode("utf-8")
    write_new(args.output / "agent.patch", submitted.output)
    if patch:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as stream:
            item = tarfile.TarInfo("observer-submission.diff")
            item.size, item.mode = len(submitted.output), 0o600
            stream.addfile(item, io.BytesIO(submitted.output))
        M.require(session.container.put_archive("/tmp", archive.getvalue()), "Codex diff staging failed")
        restored = proxy.exec_run(["git", "apply", "--reverse", "--binary", "/tmp/observer-submission.diff"],
            workdir="/testbed")
        M.require(restored.exit_code == 0, "exact Codex diff reversal failed")
    result = {"mode": M.MODE, "model": "deepseek-flash", "budget_label": args.budget_label,
        "agent_implementation": "OFFICIAL_CODEX_APP_SERVER_DYNAMIC_TOOLS",
        "termination": settings.termination, "status": outcome.get("status"),
        "thread_id": outcome.get("thread_id"), "turn_id": outcome.get("turn_id"),
        "tool_calls": outcome.get("tool_calls", []), "request_attempts": None,
        "function_bindings": len(outcome.get("function_bindings", [])),
        "patch_bytes": len(submitted.output), "gold_patch_exposed": False, "test_patch_exposed": False,
        "scope": "CODEX_RPC_TO_STOPPED_DOCKER_ROOTS; OFFICIAL_SWE_EVALUATION; NO_GPU"}
    write_new(application / "agent-result.json", result)
    return patch, result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("inputs", "bridge", "swe-adapter", "collector", "object", "output", "control-dir",
                   "image-import-provenance", "broker-token-file", "codex", "catalog"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--budget-label", choices=("codex-swe-smoke-001", "codex-swe-smoke-002"), required=True)
    parser.add_argument("--broker-base-url", default="http://127.0.0.1:10091/v1")
    parser.add_argument("--max-rounds", type=int, choices=(4,), default=4)
    parser.add_argument("--max-calls", type=int, choices=(8, 10), default=8)
    parser.add_argument("--max-output", type=int, choices=(4096,), default=4096)
    parser.add_argument("--tool-timeout", type=int, choices=(45,), default=45)
    parser.add_argument("--test-timeout", type=int, default=300)
    parser.add_argument("--docker-socket", default="/var/run/docker.sock")
    parser.add_argument("--capture-only", action="store_true")
    args = parser.parse_args(argv)
    M.require(1 <= args.test_timeout <= 600, "bounded official test timeout required")
    expected_calls = 10 if args.budget_label.endswith("-002") else 8
    M.require(args.max_calls == expected_calls, "tool-call limit must match registered smoke label")
    M.ModelSession, M.solve_model = CodexSWESession, solve_codex
    return M.run_worker(args)


if __name__ == "__main__":
    raise SystemExit(main())
