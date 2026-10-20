#!/usr/bin/env python3
"""AgentBench FC OS subset using its unchanged task loader and judge.

The local transport is Docker exec, not the upstream Redis/controller stack.
Selected tasks do not depend on a persistent terminal's cwd or environment.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import signal
import sys
import time
import urllib.request
import uuid
from pathlib import Path
from types import SimpleNamespace


async def command(*argv, timeout=60):
    proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE,
                                               stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
    except BaseException:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        raise
    return proc.returncode, stdout, stderr


class DockerContainer:
    def __init__(self, identifier, log):
        self.identifier, self.log, self.audit = identifier, log, None

    async def execute(self, script):
        code, stdout, stderr = await self.execute_independent(("bash", script))
        return SimpleNamespace(exit_code=code, output=stdout + stderr)

    async def execute_independent(self, script, *params):
        language, text = script
        if language == "bash":
            argv = ["bash", "-c", text, "--", *params]
        elif language == "python":
            argv = ["python3", "-c", text, *params]
        else:
            raise ValueError("Pilot supports only the declared bash/Python scripts")
        start = time.monotonic_ns()
        if self.audit is not None and not self.audit.closed:
            self.audit.mark("TOOL_START", tool_id=len(self.log), command=text)
        result = await command("docker", "exec", "-w", "/root", self.identifier, *argv)
        if self.audit is not None and not self.audit.closed:
            self.audit.mark("TOOL_END", tool_id=len(self.log), exit_code=result[0])
        self.log.append({"kind": "tool", "language": language, "command": text,
                         "start_ns": start, "end_ns": time.monotonic_ns(), "return_code": result[0]})
        return result


class Session:
    def __init__(self, args, tools, config, task_id):
        self.args, self.tools, self.config = args, tools, config
        self.task_id = task_id
        self.history, self.actions, self.round, self.audit = [], [], 0, None

    def inject(self, item):
        if isinstance(item, dict) and item.get("role"):
            self.history.append(item)

    async def action(self):
        if self.args.agent == "example-control":
            if self.round == 0:
                name, arguments = "bash_action", {"script": self.config.example_script[1]}
            elif self.config.check and self.config.check[0] is None:
                output = next(row["content"] for row in reversed(self.history) if row["role"] == "tool")
                name, arguments = "answer_action", {"answer": output.removeprefix("The output of the OS:\n\n").strip()}
            else:
                name, arguments = "finish_action", {"thought": "Executed the official example"}
            message = {"role": "assistant", "content": None, "tool_calls": [{"id": "control-" + str(self.round),
                "type": "function", "function": {"name": name, "arguments": json.dumps(arguments)}}]}
        else:
            token = self.args.broker_token.read_text().strip()
            payload = {"model": "deepseek-flash", "messages": self.history, "tools": self.tools,
                       "max_tokens": 2048, "stream": False}
            def request():
                req = urllib.request.Request(self.args.broker_url + "/chat/completions", data=json.dumps(payload).encode(),
                    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                             "X-Benchmark-Task": "agentbench-os/" + self.task_id})
                with urllib.request.urlopen(req, timeout=180) as response:
                    return json.load(response)
            start = time.monotonic_ns()
            if self.audit is not None and not self.audit.closed:
                self.audit.mark("MODEL_REQUEST_START", request_id=self.round)
            result = await asyncio.to_thread(request)
            if self.audit is not None and not self.audit.closed:
                self.audit.mark("MODEL_REQUEST_END", request_id=self.round, usage=result.get("usage"))
            message = result["choices"][0]["message"]
            self.actions.append({"kind": "model_request", "start_ns": start, "end_ns": time.monotonic_ns(),
                                 "usage": result.get("usage"), "assistant": message})
        self.history.append(message)
        self.round += 1
        return SimpleNamespace(messages=[message])


async def run(args):
    for domain in ("cpu", "memory", "io"):
        for path in (Path("/proc/pressure") / domain, Path("/sys/fs/cgroup") / (domain + ".pressure")):
            if "some " not in path.read_text():
                raise RuntimeError("Requires enabled, readable system and cgroup PSI")
    sys.path.insert(0, str(args.source.resolve()))
    from src.server.tasks.os_interaction.task import OSInteraction
    import yaml
    audit_module, artifacts, bridge, docker_client = None, None, None, None
    if args.artifacts is not None:
        import docker
        spec = importlib.util.spec_from_file_location("benchmark_observation_session", args.audit_helper)
        audit_module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = audit_module
        spec.loader.exec_module(audit_module)
        artifacts = json.loads(args.artifacts.read_text())
        bridge = audit_module.load_bridge(args.bridge)
        for name in ("observer", "verifier", "recorder", "lifecycle", "sampler"):
            key = name + ("_object" if name in ("recorder", "lifecycle") else "_binary")
            bridge.validate_trusted_file(Path(artifacts[key]), artifacts[name + "_sha256"], name)
        for name in ("ip", "tc", "nft"):
            bridge.validate_network_collector(Path(artifacts[name + "_binary"]), artifacts[name + "_sha256"], name)
        docker_client = docker.from_env()
    raw_tools = yaml.safe_load((args.source / "configs/tasks/os.yaml").read_text())["default"]["parameters"]["tools"]
    revision = (await command("git", "-C", str(args.source), "rev-parse", "HEAD"))[1].decode().strip()
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for fixture, idx in (("3/ac.json", 0), ("3/ac.json", 2), ("2/environment.json", 4)):
        task_key = fixture.replace("/", "-").removesuffix(".json") + "-" + str(idx)
        folder = args.output / task_key
        folder.mkdir()
        logs, phase, sampler, audit = [], {}, None, None
        stderr = None

        class MeasuredTask(OSInteraction):
            async def _setup_execution_environment(self, config, container):
                nonlocal sampler, stderr, audit
                result = await super()._setup_execution_environment(config, container)
                if result is None:
                    logs.clear()  # setup is outside the observed Agent interval
                    if audit_module is not None:
                        sdk_container = docker_client.containers.get(container_id)
                        audit = audit_module.Session(sdk_container, folder / "audit", "agentbench-" + uuid.uuid4().hex,
                            artifacts, bridge, task_id=task_key, agent_id=args.agent, filesystem_root="/root")
                        container.audit = session.audit = audit
                        await asyncio.to_thread(audit.start)
                        phase["agent_start_ns"] = time.monotonic_ns()
                        return result
                    stderr = (folder / "sampler.stderr").open("xb")
                    sampler = await asyncio.create_subprocess_exec(str(args.sampler), "--output-dir", str(folder / "sampler"),
                        "--cgroup", str(cgroup), "--label", task_key, "--interval-ms", "100", "--process-interval-ms", "100",
                        "--exit-with-parent", stdout=asyncio.subprocess.PIPE, stderr=stderr)
                    if await asyncio.wait_for(sampler.stdout.readline(), 30) != b"READY\n":
                        raise RuntimeError("Sampler READY failed")
                    phase["agent_start_ns"] = time.monotonic_ns()
                return result

            async def _evaluate_answer(self, answer, config, container, session):
                phase["agent_end_ns"] = time.monotonic_ns()
                if audit is not None:
                    await asyncio.to_thread(audit.finish)
                else:
                    await stop_sampler()
                phase["judge_start_ns"] = time.monotonic_ns()
                result = await super()._evaluate_answer(answer, config, container, session)
                phase["judge_end_ns"] = time.monotonic_ns()
                return result

        async def stop_sampler():
            if sampler is not None and sampler.returncode is None:
                await asyncio.sleep(0.15)
                sampler.send_signal(signal.SIGTERM)
                try:
                    await asyncio.wait_for(sampler.wait(), 10)
                except asyncio.TimeoutError:
                    sampler.kill()
                    await sampler.wait()
            if stderr is not None:
                stderr.close()

        task = object.__new__(MeasuredTask)
        task.round_limit, task.tools = 8, raw_tools
        fixture_path = args.source / "data/os_interaction/data" / fixture
        config = task._load_configs(str(fixture_path), str(args.source / "data/os_interaction/scripts" / fixture[0]))[idx]
        if config.image != "default":
            raise RuntimeError("Pilot task unexpectedly requests another image")
        name = "observer-agentbench-" + uuid.uuid4().hex[:12]
        rc, stdout, error = await command("docker", "run", "-d", "--name", name, "--cpus", "2", "--memory", "1g",
            "--memory-swap", "1g", "--workdir", "/root", "--entrypoint", "/bin/sleep", args.image, "infinity")
        if rc:
            raise RuntimeError(error.decode())
        container_id = stdout.decode().strip()
        container = DockerContainer(container_id, logs)
        session = Session(args, raw_tools, config, task_key)
        result, error = None, None
        try:
            inspect = json.loads((await command("docker", "inspect", container_id))[1])[0]
            pid = inspect["State"]["Pid"]
            cg_path = (Path("/proc") / str(pid) / "cgroup").read_text().strip().split(":", 2)[2]
            if not cg_path.startswith("/") or cg_path == "/" or container_id not in cg_path:
                raise RuntimeError("Container cgroup identity is not established")
            cgroup = Path("/sys/fs/cgroup") / cg_path.lstrip("/")
            metadata = cgroup.stat()
            phase.update({"container_id": container_id, "init_pid": pid, "cgroup": str(cgroup),
                "inode": metadata.st_ino, "device": metadata.st_dev,
                "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "image_id": inspect["Image"]})
            result = await task._judge(session, config, container)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                if audit is not None and not audit.closed:
                    await asyncio.to_thread(audit.finish)
                await stop_sampler()
            except Exception as exc:
                error = (error + "; " if error else "") + "EVIDENCE_FINALIZATION_FAILED: " + str(exc)
            cleanup = await command("docker", "rm", "-f", container_id)
            if cleanup[0]:
                error = (error or "") + "; CONTAINER_CLEANUP_FAILED: " + cleanup[2].decode()
        verification = json.loads((folder / "audit/verification.json").read_text()) if (folder / "audit/verification.json").exists() else None
        record = {"task": task_key, "description": config.description, "agent": args.agent,
            "result": result.model_dump(mode="json") if result else None, "error": error,
            "phase": phase, "fixture_sha256": hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
            "sampler_exit_code": (audit.sampler.returncode if audit and audit.sampler else sampler.returncode if sampler else None),
            "observer_verification": verification, "audit_enabled": audit_module is not None}
        (folder / "result.json").write_text(json.dumps(record, indent=2))
        (folder / "tool-intervals.json").write_text(json.dumps(logs, indent=2))
        (folder / "agent-transcript.json").write_text(json.dumps(session.history, indent=2))
        (folder / "model-requests.json").write_text(json.dumps(session.actions, indent=2))
        results.append(record)
    summary = {"schema_version": 1, "benchmark": "THUDM/AgentBench FC OS", "source_revision": revision,
        "evaluation": "UNCHANGED_UPSTREAM_TASK_LOADER_AND_JUDGE_WITH_LOCAL_DOCKER_TRANSPORT",
        "agent": args.agent, "tasks": results,
        "audit_enabled": audit_module is not None,
        "limitations": ["3 selected OS samples only; no whole-suite score", "Docker exec is not the upstream persistent terminal/controller stack", "Observer claims retain declared partial lifecycle and actor-contract limits", "Single integration run; no slowdown or optimization claim"]}
    (args.output / "campaign-summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, sort_keys=True))
    return int(any(row["error"] or row["sampler_exit_code"] != 0 or (row["audit_enabled"] and (row["observer_verification"] or {}).get("verified") is not True) for row in results))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sampler", type=Path, required=True)
    parser.add_argument("--image", default="local-os/default")
    parser.add_argument("--artifacts", type=Path, help="Enable the real Observer audit using this digest-pinned artifact config")
    parser.add_argument("--audit-helper", type=Path, default=Path("/opt/agent-benchmarks/swe/run.py"))
    parser.add_argument("--bridge", type=Path, default=Path("/opt/bpf-observer/bridge.py"))
    parser.add_argument("--agent", choices=("example-control", "model"), required=True)
    parser.add_argument("--broker-url", default="http://10.0.2.2:10090/v1")
    parser.add_argument("--broker-token", type=Path, default=Path("/opt/agent-benchmarks/private/model-broker-token"))
    raise SystemExit(asyncio.run(run(parser.parse_args())))
