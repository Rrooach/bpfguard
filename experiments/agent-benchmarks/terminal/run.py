#!/usr/bin/env python3
"""Run pinned genuine Harbor tasks, with Observer audit and PSI sampling.

The Oracle is a harness control; budget-shell is a bounded real model agent.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib.util
import hashlib
import json
import os
import shutil
import signal
import sys
import time
import uuid
from importlib.metadata import version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from diagnostics import Diagnostics, sampler_options


def load_bridge(path):
    spec = importlib.util.spec_from_file_location("terminal_observer_bridge", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def campaign(args):
    from harbor.models.environment_type import EnvironmentType
    from harbor.models.trial.config import AgentConfig, EnvironmentConfig, TaskConfig, TrialConfig
    from harbor.trial.hooks import TrialEvent
    from harbor.trial.trial import Trial
    bridge = load_bridge(args.bridge)
    if version("harbor") != bridge.SUPPORTED_HARBOR_VERSION or os.geteuid() != 0:
        raise RuntimeError("Requires root and the reviewed Harbor 0.23.0")
    for domain in ("cpu", "memory", "io"):
        for path in (Path("/proc/pressure") / domain, Path("/sys/fs/cgroup") / (domain + ".pressure")):
            if "some " not in path.read_text():
                raise RuntimeError("Requires enabled, readable system and cgroup PSI")
    raw = json.loads(args.bridge_config.read_text())
    # Validate every task against the immutable pilot input set, even when this
    # explicitly declared campaign selects a subset for model cost control.
    manifest = json.loads(args.selection.read_text())
    all_tasks = [args.tasks_dir / row["directory"] for row in manifest["tasks"]]
    selection = bridge.validate_selection_manifest(args.selection, args.selection_sha256, all_tasks)
    known = {path.name: path for path in all_tasks}
    if len(set(args.task)) != len(args.task) or any(name not in known for name in args.task):
        raise RuntimeError("Task subset must be unique members of the pinned selection")
    for name, digest_name in (("observer_binary", "observer_sha256"),
                             ("verifier_binary", "verifier_sha256"),
                             ("recorder_object", "recorder_sha256"),
                             ("lifecycle_object", "lifecycle_sha256")):
        bridge.validate_trusted_file(Path(raw[name]), raw[digest_name], name)
    for name in ("ip", "tc", "nft"):
        bridge.validate_network_collector(Path(raw[name + "_binary"]), raw[name + "_sha256"], name)
    root = bridge.require_empty_directory_target(args.output, "campaign directory")
    trials_dir = root / "harbor-trials"
    trials_dir.mkdir()
    overlay = root / "compose-overlay.yaml"
    bridge.write_new_bytes(overlay, b"services:\n  main: {}\n")
    image_overrides = json.loads(args.prebuilt_images.read_text()) if args.prebuilt_images else {}
    materialized = {}
    for name in args.task:
        override = image_overrides.get(name)
        if not override:
            materialized[name] = known[name]
            continue
        path = root / "materialized-inputs" / name
        shutil.copytree(known[name], path)
        text = (path / "task.toml").read_text()
        if "[verifier.environment]" in text or "docker_image" in text:
            raise RuntimeError("Pilot prebuilt override refuses pre-existing image settings")
        for key in ("agent", "verifier"):
            image = override.get(key)
            if image is not None:
                if not isinstance(image, str) or not image.startswith("sha256:") or len(image) != 71:
                    raise RuntimeError("Prebuilt images must be exact local SHA-256 image IDs")
                await bridge.docker_json("image", "inspect", image, timeout=30)
        if override.get("agent"):
            text = text.replace("[environment]\n", "[environment]\ndocker_image = " + json.dumps(override["agent"]) + "\n", 1)
        if override.get("verifier"):
            text += "\n[verifier.environment]\ndocker_image = " + json.dumps(override["verifier"]) + "\n"
        (path / "task.toml").write_text(text)
        materialized[name] = path
    results = []
    for index, name in enumerate(args.task):
        options_data = {key: value for key, value in raw.items()
                        if key in bridge.BridgeOptions.__dataclass_fields__}
        for key in ("observer_binary", "verifier_binary", "recorder_object", "lifecycle_object",
                    "ip_binary", "tc_binary", "nft_binary"):
            options_data[key] = Path(options_data[key])
        options_data["evidence_root"] = root / "evidence"
        options_data["evidence_root"].mkdir(exist_ok=True)
        options = bridge.BridgeOptions(**options_data)
        agent = AgentConfig(name="oracle") if args.agent == "oracle" else AgentConfig(
            import_path="budget_agent:BudgetShellAgent", model_name="deepseek-flash", override_timeout_sec=1200)
        config = TrialConfig(task=TaskConfig(path=materialized[name]),
            trial_name=f"profile-{index}-{bridge.slug(name)[:24]}-{uuid.uuid4().hex[:10]}",
            trials_dir=trials_dir, agent=agent, environment=EnvironmentConfig(
                type=EnvironmentType.DOCKER, delete=True, extra_docker_compose=[overlay]))
        trial = await Trial.create(config)
        observer = bridge.TrialObserverBridge(trial=trial, options=options, task_label=name)
        sampler = None
        sampler_error = None
        interval = {}
        sampler_dir = root / "profiles" / name
        sampler_dir.parent.mkdir(exist_ok=True)
        stderr = None
        diagnostics = None

        async def start(event):
            nonlocal sampler, stderr, diagnostics
            await observer.agent_start(event)
            target = observer.active.target
            await observer.pause(target)
            observer.active.paused_by_bridge = True
            stderr = (sampler_dir.parent / (name + ".stderr")).open("xb")
            sampler = await asyncio.create_subprocess_exec(str(args.sampler), "--output-dir", str(sampler_dir),
                "--cgroup", str(target.cgroup_directory), "--label", observer.active.run_id,
                "--interval-ms", "100", "--process-interval-ms", "100", "--exit-with-parent",
                *sampler_options(raw.get("diagnostics", {})),
                stdout=asyncio.subprocess.PIPE, stderr=stderr)
            ready = await asyncio.wait_for(sampler.stdout.readline(), 30)
            if ready != b"READY\n":
                raise RuntimeError("Sampler failed READY; inspect retained stderr")
            meta = json.loads((sampler_dir / "load-meta.json").read_text())
            groups = meta.get("cgroups")
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            if meta.get("boot_id") != boot_id or meta.get("label") != observer.active.run_id:
                raise RuntimeError("Sampler boot or run identity mismatch")
            if (not isinstance(groups, list) or len(groups) != 1 or groups[0].get("path") != str(target.cgroup_directory)
                    or groups[0].get("inode") != target.cgroup_id
                    or groups[0].get("device") != target.cgroup_directory.stat().st_dev):
                raise RuntimeError("Sampler cgroup identity mismatch")
            with (sampler_dir / "load-samples.jsonl").open() as stream:
                first_line = stream.readline(1024 * 1024 + 1)
            if len(first_line) > 1024 * 1024 or not first_line.endswith("\n"):
                raise RuntimeError("Sampler READY did not retain a bounded initial sample")
            first_sample = json.loads(first_line)
            if first_sample.get("seq") != 0 or not isinstance(first_sample.get("monotonic_ns"), int):
                raise RuntimeError("Sampler initial sample is malformed")
            diagnostics = Diagnostics(raw.get("diagnostics", {}), sampler_dir.parent / (name + "-diagnostics"),
                                      target.cgroup_directory, observer.active.run_id)
            await asyncio.to_thread(diagnostics.start)
            interval.update({"run_id": observer.active.run_id, "container_id": target.container_id,
                "init_pid": target.init_pid, "cgroup_path": str(target.cgroup_directory),
                "cgroup_inode": target.cgroup_id, "cgroup_device": target.cgroup_directory.stat().st_dev,
                "boot_id": boot_id, "sampler_binding_validated": True,
                "agent_start_ns": time.monotonic_ns()})
            await observer.unpause(target)
            observer.active.paused_by_bridge = False

        async def stop_sampler():
            nonlocal sampler_error
            if sampler is not None and sampler.returncode is None:
                sampler.send_signal(signal.SIGTERM)
                try:
                    await asyncio.wait_for(sampler.wait(), 10)
                except asyncio.TimeoutError:
                    sampler.kill()
                    await sampler.wait()
                    sampler_error = "SAMPLER_SHUTDOWN_TIMEOUT"
            if sampler is not None and sampler.returncode != 0:
                sampler_error = f"SAMPLER_EXIT_{sampler.returncode}"
            if stderr is not None:
                stderr.close()

        async def end(event):
            interval["agent_end_ns"] = time.monotonic_ns()
            deadline = time.monotonic() + 10
            with (sampler_dir / "load-samples.jsonl").open("rb") as samples:
                pending = b""
                final_sample = None
                while time.monotonic() < deadline:
                    pending += samples.read(1024 * 1024)
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        row = json.loads(line)
                        if row.get("monotonic_ns", 0) > interval["agent_end_ns"]:
                            final_sample = row
                    if len(pending) > 1024 * 1024:
                        raise RuntimeError("Sampler row exceeds bound")
                    if final_sample is not None:
                        interval["post_agent_sample_ns"] = final_sample["monotonic_ns"]
                        break
                    if sampler.returncode is not None:
                        raise RuntimeError("Sampler exited without a post-Agent sample")
                    await asyncio.sleep(0.02)
                else:
                    raise RuntimeError("Sampler post-Agent sample timeout")
            await observer.pause(observer.active.target)
            observer.active.paused_by_bridge = True
            if diagnostics is not None:
                await asyncio.to_thread(diagnostics.finish)
            await stop_sampler()
            await observer.unpause(observer.active.target)
            observer.active.paused_by_bridge = False
            await observer.agent_end(event)

        trial.add_hook(TrialEvent.AGENT_START, start)
        trial.add_hook(TrialEvent.AGENT_END, end)
        error = None
        result = None
        try:
            result = await trial.run()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            async def finish_diagnostics():
                if diagnostics is not None:
                    await asyncio.to_thread(diagnostics.finish)
            for label, cleanup in (("diagnostics", finish_diagnostics), ("sampler", stop_sampler), ("observer", observer.cleanup)):
                try:
                    await cleanup()
                except Exception as exc:
                    error = (error + "; " if error else "") + f"{label} cleanup: {type(exc).__name__}: {exc}"
        rewards = result.verifier_result.rewards if result and result.verifier_result else None
        entry = {"task": name, "agent": args.agent, "harbor_rewards": rewards,
            "original_task_directory": str(known[name]), "executed_task_directory": str(materialized[name]),
            "runtime_prebuilt_image_override": image_overrides.get(name),
            "original_task_toml_sha256": hashlib.sha256((known[name] / "task.toml").read_bytes()).hexdigest(),
            "executed_task_toml_sha256": hashlib.sha256((materialized[name] / "task.toml").read_bytes()).hexdigest(),
            "executed_task_checksum": result.task_checksum if result else None,
            "task_reward_passed": bridge.reward_matches(rewards, 1.0),
            "harbor_result": str(trial.paths.result_path), "error": error,
            "harbor_exception": result.exception_info.model_dump(mode="json") if result and result.exception_info else None,
            "observer_completed": observer.completed, "observer_error": observer.failure,
            "profile_directory": str(sampler_dir), "sampler_error": sampler_error, "interval": interval}
        results.append(entry)
        bridge.write_new_json(root / (name + "-summary.json"), entry)
    summary = {"schema_version": 1, "benchmark": "Terminal-Bench", "dataset_selection": selection,
        "selected_tasks": args.task, "agent": args.agent, "harbor_version": version("harbor"),
        "runtime_prebuilt_image_overrides": image_overrides,
        "agent_scope": "REAL_BOUNDED_MODEL_AGENT" if args.agent != "oracle" else "OFFICIAL_ORACLE_HARNESS_CONTROL",
        "performance_scope": "SINGLE_RUN_INTEGRATION_NO_A_B_SLOWDOWN_CLAIM", "tasks": results}
    bridge.write_new_json(root / "campaign-summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 1 if any(row["error"] or row["observer_error"] or row["sampler_error"] or row["harbor_exception"]
                   or (args.agent == "oracle" and not row["task_reward_passed"]) for row in results) else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--bridge-config", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--tasks-dir", type=Path, required=True)
    parser.add_argument("--task", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sampler", type=Path, required=True)
    parser.add_argument("--agent", choices=("oracle", "budget-shell"), default="oracle")
    parser.add_argument("--prebuilt-images", type=Path, help="Explicit task->agent/verifier SHA-256 image IDs; creates declared task.toml runtime copies")
    raise SystemExit(asyncio.run(campaign(parser.parse_args())))
