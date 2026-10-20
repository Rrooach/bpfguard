#!/usr/bin/env python3
"""Run genuine Harbor Oracle controls with per-tool, SIGSTOP-gated timelines.

This is not a model-solving benchmark.  The official Oracle and verifier are
unchanged; only environment.exec transport is replaced by equivalent Docker
Exec API calls, so the actual container PID can be bound before user code runs.
No API key or paid model service is used.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import http.client
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import socket
import struct
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote


MAX_EXEC_OUTPUT = 64 * 1024 * 1024
SEARCH_PROBE_QUERIES = 64
SEARCH_PROBE_COMMAND = (
    "for ((i=0;i<64;i++)); do LC_ALL=C grep -R -n -F -- 'import' /app; "
    "rc=$?; if ((rc>1)); then exit $rc; fi; done"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value, *, replace=False) -> None:
    """Exclusive initial write, atomic later updates; never truncate evidence."""
    raw = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
    target = path.with_name(path.name + ".new-" + uuid.uuid4().hex) if replace else path
    with target.open("xb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    if replace:
        os.replace(target, path)


def parse_stat(raw: str) -> dict:
    """The comm field may contain spaces and closing parentheses."""
    left, right = raw.find("("), raw.rfind(")")
    if left < 1 or right <= left:
        raise ValueError("malformed /proc stat")
    tail = raw[right + 2:].split()
    if len(tail) < 20:
        raise ValueError("short /proc stat")
    return {"tid": int(raw[:left].strip()), "state": tail[0], "start_ticks": int(tail[19])}


def parse_cgroup(raw: str) -> str:
    paths = [line.split(":", 2)[2] for line in raw.splitlines() if line.startswith("0::")]
    if len(paths) != 1 or not paths[0].startswith("/") or ".." in Path(paths[0]).parts:
        raise ValueError("missing or malformed unified cgroup identity")
    return paths[0]


def proc_identity(pid):
    return parse_stat(Path("/proc", str(pid), "stat").read_text())


def proc_cgroup(pid):
    return parse_cgroup(Path("/proc", str(pid), "cgroup").read_text())


def cgroup_inode(path):
    return Path("/sys/fs/cgroup", path.lstrip("/")).stat().st_ino


def proc_affinity(pid):
    return sorted(os.sched_getaffinity(pid))


def frozen_baseline_threads(cgroup_directory, cgroup_mount="/sys/fs/cgroup"):
    """Explicit pre-tool identities, not a blanket exemption for unknown PIDs."""
    threads = []
    root = Path(cgroup_directory)
    if "frozen 1" not in (root / "cgroup.events").read_text().splitlines():
        raise ValueError("baseline identities require a confirmed frozen container")
    for member_file in sorted(root.rglob("cgroup.threads")):
        membership = member_file.parent
        for text in member_file.read_text().split():
            identity = proc_identity(int(text))
            actual = proc_cgroup(identity["tid"])
            if (Path(cgroup_mount) / actual.lstrip("/")).resolve() != membership.resolve():
                raise ValueError("baseline thread cgroup changed while frozen")
            threads.append({"tid": identity["tid"], "start_ticks": identity["start_ticks"],
                            "clock_ticks": os.sysconf("SC_CLK_TCK"), "cgroup_id": membership.stat().st_ino})
    if len({row["tid"] for row in threads}) != len(threads) or not threads:
        raise ValueError("ambiguous or empty frozen container baseline")
    return sorted(threads, key=lambda row: row["tid"])


def demultiplex(raw: bytes) -> tuple[str, str]:
    """Decode Docker's non-TTY stdout/stderr frames, rejecting truncation."""
    outputs = {1: bytearray(), 2: bytearray()}
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 8:
            raise ValueError("truncated Docker stream frame header")
        stream, padding, length = raw[offset], raw[offset + 1:offset + 4], struct.unpack_from(">I", raw, offset + 4)[0]
        offset += 8
        if stream not in outputs or padding != b"\0\0\0" or offset + length > len(raw):
            raise ValueError("invalid or truncated Docker stream frame")
        outputs[stream].extend(raw[offset:offset + length])
        offset += length
    return tuple(outputs[index].decode("utf-8", errors="replace") for index in (1, 2))


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = str(socket_path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class DockerAPI:
    def __init__(self, socket_path="/var/run/docker.sock"):
        self.socket_path = socket_path

    def request(self, method, path, data=None, *, timeout=30, raw=False):
        connection = UnixHTTPConnection(self.socket_path, timeout)
        payload = None if data is None else json.dumps(data).encode()
        try:
            connection.request(method, path, body=payload, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read(MAX_EXEC_OUTPUT + 1)
            if len(body) > MAX_EXEC_OUTPUT:
                raise ValueError("Docker response exceeds the declared output budget")
            if response.status not in (200, 201, 204):
                raise RuntimeError("Docker API {} {} returned {}: {}".format(
                    method, path, response.status, body[:1000].decode(errors="replace")))
            return body if raw else json.loads(body) if body else None
        finally:
            connection.close()


class GatedExec:
    """One real Docker Exec root per tool, never attribution by timestamp alone."""
    def __init__(self, docker, container_id, cgroup_path, manifest, directory, result_factory=None, environment=None,
                 agent_id=None, tool_prefix="exec", kind="OFFICIAL_ORACLE_EXEC"):
        self.docker = docker
        self.container_id = container_id
        self.cgroup_path = cgroup_path
        self.manifest = manifest
        self.directory = Path(directory)
        self.result_factory = result_factory or SimpleNamespace
        self.environment = environment
        self.agent_id = agent_id
        self.tool_prefix = tool_prefix
        self.kind = kind
        self.sequence = 0

    def persist(self):
        write_json(self.directory / "manifest.json", self.manifest, replace=(self.directory / "manifest.json").exists())

    def journal(self, event):
        with (self.directory / "tool-spans.jsonl").open("ab") as output:
            output.write((json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n").encode())
            output.flush()
            os.fsync(output.fileno())

    async def __call__(self, command: str, cwd=None, env=None, timeout_sec=None, user=None, **kwargs):
        if kwargs:
            raise ValueError("unsupported Harbor exec options: " + ",".join(sorted(kwargs)))
        if not isinstance(command, str) or not command or "\0" in command:
            raise ValueError("exec requires a nonempty, NUL-free shell command")
        if env is not None and (not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items())):
            raise ValueError("environment must map strings to strings")
        self.sequence += 1
        tool_id = "{}-{:04d}".format(self.tool_prefix, self.sequence)
        invocation_ns = time.monotonic_ns()
        timeout = float(timeout_sec or 600)
        if timeout <= 0 or timeout > 86400:
            raise ValueError("exec timeout must be in (0,86400]")
        # Match Harbor Docker.exec: its actual shell, cwd and merged environment.
        # A noninteractive POSIX sh gate avoids sourcing BASH_ENV before STOP;
        # the original inner bash still receives and applies its environment.
        shell = ["/bin/bash", "-lc", command]
        if self.environment is not None:
            cwd = cwd or self.environment.task_env_config.workdir
            env = self.environment._merge_env(env)
            user = self.environment._resolve_user(user)
            shell = self.environment._platform.exec_shell_args(command)
        request = {"AttachStdout": True, "AttachStderr": True, "Tty": False,
                   "Cmd": ["/bin/sh", "-c", "kill -STOP $$ || exit 125; exec " + shlex.join(shell)]}
        if cwd is not None:
            request["WorkingDir"] = str(cwd)
        if env:
            request["Env"] = [key + "=" + value for key, value in sorted(env.items())]
        if user is not None:
            request["User"] = str(user)
        created = await asyncio.to_thread(self.docker.request, "POST", "/containers/" + quote(self.container_id) + "/exec", request)
        exec_id = created.get("Id")
        if not isinstance(exec_id, str) or re.fullmatch(r"[0-9a-f]{64}", exec_id) is None:
            raise ValueError("Docker did not return a full Exec ID")
        output_task = asyncio.create_task(asyncio.to_thread(self.docker.request, "POST", "/exec/" + exec_id + "/start",
                                         {"Detach": False, "Tty": False}, timeout=timeout + 35, raw=True))
        pidfd = None
        owned_root = False
        entry = None
        sampler = getattr(self, "resource_sampler", None)
        sample_name = None
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                inspected = await asyncio.to_thread(self.docker.request, "GET", "/exec/" + exec_id + "/json")
                pid = inspected.get("Pid", 0)
                if inspected.get("Running") is True and type(pid) is int and pid > 0:
                    try:
                        identity = proc_identity(pid)
                    except FileNotFoundError:
                        identity = None
                    if identity and identity["state"] in ("T", "t"):
                        break
                if output_task.done():
                    await output_task
                    raise RuntimeError("Docker Exec exited before its stopped root was bound")
                await asyncio.sleep(0.005)
            else:
                raise TimeoutError("Docker Exec root never reached the SIGSTOP gate")
            pidfd = os.pidfd_open(pid)
            if proc_identity(pid) != identity:
                raise ValueError("Docker Exec root identity changed before release")
            owned_root = True
            actual_cgroup = proc_cgroup(pid)
            if actual_cgroup != self.cgroup_path and not actual_cgroup.startswith(self.cgroup_path + "/"):
                raise ValueError("Docker Exec root is outside the registered container cgroup")
            entry = {"agent_id": self.agent_id or self.manifest["agent_id"], "task_id": self.manifest["task_id"],
                     "tool_call_id": tool_id, "command": command, "cwd": cwd, "docker_exec_id": exec_id,
                     "begin_ns": None, "end_ns": None, "enrolled_ns": time.monotonic_ns(),
                     "invocation_ns": invocation_ns, "tool_kind": self.kind,
                     "allowed_cpus": proc_affinity(pid),
                     "root": {"tid": pid, "start_ticks": identity["start_ticks"], "clock_ticks": os.sysconf("SC_CLK_TCK")},
                     "cgroup_id": cgroup_inode(actual_cgroup),
                     "root_binding": "DOCKER_EXEC_INSPECT_PID_AND_STOPPED_PROC_IDENTITY", "result": None}
            self.manifest["tools"].append(entry)
            if sampler is not None:
                target_name = "docker-tool:" + tool_id
                sampler.register(target_name, pid=pid, role="TOOL_ROOT", tool_call_id=tool_id)
                sample_name = target_name
                # Docker Exec roots share their container's cgroup. Keep that
                # gauge as an Agent/container series, never a per-tool peak.
                container_sample = "docker-container:" + self.container_id
                if not getattr(self, "_resource_container_registered", False):
                    sampler.register(container_sample, role="AGENT_CONTAINER",
                        cgroup=Path("/sys/fs/cgroup") / actual_cgroup.lstrip("/"),
                        cgroup_scope="SHARED_CONTAINER_CGROUP_NOT_PER_TOOL")
                    self._resource_container_registered = True
            self.journal({"event": "TOOL_ENROLLED", **entry})
            self.persist()
            # All enrollment fsync is outside the tool clock.  A timestamp
            # before fsync would mislabel recorder overhead as a stopped tool.
            entry["begin_ns"] = time.monotonic_ns()
            signal.pidfd_send_signal(pidfd, signal.SIGCONT)
            self.journal({"event": "TOOL_START", **entry})
            raw = await asyncio.wait_for(asyncio.shield(output_task), timeout)
            inspected = await asyncio.to_thread(self.docker.request, "GET", "/exec/" + exec_id + "/json")
            if inspected.get("Running") is not False or type(inspected.get("ExitCode")) is not int:
                raise ValueError("Docker Exec did not report a final exit code")
            stdout, stderr = demultiplex(raw)
            entry.update(end_ns=time.monotonic_ns(), result={"return_code": inspected["ExitCode"],
                         "stdout_bytes": len(stdout.encode()), "stderr_bytes": len(stderr.encode())})
            self.journal({"event": "TOOL_END", **entry})
            self.persist()
            return self.result_factory(stdout=stdout, stderr=stderr, return_code=inspected["ExitCode"])
        except BaseException as error:
            if pidfd is not None and owned_root:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if entry is not None:
                entry.update(end_ns=time.monotonic_ns(), result={"error": type(error).__name__ + ": " + str(error)})
                self.journal({"event": "TOOL_END", **entry})
                self.persist()
            if not output_task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(output_task), 5)
                except BaseException:
                    pass
            raise
        finally:
            if sampler is not None and sample_name is not None:
                sampler.finish(sample_name)
            if pidfd is not None:
                os.close(pidfd)


def load_bridge(path):
    spec = importlib.util.spec_from_file_location("timeline_terminal_bridge", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def assess_timeline(report, manifest):
    """Goal check AFTER independent raw replay, not a replacement for replay.

    A passing reference solution or a decodable WAL alone is insufficient.
    All requested tool roots must be bound, their completion paths accounted,
    and their observed descendants must have exited at the frozen boundary.
    """
    issues, summaries = [], []
    if report.get("health", {}).get("status") != "COMPLETE_FOR_SELECTED_HOOKS":
        issues.append("SELECTED_HOOK_CAPTURE_INCOMPLETE")
    if report.get("critical_path", {}).get("status") != "RECONSTRUCTED_WITHIN_SELECTED_MODEL":
        issues.append("COMPLETION_PATH_NOT_RECONSTRUCTED")
    declared = {row["tool_call_id"]: row for row in manifest.get("tools", [])}
    tools = {row["tool_call_id"]: row for row in report.get("tools", [])}
    paths = {row["tool_call_id"]: row for row in report.get("critical_path", {}).get("tools", [])}
    if not declared or set(declared) != set(tools) or set(declared) != set(paths):
        issues.append("DECLARED_TOOL_SET_NOT_RECONSTRUCTED")
    closure = manifest.get("closure") or {}
    if closure.get("frozen") is not True or closure.get("nonbaseline_thread_candidates") != []:
        issues.append("FROZEN_TOOL_TREE_CLOSURE_NOT_ESTABLISHED")
    serious = {"COLLECTION_GAP", "CPU_SEQUENCE_GAP_OR_DUPLICATE", "MISSING_CPU_SEQUENCE", "UNRESOLVED_TOOL_ROOT",
               "ORPHAN_SYSCALL_EXIT", "SYSCALL_NUMBER_MISMATCH", "DUPLICATE_SYSCALL_ENTRY", "CONFLICTING_PARENT",
               "UNRESOLVED_TASK_IDENTITY", "UNPAIRED_SYSCALL_ENTRY"}
    for finding in report.get("findings", []):
        if finding.get("kind") in serious:
            issues.append("REPLAY_FINDING:" + finding["kind"])
    for tool_id, original in declared.items():
        tool, path = tools.get(tool_id, {}), paths.get(tool_id, {})
        owned = [row for row in report.get("threads", []) if row.get("tool_call_id") == tool_id]
        if (tool.get("association") != "RUNTIME_GATE_AND_KERNEL_LIFETIME" or not owned
                or any(tool.get(key) != original.get(key) for key in ("agent_id", "task_id", "root"))):
            issues.append("TOOL_ROOT_OR_OWNER_NOT_BOUND:" + tool_id)
        if any(type(row.get("exit_ns")) is not int or row["exit_ns"] > manifest["end_ns"] for row in owned):
            issues.append("TOOL_DESCENDANT_EXIT_NOT_OBSERVED:" + tool_id)
        # sched_process_exit precedes exit_mm/exit_files and can itself be
        # followed by preemption or blocking. Only the raw, non-preempting
        # TASK_DEAD switch proves that an observed task finished scheduling.
        if any(type(row.get("terminal_switch_ns")) is not int
                or row["terminal_switch_ns"] > manifest["end_ns"]
                or (type(row.get("exit_ns")) is int and row["terminal_switch_ns"] < row["exit_ns"])
                for row in owned):
            issues.append("TOOL_DESCENDANT_TERMINAL_SWITCH_NOT_OBSERVED:" + tool_id)
        if path.get("unknown_ns") != 0 or path.get("status") != "RECONSTRUCTED_WITHIN_SELECTED_MODEL":
            issues.append("TOOL_COMPLETION_PATH_HAS_UNKNOWN:" + tool_id)
        objects, source_bytes, source_calls = set(), 0, 0
        for thread in owned:
            for call in thread.get("calls", []):
                for file in call.get("files", []):
                    returned = (file.get("read") or {}).get("returned_bytes")
                    if (str(file.get("path") or "").startswith("/app/") and type(returned) is int and returned > 0):
                        source_bytes += returned
                        source_calls += 1
                        objects.add(tuple(file.get(key) for key in ("mount_id", "device", "inode", "generation")))
        is_probe = original.get("tool_kind") == "LABELED_READONLY_SEARCH_CALIBRATION"
        if is_probe and (not objects or not source_bytes or not source_calls):
            issues.append("TASK_SOURCE_FILE_READ_NOT_RESOLVED:" + tool_id)
        # Oracle chmod may have no children; the explicit search probe always
        # forks grep and must demonstrate namespace-correct wait dependencies.
        if is_probe and not path.get("dependency_edges"):
            issues.append("CONTAINER_SEARCH_WAIT_DEPENDENCY_NOT_ESTABLISHED:" + tool_id)
        if is_probe:
            # This calibration has exactly one shell plus 64 sequential grep
            # children. A few visible reads or one wake edge must not pass a
            # partially reconstructed 64-query tool. These are workload
            # invariants, not assumptions about arbitrary user commands.
            grep_threads = [row for row in owned if row.get("comm") == "grep"]
            edge_counts = {basis: sum(edge.get("basis") == basis for edge in path.get("dependency_edges", []))
                           for basis in ("BACKWARD_WAIT4_RESULT_AND_KERNEL_WAKER_AND_CHILD_EXIT", "KERNEL_FORK_ORIGIN_PREFIX")}
            if (original.get("command") != SEARCH_PROBE_COMMAND
                    or len(owned) != SEARCH_PROBE_QUERIES + 1 or len(grep_threads) != SEARCH_PROBE_QUERIES
                    or any(row.get("parent_key") != tool.get("root_key") for row in grep_threads)
                    or any(row.get("agent_id") != original.get("agent_id")
                           or row.get("task_id") != original.get("task_id") for row in owned)
                    or any(count != SEARCH_PROBE_QUERIES for count in edge_counts.values())):
                issues.append("CONCURRENT_SEARCH_WORKLOAD_LINEAGE_NOT_FULLY_RECONSTRUCTED:" + tool_id)
        summaries.append({"tool_call_id": tool_id, "agent_id": original["agent_id"], "thread_count": len(owned),
                          "wall_ns": path.get("wall_ns"), "completion_path_state_ns": path.get("state_totals_ns"),
                          "completion_dependency_edges": len(path.get("dependency_edges", [])),
                          "source_unique_files_read": len(objects), "source_returned_bytes": source_bytes,
                          "source_positive_vfs_read_calls": source_calls,
                          "metric_scope": "SOURCE_READS_ARE_SELECTED_VFS_READ_PATHS; STATE_NS_IS_ONE_COMPLETION_PATH_NOT_SUM_OF_THREADS"})
    return {"run_id": manifest.get("run_id"), "task_id": manifest.get("task_id"),
            "status": "FAIL" if issues else "PASS_WITHIN_SELECTED_MODEL", "issues": sorted(set(issues)),
            "tools": summaries, "scope": "COOPERATIVE_GATED_TOOLS_NO_GPU_NO_GENERAL_CAUSAL_OR_COUNTERFACTUAL_PROOF"}


async def campaign(args, *, agent_config=None, agent_identity=None, paid_call_info=None):
    """Use reviewed public Harbor hooks; preserve official Oracle and tests."""
    from importlib.metadata import version
    from harbor.models.environment_type import EnvironmentType
    from harbor.models.trial.config import AgentConfig, EnvironmentConfig, TaskConfig, TrialConfig
    from harbor.trial.hooks import TrialEvent
    from harbor.trial.trial import Trial
    from harbor.environments.base import ExecResult

    bridge = load_bridge(args.bridge)
    if (agent_config is None) != (agent_identity is None):
        raise ValueError("an explicit non-Oracle agent requires its explicit identity")
    if agent_identity is not None:
        if (not isinstance(agent_identity, dict) or agent_identity.get("mode") != "MODEL_AGENT"
                or not all(isinstance(agent_identity.get(key), str) and agent_identity[key]
                           for key in ("agent_id", "agent_scope", "budget_label", "model"))
                or args.search_probe or not callable(paid_call_info)):
            raise ValueError("model identity, public-task-only mode and paid-call accounting are required")
    if os.geteuid() != 0 or version("harbor") != bridge.SUPPORTED_HARBOR_VERSION:
        raise RuntimeError("Requires root on the target Linux and reviewed Harbor 0.23.0")
    if args.ring_bytes < 4096 or args.ring_bytes > 256 * 1024 * 1024 or args.ring_bytes & (args.ring_bytes - 1):
        raise ValueError("ring-bytes must be a power of two between 4 KiB and 256 MiB")
    collector_cpus = None
    if args.collector_cpus:
        if re.fullmatch(r"[0-9]+(?:,[0-9]+)*", args.collector_cpus) is None:
            raise ValueError("collector-cpus must be a comma-separated CPU list")
        collector_cpus = {int(cpu) for cpu in args.collector_cpus.split(",")}
        if not collector_cpus or not collector_cpus <= os.sched_getaffinity(0):
            raise ValueError("collector CPUs must be in the runner's existing CPU affinity")
    if args.output.exists():
        raise ValueError("output must not exist")
    args.output.mkdir(mode=0o700, parents=True)
    pinned = args.output / "pinned-artifacts"
    pinned.mkdir(mode=0o700)
    collector_source, object_source = args.collector.resolve(strict=True), args.object.resolve(strict=True)
    collector_identity = {"sha256": sha256(collector_source), "size_bytes": collector_source.stat().st_size}
    object_identity = {"sha256": sha256(object_source), "size_bytes": object_source.stat().st_size}
    collector_binary, bpf_object = pinned / "collect", pinned / "execution_timeline.bpf.o"
    shutil.copy2(collector_source, collector_binary)
    shutil.copy2(object_source, bpf_object)
    if (collector_identity != {"sha256": sha256(collector_binary), "size_bytes": collector_binary.stat().st_size}
            or object_identity != {"sha256": sha256(bpf_object), "size_bytes": bpf_object.stat().st_size}):
        raise ValueError("artifact changed while making this campaign's immutable copy")
    original = json.loads(args.selection.read_text())
    all_tasks = [args.tasks_dir / row["directory"] for row in original["tasks"]]
    selection = bridge.validate_selection_manifest(args.selection, args.selection_sha256, all_tasks)
    known = {path.name: path for path in all_tasks}
    if len(set(args.task)) != len(args.task) or any(task not in known for task in args.task):
        raise ValueError("tasks must be unique members of the pinned original selection")
    overrides = json.loads(args.prebuilt_images.read_text())
    docker = DockerAPI(args.docker_socket)
    rows = []
    for index, task in enumerate(args.task):
        copied = args.output / "materialized-inputs" / task
        shutil.copytree(known[task], copied)
        text = (copied / "task.toml").read_text()
        if "docker_image" in text or "[verifier.environment]" in text:
            raise ValueError("refusing to overwrite existing image configuration")
        images = overrides[task]
        for kind in ("agent", "verifier"):
            image = images[kind]
            if re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
                raise ValueError("prebuilt image must use an exact local SHA-256 ID")
            await asyncio.to_thread(docker.request, "GET", "/images/" + quote(image, safe="") + "/json")
        text = text.replace("[environment]\n", "[environment]\ndocker_image = " + json.dumps(images["agent"]) + "\n", 1)
        text += "\n[verifier.environment]\ndocker_image = " + json.dumps(images["verifier"]) + "\n"
        (copied / "task.toml").write_text(text)
        trial = await Trial.create(TrialConfig(task=TaskConfig(path=copied),
            trial_name="timeline-{}-{}-{}".format(index, task, uuid.uuid4().hex[:10]), trials_dir=args.output / "harbor-trials",
            agent=AgentConfig(name="oracle") if agent_config is None else agent_config,
            environment=EnvironmentConfig(type=EnvironmentType.DOCKER, delete=True)))
        finder = bridge.TrialObserverBridge(trial=trial, options=SimpleNamespace(docker_timeout=30), task_label=task)
        manifest = {"schema_version": 1, "run_id": "terminal-timeline-" + uuid.uuid4().hex,
                    "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                    "agent_id": "official-oracle:" + task, "task_id": "terminal-bench/" + task,
                    "agent_scope": "OFFICIAL_ORACLE_HARNESS_CONTROL_NOT_MODEL_SCORE" if not args.search_probe else
                        "OFFICIAL_ORACLE_WITH_SEPARATELY_LABELED_READONLY_CONCURRENT_SEARCH_CALIBRATION",
                    "begin_ns": None, "end_ns": None, "tools": [], "artifacts": {},
                    "capture_directory": "capture", "collector_binary": str(collector_binary.resolve()),
                    "collector_identity": collector_identity, "bpf_object": str(bpf_object.resolve()),
                    "bpf_object_identity": object_identity,
                    "capture_options": {"ring_bytes": args.ring_bytes, "kernel_stacks": args.kernel_stacks,
                                        "collector_requested_cpus": sorted(collector_cpus) if collector_cpus else None,
                                        "tool_cpu_supply_changed_by_adapter": False}}
        if agent_identity is not None:
            manifest.update(agent_identity)
        directory = args.output / "timelines" / task
        directory.mkdir(mode=0o700, parents=True)
        collector = None
        stderr = None
        original_exec = None
        target = None
        probe_check = None
        collector_error = None
        async def start(_event):
            nonlocal collector, stderr, original_exec, target, probe_check
            target = await finder.discover_target()
            await finder.pause(target)
            try:
                stderr = (directory / "collector.stderr").open("xb")
                collector = await asyncio.create_subprocess_exec(str(collector_binary),
                    "--object", str(bpf_object), "--cgroup", str(target.cgroup_directory),
                    "--output-dir", str(directory / "capture"), "--ring-bytes", str(args.ring_bytes),
                    *( ["--kernel-stacks"] if args.kernel_stacks else [] ),
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=stderr)
                if collector_cpus is not None:
                    os.sched_setaffinity(collector.pid, collector_cpus)
                manifest["capture_options"]["collector_actual_cpus"] = proc_affinity(collector.pid)
                ready_line = await asyncio.wait_for(collector.stdout.readline(), 30)
                ready = json.loads(ready_line)
                if (ready.get("status") != "READY" or ready.get("boot_id") != manifest["boot_id"]
                        or ready.get("root_cgroup_id") != target.cgroup_id or ready.get("schema_version") != 1
                        or ready.get("clock") != "CLOCK_MONOTONIC"):
                    raise RuntimeError("timeline collector READY boot/cgroup/ABI/clock binding failed")
                shutil.copyfile("/proc/kallsyms", directory / "kallsyms.txt")
                write_json(directory / "ready.json", ready)
                baseline = frozen_baseline_threads(target.cgroup_directory)
                write_json(directory / "baseline-threads.json", baseline)
                manifest.update(begin_ns=time.monotonic_ns(), cgroup_root=str(target.cgroup_directory),
                    cgroup_id=target.cgroup_id, container_id=target.container_id,
                    namespace={key: Path("/proc", str(target.init_pid), "ns", key).stat().st_ino
                               for key in ("mnt", "pid", "user", "net")}, collector_ready=ready,
                    baseline_threads=baseline)
                write_json(directory / "manifest.json", manifest)
                original_exec = trial.agent_environment.exec
                trial.agent_environment.exec = GatedExec(docker, target.container_id, target.cgroup_path,
                                                          manifest, directory, ExecResult, trial.agent_environment)
            finally:
                await finder.unpause(target)
            if args.search_probe:
                # A separate, explicit calibration on real task input files.
                # It is not attributed to an actual model or hidden inside an
                # official Oracle score. Two roots share one container cgroup
                # so ownership must follow the root lifetime + fork lineage.
                command = SEARCH_PROBE_COMMAND
                probes = [GatedExec(docker, target.container_id, target.cgroup_path, manifest, directory, ExecResult,
                                   trial.agent_environment, agent_id="search-calibration-agent-" + str(number),
                                   tool_prefix="search-probe-" + str(number), kind="LABELED_READONLY_SEARCH_CALIBRATION")
                          for number in (1, 2)]
                outputs = await asyncio.gather(*(probe(command=command, timeout_sec=120) for probe in probes))
                spans = [row for row in manifest["tools"] if row["tool_kind"] == "LABELED_READONLY_SEARCH_CALIBRATION"]
                probe_check = {"scope": "HARNESS_INJECTED_CALIBRATION_NOT_ORIGINAL_AGENT_WORK_OR_MODEL_SCORE",
                    "command": command, "tool_call_ids": [row["tool_call_id"] for row in spans],
                    "output_identical": outputs[0].stdout == outputs[1].stdout and outputs[0].stderr == outputs[1].stderr,
                    "return_codes": [row.return_code for row in outputs],
                    "overlap_ns": max(0, min(row["end_ns"] for row in spans) - max(row["begin_ns"] for row in spans)),
                    "outputs": [{"stdout_sha256": hashlib.sha256((row.stdout or "").encode()).hexdigest(),
                                 "stdout_bytes": len((row.stdout or "").encode()),
                                 "stderr_sha256": hashlib.sha256((row.stderr or "").encode()).hexdigest(),
                                 "stderr_bytes": len((row.stderr or "").encode())} for row in outputs]}
                write_json(directory / "search-probe-check.json", probe_check)
                if not probe_check["output_identical"] or probe_check["return_codes"] != [0, 0] or not probe_check["overlap_ns"]:
                    raise RuntimeError("read-only concurrent search calibration did not establish equal work and overlapping tool roots")

        async def finish(_event=None):
            nonlocal original_exec, collector_error
            if collector is None or collector.returncode is not None:
                return
            if original_exec is not None:
                trial.agent_environment.exec = original_exec
                original_exec = None
            paused = False
            try:
                await finder.pause(target)
                paused = True
                closure = frozen_baseline_threads(target.cgroup_directory)
                baseline_keys = {(row["tid"], row["start_ticks"]) for row in manifest["baseline_threads"]}
                candidates = [row for row in closure if (row["tid"], row["start_ticks"]) not in baseline_keys]
                manifest["closure"] = {"frozen": True, "monotonic_ns": time.monotonic_ns(), "threads": closure,
                                       "nonbaseline_thread_candidates": candidates,
                                       "meaning": "NONBASELINE_SURVIVORS_REQUIRE_KERNEL_LINEAGE_REVIEW_NOT_AUTOMATIC_LEAK_VERDICT"}
                write_json(directory / "closure-threads.json", manifest["closure"])
                manifest["end_ns"] = time.monotonic_ns()
                collector.stdin.write(b"STOP\n")
                await collector.stdin.drain()
                await asyncio.wait_for(collector.wait(), 30)
                if candidates:
                    collector_error = "NONBASELINE_THREADS_REMAIN_AT_DECLARED_END"
            except Exception as exc:
                collector_error = type(exc).__name__ + ": " + str(exc)
                manifest["end_ns"] = time.monotonic_ns()
                if collector.returncode is None:
                    collector.terminate()
                    try:
                        await asyncio.wait_for(collector.wait(), 5)
                    except asyncio.TimeoutError:
                        collector.kill()
                        await collector.wait()
            finally:
                if paused:
                    await finder.unpause(target)
                if stderr is not None:
                    stderr.close()
            manifest["collector_return_code"] = collector.returncode
            files = list((directory / "capture").iterdir()) + [directory / name for name in
                    ("kallsyms.txt", "tool-spans.jsonl", "ready.json", "collector.stderr", "baseline-threads.json",
                     "closure-threads.json", "search-probe-check.json")]
            for path in sorted(files):
                if path.is_file():
                    manifest["artifacts"][str(path.relative_to(directory))] = {"sha256": sha256(path), "size_bytes": path.stat().st_size}
            write_json(directory / "manifest.json", manifest, replace=True)
            if collector.returncode != 0:
                # An Observer failure is not an Oracle or official-test
                # failure. Let Harbor score the unchanged result, but retain
                # this independent failure and return nonzero for the campaign.
                collector_error = (collector_error + "; " if collector_error else "") + "COLLECTOR_EXIT_" + str(collector.returncode)

        trial.add_hook(TrialEvent.AGENT_START, start)
        trial.add_hook(TrialEvent.AGENT_END, finish)
        error = None
        result = None
        try:
            result = await trial.run()
        except Exception as exc:
            error = type(exc).__name__ + ": " + str(exc)
        finally:
            try:
                await finish()
            except Exception as exc:
                error = (error + "; " if error else "") + "finish: " + type(exc).__name__ + ": " + str(exc)
        rewards = result.verifier_result.rewards if result and result.verifier_result else None
        replay_error = None
        timeline_check = None
        if error is None and not args.capture_only:
            try:
                process = await asyncio.create_subprocess_exec(sys.executable, str(args.replay), "--run-dir", str(directory),
                    "--output", str(directory / "report.json"), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, replay_stderr = await asyncio.wait_for(process.communicate(), 120)
                if process.returncode != 0:
                    raise RuntimeError(replay_stderr.decode(errors="replace")[-4000:])
                timeline_check = assess_timeline(json.loads((directory / "report.json").read_text()), manifest)
                write_json(directory / "timeline-acceptance.json", timeline_check)
                process = await asyncio.create_subprocess_exec(sys.executable, str(args.renderer), "--report", str(directory / "report.json"),
                    "--output", str(directory / "timeline.html"), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, replay_stderr = await asyncio.wait_for(process.communicate(), 120)
                if process.returncode != 0:
                    raise RuntimeError(replay_stderr.decode(errors="replace")[-4000:])
            except Exception as exc:
                replay_error = type(exc).__name__ + ": " + str(exc)
        row = {"task": task, "harbor_rewards": rewards, "task_reward_passed": bridge.reward_matches(rewards, 1.0),
               "error": error, "harbor_exception": result.exception_info.model_dump(mode="json") if result and result.exception_info else None,
               "harbor_result": str(trial.paths.result_path), "timeline_directory": str(directory),
               "tool_count": len(manifest["tools"]), "replay_error": replay_error,
               "timeline_check": timeline_check,
               "collector_error": collector_error,
               "timeline_acceptance": "CAPTURE_INCOMPLETE" if collector_error else
                    "PENDING_INDEPENDENT_REPLAY" if args.capture_only else
                    "REPLAY_FAILED" if replay_error else timeline_check["status"] if timeline_check else "NOT_REPLAYED",
               "search_probe": probe_check,
               "original_task_toml_sha256": sha256(known[task] / "task.toml"),
               "executed_task_toml_sha256": sha256(copied / "task.toml"), "prebuilt_images": images}
        write_json(args.output / (task + "-summary.json"), row)
        rows.append(row)
    summary = {"schema_version": 1, "benchmark": "Terminal-Bench", "dataset_selection": selection,
               "agent_scope": (agent_identity["agent_scope"] if agent_identity is not None else
                    "OFFICIAL_ORACLE_HARNESS_CONTROL_NOT_MODEL_SCORE" if not args.search_probe else
                    "OFFICIAL_ORACLE_WITH_SEPARATELY_LABELED_READONLY_CONCURRENT_SEARCH_CALIBRATION"), "paid_api_calls": 0,
               "coverage_scope": "GATED_DOCKER_EXEC_ROOT_AND_OBSERVED_DESCENDANTS_NO_GPU",
               "collector": {"path": str(collector_binary), "source": str(collector_source), **collector_identity},
               "bpf_object": {"path": str(bpf_object), "source": str(object_source), **object_identity}, "tasks": rows}
    if agent_identity is not None:
        accounting = paid_call_info()
        if (not isinstance(accounting, dict) or accounting.get("paid_api_calls") is not None
                or type(accounting.get("client_request_attempts")) is not int or accounting["client_request_attempts"] < 0):
            raise ValueError("model client-attempt accounting and ledger-only charge authority are required")
        summary.update(mode="MODEL_AGENT", model_identity=agent_identity, model_accounting=accounting,
                       paid_api_calls=accounting["paid_api_calls"])
    write_json(args.output / "campaign-summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return int(any(row["error"] or row["collector_error"] or row["replay_error"] or row["harbor_exception"]
                   or (row["timeline_check"] is not None and row["timeline_check"]["status"] != "PASS_WITHIN_SELECTED_MODEL")
                   or not row["task_reward_passed"] for row in rows))


def main():
    if sys.argv[1:2] == ["check"]:
        from replay import verify_run
        check_parser = argparse.ArgumentParser(description="Independently replay a Terminal timeline, then check the requested attribution/wait/closure goal.")
        check_parser.add_argument("--run-dir", type=Path, required=True)
        check_parser.add_argument("--collector", type=Path)
        check_parser.add_argument("--expected-manifest-sha256")
        check_parser.add_argument("--output", type=Path, required=True)
        options = check_parser.parse_args(sys.argv[2:])
        report = verify_run(options.run_dir, options.collector, options.expected_manifest_sha256)
        result = assess_timeline(report, json.loads((options.run_dir / "manifest.json").read_text()))
        write_json(options.output, result)
        print(json.dumps(result, sort_keys=True))
        return int(result["status"] != "PASS_WITHIN_SELECTED_MODEL")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--object", type=Path, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--tasks-dir", type=Path, required=True)
    parser.add_argument("--prebuilt-images", type=Path, required=True)
    parser.add_argument("--task", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--docker-socket", default="/var/run/docker.sock")
    parser.add_argument("--kernel-stacks", action="store_true")
    parser.add_argument("--search-probe", action="store_true",
                        help="Explicitly inject two concurrent, read-only grep tools before Oracle; separate ownership calibration, not original benchmark workload")
    parser.add_argument("--capture-only", action="store_true",
                        help="Retain official rewards and raw capture; explicitly leave independent replay and timeline acceptance pending")
    parser.add_argument("--ring-bytes", type=int, default=64 * 1024 * 1024,
                        help="Bounded native ring buffer, default 64 MiB; actual configuration is retained")
    parser.add_argument("--collector-cpus",
                        help="Optional collector-only CPU affinity, e.g. 4,5; does not reserve CPUs or modify tool CPU supply")
    parser.add_argument("--replay", type=Path, default=Path(__file__).with_name("replay.py"))
    parser.add_argument("--renderer", type=Path, default=Path(__file__).with_name("render.py"))
    return asyncio.run(campaign(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
