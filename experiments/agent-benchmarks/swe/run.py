#!/usr/bin/env python3
"""One real SWE-bench Verified task: official gold control and bounded Agent solve.

Run only on the target Linux Guest. Evaluation remains the pinned official
SWE-bench run_instance implementation; a process-local proxy brackets its live
container before patch application and before cleanup.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.request
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from diagnostics import Diagnostics, sampler_options

HARNESS_VERSION = "3.0.17"
HARNESS_REVISION = "3f01bd622c0a22c00406139f69a234ef08225f22"


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def proc_identity(pid):
    raw = Path("/proc", str(pid), "stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    return {"pid": pid, "start_ticks": int(fields[19])}


def read_line(process, timeout, maximum=64 * 1024, decode_json=True):
    deadline = time.monotonic() + timeout
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                continue
            chunk = os.read(process.stdout.fileno(), min(4096, maximum + 1 - len(data)))
            if not chunk:
                raise RuntimeError("collector closed stdout before protocol response")
            data.extend(chunk)
            if len(data) > maximum:
                raise RuntimeError("collector protocol response is oversized")
            if b"\n" in data:
                if data.count(b"\n") != 1 or not data.endswith(b"\n"):
                    raise RuntimeError("collector returned multiple protocol responses")
                return json.loads(data) if decode_json else bytes(data)
    raise TimeoutError("collector protocol timeout")


def terminate(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def load_bridge(path):
    spec = importlib.util.spec_from_file_location("swe_observer_bridge", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validate_task(task, provenance):
    if not isinstance(task, list) or len(task) != 1:
        raise ValueError("pilot admits exactly one official task")
    row = task[0]
    if row.get("instance_id") != provenance.get("instance_id"):
        raise ValueError("task/provenance identity mismatch")
    if provenance.get("dataset") != "princeton-nlp/SWE-bench_Verified":
        raise ValueError("task is not bound to SWE-bench Verified")
    if provenance.get("harness_revision") != HARNESS_REVISION:
        raise ValueError("unexpected official harness revision")
    return row


def validate_installed_harness(inputs, provenance):
    archive_path = inputs / "harness.tar.gz"
    if hashlib.sha256(archive_path.read_bytes()).hexdigest() != provenance["harness_source"]["sha256"]:
        raise ValueError("official harness archive differs from prepared source digest")
    package = importlib.util.find_spec("swebench")
    if package is None or not package.submodule_search_locations:
        raise ValueError("official swebench package is not installed")
    installed = Path(list(package.submodule_search_locations)[0])
    prefix = "SWE-bench-" + HARNESS_REVISION + "/swebench/"
    files = {}
    excluded_auxiliary = []
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        for member in members:
            if not member.name.startswith(prefix) or not member.name.endswith(".py"):
                continue
            relative = member.name[len(prefix):]
            if not member.isfile() or ".." in Path(relative).parts:
                raise ValueError("unexpected harness Python archive entry")
            # setuptools.find_packages omits auxiliary script directories that
            # are not Python packages; do not pretend those scripts are installed.
            parents = [parent for parent in Path(relative).parents if str(parent) != "."]
            if any(prefix + parent.as_posix() + "/__init__.py" not in names for parent in parents):
                excluded_auxiliary.append(relative)
                continue
            source = archive.extractfile(member).read()
            digest = hashlib.sha256(source).hexdigest()
            if hashlib.sha256((installed / relative).read_bytes()).hexdigest() != digest:
                raise ValueError("installed official harness differs from pinned source: " + relative)
            files[relative] = digest
    if "harness/run_evaluation.py" not in files or "harness/grading.py" not in files:
        raise ValueError("harness archive lacks evaluator or grading implementation")
    return {"version": HARNESS_VERSION, "revision": HARNESS_REVISION,
            "installed_root": str(installed), "python_files_sha256": files,
            "auxiliary_scripts_not_packaged": excluded_auxiliary}


def validate_agent_command(content):
    value = json.loads(content)
    if not isinstance(value, dict) or set(value) != {"command"}:
        raise ValueError("Agent must return exactly one command field")
    command = value["command"]
    if not isinstance(command, str) or not command.strip() or len(command.encode()) > 16_384:
        raise ValueError("Agent command is missing or oversized")
    return command


def summarize_observation(directory):
    summary = {"observer_verification_passed": False, "state": "UNKNOWN", "errors": []}
    def optional(relative):
        path = directory / relative
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError) as error:
            summary["errors"].append(relative + ": " + str(error))
            return None
    verification = optional("verification.json")
    summary["observer_verification_passed"] = bool(verification and verification.get("verified") is True)
    report = optional("observer/deployment-observation-report.json")
    if report:
        summary["state"] = report.get("overall_evidence_status", "UNKNOWN")
        summary["aggregate_health"] = report.get("aggregate_health")
        summary["filesystem_state"] = report.get("filesystem_state")
        summary["bpf_state"] = report.get("bpf_state")
        summary["linux_state"] = report.get("linux_state")
    stats = optional("load/load-sampler-stats.json")
    if stats:
        summary["sampler"] = {key: stats.get(key) for key in (
            "samples", "process_samples", "read_errors", "missed_ticks",
            "vanished_processes", "truncated_process_sets", "truncated_cgroup_traversals",
            "cgroup_traversal_read_errors")}
    summary["post_execution_sample"] = optional("post-execution-sample.json")
    summary["target"] = optional("target.json")
    return summary


def image_download_budget(reference, maximum_bytes=4 * 1024 * 1024 * 1024):
    """Bound the public registry's compressed layers before initiating a pull."""
    repository, tag = reference.rsplit(":", 1)
    if not repository.startswith("swebench/sweb.eval.x86_64."):
        raise ValueError("image is outside the selected official SWE-bench namespace")
    auth_url = "https://auth.docker.io/token?" + urllib.parse.urlencode({
        "service": "registry.docker.io", "scope": "repository:" + repository + ":pull"})
    with urllib.request.urlopen(auth_url, timeout=30) as response:
        token_raw = response.read(256 * 1024 + 1)
    if len(token_raw) > 256 * 1024:
        raise ValueError("registry token response exceeds bound")
    token = json.loads(token_raw)["token"]
    def get_manifest(selector):
        request = urllib.request.Request("https://registry-1.docker.io/v2/" + repository + "/manifests/" + selector,
            headers={"Authorization": "Bearer " + token, "Accept": ",".join([
                "application/vnd.docker.distribution.manifest.v2+json",
                "application/vnd.docker.distribution.manifest.list.v2+json",
                "application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.image.index.v1+json"])})
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("registry manifest exceeds bound")
        return json.loads(raw), hashlib.sha256(raw).hexdigest()
    manifest, digest = get_manifest(tag)
    if "manifests" in manifest:
        selected = [item for item in manifest["manifests"] if item.get("platform", {}).get("os") == "linux"
                    and item.get("platform", {}).get("architecture") == "amd64"]
        if len(selected) != 1:
            raise ValueError("image has no unique linux/amd64 manifest")
        manifest, digest = get_manifest(selected[0]["digest"])
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise ValueError("registry manifest lacks layers")
    total = sum(layer["size"] for layer in layers)
    if total > maximum_bytes:
        raise ValueError("one-task compressed image exceeds4GiB download budget")
    return {"compressed_layer_bytes": total, "manifest_sha256": digest,
            "maximum_compressed_bytes": maximum_bytes}


class Session:
    def __init__(self, container, root, run_id, artifacts, bridge, profile="balanced",
                 task_id=None, agent_id=None, filesystem_root="/testbed"):
        self.container, self.root, self.run_id = container, root, run_id
        self.artifacts, self.bridge, self.profile = artifacts, bridge, profile
        self.task_id, self.agent_id = task_id, agent_id
        self.filesystem_root = filesystem_root
        if not filesystem_root.startswith("/") or filesystem_root == "/":
            raise ValueError("filesystem scope must name an explicit absolute subdirectory")
        self.observer = self.sampler = None
        self.diagnostics = None
        self.finish_nonce = None
        self.handles, self.events = [], []
        self.paused = False
        self.closed = False
        self.root.mkdir(parents=True, exist_ok=False)
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()

    def mark(self, name, **fields):
        self.events.append({"schema_version": 1, "run_id": self.run_id,
                            "task_id": self.task_id, "agent_id": self.agent_id,
                            "boot_id": self.boot_id, "monotonic_ns": time.monotonic_ns(),
                            "phase": name, "container_id": self.container.id,
                            "target": getattr(self, "target", None), **fields})

    def freeze(self, frozen):
        if frozen:
            self.container.pause()
            self.paused = True
        else:
            self.container.unpause()
            self.paused = False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.cgroup.stat().st_ino != self.target["cgroup_inode"]:
                raise RuntimeError("target cgroup identity changed")
            fields = dict(line.split() for line in (self.cgroup / "cgroup.events").read_text().splitlines())
            if fields.get("frozen") == str(int(frozen)):
                return
            time.sleep(.02)
        raise TimeoutError("container cgroup freeze did not settle")

    def start(self):
        self.container.reload()
        pid = self.container.attrs["State"]["Pid"]
        cgpath = self.bridge.parse_proc_cgroup(Path("/proc", str(pid), "cgroup").read_text())
        if not self.bridge.cgroup_binds_container(cgpath, self.container.id):
            raise RuntimeError("live cgroup does not bind exact full Docker identity")
        self.cgroup = Path("/sys/fs/cgroup") / cgpath.lstrip("/")
        self.target = {"process": proc_identity(pid), "cgroup_path": cgpath,
                       "cgroup_inode": self.cgroup.stat().st_ino,
                       "cgroup_device": self.cgroup.stat().st_dev,
                       "mount_namespace_inode": Path("/proc", str(pid), "ns/mnt").stat().st_ino,
                       "network_namespace_inode": Path("/proc", str(pid), "ns/net").stat().st_ino,
                       "image_id": self.container.image.id}
        self.freeze(True)
        if proc_identity(pid) != self.target["process"]:
            raise RuntimeError("Docker init process identity changed at the start barrier")
        interfaces = self.bridge.parse_proc_net_dev(Path("/proc", str(pid), "net/dev").read_text())
        artifact = self.artifacts
        config = self.bridge.build_observer_config(
            container_id=self.container.id, init_pid=pid, cgroup_path=cgpath,
            mount_namespace_inode=self.target["mount_namespace_inode"],
            network_namespace_inode=self.target["network_namespace_inode"],
            network_interfaces=interfaces,
            ip_binary=Path(artifact["ip_binary"]), ip_sha256=artifact["ip_sha256"],
            tc_binary=Path(artifact["tc_binary"]), tc_sha256=artifact["tc_sha256"],
            nft_binary=Path(artifact["nft_binary"]), nft_sha256=artifact["nft_sha256"],
            recorder_object=Path(artifact["recorder_object"]), recorder_sha256=artifact["recorder_sha256"],
            lifecycle_object=Path(artifact["lifecycle_object"]), lifecycle_sha256=artifact["lifecycle_sha256"],
            output_directory=self.root / "observer", run_id=self.run_id, epoch=1)
        config["profile"] = self.profile
        config["filesystem_state_scope"]["roots"] = [{"path_bytes_hex": os.fsencode(self.filesystem_root).hex()}]
        write_new(self.root / "config.json", config)
        write_new(self.root / "target.json", self.target)
        self.config = config
        stderr = (self.root / "observer.stderr").open("xb")
        self.handles.append(stderr)
        self.observer = subprocess.Popen([artifact["observer_binary"], "--config", str(self.root / "config.json")],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, bufsize=0)
        ready = read_line(self.observer, 180)
        self.finish_nonce = self.bridge.validate_ready(ready, run_id=self.run_id, epoch=1,
                           effect_sha256=artifact["recorder_sha256"],
                           lifecycle_sha256=artifact["lifecycle_sha256"],
                           expected_cgroup_id=self.target["cgroup_inode"])
        write_new(self.root / "ready.json", ready)
        samplererr = (self.root / "sampler.stderr").open("xb")
        self.handles.append(samplererr)
        self.sampler = subprocess.Popen([artifact["sampler_binary"], "--output-dir", str(self.root / "load"),
            "--cgroup", str(self.cgroup), "--label", self.run_id, "--interval-ms", "100",
            "--process-interval-ms", "100", "--exit-with-parent",
            *sampler_options(artifact.get("diagnostics", {}))],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=samplererr, bufsize=0)
        raw_ready = read_line(self.sampler, 60, decode_json=False)
        if raw_ready != b"READY\n":
            raise RuntimeError("sampler did not flush its initial sample")
        sampler_meta = json.loads((self.root / "load/load-meta.json").read_text())
        groups = sampler_meta.get("cgroups")
        if sampler_meta.get("boot_id") != self.boot_id or sampler_meta.get("label") != self.run_id:
            raise RuntimeError("sampler run or boot identity mismatch")
        if (not isinstance(groups, list) or len(groups) != 1 or groups[0].get("path") != str(self.cgroup)
                or groups[0].get("inode") != self.target["cgroup_inode"]
                or groups[0].get("device") != self.target["cgroup_device"]):
            raise RuntimeError("sampler cgroup identity mismatch")
        write_new(self.root / "sampler-ready.json", {"status": "READY", "binding_validated": True})
        self.diagnostics = Diagnostics(artifact.get("diagnostics", {}), self.root / "diagnostics",
                                       self.cgroup, self.run_id)
        self.diagnostics.start()
        self.mark("EXECUTION_START")
        self.freeze(False)

    def finish(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.mark("EXECUTION_END")
            execution_end_ns = self.events[-1]["monotonic_ns"]
            if self.observer is None or self.finish_nonce is None:
                return
            self.freeze(True)
            # Require an actual flushed sample after execution, not an assumed delay.
            deadline = time.monotonic() + 10
            samples = self.root / "load/load-samples.jsonl"
            post_sample = None
            while time.monotonic() < deadline:
                if self.sampler.poll() is not None:
                    raise RuntimeError("sampler exited before the final execution sample")
                with samples.open("rb") as stream:
                    size = stream.seek(0, os.SEEK_END)
                    stream.seek(max(0, size - 128 * 1024))
                    tail = stream.read(128 * 1024)
                complete = tail.split(b"\n")[:-1]
                if complete:
                    try:
                        latest = json.loads(complete[-1])
                    except (ValueError, UnicodeDecodeError):
                        latest = None
                    if (isinstance(latest, dict) and isinstance(latest.get("monotonic_ns"), int)
                            and latest["monotonic_ns"] > execution_end_ns):
                        post_sample = {"seq": latest.get("seq"), "monotonic_ns": latest["monotonic_ns"],
                                       "collection_end_ns": latest.get("collection_end_ns")}
                        break
                time.sleep(.02)
            if post_sample is None:
                raise TimeoutError("no flushed post-execution resource sample")
            write_new(self.root / "post-execution-sample.json", post_sample)
            if self.diagnostics is not None:
                self.diagnostics.finish()
            terminate(self.sampler)
            if self.sampler.returncode != 0:
                raise RuntimeError("sampler finalization returned a failure status")
            request = {"protocol_version": 2, "command": "FINISH", "run_id": self.run_id,
                       "finish_nonce": self.finish_nonce}
            write_new(self.root / "finish.json", request)
            self.observer.stdin.write(json.dumps(request).encode() + b"\n")
            self.observer.stdin.flush()
            self.observer.stdin.close()
            finished = read_line(self.observer, 300)
            report_digest, manifest_digest = self.bridge.validate_finished(finished, run_id=self.run_id)
            write_new(self.root / "finished.json", finished)
            if self.observer.wait(timeout=60) != 0:
                raise RuntimeError("observer finalization failed")
            expectation = {"expected_config": self.config, "expected_artifact_manifest_sha256": manifest_digest,
                           "expected_report_sha256": report_digest}
            write_new(self.root / "verification-expectation.json", expectation)
            verified = subprocess.run([self.artifacts["verifier_binary"], "--artifacts", str(self.root / "observer"),
                                      "--expectation", str(self.root / "verification-expectation.json")],
                                     capture_output=True, timeout=300)
            with (self.root / "verifier.stdout").open("xb") as output:
                output.write(verified.stdout)
            with (self.root / "verifier.stderr").open("xb") as output:
                output.write(verified.stderr)
            if verified.returncode:
                raise RuntimeError("independent Observer verifier rejected artifacts: " +
                                   verified.stderr.decode("utf-8", "replace")[-4096:].strip())
            result = json.loads(verified.stdout)
            write_new(self.root / "verification.json", result)
            if verified.returncode or result.get("verified") is not True:
                raise RuntimeError("independent observer verifier rejected artifacts")
        finally:
            try:
                if self.diagnostics is not None:
                    self.diagnostics.finish()
            finally:
                try:
                    terminate(self.sampler)
                finally:
                    try:
                        terminate(self.observer)
                    finally:
                        try:
                            if self.paused:
                                self.freeze(False)
                        finally:
                            for handle in self.handles:
                                handle.close()
                            for process in (self.sampler, self.observer):
                                if process is not None and process.stdout is not None:
                                    process.stdout.close()
                            with (self.root / "phase-events.jsonl").open("x", encoding="utf-8") as stream:
                                for event in self.events:
                                    stream.write(json.dumps(event, ensure_ascii=False) + "\n")


class ContainerProxy:
    def __init__(self, container, session):
        self.original, self.session = container, session

    def __getattr__(self, name):
        return getattr(self.original, name)

    def start(self):
        self.original.start()
        self.session.start()

    def exec_run(self, *args, **kwargs):
        phase_id = len(self.session.events)
        self.session.mark("TOOL_START", tool_id=phase_id, command=args[0] if args else kwargs.get("cmd"))
        try:
            result = self.original.exec_run(*args, **kwargs)
            self.session.mark("TOOL_END", tool_id=phase_id, exit_code=result.exit_code)
            return result
        except BaseException as error:
            self.session.mark("TOOL_END", tool_id=phase_id, error=str(error))
            raise


def official_evaluation(row, patch, model_label, output, artifacts, bridge, timeout, expected_image_id=None,
                        import_provenance=None):
    import docker
    from swebench.harness import run_evaluation as official
    from swebench.harness.test_spec.test_spec import make_test_spec
    spec = make_test_spec(row, namespace="swebench", instance_image_tag="latest")
    client = docker.from_env(timeout=600)
    # A pull is allowed only for the one selected task image, never a full benchmark.
    try:
        image = client.images.get(spec.instance_image_key)
        download_budget = {"status": "IMAGE_ALREADY_LOCAL"}
    except docker.errors.ImageNotFound:
        download_budget = image_download_budget(spec.instance_image_key)
        repository, tag = spec.instance_image_key.rsplit(":", 1)
        digest = "sha256:" + download_budget["manifest_sha256"]
        image = client.images.pull(repository + "@" + digest)
        image.tag(repository, tag)
    if expected_image_id is not None and image.id != expected_image_id:
        raise RuntimeError("official task image identity changed between trial phases")
    if import_provenance is not None:
        if import_provenance.get("image_config_digest") != image.id:
            raise RuntimeError("imported image config digest does not match the actual Docker image")
        repository = spec.instance_image_key.rsplit(":", 1)[0]
        if not import_provenance.get("pinned_reference", "").startswith(repository + "@sha256:"):
            raise RuntimeError("imported image provenance names a different task image")
    if not image.attrs.get("RepoDigests") and import_provenance is None:
        raise RuntimeError("locally imported image requires registry/archive provenance")
    write_new(output / "image.json", {"reference": spec.instance_image_key, "id": image.id,
                                      "repo_digests": image.attrs.get("RepoDigests", []),
                                      "size_bytes": image.attrs.get("Size"), "download_budget": download_budget,
                                      "import_provenance": import_provenance})
    original_build, original_cleanup = official.build_container, official.cleanup_container
    original_exec = official.exec_run_with_timeout
    active = []
    run_id = output.parent.name + "-" + output.name
    def wrapped_build(*args, **kwargs):
        container = original_build(*args, **kwargs)
        session = Session(container, output / "observation", run_id, artifacts, bridge,
                          task_id=row["instance_id"], agent_id=model_label)
        active.append(session)
        return ContainerProxy(container, session)
    def wrapped_cleanup(client, container, logger):
        if isinstance(container, ContainerProxy):
            try:
                container.session.finish()
            finally:
                original_cleanup(client, container.original, logger)
            return
        return original_cleanup(client, container, logger)
    def wrapped_exec(container, command, timeout):
        container.session.mark("TESTS_START", command=command)
        try:
            result = original_exec(container.original, command, timeout)
            container.session.mark("TESTS_END", timed_out=result[1], runtime_seconds=result[2])
            return result
        except BaseException as error:
            container.session.mark("TESTS_END", error=str(error))
            raise
    official.build_container, official.cleanup_container = wrapped_build, wrapped_cleanup
    official.exec_run_with_timeout = wrapped_exec
    saved = Path.cwd()
    os.chdir(output)
    try:
        result = official.run_instance(spec, {"instance_id": row["instance_id"],
                    "model_name_or_path": model_label, "model_patch": patch},
                    False, False, client, run_id, timeout)
        if not result:
            raise RuntimeError("official harness returned no evaluation report")
        # Harness reports exceptions internally; verification is checked independently.
        if not (output / "observation/verification.json").is_file():
            raise RuntimeError("official evaluation finished without verified Observer evidence")
        write_new(output / "official-result.json", {"instance_id": result[0], "report": result[1]})
        return result[1]
    finally:
        os.chdir(saved)
        official.build_container, official.cleanup_container = original_build, original_cleanup
        official.exec_run_with_timeout = original_exec
        for session in active:
            session.finish()
        client.close()


def request_model(base_url, model, messages, broker_token=None, task_label="swe-verified"):
    payload = {"model": model, "messages": messages, "max_tokens": 2048, "temperature": 0,
               "response_format": {"type": "json_object"}}
    headers = {"Content-Type": "application/json", "X-Benchmark-Task": task_label}
    if broker_token:
        headers["Authorization"] = "Bearer " + broker_token
    request = urllib.request.Request(base_url.rstrip("/") + "/chat/completions",
              data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=180) as response:
        raw = response.read(512 * 1024 + 1)
    if len(raw) > 512 * 1024:
        raise ValueError("model response oversized")
    return json.loads(raw)


def solve(row, output, artifacts, bridge, base_url, model, steps, tool_timeout, broker_token=None,
          expected_image_id=None):
    import docker
    from swebench.harness.test_spec.test_spec import make_test_spec
    spec = make_test_spec(row, namespace="swebench", instance_image_tag="latest")
    client = docker.from_env(timeout=600)
    image = client.images.get(spec.instance_image_key)
    if expected_image_id is not None and image.id != expected_image_id:
        raise RuntimeError("Agent task image identity differs from the gold control")
    run_id = output.parent.name + "-" + output.name
    container = client.containers.create(image.id,
                 name="observer-swe-agent-" + run_id, command="tail -f /dev/null",
                 user="root", detach=True, labels={"observer.benchmark": "swe-verified", "observer.run": run_id})
    session = Session(container, output / "observation", run_id, artifacts, bridge,
                      task_id=row["instance_id"], agent_id=model)
    proxy = ContainerProxy(container, session)
    messages = [{"role": "system", "content": (
        "You are a coding Agent in a disposable Linux container. Fix the reported issue in /testbed. "
        "Reply with exactly one JSON object: {\"command\":\"bash command\"}. Run shell commands to inspect, "
        "edit and test the repository. Each shell tool activates the prepared conda testbed environment. "
        "Do not use network services. When finished, use command "
        "COMPLETE_TASK. You have at most %d tool steps. No reference patch is available." % steps)},
        {"role": "user", "content": row["problem_statement"]}]
    transcript = []
    error = None
    completed = False
    patch = ""
    try:
        proxy.start()
        for index in range(steps):
            session.mark("MODEL_REQUEST_START", request_id=index, model=model,
                         attribution="APPLICATION_REQUEST_ASSOCIATION",
                         execution_domain="COORDINATOR_OUTSIDE_CONTAINER")
            result = request_model(base_url, model, messages, broker_token, run_id)
            session.mark("MODEL_REQUEST_END", request_id=index, usage=result.get("usage"),
                         execution_domain="COORDINATOR_OUTSIDE_CONTAINER")
            content = result["choices"][0]["message"]["content"]
            command = validate_agent_command(content)
            transcript.append({"step": index, "assistant": content, "usage": result.get("usage")})
            messages.append({"role": "assistant", "content": content})
            if command.strip() == "COMPLETE_TASK":
                completed = True
                break
            # timeout kills the shell command group inside this disposable container.
            executed = proxy.exec_run(["timeout", "--kill-after=5s", str(tool_timeout),
                                      "/bin/bash", "-lc",
                                      "source /opt/miniconda3/bin/activate && conda activate testbed && " + command],
                                      workdir="/testbed")
            text = executed.output.decode("utf-8", "replace")[:12_000]
            transcript[-1].update({"exit_code": executed.exit_code, "output": text,
                                  "output_truncated": len(executed.output) > 12_000})
            messages.append({"role": "user", "content": "Exit code: %d\n%s" % (executed.exit_code, text)})
            # Bound subsequent context without letting the evaluator's test/gold patch enter it.
            if sum(len(message["content"]) for message in messages) > 48_000:
                raise RuntimeError("Agent context budget exhausted")
    except Exception as failure:
        error = str(failure)
    finally:
        try:
            if container.attrs.get("State", {}).get("Running") or session.observer is not None:
                diff = proxy.exec_run(["git", "diff", "--binary"], workdir="/testbed")
                if diff.exit_code:
                    raise RuntimeError("could not extract Agent patch")
                if len(diff.output) > 1024 * 1024:
                    raise RuntimeError("Agent patch exceeds 1MiB limit")
                patch = diff.output.decode("utf-8")
            session.finish()
        finally:
            container.remove(force=True)
            client.close()
            write_new(output / "agent-transcript.json", transcript)
            write_new(output / "agent-result.json", {"completed": completed, "error": error,
                       "steps_used": len(transcript), "patch_bytes": len(patch.encode()),
                       "agent": "BOUNDED_SHELL_AGENT", "model": model,
                       "gold_patch_exposed": False, "test_patch_exposed": False})
            with (output / "agent.patch").open("x", encoding="utf-8") as stream:
                stream.write(patch)
    return patch


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--image-import-provenance", type=Path,
                        help="Registry/archive provenance when the image was loaded offline")
    parser.add_argument("--model-base-url", help="Shared budget-limited model broker; no raw API key")
    parser.add_argument("--broker-token-file", type=Path, help="Private dummy broker credential, never the provider key")
    parser.add_argument("--model", default="deepseek-flash")
    parser.add_argument("--steps", type=int, default=12)
    parser.add_argument("--tool-timeout", type=int, default=60)
    parser.add_argument("--test-timeout", type=int, default=300)
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or not Path("/proc/self/ns/cgroup").exists():
        parser.error("run as root on the target Linux Guest")
    dmi = " ".join(Path("/sys/devices/virtual/dmi/id", name).read_text(errors="replace")
                   for name in ("sys_vendor", "product_name"))
    if not any(marker in dmi.lower() for marker in ("qemu", "kvm", "bochs")):
        parser.error("this experiment must run inside the disposable QEMU/KVM Guest")
    if not 1 <= args.steps <= 20:
        parser.error("steps must be within1..20")
    import importlib.metadata
    if importlib.metadata.version("swebench") != HARNESS_VERSION:
        parser.error("requires pinned official swebench " + HARNESS_VERSION)
    args.inputs, args.output_dir = args.inputs.resolve(), args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    summary = {"benchmark": "SWE-bench Verified", "task_count": 1,
               "evaluation_scope": "ONE_TASK_PILOT_NOT_FULL_500_TASK_SCORE", "errors": []}
    try:
        provenance = json.loads((args.inputs / "provenance.json").read_text())
        task_path = args.inputs / "task.json"
        if hashlib.sha256(task_path.read_bytes()).hexdigest() != provenance["task_sha256"]:
            raise ValueError("task bytes differ from prepared input digest")
        row = validate_task(json.loads(task_path.read_text()), provenance)
        write_new(args.output_dir / "harness-runtime.json", validate_installed_harness(args.inputs, provenance))
        artifacts = json.loads(args.artifacts.read_text())
        bridge = load_bridge(args.bridge)
        for binary, digest in (("observer_binary", "observer_sha256"), ("verifier_binary", "verifier_sha256"),
                               ("recorder_object", "recorder_sha256"), ("lifecycle_object", "lifecycle_sha256"),
                               ("sampler_binary", "sampler_sha256"), ("ip_binary", "ip_sha256"),
                               ("tc_binary", "tc_sha256"), ("nft_binary", "nft_sha256")):
            bridge.validate_trusted_file(Path(artifacts[binary]), artifacts[digest], binary)
        write_new(args.output_dir / "provenance.json", provenance)
        summary["instance_id"] = row["instance_id"]
        imported = (json.loads(args.image_import_provenance.read_text())
                    if args.image_import_provenance is not None else None)
        gold = args.output_dir / "gold-control"
        gold.mkdir()
        summary["gold_control"] = official_evaluation(row, row["patch"], "gold-control", gold,
                                                      artifacts, bridge, args.test_timeout,
                                                      import_provenance=imported)
        if not summary["gold_control"].get(row["instance_id"], {}).get("resolved"):
            raise RuntimeError("official gold control did not pass; Agent inference was not started")
        if args.model_base_url:
            if args.broker_token_file is None:
                raise ValueError("model broker requires a private token file")
            token_stat = args.broker_token_file.stat()
            if token_stat.st_mode & 0o077 or token_stat.st_uid != os.geteuid():
                raise ValueError("broker token file must be private and owned by the coordinator")
            broker_token = args.broker_token_file.read_text().strip()
            if not broker_token or len(broker_token) > 4096:
                raise ValueError("invalid broker token")
            agent = args.output_dir / "agent-attempt"
            agent.mkdir()
            patch = solve(row, agent, artifacts, bridge, args.model_base_url, args.model,
                          args.steps, args.tool_timeout, broker_token,
                          json.loads((gold / "image.json").read_text())["id"])
            if patch:
                evaluation = args.output_dir / "agent-evaluation"
                evaluation.mkdir()
                summary["agent_evaluation"] = official_evaluation(row, patch, "bounded-agent", evaluation,
                                                   artifacts, bridge, args.test_timeout,
                                                   json.loads((gold / "image.json").read_text())["id"], imported)
            else:
                summary["agent_evaluation"] = {"status": "NO_PATCH_PRODUCED", "resolved": False}
        else:
            summary["agent_evaluation"] = {"status": "NOT_RUN_MODEL_BROKER_NOT_CONFIGURED"}
    except Exception as error:
        summary["errors"].append(str(error))
        # Preserve an official test result even when the independent evidence
        # gate fails during the harness's finally/cleanup path.
        for phase, label in (("gold-control", "gold_control"), ("agent-evaluation", "agent_evaluation")):
            phase_dir = args.output_dir / phase
            if label not in summary and phase_dir.is_dir():
                reports = list(phase_dir.glob("logs/run_evaluation/*/*/*/report.json"))
                if len(reports) == 1:
                    summary[label] = {"official_report": json.loads(reports[0].read_text()),
                                      "observer_verification_passed": False}
        with (args.output_dir / "failure.txt").open("x") as stream:
            traceback.print_exc(file=stream)
    finally:
        summary["observations"] = {phase: summarize_observation(args.output_dir / phase / "observation")
            for phase in ("gold-control", "agent-attempt", "agent-evaluation")
            if (args.output_dir / phase / "observation").is_dir()}
        agent_result = args.output_dir / "agent-attempt/agent-result.json"
        if agent_result.is_file():
            summary["agent_attempt"] = json.loads(agent_result.read_text())
        summary["status"] = "FAILED" if summary["errors"] else "COMPLETED"
        write_new(args.output_dir / "benchmark-summary.json", summary)
        print(json.dumps(summary, ensure_ascii=False))
    return int(bool(summary["errors"]))


if __name__ == "__main__":
    sys.exit(main())
