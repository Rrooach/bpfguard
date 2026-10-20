#!/usr/bin/env python3
"""Private, bounded inter-process barriers for fixed-work benchmark trials.

All timestamps use the target Linux CLOCK_MONOTONIC. This is a cooperative
controller protocol, not a kernel or adversarial attestation.
"""
import asyncio
import json
import os
from pathlib import Path
import re
import time
import uuid

from common import write_new


class CampaignAborted(RuntimeError):
    pass


def job_name(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value) is None:
        raise ValueError("a bounded, path-safe job ID is required")
    return value


def publish(path, value):
    """Publish a complete file without replacing an existing decision."""
    path = Path(path)
    temporary = path.parent / (".pending-" + uuid.uuid4().hex)
    write_new(temporary, value)
    try:
        os.link(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink()


def read_record(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ValueError("unsafe or oversized control record")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("control record must be an object")
    return value


def cgroup_snapshot(metadata):
    """Boundary counters, not samples of arbitrary short-lived /proc tasks."""
    name = metadata.get("cgroup_root")
    if not name:
        return {"status": "NOT_SELECTED", "monotonic_ns": time.monotonic_ns()}
    root = Path(name).resolve(strict=True)
    parent = Path('/sys/fs/cgroup').resolve(strict=True)
    if parent not in root.parents or metadata.get('cgroup_id') != root.stat().st_ino:
        raise ValueError('resource counter cgroup identity differs from registered target')
    def frozen():
        fields = dict(line.split() for line in (root/'cgroup.events').read_text().splitlines())
        if fields.get('frozen') != '1' or root.stat().st_ino != metadata['cgroup_id']:
            raise ValueError('registered cgroup is not actually frozen at resource boundary')
        return fields
    frozen_before = frozen()
    result = {'status':'CAPTURED_BOUNDARY_COUNTERS', 'begin_ns':time.monotonic_ns(),
              'cgroup_root':str(root),'cgroup_id':root.stat().st_ino,'files':{},'errors':{},
              'frozen_before': frozen_before}
    for name in ('cpu.stat','memory.current','memory.peak','memory.stat','cpu.pressure',
                 'memory.pressure','io.pressure','io.stat','pids.current','pids.events'):
        try:
            result['files'][name]=(root/name).read_text()
        except OSError as error:
            result['errors'][name]=type(error).__name__+': '+str(error)
    result['end_ns']=time.monotonic_ns()
    result['frozen_after'] = frozen()
    if result['errors']:
        result['status']='PARTIAL_BOUNDARY_COUNTERS'
    return result


class Control:
    def __init__(self, control_dir, job_id, timeout=1800.0):
        self.root = Path(control_dir).resolve(strict=True)
        self.job_id = job_name(job_id)
        self.directory = self.root / self.job_id
        if self.directory.is_symlink() or not self.directory.is_dir():
            raise ValueError("controller must pre-create the exact private job directory")
        self.timeout = float(timeout)
        if not 0 < self.timeout <= 7200:
            raise ValueError("control timeout must be positive and <=7200 seconds")
        self.release_observed_ns = None
        self.registered_metadata = None

    def fail(self, error):
        record = {"schema_version": 1, "event": "ABORT", "job_id": self.job_id,
                  "monotonic_ns": time.monotonic_ns(), "error": str(error)[:4096]}
        try:
            publish(self.root / "abort.json", record)
        except FileExistsError:
            pass

    def _wait(self, path):
        deadline = time.monotonic() + self.timeout
        while True:
            if (self.root / "abort.json").exists():
                raise CampaignAborted(str(read_record(self.root / "abort.json")))
            if path.exists():
                value = read_record(path)
                if value.get("schema_version") != 1:
                    raise ValueError("unsupported control record")
                return {**value, "observed_ns": time.monotonic_ns()}
            if time.monotonic() >= deadline:
                self.fail("control barrier timeout: " + path.name)
                raise TimeoutError("control barrier timeout: " + path.name)
            time.sleep(0.002)

    def ready_sync(self, metadata):
        if not isinstance(metadata, dict):
            raise ValueError("READY metadata must be an object")
        self.registered_metadata = dict(metadata)
        publish(self.directory / "ready.json", {"schema_version": 1, "event": "READY",
            "job_id": self.job_id, "monotonic_ns": time.monotonic_ns(), "metadata": metadata})
        result = self._wait(self.directory / "release.json")
        if result.get("event") != "RELEASE" or result.get("job_id") != self.job_id:
            self.fail("release identity mismatch")
            raise ValueError("release identity mismatch")
        self.release_observed_ns = result["observed_ns"]
        publish(self.directory/'resources-before.json',cgroup_snapshot(self.registered_metadata))
        return result

    def done_sync(self, metadata):
        if self.release_observed_ns is None or not isinstance(metadata, dict):
            raise ValueError("DONE requires a successful release and object metadata")
        publish(self.directory/'resources-after.json',cgroup_snapshot(self.registered_metadata))
        publish(self.directory / "agent-done.json", {"schema_version": 1, "event": "AGENT_DONE",
            "job_id": self.job_id, "monotonic_ns": time.monotonic_ns(), "metadata": metadata})
        result = self._wait(self.root / "all-agents-done.json")
        if result.get("event") != "ALL_AGENTS_DONE":
            raise ValueError("unexpected postprocessing release")
        return result

    async def ready(self, metadata):
        return await asyncio.to_thread(self.ready_sync, metadata)

    async def done(self, metadata):
        return await asyncio.to_thread(self.done_sync, metadata)
