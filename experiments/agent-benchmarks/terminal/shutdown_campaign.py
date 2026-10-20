#!/usr/bin/env python3
"""Graceful shutdown and retained-artifact receipt for the owned benchmark VM."""
import argparse
import hashlib
import json
import os
import socket
import subprocess
import time
from pathlib import Path


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def identity(pid):
    proc = Path("/proc") / str(pid)
    text = (proc / "stat").read_text()
    return {"pid": pid, "start_ticks": int(text[text.rfind(")") + 2:].split()[19]),
        "executable": os.readlink(proc / "exe"),
        "arguments": (proc / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")}


parser = argparse.ArgumentParser()
parser.add_argument("--directory", type=Path, required=True)
parser.add_argument("--ssh-key", type=Path, required=True)
parser.add_argument("--port", type=int, default=10089)
parser.add_argument("--base", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
directory = args.directory.resolve(strict=True)
expected = json.loads((directory / "qemu-identity.json").read_text())
if identity(expected["pid"]) != expected:
    raise ValueError("Owned VM identity changed; refusing shutdown")
if not any(value.startswith("file=" + str(directory / "rootfs.raw") + ",") for value in expected["arguments"]):
    raise ValueError("Owned VM does not bind exact private rootfs")
if not any("hostfwd=tcp:127.0.0.1:" + str(args.port) + "-:22" in value for value in expected["arguments"]):
    raise ValueError("Owned VM does not bind exact SSH port")
ssh = ["ssh", "-i", str(args.ssh_key), "-p", str(args.port), "-o", "BatchMode=yes",
       "-o", "ConnectTimeout=10", "root@127.0.0.1"]
code = """import json,pathlib,subprocess
containers=subprocess.check_output(['docker','ps','-a','--format','{{json .}}'],text=True).splitlines()
processes=[]
for path in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
 try:
  argv=path.read_bytes().rstrip(b'\\0').split(b'\\0')
 except OSError: continue
 if not argv: continue
 executable=argv[0].decode(errors='replace')
 basename=pathlib.Path(executable).name
 if basename in ('deployment-observe','allox-load-sampler') or (basename.startswith('python') and any(b'/opt/agent-benchmarks/' in arg and arg.endswith(b'/run.py') for arg in argv[1:])):
  processes.append({'pid':int(path.parent.name),'argv':[arg.decode(errors='replace') for arg in argv]})
print(json.dumps({'containers':containers,'collector_or_runner_processes':processes,'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}))
"""
import shlex
result = subprocess.run(ssh + ["python3 -c " + shlex.quote(code)], capture_output=True, text=True, timeout=30, check=True)
guest = json.loads(result.stdout)
if guest["containers"] or guest["collector_or_runner_processes"]:
    raise RuntimeError("Benchmark containers or collectors remain; refusing to conceal them by shutdown")
before = (directory / "base.before.sha256").read_text().split()[0]
after = sha256(args.base.resolve(strict=True))
if before != after:
    raise ValueError("Original immutable base changed")
# Recheck before issuing the Guest's own orderly poweroff.
if identity(expected["pid"]) != expected:
    raise ValueError("Owned VM changed before Guest shutdown")
shutdown = subprocess.run(ssh + ["sync; /sbin/poweroff"], capture_output=True, text=True, timeout=30)
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    try:
        current = identity(expected["pid"])
    except FileNotFoundError:
        break
    if current != expected:
        break
    time.sleep(.2)
else:
    raise RuntimeError("Owned VM did not stop gracefully; no broad kill performed")
with socket.socket() as connection:
    connection.settimeout(1)
    port_free = connection.connect_ex(("127.0.0.1", args.port)) != 0
receipt = {"schema_version":1, "status":"COMPLETE" if port_free else "PORT_STILL_OPEN",
    "owned_vm":expected, "guest_before_shutdown":guest, "ssh_shutdown_exit_code":shutdown.returncode,
    "owned_qemu_exited":True, "ssh_port_free":port_free, "ssh_port":args.port,
    "original_base_sha256_before":before, "original_base_sha256_after":after,
    "original_base_unchanged":before == after, "private_rootfs_retained":str(directory / "rootfs.raw"),
    "evidence_retained":str(args.output.parent), "existing_other_vms":"NOT_SIGNALED_OR_REBOOTED"}
with args.output.open("x") as output:
    json.dump(receipt,output,indent=2)
print(json.dumps({key:receipt[key] for key in ("status","owned_qemu_exited","ssh_port_free","original_base_unchanged")}))
