#!/usr/bin/env python3
"""Capture/check one owned QEMU PID before final experiment cleanup."""
import argparse
import ctypes
import json
import os
import platform
import signal
import time
from pathlib import Path


def identity(pid):
    proc = Path("/proc") / str(pid)
    raw = (proc / "stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    return {"pid": pid, "start_ticks": int(fields[19]), "executable": os.readlink(proc / "exe"),
            "arguments": (proc / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")}


def validate_owned(record, directory, port):
    if not record["executable"].endswith("/qemu-system-x86_64"):
        raise ValueError("PID is not QEMU")
    disk = str(directory / "rootfs.raw")
    if not any(value.startswith("file=" + disk + ",") for value in record["arguments"]):
        raise ValueError("QEMU does not own this exact experiment disk")
    if not any("hostfwd=tcp:127.0.0.1:" + str(port) + "-:22" in value for value in record["arguments"]):
        raise ValueError("QEMU does not own this exact SSH endpoint")


parser = argparse.ArgumentParser()
parser.add_argument("operation", choices=("capture", "check", "stop"))
parser.add_argument("--directory", type=Path, required=True)
parser.add_argument("--port", type=int, default=10089)
args = parser.parse_args()
directory = args.directory.resolve(strict=True)
file = directory / "qemu-identity.json"
if args.operation == "capture":
    current = identity(int((directory / "qemu.pid").read_text()))
    validate_owned(current, directory, args.port)
    with file.open("x") as output:
        json.dump(current, output, indent=2)
    print(json.dumps({"status": "CAPTURED", "pid": current["pid"], "start_ticks": current["start_ticks"]}))
else:
    expected = json.loads(file.read_text())
    validate_owned(expected, directory, args.port)
    try:
        current = identity(expected["pid"])
    except FileNotFoundError:
        print(json.dumps({"status": "ALREADY_EXITED", "pid": expected["pid"]}))
        raise SystemExit(0)
    if current != expected:
        raise ValueError("PID identity changed; refusing to signal another process")
    if args.operation == "stop":
        if platform.machine() != "x86_64":
            raise RuntimeError("This pidfd syscall helper is restricted to the tested x86-64 Host")
        # Hold the process itself, then recheck identity; PID reuse cannot turn
        # this cleanup into a signal to a different process.
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        pidfd = libc.syscall(434, expected["pid"], 0)  # pidfd_open, Linux x86-64
        if pidfd < 0:
            raise OSError(ctypes.get_errno(), "pidfd_open failed; no signal sent")
        try:
            if identity(expected["pid"]) != expected:
                raise ValueError("QEMU changed after pidfd_open; no signal sent")
            if libc.syscall(424, pidfd, signal.SIGTERM, 0, 0) < 0:  # pidfd_send_signal
                raise OSError(ctypes.get_errno(), "pidfd_send_signal failed")
        finally:
            os.close(pidfd)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                current = identity(expected["pid"])
            except FileNotFoundError:
                break
            if current != expected or not current["arguments"]:
                break
            time.sleep(0.1)
        else:
            raise TimeoutError("Owned QEMU did not exit; no broad kill performed")
    print(json.dumps({"status": "STOPPED" if args.operation == "stop" else "IDENTITY_MATCHED", "pid": expected["pid"]}))
