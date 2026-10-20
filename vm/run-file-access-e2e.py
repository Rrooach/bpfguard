#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot a private initramfs and check live access accounting, without root/SSH."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

PROJECT = Path(__file__).resolve().parents[1]


def copy_binary(source, destination, root):
    shutil.copy2(source, destination)
    dependencies = subprocess.run(
        ["ldd", str(source)], capture_output=True, text=True, check=False
    )
    for name in re.findall(r"(?:=>\s+)?(/[^\s]+)", dependencies.stdout):
        library = Path(name)
        target = root / library.relative_to("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(library, target)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_report(report, mode):
    require(mode in {"user-input", "kernel-file-open-partial", "kernel-file-open-write-partial",
                     "kernel-object-expanded-partial"}, "unknown object-resolution mode")
    require(report["profile"] == "file-access", "report profile differs")
    require(report["unmatched_attempts"] == report["unmatched_results"] == 0,
            "unmatched file-access syscall events")
    require(not report["truncated_wal_tail"], "truncated WAL tail")
    require(report["event_sequence_gap_runs"] == 0, "WAL sequence gap")
    require(report["disclosed_correlation_failure_events"] == 0
            and report["disclosed_object_failure_events"] == 0, "disclosed collection failure")
    require(report["recorded_pairing_status"] == "PAIRED_RECORDED_EVENTS_ONLY_NOT_COVERAGE_PROOF",
            "recorded pairing is incomplete")
    require(report["run_verification"].startswith("NOT_PERFORMED"),
            "diagnostic report must not impersonate run verification")
    calls = report["calls"]
    require(all(c["duration_ns"] is not None and c["duration_ns"] >= 0 for c in calls),
            "missing or negative syscall duration")
    require(report["totals"]["failed_calls"] >= 2, "failed fixture calls missing")
    require(any(c["syscall"] == "read" and c["requested_bytes"] == 32
                and c["actual_bytes"] == 13 for c in calls), "short read result missing")
    require(any(c["syscall"] == "read" and c["actual_bytes"] == 0 for c in calls), "EOF missing")
    require(any(c["syscall"] == "read" and c["return_value"] == -9
                and c["actual_bytes"] is None for c in calls), "failed read bytes invented")
    for name in ["readv", "preadv", "preadv2", "writev", "pwritev", "pwritev2"]:
        require(any(c["syscall"] == name and c["actual_bytes"] == 5
                    and c["requested_bytes"] is None for c in calls), "vector result missing: " + name)
    if mode == "user-input":
        require(report["unique_file_objects"] == 0, "user-input invented object identities")
        return
    files = {p["display"]: f for f in report["files"] for p in f["observed_paths"]}
    a, b = files["/tmp/file-access/a"], files["/tmp/file-access/b"]
    require(files["/tmp/file-access/alias"] is a, "hard-link aliases must deduplicate")
    require(a is not b, "reused fd must not merge different inodes")
    if mode == "kernel-file-open-partial":
        require(a["totals"]["bytes_read"] == a["totals"]["bytes_written"] == 0,
                "open-only mode invented I/O object accounting")
        return
    require(a["totals"]["bytes_read"] == 37 and a["totals"]["bytes_written"] == 25,
            "first file byte accounting differs from fixture")
    require(b["totals"]["bytes_read"] == 3 and b["totals"]["bytes_written"] == 3,
            "reused-fd file byte accounting differs from fixture")
    require(report["unique_files"] >= 2, "named objects missing")
    require(report["unique_anonymous_pseudo_files"] >= 1, "stdout pipe identity missing")
    require(report["anonymous_file_totals"]["bytes_written"] == 23, "stdout bytes misaccounted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path, help="BTF + BPF LSM bzImage")
    parser.add_argument("--observer", type=Path, default=PROJECT / ".output/cargo-target/release/bpf-state-observer")
    parser.add_argument("--recorder-object", type=Path, default=PROJECT / ".output/system_effects.bpf.o")
    parser.add_argument("--lifecycle-object", type=Path, default=PROJECT / ".output/process_lifecycle.bpf.o")
    parser.add_argument("--workload", type=Path, default=PROJECT / ".output/workloads/file-access-smoke")
    parser.add_argument("--busybox", type=Path, default=Path(shutil.which("busybox") or "/bin/busybox"))
    parser.add_argument("--object-resolution", default="kernel-file-open-write-partial", choices=[
        "user-input", "kernel-file-open-partial", "kernel-file-open-write-partial", "kernel-object-expanded-partial"
    ])
    parser.add_argument("--output-dir", type=Path, default=PROJECT / ".output/file-access-e2e")
    parser.add_argument("--timeout-sec", type=int, default=240)
    args = parser.parse_args()
    expanded = args.object_resolution == "kernel-object-expanded-partial"
    sources = [args.kernel, args.observer, args.recorder_object, args.workload, args.busybox]
    if expanded:
        sources.append(args.lifecycle_object)
    for source in sources:
        if not source.is_file():
            parser.error(f"missing input: {source}")
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    root = out / "root"
    for directory in ["bin", "proc", "sys", "dev", "tmp", "run", "lib64", "etc", "opt"]:
        (root / directory).mkdir(parents=True, exist_ok=True)
    copy_binary(args.busybox.resolve(), root / "bin/busybox", root)
    for name in ["sh", "mount", "mkdir", "cat", "poweroff", "sha256sum"]:
        (root / "bin" / name).symlink_to("busybox")
    copy_binary(args.observer.resolve(), root / "opt/observer", root)
    copy_binary(args.workload.resolve(), root / "opt/workload", root)
    shutil.copy2(args.recorder_object, root / "opt/recorder.o")
    if expanded:
        shutil.copy2(args.lifecycle_object, root / "opt/lifecycle.o")
    lifecycle_observe = ('--process-lifecycle-object /opt/lifecycle.o '
                         '--expected-process-lifecycle-sha256 "$lifecycle_sha"') if expanded else ''
    lifecycle_verify = '--expected-process-lifecycle-sha256 "$lifecycle_sha"' if expanded else ''
    init = '''#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /sys/fs/cgroup /sys/kernel/security /sys/fs/bpf /sys/kernel/tracing
mount -t tracefs tracefs /sys/kernel/tracing
mount -t cgroup2 none /sys/fs/cgroup
mount -t securityfs none /sys/kernel/security
mount -t bpf bpf /sys/fs/bpf
ulimit -l unlimited
set -e
sha=$(sha256sum /opt/recorder.o)
sha=${sha%% *}
lifecycle_sha=$(sha256sum /opt/lifecycle.o 2>/dev/null || true)
lifecycle_sha=${lifecycle_sha%% *}
/opt/observer observe-effects --recorder-object /opt/recorder.o --expected-recorder-sha256 "$sha" --output-dir /run/access --run-id access --profile file-access --object-resolution __MODE__ __LIFECYCLE_OBSERVE__ --timeout-ms 60000 -- /opt/workload /tmp/file-access
/opt/observer verify-effects --run-dir /run/access --expected-recorder-sha256 "$sha" --expected-profile file-access --expected-object-resolution __MODE__ __LIFECYCLE_VERIFY__
/opt/observer file-access-report --wal /run/access/system-effects.raw.bin > /run/report.json
cat /run/access/workload.stdout
echo FILE_ACCESS_REPORT_BEGIN
cat /run/report.json
echo FILE_ACCESS_REPORT_END
echo FILE_ACCESS_E2E_OK
poweroff -f
'''
    init = init.replace("__MODE__", args.object_resolution).replace(
        "__LIFECYCLE_OBSERVE__", lifecycle_observe).replace("__LIFECYCLE_VERIFY__", lifecycle_verify)
    (root / "init").write_text(init)
    (root / "init").chmod(0o755)
    archive = out / "initramfs.cpio"
    files = ["."] + [str(p.relative_to(root)) for p in sorted(root.rglob("*"))]
    with archive.open("wb") as output:
        subprocess.run(["cpio", "-o", "--format=newc", "--quiet"],
                       input="\n".join(files).encode() + b"\n", cwd=root, stdout=output, check=True)
    command = ["qemu-system-x86_64", "-accel", "tcg", "-m", "2048", "-smp", "2",
               "-kernel", str(args.kernel.resolve()), "-initrd", str(archive), "-append",
               "console=ttyS0 rdinit=/init panic=-1 loglevel=3 lsm=lockdown,yama,integrity,apparmor,bpf",
               "-display", "none", "-serial", "stdio", "-monitor", "none", "-nic", "none", "-no-reboot"]
    print(f"Starting disposable TCG VM; console: {out / 'console.log'}", flush=True)
    with (out / "console.log").open("w") as output:
        try:
            subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                           timeout=args.timeout_sec, check=True)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
            raise SystemExit(f"QEMU failed; inspect {out / 'console.log'}: {error}")
    log = (out / "console.log").read_text()
    if "FILE_ACCESS_E2E_OK" not in log:
        raise SystemExit(f"Guest failed; inspect {out / 'console.log'}\n{log[-10000:]}")
    report = json.loads(log.split("FILE_ACCESS_REPORT_BEGIN", 1)[1].split("FILE_ACCESS_REPORT_END", 1)[0])
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    validate_report(report, args.object_resolution)
    print(f"PASS ({args.object_resolution}): bytes/latency, short I/O, EOF, errors, vector variants and file identity; {out / 'report.json'}")


if __name__ == "__main__":
    main()
