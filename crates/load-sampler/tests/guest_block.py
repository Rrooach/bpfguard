#!/usr/bin/env python3
"""Small cooperative fdatasync/block diagnostic control in a disposable VM.

Block hooks are explicitly system scoped. This fixture does not attribute
writeback or flush requests to the child and does not infer missing queue spans.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
import uuid


def wait_until(predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise RuntimeError('block calibration barrier timed out')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sampler', type=Path, required=True)
    parser.add_argument('--object', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    product = Path('/sys/class/dmi/id/product_name').read_text().lower()
    if not any(value in product for value in ('qemu', 'kvm', 'standard pc')):
        parser.error('only run this mutating control inside a disposable QEMU/KVM Guest')
    args.output.mkdir(mode=0o700)
    group = Path('/sys/fs/cgroup') / ('block-cal-' + uuid.uuid4().hex)
    data = args.output / 'owned-fdatasync-data'
    child = sampler = None
    files = []
    group.mkdir()
    group_inode = group.stat().st_ino
    try:
        worker = """import os, signal, sys, json, time
os.kill(os.getpid(), signal.SIGSTOP)
begin = time.monotonic_ns()
fd = os.open(sys.argv[1], os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
for i in range(8):
    assert os.write(fd, bytes([i]) * 32768) == 32768
    os.fdatasync(fd)
os.close(fd)
print(json.dumps({'write_calls':8,'write_bytes':262144,'fdatasync_calls':8,
                  'start_ns':begin,'end_ns':time.monotonic_ns()}))
"""
        out = (args.output / 'workload.jsonl').open('wb')
        err = (args.output / 'workload.stderr').open('wb')
        files += [out, err]
        child = subprocess.Popen(['python3', '-c', worker, str(data.resolve())], stdout=out, stderr=err)
        wait_until(lambda: Path('/proc/%d/stat' % child.pid).read_text().rsplit(')', 1)[1].split()[0] == 'T')
        (group / 'cgroup.procs').write_text(str(child.pid))
        stderr = (args.output / 'sampler.stderr').open('wb')
        files.append(stderr)
        digest = hashlib.sha256(args.object.read_bytes()).hexdigest()
        command = [str(args.sampler.resolve()), '--output-dir', str(args.output / 'load'),
                   '--interval-ms', '50', '--process-interval-ms', '50', '--cgroup', str(group),
                   '--kernel-hist-object', str(args.object.resolve()), '--kernel-hist-sha256', digest,
                   '--kernel-hist-groups', 'blk', '--label', 'system-block-fdatasync-control']
        sampler = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr)
        selector = selectors.DefaultSelector()
        selector.register(sampler.stdout, selectors.EVENT_READ)
        ready, deadline = bytearray(), time.monotonic() + 30
        while b'READY\n' not in ready:
            if sampler.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('sampler did not reach READY')
            for key, _ in selector.select(0.1):
                ready += os.read(key.fd, 4096)
        selector.close()
        time.sleep(0.1)
        before = time.monotonic_ns()
        os.kill(child.pid, signal.SIGCONT)
        assert child.wait(timeout=30) == 0
        after = time.monotonic_ns()
        assert 'populated 0' in (group / 'cgroup.events').read_text()
        time.sleep(0.2)
        sampler.send_signal(signal.SIGTERM)
        assert sampler.wait(timeout=30) == 0
        for stream in files:
            stream.flush()
        meta = json.loads((args.output / 'load/load-meta.json').read_text())
        stats = json.loads((args.output / 'load/load-sampler-stats.json').read_text())
        diag = stats['kernel_hist']['block_diagnostics']
        assert diag['version'] == 1 and diag['scope'] == 'SYSTEM_UNATTRIBUTED'
        assert diag['counters']['request_read_failed'] == 0
        assert diag['flush_service']['count'] > 0, 'this environment did not exercise a supported zero-byte FLUSH'
        assert diag['counters']['flush_completed'] >= diag['flush_service']['count']
        programs = stats['kernel_hist']['programs']
        assert all(program['recursion_misses'] == 0 for program in programs)
        expected = b''.join(bytes([i]) * 32768 for i in range(8))
        assert data.read_bytes() == expected
        verdict = {'schema_version':1,'status':'PASS_WITH_BLOCK_BOUNDARIES_EXPLICIT',
                   'boot_id':meta['boot_id'],'object_sha256':digest,
                   'workload_window_ns':[before,after],
                   'expected_write_bytes':len(expected),'successful_fdatasync_calls':8,
                   'fixture_content_sha256':hashlib.sha256(expected).hexdigest(),
                   'block_diagnostics':diag,'measurement_recursion_misses':0,
                   'limits':['system-wide block observations are not attributed to the child',
                             'queue span without insert remains UNKNOWN; never represented by zero',
                             'untracked completions remain UNKNOWN even if flags suggest sequencing',
                             'bounded samples are not a full request history',
                             'fdatasync success does not prove power-loss durability']}
        (args.output / 'validation.json').write_text(json.dumps(verdict, indent=2) + '\n')
        print(json.dumps({'status':verdict['status'],'flush_service_count':diag['flush_service']['count'],
                          'untracked_complete':diag['counters']['untracked_complete'],
                          'queue_span_unknown':diag['counters']['queue_span_unknown']}))
    finally:
        for process in (child, sampler):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
        for stream in files:
            stream.close()
        if group.exists() and group.stat().st_ino == group_inode:
            group.rmdir()


if __name__ == '__main__':
    main()
