#!/usr/bin/env python3
"""Privileged owned-Guest conformance: known bytes, aliases, threads and faults."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time
import uuid

_original_path = list(sys.path)
try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'search-profile'))
    import cache_probe
    import access_search
finally:
    sys.path[:] = _original_path


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def validate_raw(path, inode, device):
    reads, faults, mm_faults, opens, invalid = [], [], [], [], []
    with path.open('rb') as stream:
        while True:
            raw = stream.read(192)
            if not raw:
                break
            if (len(raw) != 192 or struct.unpack_from('<IHHI', raw)[:2] != (0x46414343, 1)
                    or struct.unpack_from('<I', raw, 8)[0] != 192):
                raise ValueError('Malformed fixed event')
            kind = struct.unpack_from('<H', raw, 6)[0]
            flags = struct.unpack_from('<I', raw, 12)[0]
            event_inode = struct.unpack_from('<Q', raw, 96)[0]
            event_device = struct.unpack_from('<I', raw, 160)[0]
            result = struct.unpack_from('<q', raw, 128)[0]
            if kind == 1 and not flags & 1 and result == -9:
                invalid.append(raw)
            if (event_inode, event_device) != (inode, device):
                continue
            if kind in (1, 2): reads.append(raw)
            if kind == 4: opens.append(raw)
            if kind == 5: faults.append(raw)
            if kind == 6: mm_faults.append(raw)
    returned = sum(struct.unpack_from('<q', row, 128)[0] for row in reads)
    tids = {struct.unpack_from('<I', row, 172)[0] for row in reads}
    if len(reads) != 9 or returned != 438 or len(tids) != 3:
        raise ValueError('Known READ bytes/calls/threads differ: ' + repr((len(reads), returned, len(tids))))
    if len(opens) != 1 or not invalid or len(faults) < 1 or len(mm_faults) < 4:
        raise ValueError('Open, invalid-fd or mapped-page evidence missing: ' +
                         repr((len(opens), len(invalid), len(faults), len(mm_faults))))
    if any(struct.unpack_from('<Q', row, 64)[0] < struct.unpack_from('<Q', row, 56)[0]
           for row in reads + faults + mm_faults + opens):
        raise ValueError('Event time went backwards')
    return {'fixture_read_calls': len(reads), 'fixture_returned_bytes': returned,
        'reader_thread_instances': len(tids), 'fixture_successful_opens': len(opens),
        'fixture_filemap_fault_attempts': len(faults),
        'fixture_mm_fault_attempts': len(mm_faults), 'invalid_fd_reads': len(invalid)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profiler', type=Path, required=True)
    parser.add_argument('--bpf-object', type=Path, required=True)
    parser.add_argument('--workload', type=Path, required=True)
    parser.add_argument('--backend', choices=('fentry', 'kprobe-tracefs'), default='fentry')
    args = parser.parse_args()
    cache_probe._ensure_guest()
    args.output.mkdir(mode=0o700)
    fixture = args.output / 'fixture.bin'
    with fixture.open('xb') as stream:
        stream.write(bytes(i % 251 for i in range(16384)))
        stream.flush()
        os.fsync(stream.fileno())
    info = fixture.stat()
    group = Path('/sys/fs/cgroup') / ('access-calibration-' + uuid.uuid4().hex)
    group.mkdir()
    inode = group.stat().st_ino
    child, collector, stderr = None, None, None
    try:
        child = os.fork()
        if child == 0:
            os.setsid()
            with (args.output / 'workload.stdout').open('xb') as output:
                os.dup2(output.fileno(), 1)
                os.kill(os.getpid(), signal.SIGSTOP)
                os.execv(str(args.workload), [str(args.workload), str(fixture)])
            os._exit(127)
        waited, state = os.waitpid(child, os.WUNTRACED)
        if waited != child or not os.WIFSTOPPED(state):
            raise RuntimeError('Workload did not stop')
        (group / 'cgroup.procs').write_text(str(child))
        stderr = (args.output / 'collector.stderr').open('xb')
        command = [str(args.profiler), '--cgroup', str(group), '--output-dir', str(args.output / 'trace'),
            '--bpf-object', str(args.bpf_object), '--bpf-sha256', hashlib.sha256(args.bpf_object.read_bytes()).hexdigest(),
            '--run-id', args.output.name, '--max-seconds', '60', '--max-bytes', str(128 * 1024 ** 2),
            '--backend', args.backend]
        collector = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr)
        ready = access_search.read_ready(collector)
        write(args.output / 'ready.json', ready)
        release = time.monotonic_ns()
        os.kill(child, signal.SIGCONT)
        deadline = time.monotonic() + 30
        while True:
            waited, state = os.waitpid(child, os.WNOHANG)
            if waited:
                child = None
                if not os.WIFEXITED(state) or os.WEXITSTATUS(state):
                    raise RuntimeError('Calibration workload failed: ' + str(state))
                break
            if time.monotonic() > deadline:
                raise TimeoutError('Calibration workload timed out')
            time.sleep(.01)
        end = time.monotonic_ns()
        if 'populated 1' in (group / 'cgroup.events').read_text():
            raise RuntimeError('Descendants remain')
        collector.send_signal(signal.SIGTERM)
        if collector.wait(timeout=30):
            raise RuntimeError('Collector failed finalization')
        final = json.loads((args.output / 'trace/final.json').read_bytes())
        result = validate_raw(args.output / 'trace/events.bin', info.st_ino,
            os.major(info.st_dev) << 20 | os.minor(info.st_dev))
        if final['observation_health'] != 'COMPLETE_FOR_SELECTED_HOOKS':
            raise ValueError('Collector incomplete: ' + json.dumps(final))
        result.update(status='PASS', release_ns=release, end_ns=end,
            backend=args.backend,
            boot_id=ready['boot_id'], cgroup={'path': str(group), 'inode': inode},
            workload_sha256=hashlib.sha256(args.workload.read_bytes()).hexdigest(),
            fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
            calibration_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            scope='Deterministic native READ/readv bytes, alias, EOF, invalid FD, threads and mapped-file fault attempts; not performance')
        write(args.output / 'validation.json', result)
        print(json.dumps(result))
    finally:
        if child is not None:
            try:
                os.killpg(child, signal.SIGKILL)
                os.waitpid(child, 0)
            except (ProcessLookupError, ChildProcessError): pass
        if collector is not None and collector.poll() is None:
            collector.send_signal(signal.SIGTERM)
            collector.wait(timeout=30)
        if stderr: stderr.close()
        if group.stat().st_ino != inode:
            raise RuntimeError('Owned cgroup identity changed')
        group.rmdir()


if __name__ == '__main__':
    main()
