#!/usr/bin/env python3
"""Actual bounded file-object diagnostic calibration, inside QEMU only."""
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


def write(path, value):
    with Path(path).open('x') as out:
        json.dump(value, out, indent=2)
        out.write('\n')


def wait_ready(process, seconds=30):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('file profiler exited before READY')
            for key, _ in selector.select(0.1):
                if key.fileobj.readline().strip() == 'READY':
                    return
        raise RuntimeError('file profiler READY timeout')
    finally:
        selector.close()


def check(profile, expected, inode, domain_ids):
    rows = [r for r in profile['records'] if r['object']['inode'] == inode]
    if profile['observation_health'] != 'COMPLETE_FOR_SELECTED_HOOKS':
        raise ValueError('selected file hooks incomplete: ' + json.dumps(profile['health']))
    for domain in domain_ids:
        selected = [r for r in rows if r['domain_id'] == domain]
        actual = sum(r['returned_bytes'] for r in selected)
        if actual != expected['returned_file_bytes']:
            raise ValueError('returned bytes differ: %s != %s' % (actual, expected['returned_file_bytes']))
        readv = [r for r in selected if r['operation'] == 'readv_or_preadv']
        if sum(r['calls'] for r in readv) != 3:
            raise ValueError('readv/preadv/preadv2 were not all observed')
        mmap = [r for r in selected if r['operation'] == 'file_mmap']
        if sum(r['calls'] for r in mmap) != expected.get('mmap_calls', 1) or any(r['returned_bytes'] for r in mmap):
            raise ValueError('mapping observation wrong or mmap bytes fabricated')
        if 'mmap_errors' in expected and (sum(r['errors'] for r in mmap) != expected['mmap_errors']
                or sum(r['success_calls'] for r in mmap) != expected['mmap_success']):
            raise ValueError('resolved mmap success/error classification differs')
        directories = [r for r in profile['records']
                       if r['domain_id'] == domain and r['operation'] == 'directory_iteration']
        if not directories or any(r['returned_bytes'] for r in directories):
            raise ValueError('directory hook absent or directory bytes fabricated')
        threads = {r['thread']['tid'] for r in selected if r['operation'] == 'read_or_pread'}
        if len(threads) != 3:
            raise ValueError('main and two worker TID instances not distinguished')
    return {'status': 'PASS', 'domains': len(domain_ids),
            'expected_file_bytes_per_domain': expected['returned_file_bytes'],
            'actual_file_bytes': sum(r['returned_bytes'] for r in rows),
            'coverage': ['read', 'pread64', 'readv', 'preadv', 'preadv2',
                         'file mmap identity and classified success/error, zero access bytes',
                         'directory iteration, zero directory bytes', 'distinct main/worker thread identities']}


def run(args):
    vendor = ' '.join(p.read_text() for p in (Path('/sys/class/dmi/id/product_name'),
                                            Path('/sys/class/dmi/id/sys_vendor')) if p.exists()).lower()
    if not any(v in vendor for v in ('qemu', 'kvm')):
        raise ValueError('calibration must run in target QEMU Linux, not physical host')
    out = Path(args.output).absolute()
    out.mkdir()
    fixture = out / 'fixture.bin'
    fixture.write_bytes(bytes(range(256)) * 16)
    inode = fixture.stat().st_ino
    parent = Path('/sys/fs/cgroup') / ('file-profile-' + uuid.uuid4().hex[:12])
    parent.mkdir()
    roots, workers, root_ids = [], [], {}
    parent_id = parent.stat().st_ino
    collector = None
    try:
        for i in range(2):
            root = parent / ('agent-' + str(i))
            root.mkdir()
            roots.append(root)
            root_ids[str(root)] = root.stat().st_ino
            child = os.fork()
            if child == 0:
                try:
                    os.setsid()
                    with (out / ('workload-%d.json' % i)).open('x') as stream:
                        os.dup2(stream.fileno(), 1)
                        os.kill(os.getpid(), signal.SIGSTOP)
                        os.execv(args.workload, [args.workload, str(fixture), str(out)])
                except BaseException:
                    os._exit(127)
            workers.append(child)
            waited, status = os.waitpid(child, os.WUNTRACED)
            if waited != child or not os.WIFSTOPPED(status):
                raise RuntimeError('workload did not stop')
            (root / 'cgroup.procs').write_text(str(child))
        command = [args.profiler, '--output-dir', str(out / 'profile'),
                   '--bpf-object', args.bpf_object, '--bpf-sha256',
                   hashlib.sha256(Path(args.bpf_object).read_bytes()).hexdigest(),
                   '--max-seconds', '60', '--label', out.name]
        for root in roots:
            command += ['--cgroup', str(root)]
        with (out / 'collector.stderr').open('x') as stderr:
            collector = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr, text=True)
            wait_ready(collector)
            for worker in workers:
                os.kill(worker, signal.SIGCONT)
            while workers:
                worker = workers.pop(0)
                _, status = os.waitpid(worker, 0)
                if os.waitstatus_to_exitcode(status) != 0:
                    raise RuntimeError('workload failed')
            if any('populated 1' in (r / 'cgroup.events').read_text() for r in roots):
                raise RuntimeError('workload descendants remain')
            collector.send_signal(signal.SIGTERM)
            if collector.wait(timeout=15):
                raise RuntimeError('collector finalization failed')
        profile = json.loads((out / 'profile/file-profile.json').read_text())
        expected = json.loads((out / 'workload-0.json').read_text())
        if json.loads((out / 'workload-1.json').read_text()) != expected:
            raise ValueError('calibration workloads differ')
        result = check(profile, expected, inode, [r.stat().st_ino for r in roots])
        result['profiler_sha256'] = hashlib.sha256(Path(args.profiler).read_bytes()).hexdigest()
        result['bpf_sha256'] = hashlib.sha256(Path(args.bpf_object).read_bytes()).hexdigest()
        write(out / 'validation.json', result)
        print(json.dumps(result))
    finally:
        for worker in workers:
            try:
                os.kill(worker, signal.SIGKILL)
                os.waitpid(worker, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
        if collector and collector.poll() is None:
            collector.send_signal(signal.SIGTERM)
            try:
                collector.wait(timeout=15)
            except subprocess.TimeoutExpired:
                collector.kill()
                collector.wait()
        for root in reversed(roots):
            if root.stat().st_ino != root_ids[str(root)]:
                raise RuntimeError('owned cgroup identity changed; refusing cleanup')
            if (root / 'cgroup.events').read_text().startswith('populated 0'):
                root.rmdir()
        if parent.stat().st_ino == parent_id and not any(root.exists() for root in roots):
            parent.rmdir()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--profiler', required=True)
    parser.add_argument('--bpf-object', required=True)
    parser.add_argument('--workload', required=True)
    run(parser.parse_args())
