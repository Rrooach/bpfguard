#!/usr/bin/env python3
"""Guest-only short real diagnostic handshake; never a slowdown benchmark."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

from diagnostics import Diagnostics, _line, sampler_options


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def freeze(cgroup, frozen):
    (cgroup / 'cgroup.freeze').write_text(str(int(frozen)))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if dict(line.split() for line in (cgroup / 'cgroup.events').read_text().splitlines()).get('frozen') == str(int(frozen)):
            return
        time.sleep(.01)
    raise TimeoutError('smoke freeze boundary did not settle')


def worker(path):
    payload = path.read_bytes()
    begin = time.process_time()
    value = 0
    while time.process_time() - begin < .65:
        value += sum(payload[:8192])
    print(json.dumps({'pid': os.getpid(), 'tid': os.getpid(), 'cpu_seconds': time.process_time() - begin,
                      'input_sha256': hashlib.sha256(payload).hexdigest(), 'result': value}), flush=True)


def trial(root, config, sampler_binary, mode):
    output = root / mode
    output.mkdir()
    cgroup = Path('/sys/fs/cgroup') / ('diag-smoke-' + mode + '-' + uuid.uuid4().hex[:10])
    cgroup.mkdir()
    expected_inode = cgroup.stat().st_ino
    child = sampler = diagnostic = None
    handles = []
    report = {'mode': mode, 'status': 'STARTING', 'scope': 'REAL_COLLECTOR_HANDSHAKE_NOT_OVERHEAD_OR_BENCHMARK_SCORE',
              'cgroup': str(cgroup), 'cgroup_inode': expected_inode}
    try:
        stdout = (output / 'workload.stdout').open('xb')
        stderr = (output / 'workload.stderr').open('xb')
        handles.extend((stdout, stderr))
        child = os.fork()
        if child == 0:
            try:
                os.setsid()
                os.dup2(stdout.fileno(), 1)
                os.dup2(stderr.fileno(), 2)
                os.kill(os.getpid(), signal.SIGSTOP)
                os.execv(sys.executable, [sys.executable, '-B', __file__, '--worker', str(root / 'input.bin')])
            except BaseException:
                os._exit(127)
        waited, stopped = os.waitpid(child, os.WUNTRACED)
        if waited != child or not os.WIFSTOPPED(stopped):
            raise RuntimeError('smoke workload failed stopped-launch barrier')
        (cgroup / 'cgroup.procs').write_text(str(child))
        freeze(cgroup, True)
        diagnostic = Diagnostics({**config, 'mode': mode}, output / 'diagnostics', cgroup, output.parent.name + '-' + mode)
        diagnostic.start()
        err = (output / 'sampler.stderr').open('xb')
        handles.append(err)
        command = [sampler_binary, '--output-dir', str(output / 'load'), '--cgroup', str(cgroup),
                   '--label', output.parent.name + '-' + mode, '--interval-ms', '100',
                   '--process-interval-ms', '100', '--exit-with-parent', *sampler_options({**config, 'mode': mode})]
        report['sampler_command'] = command
        sampler = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err)
        if _line(sampler.stdout.fileno(), 40) != b'READY\n':
            raise RuntimeError('smoke sampler not READY')
        meta = json.loads((output / 'load/load-meta.json').read_text())
        if (len(meta.get('cgroups', [])) != 1 or meta['cgroups'][0]['inode'] != expected_inode or
                meta['cgroups'][0]['path'] != str(cgroup)):
            raise RuntimeError('smoke sampler target identity mismatch')
        report['sampler_ready_bound'] = True
        if mode == 'kernel':
            if not meta.get('kernel_hist') or not meta.get('thread_sampling', {}).get('schedstats_runtime_enabled_at_start'):
                raise RuntimeError('real kernel/thread diagnostics not enabled')
        os.kill(child, signal.SIGCONT)
        report['released_ns'] = time.monotonic_ns()
        freeze(cgroup, False)
        _, status = os.waitpid(child, 0)
        child = None
        report['completed_ns'] = time.monotonic_ns()
        report['workload_returncode'] = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
        if report['workload_returncode']:
            raise RuntimeError('smoke workload failed')
        freeze(cgroup, True)
        report['diagnostics'] = diagnostic.finish()
        if report['diagnostics']['status'] != 'COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE':
            report['status'] = 'INCOMPLETE_DIAGNOSTIC_HEALTH'
        else:
            report['status'] = 'PASS_FOR_REAL_READY_FINISH_HANDSHAKE'
        # Ensure at least one real sample after the completed workload.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            rows = [json.loads(row) for row in (output / 'load/load-samples.jsonl').read_text().splitlines()]
            if rows[-1]['monotonic_ns'] > report['completed_ns']:
                break
            time.sleep(.02)
        else:
            raise TimeoutError('smoke has no post-workload resource sample')
        sampler.terminate()
        if sampler.wait(timeout=20):
            raise RuntimeError('smoke sampler finalization failed')
        report['sampler_stats'] = json.loads((output / 'load/load-sampler-stats.json').read_text())
        report['sampler_meta'] = meta
    except BaseException as error:
        report['status'] = 'FAILED'
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        if child is not None:
            try:
                os.kill(child, signal.SIGKILL)
                freeze(cgroup, False)
                os.waitpid(child, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
        if sampler is not None and sampler.poll() is None:
            sampler.terminate()
            try:
                sampler.wait(timeout=20)
            except subprocess.TimeoutExpired:
                sampler.kill()
                sampler.wait(timeout=5)
        if sampler is not None and sampler.stdout is not None:
            sampler.stdout.close()
        if diagnostic is not None and diagnostic.started and not diagnostic.finished:
            try:
                freeze(cgroup, True)
                report['cleanup_diagnostics'] = diagnostic.finish()
            except BaseException as error:
                report['cleanup_error'] = str(error)
        for handle in handles:
            handle.close()
        if cgroup.stat().st_ino != expected_inode:
            report['cleanup_error'] = 'owned cgroup identity changed; not removed'
        elif dict(line.split() for line in (cgroup / 'cgroup.events').read_text().splitlines()).get('populated') == '0':
            cgroup.rmdir()
            report['owned_cgroup_removed'] = True
        else:
            report['cleanup_error'] = 'owned cgroup unexpectedly populated; not removed'
        write(output / 'smoke.json', report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', type=Path)
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker)
        return
    vendor = ' '.join(path.read_text() for path in (Path('/sys/class/dmi/id/product_name'), Path('/sys/class/dmi/id/sys_vendor'))
                      if path.exists()).lower()
    if not any(value in vendor for value in ('qemu', 'kvm')):
        raise RuntimeError('real diagnostic smoke must run in the experiment Guest')
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'input.bin').write_bytes(bytes(range(256)) * 4096)
    assets = json.loads(args.assets.read_text())
    artifacts = json.loads(args.artifacts.read_text())
    sampler = Path(artifacts['sampler_binary'])
    if hashlib.sha256(sampler.read_bytes()).hexdigest() != artifacts['sampler_sha256']:
        raise RuntimeError('sampler binary pin mismatch')
    results = [trial(args.output, assets, str(sampler), mode) for mode in ('files', 'perf', 'kernel')]
    summary = {'scope': 'REAL_READY_FINISH_HANDSHAKE_NOT_BENCHMARK_OR_OVERHEAD',
               'results': [{key: result.get(key) for key in ('mode', 'status', 'error', 'cleanup_error', 'owned_cgroup_removed')} for result in results]}
    write(args.output / 'summary.json', summary)
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
