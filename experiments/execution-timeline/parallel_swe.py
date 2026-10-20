#!/usr/bin/env python3
"""One isolated SWE Verified reference job for a fixed-eight-job campaign.

The pinned official run_instance and tests are unchanged. Docker Exec transport
is gated so the actual pytest root, not the Docker client, is registered before
release. No model, provider credential, network pull or legacy state confirmer
is used. Every job must run in its own OS process: the official harness uses
process-global hooks and working directories.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import namedtuple
import importlib.metadata
import importlib.util
import json
import logging
import os
from pathlib import Path
import re
import selectors
import shutil
import shlex
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

from common import digest, write_new
from terminal_validate import DockerAPI, GatedExec, frozen_baseline_threads, proc_identity, write_json


INSTANCE = 'psf__requests-1142'
EVENT_BYTES = 688
RING_BYTES = 64 * 1024 * 1024
ExecResult = namedtuple('ExecResult', 'exit_code output')


class InfrastructureError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise InfrastructureError(message)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def command_text(command):
    if isinstance(command, (tuple, list)):
        require(command and all(isinstance(value, str) and '\0' not in value for value in command),
                'Docker exec argv must contain NUL-free strings')
        command = shlex.join(command)
    require(isinstance(command, str) and command and '\0' not in command and len(command.encode()) <= 1024 * 1024,
            'bounded nonempty Docker exec command required')
    return command


def environment_dict(value):
    if value is None:
        return None
    if isinstance(value, list):
        pairs = [entry.split('=', 1) for entry in value if isinstance(entry, str) and '=' in entry]
        require(len(pairs) == len(value) and len({pair[0] for pair in pairs}) == len(pairs),
                'ambiguous Docker exec environment')
        value = dict(pairs)
    require(isinstance(value, dict) and all(isinstance(key, str) and key and '=' not in key and '\0' not in key
            and isinstance(item, str) and '\0' not in item for key, item in value.items()), 'invalid Docker exec environment')
    return value


class SDKExecEnvironment:
    """Match Docker SDK exec argv parsing, without adding a login shell/profile.

    GatedExec normally mirrors Harbor's bash -lc transport. SWE's official SDK
    exec_run instead shlex-splits a string or executes its argv directly. The
    stopped /bin/sh gate must exec those same argv, not source extra profiles.
    """
    task_env_config = SimpleNamespace(workdir=None)
    def __init__(self):
        self._platform = SimpleNamespace(exec_shell_args=self.exec_argv)
    @staticmethod
    def exec_argv(command):
        values = shlex.split(command)
        require(values and all('\0' not in value for value in values), 'empty or invalid official exec argv')
        return values
    @staticmethod
    def _merge_env(value):
        return value
    @staticmethod
    def _resolve_user(value):
        return value


def merged_frames(raw):
    """Preserve Docker stdout/stderr frame order and raw bytes for official SDK semantics."""
    require(isinstance(raw, bytes) and len(raw) <= 64 * 1024 * 1024, 'bounded raw Docker output required')
    chunks, offset = [], 0
    while offset < len(raw):
        require(len(raw) - offset >= 8, 'truncated Docker output header')
        stream, padding, length = raw[offset], raw[offset + 1:offset + 4], struct.unpack_from('>I', raw, offset + 4)[0]
        offset += 8
        require(stream in (1, 2) and padding == b'\0\0\0' and offset + length <= len(raw), 'invalid Docker output frame')
        chunks.append(raw[offset:offset + length])
        offset += length
    return b''.join(chunks)


class RecordingDocker(DockerAPI):
    def __init__(self, socket_path='/var/run/docker.sock'):
        super().__init__(socket_path)
        self.outputs = {}

    def request(self, method, path, data=None, **kwargs):
        value = super().request(method, path, data, **kwargs)
        if method == 'POST' and path.startswith('/exec/') and path.endswith('/start') and kwargs.get('raw') is True:
            self.outputs[path.split('/')[2]] = value
        return value

    def take_output(self, exec_id):
        require(exec_id in self.outputs, 'Docker exec output was not bound to its actual Exec ID')
        return self.outputs.pop(exec_id)


class GatedContainer:
    """Only the prepared container is proxied; original archive/copy APIs remain SDK calls."""
    def __init__(self, container, gate, test_gate, docker_api, manifest, timeout=300):
        self.original, self.gate, self.test_gate = container, gate, test_gate
        self.docker_api, self.manifest, self.timeout = docker_api, manifest, timeout
        self.infrastructure_error = None
        self.test_timeouts = 0
        self.cleanup_requested_ns = None
        self.started = False

    def __getattr__(self, name):
        return getattr(self.original, name)

    def start(self):
        # The same official idle image was started, frozen and instrumented
        # BEFORE READY. Do not launch another container in the measured window.
        self.original.reload()
        require(self.original.attrs.get('State', {}).get('Running') is True, 'prepared official container no longer running')
        require(not self.started, 'official container start called twice')
        self.started = True

    def _run(self, command, *, test=False, timeout=None, **options):
        try:
            unsupported = set(options) - {'workdir', 'user', 'environment', 'stdout', 'stderr', 'tty', 'stream', 'socket', 'demux', 'detach', 'stdin', 'privileged'}
            require(not unsupported, 'unsupported Docker exec options: ' + ','.join(sorted(unsupported)))
            require(all(options.get(name, False) is False for name in ('tty', 'stream', 'socket', 'demux', 'detach', 'stdin', 'privileged')),
                    'interactive, detached, privileged or streaming exec is outside the reviewed SWE transport')
            require(options.get('stdout', True) is True and options.get('stderr', True) is True,
                    'official output channels cannot be suppressed')
            command = command_text(command)
            env = environment_dict(options.get('environment'))
            selected = self.test_gate if test else self.gate
            count = len(self.manifest['tools'])
            result = asyncio.run(selected(command=command, cwd=options.get('workdir'), user=options.get('user'),
                env=env, timeout_sec=timeout or self.timeout))
            require(type(result.return_code) is int, 'Docker gated exec lacks final integer status')
            require(len(self.manifest['tools']) == count + 1, 'exactly one root must be enrolled per official exec')
            entry = self.manifest['tools'][-1]
            require(isinstance(entry.get('docker_exec_id'), str), 'gated exec did not bind Docker Exec ID')
            return ExecResult(result.return_code, merged_frames(self.docker_api.take_output(entry['docker_exec_id'])))
        except (TimeoutError, asyncio.TimeoutError) as error:
            released = self.manifest['tools'][count:] if 'count' in locals() else []
            if not released or not all(type(entry.get('begin_ns')) is int and entry['begin_ns'] > 0 for entry in released):
                self.infrastructure_error = 'STOP_GATE_TIMEOUT_BEFORE_BOUND_RELEASE: ' + str(error)
                raise InfrastructureError(self.infrastructure_error) from error
            if test:
                self.test_timeouts += 1
            raise
        except BaseException as error:
            self.infrastructure_error = type(error).__name__ + ': ' + str(error)
            raise

    def exec_run(self, cmd, **options):
        return self._run(cmd, **options)

    def exec_test_with_timeout(self, command, timeout):
        require(timeout is not None and 0 < float(timeout) <= 3600, 'bounded official test timeout required')
        begin = time.monotonic_ns()
        try:
            result = self._run(command, test=True, timeout=float(timeout))
            return result.output.decode('utf-8'), False, (time.monotonic_ns() - begin) / 1e9
        except (TimeoutError, asyncio.TimeoutError):
            # A timeout is not test success. DONE is still forbidden until a
            # separate frozen closure proves no nonbaseline live threads.
            return '', True, (time.monotonic_ns() - begin) / 1e9


def validate_ready(ready, boot, cgroup_id):
    require(isinstance(ready, dict) and ready.get('status') == 'READY' and ready.get('schema_version') == 1
        and all(type(ready.get(name)) is int for name in ('schema_version', 'event_bytes', 'root_cgroup_id', 'timestamp_ns'))
        and ready['timestamp_ns'] > 0
        and ready.get('event_bytes') == EVENT_BYTES and ready.get('boot_id') == boot
        and ready.get('root_cgroup_id') == cgroup_id and ready.get('clock') == 'CLOCK_MONOTONIC',
        'native READY ABI/boot/cgroup/clock binding differs; no fallback')
    return ready


def read_ready(process, timeout=30):
    deadline, value = time.monotonic() + timeout, bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                continue
            data = os.read(process.stdout.fileno(), 4096)
            require(data, 'native collector closed stdout before READY')
            value.extend(data)
            require(len(value) <= 64 * 1024, 'native READY exceeded protocol bound')
            if b'\n' in value:
                require(value.count(b'\n') == 1 and value.endswith(b'\n'), 'native READY has extra protocol records')
                return json.loads(value)
    raise InfrastructureError('native READY timeout')


def validate_image(image, reference, provenance):
    repository = reference.rsplit(':', 1)[0]
    pinned = provenance.get('pinned_reference', '')
    require(re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', pinned) is not None,
            'image provenance does not bind the exact official task repository')
    require(provenance.get('image_config_digest') == image.id, 'actual local Docker image differs from pinned config digest')
    require(provenance.get('manifest_sha256') == pinned.rsplit(':', 1)[1], 'image manifest provenance differs')
    return {'reference': reference, 'id': image.id, 'repo_digests': image.attrs.get('RepoDigests', []),
            'size_bytes': image.attrs.get('Size'), 'import_provenance': provenance, 'download': 'NO_PULL_LOCAL_PINNED_IMAGE_ONLY'}


def official_reference(official, spec, row, client, proxy, output, run_id, timeout, *, model_label='oracle-reference'):
    """Process-local transport hooks. This function must never run in a thread pool."""
    saved = official.build_container, official.cleanup_container, official.exec_run_with_timeout, Path.cwd()
    def build(*_args, **_kwargs):
        return proxy
    def cleanup(_client, container, _logger):
        require(container is proxy or container is None, 'official cleanup named an unexpected container')
        proxy.cleanup_requested_ns = time.monotonic_ns()
    def timed(container, command, timeout):
        require(container is proxy, 'official test named an unexpected container')
        return proxy.exec_test_with_timeout(command, timeout)
    official.build_container, official.cleanup_container, official.exec_run_with_timeout = build, cleanup, timed
    try:
        os.chdir(output)
        result = official.run_instance(spec, {'instance_id': row['instance_id'],
            'model_name_or_path': model_label, 'model_patch': row['patch']}, False, False, client, run_id, timeout)
    finally:
        official.build_container, official.cleanup_container, official.exec_run_with_timeout = saved[:3]
        os.chdir(saved[3])
    require(proxy.infrastructure_error is None, 'official harness caught a transport/identity failure: ' + str(proxy.infrastructure_error))
    if result is None:
        return {'instance_id': row['instance_id'], 'report': None, 'resolved': False,
                'status': 'NO_OFFICIAL_REPORT_TASK_FAILED', 'test_timeouts': proxy.test_timeouts}
    require(isinstance(result, tuple) and len(result) == 2 and result[0] == row['instance_id'] and isinstance(result[1], dict),
            'official harness returned an unexpected task/report identity')
    resolved = result[1].get(row['instance_id'], {}).get('resolved') is True and proxy.test_timeouts == 0
    return {'instance_id': result[0], 'report': result[1], 'resolved': resolved,
            'status': 'OFFICIAL_RESULT', 'test_timeouts': proxy.test_timeouts}


class TimelineSession:
    def __init__(self, args, container, bridge, image_info):
        self.args, self.container, self.bridge, self.image_info = args, container, bridge, image_info
        self.directory = args.output / 'timeline'
        self.directory.mkdir(mode=0o700)
        self.process = self.stderr = None
        self.paused = False
        self.postprocessing_authorized = False
        self.manifest = None
        self.target = None
        self.docker = RecordingDocker(args.docker_socket)

    def _check_target(self):
        require(self.group.stat().st_ino == self.target['cgroup_inode'] and self.group.stat().st_dev == self.target['cgroup_device'],
                'container cgroup identity changed')
        actual = proc_identity(self.target['init']['tid'])
        require((actual['tid'], actual['start_ticks']) == (self.target['init']['tid'], self.target['init']['start_ticks']),
                'container init lifetime changed')
        require(self.bridge.parse_proc_cgroup(Path('/proc', str(actual['tid']), 'cgroup').read_text()) == self.target['cgroup_path'],
                'container init moved cgroups')

    def freeze(self, frozen):
        if frozen != self.paused:
            self.container.pause() if frozen else self.container.unpause()
            self.paused = frozen
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            self._check_target()
            fields = dict(line.split() for line in (self.group / 'cgroup.events').read_text().splitlines())
            if fields.get('frozen') == str(int(frozen)):
                return
            time.sleep(.005)
        raise InfrastructureError('container freeze/unfreeze did not settle')

    def prepare(self):
        self.container.reload()
        require(re.fullmatch(r'[0-9a-f]{64}', self.container.id) is not None, 'full Docker container identity required')
        pid = self.container.attrs['State']['Pid']
        require(type(pid) is int and pid > 0 and self.container.attrs['State']['Running'] is True, 'official idle container did not start')
        cgpath = self.bridge.parse_proc_cgroup(Path('/proc', str(pid), 'cgroup').read_text())
        require(self.bridge.cgroup_binds_container(cgpath, self.container.id), 'exact container cgroup binding missing')
        self.group = Path('/sys/fs/cgroup', cgpath.lstrip('/'))
        self.target = {'container_id': self.container.id, 'init': proc_identity(pid), 'cgroup_path': cgpath,
            'cgroup_inode': self.group.stat().st_ino, 'cgroup_device': self.group.stat().st_dev,
            'namespace': {name: Path('/proc', str(pid), 'ns', name).stat().st_ino for name in ('mnt', 'pid', 'user', 'net')},
            'image_id': self.image_info['id']}
        self.freeze(True)
        write_new(self.directory / 'target.json', self.target)
        pinned = self.directory / 'pinned-artifacts'
        pinned.mkdir(mode=0o700)
        copies = {}
        for name, source in (('collect', self.args.collector), ('execution_timeline.bpf.o', self.args.object)):
            source = source.resolve(strict=True)
            before = digest(source)
            shutil.copy2(source, pinned / name)
            require(digest(source) == before == digest(pinned / name), 'native asset changed during pinning')
            copies[name] = before
        self.collector = (pinned / 'collect').resolve()
        self.object = (pinned / 'execution_timeline.bpf.o').resolve()
        tested = subprocess.run([str(self.collector), '--self-test'], capture_output=True, timeout=30, check=True)
        native_test = json.loads(tested.stdout)
        require(native_test.get('schema_version') == 1 and native_test.get('event_bytes') == EVENT_BYTES
            and type(native_test.get('schema_version')) is int and type(native_test.get('event_bytes')) is int
            and native_test.get('status') == 'SELF_TEST_PASSED_SYNTHETIC_ONLY', 'unsupported native event ABI')
        write_new(self.directory / 'native-self-test.json', native_test)
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.stderr = (self.directory / 'collector.stderr').open('xb')
        self.process = subprocess.Popen([str(self.collector), '--object', str(self.object), '--cgroup', str(self.group),
            '--output-dir', str(self.directory / 'capture'), '--ring-bytes', str(RING_BYTES), '--kernel-stacks'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr, bufsize=0)
        ready = validate_ready(read_ready(self.process), boot, self.target['cgroup_inode'])
        write_new(self.directory / 'ready.json', ready)
        meta = json.loads((self.directory / 'capture/meta.json').read_bytes())
        require(meta.get('event_bytes') == EVENT_BYTES and meta.get('ring_bytes') == RING_BYTES
            and meta.get('json_projection') == 'AFTER_DETACH' and meta.get('kernel_stacks') is True,
            'capture profile differs from fixed-eight constant recorder contract')
        shutil.copyfile('/proc/kallsyms', self.directory / 'kallsyms.txt')
        baseline = frozen_baseline_threads(self.group)
        write_new(self.directory / 'baseline-threads.json', baseline)
        write_new(self.directory / 'tool-spans.jsonl', b'')
        self.manifest = {'schema_version': 1, 'run_id': 'swe-timeline-' + self.args.job_id + '-' + uuid.uuid4().hex,
            'boot_id': boot, 'agent_id': 'oracle-reference:' + self.args.job_id, 'task_id': INSTANCE,
            'agent_scope': 'FIXED_REFERENCE_PATCH_AND_OFFICIAL_TESTS_NOT_MODEL_AGENT_SCORE',
            'scope': {'kind': 'DOCKER_GATED_EXEC'}, 'begin_ns': time.monotonic_ns(), 'end_ns': None,
            'cgroup_root': str(self.group), 'cgroup_id': self.target['cgroup_inode'], 'container_id': self.container.id,
            'namespace': self.target['namespace'], 'collector_ready': ready, 'baseline_threads': baseline,
            'tools': [], 'artifacts': {}, 'capture_directory': 'capture',
            'collector_binary': str(self.collector), 'collector_identity': copies['collect'],
            'bpf_object': str(self.object), 'bpf_object_identity': copies['execution_timeline.bpf.o'],
            'capture_options': {'ring_bytes': RING_BYTES, 'kernel_stacks': True, 'json_projection': 'AFTER_DETACH',
                'scope': 'ONE_OF_EIGHT_ALWAYS_READY_CONTAINER_COLLECTORS; NO_LEGACY_STATE_CONFIRMERS'}}
        self.persist()
        general = GatedExec(self.docker, self.container.id, cgpath, self.manifest, self.directory,
            environment=SDKExecEnvironment(), agent_id=self.manifest['agent_id'],
            tool_prefix=self.args.job_id + '-reference', kind='OFFICIAL_REFERENCE_EVALUATION')
        test = GatedExec(self.docker, self.container.id, cgpath, self.manifest, self.directory,
            environment=SDKExecEnvironment(), agent_id=self.manifest['agent_id'],
            tool_prefix=self.args.job_id + '-test', kind='OFFICIAL_TEST_EXEC')
        return GatedContainer(self.container, general, test, self.docker, self.manifest, self.args.test_timeout)

    def persist(self):
        write_json(self.directory / 'manifest.json', self.manifest, replace=(self.directory / 'manifest.json').exists())

    def quiesce(self):
        require(self.process.poll() is None, 'collector exited during official workload')
        self.freeze(True)
        closure = frozen_baseline_threads(self.group)
        original = {(row['tid'], row['start_ticks']) for row in self.manifest['baseline_threads']}
        candidates = [row for row in closure if (row['tid'], row['start_ticks']) not in original]
        self.manifest['closure'] = {'frozen': True, 'monotonic_ns': time.monotonic_ns(), 'threads': closure,
            'nonbaseline_thread_candidates': candidates, 'meaning': 'CONFIRMED_FROZEN_WITH_NO_NONBASELINE_LIVE_THREADS_REQUIRED'}
        write_new(self.directory / 'closure-threads.json', self.manifest['closure'])
        require(not candidates, 'nonbaseline live threads remain; cannot publish quiescent DONE')
        self.manifest['end_ns'] = time.monotonic_ns()
        self.persist()
        return self.manifest['end_ns']

    def stop(self):
        require(self.postprocessing_authorized and self.paused and self.process.poll() is None,
                'STOP requires frozen live collector after all-jobs barrier')
        self._check_target()
        self.process.stdin.write(b'STOP\n')
        self.process.stdin.flush()
        self.process.stdin.close()
        require(self.process.wait(timeout=300) == 0, 'native collector failed finalization')
        self.stderr.close()
        self.manifest['collector_return_code'] = self.process.returncode
        files = list((self.directory / 'capture').iterdir()) + [self.directory / name for name in
            ('kallsyms.txt', 'target.json', 'tool-spans.jsonl', 'ready.json', 'collector.stderr',
             'baseline-threads.json', 'closure-threads.json', 'native-self-test.json')]
        self.manifest['artifacts'] = {str(path.relative_to(self.directory)): digest(path) for path in files if path.is_file()}
        self.persist()
        # Native schema1 explicitly limits this verdict to selected hooks. It
        # never emits a whole-Agent/whole-system "COMPLETE" status.
        require(json.loads((self.directory / 'capture/health.json').read_bytes()).get('status') == 'COMPLETE_FOR_SELECTED_HOOKS',
                'capture health is incomplete; no green worker result')

    def close(self):
        errors = []
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
        except BaseException as error:
            errors.append('collector: ' + str(error))
        for stream in (self.stderr, getattr(self.process, 'stdin', None), getattr(self.process, 'stdout', None)):
            try:
                if stream is not None and not stream.closed:
                    stream.close()
            except BaseException as error:
                errors.append('stream: ' + str(error))
        try:
            if self.paused:
                self.container.unpause()
                self.paused = False
        except BaseException as error:
            errors.append('unpause: ' + str(error))
        finally:
            # Exact fresh container only; try removal even if unpause failed.
            try:
                self.container.remove(force=True)
            except BaseException as error:
                errors.append('remove: ' + str(error))
        require(not errors, '; '.join(errors))


def derive(session, official_passed):
    from export_reads import export_report
    from render import render_report
    from replay import verify_run
    from summarize import format_chinese, summarize_report
    directory = session.directory
    report = verify_run(directory, expected_manifest_sha256=digest(directory / 'manifest.json')['sha256'])
    write_new(directory / 'report.json', report)
    summary = summarize_report(report)
    report_binding = digest(directory / 'report.json')
    summary['source_report'] = {'path': str((directory / 'report.json').resolve()),
        'sha256': report_binding['sha256'], 'bytes': report_binding['size_bytes']}
    write_new(directory / 'summary.json', summary)
    write_new(directory / 'summary.txt', format_chinese(summary).encode())
    write_new(directory / 'timeline.html', render_report(report).encode())
    export_report(report, directory / 'read-tables', summary['source_report'])
    test_tools = [tool for tool in report['tools'] if tool.get('tool_kind') == 'OFFICIAL_TEST_EXEC']
    test_root_keys = {tool.get('root_key') for tool in test_tools}
    issues = []
    if not test_tools or None in test_root_keys:
        issues.append('OFFICIAL_PYTEST_ROOT_NOT_BOUND')
    if len(test_tools) != 1 or any(tool.get('command') != '/bin/bash /eval.sh' for tool in test_tools):
        issues.append('PINNED_OFFICIAL_TEST_COMMAND_NOT_ESTABLISHED')
    if summary['selected_tool_timeline_status'] != 'COMPLETE_WITHIN_SELECTED_TOOL_SCOPE':
        issues.append('SELECTED_TOOL_TIMELINE_INCOMPLETE')
    timeline_status = 'PASS_WITHIN_SELECTED_MODEL' if not issues else 'INCOMPLETE'
    goal = {'schema_version': 1, 'status': 'OFFICIAL_TASK_FAILED' if not official_passed else timeline_status,
        'timeline_status': timeline_status,
        'official_passed': official_passed, 'mode': 'ORACLE_REFERENCE', 'run_id': report['run']['run_id'],
        'test_tool_ids': [tool['tool_call_id'] for tool in test_tools], 'issues': issues,
        'scope': 'OFFICIAL_REFERENCE_EVALUATION; NOT_MODEL_SCORE_OR_WHOLE_CGROUP_ATTRIBUTION'}
    write_new(directory / 'goal.json', goal)
    return goal


def run_worker(args):
    from phase_control import Control, job_name
    job_name(args.job_id)
    # run_instance changes cwd; all live manifest/ledger paths must remain
    # absolute. absolute() intentionally does not follow a destination symlink.
    args.output = args.output.absolute()
    control = Control(args.control_dir, args.job_id)
    result = {'schema_version': 1, 'benchmark': 'SWE-bench Verified', 'job_id': args.job_id, 'task_id': INSTANCE,
        'mode': 'ORACLE_REFERENCE', 'distinct_task_count': 1, 'paid_api_calls': 0, 'timeline_directory': 'timeline',
        'official_passed': False, 'official_result': {}, 'agent_return_ns': None, 'quiescent_ns': None,
        'capture_status': 'NOT_CAPTURED', 'status': 'INITIALIZING', 'errors': [],
        'timing_scope': 'RELEASE_TO_OFFICIAL_RUN_INSTANCE_RETURN_INCLUDES_PATCH_TESTS_AND_OFFICIAL_GRADING; PREPARE_AND_POSTPROCESS_SEPARATE'}
    session = container = client = None
    output_created = False
    try:
        vendor = ' '.join(Path('/sys/class/dmi/id', name).read_text(errors='replace') for name in ('sys_vendor', 'product_name'))
        require(os.geteuid() == 0 and any(value in vendor.lower() for value in ('qemu', 'kvm', 'bochs')),
                'run this worker only as root inside the owned experimental QEMU Guest')
        require(not args.output.exists() and not args.output.is_symlink(), 'worker output must be fresh')
        args.output.mkdir(parents=True, mode=0o700)
        output_created = True
        adapter = load_module('parallel_swe_provenance_adapter', args.swe_adapter)
        bridge = load_module('parallel_swe_container_identity_bridge', args.bridge)
        require(importlib.metadata.version('swebench') == adapter.HARNESS_VERSION, 'installed official harness version differs')
        provenance = json.loads((args.inputs / 'provenance.json').read_bytes())
        require(digest(args.inputs / 'task.json')['sha256'] == provenance['task_sha256'], 'prepared task digest differs')
        row = adapter.validate_task(json.loads((args.inputs / 'task.json').read_bytes()), provenance)
        require(row['instance_id'] == INSTANCE, 'this campaign admits only the pinned prepared Requests task')
        write_new(args.output / 'harness-runtime.json', adapter.validate_installed_harness(args.inputs, provenance))
        write_new(args.output / 'provenance.json', provenance)
        result['source_identity'] = {name: digest(path) for name, path in
            (('worker', Path(__file__)), ('swe_adapter', args.swe_adapter), ('bridge', args.bridge),
             ('task', args.inputs / 'task.json'), ('provenance', args.inputs / 'provenance.json'),
             ('image_import_provenance', args.image_import_provenance))}
        import docker
        from swebench.harness import run_evaluation as official
        from swebench.harness.test_spec.test_spec import make_test_spec
        spec = make_test_spec(row, namespace='swebench', instance_image_tag='latest')
        client = docker.from_env(timeout=600)
        image = client.images.get(spec.instance_image_key)  # no pull in worker or timing window
        image_info = validate_image(image, spec.instance_image_key, json.loads(args.image_import_provenance.read_bytes()))
        write_new(args.output / 'image.json', image_info)
        result['image_identity'] = image_info
        run_id = 'parallel-' + args.job_id + '-' + uuid.uuid4().hex[:12]
        logger = logging.getLogger('parallel-swe-prepare-' + args.job_id)
        container = official.build_container(spec, client, run_id, logger, False, False)
        container.start()
        session = TimelineSession(args, container, bridge, image_info)
        proxy = session.prepare()
        session.manifest['worker_source_identity'] = result['source_identity']
        session.persist()
        release = control.ready_sync({'benchmark': result['benchmark'], 'job_id': args.job_id, 'task_id': INSTANCE,
            'mode': 'ORACLE_REFERENCE', 'run_id': session.manifest['run_id'], 'target': session.target,
            'boot_id': session.manifest['boot_id'], 'cgroup_root': str(session.group),
            'cgroup_id': session.target['cgroup_inode'],
            'collector_identity': session.manifest['collector_identity'], 'bpf_object_identity': session.manifest['bpf_object_identity'],
            'ring_bytes': RING_BYTES, 'profile': 'EIGHT_ALWAYS_READY_NATIVE_TIMELINE_COLLECTORS', 'image_id': image.id})
        result['release_observed_ns'] = release['observed_ns']
        result['workload_begin_ns'] = time.monotonic_ns()
        session.freeze(False)
        official_dir = args.output / 'official'
        official_dir.mkdir()
        evaluated = official_reference(official, spec, row, client, proxy, official_dir, run_id, args.test_timeout)
        result['agent_return_ns'] = time.monotonic_ns()
        result['official_result'] = evaluated
        result['official_passed'] = evaluated['resolved'] is True
        write_new(args.output / 'official-result.json', evaluated)
        result['quiescent_ns'] = session.quiesce()
        result['capture_status'] = 'FROZEN_QUIESCENT_AWAITING_ALL_JOBS'
        write_new(args.output / 'workload-result.json', result)
        post = control.done_sync({'agent_return_ns': result['agent_return_ns'], 'quiescent_ns': result['quiescent_ns'],
            'quiescent': True, 'official_passed': result['official_passed'], 'mode': 'ORACLE_REFERENCE',
            'run_id': session.manifest['run_id'], 'container_id': container.id, 'nonbaseline_live_threads': 0})
        result['all_agents_done_observed_ns'] = post['observed_ns']
        session.postprocessing_authorized = True
        result['capture_finalize_begin_ns'] = time.monotonic_ns()
        session.stop()
        result['capture_status'] = 'CAPTURED_COMPLETE_PENDING_INDEPENDENT_REPLAY'
        if not args.capture_only:
            goal = derive(session, result['official_passed'])
            result['timeline_goal'] = goal
            result['capture_status'] = 'VERIFIED_WITHIN_SELECTED_SCOPE' if goal['timeline_status'] == 'PASS_WITHIN_SELECTED_MODEL' else 'VERIFIED_WITH_DECLARED_GAPS'
        result['status'] = 'COMPLETED' if result['official_passed'] else 'COMPLETED_OFFICIAL_TASK_FAILED'
    except BaseException as error:
        result['status'], result['capture_status'] = 'INFRASTRUCTURE_ERROR', 'FAILED_OR_INCOMPLETE_CAPTURE'
        result['errors'].append(type(error).__name__ + ': ' + str(error))
        control.fail(result['errors'][-1])
    finally:
        try:
            if session is not None:
                session.close()
            elif container is not None:
                container.remove(force=True)
        except BaseException as error:
            result['errors'].append('cleanup: ' + type(error).__name__ + ': ' + str(error))
            result['status'] = 'INFRASTRUCTURE_ERROR'
            control.fail(result['errors'][-1])
        if client is not None:
            client.close()
        result['worker_end_ns'] = time.monotonic_ns()
        if output_created:
            write_new(args.output / 'worker-result.json', result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return int(bool(result['errors']))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--bridge', type=Path, required=True)
    parser.add_argument('--swe-adapter', type=Path, required=True)
    parser.add_argument('--collector', type=Path, required=True)
    parser.add_argument('--object', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--control-dir', type=Path, required=True)
    parser.add_argument('--job-id', required=True)
    parser.add_argument('--image-import-provenance', type=Path, required=True)
    parser.add_argument('--test-timeout', type=int, default=300)
    parser.add_argument('--docker-socket', default='/var/run/docker.sock')
    parser.add_argument('--capture-only', action='store_true', help='defer report/HTML/CSV to independent Host replay after raw finalization')
    args = parser.parse_args(argv)
    if not 1 <= args.test_timeout <= 3600:
        parser.error('test timeout must be within1..3600 seconds')
    return run_worker(args)


if __name__ == '__main__':
    raise SystemExit(main())
