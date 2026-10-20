#!/usr/bin/env python3
"""SWE transport/control contracts without Docker, Guest, BPF attach or API calls."""
import asyncio
from contextlib import redirect_stdout
import io
import functools
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import threading
import tempfile
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

import parallel_swe as M
import phase_control
import terminal_validate as T


def frame(stream, body):
    return bytes((stream, 0, 0, 0)) + struct.pack('>I', len(body)) + body


class FakeDocker:
    def __init__(self):
        self.outputs = {}
    def take_output(self, key):
        return self.outputs.pop(key)


class FakeGate:
    def __init__(self, manifest, docker, label, error=None, released_error=False):
        self.manifest, self.docker, self.label, self.error = manifest, docker, label, error
        self.released_error = released_error
        self.calls = []
    async def __call__(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            if self.released_error:
                self.manifest['tools'].append({'begin_ns': time.monotonic_ns(), 'result': {'error': 'runtime timeout'}})
            raise self.error
        key = '{:064x}'.format(len(self.manifest['tools']) + 1)
        self.manifest['tools'].append({'docker_exec_id': key, 'tool_kind': self.label})
        self.docker.outputs[key] = frame(1, b'first\n') + frame(2, b'error\n') + frame(1, b'last\n')
        return SimpleNamespace(return_code=0, stdout='first\nlast\n', stderr='error\n')


def proxy(error=None, released_error=False):
    container = mock.Mock()
    container.attrs = {'State': {'Running': True}}
    manifest, docker = {'tools': []}, FakeDocker()
    general, test = FakeGate(manifest, docker, 'general'), FakeGate(manifest, docker, 'test', error, released_error)
    return M.GatedContainer(container, general, test, docker, manifest), general, test


class TransportTests(unittest.TestCase):
    def test_sdk_result_preserves_real_output_frame_order_and_bytes(self):
        container, general, test = proxy()
        result = container.exec_run(['printf', '%s', 'a b'], workdir='/testbed', user='root', environment=['A=x=y'])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output, b'first\nerror\nlast\n')
        self.assertEqual(general.calls[0]['command'], "printf %s 'a b'")
        self.assertEqual(general.calls[0]['cwd'], '/testbed')
        self.assertEqual(general.calls[0]['env'], {'A': 'x=y'})
        self.assertEqual(test.calls, [])

    def test_actual_official_test_uses_test_gate_not_docker_client_only(self):
        container, general, test = proxy()
        output, timed_out, duration = container.exec_test_with_timeout('/bin/bash /eval.sh', 30)
        self.assertEqual(output, 'first\nerror\nlast\n')
        self.assertFalse(timed_out)
        self.assertGreaterEqual(duration, 0)
        self.assertEqual(general.calls, [])
        self.assertEqual(test.calls[0]['command'], '/bin/bash /eval.sh')
        self.assertEqual(test.calls[0]['timeout_sec'], 30)
        self.assertEqual(container.manifest['tools'][0]['tool_kind'], 'test')

    def test_test_gate_timeout_returns_official_failure_not_success(self):
        container, general, test = proxy(TimeoutError('runtime test timeout'), released_error=True)
        output, timed_out, _ = container.exec_test_with_timeout('/bin/bash /eval.sh', 1)
        self.assertEqual(output, '')
        self.assertTrue(timed_out)
        self.assertEqual(container.test_timeouts, 1)
        self.assertEqual(len(container.manifest['tools']), 1)
        self.assertIsNone(container.infrastructure_error)

    def test_startup_gate_timeout_is_infrastructure_not_failed_pytest(self):
        container, _, _ = proxy(TimeoutError('STOP root never appeared'))
        with self.assertRaisesRegex(M.InfrastructureError, 'BEFORE_BOUND_RELEASE'):
            container.exec_test_with_timeout('/bin/bash /eval.sh', 1)
        self.assertEqual(container.test_timeouts, 0)
        self.assertIsNotNone(container.infrastructure_error)

    def test_identity_or_transport_failure_is_fatal_even_if_official_catches_it(self):
        container, _, _ = proxy(ValueError('wrong cgroup'))
        with self.assertRaisesRegex(ValueError, 'cgroup'):
            container.exec_test_with_timeout('/bin/bash /eval.sh', 1)
        self.assertIn('wrong cgroup', container.infrastructure_error)

    def test_unsupported_detached_or_privileged_exec_is_not_silently_accepted(self):
        for options in ({'detach': True}, {'privileged': True}, {'stream': True}, {'demux': True}, {'extra': 1}):
            container, general, _ = proxy()
            with self.assertRaises(M.InfrastructureError):
                container.exec_run('true', **options)
            self.assertEqual(general.calls, [])
            self.assertIsNotNone(container.infrastructure_error)

    def test_truncated_or_invalid_docker_stream_cannot_be_success(self):
        for raw in (b'x', frame(3, b'x'), frame(1, b'abc')[:-1], b'\1\1\0\0\0\0\0\0'):
            with self.assertRaises(M.InfrastructureError):
                M.merged_frames(raw)
        self.assertEqual(M.merged_frames(frame(1, b'\xff')), b'\xff')

    def test_command_and_environment_are_strict(self):
        for value in ('', 'a\0b', [], ['ok', 1]):
            with self.assertRaises(M.InfrastructureError):
                M.command_text(value)
        for value in (['A=1', 'A=2'], ['A'], {'A': 1}, {'A\0B': 'x'}):
            with self.assertRaises(M.InfrastructureError):
                M.environment_dict(value)

    def test_sdk_argv_semantics_do_not_source_an_extra_login_shell(self):
        environment = M.SDKExecEnvironment()
        self.assertEqual(environment.exec_argv('/bin/bash /eval.sh'), ['/bin/bash', '/eval.sh'])
        self.assertEqual(environment.exec_argv(M.command_text(['printf', '%s', 'a b'])), ['printf', '%s', 'a b'])
        self.assertEqual(environment.exec_argv('echo hi && pwd'), ['echo', 'hi', '&&', 'pwd'])
        self.assertIsNone(environment._merge_env(None))
        self.assertIsNone(environment._resolve_user(None))
        with self.assertRaises(M.InfrastructureError):
            environment.exec_argv('   ')

    def test_real_gated_exec_binds_stopped_pytest_pid_with_original_sdk_argv(self):
        class Docker:
            def __init__(self):
                self.released = threading.Event()
                self.finished = False
                self.created = None
                self.outputs = {}
            def request(self, method, path, data=None, **options):
                if path.endswith('/exec'):
                    self.created = data
                    return {'Id': 'a' * 64}
                if path.endswith('/start'):
                    if not self.released.wait(2):
                        raise TimeoutError('stopped root was never released')
                    value = frame(1, b'pytest passed\n')
                    self.outputs['a' * 64] = value
                    self.finished = True
                    return value
                if path.endswith('/json'):
                    return {'Pid': 123, 'Running': not self.finished, 'ExitCode': 0}
                raise AssertionError(path)
            def take_output(self, key):
                return self.outputs.pop(key)
        async def to_thread(function, *args, **kwargs):
            return await asyncio.get_running_loop().run_in_executor(None, functools.partial(function, *args, **kwargs))
        docker, manifest = Docker(), {'agent_id': 'oracle-reference:job-1', 'task_id': M.INSTANCE, 'tools': []}
        identity = {'tid': 123, 'state': 'T', 'start_ticks': 10}
        with tempfile.TemporaryDirectory() as tmp:
            gate = M.GatedExec(docker, 'b' * 64, '/docker/' + 'b' * 64, manifest, Path(tmp),
                environment=M.SDKExecEnvironment(), tool_prefix='job-1-test', kind='OFFICIAL_TEST_EXEC')
            def release(_fd, signum):
                self.assertEqual(signum, T.signal.SIGCONT)
                docker.released.set()
            with mock.patch.object(asyncio, 'to_thread', to_thread, create=True), \
                    mock.patch.object(T, 'proc_identity', return_value=identity), \
                    mock.patch.object(T, 'proc_cgroup', return_value='/docker/' + 'b' * 64), \
                    mock.patch.object(T, 'cgroup_inode', return_value=99), \
                    mock.patch.object(T, 'proc_affinity', return_value=[0, 1]), \
                    mock.patch.object(T.os, 'pidfd_open', return_value=77, create=True), \
                    mock.patch.object(T.signal, 'pidfd_send_signal', side_effect=release, create=True), \
                    mock.patch.object(T.os, 'close'):
                container = mock.Mock()
                proxy = M.GatedContainer(container, gate, gate, docker, manifest)
                output, timed_out, _ = proxy.exec_test_with_timeout('/bin/bash /eval.sh', 1)
            self.assertEqual(output, 'pytest passed\n')
            self.assertFalse(timed_out)
            self.assertEqual(docker.created['Cmd'], ['/bin/sh', '-c', 'kill -STOP $$ || exit 125; exec /bin/bash /eval.sh'])
            self.assertEqual(manifest['tools'][0]['root']['tid'], 123)
            self.assertEqual(manifest['tools'][0]['root']['start_ticks'], 10)
            self.assertEqual(manifest['tools'][0]['cgroup_id'], 99)
            self.assertEqual(manifest['tools'][0]['tool_call_id'], 'job-1-test-0001')
            self.assertEqual(manifest['tools'][0]['tool_kind'], 'OFFICIAL_TEST_EXEC')
            ledger = [json.loads(line) for line in (Path(tmp) / 'tool-spans.jsonl').read_text().splitlines()]
            self.assertEqual([row['event'] for row in ledger], ['TOOL_ENROLLED', 'TOOL_START', 'TOOL_END'])

    def test_prestarted_container_does_not_start_another_workload(self):
        container, _, _ = proxy()
        container.start()
        container.original.start.assert_not_called()
        with self.assertRaises(M.InfrastructureError):
            container.start()

    def test_recording_transport_binds_raw_to_exec_id(self):
        client = M.RecordingDocker('/fake/no-socket')
        raw = frame(1, b'x')
        with mock.patch.object(M.DockerAPI, 'request', return_value=raw):
            self.assertEqual(client.request('POST', '/exec/' + 'a' * 64 + '/start', {}, raw=True), raw)
        self.assertEqual(client.take_output('a' * 64), raw)
        with self.assertRaises(M.InfrastructureError):
            client.take_output('a' * 64)


class ProtocolTests(unittest.TestCase):
    def test_ready_requires_exact_native_abi_boot_group_clock(self):
        good = {'status': 'READY', 'schema_version': 1, 'event_bytes': 688, 'boot_id': 'boot',
            'root_cgroup_id': 99, 'clock': 'CLOCK_MONOTONIC', 'timestamp_ns': 123}
        self.assertEqual(M.validate_ready(good, 'boot', 99), good)
        for change in ({'schema_version': 2}, {'event_bytes': 192}, {'boot_id': 'wrong'},
                       {'root_cgroup_id': 100}, {'clock': 'CLOCK_REALTIME'}, {'status': 'FALLBACK'},
                       {'event_bytes': 688.0}, {'schema_version': True}, {'timestamp_ns': 0}):
            with self.assertRaises(M.InfrastructureError):
                M.validate_ready(dict(good, **change), 'boot', 99)

    def test_ready_partial_line_is_bounded_by_deadline(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; print("{",end="",flush=True);time.sleep(5)'], stdout=subprocess.PIPE)
        try:
            with self.assertRaisesRegex(M.InfrastructureError, 'timeout'):
                M.read_ready(child, .03)
        finally:
            child.terminate()
            child.wait(timeout=3)
            child.stdout.close()

    def test_ready_rejects_protocol_extra_records(self):
        child = subprocess.Popen([sys.executable, '-c', 'print("{}\\n{}")'], stdout=subprocess.PIPE)
        try:
            with self.assertRaises(M.InfrastructureError):
                M.read_ready(child)
        finally:
            child.wait(timeout=3)
            child.stdout.close()

    def test_image_is_local_and_exact_import_provenance_not_another_task(self):
        image = SimpleNamespace(id='sha256:' + '2' * 64, attrs={})
        repository = 'swebench/sweb.eval.x86_64.psf_1776_requests-1142'
        prov = {'pinned_reference': repository + '@sha256:' + '1' * 64,
            'manifest_sha256': '1' * 64, 'image_config_digest': image.id}
        self.assertEqual(M.validate_image(image, repository + ':latest', prov)['download'], 'NO_PULL_LOCAL_PINNED_IMAGE_ONLY')
        for change in ({'pinned_reference': 'wrong@sha256:' + '1' * 64}, {'image_config_digest': 'sha256:' + '3' * 64},
                       {'manifest_sha256': '4' * 64}):
            with self.assertRaises(M.InfrastructureError):
                M.validate_image(image, repository + ':latest', dict(prov, **change))

    def test_quiescent_done_is_impossible_with_nonbaseline_live_thread(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = object.__new__(M.TimelineSession)
            session.process = mock.Mock()
            session.process.poll.return_value = None
            session.freeze = mock.Mock()
            session.group, session.directory = Path('/fake/cgroup'), Path(tmp)
            baseline = {'tid': 1, 'start_ticks': 10}
            session.manifest = {'baseline_threads': [baseline], 'end_ns': None}
            session.persist = mock.Mock()
            with mock.patch.object(M, 'frozen_baseline_threads', return_value=[baseline, {'tid': 2, 'start_ticks': 20}]):
                with self.assertRaisesRegex(M.InfrastructureError, 'nonbaseline'):
                    session.quiesce()
            self.assertIsNone(session.manifest['end_ns'])
            session.persist.assert_not_called()
            self.assertEqual(json.loads((Path(tmp) / 'closure-threads.json').read_bytes())['nonbaseline_thread_candidates'][0]['tid'], 2)

    def test_stop_cannot_run_before_all_agents_done_release(self):
        session = object.__new__(M.TimelineSession)
        session.postprocessing_authorized = False
        session.paused = True
        session.process = mock.Mock()
        session.process.poll.return_value = None
        with self.assertRaisesRegex(M.InfrastructureError, 'all-jobs'):
            session.stop()
        session.process.stdin.write.assert_not_called()

    def test_stop_accepts_only_actual_native_selected_hook_health_status(self):
        for status in ('COMPLETE_FOR_SELECTED_HOOKS', 'INCOMPLETE', 'COMPLETE', None):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                capture = directory / 'capture'
                capture.mkdir()
                # A real native status is computed from transport/hook gaps;
                # the old generic COMPLETE string is not an accepted alias.
                (capture / 'health.json').write_text(json.dumps({'status': status}))
                session = object.__new__(M.TimelineSession)
                session.directory = directory
                session.postprocessing_authorized = session.paused = True
                session.process = mock.Mock()
                session.process.poll.return_value = None
                session.process.wait.return_value = session.process.returncode = 0
                session.stderr = mock.Mock()
                session._check_target = mock.Mock()
                session.manifest = {}
                session.persist = mock.Mock()
                if status == 'COMPLETE_FOR_SELECTED_HOOKS':
                    session.stop()
                else:
                    with self.assertRaisesRegex(M.InfrastructureError, 'health is incomplete'):
                        session.stop()
                session.process.stdin.write.assert_called_once_with(b'STOP\n')
                session.process.wait.assert_called_once_with(timeout=300)
                self.assertIn('capture/health.json', session.manifest['artifacts'])

    def test_cleanup_still_removes_only_owned_container_when_unpause_fails(self):
        session = object.__new__(M.TimelineSession)
        session.process = session.stderr = None
        session.paused = True
        session.container = mock.Mock()
        session.container.unpause.side_effect = RuntimeError('pause state changed')
        with self.assertRaises(M.InfrastructureError):
            session.close()
        session.container.remove.assert_called_once_with(force=True)


class OfficialHookTests(unittest.TestCase):
    def test_official_test_and_helpers_are_gated_hooks_restored_after_success(self):
        container, general, test = proxy()
        build, cleanup, timed = mock.Mock(), mock.Mock(), mock.Mock()
        official = SimpleNamespace(build_container=build, cleanup_container=cleanup, exec_run_with_timeout=timed)
        def run(spec, prediction, *_args):
            self.assertEqual(prediction['model_patch'], 'fixed official patch')
            self.assertIs(official.build_container(), container)
            container.start()
            container.exec_run('git apply /tmp/patch.diff', workdir='/testbed')
            output, timeout, _ = official.exec_run_with_timeout(container, '/bin/bash /eval.sh', 30)
            self.assertFalse(timeout)
            self.assertEqual(output, 'first\nerror\nlast\n')
            official.cleanup_container(None, container, None)
            return M.INSTANCE, {M.INSTANCE: {'resolved': True}}
        official.run_instance = run
        before = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            result = M.official_reference(official, object(), {'instance_id': M.INSTANCE, 'patch': 'fixed official patch'},
                object(), container, Path(tmp), 'run', 30)
        self.assertTrue(result['resolved'])
        self.assertEqual((len(general.calls), len(test.calls)), (1, 1))
        self.assertIsNotNone(container.cleanup_requested_ns)
        self.assertEqual(Path.cwd(), before)
        self.assertIs(official.build_container, build)
        self.assertIs(official.cleanup_container, cleanup)
        self.assertIs(official.exec_run_with_timeout, timed)
        container.original.remove.assert_not_called()

    def test_official_failure_or_caught_transport_error_never_becomes_resolved(self):
        for fatal in (False, True):
            container, _, _ = proxy()
            official = SimpleNamespace(build_container=mock.Mock(), cleanup_container=mock.Mock(), exec_run_with_timeout=mock.Mock(),
                run_instance=mock.Mock(return_value=None))
            if fatal:
                container.infrastructure_error = 'wrong root lifetime'
            with tempfile.TemporaryDirectory() as tmp:
                if fatal:
                    with self.assertRaisesRegex(M.InfrastructureError, 'transport/identity'):
                        M.official_reference(official, object(), {'instance_id': M.INSTANCE, 'patch': 'patch'}, None,
                            container, Path(tmp), 'run', 30)
                else:
                    result = M.official_reference(official, object(), {'instance_id': M.INSTANCE, 'patch': 'patch'}, None,
                        container, Path(tmp), 'run', 30)
                    self.assertIs(result['resolved'], False)

    def test_global_hooks_and_cwd_restored_on_exception(self):
        container, _, _ = proxy()
        official = SimpleNamespace(build_container=mock.Mock(), cleanup_container=mock.Mock(), exec_run_with_timeout=mock.Mock(),
            run_instance=mock.Mock(side_effect=ValueError('bad official result')))
        saved = official.build_container, official.cleanup_container, official.exec_run_with_timeout, Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, 'bad official'):
                M.official_reference(official, None, {'instance_id': M.INSTANCE, 'patch': 'patch'}, None,
                    container, Path(tmp), 'run', 30)
        self.assertEqual((official.build_container, official.cleanup_container, official.exec_run_with_timeout, Path.cwd()), saved)


class WorkerFlowTests(unittest.TestCase):
    def run_fake(self, *, resolved=True, infrastructure_error=False, preexisting=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = root / 'inputs'
            inputs.mkdir()
            (inputs / 'task.json').write_text(json.dumps([{'instance_id': M.INSTANCE, 'patch': 'gold'}]))
            (inputs / 'provenance.json').write_text(json.dumps({'task_sha256': M.digest(inputs / 'task.json')['sha256']}))
            for name in ('bridge.py', 'adapter.py'):
                (root / name).write_text('# safe local fixture\n')
            repository = 'swebench/sweb.eval.x86_64.psf_1776_requests-1142'
            image = SimpleNamespace(id='sha256:' + '2' * 64, attrs={})
            (root / 'image.json').write_text(json.dumps({'pinned_reference': repository + '@sha256:' + '1' * 64,
                'manifest_sha256': '1' * 64, 'image_config_digest': image.id}))
            args = SimpleNamespace(inputs=inputs, output=root / 'output', control_dir=root / 'control', job_id='job-1',
                swe_adapter=root / 'adapter.py', bridge=root / 'bridge.py', image_import_provenance=root / 'image.json',
                collector=root / 'collect', object=root / 'object', docker_socket='/fake/no-socket', test_timeout=30, capture_only=True)
            if preexisting:
                args.output.mkdir()
                (args.output / 'user.txt').write_text('keep')
            events, controls, ready_meta = [], [], []
            class FakeControl:
                def __init__(self, *_args, **_kwargs):
                    pass
                def ready_sync(self, value):
                    ready_meta.append(value)
                    events.append('READY')
                    return {'observed_ns': time.monotonic_ns()}
                def done_sync(self, value):
                    self.assert_quiet = value
                    if not value['quiescent']:
                        raise AssertionError('not quiet')
                    events.append('ALL_DONE')
                    return {'observed_ns': time.monotonic_ns()}
                def fail(self, value):
                    controls.append(value)
            class FakeSession:
                def __init__(self, _args, container, *_rest):
                    self.directory = args.output / 'timeline'
                    self.directory.mkdir()
                    self.target = {'cgroup_inode': 99}
                    self.group = Path('/sys/fs/cgroup/owned-fixture')
                    self.manifest = {'run_id': 'run', 'boot_id': 'boot', 'collector_identity': {}, 'bpf_object_identity': {}}
                def prepare(self):
                    events.append('CAPTURE_READY')
                    return object()
                def persist(self):
                    pass
                def freeze(self, frozen):
                    events.append('FREEZE' if frozen else 'UNFREEZE')
                def quiesce(self):
                    events.append('QUIESCENT')
                    return time.monotonic_ns()
                def stop(self):
                    if not self.postprocessing_authorized:
                        raise AssertionError('STOP before all done')
                    events.append('STOP_DECODE')
                def close(self):
                    events.append('CLEANUP_OWNED')
            container = mock.Mock()
            client = mock.Mock()
            client.images.get.return_value = image
            official = SimpleNamespace(build_container=mock.Mock(return_value=container))
            harness = ModuleType('swebench.harness')
            harness.run_evaluation = official
            spec_module = ModuleType('swebench.harness.test_spec.test_spec')
            spec_module.make_test_spec = lambda *_a, **_k: SimpleNamespace(instance_image_key=repository + ':latest')
            docker = ModuleType('docker')
            docker.from_env = mock.Mock(return_value=client)
            modules = {'docker': docker, 'swebench.harness': harness,
                'swebench.harness.test_spec.test_spec': spec_module}
            adapter = SimpleNamespace(HARNESS_VERSION='3.0.17', validate_task=lambda value, _prov: value[0],
                validate_installed_harness=lambda *_args: {'pinned': True})
            original_read_text = Path.read_text
            def read_text(path, *a, **kw):
                if str(path).startswith('/sys/class/dmi/id/'):
                    return 'QEMU'
                return original_read_text(path, *a, **kw)
            def evaluate(*_args):
                events.append('OFFICIAL_PATCH_AND_TESTS')
                if infrastructure_error:
                    raise M.InfrastructureError('identity conflict')
                return {'resolved': resolved, 'report': {M.INSTANCE: {'resolved': resolved}}}
            with mock.patch.dict(sys.modules, modules), mock.patch.object(phase_control, 'Control', FakeControl), \
                    mock.patch.object(M, 'TimelineSession', FakeSession), mock.patch.object(M, 'official_reference', side_effect=evaluate), \
                    mock.patch.object(M, 'load_module', side_effect=[adapter, object()]), \
                    mock.patch.object(M.importlib.metadata, 'version', return_value='3.0.17'), \
                    mock.patch.object(M.os, 'geteuid', return_value=0), mock.patch.object(Path, 'read_text', read_text), \
                    redirect_stdout(io.StringIO()):
                returned = M.run_worker(args)
            output = json.loads((args.output / 'worker-result.json').read_bytes()) if not preexisting else None
            if preexisting:
                self.assertEqual(list(path.name for path in args.output.iterdir()), ['user.txt'])
            client.images.pull.assert_not_called()
            return returned, output, events, controls, ready_meta

    def test_success_barrier_order_and_required_schema_without_vm_or_api(self):
        status, result, events, failures, ready = self.run_fake()
        self.assertEqual(status, 0)
        self.assertEqual(events, ['CAPTURE_READY', 'READY', 'UNFREEZE', 'OFFICIAL_PATCH_AND_TESTS', 'QUIESCENT', 'ALL_DONE', 'STOP_DECODE', 'CLEANUP_OWNED'])
        self.assertEqual(failures, [])
        self.assertTrue(result['official_passed'])
        self.assertEqual(result['paid_api_calls'], 0)
        self.assertEqual(result['mode'], 'ORACLE_REFERENCE')
        self.assertEqual(result['capture_status'], 'CAPTURED_COMPLETE_PENDING_INDEPENDENT_REPLAY')
        self.assertEqual(result['timeline_directory'], 'timeline')
        self.assertLessEqual(result['agent_return_ns'], result['quiescent_ns'])
        self.assertEqual(ready[0]['cgroup_root'], '/sys/fs/cgroup/owned-fixture')
        self.assertEqual(ready[0]['cgroup_id'], 99)

    def test_clean_official_failure_can_finish_but_never_reward_green(self):
        status, result, events, failures, _ = self.run_fake(resolved=False)
        self.assertEqual(status, 0)
        self.assertIs(result['official_passed'], False)
        self.assertEqual(result['status'], 'COMPLETED_OFFICIAL_TASK_FAILED')
        self.assertIn('ALL_DONE', events)
        self.assertEqual(failures, [])

    def test_identity_failure_aborts_no_done_or_normal_stop(self):
        status, result, events, failures, _ = self.run_fake(infrastructure_error=True)
        self.assertEqual(status, 1)
        self.assertEqual(result['status'], 'INFRASTRUCTURE_ERROR')
        self.assertNotIn('ALL_DONE', events)
        self.assertNotIn('STOP_DECODE', events)
        self.assertTrue(failures)

    def test_preexisting_output_is_not_modified(self):
        status, result, events, failures, _ = self.run_fake(preexisting=True)
        self.assertEqual(status, 1)
        self.assertIsNone(result)
        self.assertEqual(events, [])
        self.assertTrue(failures)

    def test_postprocess_keeps_official_failure_separate_from_verified_timeline(self):
        import replay
        import test_replay as fixture
        report = replay.build_report(fixture.ReplayTests().basic(), fixture.manifest(), {})
        report['tools'][0].update(tool_kind='OFFICIAL_TEST_EXEC', command='/bin/bash /eval.sh')
        for official_passed in (False, True):
            with self.subTest(official_passed=official_passed), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                (directory / 'manifest.json').write_text('{}')
                session = SimpleNamespace(directory=directory)
                with mock.patch.object(replay, 'verify_run', return_value=report):
                    goal = M.derive(session, official_passed)
                self.assertEqual(goal['timeline_status'], 'PASS_WITHIN_SELECTED_MODEL')
                self.assertEqual(goal['status'], 'PASS_WITHIN_SELECTED_MODEL' if official_passed else 'OFFICIAL_TASK_FAILED')
                summary = json.loads((directory / 'summary.json').read_bytes())
                self.assertEqual(summary['source_report']['bytes'], (directory / 'report.json').stat().st_size)
                self.assertTrue((directory / 'read-tables/reads.csv').is_file())
                self.assertTrue((directory / 'timeline.html').is_file())


if __name__ == '__main__':
    unittest.main()
