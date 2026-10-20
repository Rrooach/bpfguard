#!/usr/bin/env python3
"""Bounded REAL model SWE job; never supply the reference/test patch to the model.

Reuse the stopped Docker Exec/native capture transport. The official evaluator
receives only the submitted model diff. Agent failure is a result, not an
infrastructure retry. API requests use the single external capped broker.
"""
from __future__ import annotations
import argparse
import asyncio
import importlib.metadata
import io
import json
import logging
import os
from pathlib import Path
import tarfile
import time
import uuid

from common import digest, write_new
from model_client import ModelClient, ModelRequestError
from parallel_swe import (INSTANCE, RING_BYTES, TimelineSession, load_module,
    official_reference, require, validate_image)
from phase_control import Control, job_name

MODE = 'MODEL_AGENT'
TOOLS = [
    {'type': 'function', 'function': {'name': 'bash', 'description': 'Inspect, edit, or test /testbed using one bash command.',
      'parameters': {'type': 'object', 'properties': {'command': {'type': 'string'}}, 'required': ['command'], 'additionalProperties': False}}},
    {'type': 'function', 'function': {'name': 'finish', 'description': 'Submit the current repository changes.',
      'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False}}}]


class ModelSession(TimelineSession):
    def prepare(self):
        proxy = super().prepare()
        self.manifest.update(agent_id='model:' + self.args.budget_label,
            agent_scope='REAL_BOUNDED_MODEL_AGENT; API_CLIENT_WAIT_OUTSIDE_CONTAINER; NO_GPU_INTERNAL_EVIDENCE',
            mode=MODE, model='deepseek-flash', budget_label=self.args.budget_label)
        proxy.gate.agent_id = proxy.test_gate.agent_id = self.manifest['agent_id']
        proxy.gate.tool_prefix, proxy.gate.kind = self.args.budget_label + '-exec', 'MODEL_SHELL_OR_SUBMISSION_TOOL'
        proxy.test_gate.tool_prefix = self.args.budget_label + '-test'
        self.persist()
        return proxy

    def stop(self):
        super().stop()
        for path in self.directory.glob('application/**/*'):
            if path.is_file():
                self.manifest['artifacts'][str(path.relative_to(self.directory))] = digest(path)
        self.persist()


def command_argument(call):
    def valid(condition, message):
        if not condition:
            raise ValueError(message)
    valid(isinstance(call, dict) and isinstance(call.get('id'), str), 'provider tool-call ID required')
    function = call.get('function') or {}
    values = json.loads(function.get('arguments', '{}'))
    valid(isinstance(values, dict), 'tool arguments must be object')
    if function.get('name') == 'finish':
        valid(not values, 'finish arguments must be empty')
        return None
    valid(function.get('name') == 'bash' and set(values) == {'command'}, 'only one bash command or finish is admitted')
    command = values['command']
    valid(isinstance(command, str) and command.strip() and '\0' not in command and len(command.encode()) <= 16384,
            'bounded nonempty model shell command required')
    return command


def solve_model(row, session, proxy, args):
    # No reference/test patch crosses this boundary, including transcripts.
    public = {key: row[key] for key in ('instance_id', 'problem_statement')}
    application = session.directory / 'application'
    application.mkdir(mode=0o700)
    client = ModelClient(args.broker_base_url, args.broker_token_file, args.budget_label,
        application / 'api', max_output=args.max_output, request_timeout=180,
        boot_id=session.manifest['boot_id'])
    messages = [{'role': 'system', 'content':
        'You are a coding agent inside a disposable Linux container. Fix the issue in /testbed. '
        'Use bash to inspect, edit and test; then call finish. The conda testbed environment is activated for every command. '
        'Only public repository tests are available: no gold patch, hidden tests, /solution or verifier artifacts. '
        'Do not use network services or background processes. Keep output concise and edits small. '
        'You have at most 4 model rounds, with 1024 output tokens per response. Call one bash tool at a time.'},
        {'role': 'user', 'content': public['problem_statement']}]
    mappings, termination, error = [], 'ROUND_LIMIT', None
    try:
        for step in range(args.max_rounds):
            response = asyncio.run(client.request(messages, TOOLS, step))
            message = response['choices'][0]['message']
            messages.append(message)
            calls = message.get('tool_calls') or []
            if not isinstance(calls, list) or len(calls) > 2:
                raise ValueError('at most two tool calls per model round')
            if not calls:
                termination = 'TEXT_ONLY_RESPONSE'
                break
            finished = False
            for call in calls:
                try:
                    command = command_argument(call)
                except (ValueError, TypeError) as failure:
                    messages.append({'role': 'tool', 'tool_call_id': call.get('id', ''), 'content': 'Rejected malformed tool: ' + str(failure)})
                    continue
                if command is None:
                    finished = True
                    messages.append({'role': 'tool', 'tool_call_id': call['id'], 'content': 'submitted'})
                    continue
                count = len(session.manifest['tools'])
                executed = proxy.exec_run(['timeout', '--kill-after=5s', str(args.tool_timeout), '/bin/bash', '-lc',
                    'source /opt/miniconda3/bin/activate && conda activate testbed && ' + command], workdir='/testbed')
                require(len(session.manifest['tools']) == count + 1, 'one exact enrollment per model shell required')
                entry = session.manifest['tools'][-1]
                mappings.append({'request_id': args.budget_label + '-step-' + str(step),
                    'provider_tool_call_id': call['id'], 'tool_call_id': entry['tool_call_id'],
                    'docker_exec_id': entry['docker_exec_id'], 'root': entry['root'],
                    'begin_ns': entry['begin_ns'], 'end_ns': entry['end_ns'], 'command': command,
                    'attribution': 'EXPLICIT_APPLICATION_DISPATCH_TO_GATED_EXEC'})
                text = executed.output.decode('utf-8', 'replace')
                messages.append({'role': 'tool', 'tool_call_id': call['id'], 'content': json.dumps({
                    'exit_code': executed.exit_code, 'output': text[:3500], 'truncated': len(text) > 3500})})
            if finished:
                termination = 'MODEL_FINISHED'
                break
            if len(json.dumps(messages, ensure_ascii=False).encode()) > 20000:
                termination = 'LOCAL_CONTEXT_BOUND'
                break
    except ModelRequestError as failure:
        termination, error = 'MODEL_REQUEST_' + str(failure.kind), str(failure)
    except (ValueError, KeyError, TypeError, IndexError) as failure:
        # Invalid model output is not an observer transport failure.
        termination, error = 'MODEL_PROTOCOL_ERROR', type(failure).__name__ + ': ' + str(failure)
    require(proxy.infrastructure_error is None, 'model transport/identity failure: ' + str(proxy.infrastructure_error))
    result = {'mode': MODE, 'model': 'deepseek-flash', 'budget_label': args.budget_label,
        'termination': termination, 'error': error, 'usage': client.usage,
        'request_attempts': len(client.events), 'mappings': mappings,
        'boot_id': session.manifest['boot_id'], 'clock': 'CLOCK_MONOTONIC',
        'gold_patch_exposed': False, 'test_patch_exposed': False,
        'scope': 'APPLICATION_REQUEST_ASSOCIATION; NOT_SERVER_GPU_QUEUE_OR_GENERAL_CAUSAL_ATTRIBUTION'}
    write_new(application / 'agent-result.json', result)
    # Snapshot the actual submission, including new non-ignored files. Restore
    # only that diff so the unchanged official harness can apply it once.
    submitted = proxy.exec_run(['bash', '-lc', 'git add -N -- . && git diff --binary HEAD'], workdir='/testbed')
    require(submitted.exit_code == 0 and len(submitted.output) <= 1024 * 1024, 'bounded model diff extraction failed')
    patch = submitted.output.decode('utf-8')
    write_new(args.output / 'agent.patch', submitted.output)
    if patch:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as tar:
            item = tarfile.TarInfo('observer-submission.diff')
            item.size, item.mode = len(submitted.output), 0o600
            tar.addfile(item, io.BytesIO(submitted.output))
        require(session.container.put_archive('/tmp', archive.getvalue()), 'model diff staging failed')
        restored = proxy.exec_run(['git', 'apply', '--reverse', '--binary', '/tmp/observer-submission.diff'], workdir='/testbed')
        require(restored.exit_code == 0, 'exact model-diff reversal failed; do not run misleading official tests')
    result['patch_bytes'] = len(submitted.output)
    return patch, result


def run_worker(args):
    job_name(args.job_id)
    args.output = args.output.absolute()
    control = Control(args.control_dir, args.job_id, timeout=7200)
    result = {'schema_version': 1, 'benchmark': 'SWE-bench Verified', 'job_id': args.job_id,
        'task_id': INSTANCE, 'mode': MODE, 'budget_label': args.budget_label, 'timeline_directory': 'timeline',
        'official_passed': False, 'agent_return_ns': None, 'quiescent_ns': None,
        'capture_status': 'NOT_CAPTURED', 'status': 'INITIALIZING', 'errors': [],
        'timing_scope': 'REAL_MODEL_REQUESTS_AND_TOOLS_PLUS_OFFICIAL_TESTS; API_WAIT_IS_CLIENT_SIDE_NOT_GPU'}
    session = container = docker_client = None
    created = False
    try:
        vendor = ' '.join(Path('/sys/class/dmi/id', name).read_text(errors='replace') for name in ('sys_vendor', 'product_name'))
        require(os.geteuid() == 0 and any(x in vendor.lower() for x in ('qemu', 'kvm', 'bochs')), 'owned QEMU Guest only')
        require(not args.output.exists() and not args.output.is_symlink(), 'fresh worker output required')
        args.output.mkdir(mode=0o700)
        created = True
        adapter = load_module('model_swe_provenance_adapter', args.swe_adapter)
        bridge = load_module('model_swe_identity_bridge', args.bridge)
        require(importlib.metadata.version('swebench') == adapter.HARNESS_VERSION, 'official harness version differs')
        provenance = json.loads((args.inputs / 'provenance.json').read_bytes())
        require(digest(args.inputs / 'task.json')['sha256'] == provenance['task_sha256'], 'prepared task digest differs')
        row = adapter.validate_task(json.loads((args.inputs / 'task.json').read_bytes()), provenance)
        require(row['instance_id'] == INSTANCE, 'unexpected task')
        write_new(args.output / 'harness-runtime.json', adapter.validate_installed_harness(args.inputs, provenance))
        write_new(args.output / 'provenance.json', provenance)
        import docker
        from swebench.harness import run_evaluation as official
        from swebench.harness.test_spec.test_spec import make_test_spec
        spec = make_test_spec(row, namespace='swebench', instance_image_tag='latest')
        docker_client = docker.from_env(timeout=600)
        image = docker_client.images.get(spec.instance_image_key)
        info = validate_image(image, spec.instance_image_key, json.loads(args.image_import_provenance.read_bytes()))
        write_new(args.output / 'image.json', info)
        run_id = args.budget_label + '-' + uuid.uuid4().hex[:12]
        container = official.build_container(spec, docker_client, run_id, logging.getLogger(run_id), False, False)
        container.start()
        session = ModelSession(args, container, bridge, info)
        proxy = session.prepare()
        release = control.ready_sync({'benchmark': result['benchmark'], 'job_id': args.job_id, 'task_id': INSTANCE,
            'mode': MODE, 'budget_label': args.budget_label, 'run_id': session.manifest['run_id'],
            'target': session.target, 'boot_id': session.manifest['boot_id'], 'cgroup_root': str(session.group),
            'cgroup_id': session.target['cgroup_inode'], 'collector_identity': session.manifest['collector_identity'],
            'bpf_object_identity': session.manifest['bpf_object_identity'], 'ring_bytes': RING_BYTES})
        result['release_observed_ns'] = release['observed_ns']
        session.freeze(False)
        patch, agent = solve_model(row, session, proxy, args)
        result['model_result'] = agent
        result['model_return_ns'] = time.monotonic_ns()
        evaluation_row = dict(row, patch=patch)
        official_dir = args.output / 'official'
        official_dir.mkdir()
        evaluated = official_reference(official, spec, evaluation_row, docker_client, proxy, official_dir,
            run_id, args.test_timeout, model_label='deepseek-flash-real-bounded-model')
        result['agent_return_ns'] = time.monotonic_ns()
        result['official_result'], result['official_passed'] = evaluated, evaluated['resolved'] is True
        write_new(args.output / 'official-result.json', evaluated)
        result['quiescent_ns'] = session.quiesce()
        result['capture_status'] = 'FROZEN_QUIESCENT_AWAITING_ALL_JOBS'
        write_new(args.output / 'workload-result.json', result)
        post = control.done_sync({'agent_return_ns': result['agent_return_ns'], 'quiescent_ns': result['quiescent_ns'],
            'quiescent': True, 'official_passed': result['official_passed'], 'mode': MODE,
            'run_id': session.manifest['run_id'], 'container_id': container.id, 'nonbaseline_live_threads': 0})
        result['all_agents_done_observed_ns'] = post['observed_ns']
        session.postprocessing_authorized = True
        session.stop()
        result['capture_status'] = 'CAPTURED_COMPLETE_PENDING_INDEPENDENT_REPLAY'
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
            result['errors'].append('cleanup: ' + str(error))
            control.fail(result['errors'][-1])
        if docker_client is not None:
            docker_client.close()
        if created:
            result['worker_end_ns'] = time.monotonic_ns()
            write_new(args.output / 'worker-result.json', result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return int(bool(result['errors']))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('inputs', 'bridge', 'swe-adapter', 'collector', 'object', 'output', 'control-dir', 'image-import-provenance', 'broker-token-file'):
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--job-id', required=True)
    parser.add_argument('--budget-label', required=True)
    parser.add_argument('--broker-base-url', default='http://10.0.2.2:10091/v1')
    parser.add_argument('--max-rounds', type=int, choices=(4,), default=4)
    parser.add_argument('--max-output', type=int, choices=(1024,), default=1024)
    parser.add_argument('--tool-timeout', type=int, default=45)
    parser.add_argument('--test-timeout', type=int, default=300)
    parser.add_argument('--docker-socket', default='/var/run/docker.sock')
    parser.add_argument('--capture-only', action='store_true')
    args = parser.parse_args(argv)
    require(1 <= args.tool_timeout <= 60 and 1 <= args.test_timeout <= 600, 'bounded task timeouts required')
    return run_worker(args)


if __name__ == '__main__':
    raise SystemExit(main())
