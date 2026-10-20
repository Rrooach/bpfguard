#!/usr/bin/env python3
"""Explicit real-model matrix with fail-closed identities and manual export gaps.

Task reward=0 is retained, not retried or treated as capture failure. Every
group, including the last, waits for a boot/digest-bound NEXT after export.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

from common import digest, write_new
from matrix_run import (argument, assert_quiet, await_next, check_pins, guest_identity,
    load_json, pin_file, relative_directory, require)
from parallel_run import load_plan
import matrix_run

matrix_run.WORKER_NAMES.update({'model_swe.py', 'model_terminal.py'})

HERE = Path(__file__).resolve().parent


def prepare(paths):
    pins, plans, keys = {}, [], set()
    for raw in paths:
        path = Path(raw).resolve(strict=True)
        plan = load_plan(path)
        config = plan.get('resource_configuration') or {}
        benchmark, concurrency = plan.get('benchmark'), plan.get('concurrency')
        require(benchmark in ('SWE-bench Verified', 'Terminal-Bench') and concurrency in (2, 4, 6, 8), 'explicit model benchmark/concurrency required')
        require(plan.get('mode') == 'MODEL_AGENT' and config.get('model') == 'deepseek-flash'
            and config.get('model_rounds') == 4 and config.get('model_max_output_tokens') == 1024
            and config.get('total_preloaded_collectors') == 8 and config.get('sample_size_per_condition') == 1,
            'real-model fixed limits required, not an Oracle plan')
        key = ('swe' if benchmark.startswith('SWE') else 'terminal', concurrency)
        require(key not in keys, 'duplicate benchmark/concurrency')
        keys.add(key)
        pin_file(pins, path)
        for name, identity in config['source_identities'].items():
            require(Path(name).name == name, 'unsafe source identity')
            pin_file(pins, HERE / name, identity)
        for number, job in enumerate(plan['jobs']):
            argv = job['command']
            expected_label = f'model-{key[0]}-c{concurrency}-{number:02d}'
            require(argument(argv, '--budget-label') == expected_label, 'exact registered per-job budget label required')
            require(argument(argv, '--max-rounds') == '4' and argument(argv, '--max-output') == '1024', 'consistent bounded agent configuration required')
            require(argument(argv, '--broker-base-url') == 'http://127.0.0.1:10091/v1', 'only owned SSH-tunneled shared broker allowed')
            for option in ('--collector', '--object', '--bridge', '--selection', '--prebuilt-images', '--swe-adapter', '--image-import-provenance'):
                value = argument(argv, option, required=option in ('--collector', '--object'))
                if value:
                    expected = config.get('collector_identity' if option == '--collector' else 'bpf_object_identity') if option in ('--collector', '--object') else None
                    pin_file(pins, value, expected)
        plans.append({'name': f'{key[0]}-c{concurrency}-r001', 'path': path, 'plan': plan, 'identity': digest(path), 'concurrency': concurrency})
    require(keys == {(label, count) for label in ('swe', 'terminal') for count in (2, 4, 6, 8)}, 'exact full eight-group model matrix required')
    return plans, pins


def validate_group(root, entry, boot):
    campaign = load_json(root / 'campaign.json')
    require(campaign['status'] == 'WORKERS_COMPLETED' and campaign['boot_id'] == boot
        and campaign['concurrency'] == entry['concurrency'] and campaign['plan_identity'] == entry['identity'], 'controller completion/identity differs')
    jobs = []
    for job in entry['plan']['jobs']:
        directory = root / 'jobs' / job['job_id']
        worker = load_json(directory / 'worker-result.json')
        require(worker['mode'] == 'MODEL_AGENT' and worker['job_id'] == job['job_id']
            and worker['task_id'] == job['task_id'] and type(worker['official_passed']) is bool
            and not worker.get('errors'), 'model identity or infrastructure failure')
        timeline = relative_directory(directory, worker['timeline_directory'])
        manifest = load_json(timeline / 'manifest.json')
        health = load_json(timeline / 'capture/health.json')
        require(manifest['boot_id'] == boot and health['status'] == 'COMPLETE_FOR_SELECTED_HOOKS', 'native capture incomplete')
        label = argument(job['command'], '--budget-label')
        require(manifest.get('budget_label') == worker.get('budget_label') == label
            and manifest['agent_id'] in ('model:' + label, 'model-agent:' + label),
            'exact model job identity required; Oracle identity cannot label model execution')
        jobs.append({'job_id': job['job_id'], 'official_passed': worker['official_passed'],
            'worker_result': {'path': str(directory / 'worker-result.json'), **digest(directory / 'worker-result.json')},
            'manifest': {'path': str(timeline / 'manifest.json'), **digest(timeline / 'manifest.json')}, 'health': health})
    return {'schema_version': 1, 'status': 'MODEL_GROUP_CAPTURED_PENDING_RAW_REPLAY', 'boot_id': boot,
        'group_name': entry['name'], 'jobs': jobs, 'official_passed': sum(job['official_passed'] for job in jobs),
        'official_total': 8, 'mode': 'MODEL_AGENT', 'campaign_identity': digest(root / 'campaign.json')}


def run(args):
    plans, pins = prepare(args.plans)
    identity = guest_identity()
    require(identity['boot_id'] == args.expected_boot_id, 'unexpected Guest boot')
    root = args.output.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_new(root / 'identity.json', identity)
    write_new(root / 'source-pins.json', pins)
    results = []
    status, error = 'RUNNING', None
    try:
        for index, entry in enumerate(plans):
            check_pins(pins)
            require(guest_identity() == identity, 'Guest configuration changed')
            quiet_before = assert_quiet()
            output = root / entry['name']
            log = root / (entry['name'] + '.log')
            command = [sys.executable, '-B', str(HERE / 'parallel_run.py'), '--plan', str(entry['path']),
                '--output', str(output), '--concurrency', str(entry['concurrency']), '--sampler', str(args.sampler),
                '--setup-timeout', '1800', '--task-timeout', '2100', '--finalize-timeout', '3000']
            with log.open('xb') as stream:
                result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=14400)
            require(result.returncode == 0, 'group failed; no paid automatic retry')
            completed = validate_group(output, entry, identity['boot_id'])
            completed['quiet_before'], completed['quiet_after'] = quiet_before, assert_quiet()
            completed['completed_ns'] = time.monotonic_ns()
            receipt = root / f'{index:02d}-{entry["name"]}-completed.json'
            write_new(receipt, completed)
            results.append(completed)
            # External host must bind the exported bytes, fsync, and only then ACK.
            await_next(root, index, entry['name'], receipt, identity['boot_id'], 7200)
        status = 'ALL_MODEL_GROUPS_CAPTURED_PENDING_INDEPENDENT_REPLAY'
    except BaseException as failure:
        status, error = 'STOPPED_ON_FAILURE', type(failure).__name__ + ': ' + str(failure)
    finally:
        write_new(root / 'matrix.json', {'schema_version': 1, 'status': status, 'mode': 'MODEL_AGENT',
            'boot_id': identity['boot_id'], 'groups': results, 'error': error,
            'scope': 'REAL_MODEL_ATTEMPTS; TASK_FAILURE_IS_NOT_CAPTURE_FAILURE; NO_GPU; N1_PER_CONDITION'})
    print(json.dumps({'status': status, 'groups': len(results), 'error': error}), flush=True)
    return int(error is not None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plans', nargs='+', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sampler', type=Path, required=True)
    parser.add_argument('--expected-boot-id', required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
