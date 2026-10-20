#!/usr/bin/env python3
"""Prepare equal-eight real Codex/Terminal-Bench concurrency plans offline.

This does not call the model, execute an Oracle, or change the task tests.
Run each prepared plan with parallel_run.py, export/replay between groups.
"""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import json
from pathlib import Path

from common import digest, write_new
from parallel_run import load_plan

HERE = Path(__file__).resolve().parent
COUNTS = (2, 4, 6, 8)


def set_argument(argv, name, value):
    if argv.count(name) != 1 or argv.index(name) + 1 == len(argv):
        raise ValueError('one explicit argument required: ' + name)
    argv[argv.index(name) + 1] = str(value)


def prepare(template, output, runtime, native, codex, catalog, token, historical_bound='0.892690'):
    template, output = Path(template), Path(output)
    source = load_plan(template)
    if source.get('benchmark') != 'Terminal-Bench':
        raise ValueError('only the prepared Terminal-Bench task multiset is admitted')
    multiset = Counter(job['task_id'] for job in source['jobs'])
    if multiset != {'terminal-bench/bun-sourcemap-leak': 4, 'terminal-bench/html-js-filter': 4}:
        raise ValueError('expected four attempts for each of the two pinned public tasks')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    source_names = ('codex_client.py', 'codex_run.py', 'codex_harbor_agent.py', 'codex_terminal.py',
        'common.py', 'run.py', 'replay.py', 'render.py', 'syscall_catalog.py', 'kprobe_contract.py',
        'terminal_validate.py', 'parallel_terminal.py', 'parallel_run.py', 'phase_control.py')
    identities = {name: digest(HERE/name) for name in source_names}
    collector = HERE.parents[1]/'.output/execution-timeline-native023/collect'
    bpf = collector.with_name('execution_timeline.bpf.o')
    entries = []
    for count in COUNTS:
        plan = copy.deepcopy(source)
        plan.update(concurrency=count, mode='MODEL_AGENT',
            agent_implementation='OFFICIAL_CODEX_APP_SERVER',
            scope='REAL_CODEX_DEEPSEEK; SAME_EIGHT_TASK_ATTEMPTS; NO_REFERENCE_SOLUTION; N1_BATCH_PER_CONDITION')
        for index, job in enumerate(plan['jobs']):
            argv = job['command']
            argv[2] = str(Path(runtime)/'codex_terminal.py')
            old = argv.index('--max-rounds')
            del argv[old:old+2]
            for key, value in {
                '--collector': str(Path(native)/'collect'),
                '--object': str(Path(native)/'execution_timeline.bpf.o'),
                '--budget-label': f'codex-terminal-c{count}-{index:02d}',
                '--broker-token-file': token,
                '--max-output': '4096',
            }.items():
                set_argument(argv, key, value)
            argv += ['--codex', codex, '--catalog', catalog,
                '--max-calls', '8', '--max-requests', '12']
        config = plan['resource_configuration']
        config.pop('model_rounds', None)
        config.update(source_identities=identities, collector_identity=digest(collector),
            bpf_object_identity=digest(bpf), agent_implementation='OFFICIAL_CODEX_APP_SERVER',
            historical_bound_rmb=historical_bound, shared_campaign_cap_rmb='4.0',
            monetary_cap_per_job_rmb='0.2', max_response_requests_per_job=12,
            max_dynamic_shell_calls=8, model_max_output_tokens=4096, model_reasoning_effort='none',
            scope='EQUAL_TASK_MULTISET; STOCHASTIC_MODEL_ACTIONS_CAN_DIFFER; REMOTE_API_WAIT_INCLUDED; NO_GPU',
            sample_size_per_condition=1)
        target = output/f'terminal-c{count}.json'
        write_new(target, plan)
        entries.append({'concurrency': count, 'plan': str(target), 'identity': digest(target)})
    receipt = {'schema_version': 1, 'status': 'PREPARED_NOT_EXECUTED', 'benchmark': 'Terminal-Bench',
        'agent_implementation': 'OFFICIAL_CODEX_APP_SERVER', 'total_attempts': 32,
        'jobs_per_condition': 8, 'task_multiset_per_condition': dict(multiset),
        'template': {'path': str(template), **digest(template)}, 'plans': entries}
    write_new(output/'plans.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--runtime', default='/opt/terminal-codex-r002-execution-timeline')
    parser.add_argument('--native', default='/opt/native023-execution-timeline/native023')
    parser.add_argument('--codex', default='/opt/codex-timeline/codex/bin/codex')
    parser.add_argument('--catalog', default='/opt/codex-timeline/models.json')
    parser.add_argument('--token', default='/opt/terminal-codex-private/client-token')
    parser.add_argument('--historical-bound', default='0.892690')
    args = parser.parse_args()
    print(json.dumps(prepare(args.template, args.output, args.runtime, args.native,
        args.codex, args.catalog, args.token, args.historical_bound), ensure_ascii=False))


if __name__ == '__main__':
    main()
