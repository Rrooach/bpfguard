#!/usr/bin/env python3
"""Generate fresh REAL model plans and one 64-job monetary registry; no API."""
import argparse
import copy
from decimal import Decimal
import json
from pathlib import Path
import re

from common import digest, write_new

HERE = Path(__file__).resolve().parent
RUNTIME = ('model_matrix.py', 'model_swe.py', 'model_terminal.py', 'model_client.py', 'model_harbor_agent.py',
    'parallel_run.py', 'parallel_swe.py', 'parallel_terminal.py', 'phase_control.py', 'common.py',
    'terminal_validate.py', 'matrix_run.py', 'kprobe_contract.py', 'replay.py')


def generate(output, terminal_template, swe_template, native, guest_source='/opt/model-execution-timeline', *,
        guest_native=None, campaign_id='model-timeline-2468-20261018-001', historical_bound='0.468350'):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', campaign_id):
        raise ValueError('path-safe campaign identity required')
    amount = Decimal(historical_bound)
    if not amount.is_finite() or not Decimal('0.468350') <= amount <= Decimal('.8'):
        raise ValueError('historical bound plus 4.2 CNY cap must not exceed five CNY')
    guest_native = str(guest_native or (Path(guest_source) / Path(native).name))
    if not Path(guest_native).is_absolute() or '..' in Path(guest_native).parts:
        raise ValueError('absolute Guest native directory required')
    root = Path(output).absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    sources = {name: digest(HERE / name) for name in RUNTIME}
    labels, paths = [], []
    templates = {'terminal': json.loads(Path(terminal_template).read_bytes()), 'swe': json.loads(Path(swe_template).read_bytes())}
    for concurrency in (2, 4, 6, 8):
        for benchmark in ('swe', 'terminal'):
            plan = copy.deepcopy(templates[benchmark])
            plan.update(mode='MODEL_AGENT', concurrency=concurrency,
                scope='REAL_BOUNDED_MODEL_AGENT_8_JOB_ATTEMPTS; NOT_ORACLE; MODEL_ACTIONS_MAY_DIFFER; NO_GPU; N1')
            plan['resource_configuration'].update(source_identities=sources, inference_api_calls='REAL_SHARED_BUDGET_BROKER',
                model='deepseek-flash', model_rounds=4, model_max_output_tokens=1024,
                monetary_cap_per_job_rmb='0.065', shared_campaign_cap_rmb='4.2', historical_bound_rmb=str(amount),
                collector_identity=digest(Path(native)/'collect'), bpf_object_identity=digest(Path(native)/'execution_timeline.bpf.o'),
                execution_environment='DOCKER_IN_OWNED_EXPERIMENT_GUEST',
                observer_wal_filesystem='OWNED_PERSISTENT_EXT4_SCSI_SCRATCH; EXPORT_SHA_FSYNC_BEFORE_NEXT',
                scope='SAME_TASK_MULTISET_NOT_IDENTICAL_MODEL_GENERATED_OPERATIONS; REMOTE_MODEL_WAIT_INCLUDED')
            for number, job in enumerate(plan['jobs']):
                label = f'model-{benchmark}-c{concurrency}-{number:02d}'
                labels.append({'label': label, 'group_id': f'{benchmark}-c{concurrency}',
                    'job_id': job['job_id'], 'kind': 'FORMAL', 'cap_rmb': '0.065'})
                argv = [part.replace('/opt/execution-timeline/', guest_source.rstrip('/')+'/') for part in job['command']]
                argv = [part.replace('parallel_'+benchmark+'.py', 'model_'+benchmark+'.py') for part in argv]
                # Identity pins alone are insufficient: actual worker argv must
                # point at the same freshly selected native build, not the old
                # native021 path inherited from the reference template.
                for flag, filename in (('--collector', 'collect'), ('--object', 'execution_timeline.bpf.o')):
                    if flag in argv:
                        argv[argv.index(flag)+1] = str(Path(guest_native)/filename)
                if '--phase-timeout' in argv:
                    argv[argv.index('--phase-timeout')+1] = '7200'
                argv += ['--budget-label', label, '--broker-base-url', 'http://127.0.0.1:10091/v1',
                    '--broker-token-file', '/opt/model-timeline-private/client-token', '--max-rounds', '4', '--max-output', '1024']
                job['command'] = argv
            path = root / f'{benchmark}-c{concurrency}.json'
            write_new(path, plan)
            paths.append(path)
    for label in ('swe', 'terminal'):
        labels.append({'label': 'pilot-model-'+label, 'group_id': 'pilot', 'job_id': label, 'kind': 'PILOT', 'cap_rmb': '0.02'})
    registry = {'schema_version': 1, 'campaign_id': campaign_id,
        'global_limit_rmb': '4.2', 'labels': labels}
    write_new(root/'budget-labels.json', registry)
    write_new(root/'plans-index.json', {'mode': 'MODEL_AGENT', 'plans': [{'path': str(path), **digest(path)} for path in paths],
        'source_identities': sources, 'public_registry_identity': digest(root/'budget-labels.json')})
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'terminal-template', 'swe-template', 'native'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--guest-native', type=Path)
    parser.add_argument('--campaign-id', default='model-timeline-2468-20261018-001')
    parser.add_argument('--historical-bound', default='0.468350')
    args = parser.parse_args()
    paths = generate(args.output, args.terminal_template, args.swe_template, args.native,
        guest_native=args.guest_native, campaign_id=args.campaign_id, historical_bound=args.historical_bound)
    print(json.dumps({'status': 'REAL_MODEL_PLANS_PREPARED_NO_API', 'plans': [str(p) for p in paths]}))


if __name__ == '__main__': main()
