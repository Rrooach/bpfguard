#!/usr/bin/env python3
"""Produce a compact receipt from preserved campaign/performance/WAL evidence."""
import argparse
import collections
import json
from pathlib import Path


MAIN = ('matrix-basic-20261014', 'pressure-abi2-v2-corrected-20261014',
        'overhead-abi2-v2-20261014', 'overhead-50ms-abi2-v2-20261014')
DIAGNOSTIC = 'rich-diagnostic-abi2-v7-20261014'


def summarize(root):
    root = root.resolve(strict=True)
    suites, issues = {}, collections.Counter()
    for name in MAIN + (DIAGNOSTIC,):
        campaign = json.loads((root / name / 'validation-campaign.json').read_text())
        replay = json.loads((root / (name + '-replay.json')).read_text())
        if campaign['status'] != 'COMPLETE' or replay['performance_equivalence_replay'] != 'PASS':
            raise ValueError('campaign or independent performance replay did not pass: ' + name)
        issues.update(replay['measurement_issues'])
        suites[name] = {'campaign': str(root / name / 'validation-campaign.json'),
            'performance_replay': str(root / (name + '-replay.json')),
            'suite': campaign['suite'], 'campaigns': len(campaign['runs']),
            'randomized_blocks': campaign['repetitions'], 'trials': replay['trials'], 'logical_tasks': replay['tasks'],
            'raw_stdout_byte_equivalence': replay['raw_stdout_byte_equivalence'],
            'measurement_issues': replay['measurement_issues'], 'sampler_sha256': campaign['artifacts']['sampler_sha256'],
            'observer_audit_trial_statuses': replay['observer_audit_trial_statuses'],
            'comparisons': campaign['comparisons']}
    wal = json.loads((root / 'host-wal-replay' / 'summary.json').read_text())
    return {'schema_version': 1, 'scope': 'cooperative deterministic GNU grep/read calibration in owned PSI QEMU; no model/API calls',
        'main_trials': sum(suites[name]['trials'] for name in MAIN),
        'main_logical_tasks': sum(suites[name]['logical_tasks'] for name in MAIN),
        'diagnostic_trials': suites[DIAGNOSTIC]['trials'], 'diagnostic_logical_tasks': suites[DIAGNOSTIC]['logical_tasks'],
        'independent_performance_replay': 'PASS',
        'independent_host_wal_replay': wal['independent_host_wal_replay'], 'wal_trials': wal['trials'],
        'wal_evidence_statuses': wal['evidence_statuses'], 'wal_receipts': str(root / 'host-wal-replay' / 'summary.json'),
        'system_effect_wal_events': wal['system_effect_wal_events'], 'lifecycle_wal_events': wal['lifecycle_wal_events'],
        'verifier_sha256': wal['verifier_sha256'], 'measurement_issues': dict(issues),
        'failed_pressure_attempt_preserved': str(root / 'pressure-abi2-v2-20261014'), 'suites': suites,
        'limitations': ['Guest-cold is not Host/physical-disk cold', 'fixed-query/static permission views are cooperative',
            'INCOMPLETE audit evidence is not whole-Linux coverage', 'polling threads is not complete fork/exec/exit coverage',
            'root/child cgroup and completed nested spans must not be summed',
            'new-device io.stat pre-value is UNKNOWN, never silently zero',
            'diagnostic single-arm collection is not a paired incremental-cost claim']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = summarize(args.root)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({key: value for key, value in result.items() if key not in ('suites', 'limitations')}, indent=2))


if __name__ == '__main__':
    main()
