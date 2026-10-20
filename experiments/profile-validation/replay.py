#!/usr/bin/env python3
"""Independently recheck raw task outputs and collect honest measurement health.

This verifies performance experiment consistency, not the Observer audit WAL.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path


def replay(root):
    root = root.resolve(strict=True)
    manifest_path = root / 'validation-campaign.json'
    nested = manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text()) if nested else {'runs': [{'path': '.'}]}
    digests, tasks, trials, health, audits = {}, 0, 0, collections.Counter(), collections.Counter()
    inventories = set()
    for campaign_entry in manifest['runs']:
        campaign_root = (root / campaign_entry['path']).resolve(strict=True)
        campaign_root.relative_to(root)
        campaign = json.loads((campaign_root / 'campaign.json').read_text())
        if campaign['status'] != 'COMPLETE':
            raise ValueError('incomplete campaign')
        inventories.add((campaign['corpus_sha256'], campaign['permission_scope_sha256']))
        for trial_entry in campaign['trials']:
            trial = (campaign_root / trial_entry['path']).resolve(strict=True)
            trial.relative_to(campaign_root)
            raw = json.loads((trial / 'profile-run.json').read_text())
            if raw['status'] != 'COMPLETE' or raw['cleanup_errors']:
                raise ValueError('failed trial or residual cleanup error')
            trials += 1
            audits[raw.get('observer_audit', 'NOT_ENABLED')] += 1
            results = {result['task_id']: result for result in raw['results']}
            for task in raw['tasks']:
                result = results[task['task_id']]
                stdout = (trial / Path(task['stdout_path']).name).read_bytes()
                digest = hashlib.sha256(stdout).hexdigest()
                key = result['query_index']
                if key in digests and digests[key] != digest:
                    raise ValueError('raw stdout byte equivalence failed, query ' + str(key))
                digests[key] = digest
                if result['exit_code'] != 0 or len(stdout) != result['output_bytes']:
                    raise ValueError('task exit or output byte count mismatch')
                fields = stdout.split(b'\0')
                if fields[-1] != b'':
                    raise ValueError('invalid NUL-delimited result')
                normalized = hashlib.sha256(b'\0'.join(sorted(fields[:-1])) + b'\0').hexdigest()
                if normalized != result['output_sha256']:
                    raise ValueError('normalized output digest mismatch')
                tasks += 1
            report = json.loads((trial / 'report.json').read_text())
            health.update(issue['code'] for issue in report['issues'])
    return {'schema_version': 1, 'source_shape': 'NESTED_CAMPAIGNS' if nested else 'DIRECT_RUNNER_CAMPAIGN',
            'performance_equivalence_replay': 'PASS',
            'raw_stdout_byte_equivalence': 'PASS', 'query_stdout_sha256': digests,
            'tasks': tasks, 'trials': trials, 'corpus_permission_versions': sorted(inventories),
            'measurement_issues': dict(health), 'observer_audit_trial_statuses': dict(audits),
            'interpretation': 'Raw stdout equality is independent of sampler completeness. This does not replace audit WAL verification.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = replay(args.root)
    if args.output:
        with args.output.open('x') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
