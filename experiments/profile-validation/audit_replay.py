#!/usr/bin/env python3
"""Replay actual Observer WALs with a pinned independent verifier.

This is separate from performance/stdout equivalence. A verified receipt with
INCOMPLETE evidence is retained as INCOMPLETE, not promoted to complete audit.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import subprocess


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def observer_trials(root):
    root = root.resolve(strict=True)
    campaign = json.loads((root / 'validation-campaign.json').read_text())
    if campaign.get('status') != 'COMPLETE':
        raise ValueError('cannot summarize failed campaign as complete')
    for entry in campaign['runs']:
        nested = (root / entry['path']).resolve(strict=True)
        nested.relative_to(root)
        for row in json.loads((nested / 'campaign.json').read_text())['trials']:
            trial = (nested / row['path']).resolve(strict=True)
            trial.relative_to(nested)
            raw = json.loads((trial / 'profile-run.json').read_text())
            if row['mode'] not in ('observer', 'observer-sampler'):
                if (trial / 'observer').exists():
                    raise ValueError('unexpected audit evidence in non-Observer arm')
                continue
            if raw.get('status') != 'COMPLETE' or raw.get('cleanup_errors'):
                raise ValueError('Observer trial failed or cleanup incomplete')
            if not (trial / 'observer').is_dir() or not (trial / 'observer-expectation.json').is_file():
                raise ValueError('Observer arm has no original WAL/expectation')
            yield trial


def verify(roots, verifier, verifier_sha256, output):
    verifier = verifier.resolve(strict=True)
    actual = hashlib.sha256(verifier.read_bytes()).hexdigest()
    if actual != verifier_sha256:
        raise ValueError('pinned verifier SHA256 mismatch')
    output.mkdir(mode=0o700)
    evidence, statuses, receipts = collections.Counter(), collections.Counter(), []
    for root in roots:
        for trial in observer_trials(root):
            name = '%04d' % len(receipts)
            command = [str(verifier), '--artifacts', str(trial / 'observer'),
                '--expectation', str(trial / 'observer-expectation.json')]
            try:
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            except subprocess.TimeoutExpired as error:
                result = subprocess.CompletedProcess(command, -1, error.stdout or b'',
                    (error.stderr or b'') + b'\nINDEPENDENT_VERIFIER_TIMEOUT\n')
            (output / (name + '.stdout')).write_bytes(result.stdout)
            (output / (name + '.stderr')).write_bytes(result.stderr)
            try:
                parsed = json.loads(result.stdout)
            except (ValueError, UnicodeError):
                parsed = None
            passed = result.returncode == 0 and isinstance(parsed, dict) and parsed.get('verified') is True
            status = 'PASS' if passed else 'FAIL'
            statuses[status] += 1
            if passed:
                evidence[str(parsed.get('evidence_status', 'UNKNOWN'))] += 1
            receipt = {'trial': str(trial), 'returncode': result.returncode, 'replay_status': status,
                       'receipt': parsed, 'stdout': name + '.stdout', 'stderr': name + '.stderr'}
            save(output / (name + '.json'), receipt)
            receipts.append(receipt)
    summary = {'schema_version': 1, 'independent_host_wal_replay': 'PASS' if not statuses['FAIL'] and receipts else 'FAIL',
        'verifier_binary': str(verifier), 'verifier_sha256': actual, 'trials': len(receipts),
        'statuses': dict(statuses), 'evidence_statuses': dict(evidence),
        'system_effect_wal_events': sum(row['receipt'].get('system_effect_wal_event_count', 0)
            for row in receipts if row['replay_status'] == 'PASS'),
        'lifecycle_wal_events': sum(row['receipt'].get('process_lifecycle_wal_event_count', 0)
            for row in receipts if row['replay_status'] == 'PASS'),
        'receipts': receipts,
        'interpretation': 'WAL binding and independent replay only. INCOMPLETE evidence stays incomplete; not whole-Linux safety/state completeness.'}
    save(output / 'summary.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('roots', type=Path, nargs='+')
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--verifier-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.roots, args.verifier, args.verifier_sha256, args.output)
    print(json.dumps({key: value for key, value in result.items() if key != 'receipts'}, indent=2))
    return 0 if result['independent_host_wal_replay'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
