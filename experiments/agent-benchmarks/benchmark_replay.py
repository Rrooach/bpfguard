#!/usr/bin/env python3
"""Host-side independent replay of copied SWE/Terminal Observer WAL evidence.

Input evidence is read-only. The executable is externally SHA256-pinned; Guest
verification.json files are never accepted as proof. Verification passing does
not promote INCOMPLETE observation coverage to COMPLETE.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


MARKER = 'benchmark-host-replay-marker.json'
EXPECTATION = 'verification-expectation.json'
MANIFEST = 'artifact-manifest.json'
REPORT = 'deployment-observation-report.json'
MAX_JSON_BYTES = 16 * 1024 * 1024


def sha_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def write_new(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def read_json(path):
    with path.open('rb') as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError('JSON exceeds 16 MiB bound: ' + str(path))
    return json.loads(data)


def _inside(path, directory):
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def discover(root, excluded=None):
    """Find exact known layouts, and expose rather than silently omit orphans."""
    root = Path(root).resolve(strict=True)
    excluded = Path(excluded).resolve() if excluded else None
    expectations, observers, issues = [], set(), []
    for directory, children, files in os.walk(root, followlinks=False):
        folder = Path(directory)
        if (excluded and _inside(folder, excluded)) or MARKER in files:
            children[:] = []
            continue
        children.sort()
        for name in list(children):
            child = folder / name
            if child.is_symlink():
                children.remove(name)
                if name == 'observer':
                    issues.append({'error': 'SYMLINK_OBSERVER_NOT_REPLAYED', 'path': str(child)})
        if EXPECTATION in files:
            expectations.append(folder / EXPECTATION)
        if folder.name == 'observer' and any(name in files for name in (MANIFEST, REPORT, 'system-effects.raw.bin')):
            observers.add(folder)
    inputs, mapped = [], {}
    for expectation in sorted(expectations):
        observer = expectation.parent.parent / 'observer' if expectation.parent.name == 'control' else expectation.parent / 'observer'
        row = {'expectation': str(expectation), 'artifacts': str(observer),
               'layout': 'TERMINAL_CONTROL' if expectation.parent.name == 'control' else 'SWE_OR_SESSION'}
        if expectation.is_symlink() or observer.is_symlink() or not _inside(observer.resolve(), root):
            row['discovery_error'] = 'SYMLINK_OR_OUTSIDE_ROOT_INPUT'
        elif not observer.is_dir():
            row['discovery_error'] = 'EXPECTED_OBSERVER_DIRECTORY_MISSING'
        if observer in mapped:
            row['discovery_error'] = 'DUPLICATE_EXPECTATIONS_FOR_ONE_OBSERVER'
            inputs[mapped[observer]]['discovery_error'] = 'DUPLICATE_EXPECTATIONS_FOR_ONE_OBSERVER'
        mapped[observer] = len(inputs)
        inputs.append(row)
    for observer in sorted(observers - set(mapped)):
        issues.append({'error': 'OBSERVER_WITHOUT_VERIFICATION_EXPECTATION', 'path': str(observer)})
    if not inputs:
        issues.append({'error': 'NO_VERIFICATION_EXPECTATIONS_FOUND', 'path': str(root)})
    return inputs, issues


def _pinned_verifier(path, digest):
    if not isinstance(digest, str) or re.fullmatch(r'[0-9a-fA-F]{64}', digest) is None:
        raise ValueError('expected verifier SHA256 must be 64 hex characters')
    path = Path(path).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK) or sha_file(path) != digest.lower():
        raise ValueError('Host verifier executable or SHA256 mismatch')
    return path


def _counter(result, field):
    value = result.get(field)
    if type(value) is not int or value < 0:
        raise ValueError('verifier result counter missing/invalid: ' + field)
    return value


def replay(root, verifier, expected_sha256, output, timeout=300):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('input root must be a directory')
    verifier = _pinned_verifier(verifier, expected_sha256)
    output = Path(output).absolute()
    if output.exists():
        raise FileExistsError('Host replay output must be a new directory')
    if _inside(root, output.resolve()):
        raise ValueError('Host replay output cannot be input root or its ancestor')
    inputs, discovery_issues = discover(root, output)
    for item in inputs:
        if _inside(output.resolve(), Path(item['artifacts']).resolve()):
            raise ValueError('Host replay output must not modify an artifact directory')
    output.mkdir(parents=True, exist_ok=False)
    write_new(output / MARKER, {'schema_version': 1, 'purpose': 'HOST_REPLAY_OUTPUT_NOT_INPUT_EVIDENCE'})
    write_new(output / 'discovery.json', {'inputs': inputs, 'issues': discovery_issues})
    checks = []
    for index, item in enumerate(inputs):
        receipt = output / ('replay-%04d' % index)
        receipt.mkdir()
        check = {**item, 'receipt_directory': str(receipt), 'verified': False,
                 'return_code': None, 'status': 'NOT_REPLAYED'}
        try:
            if item.get('discovery_error'):
                raise ValueError(item['discovery_error'])
            observation, expectation = Path(item['artifacts']), Path(item['expectation'])
            bindings = {'expectation': expectation, 'artifact_manifest': observation / MANIFEST,
                        'observation_report': observation / REPORT}
            for path in bindings.values():
                if path.is_symlink() or not path.is_file():
                    raise ValueError('missing or symlink binding input: ' + str(path))
            before = {key: sha_file(path) for key, path in bindings.items()}
            expected = read_json(expectation)
            if not isinstance(expected, dict) or not isinstance(expected.get('expected_config'), dict):
                raise ValueError('invalid verification expectation')
            _pinned_verifier(verifier, expected_sha256)
            command = [str(verifier), '--artifacts', str(observation), '--expectation', str(expectation)]
            check.update(command=command, input_digests_before=before, start_monotonic_ns=time.monotonic_ns())
            with (receipt / 'verifier.stdout').open('xb') as stdout, (receipt / 'verifier.stderr').open('xb') as stderr:
                try:
                    completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=timeout)
                except subprocess.TimeoutExpired:
                    check['status'] = 'TIMEOUT'
                    raise
            check.update(return_code=completed.returncode, end_monotonic_ns=time.monotonic_ns(),
                         input_digests_after={key: sha_file(path) for key, path in bindings.items()})
            _pinned_verifier(verifier, expected_sha256)
            if check['input_digests_after'] != before:
                raise ValueError('input binding changed during Host replay')
            if completed.returncode:
                raise ValueError('pinned verifier rejected artifacts; see raw stdout/stderr')
            result = read_json(receipt / 'verifier.stdout')
            check['result'] = result  # Preserve the full verifier result verbatim.
            if not isinstance(result, dict) or result.get('verified') is not True:
                raise ValueError('verifier did not explicitly verify evidence')
            if result.get('run_id') != expected['expected_config'].get('run_id') or result.get('epoch') != expected['expected_config'].get('epoch'):
                raise ValueError('verifier result run/epoch differs from expectation')
            for wal, jsonl in (('system_effect_wal_event_count', 'system_effect_jsonl_event_count'),
                              ('process_lifecycle_wal_event_count', 'process_lifecycle_jsonl_event_count')):
                if _counter(result, wal) != _counter(result, jsonl):
                    raise ValueError('verified WAL/JSONL event counts differ')
            if result.get('socket_state_event_count') is not None:
                _counter(result, 'socket_state_event_count')
            if not isinstance(result.get('evidence_status'), str):
                raise ValueError('verifier evidence_status missing/invalid')
            check.update(verified=True, status='VERIFIED_NOT_A_COMPLETENESS_CLAIM',
                         evidence_status=result.get('evidence_status', 'UNKNOWN'))
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            if check['status'] != 'TIMEOUT':
                check['status'] = 'FAILED'
            check['error'] = type(error).__name__ + ': ' + str(error)
        check['stdout_sha256'] = sha_file(receipt / 'verifier.stdout') if (receipt / 'verifier.stdout').exists() else None
        check['stderr_sha256'] = sha_file(receipt / 'verifier.stderr') if (receipt / 'verifier.stderr').exists() else None
        write_new(receipt / 'receipt.json', check)
        checks.append(check)
    passed = [check for check in checks if check['verified']]
    totals = {field: sum(check['result'].get(field) or 0 for check in passed)
              for field in ('system_effect_wal_event_count', 'process_lifecycle_wal_event_count', 'socket_state_event_count')}
    totals['total_verified_wal_events'] = sum(totals.values())
    summary = {'schema_version': 1, 'input_root': str(root), 'output': str(output),
        'verifier': str(verifier), 'verifier_sha256': expected_sha256.lower(),
        'discovered_expectation_count': len(inputs), 'independent_verification_count': len(passed),
        'verifier_invocation_count': sum('command' in check for check in checks),
        'failed_count': len(checks) - len(passed), 'discovery_issues': discovery_issues,
        'all_replays_passed': bool(checks) and len(passed) == len(checks) and not discovery_issues,
        'evidence_status_counts': dict(Counter(check['evidence_status'] for check in passed)),
        'all_evidence_complete': bool(passed) and len(passed) == len(checks) and not discovery_issues and
                                 all(check['evidence_status'] == 'COMPLETE' for check in passed),
        'event_totals': totals, 'checks': checks,
        'interpretation': 'Host replay checks evidence bindings/WAL reconstruction; INCOMPLETE source coverage remains INCOMPLETE.'}
    write_new(output / 'summary.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--verifier-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=300)
    args = parser.parse_args()
    if not 0 < args.timeout <= 3600:
        parser.error('timeout must be >0 and <=3600 seconds')
    summary = replay(args.root, args.verifier, args.verifier_sha256, args.output, args.timeout)
    print(json.dumps({key: value for key, value in summary.items() if key != 'checks'}))
    raise SystemExit(0 if summary['all_replays_passed'] else 1)


if __name__ == '__main__':
    main()
