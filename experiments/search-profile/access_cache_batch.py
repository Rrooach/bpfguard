#!/usr/bin/env python3
"""Replay 160 saved cache proofs in separate serial child processes.

Use only after the workload campaign has ended.  Each large decoded proof is
owned by one child and released before the next starts.  Failed receipts and
stdout/stderr remain intact; this coordinator never changes a failed proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import verify_access_matrix as formal


MAX_DOCUMENT_BYTES = 8 * 1024 ** 2


def document(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError('bounded regular JSON document required: ' + str(path))
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError('JSON object required: ' + str(path))
    return value


def fingerprint(path):
    path, digest = Path(path), hashlib.sha256()
    before = path.stat()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 ** 2), b''):
            digest.update(block)
    after = path.stat()
    if any(getattr(before, key) != getattr(after, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
        raise ValueError('input changed while hashing: ' + str(path))
    return {'path': str(path.resolve(strict=True)), 'sha256': digest.hexdigest(), 'bytes': before.st_size}


def child(root, relative):
    path = Path(relative)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('safe descendant evidence path required')
    candidate = root / path
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(root.resolve(strict=True))
    if candidate.is_symlink():
        raise ValueError('symlink evidence path is not supported')
    return resolved


def write_new(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def update_owned(path, value):
    temporary = Path(path).with_name('.' + Path(path).name + '.' + uuid.uuid4().hex + '.tmp')
    write_new(temporary, value)
    os.replace(str(temporary), str(path))


def plan_batch(matrix_path, inventory_path, preparation_path):
    matrix_path, inventory_path, preparation_path = [Path(p).resolve(strict=True)
        for p in (matrix_path, inventory_path, preparation_path)]
    matrix = document(matrix_path)
    plans = formal.validate_manifest(matrix)
    inventory, preparation = fingerprint(inventory_path), document(preparation_path)
    if (inventory['sha256'] != matrix['source_inventory_sha256']
            or preparation.get('inventory_sha256') != inventory['sha256']
            or preparation.get('source') != matrix['source'] or preparation.get('boot_id') != matrix['boot_id']):
        raise ValueError('matrix/preparation/immutable inventory binding differs')
    cases, seen = [], set()
    for index, (entry, scheduled) in enumerate(zip(matrix['campaigns'], plans)):
        case_id = entry.get('path')
        if (not isinstance(case_id, str) or len(Path(case_id).parts) != 1
                or case_id != '%03d-r%d' % (index, scheduled['block']) or case_id in seen
                or entry.get('block') != scheduled['block'] or not isinstance(entry.get('condition'), dict)
                or any(entry['condition'].get(key) != value for key, value in scheduled.items() if key != 'block')):
            raise ValueError('formal direct case identity/order/condition differs')
        seen.add(case_id)
        root = child(matrix_path.parent, case_id)
        capture = document(root / 'capture.json')
        profile_path = child(root, capture.get('profile_path', ''))
        if profile_path.name != 'profile-run.json' or not profile_path.is_file():
            raise ValueError('capture must bind its own profile-run.json')
        cases.append({'case_id': case_id, 'trial': str(profile_path.parent),
            'capture': fingerprint(root / 'capture.json'), 'profile': fingerprint(profile_path)})
    return {'schema_version': 1, 'matrix': fingerprint(matrix_path), 'inventory': inventory,
        'preparation': fingerprint(preparation_path), 'cases': cases,
        'scope': 'SAVED_CACHE_PROOF_REPLAY_AFTER_CAMPAIGN; SERIAL_ONE_CHILD_PER_CASE; NO_LIVE_GUEST_ACCESS',
        'original_pin_binding': 'NOT_SUPPLIED; PROOF_REPLAY_MUST_KEEP_ORIGINAL_PIN_IDENTITY_UNKNOWN'}


def invoke(command, stdout, stderr, timeout_seconds):
    with Path(stdout).open('xb') as out, Path(stderr).open('xb') as err:
        try:
            result = subprocess.run(command, stdout=out, stderr=err, timeout=timeout_seconds, check=False)
            return {'returncode': result.returncode, 'error': None}
        except (OSError, subprocess.TimeoutExpired) as error:
            return {'returncode': None, 'error': type(error).__name__ + ':' + str(error)}


def run_batch(plan, output, checker=None, indexer=None, timeout_seconds=600):
    """Serial subprocess loop; injectable tools are only for tiny unit fixtures."""
    output = Path(output).absolute()
    checker = Path(checker) if checker is not None else Path(__file__).with_name('verify_cache_proof.py')
    indexer = Path(indexer) if indexer is not None else Path(__file__).with_name('verify_access_results.py')
    if output.exists() or Path(plan['matrix']['path']).parent in output.resolve().parents:
        raise ValueError('fresh output outside raw campaign evidence required')
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError('positive child timeout required')
    output.mkdir(mode=0o700)
    (output / 'receipts').mkdir()
    (output / 'logs').mkdir()
    receipt = {'schema_version': 1, 'status': 'RUNNING', 'selected_cases': len(plan['cases']),
        'results': {}, 'failures': {}, 'plan': plan, 'started_monotonic_ns': time.monotonic_ns(),
        'tools': {'coordinator': fingerprint(__file__), 'cache_verifier': fingerprint(checker),
                  'index_builder': fingerprint(indexer)}, 'child_timeout_seconds': timeout_seconds}
    write_new(output / 'batch.json', receipt)
    with (output / 'progress.jsonl').open('x', encoding='utf-8') as journal:
        for index, case in enumerate(plan['cases']):
            case_id = case['case_id']
            target = output / 'receipts' / (case_id + '.json')
            command = [sys.executable, '-B', str(checker), '--trial', case['trial'],
                '--inventory', plan['inventory']['path'], '--expected-inventory-sha256', plan['inventory']['sha256'],
                '--preparation', plan['preparation']['path'], '--output', str(target)]
            before = time.monotonic_ns()
            result = invoke(command, output / 'logs' / (case_id + '.stdout'),
                            output / 'logs' / (case_id + '.stderr'), timeout_seconds)
            result.update(command=command, elapsed_seconds=(time.monotonic_ns() - before) / 1e9)
            try:
                proof = document(target)
                result.update(receipt=fingerprint(target), proof_status=proof.get('status'),
                    cache_condition_replay=proof.get('cache_condition_replay'))
                if result['returncode'] != 0 or result['error'] is not None or (
                        proof.get('status') != 'PASS' or proof.get('cache_condition_replay') != 'PASS'):
                    receipt['failures'][case_id] = 'CHILD_FAILED_OR_CACHE_PROOF_DID_NOT_PASS'
            except (OSError, ValueError, TypeError) as error:
                receipt['failures'][case_id] = type(error).__name__ + ':' + str(error)
            receipt['results'][case_id] = result
            row = {'index': index, 'case_id': case_id, 'result': result,
                'failed': case_id in receipt['failures']}
            journal.write(json.dumps(row, ensure_ascii=False) + '\n')
            journal.flush()
            print(json.dumps({'completed': index + 1, 'total': len(plan['cases']), 'case_id': case_id,
                'failed': row['failed']}), flush=True)
    index_command = [sys.executable, '-B', str(indexer), 'index-cache', '--matrix', plan['matrix']['path'],
        '--receipts-dir', str(output / 'receipts'), '--output', str(output / 'index.json')]
    receipt['index_builder'] = invoke(index_command, output / 'logs' / 'index.stdout',
                                     output / 'logs' / 'index.stderr', timeout_seconds)
    receipt['index_builder']['command'] = index_command
    try:
        cache_index = document(output / 'index.json')
        receipt['index'] = fingerprint(output / 'index.json')
        if (receipt['index_builder']['returncode'] != 0 or receipt['index_builder']['error'] is not None
                or cache_index.get('status') != 'COMPLETE_FOR_SELECTED_CASES'
                or cache_index.get('failures') != {} or len(cache_index.get('results', {})) != len(plan['cases'])):
            receipt['failures']['__index__'] = 'INDEX_CHILD_FAILED_OR_CACHE_INDEX_INCOMPLETE'
    except (OSError, ValueError, TypeError) as error:
        receipt['failures']['__index__'] = type(error).__name__ + ':' + str(error)
    for key in ('matrix', 'inventory', 'preparation'):
        if fingerprint(plan[key]['path']) != plan[key]:
            receipt['failures']['__input_' + key + '__'] = 'INPUT_CHANGED_DURING_BATCH'
    receipt.update(status='INCOMPLETE' if receipt['failures'] else 'COMPLETE_FOR_SELECTED_CASES',
        ended_monotonic_ns=time.monotonic_ns())
    update_owned(output / 'batch.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('matrix', 'inventory', 'preparation', 'output-dir'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    plan = plan_batch(args.matrix, args.inventory, args.preparation)
    receipt = run_batch(plan, args.output_dir)
    print(json.dumps({'status': receipt['status'], 'selected_cases': receipt['selected_cases'],
        'failures': len(receipt['failures']), 'output': str(args.output_dir)}))
    return 0 if receipt['status'] == 'COMPLETE_FOR_SELECTED_CASES' else 1


if __name__ == '__main__':
    raise SystemExit(main())
