#!/usr/bin/env python3
"""Select one intact block plus an explicit continuation without rewriting raw evidence.

This is not a continuation runner.  It creates new hard-linked case directories
and binds their original metadata.  Large event streams and cache-proof gzip
files are *not* read here; their independent byte/record replay is still needed.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

import verify_access_matrix as contract


core = contract.core
KEEP = 32
BOUND_FIELDS = ('schema_version', 'seed', 'source', 'source_inventory_sha256',
    'jobs', 'passes', 'queries', 'cpus', 'measurement_coordinator_sampler_collector_cpus',
    'boot_id', 'measurement_modes', 'file_access_backend', 'collector_budget',
    'binaries', 'participating_source_roots')
METHOD = 'ORIGINAL_INTACT_BLOCK_0_PLUS_EXPLICIT_CONTINUATION_BLOCKS_1_TO_4'
OPAQUE_SCOPE = 'STAT_LENGTH_ONLY; EVENT_BYTES_AND_CACHE_GZIP_NOT_READ_OR_HASHED'


def write_new(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')


def regular_root(path):
    path = Path(path).absolute()
    core.require(path.resolve(strict=True) == path and path.is_dir(),
                 'real nonsymlink evidence directory required: ' + str(path))
    return path


def safe_relative(path):
    core.require(isinstance(path, str) and path and path != '.' and '\0' not in path
        and not Path(path).is_absolute() and '..' not in Path(path).parts
        and str(Path(path)) == path, 'unsafe case/artifact path')
    return path


def tree_receipt(root):
    """Hash bounded metadata/output files; never open events.bin or cache gzip."""
    root = regular_root(root)
    files = {}
    reader = core.Evidence()
    for directory, children, names in os.walk(str(root), followlinks=False):
        parent = Path(directory)
        for name in children:
            info = (parent / name).lstat()
            core.require(stat.S_ISDIR(info.st_mode), 'symlink/non-directory in evidence tree')
        for name in names:
            path = parent / name
            info = path.lstat()
            core.require(stat.S_ISREG(info.st_mode), 'symlink/nonregular evidence artifact')
            relative = str(path.relative_to(root))
            safe_relative(relative)
            opaque = name == 'events.bin' or name.endswith('.gz')
            row = {'bytes': info.st_size,
                   'validation': OPAQUE_SCOPE if opaque else 'SHA256_BOUND_BYTES'}
            if not opaque:
                row['sha256'] = reader.sha(path)
            files[relative] = row
    core.require('campaign.json' in files and 'capture.json' in files,
                 'case must contain campaign and capture evidence')
    return files


def check_case_entry(entry, index, plan, binding, continuation=False):
    wanted = {key: value for key, value in plan.items() if key != 'block'}
    wanted.update(mode='sampler', repetition=0,
                  file_access_backend=binding['file_access_backend'],
                  collector_ring_bytes=binding['collector_budget']['ring_bytes'])
    core.require(entry.get('path') == '%03d-r%d' % (index, plan['block'])
        and core.equal(entry.get('block'), plan['block'])
        and entry.get('stage') == 'performance'
        and core.equal(entry.get('condition'), wanted), 'source case index/condition differs')
    if continuation:
        core.require(core.equal(entry.get('original_schedule_index'), index),
                     'continuation original schedule index differs')


def validate_sources(original, continuation, pause, original_sha, pause_sha):
    """Validate only the exact conservative block-level restart policy."""
    core.require(original.get('status') in ('FAILED', 'COMPLETE'),
                 'original producer must be terminal; never select a running tree')
    core.require(continuation.get('status') == 'COMPLETE'
        and continuation.get('output_equivalence') == 'PASS', 'continuation must finish successfully')
    plans = contract.expected_schedule(101646)
    core.require(core.equal(original.get('schedule'), plans)
        and core.equal(continuation.get('schedule'), plans[KEEP:]),
        'original/full and continuation/suffix schedules differ')
    for field in BOUND_FIELDS:
        core.require(core.equal(original.get(field), continuation.get(field)),
                     'original/continuation fixed scope differs: ' + field)
    core.require(pause.get('status') == 'PAUSED_AT_USER_REQUEST'
        and pause.get('vm_boot_id') == original.get('boot_id')
        and core.integer(pause.get('completed_trials'), KEEP)
        and core.integer(pause.get('in_progress_trial_index'), KEEP)
        and pause['in_progress_trial_index'] < 64
        and pause.get('in_progress_block') == 1
        and pause['completed_trials'] == pause['in_progress_trial_index']
        and pause.get('last_completed_trial_index') == pause['completed_trials'] - 1,
        'pause receipt does not bind the interrupted second block')
    old = original.get('campaigns')
    new = continuation.get('campaigns')
    core.require(isinstance(old, list) and KEEP <= len(old) <= 160
        and isinstance(new, list) and len(new) == 128,
        'source case counts cannot form five complete intact blocks')
    for index, entry in enumerate(old):
        check_case_entry(entry, index, plans[index], original)
    for index, entry in enumerate(new, KEEP):
        check_case_entry(entry, index, plans[index], continuation, continuation=True)
    lineage = continuation.get('continuation')
    core.require(isinstance(lineage, dict)
        and lineage.get('original_matrix_sha256') == original_sha
        and lineage.get('pause_receipt_sha256') == pause_sha
        and core.equal(lineage.get('source_start_index'), KEEP)
        and core.equal(lineage.get('original_schedule_indices'), list(range(KEEP, 160)))
        and core.digest(lineage.get('adapter_sha256')),
        'continuation does not bind the terminal original and exact restart suffix')
    core.require(continuation.get('source_integrity') ==
                 'PARTICIPATING_ROOTS_POST_CAMPAIGN_REHASHED_IDENTICAL',
                 'continuation final immutable-source rehash claim missing')
    selected = copy.deepcopy(continuation)
    selected['schedule'] = plans
    selected['campaigns'] = [copy.deepcopy(row) for row in old[:KEEP] + new]
    selected.pop('continuation', None)
    # This new composition's status never changes either producer's status.
    selected['purpose'] = 'PAUSE_AWARE_SELECTION_OF_FIVE_INTACT_RANDOMIZED_BLOCKS'
    contract.validate_manifest(selected, original['boot_id'])
    return selected


def input_receipt(reader, path):
    path = Path(path).absolute()
    core.require(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode),
                 'real nonsymlink input receipt required')
    return {'path': str(path), 'sha256': reader.sha(path), 'bytes': path.stat().st_size}


def make_selection(original_path, continuation_path, pause_path, output):
    original_path, continuation_path, pause_path = map(Path,
        (original_path, continuation_path, pause_path))
    reader = core.Evidence()
    refs = {name: input_receipt(reader, path) for name, path in
        (('original_matrix', original_path), ('continuation_matrix', continuation_path),
         ('pause_receipt', pause_path))}
    original, continuation, pause = map(reader.json,
        (original_path, continuation_path, pause_path))
    selected = validate_sources(original, continuation, pause,
        refs['original_matrix']['sha256'], refs['pause_receipt']['sha256'])
    original_root, continuation_root = map(regular_root,
        (original_path.parent, continuation_path.parent))
    output = Path(output).absolute()
    core.require(not output.exists() and not output.is_symlink(), 'fresh selection output required')
    for source in (original_root, continuation_root):
        core.require(source not in output.parents, 'selection cannot be created inside raw evidence')
    core.require(output.parent.resolve(strict=True) == output.parent,
                 'real existing selection parent required')
    source_cases, used = [], set()
    for index, entry in enumerate(selected['campaigns']):
        root = original_root if index < KEEP else continuation_root
        case = regular_root(root / safe_relative(entry['path']))
        core.require(case.parent == root and case not in used, 'duplicate/escaping source case')
        used.add(case)
        source_cases.append((case, tree_receipt(case)))
    output.mkdir()
    rows = []
    for index, ((source, files), entry) in enumerate(zip(source_cases, selected['campaigns'])):
        destination = output / entry['path']
        shutil.copytree(str(source), str(destination), copy_function=os.link)
        core.require(core.equal(files, tree_receipt(destination)), 'new hard-linked case metadata differs')
        rows.append({'index': index, 'block': selected['schedule'][index]['block'],
            'selected_path': entry['path'],
            'source': 'original_matrix' if index < KEEP else 'continuation_matrix',
            'source_path': entry['path'], 'artifacts': files})
    lineage = {'schema_version': 1, 'status': 'COMPOSED_NOT_RAW_EVENT_VERIFIED',
        'method': METHOD, 'inputs': refs, 'cases': rows,
        'original_producer_status_preserved': original['status'],
        'original_kept_schedule_indices': list(range(KEEP)),
        'continuation_selected_schedule_indices': list(range(KEEP, 160)),
        'excluded_original_completed_schedule_indices': list(range(KEEP, len(original['campaigns']))),
        'excluded_original_in_progress_index': pause['in_progress_trial_index'],
        'replacement_scope': 'EVERY_ORIGINAL_CASE_FROM_BLOCK_1_ONWARD; NOT_ONLY_PAUSE_CROSSING_CASE',
        'payload_policy': 'NEW_DIRECTORIES_HARDLINK_UNMODIFIED_SOURCE_FILES; SOURCES_MUST_REMAIN_IMMUTABLE',
        'large_artifact_validation': OPAQUE_SCOPE,
        'selection_program_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    write_new(output / 'selection.json', lineage)
    selected['composition'] = {'path': 'selection.json',
        'sha256': hashlib.sha256((output / 'selection.json').read_bytes()).hexdigest(),
        'method': METHOD, 'original_status': original['status'],
        'raw_event_validation': 'NOT_PERFORMED_BY_SELECTION'}
    write_new(output / 'matrix.json', selected)
    return selected


def verify_selection(matrix_path, original_path=None, continuation_path=None, pause_path=None,
                     expected_boot_id=None, runtime_dir=None):
    """Replay origin bindings first, then the unchanged strict 160-case verifier."""
    matrix_path = Path(matrix_path).absolute()
    reader = core.Evidence()
    result = {'schema_version': 1, 'verified': False, 'status': 'FAILED', 'issues': [],
        'scope': 'PAUSE_LINEAGE_AND_SMALL_METADATA_BYTES_PLUS_EXISTING_FIXED_WORK_VERIFIER; NOT_RAW_EVENT_OR_CACHE_PROOF_REPLAY'}
    try:
        root = regular_root(matrix_path.parent)
        matrix = reader.json(matrix_path)
        composition = matrix.get('composition')
        core.require(isinstance(composition, dict) and composition.get('path') == 'selection.json'
            and composition.get('method') == METHOD
            and composition.get('sha256') == reader.sha(root / 'selection.json'),
            'matrix does not bind its pause selection receipt')
        lineage = reader.json(root / 'selection.json')
        core.require(type(lineage.get('schema_version')) is int and lineage['schema_version'] == 1
            and lineage.get('method') == METHOD
            and lineage.get('status') == 'COMPOSED_NOT_RAW_EVENT_VERIFIED'
            and lineage.get('large_artifact_validation') == OPAQUE_SCOPE
            and lineage.get('payload_policy') ==
                'NEW_DIRECTORIES_HARDLINK_UNMODIFIED_SOURCE_FILES; SOURCES_MUST_REMAIN_IMMUTABLE'
            and lineage.get('replacement_scope') ==
                'EVERY_ORIGINAL_CASE_FROM_BLOCK_1_ONWARD; NOT_ONLY_PAUSE_CROSSING_CASE'
            and core.digest(lineage.get('selection_program_sha256')),
            'selection receipt contract differs')
        inputs = lineage['inputs']
        overrides = dict(original_matrix=original_path, continuation_matrix=continuation_path,
                         pause_receipt=pause_path)
        paths = {}
        for name in ('original_matrix', 'continuation_matrix', 'pause_receipt'):
            source = Path(overrides[name] or inputs[name]['path']).absolute()
            receipt = input_receipt(reader, source)
            core.require(receipt['sha256'] == inputs[name]['sha256']
                and receipt['bytes'] == inputs[name]['bytes'], 'source receipt byte binding differs: ' + name)
            paths[name] = source
        old, new, pause = [reader.json(paths[name]) for name in
            ('original_matrix', 'continuation_matrix', 'pause_receipt')]
        expected = validate_sources(old, new, pause,
            inputs['original_matrix']['sha256'], inputs['pause_receipt']['sha256'])
        stripped = copy.deepcopy(matrix)
        stripped.pop('composition', None)
        core.require(core.equal(stripped, expected), 'selected matrix differs from independently reconstructed composition')
        core.require(composition.get('original_status') == old['status']
            and lineage.get('original_producer_status_preserved') == old['status']
            and core.equal(lineage.get('original_kept_schedule_indices'), list(range(KEEP)))
            and core.equal(lineage.get('continuation_selected_schedule_indices'), list(range(KEEP, 160)))
            and core.equal(lineage.get('excluded_original_completed_schedule_indices'), list(range(KEEP, len(old['campaigns']))))
            and lineage.get('excluded_original_in_progress_index') == pause['in_progress_trial_index'],
            'excluded/kept block or producer-status provenance differs')
        rows = lineage.get('cases')
        core.require(isinstance(rows, list) and len(rows) == 160, 'exactly 160 selected origin cases required')
        for index, (row, entry) in enumerate(zip(rows, expected['campaigns'])):
            name = 'original_matrix' if index < KEEP else 'continuation_matrix'
            core.require(row.get('index') == index and row.get('block') == expected['schedule'][index]['block']
                and row.get('source') == name and row.get('source_path') == entry['path']
                and row.get('selected_path') == entry['path'], 'selected origin index/path differs')
            source_root = regular_root(paths[name].parent)
            source = regular_root(source_root / safe_relative(row['source_path']))
            destination = regular_root(root / safe_relative(row['selected_path']))
            core.require(source.parent == source_root and destination.parent == root,
                         'source/selected case is not a direct real child')
            wanted = row.get('artifacts')
            core.require(core.equal(tree_receipt(source), wanted)
                and core.equal(tree_receipt(destination), wanted),
                'origin/selected artifact names, metadata SHA or opaque size differs at index ' + str(index))
        fixed = contract.verify(matrix_path, expected_boot_id, runtime_dir=runtime_dir)
        result['fixed_work_verification'] = fixed
        core.require(fixed['verified'], 'strict fixed-work/collector bindings replay failed')
        status = ('VERIFIED_PAUSE_SELECTION_WITH_INCOMPLETE_DIMENSIONS'
            if 'INCOMPLETE' in fixed['status'] else 'VERIFIED_PAUSE_SELECTION_WITH_DECLARED_SCOPE')
        result.update(verified=True, status=status,
            selected_cases=160, intact_original_cases=32, continuation_cases=128,
            original_status_preserved=old['status'],
            raw_event_validation='NOT_PERFORMED; REQUIRES_INDEPENDENT_ACCESS_ANALYSIS',
            matrix_sha256=reader.sha(matrix_path), selection_sha256=reader.sha(root / 'selection.json'))
    except (ValueError, OSError, TypeError, KeyError, IndexError, AttributeError, OverflowError) as error:
        result['issues'].append({'code': 'PAUSE_SELECTION_VERIFICATION_FAILED', 'detail': str(error)})
    result['input_receipts'] = reader.receipts
    result['verifier_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('build')
    build.add_argument('--original-matrix', required=True, type=Path)
    build.add_argument('--continuation-matrix', required=True, type=Path)
    build.add_argument('--pause-receipt', required=True, type=Path)
    build.add_argument('--output-dir', required=True, type=Path)
    check = sub.add_parser('verify')
    check.add_argument('--matrix', required=True, type=Path)
    check.add_argument('--original-matrix', type=Path)
    check.add_argument('--continuation-matrix', type=Path)
    check.add_argument('--pause-receipt', type=Path)
    check.add_argument('--expected-boot-id')
    check.add_argument('--runtime-dir', type=Path)
    check.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'build':
        matrix = make_selection(args.original_matrix, args.continuation_matrix,
                                args.pause_receipt, args.output_dir)
        print(json.dumps({'cases': len(matrix['campaigns']), 'output': str(args.output_dir)}))
        return 0
    result = verify_selection(args.matrix, args.original_matrix, args.continuation_matrix,
        args.pause_receipt, args.expected_boot_id, args.runtime_dir)
    output = args.output.absolute()
    raw_sources = [args.matrix.parent, args.runtime_dir]
    raw_sources += [value.parent for value in
        (args.original_matrix, args.continuation_matrix) if value]
    for source in raw_sources:
        if source:
            core.require(Path(source).resolve() not in output.resolve().parents,
                         'verification output must be outside selected/frozen evidence')
    output.parent.mkdir(parents=True, exist_ok=True)
    write_new(output, result)
    print(json.dumps({'verified': result['verified'], 'status': result['status'], 'output': str(output)}))
    return 0 if result['verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
