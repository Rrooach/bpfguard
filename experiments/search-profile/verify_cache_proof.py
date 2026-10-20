#!/usr/bin/env python3
"""Independently replay ONE saved mincore proof, never probe a live filesystem.

Example (after the timed campaign, not while workloads are running)::

  python3 -B verify_cache_proof.py --trial EXPORTED_TRIAL \
    --inventory PREPARED/corpus-inventory.json \
    --expected-inventory-sha256 SHA256 --output NEW-RECEIPT.json

Default scope is 95,989 files, one shared root or eight independent roots.
--preparation can bind exact root paths and the recorded read-only declaration;
--pinned can additionally replay a retained MINCORE_MULTIPLE_ROOT_PINS document.
Old runners did not persist that document: pin_binding then stays UNKNOWN.

This checks saved records, not the truth of mincore, current residency, atomic
cache state, immutable files, kernel trust or Host/storage caches. It never
reads corpus file data, contacts a Guest, drops caches or changes old evidence.
Whole-proof JSON is explicitly bounded (default 1 GiB decoded); run serially
outside performance windows. It is not a streaming/low-memory verifier.
"""
import argparse
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat


MAX_FILES = 200000
MAX_JSON = 128 * 1024 ** 2
MAX_GZIP = 256 * 1024 ** 2
MAX_PROOF = 1024 ** 3
HEX = re.compile(r'^[0-9a-f]{64}$')
AUTHORITY = 'FILE_OWNER_FSUID_MATCH_REQUIRED_TO_EXCLUDE_LINUX_ALL_ONES_PERMISSION_MASKING'
AGGREGATION = 'ROOTS_REPORTED_SEPARATELY_NO_PHYSICAL_CACHE_BYTES_SUMMED'
LIMITS = [
    'Replays the supplied saved mincore records; not an independent live measurement or sensor attestation.',
    'Per-file and per-root samples are sequential, non-atomic and may change before release; all ages are reported.',
    'Metadata was traversed: Guest data-cold is not metadata-cold, Host-cache-cold or SSD-cache-cold.',
    'No per-page bitmap is saved: resident_bytes is checked against legal bounds and raw aggregate sums only.',
    'A missing original pin leaves pin_binding UNKNOWN; its SHA string is not a substitute for the original document.',
    'Read-only status, when present, is a producer declaration, not independently re-attested mount state.',
    'Content SHA and metadata are declarations, not rehashed live corpus content or inode-reuse-proof identity.',
    'Input SHA values only establish byte binding; their external authenticity is the caller responsibility.',
    'Bounded whole-proof JSON may use substantial memory; run after timing, serially, not as hot-path overhead.',
]


class ProofError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ProofError(message)


def number(value, name, minimum=0):
    require(type(value) is int and value >= minimum, 'invalid integer: ' + name)
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def hex_digest(value, name):
    require(isinstance(value, str) and HEX.fullmatch(value) is not None, 'invalid SHA256: ' + name)
    return value


def path(value, absolute=False):
    require(isinstance(value, str) and value and '\0' not in value and len(value.encode()) <= 4096,
            'invalid bounded path')
    parsed = PurePosixPath(value)
    require(parsed.is_absolute() == absolute and parsed.as_posix() == value and
            '..' not in parsed.parts and value not in ('.', '..'), 'noncanonical path: ' + value)
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def json_value(raw):
    return json.loads(raw, object_pairs_hook=unique_object,
        parse_constant=lambda value: (_ for _ in ()).throw(ProofError('non-finite JSON value: ' + value)))


def read_document(source, compressed=False, max_proof_bytes=MAX_PROOF):
    """Hash and decode from one held regular-file FD, with stable metadata."""
    source = Path(source)
    descriptor = os.open(str(source), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        limit = MAX_GZIP if compressed else MAX_JSON
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'input exceeds regular-file byte budget')
        captured = stream.read(limit + 1)
        require(len(captured) <= limit, 'input grew past explicit byte budget')
        hashed = hashlib.sha256(captured)
        if compressed:
            with gzip.GzipFile(fileobj=io.BytesIO(captured), mode='rb') as decoded:
                raw = decoded.read(max_proof_bytes + 1)
            require(len(raw) <= max_proof_bytes, 'decoded cache proof exceeds explicit byte budget')
        else:
            raw = captured
        result = json_value(raw)
        after = os.fstat(stream.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(identity(before) == identity(after), 'input changed while being verified')
    return result, {'path': str(source), 'sha256': hashed.hexdigest(), 'bytes': before.st_size}


def inventory_scope(inventory, expected_files):
    rows = inventory.get('files')
    require(isinstance(rows, list) and len(rows) == expected_files and 1 <= len(rows) <= MAX_FILES,
            'inventory file cardinality differs from declared experiment')
    seen = set()
    for row in rows:
        relative = path(row.get('path'))
        require(relative not in seen, 'duplicate inventory path')
        seen.add(relative)
        number(row.get('size'), 'inventory size')
        hex_digest(row.get('sha256'), 'inventory content')
    require(inventory.get('sha256') == digest(rows), 'inventory content-list digest mismatch')
    require(inventory.get('bytes') == sum(row['size'] for row in rows), 'inventory byte total mismatch')
    permissions = inventory.get('permissions')
    require(isinstance(permissions, list), 'permission inventory absent')
    require(inventory.get('permission_scope_sha256') == digest(permissions), 'permission-scope digest mismatch')
    permission_index = {}
    for row in permissions:
        relative = row.get('path')
        if relative != '.':
            path(relative)
        require(relative not in permission_index, 'duplicate permission path')
        for key in ('mode', 'uid', 'gid'):
            number(row.get(key), 'permission ' + key)
        permission_index[relative] = row
    require(seen <= set(permission_index), 'regular file omitted from permissions')
    return rows, permission_index


def check_identity(identity, row, permissions, fsuid):
    require(isinstance(identity, dict), 'file identity missing')
    for name in ('device', 'inode', 'size', 'mode', 'uid', 'gid', 'nlink'):
        number(identity.get(name), 'identity ' + name, 1 if name in ('inode', 'nlink') else 0)
    for name in ('mtime_ns', 'ctime_ns'):
        require(type(identity.get(name)) is int, 'invalid timestamp metadata: ' + name)
    require(identity['size'] == row['size'] and stat.S_ISREG(identity['mode']), 'file size/type identity mismatch')
    require(identity['uid'] == fsuid, 'mincore owner FSUID authority not established')
    expected = permissions[row['path']]
    require((stat.S_IMODE(identity['mode']), identity['uid'], identity['gid']) ==
            (expected['mode'], expected['uid'], expected['gid']), 'file permission metadata differs from bound inventory')


def legal_resident_bounds(size, pages, resident, page_size):
    if not resident:
        return 0, 0
    last = size % page_size or page_size
    return (resident - 1) * page_size + last, min(resident * page_size, size)


def replay(profile, compact, full, inventory, expected_files=95989, preparation=None,
           pinned=None, expected_page_size=4096):
    require(profile.get('status') == 'COMPLETE', 'trial did not complete')
    require(isinstance(profile.get('run_id'), str) and profile['run_id'] and
            isinstance(profile.get('boot_id'), str) and profile['boot_id'], 'run/boot binding missing')
    config = profile.get('config', {})
    mode, layout = config.get('cache'), config.get('workspace_layout')
    require(mode in ('warm', 'guest-cold') and layout in ('shared', 'independent'), 'unsupported cache/layout scope')
    jobs = number(config.get('jobs'), 'jobs', 1)
    require(jobs == 8, 'this experiment fixes eight logical tasks')
    release = number(profile.get('release_ns'), 'release', 1)
    expected, permissions = inventory_scope(inventory, expected_files)
    require(config.get('corpus_sha256') == inventory['sha256'] and
            config.get('permission_scope_sha256') == inventory['permission_scope_sha256'], 'profile inventory scope binding differs')
    require(full.get('schema_version') == 1 and full.get('kind') == 'MINCORE_MULTIPLE_ROOT_RESIDENCY'
            and full.get('status') == 'OBSERVED_NON_ATOMIC', 'proof status/kind incomplete')
    require(full.get('aggregation') == AGGREGATION, 'unexpected cache aggregation contract')
    require(full.get('independent_roots_required') is (layout == 'independent'), 'independent-root contract differs')
    require(full.get('shared_dev_inode_identities') == [], 'reported shared identities invalidate independent-root condition')
    roots = full.get('roots')
    require(isinstance(roots, list) and len(roots) == (8 if layout == 'independent' else 1), 'cache root cardinality differs')
    root_names = [path(root.get('root'), absolute=True) for root in roots]
    require(len(set(root_names)) == len(root_names), 'duplicate cache root')
    # Copy only summaries: do not copy hundreds of thousands of file rows.
    reduced = {key: value for key, value in full.items() if key != 'roots'}
    reduced['roots'] = [{key: value for key, value in root.items() if key != 'files'} for root in roots]
    require(reduced == {key: value for key, value in compact.items() if key != 'file_details'},
            'compact proof differs from full per-file artifact')
    declaration = 'UNKNOWN'
    scope_binding = 'UNKNOWN'
    if preparation is not None:
        require(preparation.get('boot_id') == profile.get('boot_id'), 'preparation boot differs')
        declared_roots = [preparation.get('corpus')] if layout == 'shared' else preparation.get('independent_roots')
        require(isinstance(declared_roots, list) and sorted(declared_roots) == sorted(root_names), 'exact prepared root scope differs')
        number(preparation.get('completed_monotonic_ns'), 'preparation completed', 1)
        scope_binding = 'MATCHES_PREPARATION_DECLARATION'
        declaration = 'DECLARED_READ_ONLY_NOT_REATTESTED' if preparation.get('read_only_bind_mounts') is True else 'UNKNOWN'
    pin_roots = {}
    if pinned is not None:
        require(pinned.get('schema_version') == 1 and pinned.get('kind') == 'MINCORE_MULTIPLE_ROOT_PINS'
                and pinned.get('status') == 'PINNED' and pinned.get('independent_roots_required') is (layout == 'independent')
                and pinned.get('shared_dev_inode_identities') == [], 'invalid original pin document')
        require(isinstance(pinned.get('roots'), list) and len(pinned['roots']) == len(roots),
                'original pin root cardinality differs')
        pin_roots = {row['root']: row for row in pinned['roots']}
        require(len(pin_roots) == len(roots) and set(pin_roots) == set(root_names), 'original pin roots differ')
    reports, identities = [], {}
    previous_root_end = 0
    inventory_digest = digest(expected)
    for root in roots:
        require(root.get('schema_version') == 1 and root.get('kind') == 'MINCORE_FILE_DATA_RESIDENCY'
                and root.get('status') == 'OBSERVED_NON_ATOMIC' and root.get('errors') == [], 'root observation incomplete')
        page_size = number(root.get('page_size'), 'page size', 1)
        require(page_size == expected_page_size and page_size & (page_size - 1) == 0, 'base page size differs')
        require(root.get('inventory_sha256') == inventory_digest, 'root inventory digest differs')
        hex_digest(root.get('pin_sha256'), 'preparation pin')
        require(root.get('mincore_authority') == AUTHORITY, 'mincore authority contract differs')
        fsuid = number(root.get('filesystem_uid'), 'filesystem UID')
        started = number(root.get('start_monotonic_ns'), 'root start', 1)
        ended = number(root.get('end_monotonic_ns'), 'root end', 1)
        require(previous_root_end <= started <= ended <= release, 'root probes overlap or follow release')
        require(root.get('duration_ns') == ended - started, 'root duration mismatch')
        previous_root_end = ended
        if preparation is not None:
            require(preparation['completed_monotonic_ns'] <= started, 'probe precedes preparation completion')
        rows = root.get('files')
        require(isinstance(rows, list) and len(rows) == len(expected), 'per-root file count differs')
        pin = pin_roots.get(root['root'])
        if pin is not None:
            require(pin.get('kind') == 'MINCORE_PRE_CACHE_PREPARATION_PIN' and pin.get('status') == 'PINNED'
                    and pin.get('errors') == [] and pin.get('inventory_sha256') == inventory_digest,
                    'original root pin incomplete')
            require(digest(pin) == root['pin_sha256'], 'original pin digest mismatch')
            require(number(pin.get('pin_started_ns'), 'pin start', 1) <=
                    number(pin.get('pin_completed_ns'), 'pin end', 1) <= started, 'pin timing invalid')
            require(len(pin.get('files', [])) == len(rows), 'original pin file cardinality differs')
        totals = dict(total_pages=0, total_bytes=0, resident_pages=0, resident_bytes=0)
        previous_end, first_start, last_end = started, None, None
        seen = set()
        for index, (row, source) in enumerate(zip(rows, expected)):
            require(isinstance(row, dict) and row.get('path') == source['path'] and type(row.get('size')) is int and row.get('size') == source['size']
                    and row.get('sha256') == source['sha256'], 'per-file scope/order/size/content digest differs')
            require(row['path'] not in seen, 'duplicate per-file proof path')
            seen.add(row['path'])
            require(row.get('status') == 'OBSERVED_NON_ATOMIC' and 'error' not in row, 'file residency UNKNOWN')
            begin = number(row.get('start_monotonic_ns'), 'file start', 1)
            end = number(row.get('end_monotonic_ns'), 'file end', 1)
            require(previous_end <= begin <= end <= ended, 'file probe timing is not sequential or pre-release')
            previous_end, last_end = end, end
            first_start = begin if first_start is None else first_start
            check_identity(row.get('identity'), source, permissions, fsuid)
            if pin is not None:
                original = pin['files'][index]
                require(original.get('pin_status') == 'PINNED' and original.get('path') == row['path']
                        and original.get('size') == row['size'] and original.get('sha256') == row['sha256']
                        and original.get('identity') == row['identity'], 'per-file identity differs from original pin')
            key = row['identity']['device'], row['identity']['inode']
            if layout == 'independent':
                require(key not in identities or identities[key] == root['root'], 'independent copies share a device/inode')
                identities[key] = root['root']
            count = (source['size'] + page_size - 1) // page_size
            require(type(row.get('total_pages')) is int and type(row.get('total_bytes')) is int
                    and row.get('total_pages') == count and row.get('total_bytes') == source['size'], 'file page/byte total differs')
            resident = number(row.get('resident_pages'), 'resident pages')
            resident_bytes = number(row.get('resident_bytes'), 'resident bytes')
            require(resident <= count, 'resident page count exceeds file')
            lower, upper = legal_resident_bounds(source['size'], count, resident, page_size)
            require(lower <= resident_bytes <= upper, 'resident bytes outside legal partial-page bounds')
            for key in totals:
                totals[key] += row[key]
        for key, value in totals.items():
            require(type(root.get(key)) is int and root[key] == value, 'root ' + key + ' aggregate mismatch')
        for key, value in totals.items():
            observed = 'observed_' + key
            require(type(root.get(observed)) is int and root[observed] == value, 'root ' + observed + ' mismatch')
        require(all(type(root.get(key)) is int for key in ('declared_file_count', 'observed_file_count', 'unknown_file_count'))
                and root.get('declared_file_count') == len(rows) and root.get('observed_file_count') == len(rows)
                and root.get('unknown_file_count') == 0, 'declared/observed/unknown file totals differ')
        require(totals['total_pages'] > 0, 'empty data scope cannot establish hot/cold condition')
        fraction = totals['resident_pages'] / totals['total_pages']
        observed_fraction = root.get('resident_fraction')
        require(type(observed_fraction) in (float, int) and math.isfinite(observed_fraction)
                and abs(observed_fraction - fraction) <= 1e-15, 'resident fraction mismatch')
        state = ('ALL_NONRESIDENT_AT_EACH_FILE_PROBE' if totals['resident_pages'] == 0 else
                 'ALL_RESIDENT_AT_EACH_FILE_PROBE' if totals['resident_pages'] == totals['total_pages'] else 'MIXED_RESIDENCY')
        require(root.get('data_page_state') == state, 'root data-page state mismatch')
        require((mode == 'warm' and totals['resident_pages'] * 1000 >= totals['total_pages'] * 999)
                or (mode == 'guest-cold' and totals['resident_pages'] * 1000 <= totals['total_pages']), 'replayed cache threshold fails')
        reports.append({'root': root['root'], 'files': len(rows), **totals, 'resident_fraction': fraction,
            'threshold_result': 'PASS', 'root_start_to_release_ns': release - started,
            'root_end_to_release_ns': release - ended, 'oldest_file_start_to_release_ns': release - first_start,
            'newest_file_end_to_release_ns': release - last_end,
            'non_atomic_probe_span_ns': ended - started})
    require(number(profile.get('cache_probe_end_to_release_ns'), 'last-root release interval') ==
            release - max(row['end_monotonic_ns'] for row in roots),
            'last-root-to-release interval mismatch')
    return {'status': 'PASS', 'claim_scope': 'SAVED_CACHE_RECORD_REPLAY_ONLY_NOT_LIVE_CACHE_TRUTH',
        'cache_condition_replay': 'PASS', 'run_id': profile.get('run_id'), 'boot_id': profile.get('boot_id'),
        'cache': mode, 'workspace_layout': layout, 'release_ns': release, 'roots': reports,
        'pin_binding': 'MATCHES_ORIGINAL_PIN_RECORDS' if pinned is not None else 'UNKNOWN',
        'readonly_quality': declaration, 'root_scope_binding': scope_binding,
        'resident_bytes_verification': 'LEGAL_BOUNDS_AND_RAW_SUMS_ONLY_NO_PAGE_BITMAP',
        'global_oldest_file_start_to_release_ns': max(row['oldest_file_start_to_release_ns'] for row in reports),
        'atomic_snapshot': False, 'limitations': list(LIMITS)}


def verify_trial(trial, inventory_path, expected_inventory_sha256, expected_files=95989,
                 preparation_path=None, pinned_path=None, max_proof_bytes=MAX_PROOF):
    profile, p_receipt = read_document(Path(trial) / 'profile-run.json')
    compact, s_receipt = read_document(Path(trial) / 'cache-residency.json')
    full, f_receipt = read_document(Path(trial) / 'cache-residency-files.json.gz', True, max_proof_bytes)
    inventory, i_receipt = read_document(inventory_path)
    hex_digest(expected_inventory_sha256, 'external inventory binding')
    require(i_receipt['sha256'] == expected_inventory_sha256, 'external inventory byte digest differs')
    require(profile.get('cache_residency', {}).get('path') == 'cache-residency.json'
            and profile['cache_residency'].get('sha256') == s_receipt['sha256'], 'profile compact-proof byte binding differs')
    require(compact.get('file_details', {}).get('path') == 'cache-residency-files.json.gz'
            and compact['file_details'].get('sha256') == f_receipt['sha256'], 'gzip proof byte binding differs')
    inputs = {'profile': p_receipt, 'summary': s_receipt, 'file_details': f_receipt, 'inventory': i_receipt}
    preparation = pinned = None
    if preparation_path is not None:
        preparation, inputs['preparation'] = read_document(preparation_path)
        require(preparation.get('inventory_sha256') == i_receipt['sha256'], 'preparation inventory byte binding differs')
    if pinned_path is not None:
        pinned, inputs['original_pin'] = read_document(pinned_path)
    result = replay(profile, compact, full, inventory, expected_files, preparation, pinned)
    result['inputs'] = inputs
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trial', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--expected-inventory-sha256', required=True)
    parser.add_argument('--expected-files', type=int, default=95989)
    parser.add_argument('--preparation', type=Path)
    parser.add_argument('--pinned', type=Path)
    parser.add_argument('--max-proof-bytes', type=int, default=MAX_PROOF)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(1 <= args.expected_files <= MAX_FILES, 'expected-files outside budget')
    require(1 <= args.max_proof_bytes <= MAX_PROOF, 'decoded proof budget outside 1 GiB bound')
    try:
        result = verify_trial(args.trial, args.inventory, args.expected_inventory_sha256,
            args.expected_files, args.preparation, args.pinned, args.max_proof_bytes)
    except (OSError, ValueError, TypeError, KeyError, EOFError, gzip.BadGzipFile) as error:
        result = {'status': 'FAIL', 'cache_condition_replay': 'FAIL', 'error': str(error),
            'claim_scope': 'SAVED_CACHE_RECORD_REPLAY_ONLY_NOT_LIVE_CACHE_TRUTH', 'limitations': list(LIMITS)}
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'status': result['status'], 'output': str(args.output)}))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
