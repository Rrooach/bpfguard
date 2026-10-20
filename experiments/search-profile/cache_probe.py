#!/usr/bin/env python3
"""Guest-only, non-faulting file-data page-cache observations using mincore.

Correct order: hash corpus with the existing inventory builder; pin_inventory
BEFORE cache preparation; caller drops/warms the Guest cache; probe_inventory.
This module never hashes/reads corpus data, warms it, or writes drop_caches.
Metadata walking itself warms dentry/inode caches: only DATA-page residency is
observed. Per-file snapshots are non-atomic and may change before task release.

Single root: pin_inventory(root, inventory['files']) -> probe_inventory(root,pin).
Multiple roots: pin_roots(roots, files, independent=True) -> probe_roots(pins).
CLI: `pin --root ROOT [--root ROOT2] --inventory FILE --output NEW.json`, then
`probe --pinned NEW.json --output NEW-RESIDENCY.json` after cache preparation.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time


MAX_FILES = 200000
MAX_BYTES = 64 * 1024 ** 3
MAX_ROOTS = 16
MAX_ROOT_FILE_PAIRS = 1000000
MAX_ALL_BYTES = 256 * 1024 ** 3
MAX_PATH_BYTES = 4096
MAX_TOTAL_PATH_BYTES = 64 * 1024 ** 2
CHUNK_PAGES = 16384
LIMITATIONS = [
    'Metadata open/stat traversal can warm dentry/inode caches; no claim of fully cold metadata.',
    'PROT_NONE mmap plus mincore does not read/fault the declared file data; no cache drop or warm-up is performed here.',
    'Per-file observations are sequential and non-atomic; background I/O/reclaim can change residency before task release.',
    'resident_bytes counts logical file bytes on resident pages, including only valid bytes in the last partial page; not RSS/physical storage bytes.',
    'Provided content hashes are bound, not recomputed after cache preparation; immutable cooperative files and before/after metadata checks are required.',
    'Scope is declared inventory files only, not newly created/unlisted files, metadata caches, host caches, disk-controller caches or mmap access bytes.',
    'Independent roots means distinct declared dev/inode identities; CoW/block backing and host/storage cache independence are not established.',
]


def _ensure_guest():
    if sys.platform != 'linux' or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError('cache probe requires 64-bit Linux')
    vendor = ' '.join(path.read_text(errors='replace') for path in
        (Path('/sys/class/dmi/id/product_name'), Path('/sys/class/dmi/id/sys_vendor')) if path.exists()).lower()
    if not any(value in vendor for value in ('qemu', 'kvm')):
        raise RuntimeError('cache experiment probe is restricted to the cooperative QEMU/KVM Guest')


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _files(files):
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError('inventory.files must contain 1..200000 entries')
    result, seen, total, total_path_bytes = [], set(), 0, 0
    for row in files:
        if not isinstance(row, dict):
            raise ValueError('inventory row must be an object')
        relative, size, digest = row.get('path'), row.get('size'), row.get('sha256')
        if (not isinstance(relative, str) or not relative or '\0' in relative or
                len(os.fsencode(relative)) > MAX_PATH_BYTES or PurePosixPath(relative).is_absolute() or
                '..' in PurePosixPath(relative).parts or relative in ('.', '..') or
                PurePosixPath(relative).as_posix() != relative):
            raise ValueError('inventory path must be bounded canonical relative components')
        if relative in seen or type(size) is not int or size < 0 or not isinstance(digest, str) or re.fullmatch('[0-9a-fA-F]{64}', digest) is None:
            raise ValueError('duplicate path, invalid size, or missing fixed content SHA256')
        seen.add(relative)
        total += size
        total_path_bytes += len(os.fsencode(relative))
        if total > MAX_BYTES or total_path_bytes > MAX_TOTAL_PATH_BYTES:
            raise ValueError('inventory exceeds logical-file-byte or total-path budget')
        result.append({'path': relative, 'size': size, 'sha256': digest.lower()})
    return result


def _identity(metadata):
    return {'device': metadata.st_dev, 'inode': metadata.st_ino, 'size': metadata.st_size,
            'mtime_ns': metadata.st_mtime_ns, 'ctime_ns': metadata.st_ctime_ns, 'mode': metadata.st_mode,
            'uid': metadata.st_uid, 'gid': metadata.st_gid, 'nlink': metadata.st_nlink}


def _root_identity(metadata):
    return {key: value for key, value in _identity(metadata).items() if key in ('device', 'inode', 'mode', 'uid', 'gid')}


DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _root_fd(root):
    path = Path(root)
    if not path.is_absolute() or '..' in path.parts or len(os.fsencode(path)) > MAX_PATH_BYTES:
        raise ValueError('cache root must be an absolute path without parent traversal')
    descriptor = os.open('/', DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _file_fd(root_fd, relative):
    components = PurePosixPath(relative).parts
    descriptor = os.dup(root_fd)
    try:
        for part in components[:-1]:
            next_fd = os.open(part, DIR_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        if not stat.S_ISREG(os.stat(components[-1], dir_fd=descriptor, follow_symlinks=False).st_mode):
            raise ValueError('inventory entry is a symlink or non-regular file')
        return os.open(components[-1], FILE_FLAGS, dir_fd=descriptor)
    finally:
        os.close(descriptor)


def _error(error):
    return {'type': type(error).__name__, 'errno': getattr(error, 'errno', None), 'detail': str(error)}


def pin_inventory(root, files):
    """Bind provided hashes and file identities BEFORE dropping/reading cache."""
    _ensure_guest()
    files = _files(files)
    started = time.monotonic_ns()
    result = {'schema_version': 1, 'kind': 'MINCORE_PRE_CACHE_PREPARATION_PIN', 'root': str(Path(root)),
        'inventory_sha256': _digest(files), 'status': 'PINNED',
        'files': [{**row, 'pin_status': 'FAILED', 'error': {'type': 'ROOT_NOT_OPENED'}} for row in files], 'errors': [],
        'pin_started_ns': started, 'content_hash_authority': 'PROVIDED_PRE_PREPARATION_INVENTORY_NOT_REHASHED',
        'limitations': list(LIMITATIONS)}
    root_fd = None
    try:
        root_fd = _root_fd(root)
        result['root_identity'] = _root_identity(os.fstat(root_fd))
        for index, row in enumerate(files):
            descriptor = None
            pinned = {**row, 'pin_status': 'FAILED'}
            try:
                descriptor = _file_fd(root_fd, row['path'])
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != row['size']:
                    raise ValueError('file type/size differs from fixed inventory')
                pinned.update(pin_status='PINNED', identity=_identity(metadata))
            except (OSError, ValueError) as error:
                pinned['error'] = _error(error)
                result['status'] = 'INCOMPLETE'
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            result['files'][index] = pinned
        check_fd = _root_fd(root)
        try:
            if _root_identity(os.fstat(check_fd)) != result['root_identity']:
                raise ValueError('cache root identity changed while pinning')
        finally:
            os.close(check_fd)
    except (OSError, ValueError) as error:
        result.update(status='INCOMPLETE')
        result['errors'].append(_error(error))
    finally:
        if root_fd is not None:
            os.close(root_fd)
    result['pin_completed_ns'] = time.monotonic_ns()
    return result


def _fsuid():
    for line in Path('/proc/self/status').read_text().splitlines():
        if line.startswith('Uid:'):
            return int(line.split()[4])
    raise ValueError('filesystem UID unavailable; mincore permission filtering cannot be excluded')


class _Mincore:
    def __init__(self):
        self.page_size = os.sysconf('SC_PAGE_SIZE')
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
        self.libc.mmap.restype = ctypes.c_void_p
        self.libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte)]
        self.libc.mincore.restype = ctypes.c_int
        self.libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.libc.munmap.restype = ctypes.c_int

    def counts(self, descriptor, size):
        total_pages = (size + self.page_size - 1) // self.page_size
        resident_pages = resident_bytes = 0
        for offset in range(0, size, self.page_size * CHUNK_PAGES):
            length = min(size - offset, self.page_size * CHUNK_PAGES)
            pages = (length + self.page_size - 1) // self.page_size
            # PROT_NONE=0, MAP_SHARED=1: never dereference the mapped address.
            address = self.libc.mmap(None, length, 0, 1, descriptor, offset)
            if address == ctypes.c_void_p(-1).value:
                code = ctypes.get_errno()
                raise OSError(code, 'PROT_NONE mmap failed: ' + os.strerror(code))
            error = None
            try:
                vector = (ctypes.c_ubyte * pages)()
                if self.libc.mincore(address, length, vector):
                    code = ctypes.get_errno()
                    raise OSError(code, 'mincore failed: ' + os.strerror(code))
                for index, value in enumerate(vector):
                    if value & 1:
                        resident_pages += 1
                        resident_bytes += min(self.page_size, size - offset - index * self.page_size)
            except BaseException as caught:
                error = caught
            finally:
                if self.libc.munmap(address, length):
                    code = ctypes.get_errno()
                    raise OSError(code, 'munmap failed after {}: {}'.format(error, os.strerror(code)))
            if error is not None:
                raise error
        return {'total_pages': total_pages, 'resident_pages': resident_pages,
                'total_bytes': size, 'resident_bytes': resident_bytes}


def _check_pin(pinned):
    if not isinstance(pinned, dict) or pinned.get('schema_version') != 1 or pinned.get('kind') != 'MINCORE_PRE_CACHE_PREPARATION_PIN':
        raise ValueError('probe requires a pre-cache-preparation identity pin, not a legacy hash-only inventory')
    files = _files(pinned.get('files'))
    if _digest(files) != pinned.get('inventory_sha256'):
        raise ValueError('pinned inventory digest does not match its file declarations')
    return files


def probe_inventory(root, pinned):
    """Observe cache bits without reading file data; all failures stay unknown."""
    _ensure_guest()
    files = _check_pin(pinned)
    if str(Path(root)) != pinned.get('root'):
        raise ValueError('probe root differs from pre-cache-preparation pin')
    backend = _Mincore()
    result = {'schema_version': 1, 'kind': 'MINCORE_FILE_DATA_RESIDENCY', 'root': str(Path(root)),
        'inventory_sha256': pinned['inventory_sha256'], 'pin_sha256': _digest(pinned),
        'page_size': backend.page_size, 'start_monotonic_ns': time.monotonic_ns(),
        'status': 'OBSERVED_NON_ATOMIC', 'files': [], 'errors': [], 'limitations': list(LIMITATIONS),
        'mincore_authority': 'FILE_OWNER_FSUID_MATCH_REQUIRED_TO_EXCLUDE_LINUX_ALL_ONES_PERMISSION_MASKING'}
    root_fd = None
    try:
        root_fd = _root_fd(root)
        if _root_identity(os.fstat(root_fd)) != pinned.get('root_identity'):
            raise ValueError('root identity changed since pre-preparation pin')
        filesystem_uid = _fsuid()
        result['filesystem_uid'] = filesystem_uid
        for row, original in zip(files, pinned['files']):
            entry = {**row, 'start_monotonic_ns': time.monotonic_ns(), 'status': 'UNKNOWN',
                'total_pages': (row['size'] + backend.page_size - 1) // backend.page_size,
                'total_bytes': row['size'], 'resident_pages': None, 'resident_bytes': None}
            descriptor = None
            try:
                if original.get('pin_status') != 'PINNED' or not isinstance(original.get('identity'), dict):
                    raise ValueError('file was not successfully pinned before cache preparation')
                descriptor = _file_fd(root_fd, row['path'])
                before = _identity(os.fstat(descriptor))
                if before != original['identity'] or not stat.S_ISREG(before['mode']):
                    raise ValueError('file identity/type/size/version metadata changed since preparation pin')
                if before['uid'] != filesystem_uid:
                    raise PermissionError(errno.EACCES, 'mincore may mask non-owned unreadable-for-write file residency as all ones; probe refuses unproven authority')
                observed = backend.counts(descriptor, before['size'])
                after = _identity(os.fstat(descriptor))
                path_fd = _file_fd(root_fd, row['path'])
                try:
                    path_after = _identity(os.fstat(path_fd))
                finally:
                    os.close(path_fd)
                if before != after or before != path_after:
                    entry['raw_observation_invalidated_by_identity_change'] = observed
                    raise ValueError('file changed or path replaced during mincore observation')
                entry.update(observed, status='OBSERVED_NON_ATOMIC', identity=before)
            except (OSError, ValueError) as error:
                entry['error'] = _error(error)
                result['status'] = 'INCOMPLETE'
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            entry['end_monotonic_ns'] = time.monotonic_ns()
            result['files'].append(entry)
        check_fd = _root_fd(root)
        try:
            if _root_identity(os.fstat(check_fd)) != pinned.get('root_identity'):
                raise ValueError('root identity changed during cache probe')
        finally:
            os.close(check_fd)
        if pinned.get('status') != 'PINNED' or pinned.get('errors'):
            result['status'] = 'INCOMPLETE'
            result['errors'].append({'type': 'INCOMPLETE_PIN', 'detail': pinned.get('errors', [])})
    except (OSError, ValueError) as error:
        result['status'] = 'INCOMPLETE'
        result['errors'].append(_error(error))
    finally:
        if root_fd is not None:
            os.close(root_fd)
    valid = [row for row in result['files'] if row['status'] == 'OBSERVED_NON_ATOMIC']
    result.update(declared_file_count=len(files), observed_file_count=len(valid), unknown_file_count=len(files) - len(valid),
        total_pages=sum((row['size'] + backend.page_size - 1) // backend.page_size for row in files),
        total_bytes=sum(row['size'] for row in files), observed_total_pages=sum(row['total_pages'] for row in valid),
        observed_total_bytes=sum(row['total_bytes'] for row in valid),
        observed_resident_pages=sum(row['resident_pages'] for row in valid), observed_resident_bytes=sum(row['resident_bytes'] for row in valid))
    complete = result['status'] == 'OBSERVED_NON_ATOMIC' and len(valid) == len(files)
    result['resident_pages'] = result['observed_resident_pages'] if complete else None
    result['resident_bytes'] = result['observed_resident_bytes'] if complete else None
    result['resident_fraction'] = result['resident_pages'] / result['total_pages'] if complete and result['total_pages'] else None
    result['data_page_state'] = ('UNKNOWN' if not complete else 'EMPTY_DATA_SCOPE' if not result['total_pages'] else
        'ALL_NONRESIDENT_AT_EACH_FILE_PROBE' if result['resident_pages'] == 0 else
        'ALL_RESIDENT_AT_EACH_FILE_PROBE' if result['resident_pages'] == result['total_pages'] else 'MIXED_RESIDENCY')
    result['end_monotonic_ns'] = time.monotonic_ns()
    result['duration_ns'] = result['end_monotonic_ns'] - result['start_monotonic_ns']
    return result


def pin_roots(roots, files, independent=False):
    roots, normalized = list(roots), _files(files)
    if (type(independent) is not bool or not 1 <= len(roots) <= MAX_ROOTS or len({str(Path(root)) for root in roots}) != len(roots) or
            len(normalized) * len(roots) > MAX_ROOT_FILE_PAIRS or sum(row['size'] for row in normalized) * len(roots) > MAX_ALL_BYTES):
        raise ValueError('multiple roots exceed bounded unique-root/file/byte contract')
    pins = [pin_inventory(root, normalized) for root in roots]
    identities = {}
    for root_index, pin in enumerate(pins):
        for row in pin['files']:
            if row.get('pin_status') == 'PINNED':
                key = row['identity']['device'], row['identity']['inode']
                identities.setdefault(key, []).append({'root_index': root_index, 'path': row['path']})
    shared = [{'device': key[0], 'inode': key[1], 'references': references} for key, references in identities.items()
              if len({reference['root_index'] for reference in references}) > 1]
    return {'schema_version': 1, 'kind': 'MINCORE_MULTIPLE_ROOT_PINS', 'independent_roots_required': independent,
        'status': 'INCOMPLETE' if any(pin['status'] != 'PINNED' for pin in pins) or independent and shared else 'PINNED',
        'shared_dev_inode_identities': shared, 'roots': pins, 'limitations': list(LIMITATIONS)}


def probe_roots(pinned):
    if (not isinstance(pinned, dict) or pinned.get('kind') != 'MINCORE_MULTIPLE_ROOT_PINS' or
            not isinstance(pinned.get('roots'), list) or not 1 <= len(pinned['roots']) <= MAX_ROOTS):
        raise ValueError('multiple-root probe requires bounded root pins')
    all_files = [_check_pin(pin) for pin in pinned['roots']]
    if (len({pin['root'] for pin in pinned['roots']}) != len(pinned['roots']) or
            sum(len(files) for files in all_files) > MAX_ROOT_FILE_PAIRS or
            sum(row['size'] for files in all_files for row in files) > MAX_ALL_BYTES):
        raise ValueError('multiple-root pin repeats roots or exceeds global file/byte limits')
    reports = [probe_inventory(pin['root'], pin) for pin in pinned['roots']]
    return {'schema_version': 1, 'kind': 'MINCORE_MULTIPLE_ROOT_RESIDENCY',
        'status': 'OBSERVED_NON_ATOMIC' if pinned.get('status') == 'PINNED' and all(row['status'] == 'OBSERVED_NON_ATOMIC' for row in reports) else 'INCOMPLETE',
        'roots': reports, 'independent_roots_required': pinned.get('independent_roots_required'),
        'shared_dev_inode_identities': pinned.get('shared_dev_inode_identities'),
        'aggregation': 'ROOTS_REPORTED_SEPARATELY_NO_PHYSICAL_CACHE_BYTES_SUMMED', 'limitations': list(LIMITATIONS)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('pin', 'probe'))
    parser.add_argument('--root', type=Path, action='append')
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--independent', action='store_true')
    parser.add_argument('--pinned', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.inventory if args.action == 'pin' else args.pinned
    if source is None or source.stat().st_size > 256 * 1024 * 1024:
        parser.error('bounded inventory/pinned JSON is required')
    data = json.loads(source.read_bytes())
    if args.action == 'pin':
        if not args.root:
            parser.error('pin requires --root')
        result = pin_roots(args.root, data['files'] if isinstance(data, dict) else data, args.independent)
    else:
        result = probe_roots(data)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'status': result['status'], 'output': str(args.output)}))
    raise SystemExit(0 if result['status'] in ('PINNED', 'OBSERVED_NON_ATOMIC') else 1)


if __name__ == '__main__':
    main()
