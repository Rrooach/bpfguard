#!/usr/bin/env python3
"""Seal all regular-file bytes in a dedicated final export, without signing it.

No implicit exclusions: remove unwanted large/raw assets from the export before
sealing. This is artifact integrity, not sensor truth, provenance or authenticity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat


VERSION = 1
SCOPE = 'ALL_REGULAR_FILE_RELATIVE_PATHS_AND_BYTES_ONLY_NOT_SENSOR_AUTHENTICITY_OR_SIGNATURE'
DEFAULT_MAX_FILES = 100000
HARD_MAX_FILES = 1000000
MAX_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 128
CHUNK = 1024 * 1024
STABLE_FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _signature(value):
    return tuple(getattr(value, name) for name in STABLE_FIELDS)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _limit(max_files):
    if type(max_files) is not int or not 1 <= max_files <= HARD_MAX_FILES:
        raise ValueError('max_files must be an integer between 1 and {}'.format(HARD_MAX_FILES))


def _no_symlink(path):
    path = Path(path).absolute()
    for component in reversed((path, *path.parents)):
        if component.is_symlink():
            raise ValueError('symlink path component is not allowed: ' + str(component))
    return path.resolve(strict=True)


def _root(path):
    root = _no_symlink(path)
    # Reject filesystem/home/source-workspace roots, not an arbitrary chosen
    # current directory (the caller may legitimately cd into the final export).
    broad = {Path('/'), Path.home().resolve(), Path('/tmp'), Path('/var/tmp')}
    broad.update(Path(__file__).resolve().parents)
    for parent in (Path.cwd(), *Path.cwd().parents):
        if (parent / '.git').exists():
            broad.add(parent.resolve())
    if root in broad or root == Path(__file__).resolve() or not root.is_dir():
        raise ValueError('root must be a dedicated export directory, not a broad or workspace root')
    if root == Path('/proc') or Path('/proc') in root.parents or root == Path('/sys') or Path('/sys') in root.parents:
        raise ValueError('virtual kernel filesystems are not dedicated artifact exports')
    return root


def _outside(root, path, fresh=False):
    path = Path(path).absolute()
    parent = _no_symlink(path.parent)
    target = parent / path.name
    if target == root or root in target.parents:
        raise ValueError('inventory must be outside the input export directory')
    if fresh and os.path.lexists(target):
        raise FileExistsError('inventory output already exists: ' + str(target))
    return target


def _relative(value):
    if not isinstance(value, str) or not value or '\\' in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError('unsafe artifact relative path')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or path.as_posix() != value or value == '.':
        raise ValueError('noncanonical artifact relative path: ' + repr(value))
    try:
        raw = value.encode('utf-8')
    except UnicodeEncodeError as error:
        raise ValueError('artifact path must be valid UTF-8') from error
    if len(raw) > 4096:
        raise ValueError('artifact relative path exceeds bound')
    return path


def _scan(root_fd, max_files):
    files, directories, visited = {}, {}, 0
    def walk(directory_fd, prefix='', depth=0):
        nonlocal visited
        if depth > MAX_DEPTH:
            raise ValueError('artifact directory depth exceeds bound')
        before = os.fstat(directory_fd)
        directories[prefix] = _signature(before)
        with os.scandir(directory_fd) as iterator:
            entries = []
            for entry in iterator:
                visited += 1
                if visited > max_files * 4 + 1024:
                    raise ValueError('artifact tree entry count exceeds bound')
                entries.append(entry)
        for entry in entries:
            relative = prefix + '/' + entry.name if prefix else entry.name
            _relative(relative)
            value = entry.stat(follow_symlinks=False)
            if stat.S_ISREG(value.st_mode):
                files[relative] = _signature(value)
                if len(files) > max_files:
                    raise ValueError('artifact file count exceeds bound')
            elif stat.S_ISDIR(value.st_mode):
                child = os.open(entry.name, DIR_FLAGS, dir_fd=directory_fd)
                try:
                    if _signature(os.fstat(child)) != _signature(value):
                        raise ValueError('artifact directory changed during enumeration')
                    walk(child, relative, depth + 1)
                finally:
                    os.close(child)
            else:
                raise ValueError('symlink or special artifact is not allowed: ' + relative)
        if _signature(os.fstat(directory_fd)) != _signature(before):
            raise ValueError('artifact directory changed during enumeration')
    walk(root_fd)
    return files, directories


def _stream_digest(fd):
    digest, count = hashlib.sha256(), 0
    for block in iter(lambda: os.read(fd, CHUNK), b''):
        digest.update(block)
        count += len(block)
    return digest.hexdigest(), count


def _hash_file(root_fd, relative, expected, directories):
    parts = _relative(relative).parts
    parent_fd = os.dup(root_fd)
    try:
        for index, component in enumerate(parts[:-1]):
            child = os.open(component, DIR_FLAGS, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child
            if _signature(os.fstat(parent_fd)) != directories['/'.join(parts[:index + 1])]:
                raise ValueError('artifact parent directory changed before hashing')
        fd = os.open(parts[-1], FILE_FLAGS, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or _signature(before) != expected:
                raise ValueError('artifact file changed before hashing: ' + relative)
            digest, count = _stream_digest(fd)
            after = os.fstat(fd)
            binding = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if (_signature(after) != _signature(before) or not stat.S_ISREG(binding.st_mode)
                    or _signature(binding) != _signature(after) or count != before.st_size):
                raise ValueError('artifact file changed while hashing: ' + relative)
            return {'path': relative, 'bytes': count, 'sha256': digest}
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _collect(root, max_files):
    _limit(max_files)
    root_fd = os.open(root, DIR_FLAGS)
    try:
        files, directories = _scan(root_fd, max_files)
        rows = [_hash_file(root_fd, name, files[name], directories) for name in sorted(files)]
        final_files, final_directories = _scan(root_fd, max_files)
        if final_files != files or final_directories != directories or _signature(root.lstat()) != directories['']:
            raise ValueError('artifact tree changed during sealing or verification')
        return rows
    finally:
        os.close(root_fd)


def _digest_manifest(manifest):
    return hashlib.sha256(_canonical({key: value for key, value in manifest.items() if key != 'inventory_sha256'})).hexdigest()


def seal_export(root, output, max_files=DEFAULT_MAX_FILES):
    root = _root(root)
    output = _outside(root, output, fresh=True)
    files = _collect(root, max_files)
    result = {'schema_version': VERSION, 'tool_version': VERSION, 'scope': SCOPE,
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'root': str(root), 'hash_algorithm': 'SHA256', 'file_count': len(files),
        'total_bytes': sum(row['bytes'] for row in files), 'files': files,
        'limits': {'max_files': max_files, 'max_depth': MAX_DEPTH},
        'stability_checked_fields': list(STABLE_FIELDS),
        'canonicalization': 'UTF8_JSON_SORT_KEYS_COMPACT_NO_ASCII_ESCAPING_V1',
        'digest_scope': 'ALL_MANIFEST_FIELDS_EXCEPT_INVENTORY_SHA256',
        'not_claimed': 'No signature, trusted sensor, original producer authenticity, atomic snapshot, file permissions or empty-directory preservation.'}
    result['inventory_sha256'] = _digest_manifest(result)
    content = _canonical(result) + b'\n'
    if len(content) > MAX_INVENTORY_BYTES:
        raise ValueError('inventory JSON exceeds bounded verification size')
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return result


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON object key in inventory')
        result[key] = value
    return result


def _read_inventory(path):
    path = _no_symlink(path)
    fd = os.open(path, FILE_FLAGS)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INVENTORY_BYTES:
            raise ValueError('bounded regular inventory JSON is required')
        chunks, size = [], 0
        for chunk in iter(lambda: os.read(fd, CHUNK), b''):
            size += len(chunk)
            if size > MAX_INVENTORY_BYTES:
                raise ValueError('inventory JSON exceeds size bound')
            chunks.append(chunk)
        if (_signature(os.fstat(fd)) != _signature(before) or _signature(path.lstat()) != _signature(before)
                or size != before.st_size):
            raise ValueError('inventory changed while reading')
        return json.loads(b''.join(chunks), object_pairs_hook=_unique_object)
    finally:
        os.close(fd)


def verify_export(root, inventory, max_files=DEFAULT_MAX_FILES):
    root = _root(root)
    inventory = _outside(root, inventory)
    _limit(max_files)
    original = _read_inventory(inventory)
    required = {'schema_version', 'tool_version', 'scope', 'source_sha256', 'root', 'hash_algorithm',
        'file_count', 'total_bytes', 'files', 'limits', 'stability_checked_fields', 'canonicalization',
        'digest_scope', 'not_claimed', 'inventory_sha256'}
    if (not isinstance(original, dict) or type(original.get('schema_version')) is not int
            or set(original) != required or original['schema_version'] != VERSION or original.get('scope') != SCOPE
            or type(original.get('tool_version')) is not int or original['tool_version'] != VERSION
            or original.get('hash_algorithm') != 'SHA256'
            or not isinstance(original.get('root'), str) or not Path(original['root']).is_absolute()
            or not isinstance(original.get('not_claimed'), str)
            or not isinstance(original.get('source_sha256'), str) or len(original['source_sha256']) != 64
            or any(char not in '0123456789abcdef' for char in original['source_sha256'])
            or original.get('stability_checked_fields') != list(STABLE_FIELDS)
            or original.get('canonicalization') != 'UTF8_JSON_SORT_KEYS_COMPACT_NO_ASCII_ESCAPING_V1'
            or original.get('digest_scope') != 'ALL_MANIFEST_FIELDS_EXCEPT_INVENTORY_SHA256'
            or original.get('inventory_sha256') != _digest_manifest(original)):
        raise ValueError('inventory schema, scope or canonical digest is invalid')
    limits = original.get('limits')
    if not isinstance(limits, dict) or set(limits) != {'max_files', 'max_depth'} or limits.get('max_depth') != MAX_DEPTH:
        raise ValueError('invalid inventory capture limits')
    _limit(limits.get('max_files'))
    expected = original.get('files')
    if not isinstance(expected, list) or len(expected) > min(max_files, limits['max_files']):
        raise ValueError('inventory file count exceeds verifier bound or is invalid')
    paths = []
    for row in expected:
        if (not isinstance(row, dict) or set(row) != {'path', 'bytes', 'sha256'}
                or type(row.get('bytes')) is not int or row['bytes'] < 0
                or not isinstance(row.get('sha256'), str) or len(row['sha256']) != 64
                or any(char not in '0123456789abcdef' for char in row['sha256'])):
            raise ValueError('invalid inventory file declaration')
        _relative(row.get('path'))
        paths.append(row['path'])
    if paths != sorted(set(paths)):
        raise ValueError('inventory file paths must be sorted and unique')
    if (type(original.get('file_count')) is not int or original['file_count'] != len(expected)
            or type(original.get('total_bytes')) is not int or original['total_bytes'] != sum(row['bytes'] for row in expected)):
        raise ValueError('inventory file count or byte total is inconsistent')
    actual = _collect(root, max_files)
    actual_paths = {row['path'] for row in actual}
    if actual_paths != set(paths):
        raise ValueError('artifact files added or missing: added={} missing={}'.format(
            sorted(actual_paths - set(paths))[:10], sorted(set(paths) - actual_paths)[:10]))
    if actual != expected:
        raise ValueError('artifact file bytes or SHA256 differ from inventory')
    return {'status': 'VERIFIED_ARTIFACT_BYTES', 'scope': SCOPE, 'root': str(root),
        'recorded_root': original.get('root'), 'file_count': len(actual), 'total_bytes': original['total_bytes'],
        'inventory_sha256': original['inventory_sha256'],
        'verifier_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'not_claimed': original['not_claimed']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True, help='dedicated final export directory; no files are excluded')
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--output', type=Path, help='fresh inventory JSON outside root')
    action.add_argument('--verify', type=Path, help='saved inventory outside root; all current files are rehashed')
    parser.add_argument('--max-files', type=int, default=DEFAULT_MAX_FILES)
    args = parser.parse_args()
    try:
        if args.verify:
            result = verify_export(args.root, args.verify, args.max_files)
        else:
            result = seal_export(args.root, args.output, args.max_files)
            result = {'status': 'SEALED_ARTIFACT_BYTES', 'file_count': result['file_count'],
                'total_bytes': result['total_bytes'], 'inventory_sha256': result['inventory_sha256'], 'output': str(args.output)}
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, 'error: ' + str(error) + '\n')
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()
