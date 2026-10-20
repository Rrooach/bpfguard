#!/usr/bin/env python3
"""Lossless bounded storage for optional offline file-access artifacts.

An archived artifact binds logical bytes/SHA separately from its actual gzip
storage bytes/SHA. Logical paths are never claimed to be existing plain files.
Verification independently streams one gzip member with a bounded decoder;
restore writes only a fresh file. This module never deletes an input artifact.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import zlib


ARTIFACT_NAMES = frozenset(('summary.json', 'events.sqlite', 'per-file.csv',
    'read-samples.csv', 'source-read-samples.csv'))
ARCHIVED_NAMES = frozenset(('events.sqlite', 'per-file.csv'))
MAX_BYTES = 64 * 1024 ** 3
CHUNK = 64 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value, maximum=MAX_BYTES):
    return type(value) is int and 0 <= value <= maximum


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def stable(before, after):
    return all(getattr(before, field) == getattr(after, field) for field in
        ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def regular(path, maximum):
    path = Path(path).absolute()
    require(number(maximum) and path.resolve(strict=True) == path and not path.is_symlink() and stat.S_ISREG(path.stat().st_mode)
        and path.stat().st_size <= maximum, 'bounded regular non-symlink artifact required: ' + str(path))
    return path


def digest_file(path, max_bytes=MAX_BYTES):
    path, digest = regular(path, max_bytes), hashlib.sha256()
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        for block in iter(lambda: stream.read(CHUNK), b''):
            digest.update(block)
        after = os.fstat(stream.fileno())
    require(stable(before, after), 'artifact changed while hashing')
    return {'path': str(path), 'bytes': after.st_size, 'sha256': digest.hexdigest()}


def artifact_path(record, root, logical_name, max_logical_bytes=MAX_BYTES, max_storage_bytes=MAX_BYTES):
    """Validate the storage declaration without reading large artifact bytes."""
    root = Path(root).absolute()
    require(root.resolve(strict=True) == root and root.is_dir(), 'real non-symlink artifact root required')
    require(logical_name in ARTIFACT_NAMES and isinstance(record, dict), 'supported logical artifact required')
    require(number(max_logical_bytes) and number(max_storage_bytes), 'bounded artifact limits required')
    require(number(record.get('bytes'), max_logical_bytes) and sha(record.get('sha256')),
            'bounded logical bytes and SHA256 required')
    storage = record.get('storage')
    if storage is None:
        require(record.get('logical_name', logical_name) == logical_name, 'logical artifact name differs')
        value, name, maximum = record, logical_name, max_logical_bytes
    else:
        require('path' not in record and record.get('logical_name') == logical_name,
                'archive must declare its logical name without a fictitious plain path')
        require(isinstance(storage, dict) and type(storage.get('schema_version')) is int and storage.get('schema_version') == 1
            and storage.get('codec') == 'gzip' and logical_name in ARCHIVED_NAMES,
            'supported gzip storage codec/schema/artifact required')
        require(number(storage.get('bytes'), max_storage_bytes) and sha(storage.get('sha256')),
                'bounded compressed bytes and SHA256 required')
        value, name, maximum = storage, logical_name + '.gz', max_storage_bytes
    require(isinstance(value.get('path'), str) and Path(value['path']).is_absolute()
        and Path(value['path']) == root / name, 'exact root-contained artifact storage path required')
    path = regular(value['path'], maximum)
    require(path.resolve(strict=True) == path and path.stat().st_size == value['bytes'],
            'artifact storage path/length differs')
    return path


def _verify(record, root, logical_name, max_logical_bytes, max_storage_bytes, sink=None):
    path = artifact_path(record, root, logical_name, max_logical_bytes, max_storage_bytes)
    compressed = record.get('storage') is not None
    logical_digest, storage_digest, logical_count, storage_count = hashlib.sha256(), hashlib.sha256(), 0, 0
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if compressed else None

    def consume(block):
        nonlocal logical_count
        require(logical_count + len(block) <= record['bytes'] and
            logical_count + len(block) <= max_logical_bytes, 'decompressed logical size limit exceeded')
        logical_digest.update(block)
        logical_count += len(block)
        if sink is not None:
            sink.write(block)

    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            storage_digest.update(block)
            storage_count += len(block)
            if not compressed:
                consume(block)
                continue
            require(not decoder.eof, 'trailing or concatenated gzip member rejected')
            pending = block
            while pending:
                # Never allow a single highly-compressed chunk to allocate an
                # unbounded expanded buffer, even for a forged receipt.
                try:
                    expanded = decoder.decompress(pending, min(CHUNK, record['bytes'] - logical_count + 1))
                except zlib.error as error:
                    raise ValueError('invalid gzip data or checksum: ' + str(error)) from error
                consume(expanded)
                pending = decoder.unconsumed_tail
                require(not decoder.unused_data, 'trailing or concatenated gzip member rejected')
                if decoder.eof:
                    require(not pending, 'gzip decoder retained trailing input')
                    break
        after = os.fstat(stream.fileno())
    require(stable(before, after), 'artifact changed during independent verification')
    if compressed:
        require(decoder.eof, 'truncated gzip stream rejected')
    require(logical_count == record['bytes'] and logical_digest.hexdigest() == record['sha256'],
            'logical artifact bytes/SHA256 differ')
    stored = record['storage'] if compressed else record
    require(storage_count == stored['bytes'] and storage_digest.hexdigest() == stored['sha256'],
            'stored artifact bytes/SHA256 differ')
    proof = {'status': 'VERIFIED_DECOMPRESSED_BYTES' if compressed else 'VERIFIED_PLAIN_BYTES',
        'bytes': logical_count, 'sha256': logical_digest.hexdigest(),
        'artifact_module_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    if compressed:
        proof['storage'] = {'path': str(path), 'bytes': storage_count, 'sha256': storage_digest.hexdigest()}
    return proof


def verify_artifact(record, root, logical_name, max_logical_bytes=MAX_BYTES, max_storage_bytes=MAX_BYTES):
    return _verify(record, root, logical_name, max_logical_bytes, max_storage_bytes)


class _BoundedWriter:
    def __init__(self, stream, directory, maximum, min_free):
        self.stream, self.directory, self.maximum, self.min_free = stream, directory, maximum, min_free
        self.count, self.digest = 0, hashlib.sha256()

    def write(self, block):
        require(self.count + len(block) <= self.maximum, 'compressed storage size limit exceeded')
        require(shutil.disk_usage(str(self.directory)).free >= self.min_free + len(block),
                'persistent output free-space reserve exhausted')
        written = self.stream.write(block)
        require(written == len(block), 'short compressed artifact write')
        self.count += written
        self.digest.update(block)
        return written

    def flush(self):
        self.stream.flush()


def store_gzip(source, output_dir, logical_name, max_logical_bytes=MAX_BYTES,
               max_storage_bytes=MAX_BYTES, min_free_bytes=0):
    require(logical_name in ARCHIVED_NAMES and number(min_free_bytes), 'supported archived artifact/reserve required')
    source = regular(source, max_logical_bytes)
    root = Path(output_dir).absolute()
    require(root.resolve(strict=True) == root and root.is_dir(), 'real final artifact directory required')
    path = root / (logical_name + '.gz')
    digest, logical_count = hashlib.sha256(), 0
    with source.open('rb') as original, path.open('xb') as stored:
        before = os.fstat(original.fileno())
        writer = _BoundedWriter(stored, root, max_storage_bytes, min_free_bytes)
        with gzip.GzipFile(filename='', fileobj=writer, mode='wb', compresslevel=1, mtime=0) as compressor:
            for block in iter(lambda: original.read(CHUNK), b''):
                logical_count += len(block)
                require(logical_count <= max_logical_bytes, 'logical artifact grew past size bound')
                digest.update(block)
                compressor.write(block)
        stored.flush()
        os.fsync(stored.fileno())
        after = os.fstat(original.fileno())
    require(stable(before, after) and logical_count == before.st_size, 'source artifact changed during compression')
    record = {'logical_name': logical_name, 'bytes': logical_count, 'sha256': digest.hexdigest(),
        'storage': {'schema_version': 1, 'codec': 'gzip', 'path': str(path),
                    'bytes': writer.count, 'sha256': writer.digest.hexdigest()}}
    record['verification'] = verify_artifact(record, root, logical_name, max_logical_bytes, max_storage_bytes)
    return record


def restore_artifact(record, root, logical_name, output, max_logical_bytes=MAX_BYTES, max_storage_bytes=MAX_BYTES):
    # Validate both declaration and source path before creating an output.
    artifact_path(record, root, logical_name, max_logical_bytes, max_storage_bytes)
    output = Path(output).absolute()
    require(output.parent.resolve(strict=True) == output.parent and output.parent.is_dir(),
            'real existing restore directory required')
    require(not output.exists() and not output.is_symlink(), 'fresh restore destination required')
    require(shutil.disk_usage(str(output.parent)).free >= record['bytes'], 'insufficient bounded restore space')
    with output.open('xb') as stream:
        proof = _verify(record, root, logical_name, max_logical_bytes, max_storage_bytes, stream)
        stream.flush()
        os.fsync(stream.fileno())
    return dict(proof, path=str(output))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('verify', 'restore'):
        child = sub.add_parser(command)
        child.add_argument('--receipt', type=Path, required=True, help='Explicit access_batch attempt receipt')
        child.add_argument('--case', required=True)
        child.add_argument('--artifact', choices=sorted(ARTIFACT_NAMES), required=True)
        child.add_argument('--max-logical-bytes', type=int, default=MAX_BYTES)
        child.add_argument('--max-storage-bytes', type=int, default=MAX_BYTES)
        if command == 'restore':
            child.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = regular(args.receipt, 32 * 1024 ** 2)
    row = json.loads(receipt.read_bytes())['results'][args.case]
    record, root = row['artifacts'][args.artifact], row['output']
    if args.command == 'restore':
        proof = restore_artifact(record, root, args.artifact, args.output,
                                 args.max_logical_bytes, args.max_storage_bytes)
    else:
        proof = verify_artifact(record, root, args.artifact, args.max_logical_bytes, args.max_storage_bytes)
    print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
