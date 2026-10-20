#!/usr/bin/env python3
"""Revalidate retained immutable inputs in a NEW owned Guest before timing.

This does not rewrite the previous campaign, its boot binding, or disk image.
Per-file inode/path observations are metadata-only and precede cache preparation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time

import cache_probe
import large_search
import run as runner


def object_row(path, root, scope):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode):
        return None
    return {'path': str(path), 'relative_path': str(path.relative_to(root)),
        'source_root': str(root), 'scope_kind': scope,
        'kernel_device': os.major(value.st_dev) << 20 | os.minor(value.st_dev),
        'inode': value.st_ino, 'size': value.st_size,
        'mtime_sec': value.st_mtime_ns // 1000000000,
        'mtime_nsec': value.st_mtime_ns % 1000000000,
        'ctime_sec': value.st_ctime_ns // 1000000000,
        'ctime_nsec': value.st_ctime_ns % 1000000000,
        'mode': value.st_mode, 'uid': value.st_uid, 'gid': value.st_gid}


def inventory_rows(root, scope, expected_files=None):
    if expected_files is not None:
        for entry in expected_files:
            row = object_row(root / entry['path'], root, scope)
            if row is None or row['size'] != entry['size']:
                raise ValueError('Source metadata differs: ' + entry['path'])
            yield row
    else:
        count = 0
        for directory, dirs, files in os.walk(str(root), followlinks=False):
            dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
            for name in sorted(files):
                path = Path(directory) / name
                if path.is_symlink():
                    continue
                row = object_row(path, root, scope)
                if row is not None:
                    count += 1
                    if count > 200000:
                        raise ValueError('System inventory exceeds bound')
                    yield row


def write_inventory(path, root, scope, boot, expected_files=None):
    # JSON array is streamed so nine roots do not coexist in Python memory.
    header = {'schema_version': 1, 'boot_id': boot, 'read_only': True,
        'pre_post_identical': False, 'scope_kind': 'REGULAR_FILES_ONLY',
        'source_root': str(root), 'object_scope_kind': scope,
        'mapping_quality': 'USERSPACE_READONLY_METADATA_MAPPING_NOT_KERNEL_PATH',
        'observation_phase': 'PRE_CAMPAIGN_BEFORE_CACHE_PREPARATION',
        'post_verification': 'PENDING; final post inventory must be compared before claiming identical'}
    count = 0
    with path.open('x') as stream:
        prefix = json.dumps(header, sort_keys=True)
        stream.write(prefix[:-1] + ',"objects":[')
        for row in inventory_rows(root, scope, expected_files):
            if count:
                stream.write(',')
            json.dump(row, stream, sort_keys=True, separators=(',', ':'))
            count += 1
        stream.write(']}\n')
    return {'path': str(path), 'sha256': runner.sha_file(path), 'objects': count,
            'source_root': str(root), 'scope_kind': scope}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old-prepared', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    cache_probe._ensure_guest()
    if os.geteuid() != 0:
        parser.error('owned root Guest required')
    args.output.mkdir(mode=0o700)
    previous = json.loads((args.old_prepared / 'preparation.json').read_bytes())
    old_inventory = args.old_prepared / 'corpus-inventory.json'
    if runner.sha_file(old_inventory) != previous['inventory_sha256']:
        raise ValueError('Original inventory binding differs')
    inventory = json.loads(old_inventory.read_bytes())
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    roots = [Path(previous['corpus'])] + list(map(Path, previous['independent_roots']))
    if len(roots) != 9:
        raise ValueError('Fixed nine source roots required')
    receipts = []
    for index, root in enumerate(roots):
        print(json.dumps({'checking_root': str(root), 'index': index}), flush=True)
        actual = runner.corpus_inventory(root)
        if large_search.fingerprint(actual) != large_search.fingerprint(inventory):
            raise ValueError('Retained content or permissions differ: ' + str(root))
        subprocess.run(['mount', '--bind', str(root), str(root)], check=True)
        subprocess.run(['mount', '-o', 'remount,bind,ro', str(root)], check=True)
        if not os.statvfs(root).f_flag & os.ST_RDONLY:
            raise ValueError('Source root is not read-only')
        receipts.append(write_inventory(args.output / ('source-objects-%02d.json' % index),
            root, 'SOURCE_CORPUS', boot, inventory['files']))
    # Runtime library mapping is optional quality enhancement, never a claim
    # to observe every filesystem pathname. Make the actual static tree read-only.
    system_root = Path('/usr')
    subprocess.run(['mount', '--bind', str(system_root), str(system_root)], check=True)
    subprocess.run(['mount', '-o', 'remount,bind,ro', str(system_root)], check=True)
    receipts.append(write_inventory(args.output / 'runtime-objects.json', system_root,
        'SYSTEM_RUNTIME', boot))
    shutil.copyfile(old_inventory, args.output / 'corpus-inventory.json')
    prepared = {**previous, 'boot_id': boot, 'completed_monotonic_ns': time.monotonic_ns(),
        'previous_boot_id': previous['boot_id'], 'read_only_bind_mounts': True,
        'revalidation': 'ALL_NINE_ROOT_CONTENT_AND_PERMISSIONS_REHASHED_IN_NEW_BOOT',
        'object_inventory_receipts': receipts}
    runner.dump(args.output / 'preparation.json', prepared)
    runner.dump(args.output / 'object-inventory-manifest.json', {
        'schema_version': 1, 'boot_id': boot, 'inventories': receipts,
        'preparation_sha256': runner.sha_file(args.output / 'preparation.json'),
        'limits': ['Metadata mappings are not runtime-resolved kernel paths.',
                   'Post-campaign identity comparison remains pending.']})
    print(json.dumps({'status': 'PREPARED', 'boot_id': boot,
                      'inventoried_objects': sum(r['objects'] for r in receipts)}), flush=True)


if __name__ == '__main__':
    main()
