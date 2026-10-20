#!/usr/bin/env python3
"""Post-campaign readonly metadata mapping check; never changes originals."""
import argparse
import json
import os
from pathlib import Path
import time

import cache_probe
import prepare_access_inputs as prepare
import run as runner


def compare_rows(value):
    root = Path(value['source_root'])
    if not root.is_absolute() or root.is_symlink():
        raise ValueError('Canonical absolute source root required')
    seen = set()
    for row in value['objects']:
        path = Path(row['path'])
        path.relative_to(root)
        if path.is_symlink() or str(path) in seen:
            raise ValueError('Symlink or repeated mapped path')
        actual = prepare.object_row(path, root, row['scope_kind'])
        if actual != row:
            raise ValueError('Observed metadata changed: ' + str(path))
        seen.add(str(path))
    return len(seen)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    cache_probe._ensure_guest()
    args.output.mkdir(mode=0o700)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    manifest = json.loads((args.prepared / 'object-inventory-manifest.json').read_bytes())
    if manifest['boot_id'] != boot:
        raise ValueError('Inventory boot differs')
    receipts = []
    for entry in manifest['inventories']:
        source = Path(entry['path'])
        if runner.sha_file(source) != entry['sha256']:
            raise ValueError('Pre-campaign inventory bytes changed')
        value = json.loads(source.read_bytes())
        if value['boot_id'] != boot or value.get('read_only') is not True:
            raise ValueError('Inventory scope differs')
        if not os.statvfs(value['source_root']).f_flag & os.ST_RDONLY:
            raise ValueError('Scope is no longer read-only')
        begin = time.monotonic_ns()
        count = compare_rows(value)
        if count != entry['objects']:
            raise ValueError('Inventory count differs')
        value.update(pre_post_identical=True,
            pre_inventory_sha256=entry['sha256'],
            post_verification={'started_ns': begin, 'ended_ns': time.monotonic_ns(),
                'status': 'IDENTICAL_READONLY_METADATA_WITHIN_DECLARED_SCOPE',
                'scope': 'dev/inode/size/mtime/ctime/mode/uid/gid/path; not instantaneous kernel path or per-access content hash'})
        target = args.output / source.name
        runner.dump(target, value)
        receipts.append({**entry, 'path': str(target), 'sha256': runner.sha_file(target)})
        print(json.dumps({'verified': source.name, 'objects': count}), flush=True)
    runner.dump(args.output / 'manifest.json', {'schema_version': 1, 'boot_id': boot,
        'inventories': receipts, 'source_manifest_sha256': runner.sha_file(args.prepared / 'object-inventory-manifest.json'),
        'status': 'VERIFIED_DECLARED_READONLY_MAPPING_SCOPE'})


if __name__ == '__main__':
    main()
