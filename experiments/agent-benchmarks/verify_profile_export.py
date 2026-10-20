#!/usr/bin/env python3
"""Verify a copied Guest tree against an inventory digest recorded before export.

This checks transport/content binding, not the truth or completeness of sensors.
It never changes the sealed tree. The receipt must be written outside that tree.
"""
import argparse
import json
from pathlib import Path
import re
import time

from seal_profiles import inside, read, sha, tree_files


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate inventory JSON key: ' + key)
        result[key] = value
    return result


def verify(root, manifest_sha256):
    root = Path(root).resolve(strict=True)
    if not re.fullmatch(r'[a-fA-F0-9]{64}', manifest_sha256):
        raise ValueError('external inventory SHA256 required')
    files = tree_files(root)
    inventory_path = root / 'export-inventory.json'
    if sha(inventory_path) != manifest_sha256.lower():
        raise ValueError('inventory differs from pre-export digest')
    inventory = json.loads(inventory_path.read_bytes(), object_pairs_hook=unique_object)
    if not isinstance(inventory, dict) or not inventory:
        raise ValueError('nonempty inventory object required')
    observed = {str(path.relative_to(root)) for path in files if path != inventory_path}
    if observed != set(inventory):
        raise ValueError('export file set differs: missing={}, extra={}'.format(
            sorted(set(inventory) - observed)[:10], sorted(observed - set(inventory))[:10]))
    total_bytes = 0
    for relative, expected in inventory.items():
        if relative != Path(relative).as_posix():
            raise ValueError('noncanonical inventory path: ' + relative)
        path = inside(root, relative)
        before = path.stat()
        digest = sha(path)
        after = path.stat()
        identity = lambda s: (s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after):
            raise ValueError('export changed during verification: ' + relative)
        if (not isinstance(expected, dict) or type(expected.get('bytes')) is not int
                or expected['bytes'] != after.st_size or expected.get('sha256') != digest):
            raise ValueError('export content/size differs: ' + relative)
        total_bytes += after.st_size
    inputs = read(root / 'export-inputs.json')
    pinned = []
    for item in inputs.get('inputs', []):
        target = inside(root, item['target'])
        if sha(target) != item['sha256'] or target.stat().st_size != item['bytes']:
            raise ValueError('archived input differs from its receipt: ' + item['target'])
        if item.get('pin_source', '').split(':')[0] in ('artifacts.json', 'diagnostic-assets.json'):
            pinned.append(item['target'])
    if len(pinned) != 12 or len(set(pinned)) != 12:
        raise ValueError('expected twelve distinct pinned runtime assets')
    environment = read(root / 'export-environment.json')
    return {'schema_version': 1, 'status': 'CONTENT_BINDING_VERIFIED', 'root': str(root),
        'external_inventory_sha256': manifest_sha256.lower(), 'files': len(inventory),
        'bytes': total_bytes, 'pinned_runtime_assets_verified': len(pinned),
        'boot_id': environment['boot_id'], 'verified_wall_ns': time.time_ns(),
        'coverage': 'TRANSPORT_AND_SAVED_BINDINGS_ONLY; NOT_SENSOR_TRUTH_OR_COMPLETE_COVERAGE'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root, output = args.root.resolve(strict=True), args.output.resolve()
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        parser.error('receipt must be outside the sealed tree')
    if output.exists() or output.is_symlink():
        parser.error('fresh receipt path required')
    result = verify(root, args.manifest_sha256)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
