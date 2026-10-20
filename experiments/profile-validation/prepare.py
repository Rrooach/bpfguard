#!/usr/bin/env python3
"""Prepare only this owned Guest experiment directory; never clear Host caches."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/opt/profile-validation/search'))
    parser.add_argument('--source-artifacts', type=Path, default=Path('/opt/agent-benchmarks/artifacts-corrected.json'))
    parser.add_argument('--output-artifacts', type=Path, default=Path('/opt/profile-validation/artifacts.json'))
    parser.add_argument('--sampler', type=Path)
    parser.add_argument('--pressure-mib', type=int, default=320)
    parser.add_argument('--skip-pressure', action='store_true')
    args = parser.parse_args()
    vendor = ' '.join(p.read_text(errors='replace') for p in (Path('/sys/class/dmi/id/product_name'), Path('/sys/class/dmi/id/sys_vendor')) if p.exists()).lower()
    if not any(value in vendor for value in ('qemu', 'kvm')) or os.geteuid() != 0:
        parser.error('only root inside the owned QEMU experiment Guest')
    if not 128 <= args.pressure_mib <= 1024:
        parser.error('pressure corpus must be bounded to 128..1024 MiB')
    config = json.loads(args.source_artifacts.read_text())
    if args.sampler:
        config['sampler_binary'] = str(args.sampler.resolve(strict=True))
        config['sampler_sha256'] = hashlib.sha256(args.sampler.read_bytes()).hexdigest()
    with args.output_artifacts.open('x') as stream:
        json.dump(config, stream, indent=2)
        stream.write('\n')
    if args.skip_pressure:
        return 0
    corpus = args.root / 'pressure-corpus'
    corpus.mkdir(mode=0o755)
    # This is explicitly synthetic sequential-read calibration data, not a
    # disguised real repository or model evaluation. Never create sparse files.
    payload = (b'profile calibration: deterministic sequential read\n' * 22000)[:1024 ** 2]
    payload += b'x' * (1024 ** 2 - len(payload))
    digest = hashlib.sha256(payload).hexdigest()
    for index in range(args.pressure_mib):
        with (corpus / ('block-%04d.txt' % index)).open('xb') as stream:
            stream.write(payload)
    with (args.root / 'pressure-corpus-source.json').open('x') as stream:
        json.dump({'kind': 'SYNTHETIC_SEQUENTIAL_READ_CALIBRATION', 'files': args.pressure_mib,
                   'block_bytes': len(payload), 'block_sha256': digest,
                   'physical_storage_cold': 'UNKNOWN'}, stream, indent=2)
    return 0


if __name__ == '__main__':
    sys.exit(main())
