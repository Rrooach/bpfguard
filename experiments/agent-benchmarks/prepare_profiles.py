#!/usr/bin/env python3
"""Prepare pinned local artifacts and read-only source copies inside owned VM."""
import argparse
import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    vendor = ' '.join(Path('/sys/class/dmi/id', name).read_text() for name in ('product_name', 'sys_vendor'))
    if os.geteuid() != 0 or not any(word in vendor.lower() for word in ('qemu', 'kvm')):
        parser.error('owned privileged experiment Guest only')
    root = args.root.resolve(strict=True)
    baseline = json.loads(args.artifacts.read_text())
    sampler = root / 'bin/allox-load-sampler'
    baseline.update(sampler_binary=str(sampler), sampler_sha256=sha(sampler))
    save(root / 'artifacts.json', baseline)
    paths = {'kernel_hist_object': root / 'bin/kernel_hist.bpf.o',
        'file_profiler_binary': root / 'bin/allox-file-profiler',
        'file_profiler_object': root / 'bin/file_profile.bpf.o', 'perf_binary': Path('/usr/bin/perf').resolve(strict=True)}
    extra = {key: str(value) for key, value in paths.items()}
    extra.update(kernel_hist_sha256=sha(paths['kernel_hist_object']),
        file_profiler_sha256=sha(paths['file_profiler_binary']),
        file_profiler_object_sha256=sha(paths['file_profiler_object']), perf_sha256=sha(paths['perf_binary']),
        max_file_records=65536, frequency_hz=99)
    save(root / 'diagnostic-assets.json', extra)
    images = {'swe': ('swebench/sweb.eval.x86_64.psf_1776_requests-1142:latest', '/testbed'),
              'terminal': ('bpfguard-prewarm-bun-env:latest', '/app')}
    sources = {}
    for name, (reference, directory) in images.items():
        image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', reference]))[0]
        image_id = image['Id']
        identifier = subprocess.check_output(['docker', 'create', '--name', 'profile-source-' + uuid.uuid4().hex[:12],
            '--label', 'observer.run=' + root.name, image_id, '/bin/true'], text=True).strip()
        try:
            target = root / 'corpora' / name
            if target.exists():
                raise RuntimeError('refusing to overwrite source corpus')
            subprocess.run(['docker', 'cp', identifier + ':' + directory, str(target)], check=True)
            sources[name] = {'image_id': image_id, 'reference': reference, 'source_path': directory,
                'copied_path': str(target), 'scope': 'IMMUTABLE_BENCHMARK_SOURCE_COPY_NOT_EXECUTED_SOLUTION'}
        finally:
            subprocess.run(['docker', 'rm', identifier], check=True, stdout=subprocess.DEVNULL)
    save(root / 'corpus-provenance.json', sources)
    print(json.dumps({'prepared': str(root), 'sources': sources}, sort_keys=True))


if __name__ == '__main__':
    main()
