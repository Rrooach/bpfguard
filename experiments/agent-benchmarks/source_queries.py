#!/usr/bin/env python3
"""Fixed-work query latency on genuine SWE/Terminal source, not task scores."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--benchmark', choices=['swe', 'terminal'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    provenance = json.loads((args.root / 'corpus-provenance.json').read_text())[args.benchmark]
    records = []
    for intervention in ('none', 'exact-reuse'):
        target = args.output / intervention
        command = [sys.executable, '-B', str(args.root / 'search/run.py'),
            '--corpus', provenance['copied_path'], '--queries-file',
            str(args.root / ('search/profile-queries-' + args.benchmark + '.json')),
            '--output-dir', str(target), '--sampler', str(args.root / 'bin/allox-load-sampler'),
            '--concurrency', '1,8', '--modes', 'baseline,sampler', '--jobs', '8', '--passes', '8',
            '--repetitions', '5', '--warmups', '1', '--cache', 'warm', '--cpus', '0,1',
            '--cgroup-layout', 'shared-leaf', '--repository-version', provenance['image_id'],
            '--intervention', intervention, '--interval-ms', '100', '--process-interval-ms', '100',
            '--sample-threads', '--seed', '7351', '--cgroup-parent',
            '/sys/fs/cgroup/query-' + args.benchmark + '-' + intervention]
        print(json.dumps({'running': args.benchmark, 'intervention': intervention}), flush=True)
        with (args.output / (intervention + '.stdout')).open('xb') as out, (args.output / (intervention + '.stderr')).open('xb') as err:
            result = subprocess.run(command, stdout=out, stderr=err, timeout=900)
        records.append({'intervention': intervention, 'returncode': result.returncode, 'path': str(target), 'command': command})
        if result.returncode:
            break
    with (args.output / 'source-query-campaign.json').open('x') as stream:
        json.dump({'schema_version': 1, 'benchmark': args.benchmark, 'source': provenance,
            'scope': 'DETERMINISTIC_GREP_MECHANISM_ON_REAL_SOURCE_NOT_AUTONOMOUS_BENCHMARK_SCORE',
            'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'runs': records}, stream, indent=2)
    if len(records) != 2 or any(row['returncode'] for row in records):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
