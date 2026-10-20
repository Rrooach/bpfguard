#!/usr/bin/env python3
"""Recheck versioned block hints in a non-performance direct rich campaign."""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path

from replay import replay


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--analyzer', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--sampler-binary', type=Path, required=True)
    parser.add_argument('--hist-object', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    spec = importlib.util.spec_from_file_location('replay_analyzer', args.analyzer)
    analyzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer)
    campaign = json.loads((root / 'campaign.json').read_text())
    config = json.loads(args.artifacts.read_text())
    sampler_sha = hashlib.sha256(args.sampler_binary.read_bytes()).hexdigest()
    hist_sha = hashlib.sha256(args.hist_object.read_bytes()).hexdigest()
    if sampler_sha != config['sampler_sha256'] or sampler_sha != campaign['binaries']['sampler_sha256']:
        raise ValueError('saved sampler artifact does not match campaign/config')
    rows, issues = [], collections.Counter()
    equivalence = replay(root)
    for entry in campaign['trials']:
        trial = (root / entry['path']).resolve(strict=True)
        trial.relative_to(root)
        original = json.loads((trial / 'report.json').read_text())
        meta = json.loads((trial / 'load/load-meta.json').read_text())
        if meta['kernel_hist']['object_sha256'] != hist_sha:
            raise ValueError('saved BPF object does not match raw probe metadata')
        rebuilt = analyzer.analyze_trial(trial)
        if rebuilt['kernel_hist'] != original['kernel_hist']:
            raise ValueError('kernel diagnostic raw reanalysis differs from original report')
        hist = rebuilt['kernel_hist']
        block = hist['block_diagnostics']
        final = block['final']
        if block['status'] != 'OBSERVED_NON_ATOMIC_WITH_EXPLICIT_UNKNOWNS':
            raise ValueError('new block diagnostic endpoints unavailable')
        issues.update(issue['code'] for issue in rebuilt['issues'])
        rows.append({'trial': str(trial), 'concurrency': entry['concurrency'],
            'kernel_hist_status': hist['status'], 'registered_domains': len(hist['domains']),
            'flush_completed_spans': final['flush_service']['count'],
            'flush_service_sum_ns': final['flush_service']['sum_ns'],
            'queue_span_unknown': final['counters']['queue_span_unknown'],
            'untracked_complete_unknown': final['counters']['untracked_complete'],
            'zero_nonflush_unsupported': final['counters']['zero_nonflush_unsupported'],
            'request_fields_read_failed': final['counters']['request_read_failed'],
            'bounded_diagnostic_samples_truncated': final['samples_truncated'],
            'measurement_recursion_misses': sum(row['recursion_misses_final'] or 0 for row in hist['programs']
                if row['role'] != 'REGISTRATION_ONLY_NO_HISTOGRAM_PAYLOAD'),
            'kernel_return_probe_misses': sum(row['misses'] for row in hist['memory_return_probe_profiles']),
            'tracefs_cleanup': hist['tracefs_cleanup'], 'issues': rebuilt['issues'],
            'kernel_hist_raw_rebuild': 'PASS'})
    result = {'schema_version': 1, 'scope': 'non-performance two-trial real GNU grep rich diagnostic; no paid API',
        'raw_output_equivalence': equivalence, 'trials': rows, 'measurement_issues': dict(issues),
        'analyzer_sha256': hashlib.sha256(args.analyzer.read_bytes()).hexdigest(),
        'sampler_sha256': sampler_sha, 'hist_object_sha256': hist_sha,
        'status': 'PASS_REPLAY_WITH_EXPLICIT_UNKNOWNS',
        'interpretation': 'Replay/classification passed, not complete block coverage. Missing queue intervals and untracked completions remain UNKNOWN. Successful zero-byte FLUSH has independent service spans. Bounded hints are not full history, and system block is never Agent-attributed. No slowdown claim with one trial per concurrency.'}
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
