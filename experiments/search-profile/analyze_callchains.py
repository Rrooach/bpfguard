#!/usr/bin/env python3
"""Offline, mutually exclusive on-CPU callchain candidates for saved search diagnosis.

This never invokes perf, a Guest, or a workload. CPU-clock periods and sampled
stack contexts are not wall-clock durations, storage waits, or causal proof.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location('search_callchain_diagnose', HERE / 'diagnose.py')
DIAGNOSE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(DIAGNOSE)
# Reuse the producer's exact inline header. perf's cursor-enabled printer also
# puts IP/symbol on the next line (tools/perf/builtin-script.c); recognize only
# the same pid/tid, mode, nanosecond and period prefix, not arbitrary text.
SAMPLE = DIAGNOSE.SAMPLE
PREFIX = re.compile(r'^\s*(\d+)\s*/\s*(\d+)\s+([UKGgH]+)\s+(\d+)\.(\d{1,9}):\s+(\d+)\s*$')
HEADER_LIKE = re.compile(r'^\s*\d+\s*/\s*\d+')
FRAME = re.compile(r'^\s+((?:0x)?[0-9a-fA-F]+)\s+(.+?)\s+\((.+)\)\s*$')
FRAME_WITHOUT_DSO = re.compile(r'^\s+((?:0x)?[0-9a-fA-F]+)\s+(.+?)\s*$')
MAX_FRAMES = 4096
MAX_TEXT = DIAGNOSE.MAX_TEXT

MATCHING = 'USER_GREP_MATCHING_CANDIDATE'
DIRECTORY = 'DIRECTORY_ENUMERATION_CANDIDATE'
METADATA = 'PATH_OPEN_STAT_CLOSE_METADATA_CANDIDATE'
READ_COPY = 'KERNEL_READ_COPY_CPU_CANDIDATE_NOT_IO_WAIT'
RECLAIM = 'KERNEL_RECLAIM_CPU_CANDIDATE'
OTHER = 'OTHER_RESOLVED_ONCPU_CONTEXT'
UNKNOWN = 'UNKNOWN_OR_UNUSABLE_STACK'
CATEGORIES = (MATCHING, DIRECTORY, METADATA, READ_COPY, RECLAIM, OTHER, UNKNOWN)

# GNU grep's gnulib replacement exports rpl_fts_* on the pinned Debian build;
# these are not interchangeable with an arbitrary symbol containing "fts".
# The exact build's nm also contains bmexec_trans as a real matching function.
GREP_MATCHERS = tuple(DIAGNOSE.MATCHERS) + ('bmexec_trans',)
USER_DIRECTORY = ('fts_open', 'fts_read', 'fts_children', 'fts_build', 'fts_stat',
    'rpl_fts_open', 'rpl_fts_read', 'rpl_fts_children', 'rpl_fts_close', 'rpl_fts_set',
    'fts_safe_changedir', 'fts_sort', 'fts_compare_ino',
    'readdir', 'readdir64', '__readdir', '__readdir64', 'getdents', 'getdents64', '__getdents64')
KERNEL_DIRECTORY = ('iterate_dir', 'iterate_shared', 'ksys_getdents', '__x64_sys_getdents',
    '__x64_sys_getdents64', '__do_sys_getdents', '__do_sys_getdents64', 'filldir', 'filldir64',
    'ext4_readdir', 'btrfs_real_readdir', 'btrfs_readdir', 'ovl_iterate', 'dcache_readdir')
USER_METADATA = ('open', 'open64', 'openat', 'openat64', '__open', '__open64', '__openat', '__openat64',
    '__open64_nocancel', '__openat64_nocancel', 'stat', 'stat64', 'lstat', 'lstat64', 'fstat', 'fstat64',
    'fstatat', 'fstatat64', 'statx', '__stat', '__stat64', '__lstat', '__lstat64', '__fstat', '__fstat64',
    '__fxstat', '__fxstat64', '__fxstatat', '__fxstatat64', '__xstat', '__xstat64', '__lxstat', '__lxstat64',
    'close', '__close', '__close_nocancel', '__close_nocancel_nostatus')
KERNEL_METADATA = ('lookup_fast', 'lookup_slow', '__lookup_slow', 'link_path_walk', 'path_lookupat',
    'filename_lookup', 'walk_component', 'd_lookup', '__d_lookup', '__d_lookup_rcu', 'path_init',
    'inode_permission', 'security_inode_permission', 'security_inode_getattr', 'vfs_getattr',
    'vfs_getattr_nosec', 'vfs_statx', 'do_statx', 'vfs_fstat', 'vfs_fstatat',
    '__x64_sys_statx', '__x64_sys_newfstatat', '__x64_sys_fstat', '__x64_sys_newfstat',
    '__x64_sys_open', '__x64_sys_openat', '__x64_sys_openat2', 'do_sys_openat2', 'do_sys_open',
    'do_filp_open', 'path_openat', 'do_dentry_open', 'vfs_open', 'security_file_open',
    'ext4_lookup', 'btrfs_lookup', '__x64_sys_close', 'close_fd', 'filp_close', 'file_close_fd', '__fput')
KERNEL_READ_COPY = tuple(DIAGNOSE.READ_PATH) + ('__x64_sys_read', '__x64_sys_pread64',
    'copy_page_to_iter', 'copy_folio_to_iter', 'copy_to_iter', '_copy_to_iter',
    'copy_to_user', '_copy_to_user', 'copy_user_enhanced_fast_string', 'copy_user_generic_string',
    'copy_user_short_string', 'copy_user_enhanced_fast_string_rep_movs')
LOCKS = ('queued_spin_lock_slowpath', 'native_queued_spin_lock_slowpath', 'mutex_lock',
    '__mutex_lock', 'rwsem_down_read_slowpath', 'rwsem_down_write_slowpath',
    'down_read', 'down_write', '__lll_lock_wait', '__lll_lock_wait_private',
    'futex_wait', 'futex_wait_queue', '__futex_abstimed_wait_common')
BAD_STACK = re.compile(r'(?:unwind(?:ing)?\s+(?:fail|error)|failed\s+to\s+unwind|'
    r'callchain\s+(?:truncat|corrupt)|not enough memory for the callchain|'
    r'\[truncated\]|\[unwind error\]|<stack (?:lost|truncated)|deferred callchain)', re.I)
KERNEL_DSOS = {'[kernel.kallsyms]', '[kernel.vmlinux]', '[kernel]', 'vmlinux',
               'btrfs', 'ext4', 'xfs', 'overlay', 'overlayfs'}


def _symbol(value):
    value = re.sub(r'\+0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?$', '', value.strip())
    value = re.sub(r'\.(?:isra|constprop|part|llvm)\.[\w.]+$|\.cold(?:\.\d+)?$', '', value)
    return value.split('@', 1)[0]


def _known(frame):
    symbol = _symbol(frame['symbol'])
    return bool(frame.get('dso') and frame['dso'] not in ('unknown', '[unknown]', 'inlined')
        and symbol not in ('unknown', '[unknown]', '??')
        and not re.fullmatch(r'(?:0x)?[0-9a-fA-F]+', symbol))


def _kernel(frame):
    dso = frame.get('dso') or ''
    return dso in KERNEL_DSOS or dso.startswith('[kernel.kallsyms') or dso.endswith('.ko')


def _grep(frame, grep):
    # perf normally emits a short DSO name. Only that exact short name or the
    # recorded full executable path is accepted, not /somewhere-else/grep.
    return frame.get('dso') in (str(grep), Path(grep).name)


def _matches(frame, names):
    return _known(frame) and _symbol(frame['symbol']) in names


def classify_stack(sample, grep):
    frames = sample['frames']
    locks = [frame for frame in frames if _matches(frame, LOCKS)]
    if sample.get('stack_issues') or not frames:
        return UNKNOWN, None, locks, 'UNUSABLE_OR_MISSING_CALLCHAIN'
    mode = sample['mode']
    if mode not in ('U', 'K'):
        return UNKNOWN, None, locks, 'CPU_MODE_NOT_USER_OR_KERNEL'
    # Specific kernel activity wins over its user caller. A kernel read under
    # Fexecute is not counted as user matching. Reclaim wins over read; directory
    # traversal and metadata win over generic copy helpers inside those paths.
    if mode == 'K':
        for category, names in ((RECLAIM, DIAGNOSE.RECLAIM), (DIRECTORY, KERNEL_DIRECTORY),
                                (METADATA, KERNEL_METADATA), (READ_COPY, KERNEL_READ_COPY)):
            match = next((frame for frame in frames if _kernel(frame) and _matches(frame, names)), None)
            if match:
                return category, match, locks, 'RESOLVED_KERNEL_FRAME_CONTEXT'
    else:
        for category, names in ((DIRECTORY, USER_DIRECTORY), (METADATA, USER_METADATA)):
            match = next((frame for frame in frames if not _kernel(frame) and _matches(frame, names)), None)
            if match:
                return category, match, locks, 'RESOLVED_USER_FRAME_CONTEXT'
        match = next((frame for frame in frames if _grep(frame, grep) and _matches(frame, GREP_MATCHERS)), None)
        if match:
            basis = 'RECORDED_GREP_PATH' if match['dso'] == str(grep) else 'EXPORTED_GREP_SHORT_DSO_NAME_NOT_BUILDID_PROOF'
            return MATCHING, match, locks, basis
    if any(not _known(frame) for frame in frames):
        return UNKNOWN, None, locks, 'NO_SELECTED_CONTEXT_AND_UNRESOLVED_FRAMES'
    return OTHER, None, locks, 'RESOLVED_FRAMES_WITHOUT_SELECTED_SEMANTIC_ANCHOR'


def _header(match, line_number, inline):
    pid, tid, mode, sec, nsec, period, *frame = match.groups()
    result = {'pid': int(pid), 'tid': int(tid), 'mode': mode,
        'timestamp_ns': int(sec) * 1_000_000_000 + int(nsec.ljust(9, '0')),
        'period': int(period), 'line': line_number, 'frames': [], 'stack_issues': []}
    if inline:
        result['frames'].append(dict(zip(('ip', 'symbol', 'dso'), frame)))
    return result


def iter_callchains(lines, issues):
    """One yielded item per recognized sample header, never one per frame."""
    pending = None
    for line_number, text in enumerate(lines, 1):
        text = text.rstrip('\r\n')
        match = SAMPLE.fullmatch(text)
        prefix = None if match else PREFIX.fullmatch(text)
        if match or prefix:
            if pending is not None:
                yield pending
            pending = _header(match or prefix, line_number, bool(match))
        elif not text.strip():
            if pending is not None:
                yield pending
                pending = None
        elif text.lstrip().startswith('#') and 'LOST' not in text.upper():
            continue
        elif HEADER_LIKE.match(text):
            if pending is not None:
                yield pending
                pending = None
            issues.append({'line': line_number, 'code': 'MALFORMED_SAMPLE_HEADER_OR_TIMESTAMP'})
        elif 'LOST' in text.upper() and ('PERF_RECORD' in text.upper() or 'LOST ' in text.upper()):
            if pending is not None:
                yield pending
                pending = None
            issues.append({'line': line_number, 'code': 'LOST_PERF_RECORD', 'text': text[:300]})
        elif pending is None:
            issues.append({'line': line_number, 'code': 'ORPHAN_FRAME_OR_UNPARSED_RECORD', 'text': text[:300]})
        elif BAD_STACK.search(text):
            pending['stack_issues'].append('EXPLICIT_UNWIND_FAILURE_OR_TRUNCATION')
        else:
            frame = FRAME.fullmatch(text)
            bare = None if frame else FRAME_WITHOUT_DSO.fullmatch(text)
            if frame or bare:
                if len(pending['frames']) >= MAX_FRAMES:
                    if 'FRAME_LIMIT_EXCEEDED' not in pending['stack_issues']:
                        pending['stack_issues'].append('FRAME_LIMIT_EXCEEDED')
                elif frame:
                    pending['frames'].append(dict(zip(('ip', 'symbol', 'dso'), frame.groups())))
                else:
                    ip, symbol = bare.groups()
                    pending['frames'].append({'ip': ip, 'symbol': symbol, 'dso': None})
            else:
                pending['stack_issues'].append('UNPARSED_CALLCHAIN_FRAME')
    if pending is not None:
        yield pending


def _windows(windows):
    result = []
    for index, value in enumerate(windows):
        if not isinstance(value, dict) or any(type(value.get(key)) is not int or value[key] < 0 for key in ('release_ns', 'end_ns')):
            raise ValueError('each search window needs exact integer monotonic endpoints')
        if value['end_ns'] <= value['release_ns'] or not isinstance(value.get('run_id'), str) or not value['run_id']:
            raise ValueError('invalid search window identity or ordering')
        result.append(dict(value))
    result.sort(key=lambda value: value['release_ns'])
    if (not result or len({value['run_id'] for value in result}) != len(result)
            or any(right['release_ns'] <= left['end_ns'] for left, right in zip(result, result[1:]))):
        raise ValueError('search windows must be nonempty, uniquely identified, and nonoverlapping')
    return result


def _key(sample):
    return tuple(sample[key] for key in ('pid', 'tid', 'mode', 'timestamp_ns', 'period'))


def analyze_text(lines, windows, grep, leaf_lines=None):
    """Classify saved text; UNKNOWN stays in both sample and period denominators."""
    windows = _windows(windows)
    starts = [window['release_ns'] for window in windows]
    issues, counts, periods, reasons, anchors = [], Counter(), Counter(), Counter(), Counter()
    keys, outside, valid_periods, locks_count, locks_period = Counter(), 0, True, 0, 0
    per_window = {window['run_id']: {'sample_count': 0, 'period_weight': 0, 'categories': Counter()} for window in windows}
    examples = defaultdict(list)

    def window_for(stamp):
        index = bisect_right(starts, stamp) - 1
        return windows[index] if index >= 0 and stamp <= windows[index]['end_ns'] else None

    for sample in iter_callchains(lines, issues):
        window = window_for(sample['timestamp_ns'])
        if window is None:
            outside += 1
            continue
        keys[_key(sample)] += 1
        category, anchor, lock_frames, basis = classify_stack(sample, grep)
        if sample['pid'] <= 0 or sample['tid'] <= 0:
            category, anchor, basis = UNKNOWN, None, 'INVALID_PROCESS_OR_THREAD_ID'
            issues.append({'line': sample['line'], 'code': basis})
        if sample['period'] <= 0:
            category, anchor, basis, valid_periods = UNKNOWN, None, 'INVALID_SAMPLE_PERIOD', False
            issues.append({'line': sample['line'], 'code': basis})
        for reason in sample['stack_issues']:
            issues.append({'line': sample['line'], 'code': reason})
        weight = max(0, sample['period'])
        counts[category] += 1
        periods[category] += weight
        reasons[basis] += 1
        row = per_window[window['run_id']]
        row['sample_count'] += 1; row['period_weight'] += weight; row['categories'][category] += 1
        if anchor:
            anchors[(category, anchor['symbol'], anchor['dso'])] += weight
        if lock_frames and not sample['stack_issues']:
            locks_count += 1; locks_period += weight
        if len(examples[category]) < 5:
            examples[category].append({'line': sample['line'], 'run_id': window['run_id'],
                **{key: sample[key] for key in ('pid', 'tid', 'timestamp_ns', 'period')},
                'frame_count': len(sample['frames']), 'basis': basis, 'anchor': anchor,
                'lock_candidate': bool(lock_frames), 'stack_issues': sample['stack_issues']})
    binding = 'NOT_CHECKED_LEAF_EXPORT_NOT_PROVIDED'
    if leaf_lines is not None:
        leaf_keys = Counter()
        for number, text in enumerate(leaf_lines, 1):
            if not text.strip() or text.lstrip().startswith('#'):
                continue
            match = SAMPLE.fullmatch(text.rstrip('\r\n'))
            if match is None:
                issues.append({'line': number, 'code': 'UNPARSED_OR_LOST_LEAF_EXPORT_RECORD'})
                continue
            sample = _header(match, number, True)
            if window_for(sample['timestamp_ns']):
                leaf_keys[_key(sample)] += 1
        binding = 'MATCHED_PID_TID_MODE_TIMESTAMP_PERIOD_MULTISET' if keys == leaf_keys else 'INCOMPLETE_SAMPLE_STREAM_MISMATCH'
        if keys != leaf_keys:
            issues.append({'code': 'CALLCHAIN_LEAF_SAMPLE_STREAM_MISMATCH',
                'callchain_only_samples': sum((keys - leaf_keys).values()),
                'leaf_only_samples': sum((leaf_keys - keys).values())})
    total_count, total_period = sum(counts.values()), sum(periods.values())
    return {'schema_version': 1,
        'status': 'INCOMPLETE' if issues else ('OBSERVED_ONCPU_CANDIDATES_ONLY' if total_count else 'NO_SAMPLES_IN_SEARCH_WINDOWS'),
        'sample_count': total_count, 'period_weight': total_period if valid_periods else None,
        'outside_search_windows': outside, 'sample_stream_binding': binding,
        'categories': {category: {'samples': counts[category], 'period_weight': periods[category],
            'fraction_of_observed_samples': counts[category] / total_count if total_count else None,
            'fraction_of_observed_period': periods[category] / total_period if valid_periods and total_period else None}
            for category in CATEGORIES},
        'per_window': per_window, 'classification_basis_counts': dict(reasons), 'examples': dict(examples),
        'top_semantic_anchors': [{'category': key[0], 'symbol': key[1], 'dso': key[2], 'period_weight': value}
            for key, value in anchors.most_common(40)],
        'orthogonal_lock_annotation': {'sample_count': locks_count, 'period_weight': locks_period,
            'fraction_of_observed_period': locks_period / total_period if valid_periods and total_period else None,
            'not_additive': True, 'interpretation': 'Candidate lock-context on-CPU samples overlap primary categories; not off-CPU waiting or lock contention duration.'},
        'windows': windows, 'issues': issues,
        'classification_priority': 'KERNEL: reclaim > directory > metadata > read/copy; USER: directory > metadata > explicit grep matcher; unresolved fallback UNKNOWN, otherwise OTHER.',
        'limits': ['One sample has exactly one primary category; ancestor frames are context, not additional samples.',
            'An unresolved leaf with a resolved selected ancestor can provide candidate context; malformed/truncated/unwind-failed stacks remain UNKNOWN.',
            'Unknown samples stay in the denominator; malformed records have no recoverable weight and make the analysis INCOMPLETE.',
            'Sample periods/fractions are on-CPU software cpu-clock evidence, not wall-time shares or off-CPU storage waits.',
            'A grep short DSO name is an exported symbol candidate, not independent build-id or executable identity proof.',
            'No complete unwinding, absence of missed samples, or causal bottleneck conclusion is established.']}


def _read(root, relative, sources, json_value=True):
    path = Path(relative)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('evidence path must remain relative to diagnosis')
    source = root / path
    source.resolve(strict=True).relative_to(root)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_TEXT:
        raise ValueError('bounded non-symlink regular evidence required: ' + str(path))
    raw = source.read_bytes()
    sources[str(path)] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    return raw if json_value is None else (json.loads(raw) if json_value else raw.decode('utf-8'))


def _identity(value):
    if not isinstance(value, dict) or not isinstance(value.get('path'), str) or any(type(value.get(key)) is not int or value[key] <= 0 for key in ('inode', 'device')):
        raise ValueError('exact cgroup path/inode/device identity required')
    return {key: value[key] for key in ('path', 'inode', 'device')}


def analyze_diagnosis(directory):
    root, sources = Path(directory).resolve(strict=True), {}
    diagnosis = _read(root, 'diagnosis.json', sources)
    if (type(diagnosis.get('schema_version')) is not int or diagnosis['schema_version'] != 1 or diagnosis.get('diagnosis_only') is not True
            or diagnosis.get('not_formal_timing_or_overhead') is not True
            or type(diagnosis.get('runner_returncode')) is not int or diagnosis['runner_returncode'] != 0):
        raise ValueError('a completed diagnostic runner, not formal performance evidence, is required')
    collector = diagnosis.get('collector', {})
    if _read(root, 'collector/diagnostics.json', sources) != collector:
        raise ValueError('collector summary differs from its original diagnostics artifact')
    scope = collector.get('perf_scope', {})
    group = _identity(diagnosis.get('cgroup'))
    if (_identity(collector.get('cgroup')) != group or collector.get('boot_id') != diagnosis.get('boot_id')
            or not isinstance(diagnosis.get('boot_id'), str) or not diagnosis['boot_id']
            or scope.get('clock') != 'CLOCK_MONOTONIC' or scope.get('event') != 'software cpu-clock'
            or not group['path'].startswith('/sys/fs/cgroup/')
            or scope.get('cgroup_relative_path') != group['path'][len('/sys/fs/cgroup/'):]):
        raise ValueError('perf clock, boot or registered cgroup identity is unbound')
    command = diagnosis.get('command')
    if not isinstance(command, list) or command.count('--grep') != 1:
        raise ValueError('exact recorded grep executable path required')
    try:
        grep = command[command.index('--grep') + 1]
    except IndexError as error:
        raise ValueError('missing grep executable path') from error
    if not isinstance(grep, str) or not Path(grep).is_absolute():
        raise ValueError('grep executable path must be absolute')
    # Reuse the producer's independent raw NUL-output, task-set and timing
    # reconstruction. Do not trust its previously derived perf percentages.
    campaign, _, profiles = DIAGNOSE.output_signature(root / 'runner')
    _read(root, 'runner/campaign.json', sources)
    if (not re.fullmatch(r'[0-9a-f]{64}', diagnosis.get('grep_sha256', ''))
            or campaign.get('binaries', {}).get('grep_sha256') != diagnosis['grep_sha256']):
        raise ValueError('grep binary digest differs between diagnosis and runner')
    windows = []
    for trial_dir, profile in profiles:
        relative = trial_dir.relative_to(root)
        _read(root, relative / 'profile-run.json', sources)
        if profile.get('boot_id') != diagnosis['boot_id']:
            raise ValueError('profile boot identity differs from perf diagnosis')
        expected = group['path'] + '/' + profile['run_id']
        if _identity(profile.get('root_cgroup'))['path'] != expected:
            raise ValueError('profile cgroup is outside registered diagnostic parent')
        meta = _read(root, relative / 'load/load-meta.json', sources)
        if (meta.get('boot_id') != diagnosis['boot_id'] or meta.get('label') != profile['run_id']
                or _identity(profile['root_cgroup']) not in [_identity(value) for value in meta.get('cgroups', [])]):
            raise ValueError('profile cgroup identity differs from sampler enrollment')
        for result in profile['results']:
            _read(root, relative / (result['task_id'] + '.stdout'), sources, json_value=None)
        windows.append({'run_id': profile['run_id'], 'release_ns': profile['release_ns'], 'end_ns': profile['end_ns'],
            'source': str(relative / 'profile-run.json'), 'boot_id': profile['boot_id'], 'root_cgroup': profile['root_cgroup']})
    chain = diagnosis.get('perf_callchains', {})
    if (chain.get('status') != 'EXPORTED_RAW_NOT_CLASSIFIED' or type(chain.get('returncode')) is not int
            or chain['returncode'] != 0 or chain.get('path') != 'perf-callchains.txt'):
        raise ValueError('successful raw callchain export receipt required')
    text = _read(root, chain['path'], sources, json_value=False)
    if sources[chain['path']]['sha256'] != chain.get('sha256') or sources[chain['path']]['bytes'] != chain.get('bytes'):
        raise ValueError('raw callchain text differs from export receipt')
    leaf = _read(root, 'perf-samples.txt', sources, json_value=False)
    export_warnings = {}
    for name in ('perf-script.stderr', 'perf-callchains.stderr'):
        if (root / name).exists():
            warning = _read(root, name, sources, json_value=False)
            export_warnings[name] = {'nonempty': bool(warning.strip()), 'first_1000_characters': warning[:1000]}
    result = analyze_text(text.splitlines(), windows, grep, leaf.splitlines())
    result.update(diagnosis_directory=str(root), raw_diagnosis_status=diagnosis.get('status'),
        raw_diagnosis_issues=diagnosis.get('issues'), raw_collector_status=collector.get('status'),
        raw_collector_issues=collector.get('issues'), grep_path=grep, grep_sha256=diagnosis['grep_sha256'],
        call_graph=chain.get('call_graph'), sources=sources,
        export_warnings=export_warnings,
        analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        diagnosis_parser_sha256=hashlib.sha256((HERE / 'diagnose.py').read_bytes()).hexdigest(),
        collection_health='NOT_ESTABLISHED_BY_TEXT_REPLAY; raw diagnosis/collector issues and unresolved symbols remain explicit')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnosis', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='fresh JSON file; existing evidence is never overwritten')
    args = parser.parse_args()
    report = analyze_diagnosis(args.diagnosis)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'status': report['status'], 'samples': report['sample_count'], 'output': str(args.output)}))


if __name__ == '__main__':
    main()
