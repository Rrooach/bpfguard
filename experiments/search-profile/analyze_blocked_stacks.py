#!/usr/bin/env python3
"""Streaming, offline D-state switch-out stack candidates, never wait time.

Only this producer's sched_switch export is supported. CPU sampling analyzers
are not used. Raw bytes are SHA256 checked in the same bounded streaming pass.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('blocked_input_validator', HERE / 'diagnose.py')
DIAGNOSE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGNOSE)
MAX_BYTES = 1024 ** 3
MAX_LINE = 1024 ** 2
MAX_FRAMES = 128
MAX_COMMS = 128
MAX_EXAMPLES = 3
HEADER = re.compile(r'^\s*(\d+)\s*/\s*(\d+)\s+([UKGgH]+)\s+(\d+)\.(\d{1,9}):\s+'
    r'sched:sched_switch:\s+prev_comm=(.*?)\s+prev_pid=(\d+)\s+prev_prio=(-?\d+)\s+'
    r'prev_state=(\S+)\s+==>\s+next_comm=(.*?)\s+next_pid=(\d+)\s+next_prio=(-?\d+)\s*$')
HEADER_LIKE = re.compile(r'^\s*\d+\s*/\s*\d+')
FRAME = re.compile(r'^\s+((?:0x)?[0-9a-fA-F]+)\s+(.+?)\s+\((.+)\)\s*$')
BAD_STACK = re.compile(r'unwind.*(?:fail|error)|callchain.*(?:truncat|corrupt)|not enough memory|\[truncated\]', re.I)
CANDIDATES = ('folio_wait_filemap_read', 'direct_block_io_wait_context', 'block_queue_wait_context',
              'io_schedule_context', 'vfork_completion_wait_context', 'executable_or_file_fault_context')
DIRECT_BLOCK = {'submit_bio_wait', '__blkdev_direct_IO', '__blkdev_direct_IO_simple'}
BLOCK_QUEUE = {'blk_mq_get_tag', 'blk_mq_get_tags', 'blk_mq_alloc_request', 'blk_queue_enter', 'blk_mq_freeze_queue_wait'}


def integer(value):
    return type(value) is int and value >= 0


def identity(value):
    if (not isinstance(value, dict) or not isinstance(value.get('path'), str)
            or not value['path'].startswith('/sys/fs/cgroup/')
            or '..' in Path(value['path']).parts
            or not all(type(value.get(key)) is int and value[key] > 0 for key in ('inode', 'device'))):
        raise ValueError('exact cgroup path/inode/device required')
    return {key: value[key] for key in ('path', 'inode', 'device')}


def read_small(root, relative, sources, lines=False, raw=False):
    path = root / relative
    path.resolve(strict=True).relative_to(root)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024 ** 2:
        raise ValueError('bounded regular metadata required: ' + str(relative))
    value = path.read_bytes()
    sources[str(relative)] = {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
    if raw:
        return value.decode('utf-8')
    return [json.loads(line) for line in value.splitlines()] if lines else json.loads(value)


def bound_inputs(root):
    sources = {}
    diagnosis = read_small(root, 'diagnosis.json', sources)
    collector = read_small(root, 'collector/diagnostics.json', sources)
    ready = read_small(root, 'collector/diagnostics-ready.json', sources)
    controls = read_small(root, 'collector/perf-control.jsonl', sources, lines=True)
    if (diagnosis.get('schema_version') != 1 or diagnosis.get('diagnosis_only') is not True
            or diagnosis.get('not_formal_timing_or_overhead') is not True or diagnosis.get('perf_event') != 'sched-switch'
            or type(diagnosis.get('runner_returncode')) is not int or diagnosis['runner_returncode'] != 0
            or diagnosis.get('collector') != collector or collector.get('mode') != 'perf'):
        raise ValueError('dedicated sched-switch diagnosis/collector binding required')
    group = identity(diagnosis.get('cgroup'))
    scope = collector.get('perf_scope', {})
    boot = diagnosis.get('boot_id')
    if (not isinstance(boot, str) or not boot or collector.get('boot_id') != boot or identity(collector.get('cgroup')) != group
            or scope.get('event') != 'sched:sched_switch' or scope.get('clock') != 'CLOCK_MONOTONIC'
            or scope.get('trace_filter') != 'prev_state & 2' or scope.get('call_graph') != 'fp'
            or scope.get('period') != 1 or scope.get('frequency_hz') is not None
            or scope.get('enable_ack_received') is not True
            or scope.get('cgroup_relative_path') != group['path'][len('/sys/fs/cgroup/'):]
            or collector.get('perf_acknowledged_commands') != ['enable', 'disable']):
        raise ValueError('event, filter, boot or registered cgroup is unbound')
    command = collector.get('command', [])
    if (not isinstance(command, list) or len(command) != 21
            or command[1:18] != ['record', '--no-buildid-cache', '-e', 'sched:sched_switch', '-c', '1', '--filter',
                'prev_state & 2', '--call-graph', 'fp', '-a', '-G', scope['cgroup_relative_path'], '--clockid', 'mono', '--delay=-1', '--control']
            or not re.fullmatch(r'fd:\d+,\d+', command[18]) or command[19] != '-o'):
        raise ValueError('unexpected perf record command; do not analyze CPU samples as D records')
    for key in ('boot_id', 'cgroup', 'perf_scope', 'command', 'start_boundary', 'ready_boundary'):
        if ready.get(key) != collector.get(key):
            raise ValueError('collector READY identity/configuration differs from final receipt')
    if (ready.get('status') != 'READY' or not isinstance(controls, list) or len(controls) != 2
            or [row.get('command') for row in controls] != ['enable', 'disable']
            or any(not isinstance(row.get('ack'), str) or row['ack'].strip('\0\r\n') != 'ack'
                or not integer(row.get('monotonic_ns')) for row in controls)):
        raise ValueError('exact enable/disable ACK control receipts required')
    boundaries = [collector.get(key, {}) for key in ('start_boundary', 'ready_boundary', 'finish_boundary')]
    if (any(not integer(value.get('monotonic_ns')) or value.get('cgroup_events', {}).get('frozen') != '1' for value in boundaries)
            or not boundaries[0]['monotonic_ns'] <= controls[0]['monotonic_ns'] <= boundaries[1]['monotonic_ns']
            or not boundaries[1]['monotonic_ns'] <= boundaries[2]['monotonic_ns'] <= controls[1]['monotonic_ns']):
        raise ValueError('frozen control barriers are missing or out of order')
    campaign, _, profiles = DIAGNOSE.output_signature(root / 'runner')
    read_small(root, 'runner/campaign.json', sources)
    if campaign.get('binaries', {}).get('grep_sha256') != diagnosis.get('grep_sha256'):
        raise ValueError('pinned grep differs between runner and diagnosis')
    windows = []
    for directory, profile in profiles:
        relative = directory.relative_to(root)
        read_small(root, relative / 'profile-run.json', sources)
        child = identity(profile.get('root_cgroup'))
        meta = read_small(root, relative / 'load/load-meta.json', sources)
        if (profile.get('boot_id') != boot or child['path'] != group['path'] + '/' + profile['run_id']
                or meta.get('boot_id') != boot or meta.get('label') != profile['run_id']
                or child not in [identity(value) for value in meta.get('cgroups', [])]
                or not boundaries[1]['monotonic_ns'] <= profile['release_ns'] < profile['end_ns'] <= boundaries[2]['monotonic_ns']):
            raise ValueError('raw execution window or cgroup enrollment is outside collector barriers')
        windows.append({'run_id': profile['run_id'], 'release_ns': profile['release_ns'], 'end_ns': profile['end_ns'],
            'concurrency': profile['config']['concurrency'], 'root_cgroup': child, 'source': str(relative / 'profile-run.json')})
    windows.sort(key=lambda row: row['release_ns'])
    if any(right['release_ns'] <= left['end_ns'] for left, right in zip(windows, windows[1:])):
        raise ValueError('execution windows overlap')
    receipt = diagnosis.get('sched_switch', {})
    expected_script = [command[0], 'script', '--ns', '--show-lost-events', '-F',
        'pid,tid,misc,time,event,trace,ip,sym,dso', '-i', command[20]]
    if (receipt.get('status') != 'RAW_TRACE_EXPORTED_NOT_CLASSIFIED' or type(receipt.get('returncode')) is not int
            or receipt['returncode'] != 0 or receipt.get('event') != 'sched:sched_switch'
            or receipt.get('filter') != 'prev_state & 2' or receipt.get('call_graph') != 'fp'
            or receipt.get('path') != 'sched-switch-callchains.txt' or receipt.get('command') != expected_script
            or not integer(receipt.get('bytes')) or not 0 < receipt['bytes'] <= MAX_BYTES
            or not re.fullmatch(r'[0-9a-f]{64}', receipt.get('sha256', ''))):
        raise ValueError('successful bounded sched raw export receipt required')
    warnings = {}
    for name in ('sched-switch-script.stderr', 'collector/collector.stderr'):
        value = read_small(root, name, sources, raw=True)
        warnings[name] = {'nonempty': bool(value.strip()), 'first_2000_characters': value[:2000]}
    return diagnosis, receipt, windows, sources, warnings


def symbol(value):
    value = re.sub(r'\+0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?$', '', value)
    return re.sub(r'\.(?:isra|constprop|part|llvm)\.[\w.]+$|\.cold(?:\.\d+)?$', '', value)


def candidates(frames):
    names = {symbol(frame['symbol']) for frame in frames if frame['dso'] == '[kernel.kallsyms]'}
    result = []
    if 'folio_wait_bit_common' in names and 'filemap_read' in names:
        result.append('folio_wait_filemap_read')
    if names & DIRECT_BLOCK:
        result.append('direct_block_io_wait_context')
    if names & BLOCK_QUEUE:
        result.append('block_queue_wait_context')
    if names & {'io_schedule', 'io_schedule_timeout'}:
        result.append('io_schedule_context')
    if 'kernel_clone' in names and any(name.startswith('wait_for_completion') for name in names):
        result.append('vfork_completion_wait_context')
    if names & {'filemap_fault', 'bprm_execve', 'load_elf_binary'}:
        result.append('executable_or_file_fault_context')
    return result


def parse_stream(stream, windows, expected_bytes, expected_sha256):
    """One bounded binary pass; one record per header, never per stack frame."""
    if not integer(expected_bytes) or not 0 < expected_bytes <= MAX_BYTES:
        raise ValueError('raw stream outside 1 GiB bound')
    if (not isinstance(windows, list) or not windows
            or any(not isinstance(row, dict) or not isinstance(row.get('run_id'), str) or not row['run_id']
                or not integer(row.get('release_ns')) or not integer(row.get('end_ns'))
                or row['release_ns'] >= row['end_ns'] for row in windows)
            or len({row['run_id'] for row in windows}) != len(windows)
            or any(left['end_ns'] >= right['release_ns'] for left, right in zip(windows, windows[1:]))):
        raise ValueError('ordered, disjoint, uniquely identified integer search windows required')
    starts = [row['release_ns'] for row in windows]
    counters, issues, issue_examples, outside_comms = Counter(), Counter(), [], Counter()
    results = [{**window, 'records': 0, 'valid_d_records': 0, 'invalid_header_records': 0,
        'unknown_kernel_stack_records': 0, 'unknown_user_tail_records': 0, 'malformed_stack_records': 0,
        'comm_counts': Counter(), 'candidate_counts': Counter({key: 0 for key in CANDIDATES}),
        'candidate_counts_by_comm': {}, 'examples': {key: [] for key in CANDIDATES}} for window in windows]
    pending, digest, byte_count, line_number = None, hashlib.sha256(), 0, 0

    def issue(code, text=''):
        issues[code] += 1
        if len(issue_examples) < 20:
            issue_examples.append({'code': code, 'line': line_number, 'text': text[:300]})

    def comm_key(value, mapping):
        return value if value in mapping or len(mapping) < MAX_COMMS else '__OTHER_COMM_LIMIT__'

    def finish():
        nonlocal pending
        if pending is None:
            return
        row, pending = pending, None
        counters['recognized_headers'] += 1
        stamp = row['timestamp_ns']
        index = bisect_right(starts, stamp) - 1
        target = results[index] if index >= 0 and stamp <= windows[index]['end_ns'] else None
        # perf pid is the TGID; prev_pid identifies the switching thread (TID).
        valid = row['tid'] == row['prev_pid'] and row['pid'] > 0 and row['tid'] > 0 and row['mode'] == 'K' and row['state'] == 'D'
        if not valid:
            issue('INVALID_PID_TID_PREV_PID_MODE_OR_D_STATE', row['header'])
        if target is None:
            counters['outside_execution_windows'] += 1
            outside_comms[comm_key(row['comm'], outside_comms)] += 1
            return
        target['records'] += 1
        target['comm_counts'][comm_key(row['comm'], target['comm_counts'])] += 1
        if not valid:
            target['invalid_header_records'] += 1
            return
        target['valid_d_records'] += 1
        kernel = [frame for frame in row['frames'] if frame['dso'] == '[kernel.kallsyms]']
        unknown = lambda frame: frame['symbol'] in ('[unknown]', 'unknown', '??') or bool(re.fullmatch(r'(?:0x)?[0-9a-fA-F]+', frame['symbol']))
        if not kernel or any(unknown(frame) for frame in kernel):
            target['unknown_kernel_stack_records'] += 1
        if any(unknown(frame) for frame in row['frames'] if frame not in kernel):
            target['unknown_user_tail_records'] += 1
        if row['malformed']:
            target['malformed_stack_records'] += 1
            return
        labels = candidates(kernel)
        key = comm_key(row['comm'], target['candidate_counts_by_comm'])
        by_comm = target['candidate_counts_by_comm'].setdefault(key, Counter({label: 0 for label in CANDIDATES}))
        for label in labels:
            target['candidate_counts'][label] += 1
            by_comm[label] += 1
            if len(target['examples'][label]) < MAX_EXAMPLES:
                target['examples'][label].append({key: row[key] for key in ('line', 'timestamp_ns', 'pid', 'tid', 'prev_pid', 'comm', 'header', 'frames')})

    long_line = False
    while True:
        raw = stream.readline(MAX_LINE + 1)
        if not raw:
            break
        digest.update(raw); byte_count += len(raw)
        if byte_count > MAX_BYTES:
            raise ValueError('raw stream exceeded 1 GiB while reading')
        line_number += 1
        if long_line or len(raw) > MAX_LINE:
            if not long_line:
                finish(); issue('LINE_SIZE_LIMIT_EXCEEDED')
            long_line = not raw.endswith(b'\n')
            continue
        try:
            text = raw.decode('utf-8').rstrip('\r\n')
        except UnicodeDecodeError:
            finish(); issue('INVALID_UTF8_RECORD')
            continue
        match = HEADER.fullmatch(text)
        if match:
            finish()
            pid, tid, mode, seconds, fraction, comm, prev_pid, _, state, _, _, _ = match.groups()
            pending = {'pid': int(pid), 'tid': int(tid), 'mode': mode, 'prev_pid': int(prev_pid), 'state': state,
                'timestamp_ns': int(seconds) * 10 ** 9 + int(fraction.ljust(9, '0')), 'comm': comm,
                'header': text, 'line': line_number, 'frames': [], 'malformed': False}
        elif not text.strip():
            finish()
        elif 'LOST' in text.upper() and ('PERF_RECORD' in text.upper() or 'LOST ' in text.upper()):
            finish(); counters['lost_record_lines'] += 1; issue('REPORTED_LOST_RECORD', text)
        elif text.lstrip().startswith('#'):
            continue
        elif HEADER_LIKE.match(text):
            finish(); counters['unparsed_headers'] += 1; issue('UNPARSED_SCHED_HEADER', text)
        elif pending is None:
            counters['orphan_lines'] += 1; issue('ORPHAN_OR_UNPARSED_LINE', text)
        else:
            frame = FRAME.fullmatch(text)
            if frame and len(pending['frames']) < MAX_FRAMES:
                pending['frames'].append(dict(zip(('ip', 'symbol', 'dso'), frame.groups())))
            else:
                if not pending['malformed']:
                    issue('STACK_LIMIT_OR_EXPLICIT_UNWIND_FAILURE' if frame or BAD_STACK.search(text) else 'UNPARSED_STACK_FRAME', text)
                pending['malformed'] = True
    finish()
    actual_sha = digest.hexdigest()
    if byte_count != expected_bytes or actual_sha != expected_sha256:
        raise ValueError('stream bytes/SHA256 differ from original export receipt; do not trust derived candidates')
    return {'schema_version': 1, 'status': 'INCOMPLETE' if issues else 'OBSERVED_D_STATE_STACK_CANDIDATES_ONLY',
        'stream_binding': {'status': 'MATCHED_SINGLE_PASS_BYTES_AND_SHA256', 'bytes': byte_count, 'sha256': actual_sha},
        'counts': dict(counters), 'outside_window_comm_counts': dict(outside_comms), 'windows': results,
        'issues': dict(issues), 'issue_examples': issue_examples,
        'boundary_policy': 'CLOSED_RELEASE_END; integer CLOCK_MONOTONIC nanoseconds, no float interpolation',
        'limits': ['Each record is one D-state switch-out, not a CPU sample, elapsed wait interval or percentage of wall time.',
            'Candidate counts are independent and can overlap; do not sum them or convert their frequency into wait duration.',
            'folio_wait_bit_common under filemap_read establishes a blocked read/page-cache stack candidate, not whether the cause is disk bandwidth, a page lock, refill coordination or a virtual-device queue.',
            'direct block and io_schedule contexts are not physical SSD service-time or saturation evidence.',
            'Window filtering excludes preflight/dd outside execution; user FP tails may be unresolved while selected kernel frames remain positive evidence.',
            'The registered parent cgroup includes its descendants and launchers; comm is a recorded name, not independent executable authentication or per-Agent causal attribution.',
            'No reported lost line does not establish exhaustive collection or zero loss. Raw producer health and warnings remain separate.',
            'Only exported text is hash-bound here; perf.data is not replayed, nor is the kernel/collector independently authenticated.']}


def analyze_diagnosis(directory):
    root = Path(directory).resolve(strict=True)
    diagnosis, receipt, windows, sources, warnings = bound_inputs(root)
    path = root / receipt['path']
    if path.is_symlink() or not path.is_file() or path.stat().st_size != receipt['bytes']:
        raise ValueError('bounded regular raw text matching declared bytes required')
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        result = parse_stream(stream, windows, receipt['bytes'], receipt['sha256'])
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('raw stream changed during analysis')
    result.update(diagnosis_directory=str(root), boot_id=diagnosis['boot_id'], cgroup=diagnosis['cgroup'], sources=sources,
        raw_diagnosis_status=diagnosis.get('status'), raw_diagnosis_issues=diagnosis.get('issues'),
        raw_collector_status=diagnosis['collector'].get('status'), raw_collector_issues=diagnosis['collector'].get('issues'),
        export_warnings=warnings, collector_health='NOT_ESTABLISHED_BY_TEXT_PARSING; zero reported losses is not exhaustiveness',
        analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnosis', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='fresh JSON outside raw diagnosis; never overwritten')
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error('fresh output required')
    root, output = args.diagnosis.resolve(strict=True), args.output.resolve()
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        parser.error('output must be outside raw diagnosis')
    result = analyze_diagnosis(root)
    with output.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'status': result['status'], 'output': str(output), 'counts': result['counts']}))


if __name__ == '__main__':
    main()
