#!/usr/bin/env python3
"""Export selected, replayed VFS reads; this does not verify raw evidence.

Each calls[].files[].read is one selected VFS attempt, including EOF/errors.
Repeated segment annotations are deliberately ignored. Output is a new directory
and includes excluded records rather than guessing cross-window byte allocation.
Unassigned threads have a separate complete CSV, never an invented Agent/tool.
"""
import argparse
from collections import Counter, defaultdict
import csv
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import sys


MAX_BYTES = 64 * 1024 ** 2
GOOD_PATH = 'RECONSTRUCTED_WITHIN_SELECTED_MODEL'
PATH_QUALITIES = frozenset(('KERNEL_D_PATH', 'KERNEL_PATH_AT_LSM_PERMISSION_CANDIDATE',
    'KERNEL_PATH_AT_PERMISSION_CANDIDATE'))
READ_COLUMNS = ('read_record_id', 'run_id', 'boot_id', 'agent_id', 'task_id', 'tool_call_id',
    'root_key', 'thread_key', 'tid', 'tgid', 'thread_birth_ns', 'process_birth_ns',
    'call_id', 'syscall_nr', 'syscall_name', 'syscall_pairing', 'syscall_start_ns', 'syscall_end_ns',
    'scope_status', 'object_key', 'identity_status', 'mount_id', 'device', 'inode', 'generation',
    'generation_valid', 'path', 'path_quality', 'path_candidates_json', 'path_raw_hex',
    'start_ns', 'end_ns', 'duration_ns', 'requested_bytes', 'actual_returned_bytes',
    'signed_result', 'read_outcome', 'bytes_status')
UNASSIGNED_READ_COLUMNS = READ_COLUMNS + ('attribution_status', 'declared_agent_id',
    'declared_task_id', 'declared_tool_call_id', 'run_window_status', 'read_evidence_json')
FILE_COLUMNS = ('run_id', 'boot_id', 'agent_id', 'task_id', 'tool_call_id', 'root_key',
    'object_key', 'identity_status', 'mount_id', 'device', 'inode', 'generation',
    'path_candidates_json', 'path_quality_candidates_json', 'path_observation_status',
    'read_calls', 'unique_syscall_calls', 'known_unique_syscall_calls', 'unknown_call_id_records',
    'positive_calls', 'eof_calls', 'error_calls',
    'unknown_outcome_calls', 'unknown_bytes_calls', 'requested_bytes_known_sum',
    'unknown_requested_bytes_calls', 'actual_returned_bytes', 'actual_returned_bytes_known_sum',
    'elapsed_sum_ns', 'elapsed_mean_ns', 'elapsed_max_ns', 'timing_scope')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def interval(value):
    if not isinstance(value, dict):
        return None
    begin, end = value.get('start_ns', value.get('begin_ns')), value.get('end_ns')
    return (begin, end) if integer(begin) and integer(end) and begin <= end else None


def object_identity(file):
    if (not all(integer(file.get(name), 1) for name in ('mount_id', 'inode'))
            or not all(integer(file.get(name)) for name in ('device', 'generation'))):
        return None
    return tuple(file[name] for name in ('mount_id', 'device', 'inode', 'generation'))


def call_identity(call):
    value = call.get('call_id')
    return value if integer(value, 1) or (isinstance(value, str) and value) else None


def json_cell(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def artifact(path):
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return {'bytes': size, 'sha256': digest.hexdigest()}


def path_candidates(file):
    paths = {file['path']} if isinstance(file.get('path'), str) and file['path'] else set()
    observed = file.get('observed_paths', [])
    if isinstance(observed, list):
        paths.update(item['path'] for item in observed if isinstance(item, dict)
                     and isinstance(item.get('path'), str) and item['path'])
    return sorted(paths)


def ownership(report):
    tools, threads = report.get('tools'), report.get('threads')
    require(isinstance(tools, list) and isinstance(threads, list), 'explicit tools/threads lists required')
    require(all(isinstance(thread, dict) and isinstance(thread.get('key'), str) and thread['key'] for thread in threads),
            'nonempty stable thread keys required')
    index = {thread['key']: thread for thread in threads}
    require(len(index) == len(threads), 'duplicate stable thread key')
    require(all(isinstance(tool, dict) and isinstance(tool.get('tool_call_id'), str)
                and tool['tool_call_id'] and interval(tool) for tool in tools), 'valid tool identities/spans required')
    require(len({tool['tool_call_id'] for tool in tools}) == len(tools), 'globally unique tool_call_id required')
    roots, root_owners = {}, defaultdict(list)
    for tool in tools:
        root = tool.get('root_key')
        if root is None and isinstance(tool.get('root'), dict):
            declared = tool['root']
            birth = declared.get('birth_ns', declared.get('thread_birth_ns'))
            candidates = [thread['key'] for thread in threads if integer(birth, 1)
                and thread.get('tid') == declared.get('tid') and thread.get('birth_ns') == birth]
            root = candidates[0] if len(candidates) == 1 else None
        roots[tool['tool_call_id']] = root
        if root is not None:
            root_owners[root].append(tool['tool_call_id'])
    output, assigned, issues = [], set(), []
    for tool in tools:
        tool_id, agent, root = tool['tool_call_id'], tool.get('agent_id'), roots[tool['tool_call_id']]
        node = index.get(root)
        valid_root = node is not None and root_owners[root] == [tool_id] and node.get('agent_id') == agent and node.get('tool_call_id') == tool_id
        if not valid_root:
            issues.append({'kind': 'UNRESOLVED_OR_CONFLICTING_TOOL_ROOT', 'tool_call_id': tool_id})
        owned = []
        for thread in threads:
            if thread.get('tool_call_id') != tool_id or thread.get('agent_id') != agent:
                continue
            current, seen, valid = thread['key'], set(), False
            while valid_root and current in index and current not in seen:
                if current == root:
                    valid = True
                    break
                if current in root_owners:
                    break
                seen.add(current)
                current = index[current].get('parent_key')
            if valid:
                owned.append(thread)
                assigned.add(thread['key'])
            else:
                issues.append({'kind': 'TAGGED_THREAD_WITHOUT_VERIFIED_ROOT_ANCESTRY',
                    'thread_key': thread['key'], 'tool_call_id': tool_id})
        output.append((tool, root, owned))
    return output, assigned, issues


def read_row(tool, root, thread, call, file, sequence, run):
    read = file['read']
    timing, window = interval(read), interval(tool)
    if timing is None:
        scope = 'UNRESOLVED_READ_INTERVAL'
    elif window[0] <= timing[0] <= timing[1] <= window[1]:
        scope = 'WITHIN_TOOL_EXECUTION_WINDOW'
    elif timing[0] < window[1] and timing[1] > window[0]:
        scope = 'CROSSES_TOOL_WINDOW_UNALLOCATED'
    else:
        scope = 'OUTSIDE_TOOL_EXECUTION_WINDOW'
    record_id, identity = 'read-{:09d}'.format(sequence), object_identity(file)
    key = 'OBJECT:' + '/'.join(str(value) for value in identity) if identity else 'UNRESOLVED:' + record_id
    result, returned, requested = read.get('result'), read.get('returned_bytes'), read.get('requested_bytes')
    actual = returned if integer(returned) else None
    signed = result if type(result) is int else None
    known_bytes = None
    if signed is not None and signed < 0 and (returned is None or (integer(returned) and returned == 0)):
        outcome, bytes_status, known_bytes = 'ERROR', 'FAILED_NO_POSITIVE_RETURN', 0
    elif signed is not None and signed >= 0 and actual == signed:
        outcome, bytes_status, known_bytes = ('EOF' if signed == 0 else 'POSITIVE'), 'CONSISTENT_SIGNED_VFS_RETURN', actual
    else:
        outcome = 'ERROR' if signed is not None and signed < 0 else 'UNKNOWN'
        bytes_status = 'UNKNOWN_OR_INCONSISTENT_RETURN'
    if integer(requested) and actual is not None and actual > requested:
        bytes_status, known_bytes = 'RETURN_EXCEEDS_REQUEST', None
        if outcome != 'ERROR':
            outcome = 'UNKNOWN'
    row = {'read_record_id': record_id, 'run_id': run['run_id'], 'boot_id': run['boot_id'],
        'agent_id': tool.get('agent_id'), 'task_id': tool.get('task_id'), 'tool_call_id': tool['tool_call_id'],
        'root_key': root, 'thread_key': thread['key'], 'tid': thread.get('tid'), 'tgid': thread.get('tgid'),
        'thread_birth_ns': thread.get('birth_ns'), 'process_birth_ns': thread.get('process_birth_ns'),
        'call_id': call_identity(call), 'syscall_nr': call.get('nr'), 'syscall_name': call.get('name'),
        'syscall_pairing': call.get('pairing'), 'syscall_start_ns': call.get('start_ns'), 'syscall_end_ns': call.get('end_ns'),
        'scope_status': scope, 'object_key': key,
        'identity_status': 'VALID_BOOT_LOCAL_IDENTITY' if identity else 'UNRESOLVED',
        'generation_valid': file.get('generation_valid'),
        'path': file.get('path') if isinstance(file.get('path'), str) else None,
        'path_quality': file.get('path_quality', file.get('quality')), 'path_candidates_json': json_cell(path_candidates(file)),
        'path_raw_hex': file.get('path_raw_hex'),
        'start_ns': read.get('start_ns') if integer(read.get('start_ns')) else None,
        'end_ns': read.get('end_ns') if integer(read.get('end_ns')) else None,
        'duration_ns': timing[1] - timing[0] if timing else None,
        'requested_bytes': requested if integer(requested) else None,
        'actual_returned_bytes': actual, 'signed_result': signed, 'read_outcome': outcome, 'bytes_status': bytes_status}
    row.update({name: file.get(name) for name in ('mount_id', 'device', 'inode', 'generation')})
    return row, known_bytes


def export_report(report, output, source_report=None):
    require(isinstance(report, dict) and report.get('schema_version', 1) == 1, 'report schema v1 required')
    run = report.get('run')
    require(isinstance(run, dict) and all(isinstance(run.get(key), str) and run[key] for key in ('run_id', 'boot_id')),
            'run_id and boot_id required for object scope')
    run_window = interval(run)
    require(run_window is not None and run_window[0] < run_window[1], 'ordered positive run window required')
    groups, assigned, issues = ownership(report)
    require(all(run_window[0] <= interval(tool)[0] <= interval(tool)[1] <= run_window[1] for tool, _, _ in groups),
            'tool execution windows must be within declared run')
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'fresh output directory required; never overwrite')
    cp = report.get('critical_path', {})
    if not isinstance(cp, dict) or cp.get('status') != GOOD_PATH:
        issues.append({'kind': 'SOURCE_TIMELINE_COVERAGE_NOT_RECONSTRUCTED'})
    health = report.get('health', {})
    if isinstance(health, dict) and str(health.get('status', '')).upper() in ('INCOMPLETE', 'PARTIAL', 'UNKNOWN', 'UNRESOLVED', 'FAILED'):
        issues.append({'kind': 'SOURCE_HEALTH_NOT_COMPLETE'})
    selected_findings = [finding for finding in report.get('findings', []) if finding.get('thread') in assigned
        or finding.get('tool_call_id') in {tool['tool_call_id'] for tool, _, _ in groups}
        or (not finding.get('thread') and not finding.get('tool_call_id'))]
    if selected_findings:
        issues.append({'kind': 'SOURCE_FINDINGS_AFFECT_SELECTED_TOOLS', 'findings': selected_findings})
    output.mkdir(mode=0o700)
    counts, aggregates = Counter(), {}
    counts['report_read_records'] = sum(isinstance(file, dict) and isinstance(file.get('read'), dict)
        for thread in report['threads'] for call in thread.get('calls', []) for file in call.get('files', []))
    with (output / 'reads.csv').open('x', encoding='utf-8', newline='') as reads_stream, (output / 'excluded-reads.csv').open('x', encoding='utf-8', newline='') as excluded_stream:
        writer, excluded_writer = csv.DictWriter(reads_stream, READ_COLUMNS), csv.DictWriter(excluded_stream, READ_COLUMNS)
        writer.writeheader()
        excluded_writer.writeheader()
        for tool, root, threads in groups:
            for thread in threads:
                for call in thread.get('calls', []):
                    for file in call.get('files', []):
                        if not isinstance(file, dict) or not isinstance(file.get('read'), dict):
                            continue
                        counts['owned_read_records_seen'] += 1
                        row, known_bytes = read_row(tool, root, thread, call, file, counts['owned_read_records_seen'], run)
                        counts[row['scope_status']] += 1
                        if row['scope_status'] != 'WITHIN_TOOL_EXECUTION_WINDOW':
                            excluded_writer.writerow(row)
                            continue
                        writer.writerow(row)
                        if row['identity_status'] == 'UNRESOLVED':
                            counts['unresolved_identity_records'] += 1
                        if not row['path'] or row['path_quality'] not in PATH_QUALITIES:
                            counts['unresolved_path_records'] += 1
                        if known_bytes is None:
                            counts['unknown_bytes_records'] += 1
                        if row['requested_bytes'] is None:
                            counts['unknown_request_records'] += 1
                        if row['call_id'] is None:
                            counts['unknown_call_id_records'] += 1
                        group_key = row['boot_id'], row['agent_id'], row['tool_call_id'], row['object_key']
                        if group_key not in aggregates:
                            aggregates[group_key] = {'base': {name: row[name] for name in ('run_id', 'boot_id', 'agent_id',
                                'task_id', 'tool_call_id', 'root_key', 'object_key', 'identity_status', 'mount_id', 'device', 'inode', 'generation')},
                                'counts': Counter(), 'paths': set(), 'qualities': set(), 'calls': set(), 'max_elapsed': 0}
                        aggregate = aggregates[group_key]
                        aggregate['paths'].update(path_candidates(file))
                        aggregate['qualities'].add(str(row['path_quality']) if row['path_quality'] is not None else 'UNKNOWN')
                        if row['call_id'] is not None:
                            aggregate['calls'].add((thread['key'], row['call_id']))
                        totals = aggregate['counts']
                        totals['read_calls'] += 1
                        totals['unknown_call_id_records'] += row['call_id'] is None
                        totals[{'POSITIVE': 'positive_calls', 'EOF': 'eof_calls', 'ERROR': 'error_calls'}.get(row['read_outcome'], 'unknown_outcome_calls')] += 1
                        totals['unknown_bytes_calls'] += known_bytes is None
                        totals['actual_returned_bytes_known_sum'] += known_bytes if known_bytes is not None else 0
                        totals['unknown_requested_bytes_calls'] += row['requested_bytes'] is None
                        totals['requested_bytes_known_sum'] += row['requested_bytes'] or 0
                        totals['elapsed_sum_ns'] += row['duration_ns']
                        aggregate['max_elapsed'] = max(aggregate['max_elapsed'], row['duration_ns'])
    with (output / 'files.csv').open('x', encoding='utf-8', newline='') as files_stream:
        writer = csv.DictWriter(files_stream, FILE_COLUMNS)
        writer.writeheader()
        for aggregate in aggregates.values():
            totals, paths = aggregate['counts'], sorted(aggregate['paths'])
            row = dict(aggregate['base'])
            row.update({key: totals[key] for key in ('read_calls', 'positive_calls', 'eof_calls', 'error_calls',
                'unknown_outcome_calls', 'unknown_bytes_calls', 'requested_bytes_known_sum', 'unknown_requested_bytes_calls',
                'actual_returned_bytes_known_sum', 'elapsed_sum_ns', 'unknown_call_id_records')})
            row.update(unique_syscall_calls=None if totals['unknown_call_id_records'] else len(aggregate['calls']),
                known_unique_syscall_calls=len(aggregate['calls']), path_candidates_json=json_cell(paths),
                path_quality_candidates_json=json_cell(sorted(aggregate['qualities'])),
                path_observation_status='MULTIPLE_OBSERVED_CANDIDATES' if len(paths) > 1 else 'SINGLE_OBSERVED_CANDIDATE' if paths else 'NOT_CAPTURED',
                actual_returned_bytes=None if totals['unknown_bytes_calls'] else totals['actual_returned_bytes_known_sum'],
                elapsed_mean_ns=format(Decimal(totals['elapsed_sum_ns']) / Decimal(totals['read_calls']), 'f'),
                elapsed_max_ns=aggregate['max_elapsed'], timing_scope='PARALLEL_CUMULATIVE_NOT_WALL_OR_DEVICE_SERVICE_TIME')
            writer.writerow(row)
    # A cgroup/clock match does not give an unassigned thread an Agent identity.
    # Keep every report read, including invalid/unknown/out-of-run intervals,
    # in a separate table without contributing to selected per-tool aggregates.
    unassigned = [thread for thread in report['threads'] if thread['key'] not in assigned]
    with (output / 'unassigned-reads.csv').open('x', encoding='utf-8', newline='') as unassigned_stream:
        writer = csv.DictWriter(unassigned_stream, UNASSIGNED_READ_COLUMNS)
        writer.writeheader()
        for thread in unassigned:
            for call in thread.get('calls', []):
                for file in call.get('files', []):
                    if not isinstance(file, dict) or not isinstance(file.get('read'), dict):
                        continue
                    counts['unassigned_read_records'] += 1
                    row, _known_bytes = read_row(dict(run, tool_call_id=None), None, thread, call, file,
                        counts['owned_read_records_seen'] + counts['unassigned_read_records'], run)
                    run_scope = {'WITHIN_TOOL_EXECUTION_WINDOW': 'WITHIN_DECLARED_RUN_WINDOW',
                        'CROSSES_TOOL_WINDOW_UNALLOCATED': 'CROSSES_RUN_WINDOW_UNALLOCATED',
                        'OUTSIDE_TOOL_EXECUTION_WINDOW': 'OUTSIDE_DECLARED_RUN_WINDOW',
                        'UNRESOLVED_READ_INTERVAL': 'UNRESOLVED_READ_INTERVAL'}[row['scope_status']]
                    row.update(agent_id=None, task_id=None, tool_call_id=None, root_key=None,
                        scope_status='UNASSIGNED_NOT_ATTRIBUTED', attribution_status='UNASSIGNED_NOT_ATTRIBUTED',
                        declared_agent_id=thread.get('agent_id'), declared_task_id=thread.get('task_id'),
                        declared_tool_call_id=thread.get('tool_call_id'), run_window_status=run_scope,
                        read_evidence_json=json_cell(file))
                    writer.writerow(row)
    counts['excluded_owned_read_records'] = counts['owned_read_records_seen'] - counts['WITHIN_TOOL_EXECUTION_WINDOW']
    counts['partitioned_read_records'] = counts['WITHIN_TOOL_EXECUTION_WINDOW'] + counts['excluded_owned_read_records'] + counts['unassigned_read_records']
    require(counts['partitioned_read_records'] == counts['report_read_records'],
            'selected + excluded + unassigned read partition differs from report; no complete export receipt')
    for key in ('CROSSES_TOOL_WINDOW_UNALLOCATED', 'UNRESOLVED_READ_INTERVAL', 'unresolved_identity_records',
                'unresolved_path_records', 'unknown_bytes_records', 'unknown_request_records', 'unknown_call_id_records'):
        if counts[key]:
            issues.append({'kind': key, 'records': counts[key]})
    if not groups:
        issues.append({'kind': 'NO_SELECTED_TOOLS'})
    receipt = {'schema_version': 1, 'status': 'EXPORTED_WITH_DECLARED_GAPS' if issues else 'COMPLETE_FOR_SELECTED_REPORT_RECORDS',
        'authority': 'REPORT_DERIVED_EXPORT_NOT_RAW_VERIFICATION', 'raw_verification_status': 'NOT_PERFORMED_BY_EXPORTER',
        'source_report': source_report, 'run_id': run['run_id'], 'boot_id': run['boot_id'],
        'counts': {key: counts[key] for key in ('report_read_records', 'partitioned_read_records',
            'owned_read_records_seen', 'excluded_owned_read_records', 'unassigned_read_records', 'WITHIN_TOOL_EXECUTION_WINDOW',
            'CROSSES_TOOL_WINDOW_UNALLOCATED', 'UNRESOLVED_READ_INTERVAL', 'OUTSIDE_TOOL_EXECUTION_WINDOW',
            'unresolved_identity_records', 'unresolved_path_records', 'unknown_bytes_records', 'unknown_request_records',
            'unknown_call_id_records')},
        'tools': [{'agent_id': tool.get('agent_id'), 'tool_call_id': tool['tool_call_id'], 'root_key': root,
            'begin_ns': interval(tool)[0], 'end_ns': interval(tool)[1], 'owned_threads': len(threads)}
            for tool, root, threads in groups],
        'file_rows': len(aggregates), 'valid_identity_file_rows': sum(aggregate['base']['identity_status'] != 'UNRESOLVED' for aggregate in aggregates.values()),
        'unresolved_identity_file_rows': sum(aggregate['base']['identity_status'] == 'UNRESOLVED' for aggregate in aggregates.values()),
        'unassigned_thread_keys': [thread['key'] for thread in unassigned],
        'read_partition_status': 'ALL_REPORT_READ_RECORDS_EXPORTED_ONCE',
        'whole_capture_attribution_status': 'UNASSIGNED_EVENTS_PRESENT' if unassigned else 'ALL_REPORT_THREADS_ASSIGNED_TO_SELECTED_TOOLS',
        'issues': issues,
        'scope': {'reads': 'ONE_IN_WINDOW_calls[].files[].read_PER_ROW; NOT_SEGMENT_ANNOTATIONS; VFS_ATTEMPTS_NOT_UNIQUE_SYSCALLS',
            'excluded': 'CROSSING_OR_UNKNOWN_INTERVALS_ARE_NOT_ALLOCATED_TO_WINDOW; OUTSIDE_READS_ARE_OUT_OF_SCOPE',
            'unassigned': 'ALL_UNASSIGNED_THREAD_calls[].files[].read_PRESERVED_WITHOUT_AGENT_TOOL_OR_ROOT_ASSIGNMENT; DECLARED_TAGS_ARE_NOT_VERIFIED_OWNERSHIP; ORIGINAL_FILE_READ_FIELDS_RETAINED_IN_read_evidence_json',
            'partition': 'ALL_REPORT_READS=SELECTED_IN_WINDOW+EXCLUDED_OWNED+UNASSIGNED; NO_ABI_UNSELECTED_INTERFACE_COMPLETENESS_CLAIM',
            'bytes': 'ACTUAL_RETURNED_BYTES_NOT_REQUESTED; RAW_NULL_REMAINS_EMPTY; NEGATIVE_RETURN_IS_ERROR_AND_ZERO_POSITIVE_BYTE_CONTRIBUTION',
            'objects': 'BOOT_AGENT_TOOL_MOUNT_DEVICE_INODE_GENERATION; UNRESOLVED_EACH_RECORD_SEPARATE; NO_GLOBAL_LIFETIME_PROOF_WITH_GENERATION_ZERO',
            'paths': 'OBSERVED_CANDIDATE_SET_NOT_CANONICAL_PATH_OR_RENAME_PROOF',
            'time': 'SUM_MEAN_MAX_SELECTED_VFS_ELAPSED; PARALLEL_INTERVALS_CAN_OVERLAP; NOT_WALL_OR_DEVICE_SERVICE_TIME',
            'csv': 'UTF8_RFC4180_QUOTING; EXACT_PATH_TEXT; IMPORT_AS_TEXT_IN_SPREADSHEETS_TO_AVOID_FORMULA_EVALUATION',
            'memory': 'INPUT_BOUNDED_64MIB; STREAMED_READ_ROWS; AGGREGATE_MEMORY_SCALES_WITH_SELECTED_OBJECTS'},
        'artifacts': {name: artifact(output / name) for name in ('reads.csv', 'files.csv', 'excluded-reads.csv', 'unassigned-reads.csv')}}
    with (output / 'receipt.json').open('x', encoding='utf-8') as stream:
        json.dump(receipt, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new directory, never overwritten')
    args = parser.parse_args(argv)
    require(args.report.is_file() and not args.report.is_symlink() and args.report.stat().st_size <= MAX_BYTES,
            'bounded regular non-symlink report required (64 MiB maximum)')
    raw = args.report.read_bytes()
    require(len(raw) <= MAX_BYTES, 'report grew beyond limit')
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    def invalid(value):
        raise ValueError('nonfinite JSON number: ' + value)
    report = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    receipt = export_report(report, args.output, {'path': str(args.report.absolute()), 'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest()})
    print('逐次VFS读取与逐文件聚合已导出：' + str(args.output.absolute()))
    print('状态={}；窗口内读取={}；对象行={}；跨窗={}；时间未知={}。'.format(receipt['status'],
        receipt['counts'].get('WITHIN_TOOL_EXECUTION_WINDOW', 0), receipt['file_rows'],
        receipt['counts'].get('CROSSES_TOOL_WINDOW_UNALLOCATED', 0), receipt['counts'].get('UNRESOLVED_READ_INTERVAL', 0)))
    print('reads.csv=逐次实际读取；files.csv=逐对象聚合；excluded-reads.csv=未分配到窗口的证据；receipt.json=范围与SHA。')
    print('unassigned-reads.csv=未归属线程的全部读取，不猜Agent/tool；全报告读取={} = 窗口内{} + 窗外/跨窗/未知{} + 未归属{}。'.format(
        receipt['counts']['report_read_records'], receipt['counts']['WITHIN_TOOL_EXECUTION_WINDOW'],
        receipt['counts']['excluded_owned_read_records'], receipt['counts']['unassigned_read_records']))
    print('实际返回bytes不等于请求bytes；失败与未知分别保留。并行累计读取时长不能当墙钟或磁盘耗时；本导出不替代原始证据验证。')
    print('CSV保留真实路径文本；用电子表格打开时请按文本导入，避免路径被解释为公式。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
