#!/usr/bin/env python3
"""Small, conservative Chinese summaries of an already replayed timeline report.

This is a presentation/recomputation layer, not another raw-event verifier.
Read records come only from calls[].files[].read, never again from repeated
state annotations. Parallel elapsed sums are never added to task wall time.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys


MAX_BYTES = 64 * 1024 ** 2
STATES = ('ONCPU', 'RUNNABLE', 'SLEEP', 'WAKING', 'NEWBORN', 'RUNTIME_RETURN', 'UNKNOWN')
READ_NAMES = frozenset(('read', 'pread64', 'readv', 'preadv', 'preadv2'))
PATH_QUALITIES = frozenset(('KERNEL_D_PATH', 'KERNEL_PATH_AT_LSM_PERMISSION_CANDIDATE',
    'KERNEL_PATH_AT_PERMISSION_CANDIDATE'))
GOOD_PATH = 'RECONSTRUCTED_WITHIN_SELECTED_MODEL'
GOOD_SELECTED_TOOL = 'COMPLETE_WITHIN_SELECTED_TOOL_SCOPE'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value, minimum=0):
    return type(value) is int and value >= minimum


def span(value):
    if not isinstance(value, dict):
        return None
    begin, end = value.get('begin_ns', value.get('start_ns')), value.get('end_ns')
    return (begin, end) if number(begin) and number(end) and begin <= end else None


def tool_timing(tool, run):
    begin, end = span(tool)
    invocation = tool.get('invocation_ns')
    run_begin = run.get('begin_ns') if isinstance(run, dict) else None
    recorded = number(run_begin) and number(invocation) and run_begin <= invocation <= begin
    return {'execution_window_ns': end - begin,
        'tool_call_wall_ns': end - invocation if recorded else None,
        'dispatch_prelude_ns': begin - invocation if recorded else None,
        'invocation_status': 'RECORDED' if recorded else 'NOT_RECORDED' if invocation is None else 'INVALID_INVOCATION_BOUNDARY',
        'dispatch_scope': 'DOCKER_EXEC_OR_DIRECT_LAUNCH_AND_OBSERVER_REGISTRATION_BARRIER; NOT_WORKER_CPU_OR_IO_TIME',
        'completion_path_scope': 'EXECUTION_WINDOW_BEGIN_TO_END_ONLY; DISPATCH_PRELUDE_NOT_ADDED_TO_THREAD_STATES'}


def file_key(file):
    if not isinstance(file, dict):
        return None
    if any(not number(file.get(key), 1) for key in ('mount_id', 'inode')):
        return None
    if any(not number(file.get(key)) for key in ('device', 'generation')):
        return None
    return tuple(file[key] for key in ('mount_id', 'device', 'inode', 'generation'))


def union_ns(intervals):
    total, right = 0, None
    for begin, end in sorted(intervals):
        if right is None or begin >= right:
            total += end - begin
            right = end
        elif end > right:
            total += end - right
            right = end
    return total


def display_file(file):
    key = file_key(file)
    path = file.get('path') if isinstance(file, dict) else None
    path = path if isinstance(path, str) and path else None
    identity = {name: file.get(name) for name in ('mount_id', 'device', 'inode', 'generation')} if isinstance(file, dict) else {}
    return {'path': path, 'identity': identity, 'identity_valid': key is not None,
        'quality': file.get('path_quality', file.get('quality', 'UNKNOWN')) if isinstance(file, dict) else 'UNKNOWN',
        'display': path if path else 'identity=' + '/'.join(str(value) for value in key) if key else 'UNKNOWN'}


def completion(entry, tool):
    window, issues = span(tool), []
    totals = {state: 0 for state in STATES}
    parts = entry.get('segments', []) if isinstance(entry, dict) else []
    if not isinstance(parts, list):
        parts, issues = [], ['INVALID_COMPLETION_SEGMENTS']
    cursor, unknown_states = window[0], Counter()
    for part in parts:
        interval = span(part)
        if interval is None or interval[0] != cursor or interval[1] > window[1]:
            issues.append('COMPLETION_PATH_NOT_AN_ORDERED_WALL_PARTITION')
            break
        state = part.get('state', 'UNKNOWN')
        if state not in STATES:
            unknown_states[str(state)] += interval[1] - interval[0]
            state = 'UNKNOWN'
        totals[state] += interval[1] - interval[0]
        cursor = interval[1]
    if cursor != window[1]:
        issues.append('COMPLETION_PATH_DOES_NOT_CLOSE_TOOL_WALL')
    if not isinstance(entry, dict):
        issues.append('NO_COMPLETION_PATH_FOR_TOOL')
    declared = entry.get('state_totals_ns') if isinstance(entry, dict) else None
    if isinstance(declared, dict) and any(declared.get(state, 0) != value for state, value in totals.items()):
        issues.append('REPORTED_STATE_TOTALS_DIFFER_FROM_SEGMENTS')
    if isinstance(entry, dict) and number(entry.get('wall_ns')) and entry['wall_ns'] != window[1] - window[0]:
        issues.append('REPORTED_COMPLETION_WALL_DIFFERS_FROM_TOOL_SPAN')
    valid = not issues
    return {'reported_status': entry.get('status', 'UNKNOWN') if isinstance(entry, dict) else 'UNKNOWN',
        'integrity_status': 'PARTITION_RECOMPUTED' if valid else 'INCOMPLETE',
        'state_totals_ns': totals if valid else None,
        'reported_state_totals_ns': declared,
        'unknown_ns': totals['UNKNOWN'] if valid else window[1] - window[0],
        'runtime_return_ns': totals['RUNTIME_RETURN'] if valid else None,
        'newborn_ns': totals['NEWBORN'] if valid else None,
        'waking_ns': totals['WAKING'] if valid else None,
        'unknown_state_ns': dict(unknown_states), 'issues': issues}, parts if valid else []


def summarize_reads(owned, window):
    objects, records, durations = set(), 0, []
    counters = Counter()
    for thread in owned:
        for call in thread.get('calls', []):
            if call.get('name') in READ_NAMES:
                interval = span(call)
                if interval and window[0] <= interval[0] <= interval[1] <= window[1]:
                    counters['selected_read_syscalls'] += 1
            for file in call.get('files', []):
                read = file.get('read') if isinstance(file, dict) else None
                if not isinstance(read, dict):
                    continue
                interval = span(read)
                if interval is None:
                    counters['unresolved_read_intervals'] += 1
                    continue
                if not window[0] <= interval[0] <= interval[1] <= window[1]:
                    counters['outside_or_crossing_tool_span_read_records'] += 1
                    if interval[0] < window[1] and interval[1] > window[0]:
                        counters['crossing_tool_span_read_records'] += 1
                    continue
                records += 1
                durations.append(interval[1] - interval[0])
                key = file_key(file)
                if key is None:
                    counters['unresolved_object_read_records'] += 1
                else:
                    objects.add(key)
                if not isinstance(file.get('path'), str) or not file['path']:
                    counters['read_records_without_path'] += 1
                if file.get('path_quality', file.get('quality')) not in PATH_QUALITIES:
                    counters['unresolved_path_quality_records'] += 1
                result, returned = read.get('result'), read.get('returned_bytes')
                # The raw decoder deliberately leaves returned_bytes null for
                # a negative signed VFS return. This is a known failed read,
                # not unknown success or an unobserved EOF. Count zero positive
                # returned bytes while retaining the error separately.
                if type(result) is int and result < 0 and returned is None:
                    returned = 0
                    counters['failed_reads_with_no_positive_return'] += 1
                if number(returned) and (type(result) is not int or returned == max(0, result)):
                    counters['returned_bytes_known_sum'] += returned
                    if type(result) is int:
                        counters['error_reads' if result < 0 else 'zero_reads' if result == 0 else 'positive_reads'] += 1
                    else:
                        counters['read_records_without_signed_result'] += 1
                else:
                    counters['unknown_or_inconsistent_returned_bytes'] += 1
                requested = read.get('requested_bytes')
                if number(requested):
                    counters['requested_bytes_known_sum'] += requested
                    if number(returned) and returned > requested:
                        counters['returned_exceeds_requested_records'] += 1
                else:
                    counters['unknown_requested_bytes_records'] += 1
    unknown = counters['unknown_or_inconsistent_returned_bytes']
    output = {key: counters[key] for key in (
        'selected_read_syscalls', 'positive_reads', 'zero_reads', 'error_reads',
        'returned_bytes_known_sum', 'unknown_or_inconsistent_returned_bytes',
        'requested_bytes_known_sum', 'unknown_requested_bytes_records', 'returned_exceeds_requested_records',
        'unresolved_object_read_records', 'read_records_without_path', 'unresolved_path_quality_records',
        'read_records_without_signed_result', 'failed_reads_with_no_positive_return',
        'unresolved_read_intervals', 'outside_or_crossing_tool_span_read_records', 'crossing_tool_span_read_records')}
    output.update(read_calls=records, returned_bytes=None if unknown else counters['returned_bytes_known_sum'],
        selected_vfs_object_count=len(objects),
        read_elapsed_known_sum_ns=sum(durations),
        read_elapsed_sum_ns=None if counters['unresolved_read_intervals'] else sum(durations),
        read_elapsed_mean_ns=sum(durations) / len(durations) if durations else None,
        read_elapsed_max_ns=max(durations) if durations else None,
        timing_scope='SUM_OF_SELECTED_IN_WINDOW_VFS_READ_ELAPSED_INTERVALS; PARALLEL_INTERVALS_OVERLAP; NOT_WALL_OR_DEVICE_SERVICE_TIME',
        count_scope='calls[].files[].read RECORDS_ONLY; NO_RECOUNT_OF_SEGMENT_ANNOTATIONS; NOT_ALL_FILE_INTERFACES_OR_SOURCE_FILES',
        return_scope='SUM_OF_NONNEGATIVE_VFS_RETURNS; NEGATIVE_SIGNED_RETURNS_COUNT_AS_ERRORS_WITH_ZERO_POSITIVE_RETURNED_BYTES',
        object_identity_scope='BOOT_LOCAL_MOUNT_DEVICE_INODE_GENERATION; INCLUDES_SELECTED_SPECIAL_FILES; GENERATION_ZERO_HAS_NO_GLOBAL_LIFETIME_PROOF')
    return output


def summarize_waits(parts, thread_index, window):
    file_intervals, annotated, waits = [], [], []
    for part in parts:
        interval = span(part)
        if interval is None:
            continue
        begin, end = max(window[0], interval[0]), min(window[1], interval[1])
        if end <= begin:
            continue
        files = part.get('files', [])
        if part.get('state') == 'SLEEP' and files:
            annotated.append((begin, end))
            for file in files:
                read = file.get('read') if isinstance(file, dict) else None
                read_interval = span(read)
                if file_key(file) is not None and read_interval is not None:
                    lo, hi = max(begin, read_interval[0]), min(end, read_interval[1])
                    if hi > lo:
                        file_intervals.append((lo, hi))
        if part.get('state') in ('ONCPU', 'RUNTIME_RETURN'):
            continue
        target = thread_index.get(part.get('thread_key'))
        call = part.get('syscall')
        stack = part.get('stack') if isinstance(part.get('stack'), list) else []
        waits.append({'begin_ns': begin, 'end_ns': end, 'elapsed_ns': end - begin,
            'state': part.get('state', 'UNKNOWN'), 'thread_key': part.get('thread_key'),
            'target_thread': {name: target.get(name) for name in ('tid', 'tgid', 'birth_ns', 'process_birth_ns', 'comm')} if target else None,
            'syscall': call if isinstance(call, dict) else None,
            'files': [display_file(file) for file in files],
            'stack_first6': stack[:6], 'stack_frame_count': len(stack),
            'reason_candidate': part.get('reason', 'UNKNOWN'),
            'reason_quality': 'RECORDED_STACK_OR_REPLAY_CANDIDATE_NOT_DEVICE_CAUSAL_PROOF',
            'evidence': part.get('evidence', {'quality': 'UNKNOWN'})})
    waits.sort(key=lambda value: (-value['elapsed_ns'], value['begin_ns'], str(value['thread_key'])))
    return {'on_path_file_sleep_union_ns': union_ns(file_intervals),
        'on_path_file_annotated_sleep_union_ns': union_ns(annotated),
        'file_sleep_scope': 'UNION_OF_COMPLETION_SLEEP_INTERSECT_VALID_OBJECT_VFS_READ_INTERVALS; MAY_INCLUDE_PIPES; NOT_PROVEN_PHYSICAL_DISK_WAIT',
        'longest_wait_count': min(10, len(waits)), 'all_wait_segment_count': len(waits), 'longest_waits': waits[:10]}


def summarize_report(report):
    require(isinstance(report, dict) and report.get('schema_version', 1) == 1, 'timeline schema v1 required')
    tools, threads = report.get('tools', []), report.get('threads', [])
    require(isinstance(tools, list) and isinstance(threads, list), 'explicit tools/threads lists required')
    index = {thread['key']: thread for thread in threads}
    require(len(index) == len(threads), 'duplicate thread keys')
    require(all(isinstance(tool.get('tool_call_id'), str) and tool['tool_call_id'] and span(tool) for tool in tools),
            'valid tool identity/spans required')
    require(len({tool['tool_call_id'] for tool in tools}) == len(tools), 'globally unique tool_call_id required')
    root_owners = defaultdict(list)
    roots = {}
    for tool in tools:
        root = tool.get('root_key')
        if root is None and isinstance(tool.get('root'), dict):
            declared = tool['root']
            candidates = [thread['key'] for thread in threads if thread.get('tid') == declared.get('tid')
                and number(declared.get('birth_ns', declared.get('thread_birth_ns')), 1)
                and thread.get('birth_ns') == declared.get('birth_ns', declared.get('thread_birth_ns'))]
            root = candidates[0] if len(candidates) == 1 else None
        roots[tool['tool_call_id']] = root
        if root is not None:
            root_owners[root].append(tool['tool_call_id'])
    cp = report.get('critical_path', {})
    entries = cp.get('tools', []) if isinstance(cp, dict) else []
    global_issues = []
    if not isinstance(cp, dict) or cp.get('status') != GOOD_PATH:
        global_issues.append('GLOBAL_COMPLETION_COVERAGE_NOT_RECONSTRUCTED')
    if str(report.get('health', {}).get('status', '')).upper() in ('INCOMPLETE', 'PARTIAL', 'UNKNOWN', 'UNRESOLVED', 'FAILED'):
        global_issues.append('TERMINAL_HEALTH_NOT_COMPLETE')
    output, all_owned = [], set()
    for tool in tools:
        tool_id, agent = tool['tool_call_id'], tool.get('agent_id')
        root, window = roots[tool_id], span(tool)
        issues, owned, rejected = [], [], []
        timing = tool_timing(tool, report.get('run'))
        if timing['invocation_status'] == 'INVALID_INVOCATION_BOUNDARY':
            issues.append('INVALID_INVOCATION_BOUNDARY')
        root_thread = index.get(root)
        root_valid = (root_thread is not None and root_owners[root] == [tool_id]
            and root_thread.get('agent_id') == agent and root_thread.get('tool_call_id') == tool_id)
        if not root_valid:
            issues.append('UNRESOLVED_OR_CONFLICTING_TOOL_ROOT')
        for thread in threads:
            if thread.get('tool_call_id') != tool_id or thread.get('agent_id') != agent:
                continue
            current, visited, valid = thread['key'], set(), False
            while root_valid and current in index and current not in visited:
                if current == root:
                    valid = True
                    break
                if current in root_owners:
                    break
                visited.add(current)
                current = index[current].get('parent_key')
            if valid:
                owned.append(thread)
                all_owned.add(thread['key'])
            else:
                rejected.append(thread['key'])
        if rejected:
            issues.append('TAGGED_THREADS_WITHOUT_VERIFIED_ROOT_ANCESTRY')
        owned_keys = {thread['key'] for thread in owned}
        processes, unknown_process = set(), 0
        for thread in owned:
            if number(thread.get('tgid'), 1) and number(thread.get('process_birth_ns'), 1):
                processes.add((thread['tgid'], thread['process_birth_ns']))
            else:
                unknown_process += 1
        if unknown_process:
            issues.append('UNRESOLVED_OWNED_PROCESS_IDENTITY')
        candidates = [entry for entry in entries if entry.get('tool_call_id') == tool_id
                      and entry.get('agent_id', agent) == agent]
        measure, parts = completion(candidates[0] if len(candidates) == 1 else None, tool)
        issues.extend(measure['issues'])
        if any(part.get('thread_key') not in owned_keys for part in parts):
            issues.append('COMPLETION_SEGMENT_THREAD_NOT_OWNED')
            measure['integrity_status'] = 'INCOMPLETE'
            measure['state_totals_ns'] = None
            measure['unknown_ns'] = window[1] - window[0]
            measure['runtime_return_ns'] = None
            measure['newborn_ns'] = None
            measure['waking_ns'] = None
            parts = []
        if any(part.get('state') not in ('UNKNOWN', 'RUNTIME_RETURN') and
               part.get('evidence', {}).get('quality', 'UNKNOWN') not in
               ('RECORDED_TRANSITIONS', 'OBSERVED', 'COMPLETE') for part in parts):
            issues.append('UNRESOLVED_COMPLETION_EVIDENCE_QUALITY')
        if measure['reported_status'] != GOOD_PATH or measure['unknown_ns']:
            issues.append('COMPLETION_PATH_INCOMPLETE_OR_UNKNOWN')
        reads = summarize_reads(owned, window)
        if any(reads[key] for key in ('unknown_or_inconsistent_returned_bytes', 'returned_exceeds_requested_records',
            'unresolved_object_read_records', 'read_records_without_path', 'unresolved_path_quality_records',
            'read_records_without_signed_result',
            'unresolved_read_intervals', 'unknown_requested_bytes_records', 'crossing_tool_span_read_records')):
            issues.append('UNRESOLVED_SELECTED_READ_FIELDS')
        related = [finding for finding in report.get('findings', []) if
            finding.get('tool_call_id') == tool_id or finding.get('thread') in owned_keys
            or (not finding.get('thread') and not finding.get('tool_call_id'))]
        if related:
            issues.append('REPORT_FINDINGS_AFFECT_THIS_TOOL_OR_GLOBAL_TRACE')
        waits = summarize_waits(parts, index, window)
        if not parts and window[1] > window[0]:
            waits['on_path_file_sleep_union_ns'] = None
            waits['on_path_file_annotated_sleep_union_ns'] = None
        output.append({'agent_id': agent, 'task_id': tool.get('task_id'), 'tool_call_id': tool_id,
            'root_key': root, 'wall_ns': window[1] - window[0], 'begin_ns': window[0], 'end_ns': window[1],
            'wall_scope': 'EXECUTION_RELEASE_WINDOW_BEGIN_TO_END; INCLUDES_RUNTIME_CONFIRMATION; EXCLUDES_DISPATCH_PRELUDE; NOT_SUM_OF_THREAD_ELAPSED',
            **timing,
            'summary_status': 'INCOMPLETE' if issues else 'OBSERVED_WITH_DECLARED_LIMITS',
            'selected_tool_timeline_status': 'INCOMPLETE' if issues or global_issues else GOOD_SELECTED_TOOL,
            'issues': sorted(set(issues)), 'completion_path': measure,
            'owned': {'thread_count': len(owned), 'process_count_known': len(processes),
                'unresolved_process_identity_threads': unknown_process, 'tagged_unverified_threads': rejected,
                'association_scope': 'AGENT_TOOL_TAG_AND_VERIFIED_ROOT_PARENT_CHAIN; NO_UNASSIGNED_INFRA_ALLOCATION'},
            'reads': reads, 'report_findings': related, **waits})
    envelope = {'scope': 'TOOL_SPAN_ENVELOPE; MIN_TOOL_BEGIN_TO_MAX_TOOL_END; NOT_SUM_OF_TOOL_WALLS_OR_FULL_MANIFEST_RUN',
        'begin_ns': min((span(tool)[0] for tool in tools), default=None),
        'end_ns': max((span(tool)[1] for tool in tools), default=None)}
    envelope['wall_ns'] = envelope['end_ns'] - envelope['begin_ns'] if tools else None
    unassigned = [thread['key'] for thread in threads if thread['key'] not in all_owned]
    unassigned_keys = set(unassigned)
    unassigned_findings = [finding for finding in report.get('findings', []) if finding.get('thread') in unassigned_keys]
    attribution_issues = [finding for finding in report.get('findings', []) if finding.get('kind') in
        ('UNRESOLVED_TASK_IDENTITY', 'IDENTITY_CONFLICT', 'IDENTITY_TRANSITION_UNRESOLVED',
         'CONFLICTING_PARENT', 'UNRESOLVED_TOOL_ROOT')]
    selected_status = ('NO_SELECTED_TOOLS' if not tools else 'INCOMPLETE'
        if global_issues or any(tool['issues'] for tool in output) else GOOD_SELECTED_TOOL)
    attribution_status = ('UNASSIGNED_EVENTS_PRESENT' if unassigned else 'UNRESOLVED_ATTRIBUTION_EVIDENCE'
        if attribution_issues else 'ALL_REPORTED_THREADS_ASSOCIATED_WITH_SELECTED_TOOLS' if threads else 'NO_REPORTED_THREADS')
    return {'schema_version': 1, 'authority': 'SUMMARY_OF_REPLAY_REPORT_NOT_RAW_VERIFICATION',
        'run': report.get('run', {}), 'tool_span_envelope': envelope, 'tools': output,
        'summary_status': 'INCOMPLETE' if not tools or unassigned or global_issues or any(tool['issues'] for tool in output) else 'OBSERVED_WITH_DECLARED_LIMITS',
        'summary_status_scope': 'LEGACY_CONSERVATIVE_COMBINED_STATUS; SEE_SEPARATE_SELECTED_TOOL_AND_WHOLE_CAPTURE_DIMENSIONS',
        'selected_tool_timeline_status': selected_status,
        'selected_tool_timeline_scope': 'ONLY_DECLARED_TOOL_ROOTS_AND_VERIFIED_DESCENDANTS; RETAINS_SELECTED_STATE_OBJECT_AND_HEALTH_GAPS; NOT_ALL_CGROUP_ACTIVITY',
        'whole_capture_attribution_status': attribution_status,
        'whole_capture_attribution_scope': 'REPORTED_THREAD_ASSIGNMENT_ONLY; NOT_PROOF_OF_ALL_CGROUP_ACTIVITY_OR_CAUSAL_ATTRIBUTION',
        'whole_capture_attribution_findings': attribution_issues,
        'global_issues': global_issues,
        'unassigned_threads': {'count': len(unassigned), 'keys': unassigned,
            'details': [{name: thread.get(name) for name in ('key', 'tid', 'tgid', 'birth_ns', 'process_birth_ns',
                'parent_key', 'comm', 'agent_id', 'tool_call_id', 'task_id', 'begin_ns', 'end_ns')}
                for thread in threads if thread['key'] in unassigned_keys],
            'report_findings': unassigned_findings,
            'scope': 'NOT_ALLOCATED_TO_ANY_AGENT; UNASSIGNED_DOES_NOT_AUTOMATICALLY_MEAN_AGENT_OR_INFRASTRUCTURE'},
        'reported_critical_path_status': cp.get('status', 'UNKNOWN') if isinstance(cp, dict) else 'UNKNOWN',
        'limits': ['工具/Agent身份是运行时声明；summary不重新验证raw或manifest。',
            'VFS计数只覆盖已选择、完整落在tool span内的记录；不是所有文件接口或源码文件数。',
            '并行累计VFS时长不等于墙钟，也不等于物理磁盘服务时间；不能与各phase相加。',
            '完成路径是限定依赖模型的派生结果；stack/reason只是原因候选，不是设备因果证明。',
            '对象有身份但无path时显示identity；不根据FD或时间接近编造文件路径。',
            'RUNTIME_RETURN单独列出，不能算工作线程CPU或磁盘等待。',
            '完整tool调用墙钟仅在invocation已记录且位于run起点与execution begin之间时计算；派发前奏不进入线程完成路径。',
            '选定工具时间线完整与整个采集范围归因是独立维度；未归属线程始终保留，不能猜为Agent或基础设施。']}


def format_chinese(summary):
    envelope = summary['tool_span_envelope']
    def seconds(value):
        if value is None:
            return 'UNKNOWN'
        if value >= 1e9:
            return '{:.6f} 秒'.format(value / 1e9)
        if value >= 1e6:
            return '{:.3f} 毫秒'.format(value / 1e6)
        if value >= 1000:
            return '{:.3f} 微秒'.format(value / 1000)
        return '{} ns'.format(value)
    lines = ['执行时间线摘要（只读 report 重算，不代替原始证据验证）',
        '选定工具时间线：' + summary['selected_tool_timeline_status'],
        '整个采集范围归因：' + summary['whole_capture_attribution_status'],
        '旧版保守合并状态：' + summary['summary_status'] + '（不要将整个范围的未归属活动误读为选定工具的时间线缺失）',
        '工具区间包围长度 TOOL_SPAN_ENVELOPE：' + seconds(envelope['wall_ns']) + '（不是各工具相加，也不是整个manifest运行时长）']
    for tool in summary['tools']:
        reads, path = tool['reads'], tool['completion_path']
        lines += ['', 'Agent={} / Tool={} / Task={}'.format(tool['agent_id'], tool['tool_call_id'], tool['task_id']),
            '  完整工具调用墙钟：{}；派发／启动／登记前奏：{}；invocation={}'.format(
                seconds(tool['tool_call_wall_ns']), seconds(tool['dispatch_prelude_ns']), tool['invocation_status']),
            '  执行释放窗口 begin→end：{}；选定工具时间线：{}（完成路径只分解此窗口）'.format(
                seconds(tool['wall_ns']), tool['selected_tool_timeline_status']),
            '  可靠归属的进程／线程：{}／{}；进程身份未解析线程：{}'.format(
                tool['owned']['process_count_known'], tool['owned']['thread_count'], tool['owned']['unresolved_process_identity_threads'])]
        if path['state_totals_ns'] is None:
            lines.append('  完成路径时间分解：UNKNOWN（区间分区不完整／不一致）')
        else:
            lines.append('  派生完成路径：' + '；'.join('{}={}'.format(state, seconds(path['state_totals_ns'][state])) for state in STATES))
        lines += ['  RUNTIME_RETURN单列：{}（退出后控制面确认，不当作CPU或磁盘等待）'.format(seconds(path['runtime_return_ns'])),
            '  选定VFS读取对象：{}；读取记录：{}；返回字节：{}；零返回／错误：{}／{}'.format(
                reads['selected_vfs_object_count'], reads['read_calls'], reads['returned_bytes'] if reads['returned_bytes'] is not None else 'UNKNOWN', reads['zero_reads'], reads['error_reads']),
            '  选定读取耗时累计={}，平均={}，最长={}（并行累计，不能当墙钟或磁盘耗时）'.format(
                seconds(reads['read_elapsed_sum_ns']), seconds(reads['read_elapsed_mean_ns']), seconds(reads['read_elapsed_max_ns'])),
            '  完成路径VFS对象关联sleep并集：{}（可含管道，不等于物理磁盘等待）'.format(seconds(tool['on_path_file_sleep_union_ns']))]
        for rank, wait in enumerate(tool['longest_waits'], 1):
            call = wait['syscall'] or {}
            target = wait['target_thread'] or {}
            files = ', '.join(file['display'] for file in wait['files']) or 'UNKNOWN'
            lines.append('  等待{}：{} {}；TID={}；syscall={}；对象={}；原因候选={}'.format(rank,
                wait['state'], seconds(wait['elapsed_ns']), target.get('tid', 'UNKNOWN'), call.get('name', 'UNKNOWN'), files, wait['reason_candidate']))
            if wait['stack_first6']:
                lines.append('    stack候选：' + ' ← '.join(str(value) for value in wait['stack_first6']))
        if tool['issues']:
            lines.append('  未确认项：' + ', '.join(tool['issues']))
    lines += ['', '未分配给Agent的线程：{}（不猜归属）'.format(summary['unassigned_threads']['count']),
        '选定工具完整不代表整个cgroup的活动均已归属；未归属身份、时间和相关finding保留在summary.json。',
        'UNKNOWN／UNRESOLVED保留未知；选定探针无记录不证明没有其他系统影响。']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    require(args.report.is_file() and not args.report.is_symlink() and args.report.stat().st_size <= MAX_BYTES,
            'bounded regular report required (64 MiB maximum)')
    require(not args.output.exists() and not args.output.is_symlink(), 'fresh output required')
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
    result = summarize_report(json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid))
    result['source_report'] = {'path': str(args.report.absolute()), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        output.write('\n')
    print(format_chinese(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
