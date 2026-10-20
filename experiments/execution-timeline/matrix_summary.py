#!/usr/bin/env python3
"""Small offline index of fixed-eight reference campaigns and complete evidence.

This consumes existing independent replay receipts; it does not repeat native
raw verification. Large leaf/composite JSON, HTML and read CSV are linked, not
cropped or embedded. An optional file-wait example reads one bound leaf report.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import html
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

from common import canonical, digest, write_new


BENCHMARKS = ('SWE-bench Verified', 'Terminal-Bench')
GOOD_PATH = 'RECONSTRUCTED_WITHIN_SELECTED_MODEL'
GOOD_SELECTED = 'COMPLETE_WITHIN_SELECTED_TOOL_SCOPE'
MAX_JSON_BYTES = 64 * 1024 * 1024
FIELDS = ('benchmark', 'concurrency', 'mode', 'total_jobs', 'distinct_tasks', 'n_per_condition',
    'boot_id', 'capture_order_in_boot', 'campaign_start_ns', 'campaign_end_ns', 'batch_start_ns', 'batch_end_ns',
    'batch_wall_ns', 'agent_return_batch_wall_ns', 'campaign_wall_ns',
    'batch_wall_seconds', 'agent_return_wall_seconds', 'campaign_wall_seconds',
    'official_passed_jobs', 'independent_replay_passed_jobs', 'complete_selected_tool_jobs',
    'health_complete_jobs', 'events', 'tools', 'thread_rows', 'unassigned_thread_rows',
    'selected_read_calls', 'actual_returned_bytes', 'actual_returned_bytes_known_sum',
    'unknown_return_jobs', 'sum_per_job_observed_object_identities', 'unresolved_file_identity_rows',
    'sum_per_job_success_or_eof_objects', 'sum_per_job_failed_only_objects', 'sum_per_job_unknown_outcome_objects',
    'generation_zero_file_rows', 'cpu_user_usec_sum', 'cpu_system_usec_sum', 'pgfault_sum', 'pgmajfault_sum',
    'report_read_records', 'excluded_owned_read_records', 'unassigned_read_records')
SUM_FIELDS = {'selected_read_calls': 'read_calls', 'actual_returned_bytes': 'returned_bytes',
    'actual_returned_bytes_known_sum': 'returned_bytes_known_sum', 'cpu_user_usec_sum': 'cpu_user_usec',
    'cpu_system_usec_sum': 'cpu_system_usec', 'pgfault_sum': 'pgfault', 'pgmajfault_sum': 'pgmajfault'}
LEGEND = (
    ('官方参考任务', '使用官方reference/oracle操作验证任务和采集链路，不是新模型执行成绩，也不是8个不同题目。'),
    ('官方通过', '任务做对了；不单独证明观测证据完整或系统安全。'),
    ('原始重放', '原始证据与独立复算一致；不把未选择的Linux接口变成已覆盖。'),
    ('选定工具完整 / selected coverage', '仅在声明的hook和工具执行范围内完整，不等于全部Linux活动完整覆盖；未归属活动仍单独保留。'),
    ('ONCPU / ON_CPU', '线程正在CPU上运行，不代表每一刻都在执行有用的业务计算。'),
    ('RUNNABLE', '线程已经可以运行，但还在等CPU；不是磁盘读取耗时。'),
    ('SLEEP', '线程阻塞或睡眠；可能等待文件、管道、锁、定时器等，需结合syscall、对象和栈判断，不能一律称为磁盘等待。'),
    ('UNKNOWN', '证据缺失或无法在选定模型中解释，保留未知，不算作已完成覆盖。'),
    ('三种墙钟', '执行batch=首释放至最后静止；Agent-return=首释放至最后执行返回；全流程另含准备、冻结和采集结束等控制开销，三者不相加。'),
    ('VFS累计耗时 / PSI', 'VFS耗时是多次读取的累计，可能并行重叠；PSI表示资源压力停顿。两者都不能加到墙钟，也不能用它们替代端到端耗时。'),
    ('读取对象数', '包含库、管道、设备等对象，不是源码文件数；先在每job内去重再相加，不是全局不同文件数；generation=0仍有生命周期限制。'),
    ('page fault / 缺页', '这是任务组边界计数，不是逐文件归因；major fault少也不能据此断言没有read()读盘。'),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def get(value, *keys):
    for key in keys:
        if not isinstance(value, dict): return None
        value = value.get(key)
    return value


def aggregate(values):
    known = [value for value in values if integer(value)]
    return {'value': sum(known) if len(known) == len(values) else None,
        'known_sum': sum(known), 'known_values': len(known), 'unknown_values': len(values) - len(known)}


class Sources:
    def __init__(self):
        self.identities = {}

    def bind(self, path, expected=None):
        require(not Path(path).is_symlink(), 'source symlink is not a regular pinned artifact')
        path = Path(path).resolve(strict=True)
        require(path.is_file(), 'regular source file required')
        value = digest(path)
        if expected is not None:
            require(isinstance(expected, dict) and value['sha256'] == expected.get('sha256')
                and value['size_bytes'] == expected.get('size_bytes', expected.get('bytes')),
                'source differs from saved receipt: ' + str(path))
        self.identities[str(path)] = value
        return path

    def read(self, path, expected=None):
        path = self.bind(path, expected)
        require(path.stat().st_size <= MAX_JSON_BYTES, 'JSON exceeds explicit index input limit')
        def pairs(items):
            result = {}
            for key, value in items:
                require(key not in result, 'duplicate JSON field: ' + key)
                result[key] = value
            return result
        def invalid(value): raise ValueError('nonfinite JSON: ' + value)
        return json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_constant=invalid)

    def unchanged(self):
        require(all(digest(path) == identity for path, identity in self.identities.items()),
                'source changed during matrix summary')


def observed_objects(path, binding, run, sources):
    require(isinstance(binding, dict) and binding.get('sha256'), 'bound files.csv identity required')
    path = sources.bind(path, binding)
    objects, unresolved, generation_zero, rows = {}, 0, 0, 0
    read_counts, actual_bytes, known_bytes = [], [], []
    with path.open(newline='', encoding='utf-8') as stream:
        for row in csv.DictReader(stream):
            rows += 1
            for column, values in (('read_calls', read_counts), ('actual_returned_bytes', actual_bytes),
                                    ('actual_returned_bytes_known_sum', known_bytes)):
                text = row.get(column)
                values.append(int(text) if isinstance(text, str) and re.fullmatch('[0-9]+', text) else None)
            require(row.get('boot_id') == run['boot_id'] and row.get('run_id') == run['run_id'],
                    'files.csv run/boot differs from leaf')
            identity = []
            for name in ('mount_id', 'device', 'inode', 'generation'):
                text = row.get(name)
                if not isinstance(text, str) or re.fullmatch(r'[0-9]+', text) is None:
                    break
                identity.append(int(text))
            if row.get('identity_status') != 'VALID_BOOT_LOCAL_IDENTITY' or len(identity) != 4 or identity[0] <= 0 or identity[2] <= 0:
                unresolved += 1
                continue
            state = objects.setdefault((run['boot_id'], *identity), {'success_or_eof': False, 'error': False, 'unknown': False})
            outcomes = []
            for column in ('positive_calls', 'eof_calls', 'error_calls', 'unknown_outcome_calls'):
                text = row.get(column)
                outcomes.append(int(text) if isinstance(text, str) and re.fullmatch('[0-9]+', text) else None)
            if any(value is None for value in outcomes):
                state['unknown'] = True
            else:
                state['success_or_eof'] |= outcomes[0] + outcomes[1] > 0
                state['error'] |= outcomes[2] > 0
                state['unknown'] |= outcomes[3] > 0
            generation_zero += identity[3] == 0
    success = sum(state['success_or_eof'] for state in objects.values())
    failed_only = sum(not state['success_or_eof'] and state['error'] and not state['unknown'] for state in objects.values())
    return {'observed_identity_count': len(objects), 'unresolved_identity_rows': unresolved,
        'success_or_eof_objects': success, 'failed_only_objects': failed_only,
        'unknown_outcome_objects': len(objects) - success - failed_only,
        'generation_zero_rows': generation_zero, 'per_tool_file_rows': rows,
        'selected_read_calls': aggregate(read_counts)['value'], 'actual_returned_bytes': aggregate(actual_bytes)['value'],
        'actual_returned_bytes_known_sum': aggregate(known_bytes)['value'],
        'scope': 'PER_JOB_BOOT_MOUNT_DEVICE_INODE_GENERATION_DEDUP; NOT_GLOBAL_FILES_OR_SOURCE_PATHS; GENERATION_ZERO_HAS_NO_LIFETIME_PROOF'}


def safe_job(name):
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,119}', name), 'path-safe job identity required')
    return name


def load_group(report_directory, resource_directory, sources):
    report_root, resource_root = Path(report_directory).resolve(strict=True), Path(resource_directory).resolve(strict=True)
    result = sources.read(report_root / 'result.json')
    require(result.get('schema_version') == 1 and result.get('status') == 'INDEPENDENT_LEAF_REPORTS_COMPOSED'
            and result.get('authority') == 'COMPOSITE_VIEW_OF_INDEPENDENTLY_VERIFIED_STREAMS', 'completed replay-composition receipt required')
    timing, original = result.get('timing', {}), result.get('jobs')
    benchmark, concurrency = timing.get('benchmark'), timing.get('concurrency')
    require(benchmark in BENCHMARKS and type(concurrency) is int and concurrency in (2, 4, 6, 8), 'supported benchmark/concurrency required')
    require(result.get('total_jobs') == timing.get('total_jobs') == 8 and isinstance(original, list)
            and len(original) == 8 and len({job['job_id'] for job in original}) == 8, 'exactly eight distinct job records required')
    campaign_source = result.get('source_campaign', {})
    campaign = sources.read(campaign_source.get('path', ''), campaign_source)
    require(campaign.get('boot_id') and campaign.get('benchmark') == benchmark and campaign.get('concurrency') == concurrency,
            'composition/controller identity differs')
    for field in ('batch_start_ns', 'batch_end_ns', 'batch_wall_ns', 'campaign_start_ns', 'campaign_end_ns', 'campaign_wall_ns'):
        require(integer(timing.get(field)) and timing[field] == campaign.get(field), 'controller wall binding differs: ' + field)
    require(timing['batch_wall_ns'] == timing['batch_end_ns'] - timing['batch_start_ns'] > 0
            and timing['campaign_wall_ns'] == timing['campaign_end_ns'] - timing['campaign_start_ns'] > 0, 'wall boundary subtraction differs')
    returned = max(job['agent_return_ns'] for job in original) - timing['batch_start_ns']
    require(integer(returned) and timing.get('agent_return_batch_wall_ns') == returned, 'Agent-return wall differs from actual last return')
    resource_receipt = sources.read(resource_root / 'receipt.json')
    resource_run = resource_receipt.get('run', {})
    require(resource_run.get('boot_id') == campaign['boot_id'] and resource_run.get('benchmark') == benchmark
            and resource_run.get('concurrency') == concurrency and resource_run.get('total_jobs') == 8
            and resource_run.get('begin_ns') == timing['batch_start_ns'] and resource_run.get('end_ns') == timing['batch_end_ns'],
            'resource-view/campaign identity differs')
    require(get(resource_receipt, 'sources', 'campaign.json', 'sha256') == campaign_source['sha256'],
            'resource-view source campaign digest differs')
    acceptance_bindings = {entry['job_id']: entry['identity'] for entry in result.get('leaf_acceptance', [])}
    require(set(acceptance_bindings) == {job['job_id'] for job in original}, 'all eight leaf acceptance bindings required')
    jobs, candidates = [], []
    for job in original:
        name = safe_job(job['job_id'])
        require(job.get('mode') == 'ORACLE_REFERENCE' and type(job.get('official_passed')) is bool, 'explicit official reference mode/result required')
        leaf = report_root / 'reports' / name
        acceptance = sources.read(leaf / 'acceptance.json', acceptance_bindings[name])
        verification = sources.read(leaf / 'verification.json')
        require(acceptance.get('verification') == verification and acceptance.get('job_id') == name
                and acceptance.get('benchmark') == benchmark and acceptance.get('official_passed') is job['official_passed'],
                'leaf acceptance/verification/job identity differs')
        summary = sources.read(leaf / 'summary.json')
        require(get(summary, 'run', 'boot_id') == campaign['boot_id']
                and get(summary, 'run', 'run_id') == job.get('source_run_id'), 'leaf summary run differs')
        manifest = sources.bind(verification['source_manifest'], verification['manifest_identity'])
        reading = sources.read(leaf / 'reads/receipt.json', acceptance['reads_receipt'])
        resources = sources.read(leaf / 'resources.json', acceptance['resource_receipt'])
        require(reading.get('run_id') == summary['run']['run_id'] and reading.get('boot_id') == summary['run']['boot_id'], 'read-export run identity differs')
        counts = reading.get('counts', {})
        if integer(counts.get('report_read_records')):
            require(counts['report_read_records'] == counts.get('partitioned_read_records')
                == counts.get('WITHIN_TOOL_EXECUTION_WINDOW', 0) + counts.get('excluded_owned_read_records', 0) + counts.get('unassigned_read_records', 0),
                'selected/excluded/unassigned read partition differs')
        # Index large evidence without re-reading it during source collection.
        # Its content binding remains the prior replay/export receipt, while
        # this layer checks that every linked file exists with the bound size.
        indexed = []
        for filename in ('reads.csv', 'files.csv', 'excluded-reads.csv', 'unassigned-reads.csv'):
            path = leaf / 'reads' / filename
            identity = get(reading, 'artifacts', filename)
            require(isinstance(identity, dict) and path.is_file() and not path.is_symlink()
                and path.stat().st_size == identity.get('size_bytes', identity.get('bytes')), 'indexed read CSV is missing or size differs')
            indexed.append({'path': str(path), 'identity': identity,
                'check': 'REGULAR_FILE_AND_SIZE; CONTENT_BINDING_FROM_PRIOR_EXPORT_RECEIPT'})
        require((leaf / 'report.json').is_file() and (leaf / 'report.json').stat().st_size == verification['report_identity']['size_bytes'],
                'indexed full report is missing or size differs')
        objects = observed_objects(leaf / 'reads/files.csv', get(reading, 'artifacts', 'files.csv'), summary['run'], sources)
        require(integer(job.get('read_calls')) and job['read_calls'] == counts.get('WITHIN_TOOL_EXECUTION_WINDOW'), 'selected read count differs')
        require(job['read_calls'] == objects['selected_read_calls']
            and job.get('returned_bytes') == objects['actual_returned_bytes']
            and job.get('returned_bytes_known_sum') == objects['actual_returned_bytes_known_sum'],
            'files.csv aggregate read count or actual/known returned bytes differs from job')
        for output, field in (('cpu_user_usec', 'cpu.stat.user_usec'), ('cpu_system_usec', 'cpu.stat.system_usec'),
                              ('pgfault', 'memory.stat.pgfault'), ('pgmajfault', 'memory.stat.pgmajfault')):
            require(job.get(output) == get(resources, 'delta', 'counters', field, 'delta'), 'boundary resource differs: ' + output)
        owned_threads = aggregate([get(tool, 'owned', 'thread_count') for tool in summary.get('tools', [])])['value']
        unassigned = summary.get('unassigned_threads')
        if isinstance(unassigned, dict):
            require(integer(unassigned.get('count')) and isinstance(unassigned.get('keys'), list)
                and isinstance(unassigned.get('details'), list)
                and unassigned['count'] == len(unassigned['keys']) == len(unassigned['details']),
                'explicit unassigned count/keys/details differ')
            unassigned_count = unassigned['count']
        else:
            require(isinstance(unassigned, list), 'explicit unassigned threads required')
            unassigned_count = len(unassigned)
        row = dict(job)
        row.update(events=get(acceptance, 'health', 'records'), tools=len(summary.get('tools', [])),
            thread_rows=None if owned_threads is None else owned_threads + unassigned_count,
            unassigned_thread_rows=unassigned_count, object_counts=objects,
            replay_status=verification.get('status'), selected_tool_timeline_status=summary.get('selected_tool_timeline_status'),
            health_status=get(acceptance, 'health', 'status'), whole_capture_attribution_status=summary.get('whole_capture_attribution_status'),
            report_read_records=counts.get('report_read_records'), excluded_owned_read_records=counts.get('excluded_owned_read_records'),
            unassigned_read_records=counts.get('unassigned_read_records'),
            indexed_read_evidence=indexed,
            links={'full_timeline': str(leaf / 'timeline.html'), 'full_report': str(leaf / 'report.json'),
                'summary': str(leaf / 'summary.json'), 'verification': str(leaf / 'verification.json'),
                'acceptance': str(leaf / 'acceptance.json'), 'raw_manifest': str(manifest),
                **{csv_name: str(leaf / 'reads' / csv_name) for csv_name in ('reads.csv', 'files.csv', 'excluded-reads.csv', 'unassigned-reads.csv')}})
        jobs.append(row)
        for tool in summary.get('tools', []):
            for wait in tool.get('longest_waits', []):
                syscall = wait.get('syscall') or {}
                if wait.get('state') == 'SLEEP' and syscall.get('name') in ('read', 'pread64', 'readv', 'preadv', 'preadv2') \
                        and any(ordinary_path(file.get('path')) for file in wait.get('files', [])):
                    candidates.append({'report_path': str(leaf / 'report.json'), 'verification': verification,
                        'job_id': name, 'benchmark': benchmark, 'concurrency': concurrency,
                        'thread_key': wait.get('thread_key'), 'tool_call_id': tool['tool_call_id'],
                        'wait_begin_ns': wait['begin_ns'], 'wait_end_ns': wait['end_ns'], 'duration_ns': wait['elapsed_ns']})
    require(sum(job['official_passed'] for job in jobs) == result.get('official_passed_jobs'), 'official result count differs')
    require(sum(job['replay_status'] == 'REPLAY_PASSED' for job in jobs) == result.get('independent_replay_passed_jobs'), 'replay receipt count differs')
    totals = {'benchmark': benchmark, 'concurrency': concurrency, 'mode': 'ORACLE_REFERENCE', 'n_per_condition': 1,
        'boot_id': campaign['boot_id'],
        **{field: timing[field] for field in ('campaign_start_ns', 'campaign_end_ns', 'batch_start_ns', 'batch_end_ns')},
        'total_jobs': 8, 'distinct_tasks': len({job['task_id'] for job in jobs}),
        'batch_wall_ns': timing['batch_wall_ns'], 'agent_return_batch_wall_ns': returned, 'campaign_wall_ns': timing['campaign_wall_ns'],
        'batch_wall_seconds': timing['batch_wall_ns'] / 1e9, 'agent_return_wall_seconds': returned / 1e9,
        'campaign_wall_seconds': timing['campaign_wall_ns'] / 1e9,
        'official_passed_jobs': sum(job['official_passed'] for job in jobs),
        'independent_replay_passed_jobs': sum(job['replay_status'] == 'REPLAY_PASSED' for job in jobs),
        'complete_selected_tool_jobs': sum(job['selected_tool_timeline_status'] == GOOD_SELECTED for job in jobs),
        'health_complete_jobs': sum(job['health_status'] == 'COMPLETE_FOR_SELECTED_HOOKS' for job in jobs),
        'unknown_return_jobs': sum(not integer(job.get('returned_bytes')) for job in jobs),
        'sum_per_job_observed_object_identities': sum(job['object_counts']['observed_identity_count'] for job in jobs),
        'sum_per_job_success_or_eof_objects': sum(job['object_counts']['success_or_eof_objects'] for job in jobs),
        'sum_per_job_failed_only_objects': sum(job['object_counts']['failed_only_objects'] for job in jobs),
        'sum_per_job_unknown_outcome_objects': sum(job['object_counts']['unknown_outcome_objects'] for job in jobs),
        'unresolved_file_identity_rows': sum(job['object_counts']['unresolved_identity_rows'] for job in jobs),
        'generation_zero_file_rows': sum(job['object_counts']['generation_zero_rows'] for job in jobs)}
    quality = {}
    for field, source in {**SUM_FIELDS, **{field: field for field in ('events', 'tools', 'thread_rows', 'unassigned_thread_rows',
            'report_read_records', 'excluded_owned_read_records', 'unassigned_read_records')}}.items():
        quality[field] = aggregate([job.get(source) for job in jobs])
        totals[field] = quality[field]['value']
    return {'totals': totals, 'aggregate_quality': quality, 'jobs': jobs, 'candidates': candidates,
        'task_multiset': dict(Counter(job['task_id'] for job in jobs)),
        'resource_configuration': result.get('resource_configuration'),
        'resource_findings': resource_receipt.get('findings'),
        'links': {'group_index': str(report_root / 'index.html'), 'composite_timeline': str(report_root / 'timeline.html'),
            'complete_composite_json': str(report_root / 'timeline-report.json'), 'jobs_csv': str(report_root / 'jobs.csv'),
            'resource_view': str(resource_root / 'index.html'), 'guest_resource_csv': str(resource_root / 'guest-series.csv'),
            'cgroup_resource_csv': str(resource_root / 'cgroup-series.csv'), 'controller_campaign': str(campaign_source['path'])}}


def ordinary_path(path):
    return isinstance(path, str) and path.startswith('/') and not any(path == prefix or path.startswith(prefix + '/') for prefix in ('/proc', '/sys', '/dev'))


def proven_file_wait(report, candidate):
    """Not merely an annotated file: require same call's active VFS interval."""
    if get(report, 'critical_path', 'status') != GOOD_PATH:
        return None
    index = {thread['key']: thread for thread in report.get('threads', [])}
    for pi, tool in enumerate(get(report, 'critical_path', 'tools') or []):
        if tool.get('tool_call_id') != candidate['tool_call_id'] or tool.get('status') != GOOD_PATH:
            continue
        for si, part in enumerate(tool.get('segments', [])):
            if part.get('state') != 'SLEEP' or part.get('sleep_state') == 'STOPPED' or part.get('thread_key') != candidate['thread_key'] \
                    or (part.get('begin_ns'), part.get('end_ns')) != (candidate['wait_begin_ns'], candidate['wait_end_ns']):
                continue
            syscall, thread = part.get('syscall') or {}, index.get(part['thread_key'])
            if not thread or syscall.get('name') not in ('read', 'pread64', 'readv', 'preadv', 'preadv2'):
                continue
            for file in part.get('files', []):
                read = file.get('read') or {}
                if not ordinary_path(file.get('path')) or not all(integer(read.get(k)) for k in ('start_ns', 'end_ns', 'returned_bytes', 'result')):
                    continue
                if read['end_ns'] < read['start_ns'] or read['returned_bytes'] != read['result']:
                    continue
                overlap = min(part['end_ns'], read['end_ns']) - max(part['begin_ns'], read['start_ns'])
                matching = [(ci, fi) for ci, call in enumerate(thread.get('calls', [])) if call.get('call_id') == syscall.get('call_id')
                    for fi, actual in enumerate(call.get('files', [])) if actual.get('read') == read
                    and all(actual.get(key) == file.get(key) for key in ('mount_id', 'device', 'inode', 'generation'))]
                if overlap <= 0 or len(matching) != 1:
                    continue
                ci, fi = matching[0]
                timeline = Path(candidate['report_path']).with_name('timeline.html')
                timeline_present = timeline.is_file() and not timeline.is_symlink()
                return {'status': 'PROVEN_SELECTED_COMPLETION_SLEEP_INTERSECTS_SAME_CALL_VFS_READ',
                    'benchmark': candidate['benchmark'], 'concurrency': candidate['concurrency'], 'job_id': candidate['job_id'],
                    'tool_call_id': tool['tool_call_id'], 'thread_key': thread['key'], 'tid': thread['tid'],
                    'path': file['path'], 'path_quality': file.get('path_quality'),
                    'object_identity': {key: file.get(key) for key in ('mount_id', 'device', 'inode', 'generation')},
                    'requested_bytes': read.get('requested_bytes'), 'actual_returned_bytes': read['returned_bytes'],
                    'vfs_read_begin_ns': read['start_ns'], 'vfs_read_end_ns': read['end_ns'],
                    'vfs_elapsed_ns': read['end_ns'] - read['start_ns'], 'wait_begin_ns': part['begin_ns'],
                    'wait_end_ns': part['end_ns'], 'wait_elapsed_ns': part['end_ns'] - part['begin_ns'],
                    'active_read_sleep_intersection_ns': overlap, 'stack': part.get('stack'),
                    'reason_candidate': part.get('reason'), 'evidence': part.get('evidence'),
                    'source_json': candidate['report_path'], 'source_report_identity': candidate['verification']['report_identity'],
                    'source_timeline': str(timeline) if timeline_present else None,
                    'source_timeline_status': 'EXISTENCE_CHECKED_PRESENTATION_ONLY_NOT_CONTENT_VERIFIED' if timeline_present else 'NOT_PRESENT_OR_NOT_REGULAR',
                    'completion_locator': 'critical_path.tools[{}].segments[{}]'.format(pi, si),
                    'read_locator': 'threads[{}].calls[{}].files[{}]'.format(report['threads'].index(thread), ci, fi),
                    'limits': 'ABSOLUTE_FILE_PATH_CANDIDATE; INODE_MODE_NOT_CAPTURED; STACK_IS_NOT_PHYSICAL_SSD_CAUSAL_PROOF; DYNAMIC_FRAMES_MAY_BE_UNRESOLVED'}
    return None


def summarize_matrix(inputs, sources, allow_partial=False, skip_example=False):
    groups = [load_group(report, resources, sources) for report, resources in inputs]
    keys = [(g['totals']['benchmark'], g['totals']['concurrency']) for g in groups]
    require(len(set(keys)) == len(keys), 'duplicate benchmark/concurrency input')
    if not allow_partial:
        require(set(keys) == {(benchmark, concurrency) for benchmark in BENCHMARKS for concurrency in (2, 4, 6, 8)},
                'formal matrix requires both benchmarks with exactly2/4/6/8 groups')
        require(not skip_example, 'formal matrix must search actual bound file-wait evidence')
        native = {canonical({name: get(g, 'resource_configuration', name) for name in ('collector_identity', 'bpf_object_identity')}) for g in groups}
        require(len(native) == 1 and all(get(g, 'resource_configuration', 'collector_identity') for g in groups), 'formal matrix cannot mix collector/BPF profiles')
        for group in groups:
            for field in ('collector_identity', 'bpf_object_identity'):
                identity = get(group, 'resource_configuration', field)
                require(isinstance(identity, dict) and isinstance(identity.get('sha256'), str)
                    and re.fullmatch('[0-9a-f]{64}', identity['sha256']) is not None and integer(identity.get('size_bytes'), 1),
                    'formal matrix needs exact collector/BPF identities')
        require(all(g['totals']['distinct_tasks'] == (1 if g['totals']['benchmark'] == BENCHMARKS[0] else 2) for g in groups),
                'formal task registry requires SWE1/Terminal2 distinct tasks')
    for benchmark in BENCHMARKS:
        selected = [g for g in groups if g['totals']['benchmark'] == benchmark]
        if selected:
            require(all(g['task_multiset'] == selected[0]['task_multiset'] for g in selected), 'same benchmark must complete the same task multiset')
            require(all(canonical(g['resource_configuration']) == canonical(selected[0]['resource_configuration']) for g in selected), 'same-benchmark resource/configuration differs')
    groups.sort(key=lambda group: (BENCHMARKS.index(group['totals']['benchmark']), group['totals']['concurrency']))
    # Comparison tables use concurrency order; retain actual capture order
    # separately. CLOCK_MONOTONIC timestamps cannot order different boots.
    chronology = []
    for group in groups:
        row = group['totals']
        order = 1 + sum(other['totals']['boot_id'] == row['boot_id']
            and other['totals']['campaign_start_ns'] < row['campaign_start_ns'] for other in groups)
        row['capture_order_in_boot'] = order
        chronology.append({key: row[key] for key in ('benchmark', 'concurrency', 'boot_id', 'capture_order_in_boot',
            'campaign_start_ns', 'campaign_end_ns', 'batch_start_ns', 'batch_end_ns')})
        chronology[-1]['controller_campaign'] = group['links']['controller_campaign']
    chronology.sort(key=lambda row: (row['boot_id'], row['campaign_start_ns'], row['benchmark'], row['concurrency']))
    example = {'status': 'NOT_SEARCHED_SMOKE_AVOIDS_LARGE_REPORT_IO'} if skip_example else None
    if not skip_example:
        candidates = sorted((candidate for group in groups for candidate in group['candidates']), key=lambda c: -c['duration_ns'])
        for candidate in candidates:
            report = sources.read(candidate['report_path'], candidate['verification']['report_identity'])
            example = proven_file_wait(report, candidate)
            if example is not None: break
        example = example or {'status': 'NO_PROVEN_ORDINARY_PATH_ACTIVE_READ_SLEEP_FOUND_IN_RECORDED_LONGEST_WAIT_CANDIDATES',
            'scope': 'NOT_AN_EXHAUSTIVE_SEARCH_OF_EVERY_READ; NO_FILE_BLOCKING_OR_SSD_CONCLUSION_IS_INVENTED'}
    return {'schema_version': 1, 'status': 'SMOKE_NOT_FORMAL' if allow_partial else 'FORMAL_FIXED_EIGHT_REFERENCE_MATRIX',
        'authority': 'SUMMARY_OF_BOUND_REPLAY_RECEIPTS_NOT_A_NEW_NATIVE_RAW_VERIFIER', 'groups': groups,
        'comparison_scope': 'WITHIN_BENCHMARK_ONLY; NO_CROSS_BENCHMARK_RATIO_OR_INFERRED_OPTIMIZATION_BENEFIT',
        'object_count_scope': 'SUM_PER_JOB_OBSERVED_OBJECT_IDENTITIES; DEDUP_WITHIN_EACH_JOB_BOOT_MOUNT_DEVICE_INODE_GENERATION; NOT_GLOBAL_DISTINCT_SOURCE_FILES; GENERATION_ZERO_LIMITED',
        'metric_legend': [{'label': label, 'meaning': meaning} for label, meaning in LEGEND],
        'capture_order': chronology,
        'capture_order_scope': 'ACTUAL_CAMPAIGN_START_MONOTONIC_WITHIN_BOOT; EQUAL_START_TIMES_UNORDERED; NO_CROSS_BOOT_ORDER_INFERRED',
        'file_wait_example': example,
        'limits': ['全部任务使用官方reference/oracle操作，没有模型推理或真实模型Agent分数。',
            '每个条件只有一轮n=1；不声称统计显著性、优化收益或Observer slowdown。',
            '对比表按并发2/4/6/8排列，不是实验执行顺序；实际先后见单独的采集顺序表，同boot按真实campaign_start_ns排序，同起点不推断先后。',
            'SWE为1个不同task的8份独立复本；Terminal为2个不同task组成的8个job，具体份数见task_multiset。',
            '只在同一benchmark内比较固定8个job的2/4/6/8并发；SWE和Terminal不是同一工作量，不跨benchmark求比。',
            'batch=首任务释放到最后静止；Agent-return=首释放到最后执行返回；full campaign另含准备、冻结和采集结束/导出，三者不相加。',
            '对象数先在每job跨工具按boot/mount/device/inode/generation去重，再对8job求和；不是全局不同源码文件数；generation=0不证明跨生命周期不复用。',
            '已解析读取对象包含库、管道、设备和失败尝试关联对象，不叫源码文件数。成功/EOF按positive_calls+eof_calls>0；failure-only要求有失败、没有成功/EOF且没有未知outcome。',
            'EAGAIN等负返回是已知失败，返回bytes=null不变成未知成功；它对已知正返回字节贡献为0。',
            'known bytes只累计已知实际返回，未知总数保持UNKNOWN；累计CPU与页缺失边界计数不是墙钟、逐read或逐文件归因。',
            '合成时间线有显示子集；每leaf完整JSON/HTML、4类读取CSV和原始manifest均直接链接，未复制或裁剪。',
            '选定工具coverage与整个capture归因分开；未归属线程及读取仍保留，不补造成Agent活动。']}


def render_index(result, output):
    esc = lambda value: html.escape(str(value), quote=True)
    def link(path, label):
        return '<a href="{}">{}</a>'.format(esc(quote(os.path.relpath(path, output), safe='/.-_')), esc(label))
    def value(item):
        return 'UNKNOWN' if item is None else esc('{:.6f}'.format(item) if type(item) is float else item)
    out = ['<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>固定8任务并发：全部结果</title>',
        '<style>body{font-family:system-ui,sans-serif;max-width:1600px;margin:24px auto;padding:0 14px;line-height:1.6}table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #ddd;padding:5px;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere}.note{background:#fff3ce;padding:12px}summary{cursor:pointer;font-weight:bold}.scroll{overflow-x:auto}</style>',
        '<h1>固定8任务的2/4/6/8并发：全部结果入口</h1><p>状态：<code>{}</code>；<a href="summary.csv">完整对比CSV</a> · <a href="summary.json">完整汇总JSON</a></p>'.format(esc(result['status'])),
        '<div class="note">' + '<br>'.join(esc(note) for note in result['limits']) + '</div>']
    if result.get('bound_context'):
        out.append('<p>选定输入与实验环境回执（不是替代原始重放的验证）：' + ' · '.join(
            link(item['path'], item['label']) for item in result['bound_context']) + '</p>')
    out.append('<h2>先看懂这些指标</h2><table><tr><th>名称</th><th>通俗解释</th></tr>')
    for item in result.get('metric_legend', [{'label': label, 'meaning': meaning} for label, meaning in LEGEND]):
        out.append('<tr><td>{}</td><td>{}</td></tr>'.format(esc(item['label']), esc(item['meaning'])))
    out.append('</table>')
    if result.get('capture_order'):
        out.append('<h2>实际采集顺序（不是下表的并发排序）</h2><p>只在同一boot内按真实单调时钟开始时间排序；时间单位为ns，不是UTC日期。相同起点共用名次，不推断先后。单轮结果可能受缓存与运行顺序影响。</p><div class="scroll"><table><tr><th>boot</th><th>boot内顺序</th><th>benchmark / 并发</th><th>全流程开始ns</th><th>执行batch开始ns</th><th>原始控制记录</th></tr>')
        for row in result['capture_order']:
            out.append('<tr><td>{}</td><td>{}</td><td>{} / {}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
                esc(row['boot_id']), value(row['capture_order_in_boot']), esc(row['benchmark']), value(row['concurrency']),
                value(row['campaign_start_ns']), value(row['batch_start_ns']), link(row['controller_campaign'], 'campaign.json')))
        out.append('</table></div>')
    for benchmark in BENCHMARKS:
        groups = [g for g in result['groups'] if g['totals']['benchmark'] == benchmark]
        if not groups: continue
        out.append('<h2>{}</h2><p>任务构成：<code>{}</code>；以下墙钟均为8个job的实际固定总工作，不是各线程时间之和。</p>'.format(esc(benchmark), esc(json.dumps(groups[0]['task_multiset'], ensure_ascii=False))))
        out.append('<div class="scroll"><table><tr><th>并发</th><th>batch秒</th><th>Agent-return秒</th><th>full campaign秒</th><th>官方通过</th><th>独立重放</th><th>选定工具完整</th><th>原始采集健康</th><th>完整入口</th></tr>')
        for group in groups:
            row = group['totals']
            out.append('<tr>' + ''.join('<td>{}</td>'.format(value(row[field])) for field in ('concurrency', 'batch_wall_seconds', 'agent_return_wall_seconds', 'campaign_wall_seconds'))
                + ''.join('<td>{}/8</td>'.format(value(row[field])) for field in ('official_passed_jobs', 'independent_replay_passed_jobs', 'complete_selected_tool_jobs', 'health_complete_jobs'))
                + '<td>{} · {}</td></tr>'.format(link(group['links']['group_index'], '时间线/证据'), link(group['links']['resource_view'], '资源图')))
        out.append('</table></div><h3>观测到的实际数量</h3><div class="scroll"><table><tr>'
            + ''.join('<th>{}</th>'.format(esc(label)) for label in ('并发', '事件', '工具', '线程行', '未归属线程行', '窗口内VFS读取尝试', '实际返回B', '已知返回B', '已解析读取对象（逐job去重后相加）',
                '成功/EOF对象', 'failure-only对象', 'outcome未知对象', 'CPU user μs', 'CPU system μs', 'faults', 'major')) + '</tr>')
        for group in groups:
            row = group['totals']
            out.append('<tr>' + ''.join('<td>{}</td>'.format(value(row[field])) for field in ('concurrency', 'events', 'tools', 'thread_rows', 'unassigned_thread_rows', 'selected_read_calls',
                'actual_returned_bytes', 'actual_returned_bytes_known_sum', 'sum_per_job_observed_object_identities',
                'sum_per_job_success_or_eof_objects', 'sum_per_job_failed_only_objects', 'sum_per_job_unknown_outcome_objects',
                'cpu_user_usec_sum', 'cpu_system_usec_sum', 'pgfault_sum', 'pgmajfault_sum')) + '</tr>')
        out.append('</table></div>')
        for group in groups:
            out.append('<details><summary>并发{}：全部8个job及完整读取数据</summary><div class="scroll"><table><tr><th>job/task</th><th>官方/重放/coverage</th><th>事件/工具/线程</th><th>VFS尝试/实际B</th><th>job内对象：全部/成功EOF/失败-only/未知</th><th>完整数据入口</th></tr>'.format(group['totals']['concurrency']))
            for job in group['jobs']:
                links = ' · '.join(link(job['links'][key], label) for key, label in (
                    ('full_timeline', '完整泳道'), ('full_report', '完整JSON'), ('reads.csv', '逐次read'), ('files.csv', '逐文件'),
                    ('excluded-reads.csv', '窗外read'), ('unassigned-reads.csv', '未归属read'), ('raw_manifest', '原始manifest'), ('verification', '重放回执')))
                out.append('<tr><td>{}<br>{}</td><td>{}<br>{}<br>{}</td><td>{}/{}/{}</td><td>{}/{}</td><td>{}</td><td>{}</td></tr>'.format(
                    esc(job['job_id']), esc(job['task_id']), value(job['official_passed']), esc(job['replay_status']), esc(job['selected_tool_timeline_status']),
                    value(job['events']), job['tools'], value(job['thread_rows']), value(job.get('read_calls')), value(job.get('returned_bytes')),
                    '/'.join(str(job['object_counts'][key]) for key in ('observed_identity_count', 'success_or_eof_objects', 'failed_only_objects', 'unknown_outcome_objects')), links))
            out.append('</table></div><p>逐字段未知情况：<code>{}</code></p><p>资源图缺口：<code>{}</code></p></details>'.format(esc(json.dumps(group['aggregate_quality'], ensure_ascii=False)), esc(json.dumps(group['resource_findings'], ensure_ascii=False))))
    example = result['file_wait_example']
    out.append('<h2>一个真实文件读取等待证据（若存在）</h2><p>必须同时位于已重建完成路径、与同一syscall的实际VFS读区间相交；不是仅有文件annotation。栈仅为原因候选，不证明SSD饱和。</p>')
    out.append('<pre>' + esc(json.dumps(example, ensure_ascii=False, indent=2)) + '</pre>')
    if example.get('source_json'): out.append(link(example['source_json'], '打开该例的完整源JSON'))
    if example.get('source_timeline'):
        out.append(' · ' + link(example['source_timeline'], '打开该例的完整时间线HTML')
            + '<p>JSON包含复算后的证据；HTML仅用于展示，本汇总只检查该展示文件存在，未将它冒充新原始证据验证。</p>')
    return '\n'.join(out) + '</html>'


def export_matrix(inputs, output, allow_partial=False, skip_example=False, selection=None, context_receipts=()):
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'fresh matrix output required; never overwrite')
    sources = Sources()
    result = summarize_matrix(inputs, sources, allow_partial, skip_example)
    result['bound_context'] = []
    if selection is not None:
        selected = sources.read(selection)
        require(selected.get('status') == 'EIGHT_FORMAL_REFERENCE_GROUPS_CAPTURED_EXPORTED_FSYNCED_AND_GUEST_QUIET',
                'sealed formal selection receipt required')
        members = selected.get('groups_in_actual_capture_order')
        require(isinstance(members, list) and len(members) == 8, 'formal selection requires eight members')
        expected = {(item['benchmark'], item['concurrency'], str((Path(item['host_directory']) / 'campaign.json').resolve(strict=True)))
                    for item in members}
        actual = {(group['totals']['benchmark'], group['totals']['concurrency'],
                   str(Path(group['links']['controller_campaign']).resolve(strict=True))) for group in result['groups']}
        require(len(expected) == 8 and actual == expected, 'matrix inputs differ from sealed formal selection')
        require(all(group['totals']['boot_id'] == selected.get('boot_id') for group in result['groups']),
                'matrix boot differs from sealed formal selection')
        result['bound_context'].append({'label': '正式8组选择及采集/导出回执', 'path': str(Path(selection).resolve(strict=True)),
            'identity': sources.identities[str(Path(selection).resolve(strict=True))], 'authority': 'EXTERNAL_CAPTURE_SELECTION_CONTEXT'})
    for context in context_receipts:
        document = sources.read(context)
        require(isinstance(document, dict), 'context receipt must be a JSON object')
        path = str(Path(context).resolve(strict=True))
        result['bound_context'].append({'label': Path(path).name, 'path': path, 'identity': sources.identities[path],
            'authority': 'EXTERNAL_CONTEXT_RECEIPT_NOT_NATIVE_REPLAY', 'reported_status': document.get('status')})
    result['sources'] = sources.identities
    result['exporter_identity'] = digest(__file__)
    output.mkdir(parents=True, mode=0o700)
    write_new(output / 'summary.json', result)
    with (output / 'summary.csv').open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, FIELDS)
        writer.writeheader()
        writer.writerows({key: group['totals'].get(key) for key in FIELDS} for group in result['groups'])
    write_new(output / 'index.html', render_index(result, output).encode())
    sources.unchanged()
    write_new(output / 'receipt.json', {'schema_version': 1, 'status': result['status'], 'authority': result['authority'],
        'sources': sources.identities, 'exporter_identity': result['exporter_identity'],
        'artifacts': {name: digest(output / name) for name in ('summary.csv', 'summary.json', 'index.html')}})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', action='append', nargs=2, required=True, metavar=('REPORT_DIR', 'RESOURCE_VIEW_DIR'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-partial', action='store_true', help='仅smoke；标记SMOKE_NOT_FORMAL')
    parser.add_argument('--skip-example', action='store_true', help='smoke期间不读取大leaf JSON，正式矩阵不允许')
    parser.add_argument('--selection', type=Path, help='绑定正式8组选择回执，必须与实际campaign成员及boot完全相同')
    parser.add_argument('--context-receipt', type=Path, action='append', default=[], help='额外环境回执，仅绑定并链接，不替代native重放')
    args = parser.parse_args(argv)
    result = export_matrix(args.group, args.output, args.allow_partial, args.skip_example, args.selection, args.context_receipt)
    print('全部结果入口：{}；状态={}；组数={}。'.format((args.output / 'index.html').absolute(), result['status'], len(result['groups'])))
    print('只在各benchmark内比较固定8任务；n=1，不声称优化收益或Observer slowdown。')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
