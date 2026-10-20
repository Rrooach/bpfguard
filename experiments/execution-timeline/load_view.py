#!/usr/bin/env python3
"""Offline, standard-library resource charts from actual load-sampler records.

This side channel is not native timeline evidence or per-read accounting. Each
rate uses adjacent actual CLOCK_MONOTONIC samples; no missing/reset counter is
replaced by zero. Guest-wide activity is never assigned to an Agent.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import html
import json
import math
from pathlib import Path

from common import digest, write_new


MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_SAMPLES = 100000
COLORS = ('#2478df', '#ed6a26', '#169e70', '#9967bb', '#be557a', '#6c821e', '#308d9b', '#815f42')
CSV_FIELDS = ('scope', 'entity', 'job_id', 'cgroup_path', 'cgroup_id', 'metric', 'unit', 'raw_unit',
    'sample_seq', 'sample_monotonic_ns', 'sample_collection_end_ns', 'previous_monotonic_ns',
    'interval_ns', 'relative_batch_seconds', 'value', 'status', 'counter_delta',
    'previous_raw_json', 'current_raw_json', 'source', 'semantics')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def get(value, *keys):
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list) and type(key) is int and 0 <= key < len(value):
            value = value[key]
        else:
            return None
    return value


def json_value(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def load_json(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_INPUT_BYTES,
            'bounded regular non-symlink JSON required: ' + str(path))
    raw = path.read_bytes()
    require(len(raw) <= MAX_INPUT_BYTES, 'JSON grew beyond input budget')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field: ' + key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('nonfinite JSON value: ' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def load_samples(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_INPUT_BYTES,
            'bounded regular non-symlink sample JSONL required')
    rows, size = [], 0
    with path.open('rb') as stream:
        while True:
            raw = stream.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            size += len(raw)
            require(len(raw) <= MAX_LINE_BYTES and raw.endswith(b'\n'), 'oversized or truncated sample line')
            require(size <= MAX_INPUT_BYTES, 'sample source grew beyond input budget')
            def pairs(items):
                result = {}
                for key, value in items:
                    require(key not in result, 'duplicate sample JSON field: ' + key)
                    result[key] = value
                return result
            rows.append(json.loads(raw, object_pairs_hook=pairs,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite sample: ' + value))))
            require(len(rows) <= MAX_SAMPLES, 'sample count exceeds explicit viewer budget')
    return rows


def build_series(meta, samples, campaign, stats=None):
    """Pure derivation. Source arrays and application identities are not changed."""
    require(isinstance(meta, dict) and meta.get('schema_version') == 1, 'sampler schema1 metadata required')
    require(isinstance(campaign, dict) and campaign.get('schema_version') == 1, 'campaign schema1 required')
    require(isinstance(meta.get('boot_id'), str) and meta['boot_id']
            and meta['boot_id'] == campaign.get('boot_id'), 'sampler/campaign boot identity differs')
    require(all(integer(meta.get(name), 1) for name in ('online_cpus', 'clk_tck', 'interval_ms')),
            'positive recorded CPU count, USER_HZ and sampling interval required')
    begin, end = campaign.get('batch_start_ns'), campaign.get('batch_end_ns')
    require(integer(begin) and integer(end) and end > begin, 'ordered actual campaign batch boundaries required')
    require(isinstance(samples, list) and len(samples) >= 2, 'at least two actual samples required')
    require(len(samples) <= MAX_SAMPLES, 'sample count exceeds explicit viewer budget')
    findings, previous = [], None
    for index, sample in enumerate(samples):
        require(isinstance(sample, dict) and integer(sample.get('seq')) and integer(sample.get('monotonic_ns'))
            and integer(sample.get('collection_end_ns')) and sample['collection_end_ns'] >= sample['monotonic_ns'],
            'invalid sample sequence or CLOCK_MONOTONIC collection bounds')
        if previous is not None:
            require(sample['monotonic_ns'] > previous['monotonic_ns'] and sample['seq'] > previous['seq'],
                    'duplicate/backwards sample time or sequence')
            if sample['seq'] != previous['seq'] + 1:
                findings.append({'kind': 'SAMPLE_SEQUENCE_GAP', 'at_sample': sample['seq']})
        elif sample['seq'] != 0:
            findings.append({'kind': 'FIRST_SEQUENCE_NOT_ZERO', 'at_sample': sample['seq']})
        previous = sample
    if samples[0]['collection_end_ns'] > begin or samples[-1]['monotonic_ns'] < end:
        findings.append({'kind': 'SAMPLES_DO_NOT_TRULY_BRACKET_BATCH'})
    if stats is not None:
        require(isinstance(stats, dict) and stats.get('schema_version') == 1, 'sampler stats schema1 required')
        if stats.get('samples') != len(samples):
            findings.append({'kind': 'STATS_SAMPLE_COUNT_DIFFERS'})
        for name in ('read_errors', 'missed_ticks', 'truncated_cgroup_traversals', 'cgroup_traversal_read_errors'):
            if integer(stats.get(name), 1):
                findings.append({'kind': 'SAMPLER_SOURCE_HEALTH', 'field': name, 'count': stats[name]})
    groups, jobs = meta.get('cgroups'), campaign.get('jobs')
    require(isinstance(groups, list) and isinstance(jobs, list), 'explicit sampler cgroups and campaign jobs required')
    require(integer(campaign.get('total_jobs'), 1) and len(jobs) == campaign['total_jobs'], 'all campaign jobs must be retained')
    job_map = {}
    for job in jobs:
        require(isinstance(job, dict) and isinstance(job.get('job_id'), str) and job['job_id'], 'explicit job identity required')
        identity = job.get('ready_metadata') or {}
        key = identity.get('cgroup_root'), identity.get('cgroup_id')
        require(isinstance(key[0], str) and key[0].startswith('/sys/fs/cgroup/') and integer(key[1], 1)
                and key not in job_map, 'unique path/inode registered job cgroup required')
        require(all(integer(job.get(name)) for name in ('release_issued_ns', 'agent_return_ns', 'quiescent_ns'))
                and begin <= job['release_issued_ns'] <= job['agent_return_ns'] <= job['quiescent_ns'] <= end,
                'job release/return/quiescence outside batch')
        job_map[key] = job
    identities = [(group.get('path'), group.get('inode')) for group in groups if isinstance(group, dict)]
    require(len(identities) == len(groups) and len(set(identities)) == len(groups)
            and set(identities) == set(job_map), 'sampler cgroup paths/inodes differ from declared jobs')
    if any(not isinstance(sample.get('cgroups'), list) or len(sample['cgroups']) != len(groups) for sample in samples):
        findings.append({'kind': 'CGROUP_SAMPLE_INDEX_LENGTH_MISMATCH; NO_POSITIONAL_REASSIGNMENT'})
    enabled = get(meta, 'thread_sampling', 'schedstats_runtime_enabled_at_start')
    if enabled is not True:
        findings.append({'kind': 'SCHEDSTATS_DISABLED' if enabled is False else 'SCHEDSTATS_RUNTIME_ENABLEMENT_NOT_RECORDED'})
    series, expected_ns = [], meta['interval_ms'] * 1000000

    def source_error(sample, source):
        errors = sample.get('errors')
        if not errors:
            return False
        if not isinstance(errors, list):
            return True
        return any(not isinstance(error, dict) or not isinstance(error.get('path'), str)
                   or error['path'] == source for error in errors)

    def add(scope, entity, metric, unit, source, getter, *, scale=1, counter=True,
            job=None, semantics='', quality=None):
        points = []
        for index, current in enumerate(samples):
            previous = samples[index - 1] if index else None
            now = getter(current)
            before = getter(previous) if previous else None
            interval = current['monotonic_ns'] - previous['monotonic_ns'] if previous else None
            point = {'sample_seq': current['seq'], 'sample_monotonic_ns': current['monotonic_ns'],
                'sample_collection_end_ns': current['collection_end_ns'],
                'previous_monotonic_ns': previous['monotonic_ns'] if previous else None,
                'interval_ns': interval, 'relative_batch_seconds': (current['monotonic_ns'] - begin) / 1e9,
                'value': None, 'status': 'NO_PREVIOUS_SAMPLE', 'counter_delta': None,
                'previous_raw': before, 'current_raw': now}
            values = now if isinstance(now, list) else [now]
            if source_error(current, source) or (counter and previous and source_error(previous, source)):
                point['status'] = 'SOURCE_READ_ERROR'
            elif not counter:
                point.update(value=now * scale if number(now) else None,
                             status='OBSERVED_GAUGE' if number(now) else 'MISSING_OR_INVALID_GAUGE')
            elif previous is None:
                pass
            elif current['seq'] != previous['seq'] + 1:
                point['status'] = 'SAMPLE_SEQUENCE_GAP'
            elif interval > expected_ns * 1.8:
                point['status'] = 'SAMPLING_GAP'
            elif previous['collection_end_ns'] >= current['monotonic_ns']:
                point['status'] = 'NON_ATOMIC_COLLECTION_OVERLAP'
            else:
                old_values = before if isinstance(before, list) else [before]
                if not values or len(values) != len(old_values) or not all(integer(value) for value in values + old_values):
                    point['status'] = 'MISSING_OR_INVALID_COUNTER'
                elif any(b < a for a, b in zip(old_values, values)):
                    point['status'] = 'COUNTER_RESET'
                else:
                    amount = sum(b - a for a, b in zip(old_values, values))
                    point.update(value=amount * scale / (interval / 1e9), counter_delta=amount, status='ADJACENT_COUNTER_DELTA')
            if quality is not None:
                point = quality(point)
            points.append(point)
        descriptor = {'scope': scope, 'entity': entity, 'job_id': job['job_id'] if job else None,
            'cgroup_path': get(job, 'ready_metadata', 'cgroup_root') if job else None,
            'cgroup_id': get(job, 'ready_metadata', 'cgroup_id') if job else None,
            'metric': metric, 'unit': unit, 'source': source, 'semantics': semantics, 'points': points}
        descriptor['raw_unit'] = ('USER_HZ_ticks' if unit == 'percent_all_guest_cpu_capacity'
            else 'microseconds' if unit in ('percent_interval_stalled', 'cpu_cores', 'throttled_seconds_per_second')
            else 'nanoseconds' if unit == 'tasks_mean_over_interval'
            else 'KiB' if unit == 'GiB' and source == '/proc/meminfo'
            else 'bytes' if unit == 'GiB' or (unit == 'MiB_per_second' and not metric.startswith('disk.'))
            else '512_byte_sectors' if metric.startswith('disk.') else 'events_or_tasks')
        series.append(descriptor)

    cpus, ticks = meta['online_cpus'], meta['clk_tck']
    for name, columns in (('user', (0, 1)), ('system', (2,)), ('iowait', (4,)), ('irq_softirq_steal', (5, 6, 7))):
        add('GUEST', 'guest', 'cpu.' + name, 'percent_all_guest_cpu_capacity', '/proc/stat',
            lambda row, cols=columns: [get(row, 'stat', 'cpu_total', i) for i in cols],
            scale=100 / (ticks * cpus), semantics='USER_HZ_TICK_DELTA_DIVIDED_BY_ACTUAL_INTERVAL_AND_RECORDED_CPU_COUNT; IOWAIT_IS_NOT_EXECUTED_CPU')
    for name in ('MemAvailable', 'Cached', 'Buffers', 'AnonPages'):
        add('GUEST', 'guest', 'memory.' + name, 'GiB', '/proc/meminfo',
            lambda row, name=name: get(row, 'meminfo_kb', name), counter=False, scale=1024 / 2 ** 30,
            semantics='OBSERVED_GUEST_MEMINFO_GAUGE; CACHED_IS_NOT_WORKING_SET_OR_SUM_OF_AGENT_MEMORY')
    def used_memory(row):
        total, available = get(row, 'meminfo_kb', 'MemTotal'), get(row, 'meminfo_kb', 'MemAvailable')
        return total - available if number(total) and number(available) and total >= available else None
    add('GUEST', 'guest', 'memory.used_estimate', 'GiB', '/proc/meminfo', used_memory,
        counter=False, scale=1024 / 2 ** 30,
        semantics='MEMTOTAL_MINUS_MEMAVAILABLE_ESTIMATE; NOT_SUM_OF_PROCESS_RSS_OR_AGENT_EXCLUSIVE_BYTES')
    for resource in ('cpu', 'memory', 'io'):
        for kind in ('some', 'full'):
            add('GUEST', 'guest', 'psi.' + resource + '.' + kind, 'percent_interval_stalled', '/proc/pressure/' + resource,
                lambda row, resource=resource, kind=kind: get(row, 'psi', resource, kind + '_total_us'), scale=1e-4,
                semantics='STALL_MICROSECOND_DELTA_DIVIDED_BY_INTERVAL; DO_NOT_ADD_PSI_SERIES_OR_ADD_TO_WALL')
    def sched(row):
        values = get(row, 'schedstat')
        ids = get(row, 'stat', 'cpu_ids')
        if not isinstance(values, list) or len(values) != cpus or not isinstance(ids, list) or len(ids) != cpus:
            return None
        # cpu_ids must retain the same order recorded in the first sample.
        if ids != get(samples[0], 'stat', 'cpu_ids'):
            return None
        return [get(value, 1) for value in values]
    add('GUEST', 'guest', 'scheduler.raw_run_delay_tasks', 'tasks_mean_over_interval', '/proc/schedstat', sched, scale=1e-9,
        semantics='RAW_RUN_DELAY_COUNTER_DELTA; RUNTIME_ENABLEMENT_NOT_PROVEN_UNLESS_METADATA_SAYS_TRUE')
    def validate_sched(point):
        if enabled is not True:
            point['value'] = None
            point['status'] = 'SCHEDSTATS_DISABLED' if enabled is False else 'UNKNOWN_RUNTIME_ENABLEMENT_NOT_RECORDED'
        return point
    add('GUEST', 'guest', 'scheduler.validated_run_delay_tasks', 'tasks_mean_over_interval', '/proc/schedstat', sched,
        scale=1e-9, quality=validate_sched,
        semantics='SUM_OF_CPU_RUN_DELAY_NS_DELTA_DIVIDED_BY_INTERVAL; REQUIRES_RECORDED_RUNTIME_ENABLEMENT; NOT_AGENT_OR_THREAD_WAIT_ATTRIBUTION')
    for name in ('procs_running', 'procs_blocked'):
        add('GUEST', 'guest', 'scheduler.' + name, 'tasks_instantaneous', '/proc/stat',
            lambda row, name=name: get(row, 'stat', name), counter=False,
            semantics='INSTANTANEOUS_PROC_STAT_COUNT; RUNNING_INCLUDES_CURRENTLY_EXECUTING_TASKS; NOT_CUMULATIVE_WAIT')
    disks = sorted(set(meta.get('block_devices', [])) | {name for row in samples for name in (get(row, 'diskstats') or {})})
    for device in disks:
        for name, column in (('read', 2), ('write', 6)):
            add('GUEST', device, 'disk.' + name, 'MiB_per_second', '/proc/diskstats',
                lambda row, device=device, column=column: get(row, 'diskstats', device, column), scale=512 / 2 ** 20,
                semantics='RECORDED_DEVICE_512_BYTE_SECTOR_DELTA; NO_CROSS_DEVICE_SUM_OR_PHYSICAL_HOST_SSD_CLAIM')
    interfaces = sorted({name for row in samples for name in (get(row, 'net_dev') or {})})
    for interface in interfaces:
        for name, column in (('rx', 0), ('tx', 4)):
            add('GUEST', interface, 'network.' + name, 'MiB_per_second', '/proc/net/dev',
                lambda row, interface=interface, column=column: get(row, 'net_dev', interface, column), scale=1 / 2 ** 20,
                semantics='ONE_GUEST_INTERFACE; INCLUDES_OBSERVER_SSH_AND_OTHER_ACTORS; NEVER_SUM_VETH_BRIDGE_AND_EXTERNAL_BYTES')
    for name in ('ctxt', 'processes'):
        add('GUEST', 'guest', 'tasks.' + name, 'events_per_second', '/proc/stat',
            lambda row, name=name: get(row, 'stat', name),
            semantics='GUEST_COUNTER_DELTA; PROCESSES_COUNTS_NEW_TASK_CREATION_NOT_ONLY_AGENT_PROCESSES')
    for name in ('pgfault', 'pgmajfault', 'workingset_refault_file', 'workingset_refault_anon'):
        add('GUEST', 'guest', 'faults.' + name, 'events_per_second', '/proc/vmstat',
            lambda row, name=name: get(row, 'vmstat', name),
            semantics='FAULT_OR_REFAULT_COUNTER_DELTA; NOT_READ_COUNT_OR_FILE_OBJECT_ATTRIBUTION')
    for index, group in enumerate(groups):
        job = job_map[(group['path'], group['inode'])]
        def cg(row, index=index):
            values = row.get('cgroups')
            if not isinstance(values, list) or len(values) != len(groups):
                return None
            value = values[index]
            return value if isinstance(value, dict) and value.get('present') is True else None
        def cadd(metric, unit, filename, keys, **options):
            add('CGROUP', job['job_id'], metric, unit, group['path'] + '/' + filename,
                lambda row, keys=keys: get(cg(row), *keys), job=job, **options)
        for name in ('usage', 'user', 'system', 'throttled'):
            cadd('cpu.' + name, 'cpu_cores' if name != 'throttled' else 'throttled_seconds_per_second', 'cpu.stat',
                ('cpu_stat', name + '_usec'), scale=1e-6,
                semantics='CGROUP_CPU_MICROSECOND_DELTA; USAGE_INCLUDES_USER_AND_SYSTEM_DO_NOT_ADD_USAGE_AGAIN; NOT_WALL')
        for metric, keys, filename in (('current', ('memory_current',), 'memory.current'),
                ('lifetime_peak', ('memory_peak',), 'memory.peak'), ('anon', ('memory_stat', 'anon'), 'memory.stat'),
                ('file', ('memory_stat', 'file'), 'memory.stat')):
            cadd('memory.' + metric, 'GiB', filename, keys, counter=False, scale=1 / 2 ** 30,
                semantics='CGROUP_CHARGED_GAUGE; FILE_INCLUDES_SHMEM; PEAK_IS_CGROUP_LIFETIME_HIGH_WATER_NOT_THIS_BATCH_PEAK')
        for resource in ('cpu', 'memory', 'io'):
            for kind in ('some', 'full'):
                cadd('psi.' + resource + '.' + kind, 'percent_interval_stalled', resource + '.pressure',
                    ('psi', resource, kind + '_total_us'), scale=1e-4,
                    semantics='ONE_CGROUP_STALL_PERCENT; NEVER_ADD_CGROUP_PSI_OR_PSI_TO_WALL')
        for name in ('pgfault', 'pgmajfault', 'workingset_refault_file', 'workingset_refault_anon', 'pgscan', 'pgsteal'):
            cadd('faults.' + name, 'events_per_second', 'memory.stat', ('memory_stat', name),
                semantics='CGROUP_MEMORY_STAT_COUNTER_DELTA; NOT_PER_FILE_OR_READ_PAGEFAULT_ASSOCIATION')
        devices = sorted({name for row in samples for name in (get(cg(row), 'io_stat_by_device') or {})})
        for device in devices:
            for name in ('rbytes', 'wbytes'):
                cadd('io.' + device + '.' + name, 'MiB_per_second', 'io.stat',
                    ('io_stat_by_device', device, name), scale=1 / 2 ** 20,
                    semantics='ONE_MAJOR_MINOR_COUNTER_ONLY; FIRST_APPEARANCE_IS_UNKNOWN_NOT_ZERO; STACKED_DEVICES_MAY_DOUBLE_COUNT')
        cadd('tasks.current', 'tasks_instantaneous', 'pids.current', ('pids_current',), counter=False,
            semantics='CURRENT_CGROUP_TASK_COUNT_NOT_NUMBER_CREATED_DURING_INTERVAL')
    return {'schema_version': 1, 'authority': 'LOAD_SAMPLER_SIDE_CHANNEL_NOT_NATIVE_EVIDENCE_OR_PER_READ_ACCOUNTING',
        'run': {'benchmark': campaign.get('benchmark'), 'boot_id': meta['boot_id'],
            'concurrency': campaign.get('concurrency'), 'total_jobs': campaign['total_jobs'],
            'begin_ns': begin, 'end_ns': end, 'batch_wall_ns': end - begin,
            'sample_begin_ns': samples[0]['monotonic_ns'], 'sample_end_ns': samples[-1]['collection_end_ns'],
            'samples': len(samples), 'interval_ms': meta['interval_ms'], 'online_cpus': cpus},
        'jobs': jobs, 'groups': groups, 'series': series, 'findings': findings, 'sampler_stats': stats,
        'schedstats_runtime_enablement': enabled,
        'limits': ['首尾为真实包围采样；多数据源顺序读取并非原子快照；100ms采样不是逐次read计量。',
            'Guest总体包含Observer、SSH和其他系统活动，不能归给某个Agent；cgroup身份来自记录的注册表。',
            'PSI曲线不能相加，也不能加进墙钟；并行CPU时间、线程等待和VFS累计时间都不是任务墙钟。',
            '缺失、counter回退、缺样、长采样间隔会断线，不补零；第一点没有前样本，不生成rate。',
            '任务网络与逐文件pagefault关联未由sampler采集，不从Guest网络或major fault猜测归属。',
            '磁盘为Guest虚拟设备，网络按单接口展示；不把多设备或bridge/veth流量求和。']}


def csv_rows(view, scope):
    for series in view['series']:
        if series['scope'] != scope:
            continue
        for point in series['points']:
            row = {key: series.get(key) for key in CSV_FIELDS if key in series}
            row.update({key: point.get(key) for key in CSV_FIELDS if key in point})
            row['previous_raw_json'], row['current_raw_json'] = json_value(point['previous_raw']), json_value(point['current_raw'])
            yield row


def plot(view, panels, title):
    esc = lambda value: html.escape(str(value), quote=True)
    width, left, right, top = 1280, 90, 940, 55 + 15 * len(view['jobs'])
    step = max(180, 75 + 17 * max((len(panel[2]) for panel in panels), default=0))
    height = top + step * len(panels) + 30
    begin, end = view['run']['begin_ns'], view['run']['end_ns']
    xmin = (view['run']['sample_begin_ns'] - begin) / 1e9
    xmax = (view['run']['sample_end_ns'] - begin) / 1e9
    sx = lambda x: left + (x - xmin) / (xmax - xmin) * (right - left)
    out = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" role="img" aria-label="{}">'.format(width, height, esc(title)),
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="{}" y="22" font-size="16">{}</text>'.format(left, esc(title)),
        '<text x="{}" y="41" font-size="11">任务登记／释放 → 执行返回（深灰）→ 冻结静止（浅灰）；不是模型请求或逐命令轨迹</text>'.format(left)]
    for index, job in enumerate(view['jobs']):
        y = 48 + index * 15
        out.append('<text x="8" y="{}" font-size="10">{}</text>'.format(y + 10, esc(job['job_id'])))
        for a, b, color in ((job['release_issued_ns'], job['agent_return_ns'], '#777'),
                            (job['agent_return_ns'], job['quiescent_ns'], '#bbb')):
            out.append('<rect x="{:.3f}" y="{}" width="{:.3f}" height="10" fill="{}"/>'.format(
                sx((a - begin) / 1e9), y, max(.15, sx((b - begin) / 1e9) - sx((a - begin) / 1e9)), color))
    for index, (label, unit, selected) in enumerate(panels):
        y = top + index * step
        valid = [p['value'] for series in selected for p in series['points'] if p['value'] is not None]
        ymax = max(valid, default=0) * 1.08 or 1
        sy = lambda value: y + 135 - value / ymax * 112
        out.extend(['<text x="{}" y="{}" font-size="14">{}</text>'.format(left, y + 7, esc(label)),
            '<text x="8" y="{}" font-size="10">{}</text>'.format(y + 22, esc(unit)),
            '<rect x="{:.3f}" y="{}" width="{:.3f}" height="112" fill="#f0f0ed"/>'.format(
                sx(0), y + 23, sx((end - begin) / 1e9) - sx(0))])
        for tick in range(4):
            value, yy = ymax * tick / 3, sy(ymax * tick / 3)
            out.append('<line x1="{}" y1="{:.3f}" x2="{}" y2="{:.3f}" stroke="#ddd"/>'.format(left, yy, right, yy))
            out.append('<text x="{}" y="{:.3f}" text-anchor="end" font-size="10">{:.3g}</text>'.format(left - 7, yy + 3, value))
        for tick in range(6):
            x = xmin + (xmax - xmin) * tick / 5
            out.append('<line x1="{:.3f}" y1="{}" x2="{:.3f}" y2="{}" stroke="#e3e5e8"/>'.format(sx(x), y + 23, sx(x), y + 135))
            out.append('<text x="{:.3f}" y="{}" text-anchor="middle" font-size="10">{:.2f}s</text>'.format(sx(x), y + 151, x))
        if not selected:
            out.append('<text x="{}" y="{}" fill="#8b4c16" font-size="12">NOT_COLLECTED：没有该范围的已记录计数器，不能当作0</text>'.format(left + 20, y + 70))
        for si, series in enumerate(selected):
            color, segment = COLORS[si % len(COLORS)], []
            for point in series['points'] + [{'value': None}]:
                value = point['value']
                gap = point.get('interval_ns', 0) and point['interval_ns'] > view['run']['interval_ms'] * 1e6 * 1.8
                if value is None or gap:
                    if segment:
                        out.append('<polyline points="{}" fill="none" stroke="{}" stroke-width="1.5"/>'.format(' '.join(segment), color))
                    segment = []
                if value is not None:
                    segment.append('{:.3f},{:.3f}'.format(sx(point['relative_batch_seconds']), sy(value)))
                    out.append('<circle cx="{:.3f}" cy="{:.3f}" r="1.4" fill="{}"><title>{}</title></circle>'.format(
                        sx(point['relative_batch_seconds']), sy(value), color,
                        esc('{}: t={:.9f}s; value={:.9g} {}; {}; seq={}'.format(series['metric'],
                            point['relative_batch_seconds'], value, series['unit'], point['status'], point['sample_seq']))))
            out.append('<line x1="960" y1="{}" x2="979" y2="{}" stroke="{}" stroke-width="2"/>'.format(y + 29 + si * 17, y + 29 + si * 17, color))
            out.append('<text x="987" y="{}" font-size="10">{}</text>'.format(y + 33 + si * 17, esc(series['entity'] + ': ' + series['metric'])))
            if not any(p['value'] is not None for p in series['points']):
                status = ','.join(sorted({p['status'] for p in series['points']}))
                out.append('<text x="{}" y="{}" font-size="10" fill="#975d1b">UNKNOWN：{}</text>'.format(left + 15, y + 52 + si * 14, esc(status)))
    out.append('<text x="{}" y="{}" text-anchor="middle" font-size="12">相对第一任务释放的秒数；灰色区为batch墙钟窗口；断线为未知／缺样，不插值、不补零</text></svg>'.format((left + right) / 2, height - 9))
    return '\n'.join(out)


def render_view(view, device=None, interface='eth0'):
    def select(scope, entity, *metrics):
        return [series for series in view['series'] if series['scope'] == scope and series['entity'] == entity
                and series['metric'] in metrics]
    disks = sorted({s['entity'] for s in view['series'] if s['metric'].startswith('disk.')})
    if device is None:
        device = next((name for name in disks if not name.startswith(('sr', 'loop'))), disks[0] if disks else None)
    guest_panels = [
        ('Guest CPU：全部{}核容量，不是任务独占'.format(view['run']['online_cpus']), '%', select('GUEST', 'guest', 'cpu.user', 'cpu.system', 'cpu.iowait', 'cpu.irq_softirq_steal')),
        ('Guest 内存与页缓存：used=MemTotal−MemAvailable估计值', 'GiB', select('GUEST', 'guest', 'memory.used_estimate', 'memory.Cached', 'memory.Buffers', 'memory.AnonPages')),
        ('Guest PSI some：各资源停顿不能相加', '%', select('GUEST', 'guest', 'psi.cpu.some', 'psi.memory.some', 'psi.io.some')),
        ('Guest 调度：已验证run-delay平均等待数／瞬时任务数', 'tasks', select('GUEST', 'guest', 'scheduler.validated_run_delay_tasks', 'scheduler.procs_running', 'scheduler.procs_blocked')),
        ('Guest 虚拟数据盘 {}：不是物理SSD服务时间'.format(device), 'MiB/s', select('GUEST', device, 'disk.read', 'disk.write')),
        ('Guest 单网络接口 {}：包括SSH和系统流量'.format(interface), 'MiB/s', select('GUEST', interface, 'network.rx', 'network.tx')),
        ('Guest 上下文切换与新task创建', '次/s', select('GUEST', 'guest', 'tasks.ctxt', 'tasks.processes')),
        ('Guest 缺页：不等于read调用次数或文件归因', '次/s', select('GUEST', 'guest', 'faults.pgfault', 'faults.pgmajfault')),
        ('Guest 页缓存／匿名页refault', '次/s', select('GUEST', 'guest', 'faults.workingset_refault_file', 'faults.workingset_refault_anon'))]
    plots = {'guest.svg': plot(view, guest_panels, '一轮真实资源时间线：Guest总体')}
    for index, group in enumerate(view['groups']):
        job = next(job for job in view['jobs'] if get(job, 'ready_metadata', 'cgroup_root') == group['path'])
        entity = job['job_id']
        io = [s for s in view['series'] if s['scope'] == 'CGROUP' and s['entity'] == entity and s['metric'].startswith('io.')]
        panels = [
            ('任务 cgroup CPU：usage已包含user+system，不能重复相加', '核', select('CGROUP', entity, 'cpu.usage', 'cpu.user', 'cpu.system')),
            ('任务 cgroup 内存／文件页缓存charge', 'GiB', select('CGROUP', entity, 'memory.current', 'memory.anon', 'memory.file', 'memory.lifetime_peak')),
            ('任务 cgroup PSI some：不能加进墙钟', '%', select('CGROUP', entity, 'psi.cpu.some', 'psi.memory.some', 'psi.io.some')),
            ('任务 cgroup 分设备I/O：不跨设备相加；首次出现未知', 'MiB/s', io),
            ('任务 cgroup 缺页和refault：没有逐文件关联', '次/s', select('CGROUP', entity, 'faults.pgfault', 'faults.pgmajfault', 'faults.workingset_refault_file', 'faults.workingset_refault_anon'))]
        plots['cgroup-{:02d}.svg'.format(index)] = plot(view, panels, entity + '：实际注册cgroup资源')
    esc = lambda value: html.escape(str(value), quote=True)
    body = ['<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>真实资源时间序列</title>',
        '<style>body{font-family:system-ui,sans-serif;max-width:1300px;margin:24px auto;padding:0 14px;line-height:1.6}svg{width:100%;height:auto}pre,code{overflow-wrap:anywhere;white-space:pre-wrap}table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:4px 8px}.note{background:#fff3cf;padding:12px}summary{cursor:pointer;font-weight:600}</style>',
        '<h1>{}：并发{}，固定{}任务的真实资源图</h1>'.format(esc(view['run']['benchmark']), view['run']['concurrency'], view['run']['total_jobs']),
        '<p>batch墙钟 {:.6f} 秒；{}个真实样本，目标间隔{}ms；Boot <code>{}</code>。不将多轮拼成一条曲线。</p>'.format(view['run']['batch_wall_ns'] / 1e9, view['run']['samples'], view['run']['interval_ms'], esc(view['run']['boot_id'])),
        '<div class="note">' + '<br>'.join(esc(text) for text in view['limits']) + '</div>',
        '<p>全量数值：<a href="guest-series.csv">Guest CSV</a> · <a href="cgroup-series.csv">全部cgroup CSV</a> · <a href="series.json">全部series JSON</a> · <a href="receipt.json">来源SHA及口径</a>。CSV中的空值是UNKNOWN，不是0。网络和逐文件缺页不能从Guest曲线分配给Agent。</p>',
        '<details><summary>采样完整性与缺口（保留，不改绿）</summary><pre>' + esc(json_value(view['findings'])) + '</pre></details>', plots['guest.svg']]
    for index, group in enumerate(view['groups']):
        job = next(job for job in view['jobs'] if get(job, 'ready_metadata', 'cgroup_root') == group['path'])
        name = 'cgroup-{:02d}.svg'.format(index)
        body.extend(['<details><summary>{} — 查看该任务的CPU、内存、PSI、I/O与缺页</summary>'.format(esc(job['job_id'])),
            '<p>cgroup <code>{}</code>；inode {}。Agent标签 <code>{}</code> 是运行时声明，不是模型真实性证明。</p>'.format(esc(group['path']), group['inode'], esc(get(job, 'ready_metadata', 'agent_id') or 'NOT_RECORDED')),
            '<p>任务网络未采集；缺页仅cgroup计数器，不存在本图可证明的“哪个文件major fault”。</p>', plots[name], '</details>'])
    body.append('</html>')
    return '\n'.join(body), plots


def export_view(campaign_directory, output, device=None, interface='eth0'):
    root, output = Path(campaign_directory).resolve(strict=True), Path(output)
    require(not output.exists() and not output.is_symlink(), 'fresh output directory required; never overwrite')
    paths = {name: root / name for name in ('campaign.json', 'load/load-meta.json', 'load/load-samples.jsonl', 'load/load-sampler-stats.json')}
    identities = {name: digest(path) for name, path in paths.items()}
    campaign, meta, stats = [load_json(paths[name]) for name in ('campaign.json', 'load/load-meta.json', 'load/load-sampler-stats.json')]
    samples = load_samples(paths['load/load-samples.jsonl'])
    view = build_series(meta, samples, campaign, stats)
    if integer(stats.get('bytes_written')) and stats['bytes_written'] != identities['load/load-samples.jsonl']['size_bytes']:
        view['findings'].append({'kind': 'STATS_BYTES_WRITTEN_DIFFERS_FROM_COMPLETE_SOURCE'})
    html_document, plots = render_view(view, device, interface)
    output.mkdir(mode=0o700, parents=True)
    write_new(output / 'series.json', view)
    for scope, name in (('GUEST', 'guest-series.csv'), ('CGROUP', 'cgroup-series.csv')):
        with (output / name).open('x', newline='', encoding='utf-8') as stream:
            writer = csv.DictWriter(stream, CSV_FIELDS)
            writer.writeheader()
            writer.writerows(csv_rows(view, scope))
    for name, document in {**plots, 'index.html': html_document}.items():
        write_new(output / name, document.encode())
    require(all(digest(path) == identities[name] for name, path in paths.items()), 'source changed during resource export')
    states = Counter(point['status'] for series in view['series'] for point in series['points'])
    receipt = {'schema_version': 1, 'status': 'EXPORTED_ACTUAL_SERIES_WITH_DECLARED_QUALITY',
        'authority': view['authority'], 'run': view['run'], 'findings': view['findings'],
        'sources': {name: {'path': str(paths[name]), **identities[name]} for name in paths},
        'exporter_identity': digest(__file__), 'point_status_counts': dict(states),
        'series_count': len(view['series']), 'all_series_points': sum(len(s['points']) for s in view['series']),
        'artifacts': {path.name: digest(path) for path in output.iterdir() if path.is_file()}, 'limits': view['limits']}
    write_new(output / 'receipt.json', receipt)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign', required=True, type=Path, help='campaign.json及load/所在目录')
    parser.add_argument('--output', required=True, type=Path, help='全新导出目录，不覆盖')
    parser.add_argument('--device', help='Guest概览中展示的虚拟盘；全部盘数值仍导出CSV')
    parser.add_argument('--interface', default='eth0', help='Guest概览单接口；绝不跨bridge/veth求和')
    args = parser.parse_args(argv)
    receipt = export_view(args.campaign, args.output, args.device, args.interface)
    print('真实资源图已导出：' + str((args.output / 'index.html').absolute()))
    print('样本={}，series={}，数据点={}；CPU/内存/PSI/调度/磁盘/网络/创建/切换/缺页，Guest与cgroup分开。'.format(
        receipt['run']['samples'], receipt['series_count'], receipt['all_series_points']))
    print('UNKNOWN保留空值；PSI不加墙钟；采样不是逐次read计量；来源与质量见receipt.json。')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
