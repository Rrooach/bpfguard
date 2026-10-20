#!/usr/bin/env python3
"""Draw one actual representative nine-panel resource timeline per condition.

Standard library only. Curves are never a synthetic median of different runs.
Guest-wide resource series are explicitly not Agent-exclusive attribution.
"""
import argparse
import hashlib
import html
import json
import math
from pathlib import Path
import statistics

import access_comparison as comparison
import wallclock_report as wall


COLORS = ('#2478df', '#ed6a26', '#17aa7b', '#ad72cb')


def nested(value, keys):
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list) and type(key) is int and 0 <= key < len(value):
            value = value[key]
        else:
            return None
    return value


def nonnegative(value):
    return comparison.numeric(value) and value >= 0


def delta(rows, keys):
    values = [nested(row, keys) for row in rows]
    if not values or not all(nonnegative(value) for value in values):
        return None
    return None if any(b < a for a, b in zip(values, values[1:])) else values[-1] - values[0]


def source_read(directory, name, expected, lines=False):
    sources = {}
    value = wall._read(directory, name, sources, lines=lines)
    if not isinstance(expected, dict) or sources[name]['sha256'] != expected.get('sha256'):
        raise ValueError('timeline source differs from comparison SHA256: ' + name)
    return value, sources[name]


def choose_representatives(trials):
    groups = {}
    for trial in trials:
        cfg = trial['config']
        key = tuple(cfg.get(field) for field in ('cache', 'workspace_layout', 'concurrency', 'file_access_mode',
                                               'file_access_backend', 'collector_ring_bytes'))
        groups.setdefault(key, []).append(trial)
    selected = []
    for key, rows in sorted(groups.items()):
        eligible = [row for row in rows if wall.get(row, 'primary', 'usable_for_comparison') is True
                    and wall.get(row, 'cache_evidence', 'cache_condition_eligible') is True
                    and nonnegative(wall.get(row, 'primary', 'seconds'))]
        median = statistics.median(row['primary']['seconds'] for row in eligible) if eligible else None
        chosen = min(eligible, key=lambda row: (abs(row['primary']['seconds'] - median),
            row['matrix']['block'], row['run_id'])) if eligible else None
        selected.append({'condition': dict(zip(('cache', 'workspace_layout', 'concurrency', 'file_access_mode',
                                               'file_access_backend', 'collector_ring_bytes'), key)),
            'n': len(rows), 'eligible_n': len(eligible), 'median_wall_seconds': median,
            'representative': chosen,
            'selection': 'ONE_ACTUAL_RUN_NEAREST_TO_ELIGIBLE_WALL_MEDIAN; TIE_BY_BLOCK_THEN_RUN_ID'})
    return selected


def load_selected(trial):
    directory = Path(trial['directory'])
    sources = trial['sources']
    run, rsrc = source_read(directory, 'profile-run.json', sources.get('profile-run.json'))
    meta, msrc = source_read(directory, 'load/load-meta.json', sources.get('load/load-meta.json'))
    stats, ssrc = source_read(directory, 'load/load-sampler-stats.json', sources.get('load/load-sampler-stats.json'))
    rows, lsrc = source_read(directory, 'load/load-samples.jsonl', sources.get('load/load-samples.jsonl'), lines=True)
    if (run['run_id'] != trial['run_id'] or run['run_id'] != meta['label']
            or run['boot_id'] != meta['boot_id'] or run['status'] != 'COMPLETE'
            or run['makespan_ns'] != run['end_ns'] - run['release_ns'] or stats['samples'] != len(rows)):
        raise ValueError('timeline run/boot/window/sample count identity differs')
    groups = meta.get('cgroups', [])
    matching = [index for index, group in enumerate(groups)
                if wall._identity(group) == wall._identity(run.get('root_cgroup'))]
    if len(matching) != 1:
        raise ValueError('timeline exact workload root cgroup unavailable')
    index = matching[0]
    previous_end = None
    for position, row in enumerate(rows):
        if (row.get('seq') != position or type(row.get('monotonic_ns')) is not int
                or type(row.get('collection_end_ns')) is not int or row['collection_end_ns'] < row['monotonic_ns']
                or (previous_end is not None and row['monotonic_ns'] <= previous_end)):
            raise ValueError('timeline invalid source sequence/time')
        previous_end = row['collection_end_ns']
    left = [i for i, row in enumerate(rows) if row['collection_end_ns'] <= run['release_ns']]
    right = [i for i, row in enumerate(rows) if row['monotonic_ns'] >= run['end_ns']]
    if not left or not right or right[0] <= left[-1]:
        raise ValueError('timeline missing true bracketing sample')
    rows = rows[left[-1]:right[0] + 1]
    return run, meta, stats, rows, index, {'profile': rsrc, 'meta': msrc, 'stats': ssrc, 'samples': lsrc}


def panels(run, meta, rows, group_index=0, device='vda', interface='eth0'):
    release, expected_interval = run['release_ns'], meta['interval_ms'] * 1000000
    def rates(keys, multiplier=1):
        values = []
        for a, b in zip(rows, rows[1:]):
            ns = b['monotonic_ns'] - a['monotonic_ns']
            amount = delta((a, b), keys)
            valid = 0 < ns <= expected_interval * 1.8 and not a.get('errors') and not b.get('errors')
            values.append(((b['monotonic_ns'] - release) / 1e9,
                amount * multiplier / (ns / 1e9) if valid and amount is not None else None))
        return values
    def sums(series):
        return [(values[0][0], sum(v[1] for v in values) if all(v[1] is not None for v in values) else None)
                for values in zip(*series)] if series else []
    def gauge(keys, divisor=1):
        return [((row['monotonic_ns'] - release) / 1e9,
            nested(row, keys) / divisor if nonnegative(nested(row, keys)) else None) for row in rows]
    cpus, ticks = meta['online_cpus'], meta['clk_tck']
    if type(cpus) is not int or cpus <= 0 or type(ticks) is not int or ticks <= 0:
        raise ValueError('positive measured CPU/clock basis required')
    cpu = lambda i: rates(('stat', 'cpu_total', i), 100 / (ticks * cpus))
    cg = ('cgroups', group_index)
    sched_enabled = nested(meta, ('thread_sampling', 'schedstats_runtime_enabled_at_start')) is True
    run_delay = sums([rates(('schedstat', i, 1), 1e-9) for i in range(cpus)]) if sched_enabled else []
    return [
        ('Guest CPU（全部 {} 核，不是任务独占）'.format(cpus), '%',
         [('user', cpu(0)), ('system', cpu(2)), ('iowait', cpu(4)),
          ('irq+softirq+steal', sums([cpu(5), cpu(6), cpu(7)]))]),
        ('任务 cgroup CPU', '核', [(name, rates(cg + ('cpu_stat', name + '_usec'), 1e-6)) for name in ('user', 'system')]),
        ('任务 cgroup 内存（缓存是 charge，不是总工作集）', 'GiB',
         [('memory.current', gauge(cg + ('memory_current',), 2 ** 30)),
          ('anon', gauge(cg + ('memory_stat', 'anon'), 2 ** 30)),
          ('file cache', gauge(cg + ('memory_stat', 'file'), 2 ** 30))]),
        ('任务 cgroup PSI some（各曲线不能相加）', '%',
         [(name, rates(cg + ('psi', name, 'some_total_us'), 1e-4)) for name in ('cpu', 'memory', 'io')]),
        ('全 Guest 调度等待（不是 Agent 独占等待）', 'tasks',
         [('平均 CPU run-delay 等待' if sched_enabled else 'schedstats 未开启', run_delay),
          ('D-state 瞬时数量', gauge(('stat', 'procs_blocked')))]),
        ('全 Guest 虚拟数据盘 {}（不是物理 SSD）'.format(device), 'MiB/s',
         [('read', rates(('diskstats', device, 2), 512 / 2 ** 20)),
          ('write', rates(('diskstats', device, 6), 512 / 2 ** 20))]),
        ('全 Guest {} 网络（不是任务独占流量）'.format(interface), 'MiB/s',
         [('RX', rates(('net_dev', interface, 0), 1 / 2 ** 20)),
          ('TX', rates(('net_dev', interface, 4), 1 / 2 ** 20))]),
        ('全 Guest 上下文切换与 task 创建', '次/s',
         [('context switches', rates(('stat', 'ctxt'))), ('task 创建', rates(('stat', 'processes')))]),
        ('全 Guest page faults（不等于 read 次数）', '次/s',
         [('总 faults', rates(('vmstat', 'pgfault'))), ('major faults', rates(('vmstat', 'pgmajfault')))])]


def esc(value):
    return html.escape(str(value), quote=True)


def svg_plot(run, meta, rows, group_index=0, device='vda', interface='eth0'):
    width, left, right, panel_height, top = 1200, 82, 905, 176, 145
    height = top + panel_height * 9 + 50
    xmin = (rows[0]['monotonic_ns'] - run['release_ns']) / 1e9
    xmax = (rows[-1]['monotonic_ns'] - run['release_ns']) / 1e9
    if xmax <= xmin:
        raise ValueError('positive timeline span required')
    wall_seconds = run['makespan_ns'] / 1e9
    sx = lambda value: left + (value - xmin) * (right - left) / (xmax - xmin)
    out = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" role="img" aria-label="一轮真实九项指标时间线">'.format(width, height),
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="{}" y="19" font-size="15">八个任务的真实查询区间；灰色背景仅为执行窗口，没有模型调用</text>'.format(left)]
    for i, result in enumerate(sorted(run['results'], key=lambda item: item['task_id'])):
        y = 29 + i * 11
        out.append('<text x="8" y="{}" font-size="9">{}</text>'.format(y + 8, esc(result['task_id'])))
        for span in result.get('query_statistics', {}).get('query_spans', []):
            begin, end = [(span[key] - run['release_ns']) / 1e9 for key in ('begin_ns', 'end_ns')]
            out.append('<rect x="{:.3f}" y="{}" width="{:.3f}" height="8" fill="#777"/>'.format(
                sx(begin), y, max(.1, sx(end) - sx(begin))))
    for index, (title, unit, series) in enumerate(panels(run, meta, rows, group_index, device, interface)):
        y = top + index * panel_height
        ymax = max((v for _, data in series for _, v in data if v is not None), default=0) * 1.08 or 1
        sy = lambda value: y + 131 - value / ymax * 112
        out.extend(['<text x="{}" y="{}" font-size="14">{}</text>'.format(left, y + 5, esc(title)),
            '<rect x="{:.3f}" y="{}" width="{:.3f}" height="112" fill="#eeeeec"/>'.format(sx(0), y + 19, sx(wall_seconds) - sx(0)),
            '<text x="8" y="{}" font-size="10">{}</text>'.format(y + 19, esc(unit))])
        for tick in range(4):
            value = ymax * tick / 3
            yy = sy(value)
            out.append('<line x1="{}" y1="{:.2f}" x2="{}" y2="{:.2f}" stroke="#ddd"/>'.format(left, yy, right, yy))
            out.append('<text x="{}" y="{:.2f}" text-anchor="end" font-size="10">{:.3g}</text>'.format(left - 7, yy + 3, value))
        for tick in range(6):
            value = xmin + (xmax - xmin) * tick / 5
            xx = sx(value)
            out.append('<line x1="{:.2f}" y1="{}" x2="{:.2f}" y2="{}" stroke="#eee"/>'.format(xx, y + 19, xx, y + 131))
            out.append('<text x="{:.2f}" y="{}" text-anchor="middle" font-size="10">{:.2f}</text>'.format(xx, y + 148, value))
        for si, (name, data) in enumerate(series):
            color, segments, current, previous = COLORS[si], [], [], None
            for xx, value in data:
                if value is None or (previous is not None and xx - previous > meta['interval_ms'] / 1000 * 1.8):
                    if current:
                        segments.append(current)
                    current = []
                if value is not None:
                    current.append('{:.3f},{:.3f}'.format(sx(xx), sy(value)))
                previous = xx
            if current:
                segments.append(current)
            for segment in segments:
                out.append('<polyline points="{}" fill="none" stroke="{}" stroke-width="1.6"/>'.format(' '.join(segment), color))
            out.append('<line x1="930" y1="{}" x2="949" y2="{}" stroke="{}" stroke-width="2"/>'.format(y + 27 + 19 * si, y + 27 + 19 * si, color))
            out.append('<text x="956" y="{}" font-size="11">{}</text>'.format(y + 31 + 19 * si, esc(name)))
    out.append('<text x="{}" y="{}" text-anchor="middle" font-size="13">相对 release 的秒数；首尾为包围采样，不插值</text></svg>'.format((left + right) / 2, height - 15))
    return '\n'.join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--comparison', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--device', default='vda')
    parser.add_argument('--interface', default='eth0')
    args = parser.parse_args()
    raw = args.comparison.read_bytes()
    report = json.loads(raw)
    selected = choose_representatives(report['trials'])
    args.output_dir.mkdir(mode=0o700)
    records = []
    body = ['<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>2/4/6/8 搜索资源时间线</title>',
        '<style>body{font-family:system-ui,sans-serif;max-width:1250px;margin:24px auto;padding:0 12px;line-height:1.6}img{width:100%;height:auto}code{word-break:break-all}.note{background:#fff3ce;padding:12px}</style>',
        '<h1>2 / 4 / 6 / 8 并发搜索：真实资源时间线</h1>',
        '<p>每个条件选择墙钟耗时最接近中位数的一轮。每幅图是一轮真实记录，绝不是多轮拼成的中位数曲线。</p>',
        '<p class="note">sampler 与 access 分开。access 同时启用逐事件文件采集，会有额外开销。灰色背景是任务窗口；全 Guest 曲线包含采集器和其他活动，不是 Agent 独占成本。缺数据/回退/超长间隔断线，不补零。</p>']
    for entry in selected:
        trial = entry.pop('representative')
        condition = entry['condition']
        label = '{} / {} / 并发 {} / {} / {} / ring {} MiB'.format(condition['cache'], condition['workspace_layout'], condition['concurrency'], condition['file_access_mode'], condition.get('file_access_backend') or 'UNDECLARED', (condition.get('collector_ring_bytes') or 0) / 1024 ** 2)
        body.append('<h2>{}</h2>'.format(esc(label)))
        if trial is None:
            entry['status'] = 'NO_ELIGIBLE_ACTUAL_RUN'
            records.append(entry)
            body.append('<p>没有符合任务与缓存条件的真实轮次，不生成图。</p>')
            continue
        run, meta, stats, rows, index, sources = load_selected(trial)
        name = '{}-{}-c{}-{}-{}-ring{}'.format(condition['cache'], condition['workspace_layout'], condition['concurrency'], condition['file_access_mode'], condition.get('file_access_backend') or 'UNDECLARED', condition.get('collector_ring_bytes') or 0)
        with (args.output_dir / (name + '.svg')).open('x') as out:
            out.write(svg_plot(run, meta, rows, index, args.device, args.interface))
        entry.update(status='ONE_ACTUAL_RUN_RENDERED', run_id=run['run_id'], boot_id=run['boot_id'],
            block=trial['matrix']['block'], actual_wall_seconds=run['makespan_ns'] / 1e9,
            svg=name + '.svg', sources=sources, sampler_stats=stats,
            sampler_health=trial['resources']['status'],
            boundary={'before_uncertainty_ns': run['release_ns'] - rows[0]['monotonic_ns'],
                'after_uncertainty_ns': rows[-1]['collection_end_ns'] - run['end_ns'], 'samples': len(rows)})
        records.append(entry)
        body.append('<p>本轮 {:.6f} 秒，条件中位数 {:.6f} 秒，n={}、有效 {}。Run <code>{}</code>；采样状态 <code>{}</code>。</p>'.format(
            entry['actual_wall_seconds'], entry['median_wall_seconds'], entry['n'], entry['eligible_n'], esc(run['run_id']), esc(entry['sampler_health'])))
        body.append('<p>包围窗口左侧 {:.3f} ms，右侧 {:.3f} ms。缓存 charge 不等于整个系统缓存总量；少量 major fault 不代表没有 buffered read 读盘。</p>'.format(
            entry['boundary']['before_uncertainty_ns'] / 1e6, entry['boundary']['after_uncertainty_ns'] / 1e6))
        body.append('<a href="{}"><img src="{}" alt="{}"></a>'.format(esc(name + '.svg'), esc(name + '.svg'), esc(label)))
    body.append('<p>原始来源、选择方法、健康与窗口误差见 <a href="timeline-index.json">timeline-index.json</a>。本图不是物理 SSD 诊断，也不是全内核安全证明。</p></html>')
    summary = {'schema_version': 1, 'comparison_sha256': hashlib.sha256(raw).hexdigest(),
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'groups': records,
        'curve_scope': 'ONE_ACTUAL_RUN_PER_CONDITION_NOT_MEDIAN_SYNTHESIS'}
    with (args.output_dir / 'timeline-index.json').open('x') as out:
        json.dump(summary, out, ensure_ascii=False, indent=2)
        out.write('\n')
    with (args.output_dir / 'index.html').open('x') as out:
        out.write('\n'.join(body) + '\n')
    print(json.dumps({'groups': len(records), 'rendered': sum(r['status'] == 'ONE_ACTUAL_RUN_RENDERED' for r in records),
        'index': str(args.output_dir / 'index.html')}))


if __name__ == '__main__':
    main()
