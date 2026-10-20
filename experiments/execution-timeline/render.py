#!/usr/bin/env python3
"""Dependency-free offline timeline viewer; visualization is not verification.

The original semantic JSON is downloadable without display truncation. Canvas
rendering is bounded and filtered; report loading still consumes memory in
proportion to the complete report (64 MiB input limit). Absolute ns/birth values
are never converted to JavaScript floating point to position the timeline.
"""
import argparse
import bisect
from collections import defaultdict
import errno
import json
from pathlib import Path
import sys

from syscall_catalog import BYTE_COUNT_ARG2, BYTE_RETURN, describe, descriptor_argument, TABLE_SHA256


MAX_REPORT_BYTES = 64 * 1024 ** 2
JS_SAFE_INTEGER = (1 << 53) - 1
STATES = frozenset(('ONCPU', 'RUNNABLE', 'SLEEP', 'WAKING', 'UNKNOWN', 'RUNTIME_RETURN', 'NEWBORN'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_js(value):
    """Preserve exact large integers in the UI inspector as decimal strings."""
    if type(value) is int and abs(value) > JS_SAFE_INTEGER:
        return str(value)
    if isinstance(value, dict):
        return {key: safe_js(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [safe_js(item) for item in value]
    return value


def embedded(value):
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
    return raw.replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')


def interval(item, label):
    require(isinstance(item, dict), label + ' must be an object')
    begin, end = item.get('begin_ns', item.get('start_ns')), item.get('end_ns')
    require(type(begin) is int and type(end) is int and 0 <= begin <= end,
            label + ' requires ordered integer begin/start_ns and end_ns')
    return begin, end


def tool_timing(item, run_begin):
    begin, end = interval(item, 'tool')
    invocation = item.get('invocation_ns')
    recorded = type(invocation) is int and run_begin <= invocation <= begin
    return {'execution_window_ns': end - begin,
        'tool_call_wall_ns': end - invocation if recorded else None,
        'dispatch_prelude_ns': begin - invocation if recorded else None,
        'invocation_status': 'RECORDED' if recorded else 'NOT_RECORDED' if invocation is None else 'INVALID_INVOCATION_BOUNDARY',
        'scope': 'FULL_CALL=INVOCATION_TO_RESULT; EXECUTION=RELEASE_TO_RESULT; DISPATCH_IS_NOT_WORKER_CPU_OR_IO'}


def call_presentation(call, run_begin=0):
    """Names/units for the UI only; never resolve a pointer, fd, or missing path."""
    value = describe(call.get('nr'), call.get('name'))
    result = call.get('result')
    ordinary = call.get('pairing') in (None, 'PAIRED')
    value.update(nr=call.get('nr'), descriptor=descriptor_argument(call),
        result=safe_js(result), pairing=call.get('pairing', 'NOT_RECORDED'))
    if type(result) is int and ordinary:
        value['outcome'] = ('ERROR' if -result in errno.errorcode else 'KERNEL_NEGATIVE_RETURN_NOT_NAMED_ERRNO') if result < 0 else 'SUCCESS'
        value['errno'] = errno.errorcode.get(-result) if result < 0 else None
    else:
        value.update(outcome='NO_ORDINARY_RESULT_OR_INCOMPLETE', errno=None)
    args = call.get('args')
    value['requested_bytes'] = safe_js(args[2]) if value['name'] in BYTE_COUNT_ARG2 and isinstance(args, list) and len(args) > 2 and type(args[2]) is int and args[2] >= 0 else None
    value['returned_bytes'] = safe_js(result) if value['name'] in BYTE_RETURN and type(result) is int and result >= 0 and ordinary else None
    value['vfs_reads'] = []
    for file in call.get('files', []) if isinstance(call.get('files', []), list) else []:
        read = file.get('read') if isinstance(file, dict) else None
        if not isinstance(read, dict):
            continue
        a, b = read.get('start_ns'), read.get('end_ns')
        value['vfs_reads'].append({'path': file.get('path') or None,
            'path_quality': file.get('path_quality', file.get('quality', 'NOT_RECORDED')),
            'object_identity': safe_js({key: file.get(key) for key in ('mount_id', 'device', 'inode', 'generation', 'generation_valid')}),
            'requested_bytes': safe_js(read.get('requested_bytes')), 'returned_bytes': safe_js(read.get('returned_bytes')),
            'result': safe_js(read.get('result')),
            't0': a - run_begin if type(a) is int and abs(a - run_begin) <= JS_SAFE_INTEGER else None,
            't1': b - run_begin if type(b) is int and abs(b - run_begin) <= JS_SAFE_INTEGER else None,
            'duration_ns': b - a if type(a) is int and type(b) is int and b >= a else None})
    return value


def model_for(report):
    require(isinstance(report, dict) and report.get('schema_version', 1) == 1,
            'timeline report schema_version 1 required')
    run = report.get('run')
    begin, end = interval(run, 'run')
    require(end > begin and end - begin <= JS_SAFE_INTEGER, 'positive <=104-day run duration required')
    require(all(isinstance(run.get(key), str) and run[key] for key in ('run_id', 'boot_id')),
            'run_id and boot_id are required')

    def span(item, label):
        start, finish = interval(item, label)
        require(abs(start - begin) <= JS_SAFE_INTEGER and abs(finish - begin) <= JS_SAFE_INTEGER,
                label + ' exceeds safe relative-nanosecond plotting range')
        raw_state = item.get('state', 'UNKNOWN')
        known = isinstance(raw_state, str) and raw_state in STATES
        state = raw_state if known else 'UNKNOWN'
        syscall = item.get('syscall')
        elapsed = None
        if isinstance(syscall, dict) and type(syscall.get('start_ns')) is int and type(syscall.get('end_ns')) is int:
            if syscall['start_ns'] <= syscall['end_ns']:
                elapsed = syscall['end_ns'] - syscall['start_ns']
        reads = []
        for file in item.get('files', []) if isinstance(item.get('files', []), list) else []:
            read = file.get('read') if isinstance(file, dict) else None
            if isinstance(read, dict):
                a, b = read.get('start_ns'), read.get('end_ns')
                reads.append({'requested_bytes': safe_js(read.get('requested_bytes')),
                    'returned_bytes': safe_js(read.get('returned_bytes')),
                    'elapsed_ns': b - a if type(a) is int and type(b) is int and b >= a else None})
        return {'t0': start - begin, 't1': finish - begin, 'state': state,
                'unsupported_state': not known, 'detail': safe_js(item),
                'syscall_elapsed_ns': elapsed, 'file_read_intervals': reads}

    tools, threads, critical = [], [], []
    require(isinstance(report.get('tools', []), list) and isinstance(report.get('threads', []), list),
            'tools and threads must be lists')
    tool_keys = set()
    for item in report.get('tools', []):
        value = span(item, 'tool')
        require(isinstance(item.get('tool_call_id'), str) and item['tool_call_id'], 'tool_call_id required')
        identity = (item.get('agent_id'), item['tool_call_id'])
        require(identity not in tool_keys, 'duplicate agent/tool identity')
        tool_keys.add(identity)
        value.update(agent_id=str(item.get('agent_id') or 'UNATTRIBUTED'),
                     task_id=str(item.get('task_id') or ''), tool_call_id=item['tool_call_id'])
        value['timing'] = tool_timing(item, begin)
        value['dispatch_prelude'] = None
        if value['timing']['invocation_status'] == 'RECORDED':
            value['dispatch_prelude'] = {'t0': item['invocation_ns'] - begin, 't1': value['t0'],
                'state': 'RUNTIME_DISPATCH', 'detail': {'kind': 'RUNTIME_DISPATCH_PRELUDE',
                    'reason': 'Docker exec／直接启动与Observer登记屏障；不是工作线程CPU或I/O时间',
                    'begin_ns': safe_js(item['invocation_ns']), 'end_ns': safe_js(item['begin_ns']),
                    'timing': value['timing']}}
        tools.append(value)
    thread_keys = set()
    for item in report.get('threads', []):
        value = span(item, 'thread')
        require(isinstance(item.get('key'), str) and item['key'] and item['key'] not in thread_keys,
                'unique nonempty thread key required')
        require(all(type(item.get(key)) is int and item[key] > 0 for key in ('tid', 'tgid', 'birth_ns')),
                'positive thread tid/tgid/birth_ns required')
        require(isinstance(item.get('segments', []), list) and isinstance(item.get('calls', []), list),
                'thread segments/calls must be lists')
        thread_keys.add(item['key'])
        segments = [span(part, 'thread segment') for part in item.get('segments', [])]
        calls = []
        for call in item.get('calls', []):
            require(isinstance(call, dict), 'thread call must be an object')
            call_begin, call_end = call.get('begin_ns', call.get('start_ns')), call.get('end_ns')
            if type(call_begin) is int and type(call_end) is int and 0 <= call_begin <= call_end:
                calls.append(span(call, 'call'))
            else:
                calls.append({'t0': None, 't1': None, 'detail': safe_js(call),
                              'timing_quality': 'UNRESOLVED_OR_INCOMPLETE_NOT_GUESSED'})
            calls[-1]['presentation'] = call_presentation(call, begin)
        value.update(key=item['key'], tid=str(item['tid']), tgid=str(item['tgid']),
            birth_ns=str(item['birth_ns']), parent_key=item.get('parent_key'),
            agent_id=str(item.get('agent_id') or 'UNATTRIBUTED'),
            task_id=str(item.get('task_id') or ''), tool_call_id=str(item.get('tool_call_id') or 'UNATTRIBUTED'),
            comm=str(item.get('comm') or ''), segments=segments, calls=calls)
        require(isinstance(item.get('execs', []), list), 'thread execs must be a list when present')
        value['execs'] = []
        for execution in item.get('execs', []):
            require(isinstance(execution, dict), 'thread exec item must be an object')
            timestamp = execution.get('timestamp_ns')
            value['execs'].append({'t0': timestamp - begin if type(timestamp) is int and abs(timestamp - begin) <= JS_SAFE_INTEGER else None,
                'detail': safe_js(execution)})
        # Large raw arrays live once in the model, not again inside thread detail.
        value['detail'] = safe_js({key: field for key, field in item.items() if key not in ('segments', 'calls')})
        threads.append(value)
    tool_index = {(tool['agent_id'], tool['tool_call_id']): tool for tool in tools}
    leaders = defaultdict(list)
    for thread in threads:
        if thread['tid'] == thread['tgid']:
            leaders[(thread['agent_id'], thread['tool_call_id'], thread['tgid'])].append(thread)
    leader_index = {}
    for identity, members in leaders.items():
        members.sort(key=lambda member: member['t0'])
        disjoint = all(left['t1'] <= right['t0'] for left, right in zip(members, members[1:]))
        leader_index[identity] = (members, [member['t0'] for member in members], disjoint)
    for thread in threads:
        matching = tool_index.get((thread['agent_id'], thread['tool_call_id']))
        if not thread['task_id'] and matching is not None:
            thread['task_id'] = matching['task_id']
        detail = thread['detail']
        if detail.get('process_key') is not None:
            thread['process_key'] = str(detail['process_key'])
            thread['process_identity_quality'] = 'EXPLICIT_PROCESS_KEY'
        elif detail.get('process_birth_ns') is not None:
            thread['process_key'] = thread['tgid'] + '/' + str(detail['process_birth_ns'])
            thread['process_identity_quality'] = 'EXPLICIT_TGID_AND_PROCESS_BIRTH'
        else:
            members, starts, disjoint = leader_index.get(
                (thread['agent_id'], thread['tool_call_id'], thread['tgid']), ([], [], True))
            index = bisect.bisect_right(starts, thread['t0']) - 1
            leader = members[index] if disjoint and index >= 0 and thread['t1'] <= members[index]['t1'] else None
            thread['process_key'] = leader['key'] if leader else 'UNRESOLVED/' + thread['key']
            thread['process_identity_quality'] = 'UNIQUE_DECLARED_LEADER_INTERVAL' if leader else 'UNRESOLVED_NOT_MERGED_BY_NUMERIC_PID'
    cp = report.get('critical_path', {})
    require(isinstance(cp, dict), 'critical_path must be an object')
    entries = cp.get('tools', [])
    require(isinstance(entries, list), 'critical_path.tools must be a list')
    if not entries and isinstance(cp.get('segments'), list):
        entries = [dict(cp, tool_call_id='ALL_TOOLS')]
    for item in entries:
        require(isinstance(item, dict) and isinstance(item.get('segments', []), list), 'critical path entry invalid')
        critical.append({'tool_call_id': str(item.get('tool_call_id') or 'UNATTRIBUTED'),
            'agent_id': str(item.get('agent_id') or ''),
            'segments': [span(part, 'critical path segment') for part in item.get('segments', [])],
            'detail': safe_js({key: field for key, field in item.items() if key != 'segments'})})
    preferred = report.get('preferred_view')
    default_view = {'t0': 0, 't1': end - begin, 'source': 'FULL_CAPTURE'}
    if isinstance(preferred, dict):
        left, right = preferred.get('begin_ns'), preferred.get('end_ns')
        if type(left) is int and type(right) is int and begin <= left < right <= end:
            default_view = {'t0': left - begin, 't1': right - begin,
                            'source': 'DISPLAY_HINT_ONLY; RESET_SHOWS_FULL_CAPTURE'}
    from summarize import summarize_report
    readable = summarize_report(report)
    summaries = {(item['agent_id'], item['tool_call_id']): item for item in readable['tools']}
    for tool in tools:
        tool['readable_summary'] = safe_js(summaries.get((tool['agent_id'], tool['tool_call_id'])))
    return {'run': safe_js(run), 'duration_ns': end - begin, 'default_view': default_view,
        'tools': tools, 'threads': threads,
        'critical': critical, 'critical_status': str(cp.get('status') or 'NOT_ESTABLISHED'),
        'health': safe_js(report.get('health', {})), 'findings': safe_js(report.get('findings', [])),
        'totals': safe_js(report.get('totals', {})),
        'display_projection': safe_js(report.get('display_projection')),
        'syscall_catalog': {'abi': 'LINUX_X86_64_NATIVE_ONLY', 'source_sha256': TABLE_SHA256,
            'scope': 'PRESENTATION_NAMES_ONLY_NOT_ADDITIONAL_HOOK_OR_OBJECT_COVERAGE'}}


HTML = r'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src data: blob:">
<title>Agent / Tool / Thread 离线时间线</title>
<style>
:root{font:14px system-ui,sans-serif;color:#19202b;background:#f4f6fa}body{margin:0;padding:18px}h1{font-size:21px;margin:0 0 8px}h2{font-size:16px}p{line-height:1.6;margin:6px 0}.card{background:white;border:1px solid #d8deea;border-radius:8px;padding:14px;margin:12px 0}.notice{color:#694700;background:#fff3d6;padding:10px;border-radius:5px}.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:end}label{display:flex;flex-direction:column;gap:4px}input{font:inherit;border:1px solid #aeb7c8;border-radius:4px;padding:6px;width:170px}input[type=number]{width:110px}button{font:inherit;padding:7px 12px;border:1px solid #8d9bb3;border-radius:4px;background:#fff;cursor:pointer}.legend{display:flex;gap:18px;flex-wrap:wrap;margin:12px 0}.swatch{display:inline-block;width:15px;height:12px;margin-right:5px;vertical-align:middle}.layout{display:grid;grid-template-columns:minmax(650px,1fr) minmax(290px,370px);gap:12px}.plot{overflow:auto;max-height:720px;border:1px solid #d8deea;background:white}canvas{display:block}#details{white-space:pre-wrap;overflow-wrap:anywhere;font:12px ui-monospace,monospace;max-height:660px;overflow:auto}#tip{position:fixed;display:none;pointer-events:none;background:#182336;color:white;padding:9px;max-width:420px;white-space:pre-wrap;border-radius:5px;font:12px ui-monospace,monospace;z-index:10}.muted{color:#526076;font-size:12px}.status{font-weight:600;color:#795200}summary{cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere}@media(max-width:1050px){.layout{grid-template-columns:1fr}body{padding:8px}}
</style></head><body>
<h1>Agent → 工具 → 进程 / 线程时间线</h1>
<style>table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:7px;border:1px solid #d8deea;text-align:left;vertical-align:top}th{background:#edf2f9}td code{white-space:pre-wrap;overflow-wrap:anywhere}.table-scroll{overflow:auto;max-height:650px}.command{max-width:520px;white-space:pre-wrap;overflow-wrap:anywhere}.command summary{font-family:ui-monospace,monospace}select{font:inherit;padding:6px;border:1px solid #aeb7c8;border-radius:4px;background:white}.metric{display:inline-block;margin:6px 18px 6px 0}.bad{color:#a62020}.good{color:#25643a}.page-nav{display:flex;align-items:center;gap:10px;margin:10px 0}.main-swimlanes{width:100%;min-width:850px}nav a{margin-right:18px}.plain-note{background:#edf4fc;padding:10px;border-radius:5px}</style>
<p id="run"></p>
<nav><a href="#overviewCard">① Agent做了什么</a><a href="#programCard">实际启动的程序</a><a href="#operationCard">② 文件操作 / syscall</a><a href="#threadPanel">③ 展开线程与等待</a></nav>
<div class="notice">这是一份离线可视化，不代替 verifier。工具区间来自运行时声明；线程状态和完成依赖路径由 replay 重建。完整工具调用为invocation→end，执行窗口为begin→end；浅色派发前奏为Docker exec／直接启动与Observer登记屏障，不是工作线程CPU或I/O，且不塞入完成路径。invocation未记录时不猜。文件、系统调用、栈只展示现有证据；SLEEP 不自动等于磁盘 I/O，时间交叠不自动构成因果关系。UNKNOWN 不表示通过。</div>
<div class="card controls">
<label>Agent / task / tool 筛选<input id="taskFilter" placeholder="输入标识子串"></label>
<label>线程筛选<input id="threadFilter" placeholder="PID、TID、comm、key"></label>
<label>窗口起点（秒）<input id="start" type="number" min="0" step="0.001" value="0"></label>
<label>窗口终点（秒）<input id="end" type="number" min="0" step="0.001"></label>
<label>最多显示线程<input id="maxThreads" type="number" min="1" max="256" value="128"></label>
<button id="apply">应用筛选</button><button id="reset">重置</button><button id="download">下载完整 JSON</button>
</div>
<section class="card" id="overviewCard"><h2>① 先看：执行了什么命令，花了多久</h2><p class="plain-note">一行是一条工具命令。紫色条是实际执行窗口；浅紫色是派发前奏。主要等待仅来自已有的完成依赖模型，不能把所有线程等待相加当成任务耗时。点击工具按钮可将下面的操作表和线程图筛选到这条工具。</p><p id="overviewStatus" class="muted"></p><div id="overviewSwimlanes" class="table-scroll"></div><div class="table-scroll"><table><thead><tr><th>Agent / 工具</th><th>实际命令</th><th>实际执行起止 / 退出码</th><th>完整调用 / 执行窗口</th><th>完成路径：主要时间 / 质量</th><th>已选VFS读取</th></tr></thead><tbody id="overviewRows"></tbody></table></div></section>
<section class="card" id="operationCard"><h2>② 具体做了哪些文件操作 / 系统调用</h2><p class="plain-note">syscall 是进程发起的内核调用；VFS read 是其中已选择读取路径的内核文件操作，二者耗时不可重复相加。open/write/rename/chmod 等调用可按编号命名，但当前路径解析主要覆盖选定读取路径：未采集的路径一律显示“未解析”，不把指针或 fd 猜成文件名。名称按本仓库 Linux x86_64 native syscall 表展示，不增加实际观测覆盖。</p><div class="controls"><label>操作搜索<input id="operationFilter" placeholder="文件路径、read、openat、fd、TID"></label><label>显示内容<select id="operationMode"><option value="filesystem">文件相关 syscall + VFS read</option><option value="syscall">全部 syscall</option><option value="vfs">仅 VFS read（逐次字节）</option></select></label><label>归属范围<select id="operationScope"><option value="tools">已归属工具线程</option><option value="all">包括未归属线程</option></select></label><label>结果<select id="operationOutcome"><option value="all">全部结果</option><option value="ERROR">仅失败</option><option value="SUCCESS">仅成功</option><option value="UNKNOWN">仅未知 / 无普通返回</option></select></label><label>排序<select id="operationSort"><option value="time">发生顺序</option><option value="duration">耗时从长到短</option></select></label><button id="operationApply">查询操作</button><button id="operationExec">查看程序启动调用 execve</button><button id="operationCsv">导出当前筛选 CSV</button></div><p id="operationStatus" class="muted"></p><div class="page-nav"><button id="operationPrevious">上一页</button><span id="operationPage"></span><button id="operationNext">下一页</button></div><div class="table-scroll"><table><thead><tr><th>相对时间 / 线程</th><th>工具 / 操作类型</th><th>调用名（编号）/ fd</th><th>结果 / 返回值</th><th>请求 / 返回 bytes</th><th>syscall 耗时</th><th>VFS read 耗时</th><th>实际对象路径 / 解析质量</th></tr></thead><tbody id="operationRows"></tbody></table></div><details><summary>为什么有些操作没有文件名？程序名能否还原？</summary><p>原始 syscall 参数中可能只有用户指针或 fd。没有内核对象/路径证据时，页面只显示调用名、参数和返回值，不能还原文件名。写入、rename、unlink 等成功也不自动证明最终状态已改变；当前 viewer 不增加写对象探针。当前 EXEC hook 未采集可执行文件路径；execve 表能显示发起线程与调用时刻，不能从用户指针猜程序路径。comm 是线程名称，可能截断或主动修改，不是可靠的完整可执行路径。这里列出的是 report 已保存的 calls，不代表覆盖全部 Linux 接口。超大合成页可能仅含显式显示投影，请打开单Agent完整页/CSV。</p></details><pre id="operationDetail" class="muted"></pre></section>
<details class="card" id="threadPanel"><summary><strong>③ 需要解释等待时，再展开：线程 / CPU / 内核完成路径</strong></summary>
<div class="legend"><span><i class="swatch" style="background:#25854b"></i>ONCPU</span><span><i class="swatch" style="background:#cf7900"></i>RUNNABLE：等 CPU</span><span><i class="swatch" style="background:#3574c5"></i>SLEEP：不可运行，原因看证据</span><span><i class="swatch" style="background:#b85b8c"></i>WAKING：唤醒递送/处理(源WAKING→目标WAKEUP，尚未完成入队)</span><span><i class="swatch" style="background:#868686"></i>UNKNOWN / 未支持状态</span><span><i class="swatch" style="background:#a5cddd"></i>NEWBORN：已创建，尚未首次唤醒／运行</span><span><i class="swatch" style="background:#a188b8"></i>RUNTIME_RETURN：终态TASK_DEAD切出至控制面确认，非 CPU；EXIT早期钩子不是终态</span><span><i class="swatch" style="background:#d7ccea"></i>RUNTIME_DISPATCH：派发／启动／登记前奏，非工作线程</span><span><i class="swatch" style="background:#5c477e"></i>执行释放窗口 begin→end</span></div>
<p id="coverage" class="muted"></p><p class="muted">点击区间查看系统调用、文件对象、stack、bytes 和 elapsed；可缩小时间窗口再看长轨迹。绘图最多 20,000 个区间，完整下载不受绘图省略影响。细线空隙不是 ONCPU。</p>
<div class="layout"><div class="plot" id="plot"><canvas id="timeline" aria-label="按Agent工具及线程分层的时间线"></canvas></div><div class="card"><h2>区间详情</h2><div id="details">悬停查看摘要，点击固定详情。暂无证据不等于未发生操作。</div></div></div>
<div class="card"><h2>工具墙钟与派发开销</h2><p class="muted">随Agent/task/tool和时间窗口筛选，最多展示256项。完整调用墙钟包含派发前奏；原完成路径只分解执行窗口，不能再把前奏相加一次。没有invocation时显示NOT_RECORDED，详见完整JSON。</p><pre id="toolTiming"></pre></div>
</details>
<div class="card"><h2>健康状态与派生完成路径</h2><p class="status" id="criticalStatus"></p><details><summary>health / findings / totals（原始字段）</summary><pre id="health"></pre></details><p class="muted">完成路径（report 的 critical_path 字段）限于声明的依赖模型，不是任意同步／数据因果的全局关键路径，也不是额外的内核观测。超大整数在详情中以十进制字符串显示；完整 JSON 下载保留原整数和所有未展示字段，但排版可能不同，不是原 JSON 文件的字节副本。加载内存仍随完整报告大小增长。</p></div>
<div id="tip"></div>
<script id="report-json" type="application/json">__REPORT_JSON__</script>
<script id="timeline-model" type="application/json">__TIMELINE_MODEL__</script>
<script>
'use strict';
const originalText=document.getElementById('report-json').textContent;
const model=JSON.parse(document.getElementById('timeline-model').textContent);
const $=id=>document.getElementById(id), canvas=$('timeline'), ctx=canvas.getContext('2d');
const COLORS={ONCPU:'#25854b',RUNNABLE:'#cf7900',SLEEP:'#3574c5',WAKING:'#b85b8c',UNKNOWN:'#868686',RUNTIME_RETURN:'#a188b8',NEWBORN:'#a5cddd'};
const LEFT=300, ROW=25, TOP=33, MAX_SEGMENTS=20000, MAX_PER_ROW=4000, MAX_ROWS=1000;
let rows=[],view0=0,view1=model.duration_ns,scale=1,drawn=0,omitted=0;
const pretty=value=>JSON.stringify(value,null,2), seconds=ns=>(ns/1e9).toFixed(6);
const hay=value=>String(value??'').toLowerCase();
const toolIdentity=value=>JSON.stringify([value.agent_id,value.tool_call_id]);
const escapeHtml=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ms=value=>typeof value==='number'?(value/1e6).toFixed(3)+' ms':'未记录';
const cell=value=>value===null||value===undefined?'UNKNOWN':String(value);
const kindFor=tool=>tool.detail.kind||tool.detail.tool_kind||'';
const fullCommandFor=tool=>typeof tool.detail.command==='string'?tool.detail.command:Array.isArray(tool.detail.command)?'argv: '+JSON.stringify(tool.detail.command):'命令未记录（仅有工具身份）';
const commandFor=tool=>kindFor(tool)==='OFFICIAL_CODEX_RUNTIME'?'Codex运行：模型请求／协调／等待（DeepSeek）':kindFor(tool)==='CODEX_DYNAMIC_SHELL'&&Array.isArray(tool.detail.command)?String(tool.detail.command.at(-1)):fullCommandFor(tool);
const runtimeTools=new Map(model.tools.map(tool=>[toolIdentity(tool),tool]));
const hasCodexShell=model.tools.some(tool=>kindFor(tool)==='CODEX_DYNAMIC_SHELL');
const operationEntries=[];let operationPage=0,filteredOperations=[];
const programEntries=[];let programPage=0,filteredPrograms=[];
for(const thread of model.threads)for(const execution of thread.execs)programEntries.push({thread,...execution});
for(const thread of model.threads)for(const call of thread.calls){
  const presentation=call.presentation;
  operationEntries.push({kind:'SYSCALL',thread,call,presentation,t0:call.t0,t1:call.t1,duration:call.t0===null?null:call.t1-call.t0});
  for(const read of presentation.vfs_reads)operationEntries.push({kind:'VFS_READ',thread,call,presentation,read,t0:read.t0,t1:read.t1,duration:read.duration_ns});
}
function overview(){
  const tools=model.tools.filter(tool=>matches(tool,hay($('taskFilter').value.trim()))&&toolOverlaps(tool,view0,view1));
  $('overviewStatus').textContent='当前匹配 '+tools.length+' 条工具；主视图最多显示256条。线程细节默认折叠，原始质量结论不变。';
  $('overviewRows').innerHTML=tools.slice(0,256).map(tool=>{
    const summary=tool.readable_summary||{},measure=summary.completion_path||{},totals=measure.state_totals_ns;
    const ranked=totals?Object.entries(totals).filter(([,v])=>typeof v==='number').sort((a,b)=>b[1]-a[1]):[];
    const labels={ONCPU:'CPU运行',RUNNABLE:'等CPU',SLEEP:'阻塞/睡眠（原因需证据）',UNKNOWN:'未知区间',RUNTIME_RETURN:'运行时确认',NEWBORN:'创建后待首次运行',WAKING:'唤醒递送'};
    const major=ranked.length?labels[ranked[0][0]]+' '+ms(ranked[0][1]):'未能建立完整分解';
    const reads=summary.reads||{},command=commandFor(tool),index=model.tools.indexOf(tool);
    const fullCommand=fullCommandFor(tool),runtimeNote=kindFor(tool)==='OFFICIAL_CODEX_RUNTIME'?'<br><span class="muted">包含工具与运行管理，不是纯模型等待；不与子工具耗时相加。</span>':'';
    const result=tool.detail.result,exit=typeof result==='number'?result:result?.return_code;
    let readText=model.display_projection?'当前为显示投影，不统计全量读取；请打开完整单Agent页':cell(reads.read_calls)+'次；'+cell(reads.returned_bytes)+' bytes<br>'+cell(reads.selected_vfs_object_count)+'个选定对象（非源码文件总数）';
    if(kindFor(tool)==='OFFICIAL_CODEX_RUNTIME')readText='<details><summary>运行管理自身的读取（非任务命令）</summary>'+readText+'</details>';
    const quality=summary.selected_tool_timeline_status,qualityText=quality==='COMPLETE_WITHIN_SELECTED_TOOL_SCOPE'?'所选范围证据完整':quality==='INCOMPLETE'?'所选范围证据有缺口':'范围质量未建立';
    return '<tr><td><button data-overview-tool="'+index+'">'+(kindFor(tool)==='OFFICIAL_CODEX_RUNTIME'?'Codex运行':'命令 '+(index+1))+'</button><details><summary>查看身份</summary>'+escapeHtml(tool.agent_id)+'<br>'+escapeHtml(tool.tool_call_id)+'</details></td><td class="command"><details><summary>'+escapeHtml(command.slice(0,180))+'</summary><code>'+escapeHtml(fullCommand)+'</code></details>'+runtimeNote+'</td><td>'+seconds(tool.t0)+'s → '+seconds(tool.t1)+'s<br>退出码 '+escapeHtml(cell(exit))+'</td><td>'+ms(tool.timing.tool_call_wall_ns)+' / '+ms(tool.timing.execution_window_ns)+'</td><td>'+escapeHtml(major)+'<details><summary>'+qualityText+'</summary><code>'+escapeHtml(quality||'UNKNOWN')+'</code></details></td><td>'+readText+'</td></tr>';
  }).join('');
  const width=Math.max(1,view1-view0),shown=tools.slice(0,256);
  let svg='<svg class="main-swimlanes" viewBox="0 0 1100 '+Math.max(75,shown.length*33+40)+'" role="img" aria-label="简明Agent工具命令主泳道">';
  shown.forEach((tool,index)=>{const y=22+index*33;
    svg+='<text x="0" y="'+(y+12)+'" font-size="11">'+escapeHtml(tool.agent_id.slice(-25)+' / '+tool.tool_call_id.slice(-16))+'</text><line x1="310" x2="1090" y1="'+(y+15)+'" y2="'+(y+15)+'" stroke="#d8deea"/>';
    for(const [span,color] of [[tool.dispatch_prelude,'#d7ccea'],[tool,'#5c477e']])if(span&&span.t1>=view0&&span.t0<=view1&&span.t1>span.t0){
      const a=Math.max(view0,span.t0),b=Math.min(view1,span.t1);
      svg+='<rect x="'+(310+(a-view0)/width*780)+'" y="'+y+'" width="'+Math.max(.7,(b-a)/width*780)+'" height="20" fill="'+color+'"><title>'+escapeHtml(commandFor(tool)+' / '+ms(b-a))+'</title></rect>';
    }
  });
  svg+='<text x="310" y="'+(shown.length*33+35)+'" font-size="11">'+seconds(view0)+'s → '+seconds(view1)+'s（同一任务时轴）</text></svg>';
  $('overviewSwimlanes').innerHTML=svg;
}
function operationFields(entry){
  const p=entry.presentation,r=entry.read,thread=entry.thread;
  const outcome=r?(typeof r.result==='number'?(r.result<0?'ERROR':'SUCCESS'):'UNKNOWN'):['SUCCESS','ERROR'].includes(p.outcome)?p.outcome:'UNKNOWN';
  const files=r?[r]:p.vfs_reads;
  const path=files.map(file=>file.path||'未解析').join(' | ')||'未解析（未采集路径；不按fd/指针猜测）';
  const quality=files.map(file=>file.path_quality||'UNKNOWN').join(' | ')||'NOT_RECORDED';
  const tool=runtimeTools.get(toolIdentity(thread));
  const executionScope=!tool?'NO_EXPLICIT_TOOL_SPAN':entry.t0===null||entry.t1===null?'UNRESOLVED_INTERVAL':
    tool.t0<=entry.t0&&entry.t1<=tool.t1?'WITHIN_TOOL_EXECUTION':entry.t0<tool.t1&&entry.t1>tool.t0?'CROSSES_TOOL_WINDOW_UNALLOCATED':'OUTSIDE_EXECUTION_STARTUP_OR_OTHER_CONTEXT';
  return {kind:entry.kind,execution_scope:executionScope,begin_seconds:typeof entry.t0==='number'?entry.t0/1e9:null,agent_id:thread.agent_id,
    tool_call_id:thread.tool_call_id,thread_key:thread.key,tid:thread.tid,operation:p.category,name:p.name,nr:p.nr,
    descriptor:p.descriptor?p.descriptor.kind+'='+p.descriptor.value:'未记录/不适用',outcome,
    result:r?r.result:p.result,errno:r?null:p.errno,pairing:p.pairing,result_class:r?'SIGNED_VFS_RETURN':p.outcome,
    requested_bytes:r?r.requested_bytes:p.requested_bytes,returned_bytes:r?r.returned_bytes:p.returned_bytes,
    syscall_duration_ns:entry.kind==='SYSCALL'?entry.duration:null,vfs_read_duration_ns:r?entry.duration:null,path,path_quality:quality};
}
function operationVerb(name,category){
  if(/^execve/.test(name))return '启动程序';if(/^rename/.test(name))return '改名';if(/^(unlink|rmdir)/.test(name))return '删除';
  if(/chmod/.test(name))return '改权限';if(/chown/.test(name))return '改所有者';if(/stat/.test(name))return '查属性';
  if(/^(open|creat)/.test(name))return '打开/创建';if(/^(p?read|preadv)/.test(name))return '读取';if(/^(p?write|pwritev)/.test(name))return '写入';if(name==='close')return '关闭';
  return category==='其他系统调用'?'系统调用':category;
}
function programs(){
  const query=hay($('taskFilter').value.trim()),filter=hay($('threadFilter').value.trim());
  filteredPrograms=programEntries.filter(entry=>!(hasCodexShell&&!query&&kindFor(runtimeTools.get(toolIdentity(entry.thread))||{detail:{}})==='OFFICIAL_CODEX_RUNTIME')&&matches(entry.thread,query)&&(!filter||hay([entry.thread.key,entry.thread.tid,entry.thread.tgid,entry.thread.comm].join(' ')).includes(filter))&&(entry.t0===null||view0<=entry.t0&&entry.t0<=view1));
  filteredPrograms.sort((a,b)=>(a.t0??Infinity)-(b.t0??Infinity));programPage=0;programTable();
}
function programTable(){
  const pages=Math.max(1,Math.ceil(filteredPrograms.length/100));programPage=Math.max(0,Math.min(programPage,pages-1));
  $('programStatus').textContent=filteredPrograms.length?'当前筛选 '+filteredPrograms.length+' 条实际成功EXEC记录；调用归属未知的记录保留为UNATTRIBUTED，不能按时间相近归到某工具。':'此报告当前窗口没有可展示的EXEC记录（旧格式可能未保留）；不能据此断言没有执行程序，也不以comm历史替代。';
  $('programPage').textContent='第 '+(programPage+1)+' / '+pages+' 页';
  $('programRows').innerHTML=filteredPrograms.slice(programPage*100,(programPage+1)*100).map(entry=>{
    const e=entry.detail,t=entry.thread,f=e.file||{},identity=['mount_id','device','inode','generation'].map(key=>key+'='+cell(f[key])).join(' / ');
    const quality=e.filename_quality==='KERNEL_EXEC_FILENAME_NOT_CANONICAL_PATH'?'内核记录的名称；路径未规范化':e.filename_quality==='READ_FAILED_OR_TRUNCATED'?'名称读取失败或截断':'未采集名称';
    return '<tr><td>'+escapeHtml(entry.t0===null?'未记录':seconds(entry.t0)+'s')+'</td><td><details><summary>查看Agent / 工具</summary>'+escapeHtml(t.agent_id)+'<br>'+escapeHtml(t.tool_call_id)+'</details></td><td>PID '+escapeHtml(t.tgid)+' / TID '+escapeHtml(t.tid)+'<details><summary>更多身份</summary>old_tid '+escapeHtml(cell(e.old_tid))+'</details></td><td><code>'+escapeHtml(e.filename||'未采集 / NOT_CAPTURED')+'</code></td><td><details><summary>'+quality+'</summary>'+escapeHtml(e.filename_quality||'NOT_CAPTURED')+'<br>'+escapeHtml(e.executable_identity_quality||'NOT_CAPTURED')+'</details></td><td><details><summary>查看内核对象</summary>'+escapeHtml(identity)+'</details></td></tr>';
  }).join('');
}
function selectOperations(){
  const mode=$('operationMode').value||'filesystem',scope=$('operationScope').value||'tools',outcome=$('operationOutcome').value||'all';
  const query=hay($('operationFilter').value.trim()),task=hay($('taskFilter').value.trim()),threadQuery=hay($('threadFilter').value.trim());
  filteredOperations=operationEntries.filter(entry=>{
    if(mode==='vfs'&&entry.kind!=='VFS_READ'||mode==='syscall'&&entry.kind!=='SYSCALL'||mode==='filesystem'&&entry.kind==='SYSCALL'&&!entry.presentation.is_filesystem_interface)return false;
    if(scope!=='all'&&entry.thread.tool_call_id==='UNATTRIBUTED')return false;
    if(scope!=='all'&&hasCodexShell&&!task&&kindFor(runtimeTools.get(toolIdentity(entry.thread))||{detail:{}})==='OFFICIAL_CODEX_RUNTIME')return false;
    if(!matches(entry.thread,task)||threadQuery&&!hay([entry.thread.key,entry.thread.tid,entry.thread.tgid,entry.thread.comm].join(' ')).includes(threadQuery))return false;
    if(entry.t0!==null&&entry.t1!==null&&!overlaps(entry,view0,view1))return false;
    const f=operationFields(entry);
    if(scope==='tools'&&f.execution_scope==='OUTSIDE_EXECUTION_STARTUP_OR_OTHER_CONTEXT')return false;
    return (outcome==='all'||f.outcome===outcome)&&(!query||hay(Object.values(f).join(' ')).includes(query));
  });
  filteredOperations.sort($('operationSort').value==='duration'?(a,b)=>(b.duration??-1)-(a.duration??-1):(a,b)=>(a.t0??Infinity)-(b.t0??Infinity));
  operationPage=0;operationTable();
}
function operationTable(){
  const pages=Math.max(1,Math.ceil(filteredOperations.length/100));operationPage=Math.max(0,Math.min(operationPage,pages-1));
  $('operationStatus').textContent='当前筛选 '+filteredOperations.length+' 条；report共保存 '+operationEntries.filter(e=>e.kind==='SYSCALL').length+' 条syscall与 '+operationEntries.filter(e=>e.kind==='VFS_READ').length+' 条VFS read。每页最多100行；未知时间项保留为UNKNOWN。syscall参数指针不解引用。';
  $('operationPage').textContent='第 '+(operationPage+1)+' / '+pages+' 页';
  $('operationRows').innerHTML=filteredOperations.slice(operationPage*100,(operationPage+1)*100).map((entry,index)=>{
    const f=operationFields(entry),row=operationPage*100+index;
    const outcome=f.outcome==='SUCCESS'?'成功':f.outcome==='ERROR'?'失败':'未确定 / 无普通返回';
    return '<tr><td>'+escapeHtml(f.begin_seconds===null?'未记录':f.begin_seconds.toFixed(6)+'s')+'<br>TID '+escapeHtml(f.tid)+'</td><td>'+escapeHtml(f.kind==='VFS_READ'?'内核文件读取':'系统调用')+'<details><summary>查看工具与范围</summary>'+escapeHtml(f.tool_call_id)+'<br>'+escapeHtml(f.execution_scope)+'</details></td><td><button data-operation-row="'+row+'">'+escapeHtml(operationVerb(f.name,f.operation))+' '+escapeHtml(f.name)+' ('+escapeHtml(cell(f.nr))+')</button><br>'+escapeHtml(f.descriptor)+'</td><td class="'+(f.outcome==='ERROR'?'bad':'')+'">'+outcome+' / '+escapeHtml(cell(f.result))+'<details><summary>返回值解释</summary>'+escapeHtml(f.errno||f.pairing)+' / '+escapeHtml(f.result_class)+'</details></td><td>'+escapeHtml(cell(f.requested_bytes))+' / '+escapeHtml(cell(f.returned_bytes))+'</td><td>'+escapeHtml(f.syscall_duration_ns===null?'—':ms(f.syscall_duration_ns))+'</td><td>'+escapeHtml(f.vfs_read_duration_ns===null?'—':ms(f.vfs_read_duration_ns))+'</td><td><code>'+escapeHtml(f.path)+'</code><details><summary>查看路径质量</summary>'+escapeHtml(f.path_quality)+'</details></td></tr>';
  }).join('');
}
function saveText(text,name,type){const url=URL.createObjectURL(new Blob([text],{type})),link=document.createElement('a');link.href=url;link.download=name;document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function downloadOperations(){
  const records=filteredOperations.map(operationFields),fields=Object.keys(records[0]||operationFields({kind:'SYSCALL',presentation:{vfs_reads:[]},thread:{},call:{}}));
  const csv=value=>{let s=cell(value);if(typeof value==='string'&&/^[=+@\-\t\r]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"';};
  saveText(fields.map(csv).join(',')+'\n'+records.map(row=>fields.map(field=>csv(row[field])).join(',')).join('\n')+'\n','observed-operations-filtered.csv','text/csv;charset=utf-8');
}
const overlaps=(value,a,b)=>value.t0!==null&&value.t1>=a&&value.t0<=b;
const toolOverlaps=(value,a,b)=>overlaps(value,a,b)||(value.dispatch_prelude&&overlaps(value.dispatch_prelude,a,b));
function matches(value,query){const tool=value.detail?.command?value:runtimeTools.get(toolIdentity(value));return !query||hay([value.agent_id,value.task_id,value.tool_call_id,tool?commandFor(tool):''].join(' ')).includes(query);}
function detailFor(row,segment,omittedByDisplay=false){
  if(row.kind==='tool')return {kind:row.tool.detail.status==='NO_RUNTIME_TOOL_SPAN'?'UNRESOLVED_TOOL_ASSOCIATION_NOT_A_RUNTIME_SPAN':segment?.state==='RUNTIME_DISPATCH'?'RUNTIME_DISPATCH_PRELUDE_NOT_WORKER_STATE':'RUNTIME_DECLARED_EXECUTION_WINDOW',timing:row.tool.timing||{invocation_status:'NOT_RECORDED'},tool:row.tool.detail,segment:segment?.detail||null};
  if(row.kind==='critical')return {kind:'REPLAY_DERIVED_COMPLETION_PATH_WITHIN_SELECTED_MODEL',tool:row.critical.detail,segment:segment?segment.detail:null};
  const thread=row.thread;
  if(!thread)return {kind:row.kind,label:row.label};
  if(!segment)return {kind:'VIEWER_DERIVED_GAP_NOT_AN_ORIGINAL_EVENT',state:'UNKNOWN',reason:'此时刻没有可显示的 replay 状态区间；不当作运行或空闲证明',thread:thread.detail};
  const calls=[];let callCount=0,untimed=0;
  for(const call of thread.calls){if(call.t0===null){untimed++;continue;}if(overlaps(call,segment.t0,segment.t1)){callCount++;if(calls.length<50)calls.push(call.detail);}}
  return {kind:'REPLAY_DERIVED_THREAD_INTERVAL',display_omitted:omittedByDisplay,
    state:segment.state,unsupported_state:segment.unsupported_state,
    elapsed_ns:segment.t1-segment.t0,syscall_elapsed_ns:segment.syscall_elapsed_ns,
    file_read_intervals:segment.file_read_intervals,thread:thread.detail,segment:segment.detail,
    overlapping_calls_not_causal_proof:calls,
    overlapping_call_count:callCount,calls_omitted_from_inspector:Math.max(0,callCount-50),
    untimed_calls_not_associated_by_guess:untimed,
    missing_evidence_note:'没有文件或stack字段时保持未知；完整calls和JSON下载未裁剪。'};
}
function addRows(){
  rows=model.critical.filter(item=>item.tool_call_id==='ALL_TOOLS').map(item=>({kind:'critical',label:'派生聚合完成路径',critical:item}));
  const task=hay($('taskFilter').value.trim()),filter=hay($('threadFilter').value.trim());
  const limit=Math.max(1,Math.min(256,Number($('maxThreads').value)||128));
  const matched=model.threads.filter(thread=>matches(thread,task)&&(!filter||hay([thread.key,thread.tid,thread.tgid,thread.comm].join(' ')).includes(filter))&&overlaps(thread,view0,view1));
  const chosen=matched.slice(0,limit),agents=new Set(),tools=new Set(),processes=new Set();
  const toolMap=new Map(model.tools.map(tool=>[toolIdentity(tool),tool]));
  function group(thread){
    const agent=thread.agent_id||'UNATTRIBUTED', tk=toolIdentity(thread);
    if(!agents.has(agent)){rows.push({kind:'agent',label:'Agent  '+agent});agents.add(agent);}
    if(!tools.has(tk)){
      const tool=toolMap.get(tk);
      rows.push({kind:'tool',label:'  Tool  '+thread.tool_call_id,tool:tool||{t0:thread.t0,t1:thread.t1,detail:{status:'NO_RUNTIME_TOOL_SPAN',agent_id:agent,tool_call_id:thread.tool_call_id}}});
      tools.add(tk);
      const cp=model.critical.find(item=>item.tool_call_id===thread.tool_call_id&&(!item.agent_id||item.agent_id===agent));
      if(cp)rows.push({kind:'critical',label:'    派生完成路径',critical:cp});
    }
    const pk=JSON.stringify([tk,thread.process_key]);
    if(!processes.has(pk)){rows.push({kind:'process',label:'    PID '+thread.tgid+(thread.process_identity_quality.startsWith('UNRESOLVED')?' [身份未闭合]':'')});processes.add(pk);}
    rows.push({kind:'thread',label:'      TID '+thread.tid+'  '+thread.comm,thread});
  }
  chosen.forEach(group);
  if(!filter){
    let spare=limit;
    for(const tool of model.tools){
      if(spare<=0)break;
      if(!matches(tool,task)||!toolOverlaps(tool,view0,view1)||tools.has(toolIdentity(tool)))continue;
      if(!agents.has(tool.agent_id)){rows.push({kind:'agent',label:'Agent  '+tool.agent_id});agents.add(tool.agent_id);}
      rows.push({kind:'tool',label:'  Tool  '+tool.tool_call_id,tool});tools.add(toolIdentity(tool));spare--;
    }
  }
  const omittedRows=Math.max(0,rows.length-MAX_ROWS);rows=rows.slice(0,MAX_ROWS);
  return {matched:matched.length,shown:rows.filter(row=>row.kind==='thread').length,total:model.threads.length,omittedRows};
}
function drawSegment(row,segment,y,color){
  const begin=Math.max(view0,segment.t0),end=Math.min(view1,segment.t1);
  if(end<begin)return;
  if(drawn>=MAX_SEGMENTS){omitted++;return;}
  const x=LEFT+(begin-view0)*scale,w=Math.max(1,(end-begin)*scale);
  ctx.fillStyle=color||COLORS[segment.state]||COLORS.UNKNOWN;ctx.fillRect(x,y+5,w,15);
  if(segment.state==='UNKNOWN'&&!color){ctx.strokeStyle='#373737';ctx.strokeRect(x,y+5,w,15);}
  row.hits.push({x0:x,x1:x+w,segment});drawn++;
}
function render(){
  const from=Number($('start').value)*1e9,to=Number($('end').value)*1e9;
  if(!Number.isFinite(from)||!Number.isFinite(to)||to<=from||from<0||to>model.duration_ns+1){$('coverage').textContent='时间窗口无效，请使用运行范围内的起止秒。';return;}
  view0=from;view1=Math.min(to,model.duration_ns);drawn=0;omitted=0;
  const count=addRows(),width=Math.max(1050,$('plot').clientWidth-2);
  canvas.width=width;canvas.height=Math.max(180,TOP+rows.length*ROW+28);scale=(width-LEFT-20)/(view1-view0);
  ctx.fillStyle='white';ctx.fillRect(0,0,canvas.width,canvas.height);ctx.font='12px system-ui,sans-serif';
  for(let i=0;i<=6;i++){const t=view0+(view1-view0)*i/6,x=LEFT+(t-view0)*scale;ctx.strokeStyle='#e3e7ee';ctx.beginPath();ctx.moveTo(x,24);ctx.lineTo(x,canvas.height);ctx.stroke();ctx.fillStyle='#46516a';ctx.fillText(seconds(t)+'s',x-12,16);}
  rows.forEach((row,index)=>{
    const y=TOP+index*ROW;row.hits=[];
    if(row.kind==='agent'){ctx.fillStyle='#eaf0fa';ctx.fillRect(0,y,width,ROW);}
    ctx.fillStyle='#19202b';ctx.save();ctx.beginPath();ctx.rect(0,y,LEFT-8,ROW);ctx.clip();ctx.fillText(row.label,8,y+17);ctx.restore();
    if(row.kind==='tool'){
      const prelude=row.tool.dispatch_prelude;
      if(prelude&&prelude.t1>prelude.t0)drawSegment(row,prelude,y,'#d7ccea');
      if(row.tool.detail.status!=='NO_RUNTIME_TOOL_SPAN'&&overlaps(row.tool,view0,view1))drawSegment(row,row.tool,y,'#5c477e');
      return;
    }
    if(row.kind!=='thread'&&row.kind!=='critical')return;
    const parts=row.kind==='thread'?row.thread.segments:row.critical.segments;
    let perRow=0;
    if(row.kind==='thread'){ctx.strokeStyle='#c9ced8';ctx.setLineDash([2,3]);ctx.beginPath();ctx.moveTo(LEFT,y+12);ctx.lineTo(width-20,y+12);ctx.stroke();ctx.setLineDash([]);}
    for(const part of parts){
      if(!overlaps(part,view0,view1))continue;
      if(drawn>=MAX_SEGMENTS||perRow>=MAX_PER_ROW){omitted++;continue;}
      drawSegment(row,part,y);perRow++;
    }
  });
  $('coverage').textContent='线程：显示 '+count.shown+' / 筛选匹配 '+count.matched+' / 总计 '+count.total+'；绘制区间 '+drawn+'，当前窗口因显示上限省略区间 '+omitted+' / 泳道 '+count.omittedRows+'。图形省略不等于证据 UNKNOWN；缩小窗口或筛选可继续查看，完整 JSON 从未裁剪。';
  const visibleTools=model.tools.filter(tool=>matches(tool,hay($('taskFilter').value.trim()))&&toolOverlaps(tool,view0,view1));
  $('toolTiming').textContent=visibleTools.slice(0,256).map(tool=>{
    const timing=tool.timing,ns=value=>value===null?'UNKNOWN':String(value)+' ns';
    return 'Agent='+tool.agent_id+' / Tool='+tool.tool_call_id+' / Task='+tool.task_id+'\n  完整调用墙钟='+ns(timing.tool_call_wall_ns)+'；执行窗口='+ns(timing.execution_window_ns)+'；派发前奏='+ns(timing.dispatch_prelude_ns)+'；invocation='+timing.invocation_status;
  }).join('\n')+(visibleTools.length>256?'\n其余 '+(visibleTools.length-256)+' 项见完整JSON。':'');
  overview();programs();selectOperations();
}
function locate(event){
  const rect=canvas.getBoundingClientRect(),x=(event.clientX-rect.left)*canvas.width/rect.width,y=(event.clientY-rect.top)*canvas.height/rect.height;
  const row=rows[Math.floor((y-TOP)/ROW)];if(!row)return null;
  const hit=row.hits.find(value=>x>=value.x0&&x<=value.x1);
  if(hit)return {row,segment:hit.segment,displayOmitted:false};
  if(row.thread&&x>=LEFT){const t=view0+(x-LEFT)/scale,part=row.thread.segments.find(value=>value.t0<=t&&t<=value.t1);return {row,segment:part||null,displayOmitted:Boolean(part)};}
  return {row,segment:null,displayOmitted:false};
}
canvas.addEventListener('mousemove',event=>{const hit=locate(event);if(!hit){$('tip').style.display='none';return;}const part=hit.segment,value=part?.detail||{},call=value.syscall||{},files=Array.isArray(value.files)?value.files:[],stack=Array.isArray(value.stack)?value.stack:[],read=part?.file_read_intervals?.length===1?part.file_read_intervals[0]:{};const text=hit.row.kind==='tool'?((part?.state==='RUNTIME_DISPATCH'?'派发／启动／登记前奏，不是工作线程CPU或I/O':'运行时声明执行窗口 begin→end')+'\n'+pretty(hit.row.tool.timing||{invocation_status:'NOT_RECORDED'})):part?(part.state+'\n'+(value.reason||'原因未知')+'\n区间 elapsed_ns: '+(part.t1-part.t0)+'\nsyscall: '+(call.name??call.nr??'UNKNOWN')+' / result: '+(call.result??'UNKNOWN')+' / elapsed_ns: '+(part.syscall_elapsed_ns??'UNKNOWN')+'\nbytes: requested='+(call.requested_bytes??value.requested_bytes??read.requested_bytes??'UNKNOWN')+', returned='+(call.returned_bytes??value.returned_bytes??read.returned_bytes??'UNKNOWN')+'\nVFS read elapsed_ns: '+(read.elapsed_ns??'UNKNOWN_OR_MULTIPLE')+'\nfiles: '+files.slice(0,2).map(file=>file.path||pretty(file.identity||file)).join(', ')+'\nstack: '+stack.slice(0,3).join(' ← ')):'点击查看 '+hit.row.kind+'；区间缺失不当作运行证明';$('tip').textContent=text;$('tip').style.display='block';$('tip').style.left=Math.max(4,Math.min(event.clientX+12,window.innerWidth-430))+'px';$('tip').style.top=Math.max(4,Math.min(event.clientY+14,window.innerHeight-120))+'px';});
canvas.addEventListener('mouseleave',()=>$('tip').style.display='none');
canvas.addEventListener('click',event=>{const hit=locate(event);if(hit)$('details').textContent=pretty(detailFor(hit.row,hit.segment,hit.displayOmitted));});
$('apply').addEventListener('click',render);
$('overviewRows').addEventListener('click',event=>{const target=event.target.closest?.('[data-overview-tool]');if(!target)return;const tool=model.tools[Number(target.getAttribute('data-overview-tool'))];if(tool){$('taskFilter').value=tool.tool_call_id;render();}});
$('operationRows').addEventListener('click',event=>{const target=event.target.closest?.('[data-operation-row]');if(!target)return;const entry=filteredOperations[Number(target.getAttribute('data-operation-row'))];if(entry)$('operationDetail').textContent=pretty({presentation:operationFields(entry),name_scope:'PRESENTATION_ONLY_X86_64_NAMES_NOT_NEW_OBJECT_EVIDENCE',raw_syscall:entry.call.detail,thread:entry.thread.detail});});
$('operationApply').addEventListener('click',selectOperations);
$('operationExec').addEventListener('click',()=>{$('operationMode').value='syscall';$('operationFilter').value='execve';selectOperations();});
$('operationFilter').addEventListener('keydown',event=>{if(event.key==='Enter')selectOperations();});
['operationMode','operationScope','operationOutcome','operationSort'].forEach(id=>$(id).addEventListener('change',selectOperations));
$('operationPrevious').addEventListener('click',()=>{operationPage--;operationTable();});
$('operationNext').addEventListener('click',()=>{operationPage++;operationTable();});
$('operationCsv').addEventListener('click',downloadOperations);
$('programPrevious').addEventListener('click',()=>{programPage--;programTable();});
$('programNext').addEventListener('click',()=>{programPage++;programTable();});
['taskFilter','threadFilter','start','end','maxThreads'].forEach(id=>$(id).addEventListener('keydown',event=>{if(event.key==='Enter')render();}));
$('reset').addEventListener('click',()=>{$('taskFilter').value='';$('threadFilter').value='';$('start').value='0';$('end').value=String(model.duration_ns/1e9);render();});
$('download').addEventListener('click',()=>{const url=URL.createObjectURL(new Blob([originalText],{type:'application/json'})),link=document.createElement('a');link.href=url;link.download='execution-timeline-full.json';document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);});
$('run').textContent='Run '+model.run.run_id+'  |  Boot '+model.run.boot_id+'  |  时长 '+seconds(model.duration_ns)+' 秒（同一 CLOCK_MONOTONIC 时间轴）';
$('quickSummary').textContent='记录时长 '+seconds(model.duration_ns)+' 秒 · 已登记工具命令 '+model.tools.filter(tool=>kindFor(tool)!=='OFFICIAL_CODEX_RUNTIME').length+' 条 · 内核成功程序启动 '+programEntries.length+' 次'+(model.display_projection?'（当前为显示投影，并非完整计数）':'');
$('criticalStatus').textContent='完成依赖路径状态：'+model.critical_status+'（限定模型的派生结论，非完整性通过标志）';
$('health').textContent=pretty({health:model.health,findings:model.findings,totals:model.totals});
$('start').value=String(model.default_view.t0/1e9);$('end').value=String(model.default_view.t1/1e9);
try{const parameters=new URLSearchParams(window.location?.search||'');if(parameters.has('tool'))$('taskFilter').value=parameters.get('tool');if(['filesystem','syscall','vfs'].includes(parameters.get('kind')))$('operationMode').value=parameters.get('kind');}catch{}
if(!$('taskFilter').value&&window.location?.hash?.startsWith('#tool=')){try{$('taskFilter').value=decodeURIComponent(window.location.hash.slice(6));}catch{}}
render();
window.addEventListener('resize',render);
</script></body></html>'''

PROGRAM_CARD = r'''<section class="card" id="programCard"><h2>实际启动了哪些程序：内核成功 EXEC 记录</h2><p class="muted">这里只列 sched_process_exec 成功事件，不以线程 comm 名称猜测程序。filename 是内核执行名称，不保证规范绝对路径；文件对象可能是脚本解释器，argv 未采集。旧版本没有 filename 时明确显示 NOT_CAPTURED。</p><p id="programStatus"></p><div class="page-nav"><button id="programPrevious">上一页</button><span id="programPage"></span><button id="programNext">下一页</button></div><div class="table-scroll"><table><thead><tr><th>相对时刻</th><th>Agent / 工具</th><th>PID / TID</th><th>内核执行名称</th><th>名称质量 / 身份质量</th><th>内核文件对象</th></tr></thead><tbody id="programRows"></tbody></table></div></section>'''
HTML = HTML.replace('<section class="card" id="operationCard">', PROGRAM_CARD + '\n<section class="card" id="operationCard">', 1)
HTML = HTML.replace('<section class="card" id="operationCard">', '<span id="operations"></span><section class="card" id="operationCard">', 1)
HTML = HTML.replace('<option value="tools">已归属工具线程</option>', '<option value="tools">工具执行窗口（含跨界/未知）</option><option value="lifetime">已归属线程全部生命周期</option>', 1)
HTML = HTML.replace('<div class="notice">这是一份离线可视化', '<p class="plain-note">先看命令、执行了什么程序，再查文件和系统调用。只有排查等待原因时，才需要展开线程细节。缺少的证据会明确写为 UNKNOWN，不会补猜。</p><details class="card"><summary>观测与可信边界（需要时展开）</summary><div class="notice">这是一份离线可视化', 1)
HTML = HTML.replace('UNKNOWN 不表示通过。</div>', 'UNKNOWN 不表示通过。</div></details>', 1)
HTML = HTML.replace('Agent / task / tool 筛选', '筛选 Agent / 任务 / 命令', 1)
HTML = HTML.replace('placeholder="输入标识子串"', 'placeholder="如 cat、grep 或 Agent 名称"', 1)
HTML = HTML.replace('当前 EXEC hook 未采集可执行文件路径；execve 表能显示发起线程与调用时刻，不能从用户指针猜程序路径。', '旧报告可能未采集执行名称。新版本的实际成功程序请看上方 EXEC 表；syscall 表仍不能从用户指针猜路径。EXEC filename 不是规范路径，argv 未采集。', 1)
HTML = HTML.replace('<p id="run"></p>', '<p id="quickSummary"></p><details class="card"><summary>记录身份与精确时钟</summary><p id="run"></p></details>', 1)
HTML = HTML.replace('<div class="card controls">', '<details class="card"><summary>高级筛选：Agent、线程、时间窗口</summary><div class="controls">', 1)
HTML = HTML.replace('</div>\n<section class="card" id="overviewCard">', '</div></details>\n<section class="card" id="overviewCard">', 1)


def render_report(report, context_label=None):
    """Return one self-contained HTML document without changing the report."""
    original = embedded(report)
    require(len(original.encode('utf-8')) <= MAX_REPORT_BYTES, 'complete report exceeds 64 MiB display input limit')
    model = model_for(report)
    prefix, rest = HTML.split('__REPORT_JSON__')
    middle, suffix = rest.split('__TIMELINE_MODEL__')
    html = prefix + original + middle + embedded(model) + suffix
    if context_label is not None:
        from html import escape
        require(isinstance(context_label, str) and 0 < len(context_label) <= 1000, 'bounded presentation context required')
        html = html.replace('<h1>Agent → 工具 → 进程 / 线程时间线</h1>', '<h1>Agent → 工具 → 进程 / 线程时间线</h1><div class="notice">展示说明：' + escape(context_label) + '</div>', 1)
    projection = report.get('display_projection')
    if isinstance(projection, dict):
        from html import escape
        require(projection.get('status') == 'DISPLAY_ONLY_BOUNDED_PROJECTION',
                'explicit display-only projection status required')
        links = [('完整合成JSON（可能较大）', projection.get('complete_report_href')),
                 ('完整单Agent结果导航', projection.get('index_href'))]
        anchors = []
        for label, href in links:
            require(isinstance(href, str) and href and not Path(href).is_absolute()
                    and '..' not in Path(href).parts and ':' not in href and '\\' not in href,
                    'bounded relative projection navigation required')
            anchors.append('<a href="{}">{}</a>'.format(escape(href, quote=True), escape(label)))
        notice = ('<div class="notice"><strong>DISPLAY_ONLY_BOUNDED_PROJECTION：当前合成图是显示子集。</strong>'
            '<p>未显示的区间不代表未发生，也不补成运行或等待；原始health和完成路径状态不因裁显变绿。'
            '按钮只下载当前显示投影，完整数据请用下列链接。</p><p>' + ' · '.join(anchors)
            + '</p><pre>' + escape(json.dumps(projection, ensure_ascii=False, indent=2)) + '</pre></div>')
        html = html.replace('<h1>Agent → 工具 → 进程 / 线程时间线</h1>',
                            '<h1>Agent → 工具 → 进程 / 线程时间线</h1>' + notice, 1)
        html = html.replace('execution-timeline-full.json', 'execution-timeline-display-projection.json')
        html = html.replace('下载完整 JSON</button>', '下载当前显示投影 JSON</button>')
        html = html.replace('health / findings / totals（原始字段）', 'health / findings / totals（findings为显示子集）')
        html = html.replace('完整 JSON 下载保留原整数和所有未展示字段', '当前显示投影下载保留原整数；完整JSON另见顶部导航')
        html = html.replace('完整calls和JSON下载未裁剪。', '显示投影不含完整calls；请到该Agent完整JSON或CSV检查。')
    return html


def read_report(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_REPORT_BYTES,
            'bounded regular non-symlink report required (64 MiB maximum)')
    raw = path.read_bytes()
    require(len(raw) <= MAX_REPORT_BYTES, 'report grew beyond 64 MiB limit')
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate JSON key: ' + key)
            value[key] = item
        return value
    def invalid(value):
        raise ValueError('nonfinite JSON value: ' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--context-label', help='presentation-only label; does not alter evidence or verification')
    args = parser.parse_args(argv)
    require(not args.output.exists() and not args.output.is_symlink(), 'fresh output required; existing files are never overwritten')
    html = render_report(read_report(args.report), args.context_label)
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(html)
    return 0


if __name__ == '__main__':
    sys.exit(main())
