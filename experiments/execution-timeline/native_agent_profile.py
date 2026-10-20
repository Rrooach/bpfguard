#!/usr/bin/env python3
"""Profile a real native Codex run without inventing per-tool OS ownership.

Native tool notifications describe application activity. The collector observes
the registered runtime and all descendants. Optional /proc matches remain
candidate links, never a reason to move kernel events into a tool's bucket.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from copy import deepcopy
import errno
import hashlib
from html import escape
import json
import os
from pathlib import Path
import shutil
from urllib.parse import quote

from common import digest, write_new
from execution_metrics import memory_data, model_collection, model_requests, partition_wall, read_jsonl
from interactive_profile_ui import render_profile_panel, _script_json
from render_agent_story import read_json
from runtime_memory_ui import SCRIPT as MEMORY_SCRIPT, STYLE as MEMORY_STYLE
from runtime_rpc_phases import runtime_rpc_phases
from semantic_annotations import apply_annotations, build_annotations, build_trajectory
from semantic_profile import build_profile, fold_view
from syscall_catalog import describe


PAGE_SIZE = 200
CORRELATION_STATUSES = frozenset(('CORRELATED_NOT_CAUSAL', 'AMBIGUOUS', 'UNBOUND'))
GLOBAL_LABEL = '完整运行时：尚未归属到单个原生工具'


def _valid_ns(value):
    return type(value) is int and value >= 0


def _frame(kind, label, **metadata):
    return {'kind': kind, 'label': str(label), **metadata}


def _index(rows, field):
    output = {}
    for index, row in enumerate(rows or []):
        key = row.get(field)
        if not isinstance(key, str) or not key or key in output:
            raise ValueError('missing/duplicate ' + field)
        output[key] = (index, row)
    return output


def _runtime(report, origin, task_id):
    """One kernel call creates exactly one global syscall operation."""
    threads, rows, files, operations = [], [], {}, []
    task = _frame('task', task_id)
    global_frame = _frame('semantic', GLOBAL_LABEL, attribution='WHOLE_RUNTIME_DIRECT_SCOPE_NOT_PER_TOOL')
    for ti, thread in enumerate(report.get('threads', [])):
        if not isinstance(thread, dict) or not isinstance(thread.get('key'), str):
            raise ValueError('native report threads require immutable lifetime keys')
        key, tid, tgid = thread['key'], thread.get('tid'), thread.get('tgid')
        label = '{} [pid {}]'.format(thread.get('comm') or '?', tgid)
        pframe = _frame('process', label, tgid=tgid, process_birth_ns=thread.get('process_birth_ns'))
        tframe = _frame('thread', '{} [tid {}]'.format(thread.get('comm') or '?', tid), tid=tid, thread_key=key)
        base = [task, global_frame, pframe, tframe]
        totals = thread.get('state_totals_ns')
        if isinstance(totals, dict):
            measures = {name: totals[state] / 1e6 for state, name in
                (('ONCPU', 'oncpu_ms'), ('RUNNABLE', 'runnable_ms')) if _valid_ns(totals.get(state))}
            sleep_values = [totals[state] for state in ('SLEEP', 'WAKING') if _valid_ns(totals.get(state))]
            if sleep_values:
                measures['sleep_ms'] = sum(sleep_values) / 1e6
            if measures:
                operations.append({'kind': 'runtime_thread_state', 'stack': base, 'measures': measures,
                    'evidence': {'thread_key': key, 'tid': tid, 'source_ref': f'report#/threads/{ti}/state_totals_ns',
                                 'attribution': 'RUNTIME_ONLY_NOT_ASSIGNED_TO_TOOL'}})
        thread_rows = []
        for ci, call in enumerate(thread.get('calls', [])):
            start, end = call.get('start_ns'), call.get('end_ns')
            paired = call.get('pairing') == 'PAIRED'
            duration = end - start if paired and _valid_ns(start) and _valid_ns(end) and end >= start else None
            presentation = describe(call.get('nr'), call.get('name'))
            result = call.get('result')
            paths, read_values, requested = [], [], []
            for obj in call.get('files', []) or []:
                if isinstance(obj.get('path'), str) and obj['path'] not in paths:
                    paths.append(obj['path'])
                read = obj.get('read')
                if isinstance(read, dict):
                    if _valid_ns(read.get('returned_bytes')):
                        read_values.append(read['returned_bytes'])
                    if _valid_ns(read.get('requested_bytes')):
                        requested.append(read['requested_bytes'])
            row = {'thread_key': key, 'tid': tid, 'tgid': tgid,
                'process_birth_ns': thread.get('process_birth_ns'), 'comm': thread.get('comm'),
                'start_ns': start, 'end_ns': end, 'at_ms': (start - origin) / 1e6 if _valid_ns(start) else None,
                'duration_us': duration / 1e3 if duration is not None else None,
                'name': presentation['name'], 'nr': call.get('nr'), 'category': presentation.get('category'),
                'result': result, 'errno': errno.errorcode.get(-result) if paired and type(result) is int and result < 0 else None,
                'pairing': call.get('pairing', 'NOT_RECORDED'), 'paths': paths,
                'returned_bytes': sum(read_values) if read_values else None,
                'requested_bytes': sum(requested) if requested else None,
                'source_ref': f'report#/threads/{ti}/calls/{ci}',
                'attribution': 'RUNTIME_ONLY_NOT_ASSIGNED_TO_TOOL'}
            rows.append(row); thread_rows.append(row)
            measures = {'syscall_count': 1}
            if duration is not None:
                measures['syscall_time_ms'] = duration / 1e6
            operations.append({'kind': 'runtime_syscall', 'stack': base + [
                _frame('syscall_category', presentation.get('category') or 'other'),
                _frame('syscall', presentation['name'])], 'measures': measures,
                'evidence': {k: row[k] for k in ('thread_key', 'tid', 'result', 'errno', 'at_ms', 'source_ref', 'attribution')}})
            if paths or read_values:
                # A rename can expose two paths. The operation and returned
                # bytes are counted once, with other paths kept as evidence.
                measures = {'file_operations': 1}
                if row['returned_bytes'] is not None:
                    measures['file_read_bytes'] = row['returned_bytes']
                primary = paths[0] if paths else '对象路径未解析（读取字节已测量）'
                operations.append({'kind': 'runtime_file', 'stack': base + [_frame('file', primary, path=paths[0] if paths else None)],
                    'measures': measures, 'evidence': {'path': paths[0] if paths else None, 'additional_paths': max(0,len(paths)-1),
                        'tid': tid, 'syscall': presentation['name'], 'source_ref': row['source_ref'],
                        'attribution': 'RUNTIME_ONLY_NOT_ASSIGNED_TO_TOOL'}})
            for path in paths:
                item = files.setdefault(path, {'path': path, 'calls': 0, 'read_bytes_observed': None, 'thread_keys': set()})
                item['calls'] += 1; item['thread_keys'].add(key)
                # Bytes only enter the primary resolved-object row. Never
                # duplicate an operation's bytes for additional path names.
                if path == paths[0] and row['returned_bytes'] is not None:
                    item['read_bytes_observed'] = (item['read_bytes_observed'] or 0) + row['returned_bytes']
        threads.append({'key': key, 'parent_key': thread.get('parent_key'), 'tid': tid, 'tgid': tgid,
            'birth_ns': thread.get('birth_ns', thread.get('thread_birth_ns')), 'process_birth_ns': thread.get('process_birth_ns'),
            'comm': thread.get('comm'), 'calls': len(thread_rows), 'state_totals_ns': totals,
            'source_ref': f'report#/threads/{ti}', 'tool_assignment': 'NOT_ESTABLISHED'})
    for item in files.values():
        item['thread_keys'] = sorted(item['thread_keys'])
    return {'scope': GLOBAL_LABEL, 'threads': threads,
            'files': sorted(files.values(), key=lambda x: (-x['calls'], x['path'])),
            'total_syscalls': len(rows), 'unassigned_syscalls': len(rows),
            'assigned_syscalls': 0, 'distinct_resolved_paths': len(files),
            'read_bytes_observed': sum(row['returned_bytes'] for row in rows if row['returned_bytes'] is not None)
                if any(row['returned_bytes'] is not None for row in rows) else None}, rows, operations


def _native_model_tools(application, rpc_rows, timing_rows, story, annotations):
    """Replay model-call IDs independently; do not invent nested command IDs."""
    from native_raw_tools import replay_native_raw_tools
    if rpc_rows:
        for row in rpc_rows:
            if (row.get('message') or {}).get('method') not in ('rawResponseItem/completed','rawResponse/completed'):
                continue
            stamp=row.get('receipt_ns')
            if (row.get('clock')!='CLOCK_MONOTONIC' or row.get('boot_id')!=story['boot_id'] or
                    not _valid_ns(stamp) or not story['begin_ns']<=stamp<=story['end_ns']):
                raise ValueError('native raw model event clock/boot/window mismatch')
        projection=replay_native_raw_tools(rpc_rows,thread_id=application.get('thread_id'),turn_id=application.get('turn_id'))
        rows=projection['native_model_tool_calls']
        if application.get('native_model_tool_calls') is not None:
            declared=_index(application['native_model_tool_calls'],'call_id')
            if set(declared)!={row['call_id'] for row in rows}:
                raise ValueError('native model tool identities differ from immutable RPC replay')
            # The run loop may timestamp the handler after CodexRPC has
            # durably timestamped receipt. Content/hash identity must match;
            # the two explicitly different observation points are not forced
            # to have the same number or silently substituted in the source.
            ignored={'request_received_ns','output_received_ns','request_to_output_ms'}
            def content(value):
                result={key:deepcopy(item) for key,item in value.items() if key not in ignored}
                for field in ('source_request','source_output'):
                    if isinstance(result.get(field),dict):result[field].pop('receipt_ns',None)
                return result
            for row in rows:
                original=declared[row['call_id']][1]
                if content(row)!=content(original):
                    raise ValueError('native model tool content/message identity differs from immutable RPC replay')
                a,b=original.get('request_received_ns'),original.get('output_received_ns')
                if (not _valid_ns(a) or not story['begin_ns']<=a<=story['end_ns'] or
                        (b is not None and (not _valid_ns(b) or not a<=b<=story['end_ns']))):
                    raise ValueError('native application handler boundaries invalid')
                if b is not None and (type(original.get('request_to_output_ms')) not in (int,float) or
                        abs(original['request_to_output_ms']-(b-a)/1e6)>1e-9):
                    raise ValueError('native application handler duration differs from its own boundaries')
                row['application_handler_timing']={key:original.get(key) for key in ignored}
                row['timing_source_reconciliation']='PROFILE_USES_RAW_RPC_LEDGER_RECEIPT; HANDLER_RECEIPTS_PRESERVED_SEPARATELY'
        source='RAW_NATIVE_RPC_REPLAY'
    else:
        rows=deepcopy(application.get('native_model_tool_calls') or [])
        source='APPLICATION_PROJECTION_ONLY_NO_RAW_REPLAY'
    final_requests={row.get('request_id'):row for row in timing_rows or [] if row.get('event')=='MODEL_REQUEST_FINISHED'}
    taxonomy=annotations['taxonomy'];output=[]
    for row in rows:
        request_links=[request for request in story['model_requests'] if row['call_id'] in
            (final_requests.get(request['request_id'],{}).get('output_tool_call_ids') or [])]
        paths={tuple(request['semantic_path']) for request in request_links}
        row=deepcopy(row)
        row['number']=len(output)+1
        row['semantic_path']=list(next(iter(paths))) if len(paths)==1 else [taxonomy['task'],taxonomy['unassigned']]
        row['semantic_quality']='EXACT_MODEL_OUTPUT_CALL_ID_TO_REQUEST_STAGE; NOT_CHILD_TOOL_OR_KERNEL_CAUSALITY' if request_links else 'NO_EXACT_MODEL_REQUEST_LINK'
        row['provider_request_ids']=[request['request_id'] for request in request_links]
        row['source_replay']=source
        row['source_refs']=[]
        for index,raw in enumerate(rpc_rows or []):
            message=raw.get('message') or {};item=(message.get('params') or {}).get('item') or {}
            if message.get('method')=='rawResponseItem/completed' and item.get('call_id')==row['call_id']:
                row['source_refs'].append('rpc#/'+str(index))
        for request in request_links:
            request.setdefault('native_output_tool_call_ids',[]).append(row['call_id'])
            request['native_output_association']='EXACT_PROVIDER_OUTPUT_CALL_ID_NOT_INNER_COMMAND_PARENT_PROOF'
        output.append(row)
    return output


def _refine_outer_wall(partition, outer_tools):
    """A native model-tool envelope refines only otherwise unmeasured gaps.

    Known model/inner-tool intervals remain unchanged and are not counted a
    second time. Envelope overlap is not labelled parallel JS execution.
    """
    tools=[row for row in outer_tools if _valid_ns(row.get('request_received_ns')) and
           _valid_ns(row.get('output_received_ns')) and row['output_received_ns']>=row['request_received_ns']]
    segments=[];totals=defaultdict(int)
    for segment in partition['segments']:
        if segment['kind']!='UNRESOLVED_RUNTIME':
            segments.append(segment);totals[segment['kind']]+=segment['duration_ns'];continue
        a,b=segment['begin_ns'],segment['end_ns']
        boundaries=sorted({a,b}|{stamp for row in tools for stamp in
            (row['request_received_ns'],row['output_received_ns']) if a<stamp<b})
        for lo,hi in zip(boundaries,boundaries[1:]):
            active=[row for row in tools if row['request_received_ns']<=lo<row['output_received_ns']]
            result={**segment,'begin_ns':lo,'end_ns':hi,'duration_ns':hi-lo}
            if active:
                result.update(kind='NATIVE_MODEL_TOOL_WINDOW',label='原生 Code Mode／模型工具窗口（内部未细分）',
                    active_ids=[row['call_id'] for row in active],
                    semantic_path=active[0]['semantic_path'] if len(active)==1 else [],
                    native_outer_ids=[row['call_id'] for row in active])
            segments.append(result);totals[result['kind']]+=hi-lo
    partition.update(segments=segments,totals_ns=dict(totals))
    partition['labels']['NATIVE_MODEL_TOOL_WINDOW']='原生模型工具窗口（非 JS CPU）'
    if sum(totals.values())!=partition['wall_ns']:
        raise ValueError('native outer-window refinement lost wall conservation')


def compile_native_profile(report, application, *, tool_results=None, correlations=None,
                           model_timing=None, model_summary=None, resource_summary=None,
                           resource_samples=None, rpc_rows=None, semantic_annotations=None):
    if application.get('schema_version') != 2 or application.get('function_bindings'):
        raise ValueError('native schema2 without fabricated function bindings required')
    run = report.get('run', {})
    begin, end = run.get('begin_ns'), run.get('end_ns')
    if not _valid_ns(begin) or not _valid_ns(end) or end < begin or not run.get('boot_id'):
        raise ValueError('native runtime report requires ordered boot-bound capture boundaries')
    tools_by_call = _index(application.get('tool_calls', []), 'call_id')
    results = _index(tool_results if tool_results is not None else application.get('native_tool_results', []), 'call_id')
    if set(results) - set(tools_by_call):
        raise ValueError('native result belongs to unknown call')
    raw_correlations = (correlations or {}).get('links', [])
    corr = _index(raw_correlations, 'call_id')
    if set(corr) - set(tools_by_call):
        raise ValueError('native correlation belongs to unknown call')
    task_id = application.get('task_id') or run.get('task_id') or 'native-task'
    runtime, syscall_rows, runtime_operations = _runtime(report, begin, task_id)
    thread_map = {row['key']: row for row in runtime['threads']}
    tools = []
    for call_id, (index, call) in tools_by_call.items():
        start, finish = call.get('requested_ns'), call.get('result_delivered_ns')
        if start is not None and (not _valid_ns(start) or not begin <= start <= end):
            raise ValueError('native tool request outside runtime capture')
        if finish is not None and (not _valid_ns(finish) or not _valid_ns(start) or not start <= finish <= end):
            raise ValueError('native tool result outside ordered runtime capture')
        _, result = results.get(call_id, (None, {}))
        _, correlation = corr.get(call_id, (None, {'call_id': call_id, 'status': 'UNBOUND', 'candidates': [],
                                                  'reason': 'NO_CORRELATION_ARTIFACT'}))
        if correlation.get('status') not in CORRELATION_STATUSES:
            raise ValueError('unsupported native process association; no causal claim accepted')
        for candidate in correlation.get('candidates', []):
            thread = thread_map.get(candidate.get('thread_key'))
            if thread is None or candidate.get('pid') != thread.get('tid'):
                raise ValueError('native process candidate absent from immutable kernel lifetime')
        args = call.get('arguments') or {}
        duration = (finish - start) / 1e6 if _valid_ns(start) and _valid_ns(finish) else None
        tools.append({'number': index+1, 'call_id': call_id, 'tool_call_id': 'native-application:'+call_id,
            'tool_name': call.get('tool_name'), 'command': args.get('command') if isinstance(args, dict) else None,
            'arguments': args, 'status': call.get('status'), 'exit_code': result.get('exit_code', call.get('exit_code')),
            'requested_ns': start, 'delivered_ns': finish,
            # These are application-observation windows, not OS exec boundaries.
            'execution_begin_ns': start, 'execution_end_ns': finish, 'total_ms': duration,
            'timing_scope': 'NATIVE_APPLICATION_ITEM_OBSERVED_START_TO_RESULT_INCLUDES_FRAMEWORK',
            'result': result, 'correlation': deepcopy(correlation),
            'kernel_binding': 'NOT_ESTABLISHED', 'syscall_rows': [], 'process_profiles': [], 'resources': None,
            'source_ref': f'application#/tool_calls/{index}'})
    agent_id = application.get('agent_id') or run.get('agent_id') or 'native-agent'
    task_id = application.get('task_id') or run.get('task_id') or 'native-task'
    requests = model_requests(deepcopy(model_timing or []), tools, run['boot_id'], application.get('budget_label'))
    story = {'schema_version': 2, 'mode': 'OFFICIAL_CODEX_NATIVE_TOOLS_NO_REPLACEMENT',
        'run_id': run.get('run_id'), 'agent_id': agent_id, 'task_id': task_id,
        'boot_id': run['boot_id'], 'begin_ns': begin, 'end_ns': end, 'agent_wall_ms': (end-begin)/1e6,
        'application_begin_ns': application.get('begin_ns'), 'application_end_ns': application.get('end_ns'),
        'wall_scope': 'FULL_RUNTIME_CAPTURE_INCLUDING_STARTUP_AND_FINAL_SHUTDOWN',
        'status': application.get('status'), 'errors': deepcopy(application.get('errors', [])),
        'application_error': application.get('error'), 'tools': tools, 'model_requests': requests,
        'code_mode': {'status': 'NOT_EXPOSED', 'invocations': [],
            'reason': '真实 Code Mode 已由原生 Codex 执行；当前协议不暴露内部 JS／await 或独立 heap，不能从 syscall 推断。'},
        'model_collection': model_collection(model_timing or [], requests, model_summary,
            application.get('budget_label'), run['boot_id']),
        'runtime': runtime, 'health': report.get('health', {}), 'critical_path': report.get('critical_path', {}),
        'memory': memory_data(resource_summary, resource_samples or [], run['boot_id'], begin, end, agent_id),
        'limitations': ['工具结果为 Codex 原生通知，不是独立判题成功。',
            '候选进程关联不是 call_id 到 OS dispatch 的证明；不按时间把 syscall 或内存摊给工具。',
            '内核指标全部保留在完整 runtime 分支；任何已知部分与缺失、未归属同时展示。']}
    rpc_phases = runtime_rpc_phases(rpc_rows or [], run['boot_id'], begin, end)
    story['runtime_phases'] = rpc_phases
    story['wall_partition'] = partition_wall(begin, end, tools, requests, story['code_mode'], run['boot_id'], rpc_phases)
    proxy_labels={'MODEL_WAIT':'客户端等待模型代理首字节','MODEL_RECEIVE':'客户端接收模型代理响应'}
    story['wall_partition']['labels'].update(proxy_labels)
    for segment in story['wall_partition']['segments']:
        if segment['kind'] in proxy_labels:segment['label']=proxy_labels[segment['kind']]
    trajectory = build_trajectory(application, story, rpc_rows)
    annotations = build_annotations(trajectory, semantic_annotations)
    story = apply_annotations(story, annotations)
    story['native_model_tools']=_native_model_tools(application,rpc_rows,model_timing,story,annotations)
    _refine_outer_wall(story['wall_partition'],story['native_model_tools'])
    code_mode_count=sum(row.get('runtime')=='NATIVE_CODE_MODE' for row in story['native_model_tools'])
    if code_mode_count:
        story['code_mode'].update(status='NATIVE_EXEC_WINDOWS_COLLECTED_JS_INTERNAL_NOT_EXPOSED',
            reason=f'已采集 {code_mode_count} 次真实原生 Code Mode exec 的 JS 源码和请求／输出窗口；内部 JS／await 切片、CPU 和独立 heap 仍未暴露。内层 commandExecution 没有协议父 ID，不按时间强认父子。')
    # Provider token totals carry exact request identity, not an invented tool.
    usage = []
    for request in story['model_requests']:
        raw = request.get('usage') or {}
        if type(raw.get('total_tokens')) is int and raw['total_tokens'] >= 0:
            usage.append({'number': len(usage)+1, 'request_id': request['request_id'],
                'semantic_path': request['semantic_path'], 'totalTokens': raw['total_tokens'],
                'inputTokens': raw.get('input_tokens'), 'outputTokens': raw.get('output_tokens'),
                'source': 'EXPLICIT_PROVIDER_HTTP_USAGE', 'attribution': 'REQUEST_ID_NOT_TOOL_PROCESS_BINDING'})
    story['model_usage'] = usage
    profile = build_profile(story)
    outer_by_id={row['call_id']:row for row in story['native_model_tools']}
    wall_by_bounds={(row['begin_ns'],row['end_ns']):row for row in story['wall_partition']['segments']}
    for operation in profile['operations']:
        if operation['kind']!='wall_partition':continue
        evidence=operation.get('evidence',{});segment=wall_by_bounds.get((evidence.get('begin_ns'),evidence.get('end_ns')), {})
        ids=segment.get('native_outer_ids',[])
        if len(ids)==1:
            outer=outer_by_id[ids[0]]
            operation['stack'].insert(-1,_frame('tool','模型原生工具 '+str(outer['number'])+' · '+outer['tool_name'],call_id=outer['call_id'],
                runtime=outer['runtime'],relation='OUTER_WINDOW_ONLY; INNER_COMMAND_PARENT_NOT_EXPOSED'))
    for outer in story['native_model_tools']:
        measures={'native_model_tool_count':1}
        if type(outer.get('request_to_output_ms')) in (int,float) and outer['request_to_output_ms']>=0:
            measures['native_model_tool_ms']=outer['request_to_output_ms']
        profile['operations'].append({'kind':'native_model_tool',
            'stack':[_frame('task',task_id)]+[_frame('semantic',x) for x in outer['semantic_path']]+[
                _frame('tool','模型原生工具 '+str(outer['number'])+' · '+outer['tool_name'],call_id=outer['call_id'],runtime=outer['runtime'],
                       relation='MODEL_TOOL_ITEM_NOT_STRONGLY_BOUND_TO_INNER_COMMANDS')],
            'measures':measures,'evidence':{'call_id':outer['call_id'],'source_refs':outer['source_refs'],
                'attribution':outer['semantic_quality'],'timing_scope':outer.get('timing_scope')}})
    profile['operations'].extend(runtime_operations)
    profile['operation_count'] = len(profile['operations'])
    for tool in story['tools']:
        if tool['total_ms'] is not None:
            profile['operations'].append({'kind': 'native_tool_observed_window',
                'stack': [_frame('task', task_id)] + [_frame('semantic', x) for x in tool['semantic_path']] +
                    [_frame('tool', f"工具 {tool['number']} · {tool['tool_name']}", call_id=tool['call_id'],
                            status=tool['status'], command=tool['command'])],
                'measures': {'native_tool_ms': tool['total_ms']},
                'evidence': {'call_id': tool['call_id'], 'source_ref': tool['source_ref'],
                             'attribution': 'APPLICATION_LIFECYCLE_ONLY_NO_PER_TOOL_KERNEL_BINDING'}})
    profile['views'].append({'name': 'native_tool_ms', 'label': '原生工具累计观察时长', 'unit': 'ms',
        'quality': '工具原生通知边界，含派发和结果返回；并发调用可重叠，不等于总墙钟'})
    profile['views'].extend([{'name':'native_model_tool_count','label':'模型原生工具调用次数（exec 等）','unit':'次',
        'quality':'rawResponseItem 的真实 call_id；与内层 commandExecution 分别计数，不相加当独立任务'},
        {'name':'native_model_tool_ms','label':'模型原生工具父窗口（含 Code Mode）','unit':'ms',
        'quality':'原生请求／匹配输出的客户端边界；不是 JS CPU，可能包围内层工具，不与内层时长相加'}])
    anchors={tool['call_id']:'native-tool-'+str(tool['number']) for tool in story['tools']}
    anchors.update({tool['call_id']:'native-model-tool-'+str(index) for index,tool in enumerate(story['native_model_tools'])})
    for operation in profile['operations']:
        for frame in operation['stack']:
            if frame.get('kind')=='tool' and frame.get('call_id') in anchors:
                frame['detail_anchor']=anchors[frame['call_id']]
    for view in profile['views']:
        tree, count = fold_view(profile['operations'], view['name'],
                                'Observer' if view['name']=='observer_rss_byte_ms' else 'Agent '+agent_id)
        view.update(tree=tree, total=tree['value'], sample_count=count, status='AVAILABLE' if count else 'NOT_COLLECTED')
        if view['name'] == 'tool_count':
            view['quality'] = '原生 Codex 显式工具调用次数；不表示已绑定 Linux 进程'
        elif view['name']=='model_wait_ms':
            view.update(label='客户端模型请求等待（代理首字节）',
                quality='Agent侧HTTP边界；预算代理会缓冲provider SSE，不是provider首token、精确推理或GPU时间')
        elif view['name']=='model_receive_ms':
            view.update(label='客户端接收模型代理响应',quality='Agent侧首body字节至代理响应结束；provider原始流可能已被预算代理缓冲')
        elif view['name']=='model_request_ms':
            view.update(label='客户端模型HTTP请求总耗时',quality='客户端代理请求边界，含网络/预算代理/上游处理；并发请求可重叠')
        elif view['name'] in ('syscall_count','syscall_time_ms','file_operations','file_read_bytes','oncpu_ms','runnable_ms','sleep_ms'):
            view['quality'] += '；完整 runtime 范围，不归属给单个原生工具'
    profile.update(operation_count=len(profile['operations']),
        attribution='NATIVE_APPLICATION_CALLS_AND_WHOLE_RUNTIME_KERNEL_EVENTS; CANDIDATES_NOT_CAUSAL',
        hierarchy='Agent → task/phase → native tool OR unassigned runtime → process/thread/object/syscall',
        semantic_quality=annotations['method'])
    profile['limitations'].extend(story['limitations'])
    totals = {view['name']: view['total'] for view in profile['views']}
    if totals['syscall_count'] != runtime['total_syscalls'] or abs(totals['wall_ms']-story['agent_wall_ms']) > 1e-6:
        raise ValueError('native profile failed syscall/wall conservation')
    return {'story': story, 'trajectory': trajectory, 'annotations': annotations,
            'profile': profile, 'syscall_rows': syscall_rows}


STYLE = r'''
body{margin:0;background:#eef3f7;color:#193247;font:14px system-ui,sans-serif}main{max-width:1450px;margin:auto;padding:22px}h1{font-size:27px}h2{font-size:21px}section.native-section,details.native-tool,details.native-model-tool{background:white;border:1px solid #d8e1e8;border-radius:10px;padding:16px;margin:14px 0}.note{color:#52697a;line-height:1.6}.warning{padding:10px;background:#fff1cd;border-left:4px solid #b57909}.metrics{display:flex;gap:16px;flex-wrap:wrap}.metrics div{background:#fff;padding:12px 17px;border:1px solid #d8e1e8;border-radius:8px}.metrics b{display:block;font-size:21px}.controls{display:flex;flex-wrap:wrap;gap:9px;align-items:center;margin:12px 0}button,select,input{font:inherit;border:1px solid #a8b9c5;padding:5px 8px;border-radius:4px;background:white}button{cursor:pointer}pre{background:#f3f6f9;padding:10px;white-space:pre-wrap;word-break:break-word;max-height:290px;overflow:auto}.tables{overflow:auto}table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:7px;border-bottom:1px solid #dce5eb;text-align:left;vertical-align:top;overflow-wrap:anywhere}code{overflow-wrap:anywhere}.muted{color:#617788}.tool-status{font-size:12px;padding:3px 6px;background:#e8f0f5;border-radius:4px}a{color:#146296}.candidate-box{padding:9px;border:1px dashed #c18d35;margin:8px 0}.artifact-list{display:flex;gap:14px;flex-wrap:wrap}.native-tool summary,.native-model-tool summary{cursor:pointer;font-weight:600}.runtime-panel{background:#fff;padding:16px;border:1px solid #d8e1e8;border-radius:10px}.runtime-note{font-size:13px;color:#617788}
'''


PAGER_SCRIPT = r'''
const nativeData=JSON.parse(document.querySelector('#native-view-data').textContent);
const qs=s=>document.querySelector(s);let runtimePage=0,runtimeFiles=[],loadingGeneration=0;
function cell(row,value){const td=document.createElement('td');td.textContent=value==null?'未采集':String(value);row.appendChild(td);return td;}
function selectedPages(){const key=qs('#native-thread').value;return key==='all'?nativeData.pages.all:(nativeData.pages.by_thread[key]||[]);}
async function showRuntimePage(){const generation=++loadingGeneration;const pages=selectedPages();runtimePage=Math.max(0,Math.min(runtimePage,pages.length-1));qs('#native-page-status').textContent=pages.length?'正在加载第 '+(runtimePage+1)+' / '+pages.length+' 页…':'此范围无已保留 syscall';const body=qs('#native-syscalls');body.replaceChildren();qs('#native-prev').disabled=runtimePage<=0;qs('#native-next').disabled=runtimePage>=pages.length-1;if(!pages.length)return;
 try{const response=await fetch(pages[runtimePage]);if(!response.ok)throw new Error('HTTP '+response.status);const payload=await response.json();if(generation!==loadingGeneration)return;if(!Array.isArray(payload.rows)||payload.rows.length>200)throw new Error('分页 schema/上限不匹配');const pattern=qs('#native-filter').value.trim().toLowerCase();let displayed=0;
  for(const call of payload.rows){if(pattern&&!JSON.stringify([call.name,call.comm,call.paths,call.errno]).toLowerCase().includes(pattern))continue;displayed++;const tr=document.createElement('tr');cell(tr,call.at_ms==null?null:call.at_ms.toFixed(3));cell(tr,call.tid);cell(tr,call.name);cell(tr,call.duration_us==null?null:call.duration_us.toFixed(3));cell(tr,call.result);cell(tr,call.returned_bytes);cell(tr,(call.paths||[]).join('\n')||'未解析对象');cell(tr,call.pairing);const td=cell(tr,'');const a=document.createElement('a');a.textContent='原始调用';a.href=nativeData.report_url+call.source_ref.replace(/^report/,'');a.target='_blank';a.rel='noopener noreferrer';td.appendChild(a);body.appendChild(tr);}
  qs('#native-page-status').textContent='第 '+(runtimePage+1)+' / '+pages.length+' 页 · 本页 '+displayed+' / '+payload.rows.length+' 条（筛选仅作用当前页） · 所有调用仍在全局未分配范围';
 }catch(error){if(generation===loadingGeneration)qs('#native-page-status').textContent='分页读取失败：'+error.message+'；请通过 HTTP 打开页面，原始 JSON 保留。';}}
function chooseThread(key){if(!nativeData.pages.by_thread[key])return;qs('#native-thread').value=key;runtimePage=0;showRuntimePage();qs('#native-runtime').scrollIntoView({behavior:'smooth'});qs('#candidate-context').textContent='当前查看候选线程 '+key+'；不是证明该工具导致了这些调用。';}
for(const button of document.querySelectorAll('[data-candidate-thread]'))button.onclick=()=>chooseThread(button.dataset.candidateThread);
qs('#native-thread').onchange=()=>{runtimePage=0;qs('#candidate-context').textContent='完整运行时查询，不按工具自动认领 syscall。';showRuntimePage();};
qs('#native-prev').onclick=()=>{runtimePage--;showRuntimePage();};qs('#native-next').onclick=()=>{runtimePage++;showRuntimePage();};qs('#native-filter').oninput=showRuntimePage;
let filePage=0;function showFiles(){const pattern=qs('#file-filter').value.trim().toLowerCase(),selected=nativeData.files.filter(x=>x.path.toLowerCase().includes(pattern));filePage=Math.max(0,Math.min(filePage,Math.ceil(selected.length/100)-1));const rows=selected.slice(filePage*100,(filePage+1)*100),body=qs('#native-files');body.replaceChildren();for(const file of rows){const tr=document.createElement('tr');cell(tr,file.path);cell(tr,file.calls);cell(tr,file.read_bytes_observed);cell(tr,file.thread_keys.length);body.appendChild(tr);}qs('#file-status').textContent=selected.length+' 条已解析路径 · 当前第 '+(filePage+1)+' 页；路径别名不是不同 inode 的证明';qs('#file-prev').disabled=filePage<=0;qs('#file-next').disabled=(filePage+1)*100>=selected.length;}
qs('#file-filter').oninput=()=>{filePage=0;showFiles();};qs('#file-prev').onclick=()=>{filePage--;showFiles();};qs('#file-next').onclick=()=>{filePage++;showFiles();};showFiles();showRuntimePage();
'''


def render_native_page(compiled, links, pages):
    story, profile = compiled['story'], compiled['profile']
    runtime = story['runtime']
    e = lambda value: escape(str(value), quote=True)
    value = lambda item: '未采集' if item is None else e(item)
    outer_cards=[]
    for index,outer in enumerate(story.get('native_model_tools',[])):
        duration=outer.get('request_to_output_ms')
        outer_cards.append('<details class="native-model-tool" id="native-model-tool-'+str(index)+'"><summary>'+e(' → '.join(outer['semantic_path']))+
            ' → 模型原生工具 '+str(outer['number'])+' · '+e(outer['tool_name'])+' · '+e(outer['runtime'])+' · '+
            (value(round(duration,3))+' ms' if duration is not None else '窗口未完整采集')+'</summary><p>真实模型 call_id <code>'+e(outer['call_id'])+
            '</code> · '+e(outer['status'])+'</p><p>精确匹配的模型请求：'+e(', '.join(outer['provider_request_ids']) or '尚无精确关联')+
            '</p><p class="note">阶段标签来自精确匹配模型请求的离线标注，不表示已独立审阅或精确计时每条 JS。'+e(outer['semantic_quality'])+
            '</p><p class="note">这是模型原生工具层；Code Mode 的 JS 会请求执行器执行命令，下面的 commandExecution 是不同层。没有原生父 ID 时不按时间强配父子。</p><h4>实际提交的 JS／工具输入</h4><pre>'+e((outer.get('request') or {}).get('text','未提供'))+
            '</pre><h4>相同 call_id 的工具输出</h4><pre>'+e((outer.get('output') or {}).get('text','未观察到输出'))+
            '</pre>'+('<p class="note">计时对账：本页采用可独立重放的 RPC 账本收包时间。原应用处理器稍后取时的窗口 '+value(outer['application_handler_timing'].get('request_to_output_ms'))+
                ' ms 另行保留；没有把两个不同观察点强制改成同一数值。原始 handler 的纳秒边界和 RPC 边界均可在完整记录检查。</p>' if outer.get('application_handler_timing') else '')+
            '<p class="warning">此窗口从客户端收到原生请求到收到匹配输出；包括工具等待与框架开销，不是 V8 JS CPU。JS 内部分段和 heap 仍未采集。</p><a href="'+e(links['story'])+'#/native_model_tools/'+str(index)+'">完整原生模型工具记录</a></details>')
    tool_cards = []
    for tool in story['tools']:
        result = tool['result']; output = result.get('output') or {}
        correlation = tool['correlation']; candidates = []
        for candidate in correlation.get('candidates', []):
            candidates.append('<div class="candidate-box">候选 PID '+e(candidate.get('pid'))+
                ' · '+e(candidate.get('basis', ''))+'<br><button type="button" data-candidate-thread="'+
                e(candidate['thread_key'])+'">查看该候选进程的线程／syscall（不是工具归属证明）</button></div>')
        tool_cards.append('<details class="native-tool" id="native-tool-'+str(tool['number'])+'"><summary>'+e(' → '.join(tool['semantic_path']))+
            ' → '+e(tool['tool_name'])+' <span class="tool-status">'+e(tool['status'])+'</span> · '+
            (value(round(tool['total_ms'],3))+' ms' if tool['total_ms'] is not None else '时长未采集')+'</summary><p>call_id <code>'+e(tool['call_id'])+
            '</code> · 原生结果退出码 '+value(tool['exit_code'])+'</p><pre>'+e(tool['command'] or json.dumps(tool['arguments'],ensure_ascii=False))+
            '</pre><p class="note">工具输出是 Codex 实际通知中的 aggregatedOutput；成功退出不等于任务正确。</p><pre>'+e(output.get('text', '未提供文本输出'))+
            '</pre>' + ('<p class="warning">输出已截断，原始总字节 '+e(output.get('size_bytes'))+'</p>' if output.get('truncated') else '')+
            '<p><strong>Linux 关联：'+e(correlation['status'])+'</strong><br>'+e(correlation.get('reason',''))+'</p>'+''.join(candidates)+
            '<p class="note">'+e('未找到候选不表示没有执行；短进程可能在采样之间结束。' if not candidates else '候选依据是采样到的参数／cwd／内核生涯；可能与其他调用重叠，不能当作强绑定。')+
            '</p><a href="'+e(links['application'])+'#/tool_calls/'+str(tool['number']-1)+'">原始工具通知投影</a> · <a href="'+e(links['results'])+'">原始输出账本</a></details>')
    threads = '<option value="all">整个原生运行时：全部未分配调用</option>'+''.join('<option value="'+e(t['key'])+'">PID '+e(t.get('tgid'))+' / TID '+e(t.get('tid'))+' · '+e(t.get('comm'))+' · '+e(t['calls'])+' 次</option>' for t in runtime['threads'])
    model_rows = ''.join('<tr>'+''.join('<td>'+value(x)+'</td>' for x in (req['request_id'],req.get('wait_first_byte_ms'),req.get('response_receive_ms'),req['request_ms'],req.get('status'),req['clock_alignment']))+'</tr>' for req in story['model_requests'])
    memory_story = {'agent_wall_ms': story['agent_wall_ms'], 'memory': story['memory']}
    memory_helpers = "const story="+_script_json(memory_story)+r''';
function esc(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmt(v){return v==null?'未采集':Number(v).toLocaleString(undefined,{maximumFractionDigits:3});}
function ms(v){return v==null?'未采集':fmt(v)+' ms';}function bytes(v){if(v==null)return'未采集';return(Number(v)/1048576).toFixed(2)+' MiB';}
const roleNames={AGENT_RUNTIME:'原生 Codex 运行时（PID）',OBSERVER_SUPERVISOR:'Observer 管理进程',OBSERVER_COLLECTOR:'Observer 采集器'};
function memoryTargets(){return story.memory?.targets||[];}
'''
    panel = render_profile_panel(profile, profile_url=links['profile'], evidence_url=None, syscall_url=links['report'],
        source_urls={key:links[key] for key in ('report','application','story','rpc') if key in links})
    native_payload = {'pages': pages, 'files': runtime['files'], 'report_url': links['report']}
    outcome_note = ('<p class="warning"><strong>Agent 本轮结果：'+e(story['status'])+'</strong>。这不是“测试通过”或“任务完成”的自动证明。'+
        ('<pre>'+e(json.dumps(story['errors'],ensure_ascii=False)[:2400])+'</pre>' if story['errors'] else '')+
        ('<pre>'+e(story['application_error'])+'</pre>' if story['application_error'] else '')+'</p>')
    return ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>原生 Codex：任务到系统行为</title><style>'+STYLE+MEMORY_STYLE+'</style></head><body><main><h1>原生 Codex：任务 → 工具 → 目标 Linux</h1><p>'+e(story['task_id'])+
        '</p>'+outcome_note+'<p class="note">这是未替换工具的真实 Codex 原生运行。原生 shell／Code Mode 由 Codex 自己执行；Observer 记录整个运行时及后代。弱关联明确显示，不冒充工具到 syscall 的强因果。</p><div class="metrics"><div><b>'+value(round(story['agent_wall_ms'],3))+' ms</b>完整运行时墙钟（含启动／收尾）</div><div><b>'+str(len(story.get('native_model_tools',[])))+'</b>模型原生工具（exec 等）</div><div><b>'+str(len(story['tools']))+'</b>内层原生执行通知项</div><div><b>'+str(runtime['total_syscalls'])+'</b>完整 runtime syscall（逐调用只计一次）</div><div><b>'+str(runtime['distinct_resolved_paths'])+'</b>已解析不同路径</div></div>'+panel+
        '<section class="native-section"><h2>模型真正调用的工具：原生 Code Mode／exec</h2><p class="note">模型工具与内层执行通知分别展示。两层时长可能包围或重叠，不能相加当端到端耗时。</p>'+(''.join(outer_cards) if outer_cards else '<p>未取得模型原生工具请求／输出；不把下面的执行通知冒充模型工具。</p>')+'</section>'+
        '<section class="native-section"><h2>原生执行器实际执行了什么：commandExecution 等</h2><p class="note">分类是可复核命令规则，不是读取隐藏思维；未识别阶段保留“未分配”。点击工具查看原始命令、输出和关联等级。</p>'+''.join(tool_cards)+
        '</section><section class="native-section"><h2>客户端模型请求等待与原生 Code Mode</h2><div class="tables"><table><thead><tr><th>请求</th><th>客户端首 body 字节等待 ms</th><th>客户端接收 ms</th><th>HTTP 请求总 ms</th><th>状态</th><th>时钟</th></tr></thead><tbody>'+model_rows+
        '</tbody></table></div><p class="note">这是客户端看到的 HTTP 请求等待；预算代理会缓冲 provider SSE，因此不能当成 provider 精确首 token、内部队列、推理计算或 GPU 时间。包括网络、代理／预算处理、上游生成与缓冲。计时完整度：'+e(story['model_collection']['status'])+'</p><p class="warning">'+e(story['code_mode']['reason'])+
        '</p></section><section class="native-section"><h2>实际内存曲线：运行时与整个执行组</h2><p class="warning">整组包含原生工具后代，不能给每个工具重复分摊；PID RSS、cgroup 总用量和文件缓存是不同口径。没有数据的项不画成 0。</p><div id="native-memory"></div></section>'+
        '<section class="native-section" id="native-runtime"><h2>完整 Linux 执行：线程／文件／syscall</h2><p class="warning">全部 '+str(runtime['unassigned_syscalls'])+' 次调用仍保留在全局未分配分支；点击候选进程只是查询该进程，不会把它的调用重新算给某个工具。</p><p class="note">整个 cgroup 会包含 Codex、codex-code-mode／V8、tokio 工作线程、工具后代，以及插件等后台活动（例如 git-remote-http）。同组只证明属于观测范围，不证明属于某一个任务阶段或工具。</p><p id="candidate-context" class="note"></p><div class="controls"><label>范围 <select id="native-thread">'+threads+'</select></label><label>当前页筛选 <input id="native-filter" type="search" placeholder="syscall、文件路径、errno"></label><button type="button" id="native-prev">上一页</button><button type="button" id="native-next">下一页</button></div><p id="native-page-status"></p><div class="tables"><table><thead><tr><th>相对开始 ms</th><th>TID</th><th>syscall</th><th>耗时 μs</th><th>返回值</th><th>VFS 实际返回 bytes</th><th>对象路径</th><th>配对</th><th>证据</th></tr></thead><tbody id="native-syscalls"></tbody></table></div>'+
        '<h3>实际访问文件／对象路径</h3><div class="controls"><input id="file-filter" type="search" placeholder="筛选全部已解析路径"><button type="button" id="file-prev">上一页</button><button type="button" id="file-next">下一页</button></div><p id="file-status"></p><div class="tables"><table><thead><tr><th>路径</th><th>调用数</th><th>实际已观察读取 bytes</th><th>线程数</th></tr></thead><tbody id="native-files"></tbody></table></div></section>'+
        '<section class="native-section"><h2>范围与原始证据</h2><p>采集健康度 '+e(story['health'].get('status','未提供'))+'；独立重放状态 '+e(compiled.get('verification',{}).get('status','未提供'))+'。重放通过不等于所有接口完整，也不建立每工具因果。</p><div class="artifact-list">'+''.join('<a href="'+e(url)+'">'+e(name)+'</a>' for name,url in links.items())+'</div><ul>'+''.join('<li>'+e(x)+'</li>' for x in story['limitations'])+'</ul></section>'+
        '<script id="native-view-data" type="application/json">'+_script_json(native_payload)+'</script><script>'+memory_helpers+MEMORY_SCRIPT+
        "document.querySelector('#native-memory').innerHTML=memoryDetailsPanel();drawMemory(0);"+PAGER_SCRIPT+'</script></main></body></html>')


def export_native_profile(run_directory, output, profile_output, *, semantic_annotations=None):
    run_directory = Path(run_directory).resolve(strict=True)
    output, profile_output = Path(output).absolute(), Path(profile_output).absolute()
    if not output.parent.is_dir() or not profile_output.parent.is_dir():
        raise ValueError('output parent directories must exist')
    assets = output.with_name(output.stem+'.assets')
    trajectory_path = output.with_name(output.stem+'.trajectory.json')
    annotations_path = output.with_name(output.stem+'.annotations.json')
    story_path = output.with_name(output.stem+'.story.json')
    receipt_path = output.with_name(output.stem+'.artifacts.json')
    targets = [output,profile_output,assets,trajectory_path,annotations_path,story_path,receipt_path]
    if len(set(targets)) != len(targets) or any(path.exists() or path.is_symlink() for path in targets):
        raise ValueError('all derived output files/directories must be new and distinct')
    inputs = {'report':run_directory/'report.json','application':run_directory/'app/steps.json',
        'results':run_directory/'app/native-tool-results.jsonl','correlations':run_directory/'native-process-correlations.json',
        'model_timing':run_directory/'app/model-request-timing.jsonl','model_summary':run_directory/'app/model-transport-summary.json',
        'resource_summary':run_directory/'resources/resource-summary.json','resource_samples':run_directory/'resources/resource-samples.jsonl',
        'rpc':run_directory/'app/rpc.jsonl','verification':run_directory/'verification.json'}
    if semantic_annotations is not None:
        inputs['semantic_annotations'] = Path(semantic_annotations).resolve(strict=True)
    loaded = {}
    hashes = {}
    for name,path in inputs.items():
        if path.is_file():
            loaded[name] = read_jsonl(path) if path.suffix=='.jsonl' else read_json(path)
            hashes[name] = {'path':str(path),'identity':digest(path)}
        elif name in ('report','application'):
            raise ValueError('required native run evidence absent: '+name)
    compiled = compile_native_profile(loaded['report'],loaded['application'],tool_results=loaded.get('results'),
        correlations=loaded.get('correlations'),model_timing=loaded.get('model_timing'),model_summary=loaded.get('model_summary'),
        resource_summary=loaded.get('resource_summary'),resource_samples=loaded.get('resource_samples'),rpc_rows=loaded.get('rpc'),
        semantic_annotations=loaded.get('semantic_annotations'))
    compiled['verification'] = loaded.get('verification',{})
    relative = lambda path: quote(os.path.relpath(path,output.parent),safe='/')
    links = {name:relative(path) for name,path in inputs.items() if name in loaded}
    links.update(profile=relative(profile_output),trajectory=relative(trajectory_path),annotations=relative(annotations_path),
                 story=relative(story_path),artifact_receipt=relative(receipt_path))
    links.setdefault('results',links['application']);links.setdefault('correlations',links['application'])
    assets.mkdir(mode=0o700)
    pages = {'all':[],'by_thread':{}}
    by_thread = defaultdict(list)
    for row in compiled['syscall_rows']:
        by_thread[row['thread_key']].append(row)
    def write_pages(label, rows):
        urls=[]
        for index in range(0,len(rows),PAGE_SIZE):
            path = assets/(label+'-'+str(index//PAGE_SIZE).zfill(5)+'.json')
            write_new(path,{'schema_version':1,'scope':'WHOLE_RUNTIME_NOT_TOOL_ASSIGNED','rows':rows[index:index+PAGE_SIZE]})
            urls.append(relative(path))
        return urls
    pages['all']=write_pages('all',compiled['syscall_rows'])
    for key,rows in by_thread.items():
        pages['by_thread'][key]=write_pages('thread-'+hashlib.sha256(key.encode()).hexdigest()[:20],rows)
    write_new(profile_output,compiled['profile']);write_new(trajectory_path,compiled['trajectory'])
    write_new(annotations_path,compiled['annotations']);write_new(story_path,compiled['story'])
    write_new(output,render_native_page(compiled,links,pages).encode())
    written = [output,profile_output,trajectory_path,annotations_path,story_path]+sorted(assets.iterdir())
    receipt = {'schema_version':1,'status':'DERIVED_FROM_NATIVE_RUN_NOT_NEW_CAPTURE','run_id':compiled['story']['run_id'],
        'inputs':hashes,'outputs':{relative(path):digest(path) for path in written},
        'conservation':{'runtime_syscalls':compiled['story']['runtime']['total_syscalls'],
            'per_tool_kernel_syscalls_assigned':0,'wall_ms':compiled['story']['agent_wall_ms']},
        'source_immutability':'READ_ONLY_INPUTS; EXCLUSIVE_CREATE_DERIVED_OUTPUTS'}
    write_new(receipt_path,receipt)
    return {'status':'EXPORTED','output':str(output),'profile':str(profile_output),
            'story':str(story_path),'trajectory':str(trajectory_path),'annotations':str(annotations_path),
            'artifacts':str(receipt_path),'runtime_syscalls':compiled['story']['runtime']['total_syscalls'],
            'native_tools':len(compiled['story']['tools']),'per_tool_kernel_assignment':'NOT_ESTABLISHED'}


PUBLIC_INPUT_ALLOWLIST = (
    'report.json','verification.json','manifest.json','ready.json','native-process-correlations.json',
    'resources/resource-summary.json','resources/resource-samples.jsonl',
    'app/steps.json','app/native-tool-results.jsonl','app/native-model-tools.jsonl',
    'app/native-process-sampling-summary.json','app/model-request-timing.jsonl',
    'app/model-transport-summary.json','app/rpc.jsonl','app/prompt.txt','app/config.public.json',
)


def export_public_native_profile(run_directory, public_directory, *, semantic_annotations=None):
    """Create a new HTTP root from named presentation inputs, never a whole run.

    No glob or recursive source copy is used. API credentials, private budget
    ledgers, environment dumps and unrelated campaign data are not candidates.
    Original raw-WAL replay remains in the private run; its receipt is copied.
    """
    run_directory=Path(run_directory).resolve(strict=True)
    public=Path(public_directory).absolute()
    if public.exists() or public.is_symlink() or not public.parent.is_dir():
        raise ValueError('new public directory with an existing parent required')
    if run_directory==public or run_directory in public.parents:
        raise ValueError('public directory must not mutate the original captured run')
    for name in ('report.json','app/steps.json'):
        if not (run_directory/name).is_file():raise ValueError('required native source absent: '+name)
    public.mkdir(mode=0o700)
    source=public/'source';source.mkdir(mode=0o700)
    copied={}
    for name in PUBLIC_INPUT_ALLOWLIST:
        src=run_directory/name
        if not src.exists():continue
        if src.is_symlink() or not src.is_file() or run_directory not in src.resolve().parents:
            raise ValueError('public input must be a regular original-run file: '+name)
        before=digest(src)
        dst=source/name;dst.parent.mkdir(parents=True,exist_ok=True)
        with src.open('rb') as incoming,dst.open('xb') as outgoing:
            shutil.copyfileobj(incoming,outgoing,1024*1024)
        os.chmod(dst,0o600)
        if digest(dst)!=before or digest(src)!=before:
            raise ValueError('native public source changed during copy: '+name)
        copied['source/'+name]=before
    marks=None
    if semantic_annotations is not None:
        src=Path(semantic_annotations)
        if src.is_symlink() or not src.is_file():raise ValueError('regular reviewed marks required')
        before=digest(src);marks=public/'reviewed-marks.json'
        with src.open('rb') as incoming,marks.open('xb') as outgoing:shutil.copyfileobj(incoming,outgoing)
        os.chmod(marks,0o600)
        if digest(marks)!=before or digest(src)!=before:raise ValueError('reviewed marks changed during public copy')
        copied['reviewed-marks.json']=before
    result=export_native_profile(source,public/'index.html',public/'semantic-profile.json',semantic_annotations=marks)
    # Enumerate only the new destination, never the campaign/private tree.
    files={str(path.relative_to(public)):digest(path) for path in sorted(public.rglob('*')) if path.is_file()}
    receipt={'schema_version':1,'status':'ALLOWLIST_PUBLIC_ROOT_CREATED','copied_inputs':copied,'files':files,
        'source_scope':'NAMED_PRESENTATION_INPUTS; NOT_FULL_RAW_WAL_OR_PRIVATE_BUDGET_BUNDLE',
        'privacy':'NO_RECURSIVE_SOURCE_COPY; PUBLIC_INPUT_ALLOWLIST_ONLY; PROMPTS_OUTPUTS_AND_PATHS_REMAIN_SENSITIVE',
        'native_kernel_attribution':'WHOLE_RUNTIME; CANDIDATE_RELATIONS_NOT_PROMOTED_TO_PER_TOOL_PROOF'}
    write_new(public/'publication.json',receipt)
    result.update(public_directory=str(public),publication_receipt=str(public/'publication.json'))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--profile-output',type=Path)
    parser.add_argument('--public-directory',type=Path,help='create a new allowlist-only HTTP root with index.html and source artifacts')
    parser.add_argument('--semantic-annotations',type=Path,help='reviewed sparse marks bound to the immutable trajectory digest')
    args=parser.parse_args()
    if args.public_directory:
        if args.output or args.profile_output:parser.error('--public-directory cannot be combined with --output/--profile-output')
        result=export_public_native_profile(args.run,args.public_directory,semantic_annotations=args.semantic_annotations)
    else:
        if not args.output or not args.profile_output:parser.error('--output and --profile-output are required without --public-directory')
        result=export_native_profile(args.run,args.output,args.profile_output,semantic_annotations=args.semantic_annotations)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
