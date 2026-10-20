#!/usr/bin/env python3
"""Present a new zero-API trace replay; never backfill the original live run."""
import argparse
from html import escape
import json
from pathlib import Path
import re

from common import digest, write_new
from interactive_profile_ui import render_profile_panel, _script_json
from native_agent_profile import _runtime, PAGE_SIZE
from native_profile_campaign import _hardlink_evidence
from render_agent_story import read_json
from semantic_profile import fold_view
from execution_metrics import read_jsonl


ACCEPTED=frozenset(('KERNEL_ARGV_AND_CORE_EXEC_IDENTITY_CORRELATED',
    'KERNEL_ARGV_SNAPSHOT_PROJECTED_AND_CORE_EXEC_IDENTITY_CORRELATED'))


def build_replay_view(report, application, scopes, tool_results=None):
    if scopes.get('kind')!='ARGV_AND_CORE_EXEC_LIFETIME_CORRELATION' or scopes.get('core_syscall_count_increment')!=0:
        raise ValueError('independently joined core scopes with zero event increment required')
    if application.get('budget_label')!='native-trace-replay' or application.get('paid_request_count') not in (None,0):
        raise ValueError('explicit trace-replay capture declaration required')
    run=report['run'];origin=run.get('begin_ns');task=application.get('task_id') or '原生工具 trace replay'
    if type(origin) is not int:raise ValueError('core begin time required')
    runtime,rows,runtime_operations=_runtime(report,origin,task)
    calls={call['call_id']:call for call in application.get('tool_calls',[])}
    if len(calls)!=len(application.get('tool_calls',[])):raise ValueError('unique native tool ids required')
    results={row['call_id']:row for row in tool_results or []}
    if len(results)!=len(tool_results or []):raise ValueError('unique result call ids required')
    if set(results)-set(calls):raise ValueError('result references unknown application call')
    source_rows={row['source_ref']:row for row in rows};owners={};tool_rows={};tools=[];seen_scopes=set()
    for index,scope in enumerate(scopes.get('calls',[])):
        call_id=scope['call_id']
        if call_id not in calls:raise ValueError('scope references an absent application call')
        if call_id in seen_scopes:raise ValueError('duplicate scope call id')
        seen_scopes.add(call_id)
        call=calls[call_id];selected=[]
        ranges=scope.get('thread_ranges',[])
        if ranges and scope.get('status') not in ACCEPTED:raise ValueError('unaccepted scope may not own syscall references')
        for thread_range in ranges:
            match=re.fullmatch(r'report#/threads/(\d+)',thread_range['thread_ref'])
            if not match:raise ValueError('invalid source thread reference')
            ti=int(match.group(1));thread=report['threads'][ti]
            if thread['key']!=thread_range['thread_key']:raise ValueError('thread lifetime key mismatch')
            for ci in thread_range['call_indices']:
                if type(ci) is not int or ci<0 or ci>=len(thread.get('calls',[])):raise ValueError('invalid core call index')
                reference=f'report#/threads/{ti}/calls/{ci}'
                if reference in owners:raise ValueError('a kernel call may not enter two tool scopes')
                row=source_rows[reference];start,end=row['start_ns'],row['end_ns']
                if type(start) is not int or type(end) is not int or not thread_range['scope_begin_ns']<=start<=end<=thread_range['scope_end_ns']:
                    raise ValueError('call lies outside the verified exec/fork scope')
                owners[reference]=call_id;selected.append(reference)
        if len(selected)!=scope['syscall_count']:raise ValueError('scope call count differs from core references')
        tool_rows[call_id]=selected
        result=results.get(call_id) or call.get('result') or {};output=result.get('output') or {}
        tools.append({'number':index+1,'call_id':call_id,'tool_name':call.get('tool_name'),
            'status':call.get('status'),'scope_status':scope.get('status'),'command':(call.get('arguments') or {}).get('command') or call.get('command') or json.dumps(call.get('arguments') or {},ensure_ascii=False),
            'output':output,'exit_code':call.get('exit_code',result.get('exit_code')),
            'syscall_count':len(selected),'thread_count':len(ranges),'scope_ref':f'scope#/calls/{index}',
            'argv_projection':scope.get('argv_projection'),'core_exec_refs':scope.get('core_exec_refs',[])})
    if seen_scopes!=set(calls):raise ValueError('scope ledger must include unbound application calls too')
    if len(owners)!=scopes.get('correlated_syscall_references'):raise ValueError('joint scope total differs')
    by_id={item['call_id']:item for item in tools};operations=[]
    for row in rows:
        call_id=owners.get(row['source_ref']);tool=by_id.get(call_id)
        stack=[{'kind':'task','label':task},{'kind':'semantic','label':'独立 trace replay · 0 付费 API'}]
        attribution='RUNTIME_ONLY_UNASSIGNED'
        if tool:
            stack.extend([{'kind':'tool','label':str(tool['number'])+' · '+str(tool['tool_name']),
                'call_id':call_id,'detail_anchor':'replay-tool-'+str(tool['number'])},
                {'kind':'attribution','label':'argv／内核身份相关（不是强因果）'}])
            attribution=tool['scope_status']
        else:stack.append({'kind':'semantic','label':'完整运行时：仍未归属的调用'})
        stack.extend([{'kind':'process','label':str(row['comm'])+' [PID '+str(row['tgid'])+']'},
            {'kind':'thread','label':'TID '+str(row['tid']),'tid':row['tid'],'thread_key':row['thread_key']}])
        evidence={key:row.get(key) for key in ('tid','thread_key','source_ref','result','errno')}
        evidence['attribution']=attribution
        measures={'syscall_count':1}
        if row['duration_us'] is not None:measures['syscall_time_ms']=row['duration_us']/1000
        operations.append({'kind':'core_replay_call','stack':stack+[{'kind':'syscall','label':row['name']}],
            'measures':measures,'evidence':evidence})
        if row['paths'] or row['returned_bytes'] is not None:
            measures={'file_operations':1}
            if row['returned_bytes'] is not None:measures['file_read_bytes']=row['returned_bytes']
            operations.append({'kind':'core_replay_file','stack':stack+[{'kind':'file','label':row['paths'][0] if row['paths'] else '对象路径未解析'}],
                'measures':measures,'evidence':{**evidence,'path':row['paths'][0] if row['paths'] else None}})
    # CPU/state measurements remain the whole thread lifetime, not a tool's
    # argv-correlated slice. Keep them visible without duplicating ownership.
    for operation in runtime_operations:
        if operation.get('kind')=='runtime_thread_state':
            operation['stack'][1]={'kind':'semantic','label':'完整运行时 CPU／调度：未按工具切片'}
            operations.append(operation)
    views=[]
    for metric,label,unit in (('syscall_count','系统调用次数','次'),('syscall_time_ms','系统调用累计时长（可重叠）','ms'),
        ('file_operations','文件对象操作次数','次'),('file_read_bytes','VFS 实际读取字节','bytes'),
        ('oncpu_ms','完整运行时线程 CPU（未分配到工具）','ms'),
        ('runnable_ms','完整运行时等待 CPU（未分配到工具）','ms'),
        ('sleep_ms','完整运行时睡眠／阻塞（未分配到工具）','ms')):
        tree,count=fold_view(operations,metric,task)
        views.append({'name':metric,'label':label,'unit':unit,'quality':'已验证 exec／fork 身份范围内的相关性；不是强因果归因或 wall-clock 分解',
            'status':'AVAILABLE' if count else 'NOT_COLLECTED','tree':tree,'total':tree['value'],'sample_count':count})
        if metric in ('oncpu_ms','runnable_ms','sleep_ms'):
            views[-1]['quality']='完整 runtime 线程状态累计；未按工具 exec 范围切片，不是 task wall time，不认领到任意工具'
    profile={'schema_version':1,'agent_id':application.get('agent_id'),'task_id':task,
        'operation_count':len(operations),'operations':operations,'views':views}
    if next(view['total'] for view in views if view['name']=='syscall_count')!=len(rows):raise ValueError('syscall conservation failed')
    return {'kind':'ZERO_PAID_API_NATIVE_TRACE_REPLAY','task_id':task,'run_id':run.get('run_id'),
        'tools':tools,'rows':rows,'tool_rows':tool_rows,'profile':profile,'runtime':runtime,
        'total_syscalls':len(rows),'correlated_syscalls':len(owners),'unassigned_syscalls':len(rows)-len(owners),
        'attribution':'CORRELATED_EXECUTION_SUBTREE_NOT_STRONG_AGENT_CAUSAL_ATTRIBUTION',
        'sidecar_argv_evidence_status':scopes.get('sidecar_argv_evidence_status'),
        'sidecar_history_status':scopes.get('sidecar_history_status'),
        'strict_unchanged_argv_status_counts':scopes.get('strict_unchanged_argv_status_counts'),
        'core_scope_status_counts':scopes.get('core_scope_status_counts'),
        'paid_request_count':0,'slowdown_claim_allowed':False,
        'limitations':['这是一轮新的实际 trace replay，不是新模型推理，也不是给原始 live004 事后补采。',
            'argv 是系统调用入口观察的用户字符串；不是最终内核拷贝或消除 TOCTOU 的强绑定。',
            'Codex bash snapshot 若把 -lc 转为 -c，使用明确版本化投影合同并展示原始变化，不按时间猜测。',
            'syscall 累计时长可能并行重叠；不能等同任务墙钟。内存仍是运行时／cgroup 范围，不分摊给工具。',
            '线程 CPU 尚未按 exec／fork 范围裁切，工具下没有认领整个线程生命周期 CPU；CPU 仍只看 runtime 级。',
            'replay001 各臂原始输出／元数据不完全一致，不能据此提供 slowdown。']}


PAGER=r'''
const replayData=JSON.parse(document.querySelector('#replay-data').textContent);let currentTool='all',page=0,renderVersion=0;
function txt(value){return value==null?'未采集':String(value)}
async function draw(){const version=++renderVersion,selected=currentTool,pageNumber=page,urls=selected==='all'?replayData.all:(replayData.by_tool[selected]||[]);const tbody=document.querySelector('#calls');tbody.replaceChildren();tbody.dataset.scope='';document.querySelector('#page-status').textContent=`${selected==='all'?'完整运行时':'所选工具的身份相关范围'} · ${urls.length?pageNumber+1:0}/${urls.length} 页 · 每页最多 200 条`;if(!urls.length){tbody.dataset.scope=selected;tbody.dataset.page='0';return}const response=await fetch(urls[pageNumber]);if(version!==renderVersion)return;if(!response.ok)throw Error('分页加载失败');const payload=await response.json();if(version!==renderVersion)return;if(!Array.isArray(payload.rows)||payload.rows.length>200)throw Error('分页格式／数量上限错误');for(const row of payload.rows){const tr=document.createElement('tr');for(const value of [row.at_ms,row.tid,row.name,row.duration_us,row.result,row.returned_bytes,row.paths.join(' | ')||'无已解析文件对象']){const td=document.createElement('td');td.textContent=txt(value);tr.append(td)}const td=document.createElement('td'),a=document.createElement('a');a.href='source/report.json'+row.source_ref.slice('report'.length);a.textContent='原始调用';td.append(a);tr.append(td);tbody.append(tr)}tbody.dataset.scope=selected;tbody.dataset.page=String(pageNumber)}
document.querySelector('#tool-scope').addEventListener('change',event=>{currentTool=event.target.value;page=0;draw().catch(showError)});
function showError(error){document.querySelector('#page-status').textContent='加载失败：'+error.message}
document.querySelector('#previous').addEventListener('click',()=>{if(page){page--;draw().catch(showError)}});document.querySelector('#next').addEventListener('click',()=>{const urls=currentTool==='all'?replayData.all:(replayData.by_tool[currentTool]||[]);if(page+1<urls.length){page++;draw().catch(showError)}});
document.querySelectorAll('[data-tool-scope]').forEach(button=>button.addEventListener('click',()=>{currentTool=button.dataset.toolScope;document.querySelector('#tool-scope').value=currentTool;page=0;draw().catch(showError);document.querySelector('#replay-calls').scrollIntoView()}));draw().catch(showError);
'''


def render_replay_page(view,pages):
    e=lambda value:escape(str(value),quote=True)
    cards=[]
    for tool in view['tools']:
        output=tool.get('output') or {};output=output.get('text','未取得文本输出') if isinstance(output,dict) else str(output)
        count_text=str(tool['syscall_count'])+' 次相关 syscall' if tool['syscall_count'] else '尚未建立 syscall 关联（不是零活动）'
        cards.append('<details class="replay-tool" id="replay-tool-'+str(tool['number'])+'"><summary>'+str(tool['number'])+' · '+e(tool['tool_name'])+' · '+e(tool['status'])+' · '+count_text+'</summary><p>'+e(tool['scope_status'])+'（相关，不是强因果） · '+str(tool['thread_count'])+' 个生命周期线程范围</p><pre>'+e(tool['command'])+'</pre><p>实际通知退出码：'+e(tool['exit_code'] if tool['exit_code'] is not None else '未提供')+'</p><pre>'+e(output)+'</pre>'+('<p class="warning">明确 argv 投影：'+e(json.dumps(tool['argv_projection'],ensure_ascii=False))+'</p>' if tool.get('argv_projection') else '')+'<button type="button" data-tool-scope="'+e(tool['call_id'])+'">查看这个工具的线程／文件／syscall</button> · <a href="scope.json#/calls/'+str(tool['number']-1)+'">范围与 exec 原始引用</a></details>')
    return '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>0 API trace replay：工具到 Linux</title><style>body{font:15px system-ui;margin:0;background:#f3f6f9;color:#193247}main{max-width:1500px;margin:auto;padding:18px}.warning{background:#fff1cd;padding:12px;border-left:4px solid #b27707}details{background:white;border:1px solid #ccdbe5;border-radius:5px;margin:10px 0;padding:12px}summary,button{cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef3f7;padding:12px;max-height:350px;overflow:auto}table{border-collapse:collapse;width:100%;background:white}td,th{border:1px solid #cbd9e2;text-align:left;padding:7px;overflow-wrap:anywhere}td:last-child{white-space:nowrap}.scroll{overflow:auto}button,select{padding:8px;margin:6px}</style><main><h1>工具 → 进程／线程 → 文件与 syscall</h1><p class="warning"><strong>这是独立 trace replay，0 次付费 API。</strong>重新播放已保存的原生消息，在新一轮真实 Linux 执行中采集；不是原始 live004 的补造归属，也不是新模型推理或 overhead 成绩。</p><p>'+e(view['task_id'])+'</p><p>原始核心 '+str(view['total_syscalls'])+' 次调用 = 工具身份相关 '+str(view['correlated_syscalls'])+' + 全局未归属 '+str(view['unassigned_syscalls'])+'。原事件数量增量为 0，每次调用只进一个分支。</p><p class="warning">侧探针全局 argv 完整度：'+e(view.get('sidecar_argv_evidence_status'))+'；选定 exec hook 历史：'+e(view.get('sidecar_history_status'))+'。不是所有 exec 都有完整参数；下面只认领通过完整候选、唯一性、版本化投影及核心生命周期核验的调用。</p>'+render_profile_panel(view['profile'],profile_url='profile.json',evidence_url=None,syscall_url='source/report.json',source_urls={'report':'source/report.json','scope':'scope.json'})+'<h2>实际工具、输出与身份关联依据</h2>'+''.join(cards)+'<section id="replay-calls"><h2>逐次系统调用与对应文件</h2><label>范围 <select id="tool-scope"><option value="all">完整运行时（每次调用只计一次）</option>'+''.join('<option value="'+e(tool['call_id'])+'">'+str(tool['number'])+' · '+e(tool['tool_name'])+' · '+str(tool['syscall_count'])+' 次</option>' for tool in view['tools'])+'</select></label><button id="previous">上一页</button><button id="next">下一页</button><p id="page-status"></p><div class="scroll"><table><thead><tr><th>相对开始 ms</th><th>TID</th><th>syscall</th><th>耗时 μs</th><th>返回值</th><th>实际读取 bytes</th><th>对象路径</th><th>来源</th></tr></thead><tbody id="calls"></tbody></table></div></section><h2>边界与原始证据</h2><ul>'+''.join('<li>'+e(item)+'</li>' for item in view['limitations'])+'</ul><p><a href="source/report.json">原始核心报告</a> · <a href="source/verification.json">核心独立重放回执</a> · <a href="scope.json">精确身份联合范围</a> · <a href="scope-export-verification.json">导出前双 WAL 与原生账本复算</a> · <a href="summary.json">守恒摘要</a> · <a href="publication.json">公开清单与哈希</a></p><script id="replay-data" type="application/json">'+_script_json(pages)+'</script><script>'+PAGER+'</script></main></html>'


def export_replay_view(run_directory,scope_path,output_directory):
    root=Path(run_directory).resolve(strict=True);target=Path(output_directory).absolute()
    if target.exists() or not target.parent.is_dir():raise ValueError('new replay output directory required')
    identities={str(path):digest(path) for path in (root/'report.json',root/'app/steps.json',Path(scope_path))}
    report=read_json(root/'report.json');app=read_json(root/'app/steps.json');scope=read_json(scope_path)
    from verify_exec_args_run import verify_native_exec_scopes
    recomputed=verify_native_exec_scopes(root,snapshot_projection=bool(scope.get('runtime_projection_contract')))
    if scope!=recomputed:raise ValueError('supplied scope differs from independently recomputed binary-WAL join')
    if recomputed.get('provider_provenance')!='REPLAYED_PROVIDER_RESPONSES_NOT_NEW_INFERENCE':
        raise ValueError('bound manifest must declare replayed provider responses, not new inference')
    if recomputed.get('core_replay',{}).get('report_identity')!=identities[str(root/'report.json')]:
        raise ValueError('profile report identity differs from independently replayed core report')
    if any(digest(path)!=identity for path,identity in identities.items()):
        raise ValueError('profile source changed during independent replay')
    results_path=root/'app/native-tool-results.jsonl'
    view=build_replay_view(report,app,scope,read_jsonl(results_path) if results_path.is_file() else None)
    target.mkdir(mode=0o700);linked={}
    for name in ('report.json','verification.json','ready.json','manifest.json','app/steps.json','app/native-tool-results.jsonl','exec-args-receipt.json'):
        if (root/name).is_file():linked['source/'+name]=_hardlink_evidence(root/name,target/'source'/name,root)
    if any(digest(path)!=identity for path,identity in identities.items()):
        raise ValueError('profile source changed during export')
    write_new(target/'scope.json',scope);write_new(target/'profile.json',view['profile'])
    write_new(target/'scope-export-verification.json',{'status':'RECOMPUTED_AND_IDENTICAL',
        'scope_identity':digest(scope_path),'core_replay':recomputed['core_replay'],
        'sidecar_artifacts':recomputed['sidecar_artifacts'],
        'correlated_syscall_references':recomputed['correlated_syscall_references'],
        'scope':'BOTH_BINARY_WALS_PINNED_COLLECTOR_RAW_RPC_AND_TOOL_LEDGER'})
    summary={key:value for key,value in view.items() if key not in ('profile','rows','tool_rows','runtime')}
    write_new(target/'summary.json',summary);assets=target/'pages';assets.mkdir(mode=0o700)
    refs={row['source_ref']:row for row in view['rows']};pages={'all':[],'by_tool':{}}
    def save(name,rows):
        urls=[]
        for index in range(0,len(rows),PAGE_SIZE):
            path=assets/(name+'-'+str(index//PAGE_SIZE).zfill(5)+'.json')
            write_new(path,{'rows':rows[index:index+PAGE_SIZE]});urls.append('pages/'+path.name)
        return urls
    pages['all']=save('all',view['rows'])
    for number,(call_id,call_refs) in enumerate(view['tool_rows'].items()):pages['by_tool'][call_id]=save('tool-'+str(number),[refs[ref] for ref in call_refs])
    write_new(target/'index.html',render_replay_page(view,pages).encode())
    write_new(target/'publication.json',{'schema_version':1,'kind':'ZERO_API_REPLAY_ALLOWLIST_PUBLICATION',
        'linked_inputs':linked,'scope_source':digest(scope_path),'core_event_increment':0,
        'scope_verification':'RECOMPUTED_FROM_BOTH_BINARY_WALS_PINNED_COLLECTOR_AND_RAW_APP_LEDGER_BEFORE_EXPORT',
        'source_files':{str(path.relative_to(target)):digest(path) for path in sorted(target.rglob('*')) if path.is_file()},
        'privacy':'ONLY_NAMED_PRESENTATION_FILES; RAW_WAL_AND_PRIVATE_BUDGET_REMAIN_OUTSIDE_HTTP_ROOT',
        'raw_replay_status':'receipt only; full original raw WAL remains private and is not independently reproducible from this UI-only export'})
    return {key:view[key] for key in ('total_syscalls','correlated_syscalls','unassigned_syscalls','paid_request_count','slowdown_claim_allowed')}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',required=True,type=Path)
    parser.add_argument('--scope',required=True,type=Path,help='independently recomputed argv/core scope JSON; verified again before publication')
    parser.add_argument('--public-directory',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(export_replay_view(args.run,args.scope,args.public_directory),ensure_ascii=False,indent=2))


if __name__=='__main__':main()
