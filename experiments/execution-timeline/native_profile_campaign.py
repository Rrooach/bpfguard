#!/usr/bin/env python3
"""Publish comparable task descriptions, not invalid failed/success speedups."""
from collections import defaultdict
from copy import deepcopy
from html import escape
import json
import os
from pathlib import Path
import re

from common import digest, write_new
from interactive_profile_ui import render_profile_panel,_safe_url
from render_agent_story import read_json
from semantic_profile import fold_view


def validate_compiled_story(story, annotations):
    """Reject swapped review outputs and paths not produced by the review.

    This transformation API accepts an already compiled story, not arbitrary
    raw evidence. File export additionally validates the bound trajectory.
    """
    from semantic_annotations import apply_annotations,_digest
    binding=story.get('semantic_annotations') or {}
    for key in ('trajectory_digest','taxonomy_version','taxonomy_digest','method'):
        if not annotations.get(key) or binding.get(key)!=annotations[key]:
            raise ValueError('compiled story/review binding differs: '+key)
    if annotations['taxonomy_digest']!=_digest(annotations['taxonomy']):raise ValueError('taxonomy digest differs')
    reapplied=apply_annotations(story,annotations)
    for section in ('tools','model_requests'):
        for actual,expected in zip(story.get(section,[]),reapplied.get(section,[])):
            if actual.get('semantic_path')!=expected.get('semantic_path'):
                raise ValueError('story semantic path differs from reviewed exact IDs: '+section)
    taxonomy=annotations['taxonomy'];unknown=[taxonomy['task'],taxonomy['unassigned']]
    requests={row['request_id']:row for row in story.get('model_requests',[])};outer={}
    for row in story.get('native_model_tools',[]):
        if row.get('call_id') in outer:raise ValueError('duplicate outer tool call')
        outer[row['call_id']]=row
        ids=row.get('provider_request_ids') or []
        if any(key not in requests or row['call_id'] not in requests[key].get('native_output_tool_call_ids',[]) for key in ids):
            raise ValueError('outer model tool lacks exact request output-call reference')
        paths={tuple(requests[key]['semantic_path']) for key in ids}
        expected=list(next(iter(paths))) if len(paths)==1 else unknown
        if row.get('semantic_path')!=expected:raise ValueError('outer tool stage differs from exact model request review')
    for actual,expected in zip((story.get('wall_partition') or {}).get('segments',[]),
                               (reapplied.get('wall_partition') or {}).get('segments',[])):
        if actual.get('kind')=='NATIVE_MODEL_TOOL_WINDOW':
            ids=actual.get('native_outer_ids') or []
            if not ids or any(key not in outer for key in ids):raise ValueError('native wall stage references unknown outer tool')
            path=outer[ids[0]]['semantic_path'] if len(ids)==1 else []
        else:path=expected.get('semantic_path')
        if actual.get('semantic_path')!=path:raise ValueError('wall responsibility differs from reviewed active IDs')


def compare_native_runs(cases):
    if len(cases)!=2:raise ValueError('exactly two source-linked runs required')
    vocabulary=None;version=None;runs=[];operations=[]
    for index,(name,story,annotations) in enumerate(cases):
        validate_compiled_story(story,annotations)
        taxonomy=annotations.get('taxonomy');current_version=annotations.get('taxonomy_version')
        if not isinstance(taxonomy,dict) or not current_version:raise ValueError('frozen reviewed taxonomy required')
        if vocabulary is None:vocabulary,version=taxonomy,current_version
        elif vocabulary!=taxonomy or version!=current_version:raise ValueError('cross-run taxonomy version/content differs')
        status=story.get('status');label=name+' · '+str(status)
        stages=defaultdict(lambda:{'inner_calls':0,'model_tool_calls':0,'model_requests':0,
            'known_provider_tokens':None,'requests_with_usage':0,'wall_ms':0})
        root_label=taxonomy['task'];unknown=[root_label,taxonomy['unassigned']]
        def path(row):
            value=row.get('semantic_path')
            return value if isinstance(value,list) and value and all(x in taxonomy.values() for x in value) else unknown
        def add(kind,row,measure,value,source_ref):
            p=path(row);stack=[{'kind':'task','label':root_label},{'kind':'run','label':label}]+[
                {'kind':'semantic','label':x} for x in p[1:]]
            operations.append({'kind':kind,'stack':stack,'measures':{measure:value},
                'evidence':{'run_id':story.get('run_id'),'source_ref':source_ref,
                    'attribution':'REVIEWED_TASK_RESPONSIBILITY_NOT_INTENT_OR_SPEEDUP_PROOF'}})
            return stages[' → '.join(p)]
        for number,row in enumerate(story.get('tools',[])):
            add('native_inner_call',row,'inner_calls',1,f'comparison#/runs/{index}/inner_call_count')['inner_calls']+=1
        for number,row in enumerate(story.get('native_model_tools',[])):
            add('native_model_tool',row,'model_tool_calls',1,f'comparison#/runs/{index}/model_tool_count')['model_tool_calls']+=1
        usage_count=0;tokens=0
        for number,row in enumerate(story.get('model_requests',[])):
            stage=stages[' → '.join(path(row))];stage['model_requests']+=1
            usage=(row.get('usage') or {}).get('total_tokens')
            if type(usage) is int and usage>=0:
                usage_count+=1;tokens+=usage
                bucket=add('provider_usage',row,'known_provider_tokens',usage,f'comparison#/runs/{index}/known_provider_tokens')
                bucket['known_provider_tokens']=(bucket['known_provider_tokens'] or 0)+usage
                stage['requests_with_usage']+=1
        for number,row in enumerate((story.get('wall_partition') or {}).get('segments',[])):
            duration=row.get('duration_ns')
            if type(duration) is int and duration>=0:
                add('wall_partition',row,'wall_ms',duration/1e6,f'comparison#/runs/{index}/wall_ms')['wall_ms']+=duration/1e6
        wall=story.get('agent_wall_ms')
        measured=sum(item['wall_ms'] for item in stages.values())
        if type(wall) not in (int,float) or abs(wall-measured)>1e-6:raise ValueError('cross-run wall aggregation lost conservation')
        runs.append({'name':name,'run_id':story.get('run_id'),'outcome':status,'wall_ms':wall,
            'wall_scope':story.get('wall_scope'),'inner_call_count':len(story.get('tools',[])),
            'model_tool_count':len(story.get('native_model_tools',[])),
            'model_request_count':len(story.get('model_requests',[])),
            'requests_with_usage':usage_count,'known_provider_tokens':tokens if usage_count else None,
            'token_completeness':'ALL_REQUESTS_HAVE_USAGE' if usage_count==len(story.get('model_requests',[])) else 'PARTIAL_KNOWN_TOKENS_ONLY',
            'stages':dict(stages),'semantic_method':annotations.get('method'),
            'trajectory_digest':annotations.get('trajectory_digest')})
    views=[]
    for metric,label,unit in (('inner_calls','原生执行通知项','次'),('model_tool_calls','模型工具调用项','次'),
        ('known_provider_tokens','已知 provider token','tokens'),('wall_ms','完整运行时墙钟','ms')):
        tree,count=fold_view(operations,metric,'两次运行：不能据此宣称提速')
        views.append({'name':metric,'label':label,'unit':unit,'quality':'失败与完成运行的工作量不同；仅解释责任分布，不是性能A/B',
            'status':'AVAILABLE' if count else 'NOT_COLLECTED','tree':tree,'total':tree['value'],'sample_count':count})
    return {'schema_version':1,'kind':'SOURCE_LINKED_NATIVE_RUN_COMPARISON','taxonomy_version':version,
        'taxonomy':vocabulary,'runs':runs,'speedup_claim_allowed':False,
        'reason':'run002 failed；run004 completed并执行修改/选定测试。结局、完成工作与环境均不能当成严格配对A/B。',
        'limitations':['缺失 usage 不当成零 token；已知 token 总和不等于费用。',
            '完整墙钟含启动/退出收尾；阶段缺证据的区间保留未分配。',
            '模型工具与内层通知是不同层，不能把两层时长相加。',
            '人工离线阶段标注不是模型真实意图，也不是论文自动递归分段的复现。'],
        'profile':{'schema_version':1,'agent_id':'native-campaign','task_id':vocabulary['task'],
            'operation_count':len(operations),'operations':operations,'views':views}}


def render_comparison(comparison):
    e=lambda x:escape(str(x),quote=True)
    runs=comparison['runs'];rows=[]
    metrics=(('outcome','Agent 结果'),('wall_ms','完整运行时墙钟 ms'),('model_request_count','模型 HTTP 请求'),
        ('model_tool_count','模型原生工具（exec 等）'),('inner_call_count','内层原生执行通知'),
        ('known_provider_tokens','已知 provider token（不是费用）'),('requests_with_usage','有 usage 的请求数'))
    for key,label in metrics:rows.append('<tr><th>'+e(label)+'</th>'+''.join('<td>'+e(run[key])+'</td>' for run in runs)+'</tr>')
    paths=sorted(set().union(*(run['stages'] for run in runs)))
    stage_rows=[]
    for path in paths:
        cells=[]
        for run in runs:
            stage=run['stages'].get(path)
            cells.append('<td>'+('未出现此阶段' if stage is None else e(str(stage['inner_calls'])+' 个内层项 / '+
                str(stage['model_tool_calls'])+' 个模型工具 / '+str(stage['known_provider_tokens'])+' 已知 tokens / '+str(round(stage['wall_ms'],3))+' ms'))+'</td>')
        stage_rows.append('<tr><th>'+e(path)+'</th>'+''.join(cells)+'</tr>')
    return '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>同任务责任对比：不是提速实验</title><style>body{font:15px system-ui;background:#f3f6f9;color:#193247;margin:0}main{max-width:1400px;margin:auto;padding:20px}table{width:100%;border-collapse:collapse;background:#fff}th,td{text-align:left;padding:10px;border:1px solid #d5e0e8}.warning{background:#fff1cc;padding:14px;border-left:4px solid #b57909}</style><main><h1>'+e(comparison['taxonomy']['task'])+'：两次实际运行的责任分布</h1><p class="warning">'+e(comparison['reason'])+' 不提供“提速百分比”，也不把失败运行当作优化基线。</p><p>同一冻结词表 '+e(comparison['taxonomy_version'])+'；分别绑定各自唯一原始轨迹。</p><table><thead><tr><th>口径</th>'+''.join('<th>'+e(run['name'])+'</th>' for run in runs)+'</tr></thead><tbody>'+''.join(rows)+'</tbody></table>'+render_profile_panel(comparison['profile'],profile_url='comparison-profile.json',evidence_url=None,source_urls={'comparison':'comparison.json'})+'<h2>相同责任名称下的实际工作</h2><table><thead><tr><th>任务阶段</th>'+''.join('<th>'+e(run['name'])+'</th>' for run in runs)+'</tr></thead><tbody>'+''.join(stage_rows)+'</tbody></table><ul>'+''.join('<li>'+e(x)+'</li>' for x in comparison['limitations'])+'</ul><a href="comparison.json">完整比较与来源绑定</a></main></html>'


def acceptance_public_summary(acceptance):
    health=acceptance.get('kernel_health') or {}
    return {'schema_version':1,'status':acceptance.get('status'),'run_id':acceptance.get('run_id'),
        'boot_id':acceptance.get('boot_id'),'application_outcome':acceptance.get('application_outcome'),
        'model_requests':acceptance.get('model_requests'),'native_model_tool_calls':acceptance.get('native_model_tool_calls'),
        'inner_tool_calls':acceptance.get('inner_tool_calls'),'kernel_totals':acceptance.get('kernel_totals'),
        'resource_sample_rows':acceptance.get('resource_sample_rows'),'manifest':acceptance.get('manifest'),
        'kernel_health':{'status':health.get('status'),'records':health.get('records'),
            'ring_drops':(health.get('counters') or {}).get('ring_drops'),'scope':health.get('scope')},
        'native_tool_ledger':acceptance.get('native_tool_ledger'),
        'per_tool_linux_binding':acceptance.get('per_tool_linux_binding'),'limits':acceptance.get('limits'),
        'privacy':'ALLOWLIST_SUMMARY; NO_PROVIDER_BODIES_CREDENTIALS_OR_BUDGET_FILES'}


def export_comparison(cases, output_directory):
    """Cases are (name, story_path, annotations_path); output must be new."""
    directory=Path(output_directory)
    if directory.exists():raise ValueError('new comparison directory required')
    parsed=[];sources=[]
    for name,story_path,annotations_path in cases:
        from semantic_annotations import validate_annotations
        story_path=Path(story_path)
        if not story_path.name.endswith('.story.json'):raise ValueError('compiled .story.json with sibling trajectory required')
        trajectory_path=story_path.with_name(story_path.name[:-len('.story.json')]+'.trajectory.json')
        story,annotations=read_json(story_path),read_json(annotations_path)
        validate_annotations(read_json(trajectory_path),annotations)
        parsed.append((name,story,annotations))
        sources.append({'name':name,'story':digest(story_path),'annotations':digest(annotations_path),
            'trajectory':digest(trajectory_path),'binding':'VALIDATED_TRAJECTORY_AND_COMPILED_STORY_REVIEW_PATHS'})
    result=compare_native_runs(parsed);result['source_identities']=sources
    directory.mkdir(mode=0o700)
    write_new(directory/'comparison.json',{key:value for key,value in result.items() if key!='profile'})
    write_new(directory/'comparison-profile.json',result['profile'])
    write_new(directory/'index.html',render_comparison(result).encode())
    return result


def _hardlink_evidence(source, target, source_root):
    source=Path(source);target=Path(target);root=Path(source_root).resolve(strict=True)
    if source.is_symlink() or not source.is_file() or root not in source.resolve(strict=True).parents:
        raise ValueError('publication source must be a named regular in-root file')
    before=digest(source);target.parent.mkdir(parents=True,exist_ok=True)
    os.link(source,target,follow_symlinks=False)
    if digest(source)!=before or digest(target)!=before:raise ValueError('source changed while linking')
    return before


def publish_frozen_live_view(frozen_directory, output_directory):
    """Reuse verified immutable artifacts without copying the large evidence.

    Only named source inputs and our generated JSON shard names are eligible.
    Hard links must not be edited after publication. The new HTML and profile
    revise display labels, never the captured values or original artifacts.
    """
    from native_agent_profile import PUBLIC_INPUT_ALLOWLIST, render_native_page
    source=Path(frozen_directory).resolve(strict=True);target=Path(output_directory).absolute()
    if target.exists() or target.is_symlink() or not target.parent.is_dir():raise ValueError('new publication directory required')
    target.mkdir(mode=0o700);linked={}
    names=['index.story.json','index.trajectory.json','index.annotations.json','index.artifacts.json','reviewed-marks.json']
    names+=['source/'+name for name in PUBLIC_INPUT_ALLOWLIST]
    for name in names:
        if (source/name).exists():linked[name]=_hardlink_evidence(source/name,target/name,source)
    shard_pattern=re.compile(r'(?:all-\d{5}|thread-[a-f0-9]{20}-\d{5})\.json\Z')
    for path in sorted((source/'index.assets').iterdir()):
        if not shard_pattern.fullmatch(path.name):raise ValueError('unexpected presentation shard')
        name='index.assets/'+path.name
        linked[name]=_hardlink_evidence(path,target/name,source)
    story=deepcopy(read_json(source/'index.story.json'));profile=deepcopy(read_json(source/'semantic-profile.json'))
    proxy={'MODEL_WAIT':'客户端等待模型代理首字节','MODEL_RECEIVE':'客户端接收模型代理响应'}
    for segment in (story.get('wall_partition') or {}).get('segments',[]):
        if segment.get('kind') in proxy:segment['label']=proxy[segment['kind']]
    for view in profile['views']:
        if view['name']=='model_wait_ms':view.update(label='客户端模型请求等待（代理首字节）',quality='Agent侧HTTP边界；预算代理会缓冲provider SSE，不是provider首token、精确推理或GPU时间')
        elif view['name']=='model_receive_ms':view.update(label='客户端接收模型代理响应',quality='Agent侧首body字节至代理响应结束；provider原始流可能已被预算代理缓冲')
        elif view['name']=='model_request_ms':view.update(label='客户端模型HTTP请求总耗时',quality='客户端代理请求边界，含网络/预算代理/上游处理；并发请求可重叠')
    # Read the old page's tiny routing map, not its generated JS or DOM.
    html=(source/'index.html').read_text()
    matched=re.search(r'<script id="native-view-data" type="application/json">(.*?)</script>',html,re.S)
    if not matched:raise ValueError('frozen native pagination manifest absent')
    pages=json.loads(matched.group(1))['pages']
    for urls in [pages.get('all',[])]+list(pages.get('by_thread',{}).values()):
        for url in urls:
            if url not in linked or not url.startswith('index.assets/'):raise ValueError('unpublished page reference')
    links={'report':'source/report.json','application':'source/app/steps.json','results':'source/app/native-tool-results.jsonl',
        'correlations':'source/native-process-correlations.json','model_timing':'source/app/model-request-timing.jsonl',
        'model_summary':'source/app/model-transport-summary.json','resource_summary':'source/resources/resource-summary.json',
        'resource_samples':'source/resources/resource-samples.jsonl','rpc':'source/app/rpc.jsonl','verification':'source/verification.json',
        'profile':'semantic-profile.json','trajectory':'index.trajectory.json','annotations':'index.annotations.json',
        'story':'index.story.json','artifact_receipt':'index.artifacts.json'}
    links={key:value for key,value in links.items() if key=='profile' or (target/value).is_file()}
    write_new(target/'semantic-profile.json',profile)
    compiled={'story':story,'profile':profile,'verification':read_json(source/'source/verification.json')}
    write_new(target/'index.html',render_native_page(compiled,links,pages).encode())
    receipt={'schema_version':1,'status':'IMMUTABLE_ALLOWLIST_HARDLINK_PUBLICATION','linked_inputs':linked,
        'derived_from':{'html':digest(source/'index.html'),'profile':digest(source/'semantic-profile.json')},
        'new_outputs':{'index.html':digest(target/'index.html'),'semantic-profile.json':digest(target/'semantic-profile.json')},
        'values_changed':False,'presentation_changes':['明确客户端代理缓冲SSE计时口径'],
        'warning':'Hardlinked evidence is immutable; do not edit. No recursive campaign or private-budget export.'}
    write_new(target/'publication.json',receipt)
    return receipt


def _render_campaign_index_base(*, live_url='live/index.html', comparison_url='compare/index.html', replay_url='replay/index.html'):
    """Three visibly different evidence contexts, lazy iframe loading."""
    e=lambda value:escape(str(value),quote=True)
    live_url,comparison_url,replay_url=map(_safe_url,(live_url,comparison_url,replay_url))
    tabs=[('live','真实 Agent 执行',live_url),('compare','两次运行对照',comparison_url),('replay','工具 → Linux 关联验证',replay_url)]
    return '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Agent 执行画像</title><style>body{margin:0;font:15px system-ui;background:#eff4f8;color:#20394c}header{padding:14px 20px;background:white;border-bottom:1px solid #cbd8e1}h1{margin:0 0 8px;font-size:24px}p{margin:7px 0;line-height:1.5}nav{display:flex;gap:8px;flex-wrap:wrap}button{border:1px solid #8ea9bb;background:white;border-radius:5px;padding:9px 14px;cursor:pointer}button[aria-selected=true]{background:#204e70;color:white}iframe{border:0;width:100%;height:calc(100vh - 212px);min-height:700px}aside{padding:10px 20px;background:#fff4d3}a{color:#194d79}</style><header><h1>一次 Agent 任务，实际做了什么？</h1><p>先看任务与原生工具，再点击火焰图逐层进入；没有可靠关联的 Linux 行为保留在全局，不硬塞给工具。</p><nav role="tablist">'+''.join('<button role="tab" id="tab-'+name+'" data-tab="'+name+'" data-src="'+e(url)+'" aria-selected="'+('true' if name=='live' else 'false')+'">'+label+'</button>' for name,label,url in tabs)+'</nav><p><a id="standalone" href="'+e(live_url)+'" target="_blank" rel="noopener">独立打开当前页面</a> · <a href="acceptance-summary.json">真实执行的重放／绑定验收摘要</a> · <a href="publication.json">公开文件清单与哈希</a> · 预算与证据保存：<a href="budget-summary.json">预算摘要</a> / <a href="archive-summary.json">证据归档</a></p></header><aside id="context">真实 Codex + DeepSeek，任务已修改代码并执行选定测试；不是官方 benchmark 成绩。模型等待是客户端代理 HTTP 时间，不是 provider 精确计算时间。</aside><iframe id="view" title="当前证据页面" src="'+e(live_url)+'"></iframe><script>const contexts={live:"真实 Codex + DeepSeek，任务已修改代码并执行选定测试；不是官方 benchmark 成绩。模型等待是客户端代理 HTTP 时间，不是 provider 精确计算时间。",compare:"同一任务词表下，一次失败、一次完成；实际完成的工作不同，不能当成提速实验。",replay:"独立的 trace replay，0 次付费 API；在新的实际执行里验证 argv／内核身份关联，不是事后补造真实执行 004 的 syscall 归属，也不提供本轮 replay001 的 slowdown。"};document.querySelectorAll("[data-tab]").forEach(button=>{button.addEventListener("click",()=>{document.querySelectorAll("[data-tab]").forEach(x=>x.setAttribute("aria-selected",String(x===button)));document.querySelector("#view").src=button.dataset.src;document.querySelector("#standalone").href=button.dataset.src;document.querySelector("#context").textContent=contexts[button.dataset.tab];});button.addEventListener("keydown",event=>{if(!["ArrowLeft","ArrowRight"].includes(event.key))return;event.preventDefault();const tabs=[...document.querySelectorAll("[data-tab]")];tabs[(tabs.indexOf(button)+(event.key==="ArrowRight"?1:tabs.length-1))%tabs.length].focus();});});</script></html>'


def render_campaign_index(*, live_url='live/index.html', comparison_url='compare/index.html', replay_url='replay/index.html'):
    page=_render_campaign_index_base(live_url=live_url,comparison_url=comparison_url,replay_url=replay_url)
    return page.replace('</p></header>',' · <a href="README.html">怎么读</a> / <a href="perf-summary.json">开销</a></p></header>',1)


def freeze_public_campaign(directory, *, additional_top_level=()):
    """Hash only a known presentation tree; reject accidental private exports."""
    from native_agent_profile import PUBLIC_INPUT_ALLOWLIST
    root=Path(directory).resolve(strict=True)
    if (root/'publication.json').exists():raise ValueError('new immutable campaign publication receipt required')
    allowed_top={'index.html','acceptance-summary.json','budget-summary.json','archive-summary.json',
        'perf-summary.json','README.md','README.html'}
    for name in additional_top_level:
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,100}\.(?:json|html|md)',name):
            raise ValueError('explicit safe top-level presentation filename required')
        if any(part in name.lower() for part in ('private','token','credential','secret')):
            raise ValueError('private-looking file cannot be added to publication')
        allowed_top.add(name)
    live_files={'index.html','semantic-profile.json','index.story.json','index.trajectory.json','index.annotations.json',
        'index.artifacts.json','reviewed-marks.json','publication.json'}
    replay_files={'index.html','summary.json','profile.json','scope.json','scope-export-verification.json','publication.json'}
    replay_sources={'report.json','verification.json','ready.json','manifest.json','app/steps.json',
        'app/native-tool-results.jsonl','exec-args-receipt.json'}
    files={}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():raise ValueError('public tree may not contain symlinks')
        if path.is_dir():continue
        name=str(path.relative_to(root));parts=name.split('/',1);accepted=False
        if len(parts)==1:accepted=name in allowed_top
        elif parts[0]=='live':
            tail=parts[1];accepted=tail in live_files or tail in {'source/'+item for item in PUBLIC_INPUT_ALLOWLIST} or bool(re.fullmatch(r'index\.assets/(?:all-\d{5}|thread-[a-f0-9]{20}-\d{5})\.json',tail))
        elif parts[0]=='compare':accepted=parts[1] in {'index.html','comparison.json','comparison-profile.json'}
        elif parts[0]=='replay':
            tail=parts[1];accepted=tail in replay_files or tail in {'source/'+item for item in replay_sources} or bool(re.fullmatch(r'pages/(?:all|tool-\d+)-\d{5}\.json',tail))
        if not accepted:raise ValueError('unexpected file in public tree: '+name)
        files[name]=digest(path)
    required={'index.html','live/index.html','compare/index.html','replay/index.html','acceptance-summary.json',
        'replay/scope-export-verification.json'}
    if not required.issubset(files):raise ValueError('required evidence presentation absent')
    result={'schema_version':1,'status':'FINAL_ALLOWLIST_PUBLIC_CAMPAIGN','files':files,
        'contexts':{'live':'REAL_CODEX_DEEPSEEK_NO_BACKFILLED_KERNEL_OWNERSHIP',
            'compare':'FAILED_VS_COMPLETED_TASK_RESPONSIBILITY_NOT_SPEEDUP',
            'replay':'NEW_ZERO_PAID_API_TRACE_REPLAY_ARGV_PROJECTION_AND_KERNEL_IDENTITY_CORRELATION'},
        'privacy':'NAMED_PRESENTATION_FILES_ONLY; NO_PRIVATE_BUDGET_OR_CREDENTIAL_FILES; PROMPTS_OUTPUTS_AND_PATHS_REMAIN_SENSITIVE',
        'scope':'UI_AND_NAMED_SOURCE_JSON; FULL_ORIGINAL_BINARY_WALS_REMAIN_PRIVATE',
        'immutability':'Hardlinked evidence and derived publication are immutable after this receipt.'}
    write_new(root/'publication.json',result)
    return result
