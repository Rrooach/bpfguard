"""Self-contained display for measured model/V8 timings and memory usage."""

STYLE = r'''
.runtime-panel{padding:22px;background:#fff;border:1px solid #d9dfeb;border-radius:14px;margin:20px 0}
.runtime-panel h3{margin:18px 0 8px}.runtime-note{color:#657086;margin:7px 0;font-size:13px}
.memory-select{padding:7px;border:1px solid #cdd5e3;border-radius:7px;max-width:100%;margin:10px 0}
.memory-plot{width:100%;border:1px solid #e2e7f0;border-radius:9px;background:#fafcff;overflow:auto}
.memory-plot svg{display:block;min-width:700px}.phase-bar{display:flex;height:25px;border-radius:6px;overflow:hidden;margin:12px 0}
.phase-bar span{min-width:0;white-space:nowrap;color:white;font-size:11px;padding:3px;overflow:hidden}
'''


SCRIPT = r'''
const roleNames={AGENT_RUNTIME:'Codex 运行时',TOOL_ROOT:'工具 root 进程',TOOL_PROCESS:'工具进程',AGENT_CONTAINER:'Agent 容器',AGENT_TOTAL:'Agent 整组',AGENT:'Agent 整组',OBSERVER_CONTROL:'Observer 管理进程',OBSERVER_SUPERVISOR:'Observer 管理进程',OBSERVER_COLLECTOR:'Observer 采集器',CODE_MODE_RUNTIME:'V8 运行时'};
function memoryTargets(){return (story.memory?.targets||[])}
function peakText(x){return x==null?'未采集':bytes(x)}
function runtimeMetricsPanel(){
 const req=story.model_requests||[],mode=story.code_mode||{},inv=mode.invocations||[],mem=story.memory||{},wp=story.wall_partition||{};
 const collection=story.model_collection||{},collectionNote=collection.status==='PARTIAL'?`<p class="runtime-note">⚠ 模型请求计时不完整：${fmt(collection.accepted_count)} 次开始、${fmt(collection.finished_count)} 次结束。已确认时长只是已记录部分；缺失请求不会算成 0。${esc((collection.reason_flags||[]).join(' / '))}</p>`:'';
 const sum=(rows,k)=>rows.reduce((v,x)=>v+(Number(x[k])||0),0);
 const modelWait=req.some(x=>x.wait_first_byte_ms!=null)?ms(sum(req,'wait_first_byte_ms')):'未采集';
 const js=inv.some(x=>x.js_ms!=null)?ms(sum(inv,'js_ms')):'未采集';
 const codeWait=inv.some(x=>x.tool_wait_ms!=null)?ms(sum(inv,'tool_wait_ms')):'未采集';
 const targets=memoryTargets(),runtime=targets.find(x=>x.target.role==='AGENT_RUNTIME');
 const v8Peak=Math.max(0,...inv.map(x=>Number(x.v8_heap_used_peak_bytes)||0));
 const cards=`<div class="metrics"><div class="metric"><b>${modelWait}</b>模型首字节等待</div><div class="metric"><b>${js}</b>V8 JavaScript 执行段</div><div class="metric"><b>${codeWait}</b>Code Mode 等待工具</div><div class="metric"><b>${runtime?peakText(runtime.sampled_rss_peak_bytes):'未采集'}</b>Codex 采集窗 RSS 峰值</div><div class="metric"><b>${v8Peak?bytes(v8Peak):'未采集'}</b>V8 heap 最大已观测值</div><div class="metric"><b>${peakText(mem.observer_peak_rss_bytes)}</b>Observer 单进程 RSS 峰值</div></div>${collectionNote}`;
 const phases=Object.entries(wp.totals_ns||{}).filter(([k,v])=>v>0).map(([k,v],i)=>`<span style="width:${100*v/wp.wall_ns}%;background:${['#64748b','#2563eb','#7c3aed','#0f766e','#c2410c','#0891b2'][i%6]}" title="${esc(wp.labels[k])} · ${ms(v/1e6)}">${esc(wp.labels[k])}</span>`).join('');
 const modelRows=req.map((x,i)=>`<tr><td>模型请求 ${i+1}<br><span class="muted">${esc(x.request_id)}</span></td><td>${ms(x.wait_first_byte_ms)}</td><td>${ms(x.response_receive_ms)}</td><td>${ms(x.request_ms)}</td><td>${esc(x.status||'UNKNOWN')}<br><span class="muted">${x.clock_alignment==='SAME_BOOT'?'与 Agent 同一 Linux 时钟':'请求在另一 Linux 计时，仅展示时长'}</span></td></tr>`).join('');
 const modeRows=inv.map(x=>`<tr><td>${esc(x.call_id)}<br><span class="muted">${x.boot_id===story.boot_id?'与 Agent 同一 Linux 时钟':'另一个 Linux：仅展示时长'}</span></td><td>${ms(x.wall_ms)}</td><td>${ms(x.js_ms)}</td><td>${ms(x.tool_wait_ms)}</td><td>${peakText(x.v8_heap_used_peak_bytes)}</td><td>${peakText(x.process_rss_peak_bytes)}</td></tr>`).join('');
 return `<section class="runtime-panel"><h2>时间花在哪里，内存用了多少</h2>${cards}<div class="phase-bar">${phases}</div><p class="runtime-note">色条按 Agent 墙钟划分，每一段只计一次；并行区间单独保留。“尚未细分”不会自动算作模型等待。</p><details ${req.length?'open':''}><summary>模型请求计时（${req.length} 次）</summary>${req.length?`<div class="tables"><table><thead><tr><th>请求</th><th>首字节等待</th><th>响应接收</th><th>请求总耗时</th><th>结果／时钟</th></tr></thead><tbody>${modelRows}</tbody></table></div>`:'<p class="runtime-note">这次记录缺少模型请求边界，无法从工具间空档还原。</p>'}<p class="runtime-note">首字节可能是 SSE 元数据；等待包含网络、服务排队、生成及上游缓冲。响应接收与 broker 本地处理分开记录。</p></details><details ${inv.length?'open':''}><summary>V8／Code Mode 执行（${inv.length} 次）</summary>${inv.length?`<div class="tables"><table><thead><tr><th>执行 ID</th><th>总墙钟</th><th>JS 执行段</th><th>等待工具</th><th>V8 heap</th><th>进程 RSS</th></tr></thead><tbody>${modeRows}</tbody></table></div>`:`<p class="runtime-note">${esc(mode.reason||'没有 Code Mode 执行事件；Codex 进程的耗时不会被当成 V8 执行。')}</p>`}<p class="runtime-note">JS 段来自执行器的明确边界；并发工具等待按区间并集计时，父调用等待和工具执行不会重复加入墙钟。V8 主线程 CPU 仅覆盖被标记的 JS 执行段。</p></details>${memoryDetailsPanel()}${runtimeCleanupPanel()}${explanationPanel()}${decisionEvidencePanel()}</section>`;
}
'''

from runtime_memory_ui import SCRIPT as MEMORY_SCRIPT, STYLE as MEMORY_STYLE
from runtime_explanations_ui import SCRIPT as EXPLANATIONS_SCRIPT
STYLE += MEMORY_STYLE
SCRIPT += MEMORY_SCRIPT + EXPLANATIONS_SCRIPT

PROFILE_SCRIPT = r'''
function metric(v,u){if(u==='bytes')return bytes(v);if(u==='byte_ms')return (v/1048576000).toLocaleString(undefined,{maximumFractionDigits:3})+' MiB·s';if(u==='ms')return ms(v);return fmt(v)+' '+u}
function focusProfileTool(callId){const i=story.tools.findIndex(x=>x.call_id===callId);if(i<0)return;const el=document.querySelector('#agent-tool-'+i);const outer=el?.closest('section.flow')?.closest('details');if(outer)outer.open=true;el?.scrollIntoView({behavior:'smooth',block:'start'})}
function drawProfile(name){
 const view=profile.views.find(v=>v.name===name&&v.status==='AVAILABLE')||profile.views.find(v=>v.status==='AVAILABLE');if(!view)return;
 document.querySelector('#profile-select').value=view.name;
 document.querySelector('#profile-summary').innerHTML=`<strong>${esc(view.label)}：${esc(metric(view.total,view.unit))}</strong> · ${fmt(view.sample_count)} 个可加权 operation<br><span class="muted">${esc(view.quality)}</span>`;
 const container=document.querySelector('#profile-chart');
 if(view.total===0){container.innerHTML='<p class="runtime-note">已采集，当前指标为 0。</p>';return}
 const width=1120,row=29,pad=2,items=[];let depth=0;
 function walk(n,x,d,w,path,owner){depth=Math.max(depth,d);owner=n.metadata?.call_id||owner;items.push({n,x,d,w,path:[...path,n.label],owner});let at=x;(n.children||[]).forEach(c=>{const cw=n.value?w*c.value/n.value:0;walk(c,at,d+1,cw,[...path,n.label],owner);at+=cw})}
 walk(view.tree,0,0,width,[],null);
 const height=(depth+1)*row+8;
 const svg=items.filter(i=>i.w>.25).map(i=>{const x=i.x+pad/2,w=Math.max(.25,i.w-pad),y=i.d*row+4,color=colors[i.n.kind]||'#64748b',cap=Math.floor((w-10)/12),text=cap>2?(i.n.label.length>cap?i.n.label.slice(0,cap-1)+'…':i.n.label):'';return `<g ${i.owner?`data-call-id="${esc(i.owner)}" style="cursor:pointer"`:''}><title>${esc(i.path.join(' → '))}\n${esc(view.label)}: ${esc(metric(i.n.value,view.unit))} (${(100*i.n.value/view.total).toFixed(2)}%)${i.owner?'\n点击查看该工具命令、文件和 syscall':''}</title><rect x="${x}" y="${y}" width="${w}" height="${row-3}" rx="3" fill="${color}" opacity=".92"/><text x="${x+5}" y="${y+18}" fill="white" font-size="12" pointer-events="none">${esc(text)}</text></g>`}).join('');
 container.innerHTML=`<svg viewBox="0 0 ${width} ${height}" width="100%" height="${height}" role="img" aria-label="${esc(view.label)} semantic flamegraph">${svg}</svg>`;
 container.onclick=event=>{const target=event.target.closest('[data-call-id]');if(target)focusProfileTool(target.getAttribute('data-call-id'))};
}
'''
