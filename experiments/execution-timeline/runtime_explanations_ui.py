"""Readable phase coverage and explicit application/kernel evidence links."""

SCRIPT=r'''
function explanationPanel(){
 const wp=story.wall_partition||{},unknown=(wp.totals_ns||{}).UNRESOLVED_RUNTIME||0;
 const unnamed=(story.tools||[]).filter(x=>x.semantic_quality==='UNANNOTATED');
 const segments=(wp.segments||[]).filter(x=>x.kind==='UNRESOLVED_RUNTIME').sort((a,b)=>b.duration_ns-a.duration_ns);
 const rows=segments.slice(0,12).map(x=>`<tr><td>+${ms((x.begin_ns-story.begin_ns)/1e6)} → +${ms((x.end_ns-story.begin_ns)/1e6)}</td><td>${ms(x.duration_ns/1e6)}</td><td>这一段没有模型、工具、V8 或已配对控制 RPC 阶段事件；不推断成 CPU、模型推理或磁盘等待。</td></tr>`).join('');
 const rpc=(story.runtime_phases||[]).map(x=>`<tr><td>${esc(x.label)}</td><td>${ms((x.end_ns-x.begin_ns)/1e6)}</td><td>按原始请求 ID 配对；客户端发送到响应收到，不是 CPU 耗时。</td></tr>`).join('');
 return `<details><summary>这些时间和标签是什么意思？未定位区间 ${ms(unknown/1e6)}；未提供步骤标签 ${unnamed.length} 个工具</summary><p class="runtime-note"><b>运行时处理（缺少内部阶段事件）</b>：Agent 的开始、结束已记录，但这一小段没有更细的执行器事件，所以知道它花了多久，不知道内部具体做了什么。不是漏算，也不是默认的模型等待。</p><p class="runtime-note"><b>未提供步骤标签</b>：任务是 ${esc(story.task_id)}，工具和命令已知；只是没有“定位问题／修改／测试”这样的子步骤标注。它不代表不知道哪个 Agent 或任务，也不能拿 Agent 的一句说明当作真实因果。</p>${rpc?`<div class="tables"><table><thead><tr><th>已补出的控制阶段</th><th>RPC 包围时间</th><th>口径</th></tr></thead><tbody>${rpc}</tbody></table></div>`:''}${rows?`<div class="tables"><table><thead><tr><th>尚未定位的时间窗</th><th>墙钟</th><th>为什么不再细分</th></tr></thead><tbody>${rows}</tbody></table></div>`:'<p>本次声明的阶段事件已覆盖墙钟；这不表示所有内部函数均已观测。</p>'}</details>`;
}

function runtimeCleanupPanel(){
 const r=story.runtime_cleanup;if(!r)return '';
 const residual=r.residual_processes_before_cleanup||[],after=r.after||{},values=after.accounting?.values||{};
 const names=residual.map(x=>`${esc(x.comm||'未知程序')} [PID ${esc(x.pid)}]`).join('、');
 return `<section><h3>任务结束后，进程和内存怎样收尾</h3><p>${r.had_residual_processes_after_root_exit?`Codex 主进程已退出，但当时组内还有 ${residual.length} 个后代：${names}。`:'主进程退出时，没有观察到仍存活的组内后代。'}${r.forced_cleanup?'已记录这些后代，再仅清理本轮新建的专用 cgroup；没有清理共享服务。':''}</p><p>清理后整组是否仍有进程：<b>${after.populated===false?'没有，已确认组空':after.populated===true?'仍有进程':'无法确认'}</b>。此时 cgroup 总记账 ${values['memory.current']!=null?bytes(values['memory.current']):'未取得'}，其中 anon ${values['memory.stat']?.anon!=null?bytes(values['memory.stat'].anon):'未取得'}、file ${values['memory.stat']?.file!=null?bytes(values['memory.stat'].file):'未取得'}。</p><p class="runtime-note">这是“退出时还有后代”的实际记录，不单凭这一瞬间就称为永久泄漏。组空后页缓存、内核记账和异步回收仍可能不为 0；清理前后读数也不是原子快照。PID 的退出标记与 cgroup 曲线是两件事。</p><details><summary>查看收尾回执</summary><pre class="raw">${esc(JSON.stringify(r,null,2))}</pre></details></section>`;
}

function chainState(status){
 const names={ORDERED_CONTEXT_ONLY:'同轮次的先前公开说明（不是因果证明）',MISSING:'这一段没有证据',CONFLICT:'证据存在冲突',PARTIAL:'部分联系尚未建立',MATCHED:'明确身份已匹配',MATCHED_NOT_REPLAYED:'字段匹配，尚未从原始记录重放',RAW_REPLAY_MATCHED:'原始 RPC 与工具账本重放匹配',OBSERVED:'已记录实际内核操作',TRUNCATED:'记录有展示上限',LINKED_WITHIN_SELECTED_EVIDENCE:'所选证据已连通（不等于全量覆盖）'};
 return names[status]||status||'未知';
}
function decisionEvidencePanel(){
 const evidence=story.decision_evidence||{},summary=evidence.summary||{},chains=evidence.chains||[];
 const items=chains.map((chain,index)=>{
  const tool=story.tools.find(x=>x.call_id===chain.call_id);
  const edges=(chain.edges||[]).map(edge=>`<li><b>${esc(edge.label)}</b>：${esc(chainState(edge.status))}${edge.reason?`<div class="muted">${esc(edge.reason)}</div>`:''}${edge.missing_fields?.length?`<div class="muted">缺少字段：${edge.missing_fields.map(esc).join('、')}</div>`:''}<details><summary>证据位置与身份字段</summary><pre class="raw">${esc(JSON.stringify(edge,null,2))}</pre></details></li>`).join('');
  const samples=(chain.observations||[]).slice(0,5).map(x=>`<tr><td>${esc(x.syscall)}</td><td>${esc(x.tid)}</td><td>${esc(x.result)}</td><td class="path">${(x.objects||[]).map(o=>esc(o.path||o.status)).join('<br>')||'这个 syscall 没有文件对象记录'}</td><td>${esc(x.evidence_ref)}</td></tr>`).join('');
  return `<details><summary>工具 ${index+1} · ${esc(chain.tool_name||chain.call_id)} — ${esc(chainState(chain.status))}</summary>${tool?`<div class="command">${esc(tool.command)}</div>`:''}<p class="muted">调用 ID：${esc(chain.call_id)} → Observer 工具 ID：${esc(chain.tool_call_id||'未绑定')}</p>${chain.context?`<blockquote>${esc(chain.context.text)}</blockquote><p class="runtime-note">这只是同一 thread/turn 中先于工具出现的公开消息，不是隐藏思维，也不证明真正原因。</p>`:'<p class="runtime-note">没有先前的公开步骤说明；工具调用和实际行为仍可分别核对。</p>'}<ol>${edges}</ol>${samples?`<div class="tables"><table><thead><tr><th>实际 syscall 示例</th><th>TID</th><th>返回值</th><th>文件／对象</th><th>原始位置</th></tr></thead><tbody>${samples}</tbody></table></div><p class="runtime-note">这里仅举前 5 条；同页逐工具区保留全部已展示 syscall 和文件操作。</p>`:''}</details>`;
 }).join('');
 const downloads=(profile.downloads||[]).map(x=>`<a href="${esc(x.href)}">${esc(x.view)} 标准 pprof</a>`).join(' · ');
 return `<section><h3>Agent 调用了什么，实际发生了什么</h3><p>${fmt(summary.tool_calls||0)} 次工具调用；${fmt(summary.linked_calls||0)} 条执行链已连通；${fmt(summary.kernel_syscall_observations||0)} 条内核 syscall；${fmt(summary.context_links||0)} 条先前公开说明。</p><p class="runtime-note">公开说明 → 真实工具请求 → 停止启动门 → PID/cgroup → 内核线程 → syscall/对象。只有明确 ID 与原始证据才能连接；不能用时间接近或模型文字猜测。</p><p class="runtime-note">内核历史覆盖：${esc(evidence.operation_history_status||'未提供')}。执行链连通不代表没有丢失、对象全部解析或真实决策因果已经证明。原始应用重放：${esc(evidence.application_source_replay?.status||'未运行')}；独立内核 verifier 回执：${esc(evidence.native_replay?.reported_status||'未提供')}（页面只读取结果，不会重新执行内核 verifier）。</p>${downloads?`<p>${downloads}</p>`:''}${items||'<p class="runtime-note">没有可连接的工具调用记录。</p>'}</section>`;
}
'''
