"""Human-readable PID versus cgroup memory panels for runtime captures.

The browser code consumes execution_metrics.memory_data's projection.  It never
fills a missing observation or a lifecycle endpoint with a made-up zero.  The
root renderer supplies story, esc, ms, bytes, fmt, roleNames and memoryTargets.
"""

STYLE = r'''
.memory-scope{margin:6px 0;color:#64748b;font-size:12px}.memory-alert{border-left:4px solid #b45309;background:#fff7ed;padding:10px 14px;margin:10px 0;color:#9a3412}
.memory-controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center}.memory-controls label{font-size:13px}.memory-caption{padding:7px 12px}.memory-muted{color:#64748b;font-size:12px}
'''

SCRIPT = r'''
function memoryHumanReason(reason){
 const reasons={
  PID_NOT_REGISTERED:'没有登记单个进程 PID，此对象只按 cgroup 记账',
  CGROUP_NOT_REGISTERED_FOR_TARGET:'此次只登记了 PID，没有登记可单独记账的 cgroup',
  NO_SUCCESSFUL_SAMPLE_FOR_FIELD:'采样时未成功读到这个字段，不能按 0 处理',
  PID_IDENTITY_NOT_ESTABLISHED_AT_REGISTRATION:'登记时没有确认 PID 的启动身份，不能认领其内存',
  PID_IDENTITY_CHANGED:'PID 已被复用，前后样本不能当作同一个进程',
  CGROUP_IDENTITY_CHANGED:'cgroup 身份发生变化，前后样本不能视为同一个执行组',
  CGROUP_CONTROLLER_OR_FILE_UNAVAILABLE_SEE_COLLECTION_ERRORS:'cgroup 内存控制器或采集文件不可读，详细原因见下方',
  LEGACY_OR_INCOMPLETE_CAPTURE_NO_FINISH_EVENT:'旧记录没有结束事件，无法确认进程何时退出',
  RESOURCE_SAMPLER_NOT_ENABLED_OR_ARTIFACTS_NOT_PROVIDED:'这次没有保存内存采样文件',
 };
 return reasons[reason]||'采集证据不足；未取得该项有效读数';
}
function memoryValue(item,metric,fallback){
 const detail=item.memory_metrics?.[metric],value=detail?.peak_bytes??item[fallback];
 if(typeof value==='number'&&Number.isFinite(value)&&value>=0){
  const partial=detail?.status==='IDENTITY_CHANGED_PARTIAL';
  return `${esc(bytes(value))}${partial?'<br><span class="memory-muted">仅身份变化前的有效样本</span>':''}`;
 }
 return `<span class="memory-muted">${esc(memoryHumanReason(detail?.reason))}</span>`;
}
function memoryObject(item){
 const target=item.target||{},role=roleNames[target.role]||target.role||'观测对象';
 return `${esc(role)}<br><span class="memory-muted">${esc(target.name||'未命名对象')}${target.pid!=null?' · PID '+esc(fmt(target.pid)):''}</span>`;
}
function memoryScope(target){
 const scope=String(target?.cgroup_scope||'');
 if(scope.includes('SHARED'))return '共享 cgroup：不能全部归给这一个进程或工具调用';
 if(scope.includes('FRESH_EPHEMERAL_TOOL')||scope.includes('PRIVATE_TOOL'))return '本次工具专用 cgroup，包含其后代进程';
 if(scope.includes('AGENT_TOTAL')||scope.includes('AGENT_DOMAIN'))return 'Agent 整组，包含运行时与其工具后代';
 if(scope.includes('PRIVATE')||scope.includes('EXCLUSIVE'))return '独立 cgroup，包含其后代；具体范围以登记配置为准';
 return '显式登记的 cgroup，包含其后代；不自动等于单个工具';
}
function memoryGroupIdentity(item){
 const target=item.target||{},id=target.cgroup_identity;
 // A path alone is not lifetime identity: the directory could be recreated.
 // Non-safe JS integers cannot establish equality of original kernel IDs.
 if(!id||typeof id.path!=='string'||!id.path||id.path!==target.cgroup||
    !Number.isSafeInteger(id.device)||id.device<0||!Number.isSafeInteger(id.inode)||id.inode<=0)return null;
 return JSON.stringify([id.path,id.device,id.inode]);
}
function memoryCgroups(targets){
 const groups=[],lookup=new Map();
 for(const item of targets){
  if(!item.target?.cgroup)continue;
  const key=memoryGroupIdentity(item);
  let group=key===null?null:lookup.get(key);
  if(!group){group={identity_complete:key!==null,key,items:[]};groups.push(group);if(key!==null)lookup.set(key,group)}
  group.items.push(item);
 }
 const fields=[['cgroup_memory','sampled_cgroup_memory_peak_bytes'],['cgroup_anon','sampled_cgroup_anon_peak_bytes'],['cgroup_file','sampled_cgroup_file_peak_bytes']];
 const valid=value=>typeof value==='number'&&Number.isFinite(value)&&value>=0;
 for(const group of groups){
  const combined={target:group.items[0].target,memory_metrics:{},collection_errors:{},cgroup_sample_count:0};
  for(const [metric,field] of fields){
   let peak=null,partial=false,reason=null;
   for(const item of group.items){
    const detail=item.memory_metrics?.[metric],value=detail?.peak_bytes??item[field];
    if(valid(value))peak=peak===null?value:Math.max(peak,value);
    partial=partial||detail?.status==='IDENTITY_CHANGED_PARTIAL';reason=reason||detail?.reason;
   }
   combined[field]=peak;
   combined.memory_metrics[metric]={peak_bytes:peak,status:partial?'IDENTITY_CHANGED_PARTIAL':peak===null?'NOT_COLLECTED':'OBSERVED_SAMPLED_PEAK',reason};
  }
  let high=null;
  for(const item of group.items){
   const value=item.cgroup_lifetime_memory_peak_bytes;if(valid(value))high=high===null?value:Math.max(high,value);
   const count=item.cgroup_sample_count;if(Number.isSafeInteger(count)&&count>=0)combined.cgroup_sample_count+=count;
   for(const [field,error] of Object.entries(item.collection_errors||{}))combined.collection_errors[(item.target.name||'对象')+':'+field]=error;
  }
  combined.cgroup_lifetime_memory_peak_bytes=high;group.aggregate=combined;
 }
 return groups;
}
function memoryGroupObject(group){
 const names=group.items.map(memoryObject).join('<br>');
 const shared=group.items.length>1?`<p class="memory-scope">同一 cgroup 的 ${esc(fmt(group.items.length))} 个登记对象；整组用量只列一次，各观察取最大值，不相加。</p>`:'';
 const identity=group.identity_complete?'':`<p class="memory-scope">⚠ cgroup 身份记录不完整：未与其他对象合并。不能仅凭路径相同认定是同一组，也不能直接与其他行相加。</p>`;
 return names+shared+`<p class="memory-scope">${esc(memoryScope(group.aggregate.target))}</p>`+identity;
}
function memoryLifecycle(item){
 const life=item.lifecycle||{},marker=(story.memory?.lifecycle_markers||[]).find(x=>x.name===item.target?.name);
 let text;
 if(life.confirmed_exit===true&&life.status==='EXIT_CONFIRMED'){
  text='已确认进程退出：该 PID 的地址空间已结束';
  if(Number.isInteger(life.exit_returncode))text+='；退出码 '+life.exit_returncode;
 }else if(life.status==='PID_STILL_PRESENT_AT_OBSERVATION_END')text='停止采样时进程仍存在，不应归零';
 else if(life.status==='EXIT_UNCONFIRMED_PROCESS_UNAVAILABLE')text='已无法读取进程，但没有退出证明，不按 0 处理';
 else if(life.status==='CGROUP_OBSERVATION_ENDED')text='本组采样结束；不代表组内进程为空或内存已释放';
 else text='未记录进程结束事件；曲线只到最后一个有效采样点';
 return esc(text)+(marker&&Number.isFinite(marker.at_ms)?`<br><span class="memory-muted">结束确认／停止采样：Agent 起点后 ${esc(ms(marker.at_ms))}</span>`:'');
}
function memoryCollectionErrors(item){
 const errors=Object.entries(item.collection_errors||{});
 if(!errors.length)return '';
 return `<details><summary>查看 ${esc(fmt(errors.length))} 项读取问题</summary><ul>${errors.slice(0,12).map(([field,error])=>`<li>${esc(String(field).slice(0,120))}：${esc(String(error).slice(0,240))}</li>`).join('')}</ul></details>`;
}
function memoryDetailsPanel(){
 const mem=story.memory||{},targets=memoryTargets();
 if(!targets.length)return `<section id="memory-details"><h3>内存使用</h3><p class="runtime-note">${esc(memoryHumanReason(mem.reason))}，不能据此判断内存用量为 0。</p></section>`;
 const pids=targets.filter(x=>x.target?.pid!=null||x.sampled_rss_peak_bytes!=null),groups=memoryCgroups(targets);
 const missingGroups=targets.filter(x=>x.target?.pid!=null&&!x.target?.cgroup);
 const pidRows=pids.map(x=>`<tr data-memory-pid-row="1"><td>${memoryObject(x)}</td><td>${memoryValue(x,'process_rss','sampled_rss_peak_bytes')}</td><td>${memoryValue(x,'process_rss_anon','sampled_process_rss_anon_peak_bytes')}</td><td>${memoryValue(x,'process_rss_file','sampled_process_rss_file_peak_bytes')}</td><td>${memoryValue(x,'process_rss_shmem','sampled_process_rss_shmem_peak_bytes')}</td><td>${esc(fmt(x.process_sample_count??0))} 个有效样本<br>${memoryLifecycle(x)}${memoryCollectionErrors(x)}</td></tr>`).join('');
 const groupRows=groups.map(group=>{const x=group.aggregate;return `<tr data-memory-cgroup-row="1"><td>${memoryGroupObject(group)}</td><td>${memoryValue(x,'cgroup_memory','sampled_cgroup_memory_peak_bytes')}</td><td>${typeof x.cgroup_lifetime_memory_peak_bytes==='number'&&Number.isFinite(x.cgroup_lifetime_memory_peak_bytes)&&x.cgroup_lifetime_memory_peak_bytes>=0?esc(bytes(x.cgroup_lifetime_memory_peak_bytes)):'<span class="memory-muted">内核未提供或字段不可读</span>'}</td><td>${memoryValue(x,'cgroup_anon','sampled_cgroup_anon_peak_bytes')}</td><td>${memoryValue(x,'cgroup_file','sampled_cgroup_file_peak_bytes')}</td><td>${esc(fmt(x.cgroup_sample_count??0))} 次有效读取${group.items.length>1?'<br><span class="memory-muted">包含同组各对象的读取，不代表不同时间点数量</span>':''}${memoryCollectionErrors(x)}</td></tr>`}).join('');
 const choices=targets.map((x,i)=>`<option value="${i}">${esc(roleNames[x.target?.role]||x.target?.role||'对象')} · ${esc(x.target?.name||'未命名')}</option>`).join('');
 const alert=mem.sample_limit_reached?'<p class="memory-alert">⚠ 已达到采样上限：后续时间可能没有内存曲线；这里的采样峰值不是完整运行的保证峰值。</p>':'';
 const otherWarnings=(mem.collection_warnings||[]).length&&!mem.sample_limit_reached?'<p class="memory-alert">⚠ 采集器报告了采样异常；以下结果只代表成功保存的有效样本。</p>':'';
 const accountingNote='<p class="runtime-note">采集器 RSS 包含 ring buffer 的 mmap 映射，以及可能共享或别名映射的页；RSS 不等于新增的私有物理内存。不能把各进程 RSS 峰值相加，也不能再加上共享 cgroup 的峰值。同一个 cgroup 仅在路径、设备号和 inode 均有完整身份记录且一致时合并。</p>';
 const missingNote=(missingGroups.length?`<p class="runtime-note">${esc(fmt(missingGroups.length))} 个 PID 对象没有登记 cgroup，因此不显示这些对象的 cgroup 空列；PID 的 RSS 不能推算出整组总用量或文件页缓存。</p>`:'')+accountingNote;
 return `<section id="memory-details"><h3>内存：分清单个进程与整个执行组</h3>${alert}${otherWarnings}<div class="memory-controls"><label>对象 <select id="memory-target" class="memory-select" onchange="drawMemory(this.value)">${choices}</select></label><label>记账方式 <select id="memory-accounting" class="memory-select" onchange="memoryAccountingChanged()"><option value="pid">单 PID 驻留内存</option><option value="cgroup">cgroup 整组内存</option></select></label></div><div class="memory-plot" id="memory-plot"></div><h4>单进程：RSS 由什么组成</h4>${pids.length?`<div class="tables"><table><thead><tr><th>对象</th><th>RSS 采样峰值</th><th>匿名驻留页</th><th>文件映射驻留页</th><th>共享内存驻留页</th><th>有效样本与结束情况</th></tr></thead><tbody>${pidRows}</tbody></table></div>`:'<p class="runtime-note">这次没有登记单独 PID，仅采集执行组资源。</p>'}<p class="runtime-note">以上四列是各自的采样峰值，不一定出现在同一时刻，不能直接相加。文件映射驻留页（RssFile）不是整个文件页缓存；单 PID 也不包含全部子进程。</p><h4>执行组：包含后代、缓存与内核记账</h4>${groups.length?`<div class="tables"><table><thead><tr><th>对象与范围</th><th>总用量采样峰值</th><th>内核 memory.peak</th><th>匿名内存采样峰值</th><th>文件缓存采样峰值</th><th>样本与读取问题</th></tr></thead><tbody>${groupRows}</tbody></table></div><p class="runtime-note">memory.current 是整组总记账；anon 与 file 是其中不同类别，不是全部构成。memory.peak 是该 cgroup 生涯峰值，只有新建的专用组才能直接对应本次调用。父组包含子组，不能重复相加；共享缓存按内核记账归属，不等于谁读了它。</p>`:'<p class="runtime-note">本次只登记了 PID，没有登记目标 cgroup，因此无法提供整组内存、cgroup 匿名内存和文件缓存。不是这些值为 0。</p>'}${missingNote}<p class="runtime-note">曲线覆盖保存下来的完整采集窗，包含 Agent 前的准备和结束后的收尾；蓝色边界表示 Agent 开始／结束。${mem.interval_ms!=null?'配置采样间隔 '+esc(fmt(mem.interval_ms))+' ms，':''}短时峰值可能落在两次采样之间。进程退出单独标记，不伪造末尾 0；进程退出后，cgroup 页缓存仍可能保留。Observer 用量独列，额外开销仍需关闭／开启的配对测量。</p></section>`;
}
function memoryAccountingChanged(){drawMemory(document.querySelector('#memory-target')?.value||0)}
function drawMemory(index){
 const mem=story.memory||{},item=memoryTargets()[Number(index)],plot=document.querySelector('#memory-plot');if(!item||!plot)return;
 const target=item.target||{},selector=document.querySelector('#memory-accounting');
 const hasPid=target.pid!=null||item.sampled_rss_peak_bytes!=null,hasGroup=Boolean(target.cgroup);
 let mode=selector?.value||'pid',fallback='';
 if(mode==='cgroup'&&!hasGroup){mode='pid';fallback='此对象没有登记 cgroup，切回单 PID 读数。'}
 if(mode==='pid'&&!hasPid&&hasGroup){mode='cgroup';fallback='此对象只登记了 cgroup，显示整组读数。'}
 if(selector){selector.value=mode;for(const option of selector.options||[]){if(option.value==='pid')option.disabled=!hasPid;if(option.value==='cgroup')option.disabled=!hasGroup}}
 const fields=mode==='pid'?[['rss_bytes','RSS 总驻留','#2563eb'],['rss_anon_bytes','匿名驻留页','#ea580c'],['rss_file_bytes','文件映射驻留页','#059669'],['rss_shmem_bytes','共享内存驻留页','#7c3aed']]:[['cgroup_current_bytes','整组总用量','#7c3aed'],['cgroup_anon_bytes','整组匿名内存','#ea580c'],['cgroup_file_bytes','整组文件缓存','#059669']];
 const numeric=x=>typeof x==='number'&&Number.isFinite(x),valid=x=>numeric(x)&&x>=0;
 const source=Array.isArray(mem.capture_series)?mem.capture_series:(mem.series||[]);
 const points=source.filter(x=>x.name===target.name&&numeric(x.at_ms)).slice().sort((a,b)=>a.at_ms-b.at_ms);
 const selected=fields.filter(f=>points.some(p=>valid(p[f[0]])));
 if(!selected.length){const metric=mode==='pid'?'process_rss':'cgroup_memory';plot.innerHTML=`<p class="memory-caption">${esc(fallback)}${esc(memoryHumanReason(item.memory_metrics?.[metric]?.reason))}。没有绘制虚构的 0 曲线。</p><p class="memory-caption">${memoryLifecycle(item)}</p>`;return}
 const markers=(mem.lifecycle_markers||[]).filter(x=>x.name===target.name&&numeric(x.at_ms));
 const xmin=Math.min(0,numeric(mem.capture_begin_ms)?mem.capture_begin_ms:0,...points.map(x=>x.at_ms));
 const xmax=Math.max(xmin+1,numeric(story.agent_wall_ms)?story.agent_wall_ms:0,numeric(mem.capture_end_ms)?mem.capture_end_ms:0,...points.map(x=>x.at_ms),...markers.map(x=>x.at_ms));
 let ymax=1;for(const p of points)for(const f of selected)if(valid(p[f[0]]))ymax=Math.max(ymax,p[f[0]]);
 const W=1080,H=280,L=86,R=20,T=44,B=46,X=x=>L+(W-L-R)*(x-xmin)/(xmax-xmin),Y=y=>T+(H-T-B)*(1-y/ymax);
 const allowedGap=3*(valid(mem.interval_ms)&&mem.interval_ms>0?mem.interval_ms:100);
 const lines=selected.map(([key,label,color])=>{let path='',before=null;for(const p of points){if(!valid(p[key])){before=null;continue}const connect=before!==null&&p.at_ms-before<=allowedGap;path+=(connect?'L':'M')+X(p.at_ms).toFixed(2)+','+Y(p[key]).toFixed(2);before=p.at_ms}return `<path data-memory-field="${key}" d="${path}" stroke="${color}" stroke-width="2" fill="none"><title>${esc(label)}</title></path>`}).join('');
 const ticks=[0,.5,1].map(v=>`<line x1="${L}" x2="${W-R}" y1="${Y(v*ymax)}" y2="${Y(v*ymax)}" stroke="#e2e8f0"/><text x="${L-8}" y="${Y(v*ymax)+4}" text-anchor="end" font-size="11" fill="#64748b">${esc(bytes(v*ymax))}</text>`).join('');
 const wall=numeric(story.agent_wall_ms)&&story.agent_wall_ms>=0?story.agent_wall_ms:0;
 const agentEdges=[[0,'Agent 开始'],[wall,'Agent 结束']].map(([at,label])=>`<line x1="${X(at)}" x2="${X(at)}" y1="${T-8}" y2="${H-B}" stroke="#2563eb" stroke-dasharray="4 4"/><text x="${X(at)}" y="${T-18}" font-size="11" text-anchor="${at===0?'start':'end'}" fill="#1d4ed8">${label}</text>`).join('');
 const lifecycle=markers.map(marker=>{const exited=mode==='pid'&&marker.confirmed_exit===true&&marker.status==='EXIT_CONFIRMED';const label=exited?'进程已退出（地址空间结束）':mode==='cgroup'?'本组采样结束（不代表内存归零）':'采样结束（未确认进程退出）';const color=exited?'#b91c1c':'#a16207';return `<line x1="${X(marker.at_ms)}" x2="${X(marker.at_ms)}" y1="${T}" y2="${H-B}" stroke="${color}" stroke-dasharray="3 3"><title>${esc(label)} · ${esc(ms(marker.at_ms))}</title></line><text x="${X(marker.at_ms)}" y="${H-B+16}" font-size="10" fill="${color}" text-anchor="end">${esc(label)}</text>`}).join('');
 plot.innerHTML=`<p class="memory-caption">${memoryObject(item)} · ${mode==='pid'?'单 PID，不含后代进程':'cgroup 整组'}${fallback?'<br>'+esc(fallback):''}</p><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(mode==='pid'?'单进程驻留内存曲线':'cgroup 整组内存曲线')}"><rect x="${X(0)}" y="${T}" width="${Math.max(0,X(wall)-X(0))}" height="${H-T-B}" fill="#eff6ff"/>${ticks}${lines}${agentEdges}${lifecycle}<text x="${L}" y="${H-9}" fill="#64748b" font-size="11">${(xmin/1000).toFixed(3)} s</text><text x="${W-R}" y="${H-9}" text-anchor="end" fill="#64748b" font-size="11">${(xmax/1000).toFixed(3)} s · 相对 Agent 开始</text></svg><p class="runtime-note memory-caption">${selected.map(f=>`<span style="color:${f[2]}">● ${esc(f[1])}</span>`).join('　')}<br>仅连接真实采样点；缺失样本或超过三个采样间隔的空档断开。退出标线不是采集到 RSS=0；cgroup 内存不随 PID 退出强制归零。</p>`;
}
'''
