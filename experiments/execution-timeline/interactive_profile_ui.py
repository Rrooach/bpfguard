#!/usr/bin/env python3
"""Self-contained, bounded interactive semantic profiles (no raw-event embedding).

The profile JSON remains the full evidence source. The UI embeds folded nodes
and a few JSON-pointer references per node, never the syscall operation array.
Widths represent the selected additive measure, not necessarily wall time.
"""
from __future__ import annotations

import hashlib
import html
import json
import math
import re
from urllib.parse import urlsplit


MAX_NODES_PER_VIEW = 20_000
MAX_EVIDENCE_PER_NODE = 4
MAX_METADATA_TEXT = 1_024
EVIDENCE_FIELDS = frozenset((
    "run_id", "agent_id", "task_id", "call_id", "tool_call_id", "evidence_chain_id",
    "runtime_id", "pid", "tid", "boot_id", "clock", "begin_ns", "end_ns", "at_ms",
    "span_id", "span_ids", "child_call_ids", "result", "errno", "path", "additional_paths",
    "syscall", "attribution", "quality", "timing_scope", "source_ref", "source_refs",
    "source", "scope", "status", "root", "cgroup_id", "process_birth_ns",
    "sample_begin_at_ms", "sample_end_at_ms", "evidence_ref", "evidence_refs"))


def _evidence_preview(value):
    # Operation evidence may hold prompts/private diagnostics added by another
    # extension. The viewer must not embed arbitrary extension payloads.
    return _compact({key: item for key, item in value.items() if key in EVIDENCE_FIELDS}) if isinstance(value, dict) else {}


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _safe_url(value):
    """Allow explicitly supplied HTTP(S) or relative artifacts, never JS/data."""
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise ValueError("artifact URL must be a nonempty safe URL")
    parsed = urlsplit(value)
    if parsed.scheme not in ("", "http", "https") or (not parsed.scheme and parsed.netloc):
        raise ValueError("artifact URL must be relative or HTTP(S)")
    if "\\" in value:
        raise ValueError("artifact URL must not contain backslashes")
    return value


def _compact(value, depth=0):
    if depth > 3:
        return "[nested data: open original JSON]"
    if isinstance(value, str):
        return value[:MAX_METADATA_TEXT] + ("…" if len(value) > MAX_METADATA_TEXT else "")
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        return value if math.isfinite(value) else "[nonfinite]"
    if isinstance(value, dict):
        return {str(k)[:128]: _compact(v, depth + 1) for k, v in list(value.items())[:16]}
    if isinstance(value, (list, tuple)):
        return [_compact(v, depth + 1) for v in value[:8]]
    return str(value)[:MAX_METADATA_TEXT]


def _script_json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).replace(
        "&", "\\u0026").replace("<", "\\u003c").replace(
        ">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def _share_evidence(payload):
    """Do not repeat the same example at every ancestor and metric."""
    records, indexes = [], {}
    for view in payload['views']:
        for node in view['nodes']:
            references = []
            for evidence in node['evidence']:
                key = evidence['operation_index']
                if key not in indexes:
                    indexes[key] = len(records)
                    records.append({name: value for name, value in evidence.items() if name != 'value'})
                references.append({'entry': indexes[key], 'value': evidence['value']})
            node['evidence'] = references
    payload['evidence_records'] = records
    payload['evidence_encoding'] = 'SHARED_OPERATION_PREVIEWS_WITH_PER_METRIC_VALUES'
    return payload


def _node_id(path):
    return "n-" + hashlib.sha256(json.dumps(path, ensure_ascii=False,
                                          separators=(",", ":")).encode()).hexdigest()[:20]


def build_ui_payload(profile, *, profile_url="semantic-profile.json",
                     evidence_url="evidence-links.json", syscall_url=None,
                     max_nodes=MAX_NODES_PER_VIEW, source_urls=None):
    """Build a bounded, auditable viewer projection; preserve additive totals.

    Tree truncation has an explicit aggregate leaf and a full-JSON link. Every
    original operation may contribute one reference to each ancestor, but only
    the first four references are retained, with the full count shown.
    """
    if not isinstance(profile, dict) or not isinstance(profile.get("views"), list):
        raise ValueError("semantic profile with views required")
    if type(max_nodes) is not int or max_nodes < 2 or max_nodes > MAX_NODES_PER_VIEW:
        raise ValueError("max_nodes must be between 2 and MAX_NODES_PER_VIEW")
    profile_url = _safe_url(profile_url)
    evidence_url = _safe_url(evidence_url) if evidence_url else None
    syscall_url = _safe_url(syscall_url) if syscall_url else None
    if source_urls is not None and (not isinstance(source_urls, dict) or len(source_urls) > 16):
        raise ValueError('bounded source URL namespace mapping required')
    source_urls = {key: _safe_url(value) for key, value in (source_urls or {}).items()
                   if isinstance(key, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}', key)}
    payload = {"schema_version": 1, "agent_id": _compact(profile.get("agent_id")),
               "task_id": _compact(profile.get("task_id")), "run_id": _compact(profile.get("run_id")),
               "profile_url": profile_url, "evidence_url": evidence_url,
               "syscall_url": syscall_url, "source_urls": source_urls,
               "operation_count": profile.get("operation_count"),
               "limitations": _compact(profile.get("limitations", [])), "views": []}
    for view_index, view in enumerate(profile["views"]):
        tree = view.get("tree")
        if not isinstance(tree, dict) or not _number(tree.get("value")):
            raise ValueError("profile tree requires finite nonnegative value")
        nodes = []
        node_ids = set()
        by_path = {}
        truncated = False

        def visit(raw, path, parent=None, pointer="", depth=0):
            nonlocal truncated
            if depth > 128 or not _number(raw.get("value")):
                raise ValueError("invalid profile depth or measure")
            current_path = path + [(str(raw.get("kind", "unknown")), str(raw.get("label", "?")))]
            ident = _node_id(current_path)
            if ident in node_ids:
                raise ValueError("duplicate folded path in profile")
            node_ids.add(ident)
            node = {"id": ident, "parent": parent, "label": _compact(str(raw.get("label", "?"))),
                    "kind": str(raw.get("kind", "unknown"))[:128], "value": raw["value"],
                    "metadata": _compact(raw.get("metadata", {})), "children": [],
                    "evidence": [], "evidence_count": 0,
                    "profile_ref": f"{profile_url}#/views/{view_index}/tree{pointer}"}
            nodes.append(node)
            by_path[tuple(current_path)] = node
            children = raw.get("children", [])
            if not isinstance(children, list) or any(not isinstance(child, dict) or
                    not _number(child.get("value")) for child in children):
                raise ValueError("invalid profile children")
            child_total = sum(child["value"] for child in children)
            if child_total - raw["value"] > max(1e-8, raw["value"] * 1e-8):
                raise ValueError("children exceed inclusive profile value")
            node["self_value"] = max(0, raw["value"] - child_total)
            for index, child in enumerate(children):
                # Reserve one aggregate slot at the cap; do not change totals.
                if len(nodes) >= max_nodes - 1:
                    remainder = sum(row["value"] for row in children[index:])
                    overflow = {"id": ident + "-more", "parent": ident,
                        "label": f"更多分支（{len(children) - index} 个；打开完整 JSON）", "kind": "truncated",
                        "value": remainder, "self_value": remainder, "metadata": {}, "children": [],
                        "evidence": [], "evidence_count": 0, "profile_ref": node["profile_ref"]}
                    # A completed deep branch may have used the final slot.
                    # In that case roll remaining mass into the parent's self
                    # bucket and surface the truncation flag, without fake nodes.
                    if len(nodes) < max_nodes:
                        nodes.append(overflow)
                        node["children"].append(overflow["id"])
                    else:
                        node["self_value"] += remainder
                    truncated = True
                    break
                child_node = visit(child, current_path, ident, pointer + f"/children/{index}", depth + 1)
                node["children"].append(child_node["id"])
            return node

        root = visit(tree, [])
        root_key = ((str(tree.get("kind", "root")), str(tree.get("label", "?"))),)
        for op_index, operation in enumerate(profile.get("operations", [])):
            value = operation.get("measures", {}).get(view.get("name"))
            if not _number(value):
                continue
            path = list(root_key)
            candidates = [root]
            for frame in operation.get("stack", []):
                path.append((str(frame.get("kind", "unknown")), str(frame.get("label", "?"))))
                if (found := by_path.get(tuple(path))) is not None:
                    candidates.append(found)
            for node in candidates:
                node["evidence_count"] += 1
                if len(node["evidence"]) < MAX_EVIDENCE_PER_NODE:
                    node["evidence"].append({"kind": str(operation.get("kind", "operation"))[:128],
                        "value": value, "ref": f"{profile_url}#/operations/{op_index}",
                        "operation_index": op_index,
                        "details": _evidence_preview(operation.get("evidence", {}))})
        projected_view = {key: _compact(view.get(key)) for key in
            ("name", "label", "unit", "quality", "status", "sample_count", "total")}
        projected_view.update(root=root["id"], nodes=nodes, truncated=truncated)
        payload["views"].append(projected_view)
    return payload


STYLE = r"""
.iprof{font:14px system-ui,sans-serif;color:#182b3e;background:#fff;border:1px solid #d9e2e7;border-radius:12px;padding:18px;margin:16px 0;--ip-blue:#176c9d}
.iprof h2{margin:0 0 7px;font-size:22px}.iprof p{margin:8px 0}.iprof .ip-muted{color:#536674;font-size:13px}.iprof .ip-controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:14px 0}
.iprof button,.iprof select,.iprof input{font:inherit;border:1px solid #a7bac9;border-radius:5px;background:#fff;color:#17334a;padding:6px 9px}.iprof button{cursor:pointer}.iprof button:hover{background:#eff6fb}.iprof button:disabled{opacity:.45;cursor:default}.iprof input[type=search]{min-width:200px}.iprof [data-role=breadcrumbs]{display:flex;flex-wrap:wrap;gap:5px;align-items:center;margin:9px 0}.iprof [data-role=breadcrumbs] button{font-size:12px;padding:3px 7px}
.iprof [data-role=chart]{width:100%;display:block;min-height:55px;background:#f4f7f8;border-radius:5px}.iprof .ip-layout{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:16px}.iprof .ip-details{font-size:13px;background:#f5f8fa;padding:12px;border-radius:6px;max-height:540px;overflow:auto;overflow-wrap:anywhere}.iprof .ip-details h3{margin:0 0 8px}.iprof .ip-details pre{white-space:pre-wrap;font-size:11px;max-height:140px;overflow:auto}.iprof .ip-details a{color:#135f90}.iprof .ip-details dt{font-weight:600;margin-top:7px}.iprof .ip-details dd{margin:2px 0 0}.iprof [data-role=branch-list]{max-height:200px;overflow:auto}.iprof [data-role=branch-list] button{display:block;text-align:left;width:100%;margin:3px 0}.iprof svg text{pointer-events:none;user-select:none}.iprof svg g[role=treeitem]{cursor:pointer;outline:none}.iprof svg g[role=treeitem]:focus rect{stroke:#111;stroke-width:2.5}.iprof .ip-live{min-height:20px;margin:8px 0}.iprof .ip-warning{background:#fff3cc;padding:8px;border-radius:5px}.iprof [data-role=tooltip]{position:fixed;z-index:9999;max-width:350px;pointer-events:none;background:#132d40;color:white;padding:8px;border-radius:5px;white-space:pre-wrap;box-shadow:0 3px 12px #0003;font-size:12px}
@media(max-width:850px){.iprof .ip-layout{grid-template-columns:1fr}.iprof .ip-details{max-height:350px}}
"""


SCRIPT = r"""(() => {
'use strict';
const host=document.getElementById(__PANEL_ID__);
if(!host)return;
const data=JSON.parse(host.querySelector('[data-role="payload"]').textContent);
const el=role=>host.querySelector('[data-role="'+role+'"]');
const ns='http://www.w3.org/2000/svg';
const add=(tag,attrs,parent,text)=>{const n=document.createElementNS(ns,tag);for(const [k,v]of Object.entries(attrs||{}))n.setAttribute(k,String(v));if(text!==undefined)n.textContent=String(text);parent.appendChild(n);return n;};
const clear=n=>{while(n.firstChild)n.removeChild(n.firstChild);};
const text=(tag,value,parent)=>{const n=document.createElement(tag);n.textContent=String(value);parent.appendChild(n);return n;};
let view=null,map=new Map(),zoom=null,selected=null,history=[],search='',matched=new Set();
let focusId=null,visible=[],renderRows=[],resizeTimer=null,selectionReason='';
const fmt=(n,unit)=>{if(n===null||n===undefined)return'未采集';const a=Number(n);if(!Number.isFinite(a))return'不可用';
 if(unit==='bytes'){for(const [d,u]of [[1073741824,'GiB'],[1048576,'MiB'],[1024,'KiB']])if(a>=d)return(a/d).toFixed(2)+' '+u;return a.toFixed(0)+' B';}
 if(unit==='byte_ms')return(a/1048576000).toFixed(3)+' MiB·s';return a.toLocaleString(undefined,{maximumFractionDigits:3})+' '+(unit||'');};
const percent=(v,total)=>total>0?(100*v/total).toFixed(2)+'%':'0%';
const escapeLabel=s=>String(s).slice(0,260);
const ancestors=id=>{const result=[];let n=map.get(id),guard=0;while(n&&guard++<130){result.unshift(n);n=map.get(n.parent);}return result;};
const children=n=>n.children.map(id=>map.get(id)).filter(Boolean);
const isMatch=n=>search&&(n.label+' '+n.kind+' '+JSON.stringify(n.metadata||{})).toLowerCase().includes(search);
function matchingWeight(node){if(matched.has(node.id))return node.value;return children(node).reduce((sum,n)=>sum+matchingWeight(n),0);}
function updateMatches(){matched=new Set();for(const n of map.values())if(isMatch(n))matched.add(n.id);}
function detail(node){
 const box=el('details');clear(box);if(!node){text('p','点击矩形查看该节点的指标及原始证据。',box);return;}
 text('h3',node.label,box);text('p',node.kind,box);
 const dl=document.createElement('dl');box.appendChild(dl);
 for(const [label,value]of [['含子项（inclusive）',fmt(node.value,view.unit)],['仅本节点（exclusive）',fmt(node.self_value,view.unit)],['占当前范围',percent(node.value,map.get(zoom).value)],['占全部',percent(node.value,map.get(view.root).value)],['原始操作数',node.evidence_count||0]]){text('dt',label,dl);text('dd',value,dl);}
 text('p','exclusive 是在本层结束的度量，不表示线程自身 CPU；本图不是时间先后排列。',box).className='ip-muted';
 const refs=document.createElement('p');box.appendChild(refs);
 const link=(label,url,parent)=>{if(!url)return;const a=document.createElement('a');a.textContent=label;a.href=url;a.target='_blank';a.rel='noopener noreferrer';parent.appendChild(a);parent.appendChild(document.createElement('br'));};
 link('完整 profile 节点 JSON',node.profile_ref,refs);
 const anchor=node.metadata?.detail_anchor;if(typeof anchor==='string'&&/^[A-Za-z][A-Za-z0-9_-]{0,119}$/.test(anchor)){const a=document.createElement('a');a.textContent='在本页查看这次工具的输入、输出和状态';a.href='#'+anchor;a.onclick=e=>{const target=document.getElementById(anchor);if(target){e.preventDefault();if(target.tagName==='DETAILS')target.open=true;target.scrollIntoView({behavior:'smooth',block:'start'});}};refs.appendChild(a);refs.appendChild(document.createElement('br'));}
 if(data.evidence_url)link('应用 → 工具 → 内核证据链',data.evidence_url,refs);
 if(data.syscall_url)link('完整 syscall 数据',data.syscall_url,refs);
 if(Object.keys(node.metadata||{}).length)text('pre',JSON.stringify(node.metadata,null,2),box);
 text('h4','原始证据（有界示例，不代表全部）',box);
 for(const item of node.evidence||[]){const e=Number.isInteger(item.entry)?{...data.evidence_records[item.entry],value:item.value}:item;const p=document.createElement('p');box.appendChild(p);link(e.kind+' #'+e.operation_index+' · '+fmt(e.value,view.unit),e.ref,p);const refs=[e.details?.source_ref,...(Array.isArray(e.details?.source_refs)?e.details.source_refs:[])];for(const ref of refs){if(typeof ref!=='string')continue;const at=ref.indexOf('#'),name=at<0?ref:ref.slice(0,at),base=data.source_urls?.[name];if(base&&at>=0)link('原始 '+name+' 记录',base+ref.slice(at),p);}text('pre',JSON.stringify(e.details,null,2),p);}
 if(!(node.evidence||[]).length)text('p','该折叠节点没有独立事件；查看子项或完整 JSON。',box);
 if((node.evidence_count||0)>(node.evidence||[]).length)text('p','共 '+node.evidence_count+' 条；完整事件保留在外部 profile JSON，未重复塞进本页。',box).className='ip-muted';
}
function setSelected(id,reason='已选择'){if(!map.has(id))return;selected=id;selectionReason=reason;detail(map.get(id));el('live').textContent=reason+'：'+map.get(id).label;}
function go(id,push=true){if(!map.has(id))return;if(push&&zoom!==id)history.push(zoom);zoom=id;focusId=id;setSelected(id,'当前展开');draw();}
function crumbs(){const bar=el('breadcrumbs');clear(bar);for(const n of ancestors(zoom)){const b=text('button',n.label,bar);b.type='button';b.onclick=()=>go(n.id);}}
function color(node){const colors={root:'#254d70',task:'#326d94',semantic:'#83629e',tool:'#2c8d87',process:'#c77c34',thread:'#ac6f45',syscall:'#bd5271',syscall_category:'#9a5c7d',file:'#508247',model:'#456bb3',phase:'#668197',truncated:'#7d858a'};return colors[node.kind]||'#597c8d';}
function draw(){
 const svg=el('chart');clear(svg);visible=[];renderRows=[];if(!view)return;
 const root=map.get(zoom);const width=Math.max(300,svg.clientWidth||900),rowH=30;
 const mode=el('depth').value;const maxDepth=mode==='overview'?7:Number(mode);let maxRow=0,hiddenSmall=0,hiddenDeep=0;
 function collect(n,x,w,depth){if(w<1.1){hiddenSmall++;return;}visible.push(n.id);renderRows.push({node:n,x,w,depth});maxRow=Math.max(maxRow,depth);
  if(depth>=maxDepth-1){hiddenDeep+=n.children.length;return;}
  if(mode==='overview'&&depth>0&&['tool','process','thread','syscall_category','syscall','file'].includes(n.kind)){hiddenDeep+=n.children.length;return;}
  let cursor=x;for(const child of children(n)){const cw=n.value>0?w*child.value/n.value:0;collect(child,cursor,cw,depth+1);cursor+=cw;}}
 if(root.value>0)collect(root,0,width,0);
 const height=Math.max(64,(maxRow+1)*rowH+8);svg.setAttribute('viewBox','0 0 '+width+' '+height);svg.setAttribute('height',height);svg.setAttribute('role','tree');svg.setAttribute('aria-label',view.label+'；左右是累计权重，不是时间顺序');
 const title=add('title',{},svg,view.label+' · '+fmt(root.value,view.unit));
 if(!root.value){add('text',{x:14,y:33,fill:'#536674'},svg,view.status==='AVAILABLE'?'该指标已采集，当前值为 0':'该指标未采集；不能视为 0。');}
 for(const row of renderRows){const n=row.node,g=add('g',{role:'treeitem',tabindex:focusId===n.id?'0':'-1','data-node-id':n.id,'aria-level':row.depth+1,'aria-label':n.label+' '+fmt(n.value,view.unit),'aria-expanded':n.children.length?String(n.id===zoom):'false','aria-selected':n.id===selected?'true':'false'},svg);
  const active=matched.has(n.id),hasSelection=n.id===selected;
  add('rect',{x:row.x+0.5,y:row.depth*rowH+1,width:Math.max(.1,row.w-1),height:rowH-3,rx:3,fill:color(n),opacity:search?(active?1:.32):1,stroke:hasSelection?'#111':active?'#ffcd00':'#fff','stroke-width':hasSelection?2:active?2.5:.5},g);
  if(row.w>28)add('text',{x:row.x+5,y:row.depth*rowH+20,fill:'#fff','font-size':12},g,escapeLabel(n.label).slice(0,Math.floor((row.w-11)/7))+(n.label.length>Math.floor((row.w-11)/7)?'…':''));
  add('title',{},g,n.label+'\n'+fmt(n.value,view.unit)+' inclusive · '+fmt(n.self_value,view.unit)+' exclusive\n点击展开；方向键选择；Enter 展开');
  g.onclick=()=>go(n.id);g.onfocus=()=>{focusId=n.id;setSelected(n.id);};
  g.onmouseenter=e=>{const t=el('tooltip');t.hidden=false;t.textContent=n.label+'\n'+fmt(n.value,view.unit)+' · '+percent(n.value,root.value)+' 当前范围';t.style.left=Math.min(e.clientX+12,Math.max(0,window.innerWidth-370))+'px';t.style.top=Math.max(0,e.clientY+16)+'px';};
  g.onmouseleave=()=>{el('tooltip').hidden=true;};
  g.onkeydown=e=>{let target=null;if(e.key==='Enter'||e.key===' '){e.preventDefault();go(n.id);focusNode(n.id);return;}if(e.key==='Escape'){e.preventDefault();go(n.parent||view.root);focusNode(zoom);return;}
   const index=visible.indexOf(n.id);if(e.key==='ArrowDown')target=visible[Math.min(visible.length-1,index+1)];if(e.key==='ArrowUp')target=visible[Math.max(0,index-1)];if(e.key==='ArrowLeft')target=visible.includes(n.parent)?n.parent:null;if(e.key==='ArrowRight')target=n.children.find(id=>visible.includes(id));if(e.key==='Home')target=visible[0];if(e.key==='End')target=visible[visible.length-1];if(target){e.preventDefault();focusNode(target);}};
 }
 if(visible.length&&!visible.includes(focusId)){focusId=visible[0];svg.querySelector('[data-node-id="'+focusId+'"]').setAttribute('tabindex','0');}
 crumbs();el('back').disabled=!history.length;el('up').disabled=zoom===view.root;el('reset').disabled=zoom===view.root&&!search;
 const weight=matchingWeight(root);el('search-result').textContent=search?('全图匹配 '+matched.size+' 个节点；当前范围不重复计重 '+fmt(weight,view.unit)+' / '+fmt(root.value,view.unit)+'（'+percent(weight,root.value)+' 当前范围）'):'左右按权重排列；上下是任务层级，不是执行时间线。';
 el('summary').textContent=view.label+' · 当前 '+fmt(root.value,view.unit)+' / 全部 '+fmt(map.get(view.root).value,view.unit)+'；'+view.quality;
 el('limit').hidden=!view.truncated;el('limit').textContent='折叠节点过多，本页有界截断；剩余权重保留，完整分支请打开原始 JSON。';
 const list=el('branch-list');clear(list);for(const n of children(root).slice(0,80)){const b=text('button',n.label+' · '+fmt(n.value,view.unit),list);b.type='button';b.onclick=()=>go(n.id);}
 if(children(root).length>80)text('p','列表仅列前 80 个；可搜索定位或下载完整 JSON。',list);
 el('visibility').textContent='已绘制 '+visible.length+' 个节点；'+hiddenSmall+' 个分支小于一像素，'+hiddenDeep+' 个下级分支可点击父节点继续展开。';
 if(selected&&map.has(selected))detail(map.get(selected));
}
function focusNode(id){focusId=id;for(const n of el('chart').querySelectorAll('[data-node-id]'))n.setAttribute('tabindex',n.getAttribute('data-node-id')===id?'0':'-1');const n=el('chart').querySelector('[data-node-id="'+id+'"]');if(n)n.focus();}
function switchView(name){const previous=zoom;view=data.views.find(v=>v.name===name)||data.views[0];if(!view)return;map=new Map(view.nodes.map(n=>[n.id,n]));history=[];zoom=map.has(previous)?previous:view.root;selected=zoom;focusId=zoom;updateMatches();draw();el('live').textContent=previous&&previous===zoom?'已保留相同层级，切换指标不改变任务范围。':'当前指标没有原层级，已返回总览。';}
for(const v of data.views){const o=text('option',v.label+(v.status==='AVAILABLE'?'':'（未采集）'),el('metric'));o.value=v.name;}
el('metric').onchange=()=>switchView(el('metric').value);el('depth').onchange=draw;
el('search').oninput=()=>{search=el('search').value.trim().toLowerCase();updateMatches();draw();};
el('find').onclick=()=>{const n=[...map.values()].find(n=>matched.has(n.id));if(n)go(n.id);else el('live').textContent='没有匹配节点。';};
el('back').onclick=()=>{if(history.length)go(history.pop(),false);};el('up').onclick=()=>go(map.get(zoom).parent||view.root);
el('reset').onclick=()=>{search='';el('search').value='';history=[];updateMatches();go(view.root,false);};
function download(blob,name){const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
el('svg').onclick=()=>{const svg=el('chart').cloneNode(true);svg.setAttribute('xmlns',ns);const caption=document.createElementNS(ns,'desc');caption.textContent=view.label+'；单位 '+view.unit+'；当前范围 '+map.get(zoom).label+'；'+view.quality;svg.insertBefore(caption,svg.firstChild);download(new Blob([new XMLSerializer().serializeToString(svg)],{type:'image/svg+xml;charset=utf-8'}),'agent-profile-'+view.name+'.svg');};
el('json').onclick=()=>download(new Blob([JSON.stringify({schema_version:1,selected_metric:view.name,zoom_node:zoom,selected_node:selected,search,payload:data},null,2)],{type:'application/json;charset=utf-8'}),'agent-profile-view.json');
const full=el('full-json');full.href=data.profile_url;full.target='_blank';full.rel='noopener noreferrer';
const resize=()=>{clearTimeout(resizeTimer);resizeTimer=setTimeout(draw,100);};if(typeof ResizeObserver!=='undefined')new ResizeObserver(resize).observe(el('chart'));else window.addEventListener('resize',resize);
// Narrow read-only API aids integration tests; all user strings use textContent.
host.profileViewer={getState:()=>({metric:view&&view.name,zoom,selected,search,visible:[...visible],matched:[...matched]}),redraw:draw};
const first=data.views.find(v=>v.name==='wall_ms'&&v.status==='AVAILABLE')||data.views.find(v=>v.status==='AVAILABLE')||data.views[0];
if(first){el('metric').value=first.name;switchView(first.name);}else{add('text',{x:12,y:28},el('chart'),'没有 profile 指标');for(const n of host.querySelectorAll('button'))n.disabled=true;el('search').disabled=true;el('metric').disabled=true;el('depth').disabled=true;}
})();"""


def render_profile_panel(profile, *, panel_id="interactive-profile", profile_url="semantic-profile.json",
                         evidence_url="evidence-links.json", syscall_url=None, max_nodes=MAX_NODES_PER_VIEW,
                         source_urls=None):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,79}", panel_id):
        raise ValueError("safe unique HTML panel_id required")
    payload = build_ui_payload(profile, profile_url=profile_url, evidence_url=evidence_url,
                               syscall_url=syscall_url, max_nodes=max_nodes, source_urls=source_urls)
    _share_evidence(payload)
    return '<style>' + STYLE + '</style>' + f'''<section class="iprof" id="{html.escape(panel_id, quote=True)}">
<h2>Agent 任务剖析</h2><p class="ip-muted">先看任务和工具，再点击展开进程／syscall。矩形宽度表示当前指标的累计权重，不是时间顺序，也不代表隐藏思维或已证明的因果。</p>
<div class="ip-controls"><label>指标 <select data-role="metric" aria-label="剖析指标"></select></label>
<label>展开深度 <select data-role="depth" aria-label="显示深度"><option value="overview">任务 → 工具（默认）</option><option value="4">当前 4 层</option><option value="8">当前 8 层</option><option value="16">当前 16 层</option></select></label>
<button type="button" data-role="back">返回</button><button type="button" data-role="up">上一层</button><button type="button" data-role="reset">重置</button></div>
<div class="ip-controls"><label>搜索 <input data-role="search" type="search" placeholder="任务、工具、PID、文件或 syscall" aria-label="搜索剖析节点"></label><button type="button" data-role="find">定位首个匹配</button><button type="button" data-role="svg">导出当前 SVG</button><button type="button" data-role="json">下载当前视图 JSON</button><a data-role="full-json">完整 profile JSON</a></div>
<p data-role="summary"></p><nav data-role="breadcrumbs" aria-label="剖析层级路径"></nav><p data-role="search-result" class="ip-muted"></p><p data-role="limit" class="ip-warning" hidden></p>
<div class="ip-layout"><div><svg data-role="chart" tabindex="0"></svg><p data-role="visibility" class="ip-muted"></p><div data-role="branch-list" aria-label="直接子分支"></div></div><aside data-role="details" class="ip-details" aria-label="所选节点详情"></aside></div>
<p class="ip-muted">键盘：Tab 进入图；↑↓ 选择，← 父节点，→ 子节点，Enter／空格展开，Esc 上一层，Home／End 首尾。原始事件保留在外部 JSON，本页仅携带折叠树和少量证据引用。</p>
<div data-role="live" class="ip-live" role="status" aria-live="polite"></div><div data-role="tooltip" hidden></div>
<script type="application/json" data-role="payload">{_script_json(payload)}</script>
<script>{SCRIPT.replace('__PANEL_ID__', _script_json(panel_id))}</script></section>'''


def render_profile_document(profile, **kwargs):
    return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Agent 交互剖析</title></head><body>' + render_profile_panel(profile, **kwargs) + '</body></html>'
