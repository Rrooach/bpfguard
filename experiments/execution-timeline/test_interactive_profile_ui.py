#!/usr/bin/env python3
"""Renderer safety/conservation tests plus executable JavaScript DOM tests.

The DOM shim exercises event handlers, not browser layout. A real-browser
integration check remains separately reportable and is not implied here.
"""
import copy
import json
import re
import shutil
import subprocess
import unittest

from interactive_profile_ui import build_ui_payload, render_profile_document, render_profile_panel


def fixture():
    frames = [{"kind": "task", "label": "修复搜索"},
              {"kind": "semantic", "label": "检查文件"},
              {"kind": "tool", "label": "shell 工具", "call_id": "call-1"},
              {"kind": "process", "label": "rg [pid 10]", "tgid": 10},
              {"kind": "syscall_category", "label": "filesystem"}]
    operations = [{"kind": "syscall", "stack": frames + [{"kind": "syscall", "label": name}],
                   "measures": {"wall_ms": value, "syscall_count": 1},
                   "evidence": {"tid": 10, "result": 12, "source_ref": f"wal:{index}"}}
                  for index, (name, value) in enumerate((("read", 7), ("openat", 3)))]

    def tree_for(measure):
        root = {"kind": "root", "label": "Agent a", "value": 0, "metadata": {}, "children": []}
        for operation in operations:
            value = operation["measures"][measure]
            node = root
            node["value"] += value
            for frame in operation["stack"]:
                child = next((item for item in node["children"] if item["kind"] == frame["kind"]
                              and item["label"] == frame["label"]), None)
                if child is None:
                    child = {"kind": frame["kind"], "label": frame["label"], "value": 0,
                             "metadata": {key: value for key, value in frame.items()
                                          if key not in ("kind", "label")}, "children": []}
                    node["children"].append(child)
                child["value"] += value
                node = child
        return root

    views = [{"name": name, "label": label, "unit": unit, "quality": "Explicit measured boundaries",
              "status": "AVAILABLE", "sample_count": len(operations), "total": tree_for(name)["value"],
              "tree": tree_for(name)} for name, label, unit in
             (("wall_ms", "墙钟", "ms"), ("syscall_count", "系统调用", "次"))]
    views.append({"name": "missing", "label": "缺失指标", "unit": "bytes", "quality": "not selected",
                  "status": "NOT_COLLECTED", "sample_count": 0, "total": 0,
                  "tree": {"kind": "root", "label": "Other root", "value": 0, "children": []}})
    return {"schema_version": 1, "agent_id": "a", "task_id": "修复搜索", "run_id": "r",
            "operation_count": len(operations), "operations": operations, "views": views}


DOM_HARNESS = r"""
const vm=require('node:vm'),assert=require('node:assert/strict');
let body='';process.stdin.setEncoding('utf8');process.stdin.on('data',s=>body+=s);
process.stdin.on('end',()=>{
 const {script,payload}=JSON.parse(body);
 class Node {
  constructor(tag='div'){this.tagName=tag;this.attributes={};this.children=[];this.parentNode=null;this._text='';this.value='';this.hidden=false;this.disabled=false;this.style={};this.clientWidth=800;this.className='';}
  get firstChild(){return this.children[0]||null;}
  set href(v){this.setAttribute('href',v);}get href(){return this.getAttribute('href');}
  set textContent(s){this.children=[];this._text=String(s);}get textContent(){return this._text+this.children.map(n=>n.textContent).join('');}
  setAttribute(k,v){this.attributes[k]=String(v);}getAttribute(k){return this.attributes[k]??null;}
  appendChild(n){this.children.push(n);n.parentNode=this;return n;}
  insertBefore(n,before){const i=this.children.indexOf(before);this.children.splice(i<0?0:i,0,n);n.parentNode=this;return n;}
  removeChild(n){const i=this.children.indexOf(n);assert(i>=0);this.children.splice(i,1);n.parentNode=null;}
  remove(){if(this.parentNode)this.parentNode.removeChild(this);}
  click(){if(this.onclick)this.onclick({clientX:20,clientY:30});}
  focus(){if(this.onfocus)this.onfocus({});}
  cloneNode(deep){const n=new Node(this.tagName);n.attributes={...this.attributes};n._text=this._text;if(deep)for(const ch of this.children)n.appendChild(ch.cloneNode(true));return n;}
  matches(selector){const m=selector.match(/^\[([^=\]]+)(?:="([^"]*)")?\]$/);return m?this.attributes[m[1]]!==undefined&&(m[2]===undefined||this.attributes[m[1]]===m[2]):false;}
  querySelectorAll(s){let out=[];for(const n of this.children){if(n.matches(s))out.push(n);out.push(...n.querySelectorAll(s));}return out;}
  querySelector(s){return this.querySelectorAll(s)[0]||null;}
 }
 const host=new Node('section');host.setAttribute('id','interactive-profile');
 const roles=['payload','metric','depth','back','up','reset','search','find','svg','json','full-json','summary','breadcrumbs','search-result','limit','chart','visibility','branch-list','details','live','tooltip'];
 const registry={};for(const role of roles){const n=new Node(role==='chart'?'svg':'div');n.setAttribute('data-role',role);registry[role]=n;host.appendChild(n);}
 registry.payload.textContent=JSON.stringify(payload);registry.depth.value='overview';
 const document={body:new Node('body'),getElementById:id=>id==='interactive-profile'?host:null,createElement:tag=>new Node(tag),createElementNS:(ns,tag)=>new Node(tag)};
 const downloads=[];class Blob {constructor(parts,options){this.parts=parts;this.options=options;}}
 const context={document,window:{innerWidth:1200,addEventListener:()=>{}},console,Blob,
  URL:{createObjectURL:blob=>{downloads.push(blob);return'blob:test';},revokeObjectURL:()=>{}},
  XMLSerializer:class{serializeToString(n){return '<svg>'+n.textContent+'</svg>';}},setTimeout:fn=>{fn();return 1;},clearTimeout:()=>{}};
 vm.runInNewContext(script,context);
 const state=()=>host.profileViewer.getState();const nodes=payload.views[0].nodes;const root=nodes[0].id;
 const tool=nodes.find(n=>n.kind==='tool'),proc=nodes.find(n=>n.kind==='process'),read=nodes.find(n=>n.label==='read');
 assert.equal(state().zoom,root);assert(state().visible.includes(tool.id));assert(!state().visible.includes(proc.id));
 assert(!Object.prototype.hasOwnProperty.call(host,'innerHTML'));
 registry.chart.querySelector('[data-node-id="'+tool.id+'"]').click();
 assert.equal(state().zoom,tool.id);assert(state().visible.includes(proc.id));assert.equal(registry.back.disabled,false);
 assert(registry.details.textContent.includes('inclusive'));assert(registry.details.textContent.includes('exclusive'));assert(registry.details.querySelectorAll('[href]').length>=2);
 registry.search.value='read';registry.search.oninput();assert(state().matched.includes(read.id));assert(registry['search-result'].textContent.includes('70.00%'));
 registry.find.click();assert.equal(state().zoom,read.id);assert(registry.details.textContent.includes('wal:0'));
 registry.metric.value='syscall_count';registry.metric.onchange();assert.equal(state().zoom,read.id);assert(registry.live.textContent.includes('保留'));
 registry.metric.value='missing';registry.metric.onchange();assert.notEqual(state().zoom,read.id);assert(registry.chart.textContent.includes('未采集'));assert(registry.live.textContent.includes('返回总览'));
 registry.metric.value='wall_ms';registry.metric.onchange();registry.reset.click();assert.equal(state().zoom,root);assert.equal(state().search,'');
 registry.depth.value='16';registry.depth.onchange();assert(state().visible.includes(read.id));
 const rootEl=registry.chart.querySelector('[data-node-id="'+root+'"]');let prevented=0;
 rootEl.onkeydown({key:'ArrowDown',preventDefault:()=>prevented++});assert.equal(prevented,1);assert.notEqual(state().selected,root);
 const focused=registry.chart.querySelector('[tabindex="0"]');focused.onkeydown({key:'Enter',preventDefault:()=>{}});assert.notEqual(state().zoom,root);
 registry.back.click();assert.equal(state().zoom,root);registry.svg.click();registry.json.click();assert.equal(downloads.length,2);
 assert(downloads[0].parts[0].includes('<svg>'));assert.equal(JSON.parse(downloads[1].parts[0]).selected_metric,'wall_ms');
 assert.equal(registry['full-json'].href,'semantic-profile.json');
 console.log(JSON.stringify({status:'PASSED',interactions:['zoom','breadcrumbs','back','search','weight','metric-preserves-zoom','missing-resets-zoom','keyboard','svg-download','json-download'],nodes:nodes.length}));
});
"""


class InteractiveProfileTests(unittest.TestCase):
    def test_payload_has_stable_ids_real_evidence_and_additive_self_values(self):
        profile = fixture()
        payload = build_ui_payload(profile)
        first, second = payload["views"][:2]
        self.assertEqual([n["id"] for n in first["nodes"]], [n["id"] for n in second["nodes"]])
        by_id = {row["id"]: row for row in first["nodes"]}
        for node in by_id.values():
            self.assertAlmostEqual(node["value"], node["self_value"] + sum(by_id[x]["value"] for x in node["children"]))
        read = next(n for n in by_id.values() if n["label"] == "read")
        self.assertEqual(read["self_value"], 7)
        self.assertEqual(read["evidence"][0]["ref"], "semantic-profile.json#/operations/0")
        self.assertEqual(read["evidence"][0]["details"]["tid"], 10)
        self.assertNotIn("operations", payload)

    def test_payload_does_not_mutate_source(self):
        profile = fixture(); saved = copy.deepcopy(profile)
        build_ui_payload(profile)
        self.assertEqual(profile, saved)

    def test_event_volume_does_not_duplicate_all_raw_syscalls_in_html(self):
        profile = fixture()
        operation = profile["operations"][0]
        profile["operations"] = [operation] * 12_000
        profile["operation_count"] = 12_000
        page = render_profile_document(profile)
        payload = build_ui_payload(profile)
        self.assertEqual(payload["views"][0]["nodes"][0]["evidence_count"], 12_000)
        self.assertEqual(len(payload["views"][0]["nodes"][0]["evidence"]), 4)
        self.assertLess(len(page), 85_000)
        self.assertNotIn('"operations":[', page)

    def test_arbitrary_extension_evidence_is_not_embedded(self):
        profile = fixture()
        profile['operations'][0]['evidence']['unit_test_private_marker'] = 'PRIVATE_EVIDENCE_DO_NOT_INLINE'
        page = render_profile_panel(profile)
        self.assertNotIn('unit_test_private_marker', page)
        self.assertNotIn('PRIVATE_EVIDENCE_DO_NOT_INLINE', page)
        payload = build_ui_payload(profile)
        self.assertEqual(payload['views'][0]['nodes'][0]['evidence'][0]['details']['tid'], 10)

    def test_folded_node_budget_keeps_total_and_exposes_truncation(self):
        profile = fixture()
        payload = build_ui_payload(profile, max_nodes=5)
        view = payload["views"][0]
        self.assertTrue(view["truncated"])
        self.assertLessEqual(len(view["nodes"]), 5)
        by_id = {row["id"]: row for row in view["nodes"]}
        self.assertEqual(by_id[view["root"]]["value"], 10)
        for node in by_id.values():
            self.assertEqual(node["value"], node["self_value"] + sum(by_id[x]["value"] for x in node["children"]))

    def test_untrusted_label_metadata_and_urls_are_not_html(self):
        profile = fixture(); attack = '</script><img src=x onerror="alert(1)">&\u2028'
        profile["task_id"] = attack
        profile["views"][0]["tree"]["label"] = attack
        profile["operations"][0]["evidence"]["untrusted"] = attack
        page = render_profile_panel(profile)
        self.assertNotIn(attack, page)
        self.assertNotIn('<img src=x', page)
        self.assertIn('\\u003c/script\\u003e', page)
        self.assertNotIn('.innerHTML', page)
        for url in ('javascript:alert(1)', 'data:text/html,hello', '//evil.test/x', 'x\\evil', '\nsecret'):
            with self.assertRaises(ValueError):
                build_ui_payload(profile, profile_url=url)
        with self.assertRaises(ValueError):
            render_profile_panel(profile, panel_id='x" onload="bad')

    def test_nonfinite_negative_or_inconsistent_trees_rejected(self):
        for invalid in (float('nan'), float('inf'), -1, True):
            profile = fixture(); profile["views"][0]["tree"]["value"] = invalid
            with self.assertRaises(ValueError):
                build_ui_payload(profile)
        profile = fixture(); profile["views"][0]["tree"]["value"] = 1
        with self.assertRaisesRegex(ValueError, 'children exceed'):
            build_ui_payload(profile)

    @unittest.skipUnless(shutil.which('node'), 'Node required for executable UI interactions')
    def test_javascript_interactions_in_dom_shim_not_browser_layout(self):
        page = render_profile_panel(fixture())
        script = re.findall(r'<script>(.*?)</script>', page, re.S)[0]
        result = subprocess.run(['node', '-e', DOM_HARNESS], input=json.dumps({
            'script': script, 'payload': build_ui_payload(fixture())}), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'PASSED')

    def test_real_chromium_interactions_when_installed(self):
        from validate_profile_ui_browser import check_page, installed_browser_paths
        module, browser = installed_browser_paths()
        if not module or not browser or not shutil.which('node'):
            self.skipTest('installed Playwright and Chromium required; no auto-download')
        profile = fixture()
        profile['task_id'] = '</script><script>window.__profile_xss=1</script>'
        profile['operations'][0]['evidence']['untrusted'] = '<img src=x onerror="alert(1)">'
        result = check_page(html=render_profile_document(profile))
        self.assertEqual(result['status'], 'PASSED')
        self.assertTrue(result['tool_zoom_checked'])
        self.assertTrue(result['metric_zoom_preserved'])
        self.assertTrue(result['metric_zoom_reset'])
        self.assertEqual(result['page_errors'], [])


if __name__ == '__main__':
    unittest.main()
