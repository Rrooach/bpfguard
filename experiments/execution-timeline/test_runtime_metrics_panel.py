"""Execute the generated page's JavaScript, not only its template strings."""
import json
import shutil
import subprocess
import unittest

from render_agent_story import build_story, render
import test_render_agent_story as story_tests


HARNESS = r"""
const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
const page=fs.readFileSync(0,'utf8');
const nodes=new Map();
const document={querySelector(selector){
  if(!nodes.has(selector))nodes.set(selector,{innerHTML:'',value:'',onclick:null});
  return nodes.get(selector);
}};
const context=vm.createContext({document,console});
// This minimal DOM harness tests the legacy metrics panel, not the independent
// interactive explorer (which has its own real Chromium interaction tests).
const main=[...page.matchAll(/<script>([\s\S]*?)<\/script>/g)].find(x=>x[1].startsWith('const story='));
assert(main,'metrics-panel main script missing');vm.runInContext(main[1],context);
vm.runInContext(`
  if(!badge('INCOMPLETE').includes('warn'))throw Error('incomplete shown as success');
  if(!badge('NOT_COLLECTED').includes('warn'))throw Error('missing shown as success');
  for(const view of profile.views.filter(x=>x.status==='AVAILABLE'))drawProfile(view.name);
  for(let i=0;i<memoryTargets().length;i++)drawMemory(i);
`,context);
assert(nodes.get('#app').innerHTML.includes('时间花在哪里，内存用了多少'));
assert(nodes.get('#profile-summary').innerHTML.length>0);
for(const node of nodes.values())assert(!/NaN|Infinity/.test(node.innerHTML));
process.stdout.write(JSON.stringify({status:'PAGE_JAVASCRIPT_PASSED',elements:nodes.size}));
"""


@unittest.skipUnless(shutil.which("node"), "Node required for page JavaScript validation")
class RuntimePanelTests(unittest.TestCase):
    def check_page(self, story):
        result = subprocess.run([shutil.which("node"), "-e", HARNESS],input=render(story),
            text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"],"PAGE_JAVASCRIPT_PASSED")

    def test_missing_data_is_renderable_without_claiming_zero(self):
        report,app=story_tests.AgentStoryTests().fixture()
        self.check_page(build_story(report,app))

    def test_memory_curve_and_partial_model_warning_execute(self):
        report,app=story_tests.AgentStoryTests().fixture()
        story=build_story(report,app)
        story["model_collection"]={"status":"PARTIAL","accepted_count":2,"finished_count":1,
            "reason_flags":["ACCEPTED_REQUEST_WITHOUT_FINISH"]}
        story["memory"]={"status":"SAMPLED_NOT_EXHAUSTIVE","interval_ms":100,
            "targets":[{"target":{"name":"codex","role":"AGENT_RUNTIME"},
                "sampled_rss_peak_bytes":4096,"process_sample_count":2}],
            "series":[{"name":"codex","role":"AGENT_RUNTIME","at_ms":0,"rss_bytes":2048},
                      {"name":"codex","role":"AGENT_RUNTIME","at_ms":story["agent_wall_ms"],"rss_bytes":4096}]}
        self.check_page(story)


if __name__=="__main__":unittest.main()
