#!/usr/bin/env python3
"""Native presentation invariants; fixtures are not native E2E claims."""
from copy import deepcopy
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

from common import write_new
from native_agent_profile import compile_native_profile, export_native_profile, export_public_native_profile


def fixture():
    origin = 1_000_000_000
    calls = [{'nr':0, 'name':'read', 'start_ns':origin+200, 'end_ns':origin+500,
              'pairing':'PAIRED', 'result':3, 'files':[{'path':'/work/a','read':{'returned_bytes':3,'requested_bytes':8}}]},
             {'nr':0, 'name':'read', 'start_ns':origin+600, 'end_ns':origin+700,
              'pairing':'PAIRED', 'result':0, 'files':[{'path':'/work/a','read':{'returned_bytes':0,'requested_bytes':8}}]},
             {'nr':257, 'name':'openat', 'start_ns':origin+800, 'end_ns':None,
              'pairing':'UNPAIRED', 'result':None, 'files':[{'path':'/work/unknown'}]}]
    report={'run':{'run_id':'run-native','boot_id':'boot','begin_ns':origin,'end_ns':origin+10_000_000},
            'threads':[{'key':'10:birth','tid':10,'tgid':10,'birth_ns':origin,'process_birth_ns':origin,
                        'comm':'codex','parent_key':None,'tool_call_id':'codex-native-runtime',
                        'state_totals_ns':{'ONCPU':2_000_000,'RUNNABLE':1_000_000},'calls':calls}],
            'health':{'status':'INCOMPLETE_FOR_SELECTED_HOOKS'}, 'critical_path':{'status':'PARTIAL'}}
    app={'schema_version':2,'mode':'OFFICIAL_CODEX_NATIVE_TOOLS_NO_REPLACEMENT','agent_id':'agent-native',
         'task_id':'修复文件搜索','begin_ns':origin+10,'end_ns':origin+9_000_000,'status':'completed',
         'function_bindings':[],'steps':[], 'prompt':'搜索固定代码库并报告', 'budget_label':'native-budget',
         'tool_calls':[{'call_id':'call-1','tool_name':'commandExecution','status':'SUCCEEDED',
                        'arguments':{'command':'grep needle /work/a','cwd':'/work'},
                        'requested_ns':origin+100,'result_delivered_ns':origin+1_000_000}]}
    results=[{'call_id':'call-1','tool_name':'commandExecution','exit_code':0,
              'application_process_handle':'999999','output':{'text':'needle\n','size_bytes':7,'truncated':False}}]
    correlations={'links':[{'call_id':'call-1','status':'CORRELATED_NOT_CAUSAL',
        'reason':'CANDIDATE_ONLY','candidates':[{'thread_key':'10:birth','pid':10,
            'basis':'EXACT_LIVE_ARGV_CWD_AND_KERNEL_LIFETIME_AND_OBSERVED_TOOL_INTERVAL'}]}]}
    return report,app,results,correlations


class NativeAgentProfileTests(unittest.TestCase):
    def compile(self, **extra):
        report,app,results,correlations=fixture()
        return compile_native_profile(report,app,tool_results=results,correlations=correlations,**extra)

    def test_tools_keep_output_but_kernel_counts_are_global_and_conserved(self):
        result=self.compile();story=result['story'];views={v['name']:v for v in result['profile']['views']}
        self.assertEqual(story['tools'][0]['result']['output']['text'],'needle\n')
        self.assertEqual(story['tools'][0]['syscall_rows'],[])
        self.assertIsNone(story['tools'][0]['resources'])
        self.assertEqual(story['runtime']['assigned_syscalls'],0)
        self.assertEqual(story['runtime']['unassigned_syscalls'],3)
        self.assertEqual(views['syscall_count']['total'],3)
        self.assertAlmostEqual(views['syscall_time_ms']['total'],0.0004)
        self.assertEqual(views['file_read_bytes']['total'],3)
        self.assertEqual(views['oncpu_ms']['total'],2)
        self.assertEqual(views['runnable_ms']['total'],1)
        self.assertEqual(views['sleep_ms']['status'],'NOT_COLLECTED')
        self.assertEqual(views['wall_ms']['total'],10)
        for operation in result['profile']['operations']:
            if operation['kind'].startswith('runtime_'):
                self.assertFalse(any(frame['kind']=='tool' for frame in operation['stack']))

    def test_missing_memory_read_and_code_mode_do_not_become_zero(self):
        result=self.compile();views={v['name']:v for v in result['profile']['views']}
        self.assertEqual(result['story']['memory']['status'],'NOT_COLLECTED')
        self.assertEqual(result['story']['code_mode']['status'],'NOT_EXPOSED')
        for name in ('memory_peak_bytes','memory_rss_byte_ms','v8_js_ms','v8_tool_wait_ms','major_faults'):
            self.assertEqual(views[name]['status'],'NOT_COLLECTED')
        unknown=next(file for file in result['story']['runtime']['files'] if file['path']=='/work/unknown')
        self.assertIsNone(unknown['read_bytes_observed'])
        self.assertEqual(result['syscall_rows'][1]['returned_bytes'],0)  # Measured EOF is genuinely zero.
        self.assertIsNone(result['syscall_rows'][2]['returned_bytes'])

    def test_annotations_reference_real_native_tool_and_not_numeric_process_handle(self):
        result=self.compile();tool=result['story']['tools'][0]
        self.assertEqual(tool['semantic_taxonomy_path'],['task','locate'])
        self.assertEqual(tool['kernel_binding'],'NOT_ESTABLISHED')
        self.assertNotIn('root_pid',tool)
        self.assertEqual(tool['correlation']['candidates'][0]['pid'],10)
        self.assertTrue(result['trajectory']['trajectory_digest'])
        self.assertEqual(result['profile']['semantic_quality'],result['annotations']['method'])

    def test_rejects_forged_binding_unknown_result_and_fake_candidate(self):
        report,app,results,corr=fixture()
        for mutator in (lambda a,r,c:a.update(function_bindings=[{'root_pid':999999}]),
                        lambda a,r,c:r[0].update(call_id='unknown'),
                        lambda a,r,c:c['links'][0]['candidates'][0].update(pid=999999),
                        lambda a,r,c:c['links'][0].update(status='CAUSAL_ESTABLISHED')):
            a,r,c=deepcopy(app),deepcopy(results),deepcopy(corr);mutator(a,r,c)
            with self.assertRaises(ValueError):compile_native_profile(report,a,tool_results=r,correlations=c)

    def test_source_inputs_not_mutated(self):
        values=fixture();saved=deepcopy(values)
        compile_native_profile(values[0],values[1],tool_results=values[2],correlations=values[3])
        self.assertEqual(values,saved)

    def test_native_model_exact_id_timing_and_tokens(self):
        report,app,results,corr=fixture();begin=report['run']['begin_ns']
        timing=[{'event':'MODEL_REQUEST_FINISHED','request_id':'request-1','task_label':'native-budget',
            'clock':'CLOCK_MONOTONIC','boot_id':'boot','outcome':'DELIVERED',
            'timestamps_ns':{'accepted':begin+1000,'upstream_dispatch':begin+2000,
                'upstream_first_byte':begin+3000,'upstream_end':begin+4000,'request_end':begin+5000},
            'durations_ns':{'request_total':4000},'output_tool_call_ids':['call-1'],
            'usage':{'total_tokens':12,'input_tokens':10,'output_tokens':2}}]
        result=compile_native_profile(report,app,tool_results=results,correlations=corr,model_timing=timing)
        views={v['name']:v for v in result['profile']['views']}
        self.assertEqual(views['token_count']['total'],12)
        self.assertEqual(views['model_wait_ms']['total'],0.001)
        self.assertEqual(views['wall_ms']['total'],10)

    def test_actual_native_code_mode_outer_layer_is_not_inner_process_or_js_cpu(self):
        report,app,results,corr=fixture();origin=report['run']['begin_ns']
        app.update(thread_id='thread',turn_id='turn')
        def raw_item(kind,stamp,**fields):
            return {'direction':'CODEX_TO_CLIENT','clock':'CLOCK_MONOTONIC','boot_id':'boot','receipt_ns':origin+stamp,
                'message':{'method':'rawResponseItem/completed','params':{'threadId':'thread','turnId':'turn',
                    'item':{'type':kind,'call_id':'model-call','name':'exec',**fields}}}}
        rpc=[raw_item('custom_tool_call',50,input='const result = await tools.exec_command({cmd:"grep needle /work/a"});'),
             raw_item('custom_tool_call_output',1_000_100,output='{"exit_code":0}')]
        timing=[{'event':'MODEL_REQUEST_FINISHED','request_id':'request-outer','task_label':'native-budget',
            'clock':'CLOCK_MONOTONIC','boot_id':'boot','outcome':'DELIVERED',
            'timestamps_ns':{'accepted':origin+10,'request_end':origin+40},
            'durations_ns':{'request_total':30},'output_tool_call_ids':['model-call']}]
        result=compile_native_profile(report,app,tool_results=results,correlations=corr,model_timing=timing,rpc_rows=rpc)
        outer=result['story']['native_model_tools'][0];views={v['name']:v for v in result['profile']['views']}
        self.assertEqual(outer['runtime'],'NATIVE_CODE_MODE')
        self.assertIn('tools.exec_command',outer['request']['text'])
        self.assertEqual(outer['provider_request_ids'],['request-outer'])
        self.assertEqual(outer['child_call_ids'],[])
        self.assertEqual(views['native_model_tool_count']['total'],1)
        self.assertEqual(views['tool_count']['total'],1)
        self.assertEqual(views['v8_js_ms']['status'],'NOT_COLLECTED')
        self.assertEqual(views['syscall_count']['total'],3)
        self.assertEqual(views['wall_ms']['total'],10)
        self.assertTrue(any(segment['kind']=='NATIVE_MODEL_TOOL_WINDOW' for segment in result['story']['wall_partition']['segments']))
        # Reviewed marks bind the same source trajectory; the new outer replay
        # is independently source-linked, never slipped into the 16-step view.
        marks={'trajectory_digest':result['trajectory']['trajectory_digest'],'taxonomy_version':'native-review-v1',
            'taxonomy':{'task':'修复搜索','inspect':'检查实现','unassigned':'未分配阶段'},
            'method':'OFFLINE_OBSERVER_REVIEW','marks':[{'step_id':result['trajectory']['steps'][0]['step_id'],
                                                     'path':['task','inspect']}]}
        reviewed=compile_native_profile(report,app,tool_results=results,correlations=corr,model_timing=timing,
                                        rpc_rows=rpc,semantic_annotations=marks)
        self.assertEqual(reviewed['trajectory']['trajectory_digest'],result['trajectory']['trajectory_digest'])
        self.assertEqual(reviewed['story']['native_model_tools'][0]['semantic_path'],['修复搜索','检查实现'])
        self.assertIn('OFFLINE_OBSERVER_REVIEW',reviewed['annotations']['method'])
        second_request=raw_item('custom_tool_call',60,input='await tools.exec_command({cmd:"pwd"});')
        second_request['message']['params']['item']['call_id']='model-call-2'
        second_output=raw_item('custom_tool_call_output',1_000_200,output='done')
        second_output['message']['params']['item']['call_id']='model-call-2'
        two=compile_native_profile(report,app,tool_results=results,correlations=corr,
            model_timing=timing,rpc_rows=[rpc[0],second_request,rpc[1],second_output])
        view=next(v for v in two['profile']['views'] if v['name']=='native_model_tool_count')
        def walk(node):
            yield node
            for child in node['children']:yield from walk(child)
        outer_nodes=[node for node in walk(view['tree']) if node['kind']=='tool']
        self.assertEqual(len(outer_nodes),2)
        self.assertEqual({n['metadata']['call_id'] for n in outer_nodes},{'model-call','model-call-2'})
        from native_raw_tools import replay_native_raw_tools
        declared=replay_native_raw_tools(rpc,thread_id='thread',turn_id='turn')['native_model_tool_calls']
        for item in declared:
            item['request_received_ns']+=10;item['source_request']['receipt_ns']+=10
            item['output_received_ns']+=20;item['source_output']['receipt_ns']+=20
            item['request_to_output_ms']=(item['output_received_ns']-item['request_received_ns'])/1e6
        app['native_model_tool_calls']=declared
        reconciled=compile_native_profile(report,app,tool_results=results,correlations=corr,model_timing=timing,rpc_rows=rpc)
        actual=reconciled['story']['native_model_tools'][0]
        self.assertEqual(actual['request_received_ns'],origin+50)
        self.assertEqual(actual['application_handler_timing']['request_received_ns'],origin+60)
        self.assertIn('RAW_RPC_LEDGER_RECEIPT',actual['timing_source_reconciliation'])
        app['native_model_tool_calls'][0]['request']['text']='forged JS'
        with self.assertRaisesRegex(ValueError,'content/message identity'):
            compile_native_profile(report,app,tool_results=results,correlations=corr,model_timing=timing,rpc_rows=rpc)

    def test_export_exclusive_create_and_bounded_syscall_pages(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);run=base/'run';(run/'app').mkdir(parents=True)
            report,app,results,corr=fixture();report['threads'][0]['calls']*=150
            write_new(run/'report.json',report);write_new(run/'app/steps.json',app)
            write_new(run/'native-process-correlations.json',corr)
            write_new(run/'app/native-tool-results.jsonl',b''.join(json.dumps(x).encode()+b'\n' for x in results))
            output=base/'native.html';profile=base/'native.profile.json'
            result=export_native_profile(run,output,profile)
            self.assertEqual(result['runtime_syscalls'],450)
            self.assertEqual(len(list((base/'native.assets').glob('all-*.json'))),3)
            for path in (base/'native.assets').glob('*.json'):
                self.assertLessEqual(len(json.loads(path.read_text())['rows']),200)
            html=output.read_text()
            self.assertIn('data-role="chart"',html)
            self.assertIn('完整运行时：尚未归属到单个原生工具',html)
            self.assertNotIn('"syscall_rows":',html)
            self.assertIn('needle',html)
            self.assertIn('memory-plot',html)
            receipt=json.loads((base/'native.artifacts.json').read_text())
            self.assertEqual(receipt['conservation']['per_tool_kernel_syscalls_assigned'],0)
            with self.assertRaises(ValueError):export_native_profile(run,output,profile)

    def test_public_export_only_named_inputs_never_budget_credentials_or_sibling_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);run=base/'run';(run/'app').mkdir(parents=True)
            report,app,results,corr=fixture()
            write_new(run/'report.json',report);write_new(run/'app/steps.json',app)
            write_new(run/'native-process-correlations.json',corr)
            write_new(run/'app/native-tool-results.jsonl',b''.join(json.dumps(x).encode()+b'\n' for x in results))
            (run/'private-budget').mkdir();write_new(run/'private-budget/token.txt',b'DO_NOT_PUBLISH_API_KEY')
            write_new(run/'app/token.txt',b'DO_NOT_PUBLISH_API_KEY')
            write_new(base/'sibling-private.json',{'private':'DO_NOT_PUBLISH_API_KEY'})
            public=base/'public';result=export_public_native_profile(run,public)
            self.assertEqual(result['runtime_syscalls'],3)
            self.assertTrue((public/'index.html').is_file())
            self.assertFalse((public/'source/private-budget').exists())
            self.assertFalse((public/'source/app/token.txt').exists())
            for path in public.rglob('*'):
                if path.is_file():self.assertNotIn(b'DO_NOT_PUBLISH_API_KEY',path.read_bytes())
            receipt=json.loads((public/'publication.json').read_text())
            self.assertEqual(receipt['status'],'ALLOWLIST_PUBLIC_ROOT_CREATED')
            self.assertEqual(receipt['copied_inputs']['source/report.json']['size_bytes'],(run/'report.json').stat().st_size)
            with self.assertRaises(ValueError):export_public_native_profile(run,public)

    def test_real_browser_native_page_paging_candidate_query_and_memory(self):
        from validate_profile_ui_browser import check_page, installed_browser_paths
        module,browser=installed_browser_paths()
        if not module or not browser or not shutil.which('node'):
            self.skipTest('installed Playwright/Chromium required; no auto-download')
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);run=base/'run';(run/'app').mkdir(parents=True);(run/'resources').mkdir()
            report,app,results,corr=fixture();report['threads'][0]['calls']*=150
            write_new(run/'report.json',report);write_new(run/'app/steps.json',app)
            write_new(run/'native-process-correlations.json',corr)
            results[0]['output']['text']='</script><img src=x onerror="window.XSS=1">'
            write_new(run/'app/native-tool-results.jsonl',b''.join(json.dumps(x).encode()+b'\n' for x in results))
            target={'name':'codex-native-runtime','pid':10,'start_ticks':2,'role':'AGENT_RUNTIME','agent_id':'agent-native'}
            origin=report['run']['begin_ns']
            samples=[{'event':'RESOURCE_SAMPLE','boot_id':'boot','begin_ns':origin+stamp,
                'end_ns':origin+stamp+1,'target':target,'process':{'status':'OBSERVED','start_ticks':2,
                'values':{'rss_bytes':100+stamp,'rss_anon_bytes':60,'rss_file_bytes':40}}}
                for stamp in (100,1000,10000)]
            write_new(run/'resources/resource-samples.jsonl',b''.join(json.dumps(x).encode()+b'\n' for x in samples))
            output=base/'native.html';profile=base/'native.profile.json';export_native_profile(run,output,profile)
            class Quiet(SimpleHTTPRequestHandler):
                def log_message(self,*args):pass
            server=ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=str(base)))
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            url='http://127.0.0.1:'+str(server.server_port)+'/native.html'
            try:
                validation=check_page(url=url,playwright=module,browser=browser)
                self.assertEqual(validation['status'],'PASSED')
                js=r'''
const assert=require('node:assert/strict');let s='';process.stdin.on('data',x=>s+=x);process.stdin.on('end',()=>{(async()=>{
const cfg=JSON.parse(s),{chromium}=require(cfg.module),b=await chromium.launch({headless:true,executablePath:cfg.browser,args:['--no-sandbox']});
try{const p=await b.newPage(),errors=[];p.on('pageerror',e=>errors.push(String(e)));await p.goto(cfg.url);
await p.waitForFunction(()=>document.querySelector('#native-syscalls').children.length===200);
assert.equal(await p.locator('#native-syscalls tr').count(),200);await p.locator('#native-next').click();await p.waitForFunction(()=>document.querySelector('#native-page-status').textContent.includes('第 2 / 3'));
await p.locator('details.native-tool summary').first().click();assert((await p.locator('details.native-tool').innerText()).includes('CORRELATED_NOT_CAUSAL'));
await p.locator('[data-candidate-thread]').first().click();assert.equal(await p.locator('#native-thread').inputValue(),'10:birth');assert((await p.locator('#candidate-context').innerText()).includes('不是证明'));
await p.locator('#file-filter').fill('unknown');assert.equal(await p.locator('#native-files tr').count(),1);assert((await p.locator('#native-files').innerText()).includes('未采集'));
assert(await p.locator('[data-memory-field="rss_bytes"]').count());assert.equal(await p.evaluate(()=>window.XSS),undefined);assert.deepEqual(errors,[]);console.log('PASSED');
}finally{await b.close();}})().catch(e=>{console.error(e.stack);process.exitCode=1;});});
'''
                check=subprocess.run(['node','-e',js],input=json.dumps({'module':module,'browser':browser,'url':url}),
                    text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
                self.assertEqual(check.returncode,0,check.stderr)
                self.assertEqual(check.stdout.strip(),'PASSED')
            finally:
                server.shutdown();server.server_close();thread.join(timeout=2)


if __name__=='__main__':unittest.main()
