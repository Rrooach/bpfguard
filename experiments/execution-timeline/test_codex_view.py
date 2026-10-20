"""Synthetic binding/view fixtures only; never API, Agent, VM or raw replay."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import codex_view as C
from common import digest, write_new
from test_render import BASE, fixture


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    write_new(path, value)


def example(root, *, incomplete=False):
    root.mkdir()
    report=fixture()
    tool=report['tools'][0]
    tool.update(kind='CODEX_DYNAMIC_SHELL',codex_call_id='call-1',command=['/bin/bash','--noprofile','--norc','-c','cat /tmp/a'],result=0,
        root={'tid':11,'start_ticks':1,'clock_ticks':100},cgroup_id=12,cgroup_path='/sys/fs/cgroup/demo',cgroup_empty=True)
    binding={key:copy.deepcopy(tool[key]) for key in ('tool_call_id','root','cgroup_id','cgroup_path','begin_ns','end_ns','cgroup_empty')}
    binding.update(thread_id='thread-codex',turn_id='turn-1',call_id='call-1',rpc_request_id=3,tool='observer_bash',
        command='cat /tmp/a',root_pid=11,binding_basis=C.BINDING,stdout_artifact='tool-0001/stdout',stderr_artifact='tool-0001/stderr')
    step=dict(binding,kind='TOOL_CALL',exit_code=0,stdout='hello\n',stderr='',output_truncated=False)
    app={'schema_version':1,'mode':C.MODE,'agent_loop':'OFFICIAL_CODEX_NOT_IMPLEMENTED_BY_THIS_CLIENT',
        'thread_id':'thread-codex','turn_id':'turn-1','model':'deepseek-flash','status':'completed',
        'steps':[step,{'kind':'AGENT_MESSAGE','thread_id':'thread-codex','turn_id':'turn-1','text':'Done <script>bad()</script>','receipt_ns':BASE+1}],
        'function_bindings':[binding]}
    save(root/'app/prompt.txt',b'Read the sample. <img src=x>')
    save(root/'app/codex-result.json',{'mode':C.MODE,'status':'CLIENT_OR_RUNTIME_FAILURE'} if incomplete else app)
    save(root/'tool-0001/stdout',b'hello\n');save(root/'tool-0001/stderr',b'')
    if not incomplete:
        save(root/'app/steps.json',app)
        save(root/'app/function-bindings.jsonl',(json.dumps(binding)+'\n').encode())
    names=[str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()]
    manifest={'schema_version':1,'mode':C.MODE,'clock':'CLOCK_MONOTONIC','run_id':report['run']['run_id'],
        'boot_id':report['run']['boot_id'],'begin_ns':BASE,'end_ns':BASE+1000000000,'agent_id':'agent-A','tools':[tool],
        'artifacts':{name:digest(root/name) for name in names}}
    save(root/'manifest.json',manifest);save(root/'report.json',report)
    save(root/'verification.json',{'status':'REPLAY_PASSED','manifest':digest(root/'manifest.json'),'report':digest(root/'report.json')})
    return manifest,app


class CodexViewTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_task_commands_and_answer_are_readable_with_escaped_content(self):
        source=self.root/'run';example(source);identity=digest(source/'report.json')
        result=C.export(source,self.root/'view')
        page=(self.root/'view/index.html').read_text()
        self.assertIn('cat /tmp/a',page);self.assertIn('成功，退出码 0',page)
        self.assertIn('&lt;img src=x&gt;',page);self.assertNotIn('<script>bad()',page)
        self.assertIn('native-readable.html?tool=tool-1&amp;kind=filesystem#operations',page)
        self.assertEqual(result['application_steps_status'],'EXPLICIT_FUNCTION_GATE_BINDINGS_CHECKED')
        self.assertEqual(digest(source/'report.json'),identity)
        with self.assertRaisesRegex(ValueError,'fresh'):C.export(source,self.root/'view')

    def test_tool_lifecycle_overview_prioritizes_status_and_three_wall_intervals(self):
        call={'call_id':'call-1','tool_name':'search_code','status':'SUCCEEDED',
            'request_to_execution_ns':2000000,'execution_duration_ns':3000000,
            'request_to_result_delivery_ns':6000000}
        step={'kind':'TOOL_CALL','call_id':'call-1','tool_call_id':'tool-1','tool_name':'search_code',
            'tool_status':'SUCCEEDED','command':'rg needle','exit_code':0,'begin_ns':BASE+2_000_000,
            'end_ns':BASE+5_000_000,'stdout':'match','stderr':'','cgroup_empty':True,
            'stdout_artifact':'stdout','stderr_artifact':'stderr'}
        result={'capture_begin_ns':BASE,'capture_end_ns':BASE+10_000_000,
            'agent_outcome':{'status':'completed'},'application_steps_status':'EXPLICIT_FUNCTION_GATE_BINDINGS_CHECKED',
            'prompt':'find needle','steps':[step],'tool_calls':[call],'provider_scope':'UNVERIFIED',
            'verification':{},'native_successful_exec_records':0,'tool_native_evidence':{}}
        page=C.page(self.root,result,self.root,False)
        self.assertIn('工具调用概览',page);self.assertIn('search_code',page)
        self.assertIn('2.000 ms',page);self.assertIn('3.000 ms',page);self.assertIn('6.000 ms',page)
        self.assertIn('工具执行成功不等于任务正确',page)

    def test_application_reported_tool_is_readable_but_not_called_linux_bound(self):
        call={'call_id':'mcp-1','tool_name':'mcpToolCall','status':'SUCCEEDED',
            'arguments':{'server':'docs','tool':'search','arguments':{'query':'needle'}},
            'result_summary':{'result_present':True},'request_to_execution_ns':None,
            'execution_duration_ns':None,'request_to_result_delivery_ns':7_000_000,
            'application_evidence':'CODEX_REPORTED_TOOL_CALL','execution_binding':'NOT_ESTABLISHED',
            'linux_effect_evidence':'NOT_BOUND_TO_LINUX_EXECUTION',
            'remote_effect':'REMOTE_EFFECT_NOT_CONFIRMABLE','producer_duration_ms':6}
        step={'kind':'APPLICATION_TOOL_CALL','call_id':'mcp-1','tool_name':'mcpToolCall',
            'tool_status':'SUCCEEDED'}
        result={'capture_begin_ns':BASE,'capture_end_ns':BASE+10_000_000,
            'agent_outcome':{'status':'completed'},
            'application_steps_status':'TOOL_EVENTS_REPLAYED_AND_PROCESS_BINDINGS_CHECKED_WHERE_PRESENT',
            'prompt':'search docs','steps':[step],'tool_calls':[call],'provider_scope':'UNVERIFIED',
            'verification':{},'native_successful_exec_records':0,'tool_native_evidence':{}}
        page=C.page(self.root,result,self.root,False)
        self.assertIn('Codex已报告',page)
        self.assertIn('未绑定Linux执行',page)
        self.assertIn('不能把附近syscall猜成该工具产生',page)
        self.assertIn('REMOTE_EFFECT_NOT_CONFIRMABLE',page)

    def test_unbound_or_modified_prompt_is_rejected(self):
        source=self.root/'run';example(source)
        (source/'app/prompt.txt').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'saved receipt'):C.compose(source)

    def test_step_root_cannot_be_replaced_by_timestamp_proximity(self):
        source=self.root/'run';manifest,app=example(source)
        app['function_bindings'][0]['root']['tid']=999
        for name,value in [('app/steps.json',app),('app/function-bindings.jsonl',(json.dumps(app['function_bindings'][0])+'\n').encode())]:
            (source/name).unlink();save(source/name,value);manifest['artifacts'][name]=digest(source/name)
        (source/'manifest.json').unlink();save(source/'manifest.json',manifest)
        verification=json.loads((source/'verification.json').read_text());verification['manifest']=digest(source/'manifest.json')
        (source/'verification.json').unlink();save(source/'verification.json',verification)
        with self.assertRaisesRegex(ValueError,'root/cgroup'):C.compose(source)

    def test_incomplete_application_keeps_failure_and_does_not_invent_steps(self):
        source=self.root/'run';example(source,incomplete=True)
        result=C.export(source,self.root/'view')
        self.assertEqual(result['steps'],[])
        self.assertEqual(result['application_steps_status'],'INCOMPLETE_APPLICATION_LOG')
        self.assertIn('不补造命令',(self.root/'view/index.html').read_text())

    def test_pass_receipt_without_report_digest_is_not_an_accepted_binding(self):
        source=self.root/'run';example(source)
        verification=json.loads((source/'verification.json').read_text());verification.pop('report')
        (source/'verification.json').unlink();save(source/'verification.json',verification)
        with self.assertRaisesRegex(ValueError,'report identity'):C.compose(source)

    def test_native_write_read_and_chmod_evidence_does_not_guess_path_from_command(self):
        report=fixture();gate=report['tools'][0];gate['command']='write /pretend/target'
        report['threads'][0]['calls']=[
            {'nr':1,'name':'write','start_ns':BASE+1,'end_ns':BASE+2,'pairing':'PAIRED','args':[3,444,15],'result':15},
            {'nr':90,'name':'syscall_90','start_ns':BASE+3,'end_ns':BASE+4,'pairing':'PAIRED','args':[444,0o600],'result':0},
            {'nr':0,'name':'read','start_ns':BASE+5,'end_ns':BASE+9,'pairing':'PAIRED','args':[3,444,16],'result':15,
             'files':[{'path':'/actual/target','path_quality':'KERNEL_PATH_AT_LSM_PERMISSION_CANDIDATE','read':{
                 'start_ns':BASE+6,'end_ns':BASE+8,'result':15,'requested_bytes':16,'returned_bytes':15}}]}]
        evidence=C.native_evidence(report,gate)
        self.assertEqual(evidence['write_samples'][0]['requested_bytes'],15)
        self.assertIsNone(evidence['write_samples'][0]['path'])
        self.assertEqual(evidence['chmod_arguments'][0]['requested_mode_octal'],'0600')
        self.assertEqual(evidence['small_read_samples'][0]['path'],'/actual/target')
        self.assertEqual(evidence['small_read_samples'][0]['returned_bytes'],15)
        self.assertNotIn('/pretend',json.dumps(evidence))

    def test_fake_provider_and_unverified_provider_are_not_called_real_inference(self):
        source=self.root/'run';example(source)
        C.export(source,self.root/'fake','FAKE_PROVIDER_NO_API')
        self.assertIn('不是 DeepSeek 真实推理结果',(self.root/'fake/index.html').read_text())
        result=C.export(source,self.root/'unverified')
        self.assertEqual(result['provider_scope'],'UNVERIFIED')
        self.assertIn('未核实真实 API 出站',(self.root/'unverified/index.html').read_text())

    def test_declared_workspace_comes_from_bound_thread_start_not_command_text(self):
        source=self.root/'run';manifest,_=example(source)
        name='app/client-requests.jsonl';save(source/name,(json.dumps({'method':'thread/start','params':{'cwd':'/declared/project'}})+'\n').encode())
        manifest['artifacts'][name]=digest(source/name)
        (source/'manifest.json').unlink();save(source/'manifest.json',manifest)
        verification=json.loads((source/'verification.json').read_text());verification['manifest']=digest(source/'manifest.json')
        (source/'verification.json').unlink();save(source/'verification.json',verification)
        _,result,_,_=C.compose(source)
        self.assertEqual(result['declared_workspace']['path'],'/declared/project')
        self.assertTrue(C.in_declared_workspace('/declared/project/a','/declared/project'))
        self.assertFalse(C.in_declared_workspace('/declared/project-other/a','/declared/project'))
        self.assertFalse(C.in_declared_workspace('/declared/project/../other','/declared/project'))

    def test_external_receipt_is_linked_only_when_manifest_and_run_match(self):
        source=self.root/'run';manifest,_=example(source)
        proof=self.root/'provider-proof.json'
        save(proof,{'status':'REAL_CODEX_PROVIDER_COMMAND_AND_FINAL_ANSWER_BOUND','run_id':manifest['run_id'],'manifest_identity':digest(source/'manifest.json')})
        result=C.export(source,self.root/'with-proof','REAL_PROVIDER_CONFIRMED_EXTERNALLY','0.154.0',proof)
        self.assertEqual(result['provider_receipt']['identity'],digest(proof))
        self.assertIn('provider-proof.json',(self.root/'with-proof/index.html').read_text())
        proof.unlink();save(proof,{'status':'REAL_CODEX_PROVIDER_COMMAND_AND_FINAL_ANSWER_BOUND','run_id':'wrong','manifest_identity':digest(source/'manifest.json')})
        with self.assertRaisesRegex(ValueError,'receipt run/manifest'):C.export(source,self.root/'bad-proof',provider_receipt=proof)


if __name__=='__main__':unittest.main()
