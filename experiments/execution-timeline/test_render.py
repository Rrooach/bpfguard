#!/usr/bin/env python3
"""Synthetic viewer tests only; no VM, profiler, evidence database or network."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('execution_timeline_render', HERE / 'render.py')
render = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(render)
BASE = 10 ** 18 + 7


def fixture():
    states = ('ONCPU', 'RUNNABLE', 'SLEEP', 'UNKNOWN')
    segments = [{'begin_ns': BASE + i * 250000000, 'end_ns': BASE + (i + 1) * 250000000,
        'state': state, 'reason': '睡眠原因须查证据' if state == 'SLEEP' else state,
        'syscall': {'nr': 0, 'name': 'read', 'call_id': 'call-1', 'result': 32,
            'start_ns': BASE + 500000000, 'end_ns': BASE + 700000000,
            'requested_bytes': 64, 'returned_bytes': 32} if state == 'SLEEP' else None,
        'files': [{'identity': {'mount_id': 4, 'inode': 9}, 'path': '/tmp/a', 'quality': 'KERNEL_OBJECT'}]
            if state == 'SLEEP' else [],
        'stack': ['io_schedule', 'vfs_read'] if state == 'SLEEP' else [],
        'evidence': {'source': 'sched_switch', 'status': 'OBSERVED'}} for i, state in enumerate(states)]
    thread = {'key': '11/1000000000000000008', 'tid': 11, 'tgid': 11, 'birth_ns': BASE + 1,
        'parent_key': None, 'comm': 'grep', 'agent_id': 'agent-A', 'tool_call_id': 'tool-1',
        'begin_ns': BASE, 'end_ns': BASE + 1000000000, 'segments': segments,
        'calls': [{'call_id': 'call-1', 'name': 'read', 'start_ns': BASE + 500000000,
                   'end_ns': BASE + 700000000, 'requested_bytes': 64, 'returned_bytes': 32}]}
    return {'schema_version': 1, 'run': {'run_id': 'run-test', 'boot_id': 'boot-test',
        'begin_ns': BASE, 'end_ns': BASE + 1000000000},
        'tools': [{'agent_id': 'agent-A', 'task_id': 'task-A', 'tool_call_id': 'tool-1',
            'begin_ns': BASE, 'end_ns': BASE + 1000000000, 'root': {'tid': 11, 'birth_ns': BASE + 1},
            'evidence': {'source': 'APPLICATION_DECLARED'}}],
        'threads': [thread],
        'critical_path': {'status': 'INCOMPLETE_WITH_UNKNOWN', 'tools': [{'tool_call_id': 'tool-1',
            'wall_ns': 1000000000, 'accounted_ns': 750000000, 'unknown_ns': 250000000,
            'segments': copy.deepcopy(segments), 'state_totals_ns': {name: 250000000 for name in states},
            'dependency_edges': [], 'status': 'INCOMPLETE_WITH_UNKNOWN'}]},
        'health': {'status': 'PARTIAL', 'lost': 0}, 'findings': [{'kind': 'UNCOVERED_INTERVAL'}],
        'totals': {'threads': 1}, 'extra_future_field': {'preserved': [1, 2, 3]}}


def script(html, identity):
    match = re.search(r'<script id="' + re.escape(identity) + r'" type="application/json">(.*?)</script>', html, re.S)
    if match is None:
        raise AssertionError('missing embedded script ' + identity)
    return match.group(1)


def main_script(html):
    return re.findall(r'<script>(.*?)</script>', html, re.S)[0]


def run_node(html, actions, location=None):
    payload = {'original': script(html, 'report-json'), 'model': script(html, 'timeline-model'),
               'script': main_script(html), 'actions': actions, 'location': location}
    harness = r'''
const vm=require('vm'),fs=require('fs'),data=JSON.parse(fs.readFileSync(0,'utf8'));
const elements={};let lastBlob=null,linkClicks=0;
const context={fillRect(){},strokeRect(){},fillText(){},save(){},restore(){},beginPath(){},rect(){},clip(){},moveTo(){},lineTo(){},stroke(){},setLineDash(){}};
function element(id){return elements[id]||(elements[id]={value:'',textContent:'',style:{},clientWidth:1100,listeners:{},addEventListener(type,callback){this.listeners[type]=callback;},getContext(){return context;},getBoundingClientRect(){return {left:0,top:0,width:this.width,height:this.height};},appendChild(){},remove(){},click(){linkClicks++;}});}
element('report-json').textContent=data.original;element('timeline-model').textContent=data.model;
element('start').value='0';element('maxThreads').value='128';
const scope={document:{getElementById:element,createElement:()=>element('download-link'),body:element('body')},
window:{innerWidth:1400,innerHeight:1000,addEventListener(){},location:data.location||{}},URLSearchParams,
Blob:class {constructor(parts,options){lastBlob={parts,options};}},
URL:{createObjectURL(){return 'blob:offline-test';},revokeObjectURL(){}},
setTimeout(callback){callback();},console};
vm.runInNewContext(data.script,scope,{timeout:10000});
vm.runInNewContext(data.actions,scope,{timeout:10000});
process.stdout.write(JSON.stringify({coverage:element('coverage').textContent,details:element('details').textContent,
 tip:element('tip').textContent,height:element('timeline').height,download:lastBlob,linkClicks,
 run:element('run').textContent,critical:element('criticalStatus').textContent,
 toolTiming:element('toolTiming').textContent,overview:element('overviewRows').innerHTML,
 operations:element('operationRows').innerHTML,operationStatus:element('operationStatus').textContent,
 operationPage:element('operationPage').textContent,operationDetail:element('operationDetail').textContent,
 programs:element('programRows').innerHTML,programStatus:element('programStatus').textContent}));
'''
    completed = subprocess.run(['node', '-e', harness], input=json.dumps(payload), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if completed.returncode:
        raise AssertionError(completed.stderr)
    return json.loads(completed.stdout)


class RenderTests(unittest.TestCase):
    def test_presentation_names_are_complete_native64_without_mutating_raw(self):
        report = fixture()
        raw = {'call_id': 9, 'nr': 263, 'name': 'syscall_263', 'args': [(1 << 64) - 100, 123456, 0],
            'start_ns': BASE + 1, 'end_ns': BASE + 12, 'result': -13, 'pairing': 'PAIRED', 'files': []}
        report['threads'][0]['calls'] = [raw]
        presentation = render.model_for(report)['threads'][0]['calls'][0]['presentation']
        self.assertEqual(presentation['name'], 'unlinkat')
        self.assertEqual(presentation['descriptor']['value'], -100)
        self.assertEqual(presentation['outcome'], 'ERROR')
        self.assertEqual(presentation['errno'], 'EACCES')
        self.assertEqual(raw['name'], 'syscall_263')
        self.assertEqual(presentation['vfs_reads'], [])

    def test_readv_iov_count_is_not_presented_as_requested_bytes(self):
        call = {'nr': 19, 'args': [3, 55555, 8], 'result': 4096, 'pairing': 'PAIRED'}
        shown = render.call_presentation(call)
        self.assertIsNone(shown['requested_bytes'])
        self.assertEqual(shown['returned_bytes'], 4096)
        self.assertEqual(shown['descriptor']['value'], 3)

    def test_nonreturn_and_missing_result_are_not_displayed_as_success(self):
        self.assertEqual(render.call_presentation({'nr': 59, 'result': 0, 'pairing': 'LIFECYCLE_TERMINATED_NONRETURNING_CALL'})['outcome'], 'NO_ORDINARY_RESULT_OR_INCOMPLETE')
        self.assertEqual(render.call_presentation({'nr': 1, 'result': None})['outcome'], 'NO_ORDINARY_RESULT_OR_INCOMPLETE')
        self.assertEqual(render.call_presentation({'nr': 202, 'result': -512, 'pairing':'PAIRED'})['outcome'], 'KERNEL_NEGATIVE_RETURN_NOT_NAMED_ERRNO')

    @unittest.skipUnless(shutil.which('node'), 'Node optional EXEC interaction check unavailable')
    def test_successful_exec_programs_are_not_guessed_from_comm(self):
        report = fixture()
        report['threads'][0]['comm_history'] = [{'comm':'misleading-name','timestamp_ns':BASE+2}]
        legacy = run_node(render.render_report(report),'')
        self.assertEqual(legacy['programs'], '')
        self.assertIn('不能据此断言',legacy['programStatus'])
        report['threads'][0]['execs'] = [{'timestamp_ns':BASE+3,'old_tid':11,'filename':'/usr/bin/grep',
            'filename_quality':'KERNEL_EXEC_FILENAME_NOT_CANONICAL_PATH','file':{'mount_id':1,'device':2,'inode':3,'generation':0},
            'executable_identity_quality':'KERNEL_BPRM_FILE_IDENTITY','evidence':'KERNEL_SCHED_PROCESS_EXEC_SUCCESS','argv':None}]
        output=run_node(render.render_report(report),'')
        self.assertIn('/usr/bin/grep',output['programs'])
        self.assertIn('KERNEL_EXEC_FILENAME_NOT_CANONICAL_PATH',output['programs'])
        self.assertNotIn('misleading-name',output['programs'])
        self.assertIn('inode=3',output['programs'])

    def test_presentation_context_is_escaped_and_does_not_modify_original_json(self):
        report=fixture();text='<b>FAKE_PROVIDER_NO_API</b>'
        page=render.render_report(report,text)
        self.assertIn('展示说明：&lt;b&gt;FAKE_PROVIDER_NO_API&lt;/b&gt;',page)
        self.assertEqual(json.loads(script(page,'report-json')),report)

    @unittest.skipUnless(shutil.which('node'), 'Node optional window scope check unavailable')
    def test_default_operations_do_not_relabel_tool_startup_as_execution(self):
        report=fixture();report['tools'][0].update(begin_ns=BASE+100,command=['cat','/tmp/a'],result=0)
        report['threads'][0]['calls']=[{'nr':257,'start_ns':BASE+10,'end_ns':BASE+20,'result':3,'pairing':'PAIRED','args':[3,999,0]},
            {'nr':1,'start_ns':BASE+110,'end_ns':BASE+120,'result':5,'pairing':'PAIRED','args':[1,999,5]}]
        first=run_node(render.render_report(report),'')
        self.assertEqual(first['operations'].count('<tr>'),1)
        self.assertNotIn('openat (257)',first['operations'])
        self.assertIn('write (1)',first['operations'])
        self.assertIn('退出码 0',first['overview'])
        self.assertIn('argv:',first['overview'])
        lifetime=run_node(render.render_report(report),"document.getElementById('operationScope').value='lifetime';document.getElementById('operationApply').listeners.click();")
        self.assertIn('openat (257)',lifetime['operations'])
        self.assertIn('OUTSIDE_EXECUTION_STARTUP_OR_OTHER_CONTEXT',lifetime['operations'])

    @unittest.skipUnless(shutil.which('node'), 'Node optional Codex label check unavailable')
    def test_codex_runtime_configuration_is_collapsed_and_shell_command_readable(self):
        report=fixture();report['tools'][0].update(kind='OFFICIAL_CODEX_RUNTIME',command=['codex','app-server','-c','long_config=1'])
        runtime=run_node(render.render_report(report),'')
        self.assertIn('<summary>Codex运行：模型请求／协调／等待（DeepSeek）</summary>',runtime['overview'])
        self.assertIn('不是纯模型等待',runtime['overview'])
        self.assertIn('long_config=1',runtime['overview'])
        report['tools'][0].update(kind='CODEX_DYNAMIC_SHELL',command=['/bin/bash','--noprofile','--norc','-c','cat /tmp/report'])
        shell=run_node(render.render_report(report),'')
        self.assertIn('<summary>cat /tmp/report</summary>',shell['overview'])

    @unittest.skipUnless(shutil.which('node'), 'Node optional deep-link check unavailable')
    def test_query_prefilters_tool_and_native_reads_without_changing_source(self):
        report=fixture()
        output=run_node(render.render_report(report),'',{'search':'?tool=tool-1&kind=vfs','hash':'#operations'})
        self.assertIn('当前筛选 0 条',output['operationStatus'])
        self.assertIn('tool-1',output['overview'])

    @unittest.skipUnless(shutil.which('node'), 'Node optional Codex focus check unavailable')
    def test_codex_default_file_list_focuses_on_dynamic_task_not_runtime_catalog(self):
        report=fixture();report['tools'][0]['kind']='OFFICIAL_CODEX_RUNTIME'
        report['threads'][0]['calls']=[{'nr':0,'start_ns':BASE+10,'end_ns':BASE+20,'args':[3,9,8],'result':8,'pairing':'PAIRED'}]
        shell=copy.deepcopy(report['tools'][0]);shell.update(kind='CODEX_DYNAMIC_SHELL',tool_call_id='shell-1')
        worker=copy.deepcopy(report['threads'][0]);worker.update(key='shell-thread',tid=22,tgid=22,tool_call_id='shell-1')
        worker['calls']=[{'nr':1,'start_ns':BASE+30,'end_ns':BASE+40,'args':[1,9,5],'result':5,'pairing':'PAIRED'}]
        report['tools'].append(shell);report['threads'].append(worker)
        shown=run_node(render.render_report(report),'')
        self.assertIn('write (1)',shown['operations']);self.assertNotIn('read (0)',shown['operations'])
        all_calls=run_node(render.render_report(report),"document.getElementById('operationScope').value='all';document.getElementById('operationApply').listeners.click();")
        self.assertIn('read (0)',all_calls['operations'])

    @unittest.skipUnless(shutil.which('node'), 'Node optional UI interaction check unavailable')
    def test_readable_commands_and_separate_syscall_vfs_rows(self):
        report = fixture(); report['tools'][0].update(command='cat /src/a', result={'return_code': 0})
        report['threads'][0]['calls'] = [{'nr': 0, 'name': 'read', 'args': [3, 999, 4096], 'result': 16,
            'pairing': 'PAIRED', 'start_ns': BASE + 10, 'end_ns': BASE + 110,
            'files': [{'path': '/src/a', 'path_quality': 'KERNEL_D_PATH', 'read': {
                'start_ns': BASE + 20, 'end_ns': BASE + 100, 'requested_bytes': 4096, 'returned_bytes': 16, 'result': 16}}]}]
        output = run_node(render.render_report(report), r'''
document.getElementById('operationMode').value='vfs';document.getElementById('operationApply').listeners.click();
document.getElementById('operationCsv').listeners.click();
''')
        self.assertIn('cat /src/a', output['overview'])
        self.assertIn('退出码 0', output['overview'])
        self.assertIn('1 条syscall与 1 条VFS read', output['operationStatus'])
        self.assertEqual(output['operations'].count('<tr>'), 1)
        self.assertIn('/src/a', output['operations'])
        self.assertIn('KERNEL_D_PATH', output['operations'])
        exported = output['download']['parts'][0]
        self.assertIn('"vfs_read_duration_ns"', exported)
        self.assertIn('"80"', exported)
        self.assertNotIn('"100"', exported)

    @unittest.skipUnless(shutil.which('node'), 'Node optional pagination check unavailable')
    def test_operation_table_pages_filters_errors_and_preserves_unknown_path(self):
        report = fixture()
        report['threads'][0]['calls'] = [{'nr': 257, 'name': 'syscall_257', 'args': [(1 << 64) - 100, 123, 0],
            'start_ns': BASE + i * 1000, 'end_ns': BASE + i * 1000 + 100, 'pairing': 'PAIRED',
            'result': -2 if i == 2 else 3, 'files': []} for i in range(225)]
        first = run_node(render.render_report(report), '')
        self.assertEqual(first['operations'].count('<tr>'), 100)
        self.assertIn('第 1 / 3 页', first['operationPage'])
        self.assertIn('openat (257)', first['operations'])
        self.assertIn('未解析（未采集路径', first['operations'])
        second = run_node(render.render_report(report), "document.getElementById('operationNext').listeners.click();")
        self.assertIn('第 2 / 3 页', second['operationPage'])
        failed = run_node(render.render_report(report), "document.getElementById('operationOutcome').value='ERROR';document.getElementById('operationApply').listeners.click();")
        self.assertEqual(failed['operations'].count('<tr>'), 1)
        self.assertIn('ENOENT', failed['operations'])

    @unittest.skipUnless(shutil.which('node'), 'Node optional escaping check unavailable')
    def test_visible_operation_paths_and_commands_are_escaped(self):
        report = fixture(); text='<img src=x onerror=alert(1)>'
        report['tools'][0]['command'] = text
        report['threads'][0]['calls'][0].update(nr=0, files=[{'path':text,'read':{'result':1}}])
        output=run_node(render.render_report(report),'')
        self.assertNotIn('<img ',output['overview'])
        self.assertNotIn('<img ',output['operations'])
        self.assertIn('&lt;img ',output['overview'])

    def test_full_json_preserves_all_fields_and_large_integer_types(self):
        value = fixture()
        html = render.render_report(value)
        self.assertEqual(json.loads(script(html, 'report-json')), value)
        self.assertEqual(value, fixture(), 'render must not modify caller data')
        self.assertIn(str(BASE), script(html, 'report-json'))

    def test_relative_time_and_large_inspector_identity_are_exact(self):
        value = json.loads(script(render.render_report(fixture()), 'timeline-model'))
        self.assertEqual(value['duration_ns'], 1000000000)
        self.assertEqual(value['threads'][0]['segments'][0]['t0'], 0)
        self.assertEqual(value['threads'][0]['segments'][1]['t0'], 250000000)
        self.assertEqual(value['threads'][0]['birth_ns'], str(BASE + 1))
        self.assertEqual(value['threads'][0]['detail']['birth_ns'], str(BASE + 1))
        self.assertEqual(value['run']['begin_ns'], str(BASE))

    def test_tool_invocation_and_dispatch_keep_exact_relative_times_and_raw_json(self):
        report = fixture()
        report['tools'][0].update(invocation_ns=BASE + 100000000, begin_ns=BASE + 200000000)
        before = copy.deepcopy(report)
        html = render.render_report(report)
        tool = json.loads(script(html, 'timeline-model'))['tools'][0]
        self.assertEqual(tool['timing']['invocation_status'], 'RECORDED')
        self.assertEqual(tool['timing']['tool_call_wall_ns'], 900000000)
        self.assertEqual(tool['timing']['execution_window_ns'], 800000000)
        self.assertEqual(tool['timing']['dispatch_prelude_ns'], 100000000)
        self.assertEqual((tool['dispatch_prelude']['t0'], tool['dispatch_prelude']['t1']), (100000000, 200000000))
        self.assertEqual(tool['dispatch_prelude']['detail']['begin_ns'], str(BASE + 100000000))
        self.assertEqual(report, before)
        self.assertEqual(json.loads(script(html, 'report-json')), report)
        self.assertIn('不塞入完成路径', html)

    def test_missing_or_invalid_invocation_is_not_inferred(self):
        report = fixture()
        tool = render.model_for(report)['tools'][0]
        self.assertEqual(tool['timing']['invocation_status'], 'NOT_RECORDED')
        self.assertIsNone(tool['timing']['tool_call_wall_ns'])
        self.assertIsNone(tool['dispatch_prelude'])
        for value in (BASE - 1, BASE + 1, True, str(BASE)):
            report['tools'][0]['invocation_ns'] = value
            tool = render.model_for(report)['tools'][0]
            self.assertEqual(tool['timing']['invocation_status'], 'INVALID_INVOCATION_BOUNDARY')
            self.assertIsNone(tool['timing']['dispatch_prelude_ns'])
            self.assertIsNone(tool['dispatch_prelude'])

    def test_zero_length_dispatch_is_known_without_creating_fake_elapsed(self):
        report = fixture()
        report['tools'][0]['invocation_ns'] = BASE
        tool = render.model_for(report)['tools'][0]
        self.assertEqual(tool['timing']['invocation_status'], 'RECORDED')
        self.assertEqual(tool['timing']['dispatch_prelude_ns'], 0)
        self.assertEqual(tool['dispatch_prelude']['t0'], tool['dispatch_prelude']['t1'])

    def test_unknown_state_is_never_converted_to_oncpu(self):
        value = fixture()
        value['threads'][0]['segments'][0]['state'] = 'NEW_UNSUPPORTED_STATE'
        result = render.model_for(value)['threads'][0]['segments'][0]
        self.assertEqual(result['state'], 'UNKNOWN')
        self.assertTrue(result['unsupported_state'])
        self.assertEqual(result['detail']['state'], 'NEW_UNSUPPORTED_STATE')
        value['threads'][0]['segments'][0]['state'] = {'bad': 'input'}
        self.assertEqual(render.model_for(value)['threads'][0]['segments'][0]['state'], 'UNKNOWN')

    def test_waking_is_a_distinct_delivery_interval_not_cpu_queue_or_unknown(self):
        report = fixture()
        report['threads'][0]['segments'][1].update(state='WAKING',
            reason='源WAKING至目标WAKEUP的递送／处理区间，尚未完成入队')
        html = render.render_report(report)
        segment = json.loads(script(html, 'timeline-model'))['threads'][0]['segments'][1]
        self.assertEqual(segment['state'], 'WAKING')
        self.assertFalse(segment['unsupported_state'])
        self.assertIn('唤醒递送/处理(源WAKING→目标WAKEUP，尚未完成入队)', html)
        self.assertIn("WAKING:'#b85b8c'", main_script(html))

    def test_script_injection_and_template_markers_are_only_data(self):
        value = fixture()
        text = '</script><img src=x onerror=alert(1)>& __TIMELINE_MODEL__ __REPORT_JSON__\u2028\u2029'
        value['threads'][0]['comm'] = text
        value['threads'][0]['segments'][0]['files'] = [{'path': text}]
        html = render.render_report(value)
        self.assertNotIn('<img src=x', html)
        self.assertNotIn('</script><img', html)
        self.assertEqual(json.loads(script(html, 'report-json')), value)
        self.assertEqual(json.loads(script(html, 'timeline-model'))['threads'][0]['comm'], text)

    def test_task_inheritance_uses_unique_agent_tool_not_time(self):
        value = render.model_for(fixture())
        self.assertEqual(value['threads'][0]['task_id'], 'task-A')
        value = fixture()
        value['threads'][0]['tool_call_id'] = 'other-tool'
        self.assertEqual(render.model_for(value)['threads'][0]['task_id'], '')

    def test_incomplete_calls_are_preserved_but_not_timed_by_guess(self):
        value = fixture()
        value['threads'][0]['calls'][0]['end_ns'] = None
        call = render.model_for(value)['threads'][0]['calls'][0]
        self.assertIsNone(call['t0'])
        self.assertIsNone(call['t1'])
        self.assertIsNone(call['detail']['end_ns'])
        self.assertEqual(call['timing_quality'], 'UNRESOLVED_OR_INCOMPLETE_NOT_GUESSED')

    def test_process_grouping_does_not_merge_reused_numeric_pid(self):
        value = fixture()
        original = value['threads'][0]
        original.update(end_ns=BASE + 400000000, segments=[])
        other = copy.deepcopy(original)
        other.update(key='11/second-instance', birth_ns=BASE + 500000000,
                     begin_ns=BASE + 500000000, end_ns=BASE + 1000000000)
        value['threads'].append(other)
        model = render.model_for(value)
        self.assertNotEqual(model['threads'][0]['process_key'], model['threads'][1]['process_key'])

    def test_unenrolled_leader_is_explicitly_unresolved(self):
        value = fixture()
        value['threads'][0]['tgid'] = 999
        model = render.model_for(value)['threads'][0]
        self.assertTrue(model['process_key'].startswith('UNRESOLVED/'))
        self.assertTrue(model['process_identity_quality'].startswith('UNRESOLVED'))

    def test_explicit_process_identity_is_used(self):
        value = fixture()
        value['threads'][0]['process_key'] = 'process-instance'
        self.assertEqual(render.model_for(value)['threads'][0]['process_key'], 'process-instance')

    def test_duplicate_thread_keys_are_rejected(self):
        value = fixture()
        value['threads'].append(copy.deepcopy(value['threads'][0]))
        with self.assertRaisesRegex(ValueError, 'unique'):
            render.render_report(value)

    def test_invalid_run_and_segment_intervals_are_rejected(self):
        for scope in ('run', 'segment'):
            value = fixture()
            target = value['run'] if scope == 'run' else value['threads'][0]['segments'][0]
            target['end_ns'] = target['begin_ns'] - 1
            with self.assertRaises(ValueError):
                render.render_report(value)

    def test_boolean_timestamps_and_zero_birth_are_rejected(self):
        value = fixture()
        value['run']['begin_ns'] = True
        with self.assertRaises(ValueError):
            render.render_report(value)
        value = fixture()
        value['threads'][0]['birth_ns'] = 0
        with self.assertRaises(ValueError):
            render.render_report(value)

    def test_legacy_flat_critical_path_is_visible_not_dropped(self):
        value = fixture()
        value['critical_path'] = {'status': 'PARTIAL', 'segments': value['threads'][0]['segments']}
        model = render.model_for(value)
        self.assertEqual(len(model['critical']), 1)
        self.assertEqual(model['critical'][0]['tool_call_id'], 'ALL_TOOLS')

    def test_runtime_return_is_a_separate_control_tail_not_unknown_or_oncpu(self):
        value = fixture()
        value['critical_path']['tools'][0]['segments'][-1]['state'] = 'RUNTIME_RETURN'
        html = render.render_report(value)
        part = json.loads(script(html, 'timeline-model'))['critical'][0]['segments'][-1]
        self.assertEqual(part['state'], 'RUNTIME_RETURN')
        self.assertFalse(part['unsupported_state'])
        self.assertIn('终态TASK_DEAD切出至控制面确认，非 CPU', html)
        self.assertIn('EXIT早期钩子不是终态', html)

    def test_newborn_creation_stage_is_not_unknown_or_cpu_queue_wait(self):
        value = fixture()
        value['threads'][0]['segments'][0]['state'] = 'NEWBORN'
        part = render.model_for(value)['threads'][0]['segments'][0]
        self.assertEqual(part['state'], 'NEWBORN')
        self.assertFalse(part['unsupported_state'])
        self.assertIn('已创建，尚未首次唤醒', render.render_report(value))

    @unittest.skipUnless((HERE / 'replay.py').exists(), 'replay component not installed')
    def test_actual_replay_schema_with_nonreturn_call_and_nested_read(self):
        with mock.patch.object(sys, 'path', [str(HERE)] + sys.path):
            import replay
        actor = {'tid': 10, 'tgid': 10, 'thread_birth_ns': 100, 'process_birth_ns': 100, 'comm': 'grep'}
        file = {'mount_id': 1, 'device': 2, 'inode': 3, 'generation': 4}
        entries = [
            ('SWITCH_OUT', 1, {'state': 'STOPPED'}), ('WAKEUP', 10, {}), ('SWITCH_IN', 20, {}),
            ('SYSCALL_ENTER', 30, {'syscall_call_id': 30, 'syscall_nr': 0, 'args': [3, 0, 4096]}),
            ('FILE_OBJECT', 31, {'syscall_call_id': 30, 'file': dict(file, path='/src/a.c', path_quality='KERNEL_D_PATH')}),
            ('SWITCH_OUT', 40, {'state': 'SLEEP_D', 'syscall_call_id': 30, 'kernel_stack': ['filemap_get_pages']}),
            ('WAKEUP', 80, {}), ('SWITCH_IN', 90, {}),
            ('FILE_READ', 99, {'syscall_call_id': 30, 'start_ns': BASE + 31, 'end_ns': BASE + 99,
                'returned_bytes': 16, 'requested_bytes': 4096, 'result': 16, 'file': file}),
            ('SYSCALL_EXIT', 100, {'syscall_call_id': 30, 'syscall_nr': 0, 'result': 16}),
            ('SYSCALL_ENTER', 110, {'syscall_call_id': 110, 'syscall_nr': 231, 'args': [0]}),
            ('EXIT', 998, {}), ('SWITCH_OUT', 999, {'state': 'SLEEP_D', 'prev_state': 0x80, 'preempt': False})]
        events = [{'schema_version': 1, 'cpu': 0, 'cpu_seq': i + 1, 'root_cgroup_id': 9,
            'caller_cgroup_id': 11, 'event': kind, 'timestamp_ns': BASE + timestamp, 'task': actor, **extra}
            for i, (kind, timestamp, extra) in enumerate(entries)]
        manifest = {'schema_version': 1, 'run_id': 'replay-run', 'boot_id': 'replay-boot',
            'begin_ns': BASE, 'end_ns': BASE + 1000, 'tools': [{'agent_id': 'agent-A',
                'task_id': 'search', 'tool_call_id': 'search-1', 'begin_ns': BASE + 10,
                'end_ns': BASE + 1000, 'cgroup_id': 11, 'root': {'tid': 10, 'birth_ns': 100}}]}
        report = replay.build_report(events, manifest, {})
        model = json.loads(script(render.render_report(report), 'timeline-model'))
        sleep = next(part for part in model['threads'][0]['segments'] if part['state'] == 'SLEEP' and part['detail'].get('syscall'))
        self.assertEqual(sleep['syscall_elapsed_ns'], 70)
        self.assertEqual(sleep['file_read_intervals'], [{'requested_bytes': 4096, 'returned_bytes': 16, 'elapsed_ns': 68}])
        self.assertIsNone(model['threads'][0]['calls'][-1]['t0'])
        self.assertEqual(model['threads'][0]['calls'][-1]['detail']['pairing'], 'LIFECYCLE_TERMINATED_NONRETURNING_CALL')
        self.assertEqual(model['critical'][0]['segments'][-1]['state'], 'RUNTIME_RETURN')

    def test_size_budget_never_truncates_download(self):
        with mock.patch.object(render, 'MAX_REPORT_BYTES', 100):
            with self.assertRaisesRegex(ValueError, '64 MiB'):
                render.render_report(fixture())

    def test_cli_writes_only_fresh_output_and_keeps_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'report.json', root / 'timeline.html'
            raw = json.dumps(fixture()).encode()
            source.write_bytes(raw)
            self.assertEqual(render.main(['--report', str(source), '--output', str(output)]), 0)
            before = output.read_bytes()
            with self.assertRaisesRegex(ValueError, 'fresh'):
                render.main(['--report', str(source), '--output', str(output)])
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual(source.read_bytes(), raw)

    def test_duplicate_json_keys_and_nonfinite_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'bad.json'
            for raw in ('{"run":1,"run":2}', '{"value":NaN}', '{"value":Infinity}'):
                source.write_text(raw)
                with self.assertRaises(ValueError):
                    render.read_report(source)

    def test_input_and_output_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source.json'
            source.write_text(json.dumps(fixture()))
            linked = root / 'linked.json'
            linked.symlink_to(source)
            with self.assertRaises(ValueError):
                render.read_report(linked)
            output = root / 'linked.html'
            output.symlink_to(root / 'not-created.html')
            with self.assertRaisesRegex(ValueError, 'fresh'):
                render.main(['--report', str(source), '--output', str(output)])

    @unittest.skipUnless(shutil.which('node'), 'Node optional syntax/interaction check unavailable')
    def test_javascript_parses_without_dependencies(self):
        html = render.render_report(fixture())
        result = subprocess.run(['node', '--check'], input=main_script(html), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("connect-src 'none'", html)
        self.assertNotRegex(html, r'<(?:script|link)\b[^>]*(?:src|href)="https?://')

    @unittest.skipUnless(shutil.which('node'), 'Node optional interaction check unavailable')
    def test_offline_click_hover_download_and_task_filter(self):
        result = run_node(render.render_report(fixture()), r'''
const c=document.getElementById('timeline'),event={clientX:760,clientY:143};
c.listeners.mousemove(event);c.listeners.click(event);document.getElementById('download').listeners.click();
document.getElementById('taskFilter').value='task-A';document.getElementById('apply').listeners.click();
''')
        self.assertIn('SLEEP', result['tip'])
        self.assertIn('read', result['tip'])
        self.assertIn('requested=64', result['tip'])
        details = json.loads(result['details'])
        self.assertEqual(details['state'], 'SLEEP')
        self.assertEqual(details['segment']['files'][0]['path'], '/tmp/a')
        self.assertEqual(details['overlapping_call_count'], 1)
        self.assertEqual(json.loads(result['download']['parts'][0]), fixture())
        self.assertEqual(result['linkClicks'], 1)
        self.assertIn('显示 1 / 筛选匹配 1', result['coverage'])

    @unittest.skipUnless(shutil.which('node'), 'Node optional dispatch interaction check unavailable')
    def test_dispatch_only_window_remains_visible_clickable_and_not_a_thread_state(self):
        report = fixture()
        report['tools'][0].update(invocation_ns=BASE + 100000000, begin_ns=BASE + 200000000)
        report['threads'] = []
        report['critical_path'] = {'status': 'NOT_ESTABLISHED', 'tools': []}
        result = run_node(render.render_report(report), r'''
document.getElementById('start').value='0.12';document.getElementById('end').value='0.18';
document.getElementById('apply').listeners.click();
const row=rows.find(value=>value.kind==='tool');
if(!row||row.hits.length!==1||row.hits[0].segment.state!=='RUNTIME_DISPATCH')throw new Error('dispatch-only tool missing or execution invented');
const h=row.hits[0],event={clientX:(h.x0+h.x1)/2,clientY:TOP+rows.indexOf(row)*ROW+10};
canvas.listeners.mousemove(event);canvas.listeners.click(event);
document.getElementById('download').listeners.click();
''')
        details = json.loads(result['details'])
        self.assertEqual(details['kind'], 'RUNTIME_DISPATCH_PRELUDE_NOT_WORKER_STATE')
        self.assertEqual(details['timing']['tool_call_wall_ns'], 900000000)
        self.assertEqual(details['timing']['execution_window_ns'], 800000000)
        self.assertEqual(details['timing']['dispatch_prelude_ns'], 100000000)
        self.assertIn('不是工作线程CPU或I/O', result['tip'])
        self.assertIn('完整调用墙钟=900000000 ns', result['toolTiming'])
        self.assertIn('执行窗口=800000000 ns', result['toolTiming'])
        self.assertIn('派发前奏=100000000 ns', result['toolTiming'])
        self.assertEqual(json.loads(result['download']['parts'][0]), report)

    @unittest.skipUnless(shutil.which('node'), 'Node optional zero-dispatch interaction check unavailable')
    def test_zero_dispatch_does_not_draw_one_pixel_fake_prelude(self):
        report = fixture()
        report['tools'][0]['invocation_ns'] = BASE
        result = run_node(render.render_report(report), r'''
const row=rows.find(value=>value.kind==='tool');
if(row.hits.some(value=>value.segment.state==='RUNTIME_DISPATCH'))throw new Error('zero dispatch rendered as interval');
''')
        self.assertIn('派发前奏=0 ns', result['toolTiming'])

    @unittest.skipUnless(shutil.which('node'), 'Node optional bounded-render check unavailable')
    def test_many_segments_are_bounded_but_full_json_is_not_cut(self):
        value = fixture()
        value['critical_path'] = {'status': 'NOT_ESTABLISHED', 'tools': []}
        value['threads'] = []
        for i in range(6):
            thread = copy.deepcopy(fixture()['threads'][0])
            thread.update(key='thread-' + str(i), tid=11 + i, tgid=11 + i,
                          segments=[{'begin_ns': BASE + n * 1000, 'end_ns': BASE + n * 1000 + 500,
                                     'state': 'ONCPU'} for n in range(5000)])
            value['threads'].append(thread)
        html = render.render_report(value)
        result = run_node(html, "document.getElementById('download').listeners.click();")
        self.assertIn('绘制区间 20000', result['coverage'])
        self.assertIn('省略区间 10001', result['coverage'])
        complete = json.loads(result['download']['parts'][0])
        self.assertEqual(sum(len(thread['segments']) for thread in complete['threads']), 30000)

    @unittest.skipUnless(shutil.which('node'), 'Node optional lane-bound check unavailable')
    def test_many_thread_groups_keep_canvas_height_bounded(self):
        value = fixture()
        value['critical_path'] = {'status': 'NOT_ESTABLISHED', 'tools': []}
        value['tools'], value['threads'] = [], []
        for i in range(300):
            tool = copy.deepcopy(fixture()['tools'][0])
            tool.update(agent_id='agent-' + str(i), tool_call_id='tool-' + str(i))
            thread = copy.deepcopy(fixture()['threads'][0])
            thread.update(key='thread-' + str(i), agent_id=tool['agent_id'], tool_call_id=tool['tool_call_id'],
                          tid=i + 1, tgid=i + 1, calls=[])
            value['tools'].append(tool)
            value['threads'].append(thread)
        result = run_node(render.render_report(value), "document.getElementById('maxThreads').value='256';document.getElementById('apply').listeners.click();")
        self.assertLessEqual(result['height'], 32767)
        self.assertIn('总计 300', result['coverage'])
        self.assertIn('泳道 112', result['coverage'])


if __name__ == '__main__':
    unittest.main()
