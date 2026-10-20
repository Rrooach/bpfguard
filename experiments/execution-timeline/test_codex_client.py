#!/usr/bin/env python3
"""Synthetic-only transport tests: no provider/API/BPF/cgroup operations."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from codex_client import CodexRPC, run_agent, strict_object, validate_tool
from tool_events import read_events, replay_tool_events


def tool_params(**changes):
    return {"threadId": "thread-1", "turnId": "turn-1", "callId": "call-1",
            "tool": "observer_bash", "arguments": {"command": "printf hello"}, **changes}


class ScriptedRPC:
    def __init__(self, messages):
        self.messages, self.requests, self.answers = list(messages), [], []
    def request(self, method, params, timeout=60):
        self.requests.append((method, params))
        return {"thread": {"id": "thread-1"}} if method == "thread/start" else {"turn": {"id": "turn-1"}} if method == "turn/start" else {}
    def send(self, value):
        self.requests.append((value["method"], value.get("params")))
    def receive(self, timeout):
        if not self.messages:
            raise EOFError("synthetic end")
        return self.messages.pop(0)
    def respond(self, request_id, result):
        self.answers.append((request_id, result))


def complete(status="completed", **params):
    return {"method": "turn/completed", "params": {"threadId": "thread-1", "turn": {"id": "turn-1", "status": status}, **params}}


def builtin_item(kind, status='inProgress'):
    common = {'type':kind, 'id':'builtin-'+kind}
    if kind == 'commandExecution':
        return {**common, 'command':'printf hello', 'cwd':'/workspace', 'processId':'pty-1',
            'source':'agent', 'status':status, 'commandActions':[], 'aggregatedOutput':'hello' if status!='inProgress' else None,
            'exitCode':0 if status!='inProgress' else None, 'durationMs':12 if status!='inProgress' else None}
    if kind == 'fileChange':
        return {**common, 'changes':[{'path':'/workspace/a','kind':'add','diff':'secret omitted by adapter'}], 'status':status}
    if kind == 'mcpToolCall':
        return {**common, 'server':'docs', 'tool':'search', 'status':status, 'arguments':{'query':'needle','token':'secret'},
            'result':{'content':[]} if status!='inProgress' else None, 'error':None,
            'durationMs':8 if status!='inProgress' else None}
    if kind == 'collabAgentToolCall':
        return {**common, 'tool':'spawnAgent', 'status':status, 'senderThreadId':'thread-1',
            'receiverThreadIds':['child-1'], 'prompt':'private prompt', 'model':None,
            'reasoningEffort':None, 'agentsStates':{}}
    if kind == 'webSearch':
        return {**common, 'query':'observer semantics', 'action':{'type':'search','query':'observer semantics'}}
    if kind == 'imageView':
        return {**common, 'path':'/workspace/image.png'}
    if kind == 'imageGeneration':
        return {**common, 'status':status, 'revisedPrompt':'draw a graph',
            'result':'result' if status!='inProgress' else '', 'savedPath':'/workspace/result.png'}
    if kind == 'sleep':
        return {**common, 'durationMs':12}
    raise AssertionError(kind)


class ToolBindingTests(unittest.TestCase):
    def test_explicit_request_is_linked_to_executor_root_not_time(self):
        with tempfile.TemporaryDirectory() as temp:
            rpc=ScriptedRPC([{"id": "server-7", "method": "item/tool/call", "params": tool_params()}, complete()])
            calls=[]
            def execute(command, call_id, request_id):
                calls.append((command,call_id,request_id))
                return {"exit_code": 0,"stdout":"hello","stderr":"","output_truncated":False,
                        "binding":{"tool_call_id":"shell-1","root_pid":123,"root":{"tid":123,"start_ticks":777},"begin_ns":1,"end_ns":2}}
            result=run_agent(rpc,"public fixture",Path(temp),execute,Path(temp),budget_label="task-registered")
            self.assertEqual(result["budget_label"],"task-registered")
            self.assertEqual(calls,[("printf hello","call-1","server-7")])
            self.assertEqual(result['function_bindings'][0]['root_pid'],123)
            self.assertEqual(result['steps'][0]['kind'],'TOOL_CALL')
            self.assertEqual(rpc.answers[0][0],'server-7')
            self.assertTrue(rpc.answers[0][1]['success'])
            self.assertIn('OFFICIAL_CODEX',result['agent_loop'])
            self.assertIsNone(result['paid_request_count'])
            self.assertTrue((Path(temp)/'steps.csv').exists())
            events=read_events(Path(temp)/'tool-events.jsonl')
            self.assertEqual([row['event'] for row in events],
                ['TOOL_REQUESTED','TOOL_DISPATCHED','TOOL_COMPLETED','TOOL_RESULT_DELIVERED'])
            self.assertEqual(replay_tool_events(events),result['tool_calls'])
            self.assertEqual(result['tool_calls'][0]['tool_name'],'observer_bash')
            self.assertEqual(result['tool_calls'][0]['status'],'SUCCEEDED')
            self.assertEqual(result['tool_calls'][0]['semantic_result'],'NOT_VERIFIED_BY_TOOL_TRANSPORT')

    def test_scope_name_argument_and_duplicate_rejections(self):
        bad=[{'threadId':'other'},{'turnId':'other'},{'tool':'exec_command'},{'namespace':'functions'},
             {'callId':''},{'callId':True},{'arguments':{'command':['echo','x']}},
             {'arguments':{'command':'echo x','timeout':10}},{'arguments':{'command':'\0'}},
             {'arguments':{'command':'x'*8193}}]
        for changes in bad:
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                validate_tool(tool_params(**changes),'thread-1','turn-1',set())
        seen=set();validate_tool(tool_params(),'thread-1','turn-1',seen)
        with self.assertRaises(ValueError):validate_tool(tool_params(),'thread-1','turn-1',seen)

    def test_explicit_terminal_v2_command_bound_leaves_old_default_unchanged(self):
        long = tool_params(arguments={'command': 'x' * 32768})
        with self.assertRaises(ValueError):validate_tool(long,'thread-1','turn-1',set())
        self.assertEqual(len(validate_tool(long,'thread-1','turn-1',set(),max_command_bytes=32768)),32768)
        oversized=tool_params(arguments={'command':'x'*32769})
        with self.assertRaises(ValueError):validate_tool(oversized,'thread-1','turn-1',set(),max_command_bytes=32768)
        multibyte=tool_params(arguments={'command':'中'*10923})
        with self.assertRaises(ValueError):validate_tool(multibyte,'thread-1','turn-1',set(),max_command_bytes=32768)

    def test_builtin_tools_are_recorded_as_application_reported_not_linux_bound(self):
        for kind in ('commandExecution','fileChange','mcpToolCall','collabAgentToolCall','webSearch','imageView','imageGeneration','sleep'):
            with tempfile.TemporaryDirectory() as temp,self.subTest(kind=kind):
                started={'method':'item/started','params':{'threadId':'thread-1','turnId':'turn-1',
                    'startedAtMs':1000,'item':builtin_item(kind)}}
                finished={'method':'item/completed','params':{'threadId':'thread-1','turnId':'turn-1',
                    'completedAtMs':1012,'item':builtin_item(kind,'completed')}}
                rpc=ScriptedRPC([started,finished,complete()])
                result=run_agent(rpc,'fixture',Path(temp),lambda *a: self.fail('unexpected execution'),Path(temp))
                self.assertEqual(len(result['tool_calls']),1)
                call=result['tool_calls'][0]
                self.assertEqual(call['application_evidence'],'CODEX_REPORTED_TOOL_CALL')
                self.assertEqual(call['execution_binding'],'NOT_ESTABLISHED')
                self.assertEqual(call['linux_effect_evidence'],'NOT_BOUND_TO_LINUX_EXECUTION')
                self.assertEqual(result['steps'][0]['kind'],'APPLICATION_TOOL_CALL')
                if kind == 'mcpToolCall':
                    self.assertEqual(call['arguments']['arguments']['token'],'[REDACTED]')

    def test_malformed_builtin_item_is_fatal_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            rpc=ScriptedRPC([{'method':'item/started','params':{'threadId':'thread-1','turnId':'turn-1',
                'item':{'type':'mcpToolCall','id':'mcp-1'}}}])
            with self.assertRaisesRegex(ValueError,'server/tool'):
                run_agent(rpc,'fixture',Path(temp),lambda *a: self.fail('unexpected execution'),Path(temp))

    def test_unknown_server_request_never_executes(self):
        with tempfile.TemporaryDirectory() as temp:
            rpc=ScriptedRPC([{'id':1,'method':'item/commandExecution/requestApproval','params':{}}])
            with self.assertRaises(ValueError):run_agent(rpc,'fixture',Path(temp),lambda *a: self.fail(),Path(temp))

    def test_failed_turn_is_not_retried_or_counted_as_success(self):
        with tempfile.TemporaryDirectory() as temp:
            rpc=ScriptedRPC([{'method':'error','params':{'error':{'message':'synthetic budget denied'}}},complete('failed')])
            result=run_agent(rpc,'fixture',Path(temp),lambda *a: self.fail(),Path(temp))
            self.assertEqual(result['status'],'failed');self.assertEqual(len(result['errors']),1)
            self.assertEqual([m for m,p in rpc.requests].count('turn/start'),1)

    def test_agent_text_is_not_promoted_to_executed_command(self):
        with tempfile.TemporaryDirectory() as temp:
            rpc=ScriptedRPC([{'method':'item/completed','params':{'threadId':'thread-1','turnId':'turn-1',
                'item':{'type':'agentMessage','id':'msg-1','text':'I ran echo; synthetic claim only'}}},complete()])
            result=run_agent(rpc,'fixture',Path(temp),lambda *a: self.fail(),Path(temp))
            self.assertEqual(result['function_bindings'],[])
            self.assertEqual(result['steps'][0]['kind'],'AGENT_MESSAGE')

    def test_duplicate_or_wrong_turn_finalization_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            rpc=ScriptedRPC([complete(threadId='different')])
            with self.assertRaises(ValueError):run_agent(rpc,'fixture',Path(temp),lambda *a:None,Path(temp))

    def test_tool_limit_request_is_recorded_and_replied_without_linux_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            first={"id":"server-1","method":"item/tool/call","params":tool_params(callId="call-1")}
            second={"id":"server-2","method":"item/tool/call","params":tool_params(callId="call-2")}
            rpc=ScriptedRPC([first,second]); executed=[]
            def execute(command, call_id, request_id):
                executed.append(call_id)
                return {"exit_code":0,"stdout":"","stderr":"","output_truncated":False,
                    "binding":{"tool_call_id":"shell-1","root":{"tid":1,"start_ticks":1},
                               "cgroup_id":2,"begin_ns":1,"end_ns":2}}
            with self.assertRaisesRegex(RuntimeError,'tool call limit'):
                run_agent(rpc,'fixture',Path(temp),execute,Path(temp),max_calls=1)
            self.assertEqual(executed,['call-1'])
            calls=replay_tool_events(read_events(Path(temp)/'tool-events.jsonl'),require_delivered=True)
            self.assertEqual(len(calls),2)
            self.assertEqual(calls[1]['status'],'FAILED')
            self.assertEqual(calls[1]['execution_binding'],'NOT_ESTABLISHED')
            self.assertEqual(rpc.answers[-1][0],'server-2')
            self.assertFalse(rpc.answers[-1][1]['success'])


class TransportTests(unittest.TestCase):
    def test_strict_json_rejects_duplicate_nonfinite_nonobject(self):
        for raw in ('{"id":1,"id":2}','{"id":NaN}','[]','null'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):strict_object(raw)

    def with_rpc(self, root, rows):
        read_fd,write_fd=os.pipe();read_client,write_client=os.pipe()
        os.write(write_fd,b''.join((json.dumps(r)+'\n').encode() for r in rows));os.close(write_fd)
        rpc=CodexRPC(read_fd,write_client,root,'synthetic-boot',io.BytesIO())
        self.addCleanup(os.close,read_fd);self.addCleanup(os.close,read_client)
        self.addCleanup(lambda: rpc.close_input())
        return rpc,read_client

    def test_notification_and_request_before_client_response_are_queued(self):
        with tempfile.TemporaryDirectory() as temp:
            rpc,read_client=self.with_rpc(Path(temp),[{'method':'thread/started','params':{}},
                {'id':'server-call','method':'item/tool/call','params':tool_params()}, {'id':1,'result':{'ok':True}}])
            self.assertEqual(rpc.request('initialize',{}),{'ok':True})
            self.assertEqual(rpc.receive(1)['method'],'thread/started')
            self.assertEqual(rpc.receive(1)['id'],'server-call')
            rpc.respond('server-call',{'success':True})
            with self.assertRaises(ValueError):rpc.respond('server-call',{})
            log=[json.loads(line) for line in (Path(temp)/'rpc.jsonl').read_text().splitlines()]
            self.assertTrue(all(r['boot_id']=='synthetic-boot' for r in log))
            self.assertTrue(all('NOT_KERNEL' in r['timing_scope'] for r in log))

    def test_wrong_response_id_is_fatal_without_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            rpc,_=self.with_rpc(Path(temp),[{'id':2,'result':{}}])
            with self.assertRaises(ValueError):rpc.request('initialize',{})
            self.assertEqual(rpc.next_id,2)

    def test_duplicate_server_request_id_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            row={'id':'same','method':'item/tool/call','params':tool_params()}
            rpc,_=self.with_rpc(Path(temp),[row,row])
            rpc.receive(1)
            with self.assertRaises(ValueError):rpc.receive(1)

if __name__=='__main__':unittest.main()
