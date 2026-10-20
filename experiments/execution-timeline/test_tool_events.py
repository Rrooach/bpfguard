#!/usr/bin/env python3
"""Application tool lifecycle tests; no provider, process or kernel access."""
import json
from pathlib import Path
import tempfile
import unittest

from codex_tool_adapter import CodexReportedToolAdapter, verify_codex_tool_sources
from tool_events import ToolEventLedger, execution_status, read_events, redact_arguments, replay_tool_events


class ToolEventTests(unittest.TestCase):
    def test_process_tool_has_human_lifecycle_and_optional_kernel_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'events.jsonl'
            ledger = ToolEventLedger(path, agent_id='agent-A', task_id='task-A')
            request = ledger.requested(call_id='call-A', tool_name='search_code', thread_id='thread-A',
                turn_id='turn-A', rpc_request_id=7, arguments={'query':'needle','token':'secret'},
                arguments_capture='STRUCTURED_REDACTED')
            dispatch = ledger.dispatched(request, execution_kind='STOPPED_PROCESS_GATE')
            complete = ledger.completed(request, dispatch, status='SUCCEEDED', exit_code=0,
                binding={'tool_call_id':'linux-A','begin_ns':dispatch['occurred_ns']+10,
                    'end_ns':dispatch['occurred_ns']+30,'root':{'tid':12},'cgroup_id':44,
                    'stdout_artifact':'app/tool.stdout','stderr_artifact':'app/tool.stderr'},
                output_truncated=False)
            ledger.delivered(request, complete)
            calls = replay_tool_events(read_events(path))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]['status'], 'SUCCEEDED')
            self.assertEqual(calls[0]['arguments']['token'], '[REDACTED]')
            self.assertEqual(calls[0]['execution_tool_call_id'], 'linux-A')
            self.assertEqual(calls[0]['execution_duration_ns'], 20)
            self.assertEqual(calls[0]['request_to_execution_ns'], dispatch['occurred_ns']+10-request['occurred_ns'])
            self.assertEqual(calls[0]['semantic_result'], 'NOT_VERIFIED_BY_TOOL_TRANSPORT')

    def test_in_process_tool_does_not_invent_pid_cgroup_or_execution_time(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'events.jsonl'
            ledger = ToolEventLedger(path, agent_id='agent', task_id='task')
            request = ledger.requested(call_id='call', tool_name='mcp_search', thread_id='thread',
                turn_id='turn', rpc_request_id='rpc', arguments={'query':'x'},
                arguments_capture='STRUCTURED_REDACTED')
            dispatch = ledger.dispatched(request, execution_kind='IN_PROCESS_OR_REMOTE')
            complete = ledger.completed(request, dispatch, status='FAILED', failure=None,
                result_summary={'error':'not found','token':'do-not-store'})
            ledger.delivered(request, complete)
            call = replay_tool_events(read_events(path))[0]
            self.assertIsNone(call['root']); self.assertIsNone(call['cgroup_id'])
            self.assertIsNone(call['execution_duration_ns'])
            self.assertEqual(call['timing_quality'], 'APPLICATION_DISPATCH_ONLY')
            self.assertEqual(call['result_summary'], {'error':'not found','token':'[REDACTED]'})

    def test_transition_or_identity_tampering_is_rejected(self):
        row = {'schema_version':1,'sequence':1,'event':'TOOL_DISPATCHED','clock':'CLOCK_MONOTONIC',
            'occurred_ns':1,'recorded_ns':1,'agent_id':'a','task_id':'t','call_id':'c',
            'tool_name':'x','thread_id':'th','turn_id':'tu','rpc_request_id':1}
        with self.assertRaisesRegex(ValueError, 'transition'):
            replay_tool_events([row])

    def test_secret_fields_are_redacted_and_original_digest_is_stable(self):
        first, digest = redact_arguments({'query':'x','nested':{'Authorization':'bearer'}})
        second, digest2 = redact_arguments({'nested':{'Authorization':'bearer'},'query':'x'})
        self.assertEqual(first['nested']['Authorization'], '[REDACTED]')
        self.assertEqual((first, digest), (second, digest2))
        with self.assertRaises(ValueError):
            redact_arguments({'value':float('nan')})

    def test_terminal_status_does_not_claim_task_correctness(self):
        self.assertEqual(execution_status(0), 'SUCCEEDED')
        self.assertEqual(execution_status(3), 'FAILED')
        self.assertEqual(execution_status(124, {'error':'TimeoutError: x'}), 'TIMED_OUT')
        self.assertEqual(execution_status(None, failure=ConnectionError('x')), 'TRANSPORT_ERROR')

    def test_codex_reported_mcp_call_replays_against_raw_rpc_without_linux_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'events.jsonl'
            ledger = ToolEventLedger(path, agent_id='agent', task_id='task')
            rows = []
            def emit(method, *args, **kwargs):
                row = getattr(ledger, method)(*args, **kwargs); rows.append(row); return row
            adapter = CodexReportedToolAdapter(emit, thread_id='thread', turn_id='turn')
            started = {'method':'item/started','params':{'threadId':'thread','turnId':'turn','startedAtMs':10,
                'item':{'type':'mcpToolCall','id':'mcp-1','server':'docs','tool':'search',
                    'status':'inProgress','arguments':{'query':'x','api_key':'secret'},'result':None,
                    'error':None,'durationMs':None}}}
            completed = {'method':'item/completed','params':{'threadId':'thread','turnId':'turn','completedAtMs':20,
                'item':{'type':'mcpToolCall','id':'mcp-1','server':'docs','tool':'search',
                    'status':'completed','arguments':{'query':'x','api_key':'secret'},
                    'result':{'content':[]},'error':None,'durationMs':7}}}
            adapter.handle('item/started', started['params'], started, 100)
            adapter.handle('item/completed', completed['params'], completed, 200)
            calls = replay_tool_events(rows)
            self.assertEqual(calls[0]['arguments']['arguments']['api_key'], '[REDACTED]')
            self.assertEqual(calls[0]['execution_binding'], 'NOT_ESTABLISHED')
            rpc = [
                {'direction':'CODEX_TO_CLIENT','receipt_ns':90,'message':started},
                {'direction':'CODEX_TO_CLIENT','receipt_ns':190,'message':completed},
            ]
            receipt = verify_codex_tool_sources(rpc, rows)
            self.assertEqual(receipt['status'], 'RAW_RPC_TOOL_EVENTS_REPLAYED')
            self.assertEqual(receipt['source_messages'], 2)

    def test_codex_source_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'events.jsonl'
            ledger = ToolEventLedger(path, agent_id='agent', task_id='task')
            rows=[]
            def emit(method,*args,**kwargs):
                row=getattr(ledger,method)(*args,**kwargs);rows.append(row);return row
            adapter=CodexReportedToolAdapter(emit,thread_id='thread',turn_id='turn')
            start={'method':'item/started','params':{'threadId':'thread','turnId':'turn','item':{
                'type':'webSearch','id':'web-1','query':'x','action':None}}}
            end={'method':'item/completed','params':{'threadId':'thread','turnId':'turn','item':{
                'type':'webSearch','id':'web-1','query':'x','action':None}}}
            adapter.handle('item/started',start['params'],start,100)
            adapter.handle('item/completed',end['params'],end,200)
            rpc=[{'direction':'CODEX_TO_CLIENT','receipt_ns':90,'message':start},
                {'direction':'CODEX_TO_CLIENT','receipt_ns':190,'message':end}]
            rows[2]['source_event']['message_sha256']='0'*64
            with self.assertRaisesRegex(ValueError,'absent'):
                verify_codex_tool_sources(rpc,rows)

    def test_codex_ledger_cannot_change_raw_rpc_tool_arguments(self):
        with tempfile.TemporaryDirectory() as temp:
            ledger=ToolEventLedger(Path(temp)/'events.jsonl',agent_id='agent',task_id='task')
            rows=[]
            def emit(method,*args,**kwargs):
                row=getattr(ledger,method)(*args,**kwargs);rows.append(row);return row
            adapter=CodexReportedToolAdapter(emit,thread_id='thread',turn_id='turn')
            start={'method':'item/started','params':{'threadId':'thread','turnId':'turn','item':{
                'type':'webSearch','id':'web-1','query':'original','action':None}}}
            end={'method':'item/completed','params':{'threadId':'thread','turnId':'turn','item':{
                'type':'webSearch','id':'web-1','query':'original','action':None}}}
            adapter.handle('item/started',start['params'],start,100)
            adapter.handle('item/completed',end['params'],end,200)
            rpc=[{'direction':'CODEX_TO_CLIENT','receipt_ns':90,'message':start},
                {'direction':'CODEX_TO_CLIENT','receipt_ns':190,'message':end}]
            rows[0]['arguments']['query']='rewritten'
            rows[0]['arguments_sha256']=redact_arguments(rows[0]['arguments'])[1]
            with self.assertRaisesRegex(ValueError,'arguments differ'):
                verify_codex_tool_sources(rpc,rows)

    def test_duplicate_non_tool_rpc_notifications_do_not_make_tool_source_ambiguous(self):
        with tempfile.TemporaryDirectory() as temp:
            ledger=ToolEventLedger(Path(temp)/'events.jsonl',agent_id='agent',task_id='task')
            rows=[]
            def emit(method,*args,**kwargs):
                row=getattr(ledger,method)(*args,**kwargs);rows.append(row);return row
            adapter=CodexReportedToolAdapter(emit,thread_id='thread',turn_id='turn')
            start={'method':'item/started','params':{'threadId':'thread','turnId':'turn','item':{
                'type':'webSearch','id':'web-1','query':'original','action':None}}}
            end={'method':'item/completed','params':{'threadId':'thread','turnId':'turn','item':{
                'type':'webSearch','id':'web-1','query':'original','action':None}}}
            repeated={'method':'item/agentMessage/delta','params':{'delta':' '}}
            adapter.handle('item/started',start['params'],start,100)
            adapter.handle('item/completed',end['params'],end,200)
            rpc=[{'direction':'CODEX_TO_CLIENT','receipt_ns':80,'message':repeated},
                {'direction':'CODEX_TO_CLIENT','receipt_ns':81,'message':repeated},
                {'direction':'CODEX_TO_CLIENT','receipt_ns':90,'message':start},
                {'direction':'CODEX_TO_CLIENT','receipt_ns':190,'message':end}]
            self.assertEqual(verify_codex_tool_sources(rpc,rows)['source_messages'],2)

    def test_duplicate_tool_rpc_source_remains_ambiguous(self):
        start={'method':'item/started','params':{'threadId':'thread','turnId':'turn','item':{
            'type':'webSearch','id':'web-1','query':'x','action':None}}}
        rpc=[{'direction':'CODEX_TO_CLIENT','receipt_ns':90,'message':start},
            {'direction':'CODEX_TO_CLIENT','receipt_ns':91,'message':start}]
        with self.assertRaisesRegex(ValueError,'ambiguous duplicate'):
            verify_codex_tool_sources(rpc,[])


if __name__ == '__main__':
    unittest.main()
