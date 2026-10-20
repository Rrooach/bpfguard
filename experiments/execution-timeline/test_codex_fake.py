#!/usr/bin/env python3
"""Optional real-Codex/local-fake-Responses protocol test; ZERO external API.

Set CODEX_TEST_BINARY and CODEX_TEST_CATALOG explicitly to enable. It uses a
new temporary CODEX_HOME, a loopback-only deterministic fixture server and one
real harmless shell command. No Observer coverage or model-success claim.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

from codex_client import CodexRPC, append_record, run_agent
from common import write_new
from codex_run import codex_command

FIXTURE_COMMAND="printf 'CODEX_FAKE_PROTOCOL_ONLY\\n' > codex-fake-proof.txt; cat codex-fake-proof.txt"


def fake_events(index, tool_name='observer_bash'):
    now=int(time.time()); response_id='resp_fake_'+str(index)
    if index==0:
        item={'type':'function_call','id':'fc_fake_1','call_id':'call_fake_1','name':tool_name,
              'arguments':json.dumps({'command':FIXTURE_COMMAND}),'status':'completed'}
    else:
        item={'type':'message','id':'msg_fake_final','status':'completed','role':'assistant',
              'content':[{'type':'output_text','text':'Fake provider protocol fixture completed. No real inference.','annotations':[]}]}
    response={'id':response_id,'object':'response','created_at':now,'status':'completed','model':'deepseek-flash',
              'output':[item],'usage':{'input_tokens':1,'output_tokens':1,'total_tokens':2}}
    events=[{'type':'response.created','response':{**response,'status':'in_progress','output':[],'usage':None}},
            {'type':'response.output_item.added','output_index':0,'item':{**item,'status':'in_progress',**({'arguments':''} if index==0 else {'content':[]})}}]
    if index==0:
        events += [{'type':'response.function_call_arguments.delta','item_id':item['id'],'output_index':0,'delta':item['arguments']},
                   {'type':'response.function_call_arguments.done','item_id':item['id'],'output_index':0,'arguments':item['arguments']}]
    else:
        part=item['content'][0]
        events += [{'type':'response.content_part.added','item_id':item['id'],'output_index':0,'content_index':0,'part':{**part,'text':''}},
                   {'type':'response.output_text.delta','item_id':item['id'],'output_index':0,'content_index':0,'delta':part['text']},
                   {'type':'response.output_text.done','item_id':item['id'],'output_index':0,'content_index':0,'text':part['text']},
                   {'type':'response.content_part.done','item_id':item['id'],'output_index':0,'content_index':0,'part':part}]
    events += [{'type':'response.output_item.done','output_index':0,'item':item},
               {'type':'response.completed','response':response}]
    return b''.join(('event: '+e['type']+'\ndata: '+json.dumps(e)+'\n\n').encode() for e in events)


class FakeResponses(BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.path=='/v1/responses'
        data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert data['model']=='deepseek-flash' and data.get('stream') is True
        assert self.headers.get('X-Benchmark-Task')=='codex-smoke-001'
        with self.server.fixture_lock:
            index=len(self.server.requests);self.server.requests.append(data)
            if getattr(self.server,'receipt_directory',None):
                append_record(self.server.receipt_directory/'requests.jsonl',{'mode':'FAKE_PROVIDER_NO_API','request_index':index,'body':data})
        tools=data.get('tools',[])
        names=[tool.get('name') for tool in tools if tool.get('type')=='function']
        matches=[name for name in names if name and 'observer_bash' in name]
        if len(matches)!=1 or index>1:
            self.send_error(400,'FAKE_ONLY_UNEXPECTED_TOOL_OR_MORE_THAN_TWO_REQUESTS');return
        body=fake_events(index,matches[0])
        self.send_response(200);self.send_header('Content-Type','text/event-stream')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);self.wfile.flush()
    def log_message(self,*args):
        pass


@unittest.skipUnless(os.environ.get('CODEX_TEST_BINARY') and os.environ.get('CODEX_TEST_CATALOG'),
                     'opt-in real Codex/local fake provider only')
class RealCodexFakeProviderTests(unittest.TestCase):
    def test_official_harness_chooses_dynamic_tool_then_finishes(self):
        with tempfile.TemporaryDirectory(prefix='observer-codex-fake-') as temp:
            root=Path(temp);home=root/'home';home.mkdir(mode=0o700)
            app=root/'app';app.mkdir();workspace=root/'workspace';workspace.mkdir()
            server=ThreadingHTTPServer(('127.0.0.1',0),FakeResponses);server.requests=[];server.fixture_lock=threading.Lock()
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
            args=SimpleNamespace(codex=Path(os.environ['CODEX_TEST_BINARY']).resolve(),
                broker_base_url='http://127.0.0.1:'+str(server.server_port)+'/v1',budget_label='codex-smoke-001',model='deepseek-flash')
            command,_=codex_command(args,Path(os.environ['CODEX_TEST_CATALOG']).resolve())
            err=(root/'codex.stderr').open('xb');raw=(root/'codex.stdout').open('xb')
            environment={'PATH':'/usr/local/bin:/usr/bin:/bin','CODEX_HOME':str(home),'OBSERVER_BROKER_TOKEN':'FAKE_PROVIDER_NO_API',
                         'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
            proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,env=environment,cwd=workspace)
            try:
                rpc=CodexRPC(proc.stdout.fileno(),proc.stdin.fileno(),app,'NO_KERNEL_COVERAGE_UNIT_TEST',raw)
                def execute(text,call_id,request_id):
                    actual=subprocess.run(['/bin/bash','--noprofile','--norc','-c',text],cwd=workspace,
                        env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True,timeout=10)
                    return {'exit_code':actual.returncode,'stdout':actual.stdout,'stderr':actual.stderr,'output_truncated':False,
                        'binding':{'tool_call_id':'synthetic-protocol-shell-1','root_pid':None,'begin_ns':None,'end_ns':None,
                        'scope':'PROTOCOL_ONLY_REAL_SHELL_NO_OBSERVER_CGROUP_IDENTITY_CLAIM'}}
                result=run_agent(rpc,'Run the requested harmless fixture command and finish.',workspace,execute,app,timeout=30)
                self.assertEqual(result['status'],'completed')
                self.assertEqual(len(result['function_bindings']),1)
                self.assertEqual((workspace/'codex-fake-proof.txt').read_text(),'CODEX_FAKE_PROTOCOL_ONLY\n')
                self.assertEqual(len(server.requests),2)
                self.assertTrue(any(i.get('type')=='function_call_output' for i in server.requests[1]['input']))
                print('REAL_CODEX_FAKE_PROVIDER_ZERO_PAID_PROTOCOL_PASS',flush=True)
            except BaseException:
                err.flush()
                print((root/'codex.stderr').read_text(errors='replace')[-12000:],flush=True)
                raise
            finally:
                proc.stdin.close()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
                proc.stdout.close();raw.close();err.close()

if __name__=='__main__':
    import sys
    if '--serve' in sys.argv:
        import argparse
        parser=argparse.ArgumentParser(description='LOOPBACK FAKE PROVIDER ONLY; NO EXTERNAL API')
        parser.add_argument('--serve',action='store_true');parser.add_argument('--port',required=True,type=int)
        parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
        args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
        server=ThreadingHTTPServer(('127.0.0.1',args.port),FakeResponses)
        server.requests=[];server.fixture_lock=threading.Lock();server.receipt_directory=args.output
        write_new(args.output/'ready.json',{'mode':'FAKE_PROVIDER_NO_API','port':args.port,'external_network_or_model_calls':False})
        print(json.dumps({'status':'READY','mode':'FAKE_PROVIDER_NO_API','port':args.port}),flush=True)
        server.serve_forever()
    else:
        unittest.main()
