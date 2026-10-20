#!/usr/bin/env python3
"""Zero-paid regression for the actual Bun tool that exposed skipped dispatch.

Runs the real Harbor Docker task and official evaluator, but the deliberately
fake local provider submits one fixed command. This is NOT a model score.
Requires the preserved smoke harness from attempt 001 as an explicit input.
"""
import argparse
import hashlib
from http.server import ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
import time

COMMAND = ('cd /app && bun run release 2>&1 | tail -5; ls dist; '
           'head -c 600 dist/client-entry.js; echo; head -c 400 dist/client-entry.js.map; '
           'echo; cat dist/release-manifest.json | head -30')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--preserved-smoke-harness',required=True,type=Path)
    p.add_argument('--plan',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--tools-directory',required=True,type=Path)
    p.add_argument('--runtime',required=True,type=Path)
    args=p.parse_args()
    args.tools_directory.mkdir(mode=0o700,exist_ok=False)
    spec=importlib.util.spec_from_file_location('preserved_no_api_smoke',args.preserved_smoke_harness)
    old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    sys.path.insert(0,str(args.runtime))
    old.TOOLS=args.tools_directory;old.TOKEN=args.tools_directory/'fake-client-token'
    old.TOKEN.write_text('FAKE_LOCAL_TOKEN_NOT_AN_API_KEY\n');old.TOKEN.chmod(0o600)
    class ExactBun(old.Fake):
        def do_POST(self):
            label=self.headers.get('X-Benchmark-Task','');rid=self.headers.get('X-Request-ID','')
            assert self.path=='/v1/chat/completions' and label=='model-terminal-c2-00'
            assert self.headers.get('Authorization')=='Bearer '+old.TOKEN.read_text().strip()
            raw=self.rfile.read(int(self.headers['Content-Length']));body=json.loads(raw)
            assert body['model']=='deepseek-flash' and body['max_tokens']==1024
            with self.server.guard:
                assert rid not in self.server.seen;self.server.seen.add(rid)
            assert rid in (label+'-step-0',label+'-step-1')
            function=({'name':'bash','arguments':json.dumps({'command':COMMAND})} if rid.endswith('-step-0')
                      else {'name':'finish','arguments':'{}'})
            response={'model':'FAKE_PROVIDER_NO_API','choices':[{'message':{'role':'assistant','content':None,
                'tool_calls':[{'id':rid+'-function','type':'function','function':function}]},'finish_reason':'tool_calls'}],
                'usage':{'prompt_tokens':10,'completion_tokens':20},'validation_only':'FAKE_PROVIDER_NO_API'}
            old.record(old.TOOLS/'fake-server-requests.jsonl',{'scope':'FAKE_PROVIDER_NO_API_EXACT_BUN_REGRESSION',
                'request_id':rid,'request_sha256':hashlib.sha256(raw).hexdigest(),'external_api_calls':0,
                'monotonic_ns':time.monotonic_ns(),'boot_id':old.BOOT})
            value=json.dumps(response).encode();self.send_response(200)
            self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(value)))
            self.end_headers();self.wfile.write(value)
    server=ThreadingHTTPServer(('127.0.0.1',10092),ExactBun)
    server.guard,server.seen=threading.Lock(),set()
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    old.write_new(old.TOOLS/'fake-server-ready.json',{'scope':'FAKE_PROVIDER_NO_API_EXACT_BUN_REGRESSION',
        'external_api_calls':0,'pid':os.getpid(),'boot_id':old.BOOT,'exact_command':COMMAND,
        'preserved_harness_sha256':hashlib.sha256(args.preserved_smoke_harness.read_bytes()).hexdigest()})
    try:return old.run(args)
    finally:server.shutdown();server.server_close();thread.join(timeout=5)


if __name__=='__main__':
    raise SystemExit(main())
