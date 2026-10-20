#!/usr/bin/env python3
"""Real Chromium checks for the live/comparison/replay distinction and drilldown."""
import argparse
import json
from pathlib import Path
import subprocess

from common import digest,write_new,proc_identity
from validate_profile_ui_browser import installed_browser_paths


CHECK=r'''
const assert=require('node:assert/strict');let data='';process.stdin.on('data',x=>data+=x);process.stdin.on('end',()=>{(async()=>{
const cfg=JSON.parse(data),{chromium}=require(cfg.module),browser=await chromium.launch({executablePath:cfg.browser,headless:true,args:['--no-sandbox']});
try{const page=await browser.newPage({viewport:{width:1480,height:1100}}),errors=[];page.on('pageerror',e=>errors.push(String(e)));await page.goto(cfg.url,{waitUntil:'networkidle'});
assert.equal(await page.locator('[role=tab]').count(),3);const live=page.frameLocator('#view');await live.locator('#native-syscalls tr').first().waitFor();assert((await live.locator('main').innerText()).includes('Agent 本轮结果：completed'));
await page.locator('#tab-compare').click();await page.waitForFunction(()=>document.querySelector('#view').getAttribute('src')==='compare/index.html');const compare=page.frameLocator('#view');await compare.locator('.iprof').waitFor();assert((await compare.locator('main').innerText()).includes('不提供“提速百分比”'));assert((await compare.locator('main').innerText()).includes('failed'));assert((await compare.locator('main').innerText()).includes('completed'));
await page.locator('#tab-replay').click();const replay=page.frameLocator('#view');await replay.locator('#calls tr').first().waitFor();assert((await page.locator('#context').innerText()).includes('0 次付费 API'));assert((await replay.locator('main').innerText()).includes('不是原始 live004'));
const frame=page.frames().find(f=>f.url().endsWith('/replay/index.html'));assert(frame);const summary=await frame.evaluate(async()=>await(await fetch('summary.json')).json()),scope=await frame.evaluate(async()=>await(await fetch('scope.json')).json());
assert.equal(summary.total_syscalls,summary.correlated_syscalls+summary.unassigned_syscalls);assert.equal(summary.paid_request_count,0);assert.equal(summary.slowdown_claim_allowed,false);assert.equal(scope.core_syscall_count_increment,0);assert.equal(summary.correlated_syscalls,scope.correlated_syscall_references);
const payload=await replay.locator('.iprof [data-role=payload]').first().evaluate(n=>JSON.parse(n.textContent)),view=payload.views.find(v=>v.name==='syscall_count');assert.equal(view.total,summary.total_syscalls);assert(view.nodes.some(n=>n.kind==='tool'));assert(view.nodes.some(n=>n.label.includes('未归属')));
const runtimeCpu=payload.views.find(v=>v.name==='oncpu_ms');assert(runtimeCpu&&runtimeCpu.total>0);assert(!runtimeCpu.nodes.some(n=>n.kind==='tool'),'whole runtime CPU must never be claimed by individual tools');
const actual=[];for(const tool of summary.tools){await replay.locator('#tool-scope').selectOption(tool.call_id);await frame.waitForFunction(id=>document.querySelector('#calls').dataset.scope===id,tool.call_id);const rows=await replay.locator('#calls tr').count();assert.equal(rows,Math.min(200,tool.syscall_count));const refs=await replay.locator('#calls tr td:last-child a').evaluateAll(nodes=>nodes.map(n=>'report'+new URL(n.href).hash));const expected=scope.calls.find(x=>x.call_id===tool.call_id);const allowed=new Set(expected.thread_ranges.flatMap(t=>t.call_indices.map(ci=>t.thread_ref+'/calls/'+ci)));assert(refs.every(ref=>allowed.has(ref)));actual.push({call_id:tool.call_id,scope_status:tool.scope_status,syscalls:tool.syscall_count,first_page_rows:rows,raw_refs_are_in_verified_scope:true});}
const first=summary.tools.find(t=>t.syscall_count>200);await replay.locator('#tool-scope').selectOption(first.call_id);await frame.waitForFunction(id=>document.querySelector('#calls').dataset.scope===id,first.call_id);const before=await replay.locator('#calls tr td:last-child a').first().getAttribute('href');await replay.locator('#next').click();await frame.waitForFunction(()=>document.querySelector('#calls').dataset.page==='1');const after=await replay.locator('#calls tr td:last-child a').first().getAttribute('href');assert.notEqual(before,after);assert((await replay.locator('#page-status').innerText()).includes('2/'));
const paths=await replay.locator('#calls tr td:nth-child(7)').allTextContents();assert(paths.some(p=>p&&p!=='未采集'),'real selected tool page must expose file objects');
const boundTools=summary.tools.filter(t=>t.syscall_count>0);assert(boundTools.length>=2);await frame.evaluate(({first,second})=>{window.__testOriginalFetch=window.fetch;window.fetch=async(...args)=>{const response=await window.__testOriginalFetch(...args);if(String(args[0]).includes('pages/tool-0-'))await new Promise(resolve=>setTimeout(resolve,250));return response};const select=document.querySelector('#tool-scope');select.value=first;select.dispatchEvent(new Event('change'));select.value=second;select.dispatchEvent(new Event('change'));},{first:boundTools[0].call_id,second:boundTools[1].call_id});await frame.waitForFunction(id=>document.querySelector('#calls').dataset.scope===id,boundTools[1].call_id);await frame.waitForTimeout(400);assert.equal(await replay.locator('#calls').getAttribute('data-scope'),boundTools[1].call_id,'late old response must not overwrite selected tool');const raceRefs=await replay.locator('#calls tr td:last-child a').evaluateAll(nodes=>nodes.map(n=>'report'+new URL(n.href).hash)),raceAllowed=new Set(scope.calls.find(x=>x.call_id===boundTools[1].call_id).thread_ranges.flatMap(t=>t.call_indices.map(ci=>t.thread_ref+'/calls/'+ci)));assert(raceRefs.every(ref=>raceAllowed.has(ref)));await frame.evaluate(()=>{window.fetch=window.__testOriginalFetch;delete window.__testOriginalFetch});
await replay.locator('details.replay-tool summary').first().click();assert((await replay.locator('details.replay-tool').first().innerText()).includes('-lc'));await replay.locator('details.replay-tool [data-tool-scope]').first().click();assert.equal(await replay.locator('#tool-scope').inputValue(),summary.tools[0].call_id);
const verify=await frame.evaluate(async()=>await(await fetch('scope-export-verification.json')).json());assert.equal(verify.status,'RECOMPUTED_AND_IDENTICAL');
const privacy={};for(const name of ['.private-budget/','private-budget/','source/app/token.txt','live/source/private-budget/token.txt','replay/source/app/token.txt']){const response=await page.request.get(new URL(name,cfg.url).href);privacy[name]=response.status();assert.equal(response.status(),404);}
await page.locator('#tab-replay').focus();await page.keyboard.press('ArrowLeft');assert.equal(await page.evaluate(()=>document.activeElement.id),'tab-compare');assert.deepEqual(errors,[]);await frame.evaluate(()=>window.scrollTo(0,0));await page.evaluate(()=>window.scrollTo(0,0));if(cfg.screenshot)await page.screenshot({path:cfg.screenshot,fullPage:false});
console.log(JSON.stringify({status:'PASSED',browser:await browser.version(),url:cfg.url,three_context_tabs:true,failed_vs_completed_not_speedup:true,replay_is_zero_api_not_live_backfill:true,total_syscalls:summary.total_syscalls,correlated_syscalls:summary.correlated_syscalls,unassigned_syscalls:summary.unassigned_syscalls,tools:actual,tool_file_syscall_drilldown:true,pagination_verified:true,raw_reference_scope_check:true,out_of_order_scope_responses_rejected:true,runtime_cpu_not_claimed_by_tools:true,scope_binary_replay_receipt:true,keyboard_tabs:true,private_paths_http_status:privacy,page_errors:errors}));
}finally{await browser.close();}})().catch(e=>{console.error(e.stack||String(e));process.exitCode=1;});});
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--page',required=True)
    parser.add_argument('--receipt',required=True,type=Path);parser.add_argument('--screenshot',type=Path)
    parser.add_argument('--server-pid',type=int);parser.add_argument('--public-root',type=Path)
    args=parser.parse_args();module,browser=installed_browser_paths()
    if not module or not browser:raise RuntimeError('installed compatible browser required')
    if args.receipt.exists() or (args.screenshot and args.screenshot.exists()):raise ValueError('new browser artifact paths required')
    result=subprocess.run(['node','-e',CHECK],input=json.dumps({'module':module,'browser':browser,
        'url':args.page,'screenshot':str(args.screenshot) if args.screenshot else None}),text=True,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
    if result.returncode:raise RuntimeError(result.stderr[-8000:])
    receipt=json.loads(result.stdout)
    if args.server_pid:receipt['server_process_identity']=proc_identity(args.server_pid)
    if args.public_root:receipt['tested_html']={str(path.relative_to(args.public_root)):digest(path) for path in
        (args.public_root/'index.html',args.public_root/'live/index.html',args.public_root/'compare/index.html',args.public_root/'replay/index.html')}
    if args.screenshot:receipt['screenshot_identity']=digest(args.screenshot)
    write_new(args.receipt,receipt);print(json.dumps(receipt,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
