#!/usr/bin/env python3
"""Exercise a real native profile HTTP page without running an Agent/API."""
import argparse
import json
from pathlib import Path
import subprocess

from common import digest, write_new
from validate_profile_ui_browser import installed_browser_paths


CHECK = r'''
const assert=require('node:assert/strict');let input='';process.stdin.on('data',s=>input+=s);process.stdin.on('end',()=>{(async()=>{
const cfg=JSON.parse(input),{chromium}=require(cfg.module),browser=await chromium.launch({executablePath:cfg.browser,headless:true,args:['--no-sandbox']});
try{const page=await browser.newPage({viewport:{width:1440,height:1050}}),errors=[];page.on('pageerror',e=>errors.push(String(e)));await page.goto(cfg.url,{waitUntil:'networkidle'});
await page.waitForFunction(()=>document.querySelector('#native-syscalls').children.length>0);
if(cfg.agentStatus)assert((await page.locator('main').innerText()).includes('Agent 本轮结果：'+cfg.agentStatus));
const outer=await page.locator('details.native-model-tool').count(),inner=await page.locator('details.native-tool').count();assert(outer>0);assert(inner>0);
await page.locator('details.native-model-tool summary').first().click();const outerText=await page.locator('details.native-model-tool').first().innerText();assert(outerText.includes('call_id'));assert(outerText.includes('JS CPU'));assert(outerText.includes('请求'));assert(await page.locator('details.native-model-tool').first().locator('pre').count()>=2);
const firstCount=await page.locator('#native-syscalls tr').count();assert(firstCount>0&&firstCount<=200);const next=page.locator('#native-next');if(await next.isEnabled()){await next.click();await page.waitForFunction(()=>document.querySelector('#native-page-status').textContent.includes('第 2 /'));}
const selectors=await page.locator('#native-thread option').count();assert(selectors>1);
const fileCount=await page.locator('#native-files tr').count();assert(fileCount>0&&fileCount<=100);
const rss=await page.locator('[data-memory-field="rss_bytes"]').count();assert(rss>0);await page.locator('#memory-accounting').selectOption('cgroup');await page.waitForFunction(()=>document.querySelector('[data-memory-field="cgroup_current_bytes"]'));assert(await page.locator('[data-memory-field="cgroup_current_bytes"]').count());
const panel=page.locator('.iprof').first(),payload=await panel.locator('[data-role="payload"]').evaluate(n=>JSON.parse(n.textContent));
const nativeView=payload.views.find(v=>v.name==='native_model_tool_ms');assert(nativeView&&nativeView.total>0);const toolNodes=nativeView.nodes.filter(n=>n.kind==='tool');const ids=toolNodes.map(n=>n.metadata.call_id);assert.equal(new Set(ids).size,outer,'native model calls must not be merged under one metadata call_id');
await panel.locator('[data-role="metric"]').selectOption('native_model_tool_ms');const node=toolNodes[0];await panel.locator('[data-role="find"]').count();await panel.locator('[data-role="search"]').fill(node.label);await panel.locator('[data-role="find"]').click();const jump=panel.getByRole('link',{name:'在本页查看这次工具的输入、输出和状态'});assert(await jump.count());await jump.click();assert(await page.locator('#'+node.metadata.detail_anchor).evaluate(n=>n.open));
const syscallView=payload.views.find(v=>v.name==='syscall_count');assert(syscallView&&syscallView.total>0);assert(!syscallView.nodes.some(n=>n.kind==='tool'),'unbound runtime syscalls must not be nested under model tools');
const privacy={};for(const path of ['private-budget/','source/private-budget/token.txt','source/app/token.txt']){const r=await page.request.get(new URL(path,cfg.url).href);privacy[path]=r.status();assert.equal(r.status(),404);}
assert.deepEqual(errors,[]);await panel.locator('[data-role="reset"]').click();await panel.locator('[data-role="metric"]').selectOption('wall_ms');await page.evaluate(()=>window.scrollTo(0,0));if(cfg.screenshot)await page.screenshot({path:cfg.screenshot,fullPage:false});
console.log(JSON.stringify({status:'PASSED',browser:await browser.version(),native_model_tools:outer,native_inner_items:inner,runtime_syscalls:syscallView.total,first_syscall_page_rows:firstCount,thread_choices:selectors-1,first_file_page_rows:fileCount,rss_curve:true,cgroup_curve:true,distinct_outer_call_ids:new Set(ids).size,same_page_tool_drilldown:true,unbound_kernel_scope_preserved:true,private_paths_http_status:privacy,page_errors:errors}));
}finally{await browser.close();}})().catch(e=>{console.error(e.stack||String(e));process.exitCode=1;});});
'''


def check_native_page(url, *, agent_status=None, screenshot=None):
    module,browser=installed_browser_paths()
    if not module or not browser:raise RuntimeError('installed Playwright/Chromium required; no auto-download')
    if screenshot and Path(screenshot).exists():raise ValueError('new screenshot filename required')
    result=subprocess.run(['node','-e',CHECK],input=json.dumps({'module':module,'browser':browser,
        'url':url,'agentStatus':agent_status,'screenshot':str(screenshot) if screenshot else None}),
        text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
    if result.returncode:raise RuntimeError(result.stderr[-8000:])
    return json.loads(result.stdout)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--page',required=True)
    parser.add_argument('--expect-agent-status')
    parser.add_argument('--receipt',type=Path)
    parser.add_argument('--html',type=Path,help='bind tested local HTML identity into receipt')
    parser.add_argument('--screenshot',type=Path)
    args=parser.parse_args()
    if args.receipt and args.receipt.exists():raise ValueError('new browser receipt required')
    result=check_native_page(args.page,agent_status=args.expect_agent_status,screenshot=args.screenshot)
    if args.html:result['html_identity']=digest(args.html)
    if args.screenshot:result['screenshot_identity']=digest(args.screenshot)
    if args.receipt:write_new(args.receipt,result)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
