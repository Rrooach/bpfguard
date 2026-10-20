#!/usr/bin/env python3
"""Real Chromium interaction check for standalone or integrated profile pages.

No browser/package download is performed. Supply an installed Playwright and
Chromium via flags or PROFILE_PLAYWRIGHT_MODULE / PROFILE_CHROMIUM_EXECUTABLE.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


CHECK_JS = r"""
const fs=require('node:fs'),assert=require('node:assert/strict');
let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',s=>input+=s);
process.stdin.on('end',()=>{(async()=>{
 const cfg=JSON.parse(input),{chromium}=require(cfg.playwright);
 const browser=await chromium.launch({executablePath:cfg.browser,headless:true,args:['--no-sandbox']});
 const context=await browser.newContext({viewport:{width:1360,height:1000},acceptDownloads:true});
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));
 try{
  if(cfg.html)await page.setContent(cfg.html,{waitUntil:'domcontentloaded'});else await page.goto(cfg.url,{waitUntil:'domcontentloaded'});
  const host=page.locator('.iprof').first();await host.waitFor();const prefix='#'+await host.getAttribute('id');
  const role=name=>page.locator(prefix+' [data-role="'+name+'"]');
  const state=()=>host.evaluate(n=>n.profileViewer.getState());
  const payload=await host.locator('[data-role="payload"]').evaluate(n=>JSON.parse(n.textContent));
  const initial=await state();assert(initial.metric);assert(initial.visible.length);
  let view=payload.views.find(v=>v.name===initial.metric),nodes=view.nodes;
  const root=view.root;const tool=nodes.find(n=>n.kind==='tool'&&n.value>0&&initial.visible.includes(n.id));
  if(tool){await page.locator(prefix+' [data-node-id="'+tool.id+'"]').click();assert.equal((await state()).zoom,tool.id);assert(await role('details').innerText());await role('back').click();assert.equal((await state()).zoom,root);}
  const diagnostic=payload.views.find(v=>v.status==='AVAILABLE'&&v.nodes.some(n=>n.kind==='syscall'))||view;
  await role('metric').selectOption(diagnostic.name);view=diagnostic;nodes=view.nodes;
  await role('depth').selectOption('16');
  let leaf=nodes.find(n=>n.kind==='syscall'&&n.value>0)||nodes.find(n=>!n.children.length&&n.value>0);
  assert(leaf,'positive measured profile leaf required for interaction check');
  await role('search').fill(leaf.label);assert((await state()).matched.includes(leaf.id));assert((await role('search-result').innerText()).includes('%'));
  await role('find').click();let zoomed=await state();assert(zoomed.matched.includes(zoomed.zoom));
  const actualId=zoomed.zoom,actual=nodes.find(n=>n.id===actualId);
  assert((await role('details').innerText()).includes('inclusive'));assert((await role('details').innerText()).includes('exclusive'));
  const evidenceLinks=await role('details').locator('a').count();assert(evidenceLinks>=1);
  const compatible=payload.views.find(v=>v.name!==view.name&&v.nodes.some(n=>n.id===actualId));
  if(compatible){await role('metric').selectOption(compatible.name);assert.equal((await state()).zoom,actualId);assert((await role('live').innerText()).includes('保留'));}
  const incompatible=payload.views.find(v=>!v.nodes.some(n=>n.id===actualId));
  if(incompatible){await role('metric').selectOption(incompatible.name);assert.equal((await state()).zoom,incompatible.root);assert((await role('live').innerText()).includes('返回总览'));}
  await role('metric').selectOption(view.name);await role('reset').click();assert.equal((await state()).zoom,view.root);assert.equal((await state()).search,'');
  await role('depth').selectOption('16');const rootRect=page.locator(prefix+' [data-node-id="'+view.root+'"]');await rootRect.focus();await page.keyboard.press('ArrowDown');assert.notEqual((await state()).selected,view.root);await page.keyboard.press('Enter');assert.notEqual((await state()).zoom,view.root);
  await role('breadcrumbs').locator('button').first().click();assert.equal((await state()).zoom,view.root);
  const hoverTarget=page.locator(prefix+' [data-node-id="'+view.root+'"]');await hoverTarget.hover();assert(await role('tooltip').isVisible());
  const svgWait=page.waitForEvent('download');await role('svg').click();const svg=await svgWait;
  const svgText=fs.readFileSync(await svg.path(),'utf8');assert(svgText.includes('<svg'));assert(svgText.includes('inclusive'));
  const jsonWait=page.waitForEvent('download');await role('json').click();const snapshot=await jsonWait;const exported=JSON.parse(fs.readFileSync(await snapshot.path(),'utf8'));assert.equal(exported.selected_metric,view.name);assert(!Object.prototype.hasOwnProperty.call(exported.payload,'operations'));
  const invalidSvg=await role('chart').evaluate(n=>[...n.querySelectorAll('rect')].some(r=>['x','y','width','height'].some(k=>!Number.isFinite(Number(r.getAttribute(k)))||(['width','height'].includes(k)&&Number(r.getAttribute(k))<0))));assert.equal(invalidSvg,false);assert.deepEqual(errors,[]);
  console.log(JSON.stringify({status:'PASSED',engine:await browser.version(),initial_metric:initial.metric,test_metric:view.name,tool_zoom_checked:!!tool,evidence_links:evidenceLinks,metric_zoom_preserved:!!compatible,metric_zoom_reset:!!incompatible,interaction_checks:['node-zoom','breadcrumbs','back','search-highlight-weight','inclusive-exclusive','raw-evidence-links','metric-selection','keyboard','hover','SVG-download','JSON-download','finite-SVG-coordinates'],page_errors:errors}));
 }finally{await context.close();await browser.close();}
})().catch(e=>{console.error(e.stack||String(e));process.exitCode=1;});});
"""


def installed_browser_paths():
    module = os.environ.get('PROFILE_PLAYWRIGHT_MODULE')
    browser = os.environ.get('PROFILE_CHROMIUM_EXECUTABLE')
    cache = Path.home() / '.cache' / 'ms-playwright'
    if not browser:
        candidates = list(cache.glob('chromium-1140/chrome-linux/chrome'))
        browser = str(candidates[0]) if candidates else None
    if not module:
        for candidate in (Path.home() / '.npm' / '_npx').glob('*/node_modules/playwright/package.json'):
            try:
                if json.loads(candidate.read_text())['version'] == '1.48.2':
                    module = str(candidate.parent)
                    break
            except (OSError, ValueError, KeyError):
                continue
    return module, browser


def check_page(*, html=None, url=None, playwright=None, browser=None):
    if bool(html) == bool(url):
        raise ValueError('provide exactly one HTML document or page URL')
    installed_module, installed_browser = installed_browser_paths()
    playwright, browser = playwright or installed_module, browser or installed_browser
    if not playwright or not browser or not shutil.which('node'):
        raise RuntimeError('installed Node, Playwright module and Chromium executable required')
    result = subprocess.run(['node', '-e', CHECK_JS], input=json.dumps({
        'playwright': playwright, 'browser': browser, 'html': html, 'url': url}),
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        raise RuntimeError('browser interaction failed: ' + result.stderr[-8000:])
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--page', required=True, help='HTTP(S) URL or local HTML path')
    parser.add_argument('--playwright-module')
    parser.add_argument('--browser')
    args = parser.parse_args()
    url = args.page if args.page.startswith(('http://', 'https://', 'file://')) else Path(args.page).resolve().as_uri()
    print(json.dumps(check_page(url=url, playwright=args.playwright_module,
                               browser=args.browser), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
