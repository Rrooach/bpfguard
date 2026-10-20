#!/usr/bin/env python3
"""Readable official-Codex steps linked to an already replayed native trace.

This is a presentation/binding check, not a second native verifier or an agent
loop. It never calls an API, executes a command, or changes source evidence.
"""
from __future__ import annotations
import argparse
from collections import Counter
import html
import json
import os
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from common import digest, write_new
from matrix_summary import Sources
from render import render_report
from syscall_catalog import BYTE_COUNT_ARG2, describe, descriptor_argument

MODE = 'REAL_CODEX_APP_SERVER_DYNAMIC_TOOLS'
BINDING = 'EXPLICIT_CODEX_REQUEST_TO_OWN_STOPPED_CHILD_NOT_TIMESTAMP_MATCHING'
PROVIDERS = ('UNVERIFIED', 'REAL_PROVIDER_CONFIRMED_EXTERNALLY', 'FAKE_PROVIDER_NO_API')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value):
    return type(value) is int and value >= 0


def bound_path(root, name, manifest, sources):
    require(isinstance(name, str) and name and not Path(name).is_absolute() and '..' not in Path(name).parts,
            'safe bound artifact name required')
    path = root / name
    require(not path.is_symlink() and root in path.resolve(strict=True).parents, 'artifact escapes run')
    identity = manifest.get('artifacts', {}).get(name)
    require(isinstance(identity, dict), 'application artifact is not manifest-bound: ' + name)
    return sources.bind(path, identity)


def read_bound(root, name, manifest, sources):
    return sources.read(bound_path(root, name, manifest, sources))


def ledger_object(line):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result, 'duplicate function ledger field')
            result[key]=value
        return result
    return json.loads(line, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite ledger value')))


def in_declared_workspace(path, workspace):
    if not isinstance(path,str) or not isinstance(workspace,str):return False
    candidate,base=PurePosixPath(path),PurePosixPath(workspace)
    return candidate.is_absolute() and base.is_absolute() and '..' not in candidate.parts and (candidate==base or base in candidate.parents)


def native_evidence(report, gate, workspace=None):
    """Observed in-window calls only; no path inference from an Agent command."""
    counts=Counter();writes=[];reads=[];modes=[]
    for thread in report.get('threads', []):
        if thread.get('tool_call_id') != gate['tool_call_id'] or thread.get('agent_id') != gate.get('agent_id'):
            continue
        for call in thread.get('calls', []):
            a,b=call.get('start_ns'),call.get('end_ns')
            if not (integer(a) and integer(b) and gate['begin_ns'] <= a <= b <= gate['end_ns']):
                continue
            name=describe(call.get('nr'),call.get('name'))['name'];result=call.get('result');args=call.get('args') or []
            success=call.get('pairing')=='PAIRED' and type(result) is int and result >= 0
            if success:
                if name.startswith(('rename','unlink')) or name in ('chmod','fchmod','fchmodat','fchmodat2'):
                    counts[name]+=1
                if name in ('chmod','fchmod','fchmodat','fchmodat2'):
                    index=1 if name in ('chmod','fchmod') else 2
                    if len(args)>index and type(args[index]) is int:
                        modes.append({'syscall':name,'requested_mode_octal':format(args[index]&0o7777,'04o'),
                            'result':result,'path':None,'path_quality':'NOT_RESOLVED_BY_CURRENT_WRITE_OBJECT_HOOKS'})
                if name in BYTE_COUNT_ARG2 and 'write' in name and result>0:
                    writes.append({'syscall':name,'requested_bytes':args[2] if len(args)>2 else None,
                        'returned_bytes':result,'descriptor':descriptor_argument(call),'duration_ns':b-a,
                        'path':None,'path_quality':'NOT_RESOLVED_BY_CURRENT_WRITE_OBJECT_HOOKS'})
            for file in call.get('files', []):
                read=file.get('read') if isinstance(file,dict) else None
                if not isinstance(read,dict):continue
                start,end=read.get('start_ns'),read.get('end_ns')
                if not(integer(start) and integer(end) and gate['begin_ns']<=start<=end<=gate['end_ns']):continue
                if type(read.get('result')) is not int or read['result']<=0:continue
                reads.append({'path':file.get('path'),'path_quality':file.get('path_quality',file.get('quality')),
                    'requested_bytes':read.get('requested_bytes'),'returned_bytes':read.get('returned_bytes'),
                    'result':read['result'],'duration_ns':end-start})
    local=[read for read in reads if in_declared_workspace(read.get('path'),workspace)]
    other=[read for read in reads if not in_declared_workspace(read.get('path'),workspace)]
    return {'successful_mutation_syscalls':dict(counts),'chmod_arguments':modes,
        'write_samples':sorted(writes,key=lambda value:value['returned_bytes'])[:20],
        'small_read_samples':sorted((read for read in reads if type(read.get('returned_bytes')) is int and read['returned_bytes']<=128),
            key=lambda value:(value['returned_bytes'],value['path'] or ''))[:20],
        'declared_workspace_read_samples':local[:100], 'declared_workspace_read_records':len(local),
        'other_read_samples':sorted(other,key=lambda value:(value.get('returned_bytes') or 0,value['path'] or ''))[:20],
        'other_read_records':len(other),
        'scope':'OBSERVED_PAIRED_CALLS_AND_VFS_READS_WITHIN_THIS_TOOL; NOT_FINAL_STATE_CONFIRMATION; NO_PATH_FROM_COMMAND_TEXT'}


def compose(run_dir):
    root = Path(run_dir).resolve(strict=True)
    sources = Sources()
    manifest = sources.read(root / 'manifest.json')
    verification = sources.read(root / 'verification.json')
    require(manifest.get('mode') == MODE and manifest.get('clock') == 'CLOCK_MONOTONIC', 'official Codex run/clock required')
    require(verification.get('manifest') == digest(root / 'manifest.json'), 'verification manifest binding differs')
    require(integer(manifest.get('begin_ns')) and integer(manifest.get('end_ns'))
            and manifest['end_ns'] >= manifest['begin_ns'], 'ordered capture boundary required')
    outcome = read_bound(root, 'app/codex-result.json', manifest, sources)
    prompt_path = bound_path(root, 'app/prompt.txt', manifest, sources)
    require(prompt_path.stat().st_size <= 32768, 'bounded public prompt required')
    prompt = prompt_path.read_text()
    workspace=None
    if 'app/client-requests.jsonl' in manifest.get('artifacts',{}):
        requests_path=bound_path(root,'app/client-requests.jsonl',manifest,sources)
        require(requests_path.stat().st_size<=4*1024*1024,'bounded application request log required')
        lines=requests_path.read_bytes().splitlines(keepends=True)
        require(all(line.endswith(b'\n') for line in lines),'truncated application request log')
        requests=[ledger_object(line) for line in lines]
        candidates={request.get('params',{}).get('cwd') for request in requests if request.get('method')=='thread/start'
                    and isinstance(request.get('params'),dict) and isinstance(request['params'].get('cwd'),str)}
        if len(candidates)==1:
            declared=next(iter(candidates))
            if PurePosixPath(declared).is_absolute() and '..' not in PurePosixPath(declared).parts:workspace=declared
    steps_path = root / 'app/steps.json'
    application = read_bound(root, 'app/steps.json', manifest, sources) if steps_path.is_file() else None
    report = None
    if verification.get('status') == 'REPLAY_PASSED':
        require(isinstance(verification.get('report'), dict), 'native report identity missing')
        report = sources.read(root / 'report.json', verification.get('report'))
        require(report.get('run', {}).get('run_id') == manifest['run_id'] and report['run'].get('boot_id') == manifest['boot_id'],
                'native report run/boot differs')
    registry = {tool['tool_call_id']: tool for tool in manifest['tools']}
    require(len(registry) == len(manifest['tools']), 'duplicate manifest tool ID')
    steps, mappings, linked = [], [], set()
    if application is not None:
        require(application.get('mode') == MODE and application.get('agent_loop') == 'OFFICIAL_CODEX_NOT_IMPLEMENTED_BY_THIS_CLIENT',
                'official Codex application contract required')
        require(all(isinstance(application.get(name), str) and application[name] for name in ('thread_id', 'turn_id')), 'Codex thread/turn required')
        require(application.get('status') == outcome.get('status'), 'application outcome differs')
        mappings = application.get('function_bindings')
        require(isinstance(mappings, list) and len(mappings) <= 8, 'bounded explicit mapping list required')
        ledger_path = bound_path(root, 'app/function-bindings.jsonl', manifest, sources)
        require(ledger_path.stat().st_size <= 1024 * 1024, 'bounded function ledger required')
        lines = ledger_path.read_bytes().splitlines(keepends=True)
        require(all(line.endswith(b'\n') for line in lines), 'truncated function ledger')
        require([ledger_object(line) for line in lines] == mappings, 'application function ledger/result differs')
        calls, rpc_ids = set(), set()
        for mapping in mappings:
            require(isinstance(mapping.get('call_id'), str) and mapping['call_id']
                and type(mapping.get('rpc_request_id')) in (str, int), 'explicit Codex request identity required')
            key = mapping.get('tool_call_id')
            require(key in registry and key not in linked and mapping.get('binding_basis') == BINDING, 'missing/duplicate explicit gate mapping')
            gate = registry[key]
            require(gate.get('kind') == 'CODEX_DYNAMIC_SHELL' and mapping.get('tool') == 'observer_bash', 'dynamic-shell mapping required')
            require(gate.get('codex_call_id') == mapping['call_id'], 'enrolled Codex call identity differs')
            require(all(mapping.get(name) == gate.get(name) for name in ('root', 'cgroup_id', 'begin_ns', 'end_ns', 'cgroup_empty')),
                    'application root/cgroup/lifecycle differs from gate')
            require(mapping.get('root_pid') == gate['root'].get('tid') and mapping.get('cgroup_path') == gate.get('cgroup_path'),
                    'application PID/cgroup path differs')
            require(gate.get('command') == ['/bin/bash', '--noprofile', '--norc', '-c', mapping.get('command')], 'actual shell command differs')
            require(mapping.get('thread_id') == application.get('thread_id') and mapping.get('turn_id') == application.get('turn_id'),
                    'Codex thread/turn identity differs')
            require(mapping.get('call_id') not in calls and mapping.get('rpc_request_id') not in rpc_ids, 'duplicate Codex call/RPC request')
            calls.add(mapping.get('call_id')); rpc_ids.add(mapping.get('rpc_request_id')); linked.add(key)
            for name in ('stdout_artifact', 'stderr_artifact'):
                bound_path(root, mapping.get(name), manifest, sources)
        by_tool = {mapping['tool_call_id']: mapping for mapping in mappings}
        seen_steps = set()
        require(isinstance(application.get('steps'), list) and len(application['steps']) <= 256, 'bounded application steps required')
        for step in application['steps']:
            require(step.get('thread_id') == application.get('thread_id') and step.get('turn_id') == application.get('turn_id'), 'step thread/turn differs')
            if step.get('kind') == 'TOOL_CALL':
                key = step.get('tool_call_id'); mapping = by_tool.get(key)
                require(mapping is not None and key not in seen_steps and all(step.get(k) == v for k, v in mapping.items()), 'step explicit binding differs')
                require(type(step.get('exit_code')) is int and step['exit_code'] == registry[key].get('result'), 'step exit code differs')
                require(all(integer(step.get(k)) for k in ('begin_ns', 'end_ns')) and step['end_ns'] >= step['begin_ns'], 'step timing differs')
                seen_steps.add(key)
            else:
                require(step.get('kind') == 'AGENT_MESSAGE' and isinstance(step.get('text'), str), 'unknown application step kind')
            steps.append(step)
        require(seen_steps == linked, 'mapped tool is missing from application steps')
    native_tools = {tool['tool_call_id']: tool for tool in report.get('tools', [])} if report else {}
    if report:
        require(set(native_tools) == set(registry), 'native/manifest tool registry differs')
        for key, gate in registry.items():
            require(all(native_tools[key].get(field) == gate.get(field) for field in ('root', 'command', 'cgroup_id', 'begin_ns', 'end_ns', 'result')),
                    'native report/gate command or identity differs')
    result = {'schema_version': 1, 'mode': MODE, 'status': 'BOUND_CODEX_APPLICATION_VIEW_NOT_NATIVE_VERIFICATION',
        'run_id': manifest['run_id'], 'boot_id': manifest['boot_id'], 'agent_id': manifest.get('agent_id'),
        'model': application.get('model') if application else None, 'agent_outcome': outcome,
        'prompt': prompt, 'steps': steps, 'application_steps_status': 'EXPLICIT_FUNCTION_GATE_BINDINGS_CHECKED' if application else 'INCOMPLETE_APPLICATION_LOG',
        'verification': verification, 'capture_begin_ns': manifest['begin_ns'], 'capture_end_ns': manifest['end_ns'],
        'raw_health': report.get('health') if report else None,
        'native_successful_exec_records': sum(len(thread.get('execs', [])) for thread in report.get('threads', [])) if report else None,
        'declared_workspace':{'path':workspace,'basis':'MANIFEST_BOUND_THREAD_START_PARAMS_CWD',
            'scope':'DISPLAY_GROUPING_ONLY_NOT_OBSERVATION_SCOPE_OR_CANONICAL_IDENTITY'} if workspace else None,
        'tool_native_evidence':{key:native_evidence(report,registry[key],workspace) for key in linked} if report else {},
        'sources': sources.identities}
    return root, result, report, sources


def page(root, result, output, native_available):
    esc = lambda value: html.escape(str(value), quote=True)
    def link(name, label):
        target = os.path.relpath(root / name, output)
        return '<a href="{}">{}</a>'.format(esc(quote(target, safe='/.-_')), esc(label))
    def read_fragment(sample):
        return '<p>实际内核读取的记录路径：<code>'+esc(sample['path'] or '未解析')+'</code>，返回 <strong>'+esc(sample['returned_bytes'])+' bytes</strong>，VFS调用耗时 '+format(sample['duration_ns']/1e6,'.3f')+' ms。</p><details><summary>路径解析质量</summary>'+esc(sample['path_quality'] or 'UNKNOWN')+'</details>'
    begin = result['capture_begin_ns']
    outcome_text={'completed':'完成','failed':'失败','interrupted':'已中断','CLIENT_OR_RUNTIME_FAILURE':'运行失败'}.get(result['agent_outcome'].get('status'),'未确定')
    replay_text='原始重放通过（不代表全部行为覆盖）' if native_available else '原始重放未通过或未完成'
    binding_text='工具请求和实际进程已明确对应' if result['application_steps_status']=='EXPLICIT_FUNCTION_GATE_BINDINGS_CHECKED' else '步骤日志未完整生成'
    count=sum(step['kind']=='TOOL_CALL' for step in result['steps'])
    provider=result.get('provider_scope','UNVERIFIED')
    version=' '+esc(result['codex_version_declared']) if result.get('codex_version_declared') else ''
    provider_text=('真正 Codex'+version+' app-server + DeepSeek，真实 API 出站由独立代理账本另行确认。' if provider=='REAL_PROVIDER_CONFIRMED_EXTERNALLY' else
        '校准样例：真正 Codex app-server，但使用本地 fake provider，零外部 API。不是 DeepSeek 真实推理结果，也不是 benchmark 成绩。' if provider=='FAKE_PROVIDER_NO_API' else
        '真正 Codex app-server，配置模型为 DeepSeek；本页未核实真实 API 出站或费用，不能仅由模型名推断。')
    out = ['<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
        '<title>Codex（DeepSeek）实际执行记录</title><style>body{font:15px system-ui;max-width:1150px;margin:24px auto;padding:0 16px;line-height:1.65;background:#f5f7fa;color:#17243a}section{background:white;border:1px solid #d6deea;border-radius:9px;padding:16px;margin:15px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f8;padding:12px}summary{cursor:pointer}a{color:#245f9d}.note{background:#fff0cf;padding:12px}.success{color:#277040}.error{color:#a12727}h1{font-size:24px}h2{font-size:19px}</style>',
        '<h1>Codex 实际做了什么</h1><p class="note">'+provider_text+'</p><p>受控命令工具模式：只开放 observer_bash，不等同于默认全内建工具。Agent 循环由官方 Codex 负责，不是自写模型循环。下面直接看实际命令和结果。</p>',
        '<section><h2>任务</h2><pre>' + esc(result['prompt']) + '</pre><p>结果：<strong>' + outcome_text + '</strong>；' + ('实际执行 '+str(count)+' 条命令' if result['application_steps_status']=='EXPLICIT_FUNCTION_GATE_BINDINGS_CHECKED' else '命令列表未完成') + '。</p><p>'+replay_text+'；'+binding_text+'。</p></section>',
        '<p class="note">这些结论分开保留：命令成功不等于全部观测完整，重放通过也不证明全部 Linux 行为都已覆盖。模型消息的时间只是客户端收到它的时刻，不能当成模型生成耗时。未采集的路径保持“未解析”。</p>']
    if native_available:
        out.append('<section><h2>想看底层记录？</h2><p><a href="native-readable.html#programCard">实际启动了哪些程序</a> · <a href="native-readable.html#operationCard">文件操作 / 每次 syscall</a> · <a href="native-readable.html#threadPanel">线程与等待时间线</a></p><p>原始报告含 {} 条成功 EXEC 记录；实际名称保留其解析质量，不以线程名猜程序。</p></section>'.format(result['native_successful_exec_records']))
    else:
        out.append('<section><h2>内核记录未通过完整重放</h2><p>不生成“通过”的内核可读页。原始错误仍保留：' + esc(result['verification']) + '</p></section>')
    tool_number = 0
    for step in result['steps']:
        if step['kind'] == 'AGENT_MESSAGE':
            out.append('<section><h2>Codex说明 / 回答</h2><pre>' + esc(step['text']) + '</pre><details><summary>消息身份与收到时刻</summary><pre>' + esc({key: step.get(key) for key in ('item_id', 'receipt_ns', 'timing_scope')}) + '</pre></details></section>')
            continue
        tool_number += 1
        wall = (step['end_ns'] - step['begin_ns']) / 1e6
        outcome = '成功' if step['exit_code'] == 0 else '失败'
        out.append('<section><h2>第{}条命令：<span class="{}">{}，退出码 {}</span></h2><pre>{}</pre><p>实际执行 {:.3f} ms；任务时轴 {:.6f}s → {:.6f}s。进程组已清空：{}。</p>'.format(tool_number,
            'success' if step['exit_code'] == 0 else 'error', outcome, step['exit_code'], esc(step['command']), wall,
            (step['begin_ns'] - begin) / 1e9, (step['end_ns'] - begin) / 1e9, esc(step.get('cgroup_empty', 'UNKNOWN'))))
        out.append('<p>标准输出：</p><pre>' + esc(step.get('stdout', '')) + '</pre>')
        native=result.get('tool_native_evidence',{}).get(step['tool_call_id'],{})
        counts=native.get('successful_mutation_syscalls',{})
        if counts:
            names={'rename':'改名','renameat':'改名','renameat2':'改名','chmod':'改权限','fchmod':'改权限','fchmodat':'改权限','fchmodat2':'改权限','unlink':'删除','unlinkat':'删除'}
            out.append('<p><strong>内核确实记录到：</strong>'+ '；'.join(esc(names.get(name,name))+'调用成功 '+str(count)+' 次' for name,count in counts.items())+'。这是调用事实，不代替最终状态快照。</p>')
        for mode in native.get('chmod_arguments',[]):
            out.append('<p>改权限调用的实际参数：<code>'+esc(mode['requested_mode_octal'])+'</code>；目标内核路径未解析，不从上面的命令文本补猜。</p>')
        for sample in native.get('write_samples',[]):
            if sample['returned_bytes']<=128:
                out.append('<p>实际写入调用：请求 '+esc(sample['requested_bytes'])+' bytes，返回 '+str(sample['returned_bytes'])+' bytes；目标路径未解析（可能是普通文件或其他fd，不按命令推断）。</p>')
        workspace=result.get('declared_workspace')
        if workspace:
            out.append('<h3>工作目录中的实际文件读取</h3><p>按Codex声明工作目录分组：<code>'+esc(workspace['path'])+'</code>。这里只改变展示顺序，不增加观测范围或路径可信度。</p>')
            local=native.get('declared_workspace_read_samples',[])
            if not local:out.append('<p>本条命令没有已记录且路径匹配该目录的成功VFS读取；不据此断言没有访问。</p>')
            out.extend(read_fragment(sample) for sample in local)
            out.append('<details><summary>运行时其他文件读取（展开）</summary><p>该目录外共记录 '+str(native.get('other_read_records',0))+' 条成功读取，以下最多20条预览；完整记录仍在内核页中。</p>')
            out.extend(read_fragment(sample) for sample in native.get('other_read_samples',[]))
            out.append('</details>')
        else:
            out.extend(read_fragment(sample) for sample in native.get('small_read_samples',[]))
        if step.get('stderr'):
            out.append('<p>标准错误：</p><pre>' + esc(step['stderr']) + '</pre>')
        out.append('<p>' + link(step['stdout_artifact'], '完整 stdout') + ' · ' + link(step['stderr_artifact'], '完整 stderr'))
        if native_available:
            out.append(' · <a href="native-readable.html?tool=' + esc(quote(step['tool_call_id'], safe='')) + '&amp;kind=filesystem#operations">查看这条命令的文件操作 / syscall</a>')
            out.append(' · <a href="native-readable.html?tool=' + esc(quote(step['tool_call_id'], safe='')) + '#threadPanel">查看这条命令的线程时间线</a>')
        out.append('</p><details><summary>查看明确绑定的 Codex 调用 / Linux 进程身份</summary><pre>' + esc({key: step.get(key) for key in ('call_id', 'rpc_request_id', 'tool_call_id', 'root', 'cgroup_id', 'binding_basis', 'output_truncated')}) + '</pre></details></section>')
    if not result['steps']:
        out.append('<section><h2>应用步骤未完成</h2><p>保留失败状态，不补造命令或模型回答。</p><pre>' + esc(result['agent_outcome']) + '</pre></section>')
    out.append('<section><h2>完整证据</h2><p>' + link('manifest.json', 'manifest') + ' · ' + link('verification.json', '原始重放回执') + ' · <a href="view-data.json">本页完整数据与来源摘要</a> · <a href="receipt.json">展示生成回执</a></p><p>费用以独立代理账本为准，本页不猜测付费请求数或账单。原始证据和配置不因生成本页而改变。</p></section></html>')
    external=result.get('provider_receipt')
    if external:
        href=quote(os.path.relpath(external['path'],output),safe='/.-_')
        out[-1]=out[-1].replace('</section></html>','<p><a href="'+esc(href)+'">真实模型请求、工具命令与最终回答的独立验证回执</a>（外部证据，不由展示模式自动证明）。</p></section></html>')
    return '\n'.join(out)


def export(run_dir, output, provider_scope='UNVERIFIED', codex_version=None, provider_receipt=None):
    require(provider_scope in PROVIDERS, 'explicit supported provider scope required')
    root, result, report, sources = compose(run_dir)
    result['provider_scope']=provider_scope
    require(codex_version is None or isinstance(codex_version,str) and 0<len(codex_version)<=40, 'bounded version declaration required')
    result['codex_version_declared']=codex_version
    result['provider_scope_authority']='CALLER_DECLARATION_FROM_EXTERNAL_EVIDENCE_NOT_VERIFIED_AS_API_BILL_BY_THIS_VIEW'
    if provider_receipt is not None:
        receipt_path=sources.bind(provider_receipt);external=sources.read(receipt_path)
        require(external.get('run_id')==result['run_id'] and external.get('manifest_identity')==digest(root/'manifest.json')
            and external.get('status')=='REAL_CODEX_PROVIDER_COMMAND_AND_FINAL_ANSWER_BOUND','external provider receipt run/manifest/status differs')
        result['provider_receipt']={'path':str(receipt_path),'identity':digest(receipt_path),'status':external['status'],
            'scope':'EXTERNAL_VERIFIER_RECEIPT_LINKED_NOT_REEXECUTED_BY_VIEWER'}
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), 'fresh Codex view directory required')
    output.mkdir(parents=True, mode=0o700)
    if report:
        write_new(output / 'native-readable.html', render_report(report, '真正 Codex 受控命令执行；provider范围声明 '+provider_scope+'。工具来自明确动态请求 → stopped 子进程登记，不按时间猜归属；API出站与费用另看代理账本。').encode())
    write_new(output / 'view-data.json', result)
    write_new(output / 'index.html', page(root, result, output, report is not None).encode())
    sources.unchanged()
    names = ['view-data.json', 'index.html'] + (['native-readable.html'] if report else [])
    write_new(output / 'receipt.json', {'schema_version': 1, 'status': result['status'], 'sources': sources.identities,
        'generators': {name: digest(Path(__file__).with_name(name)) for name in ('codex_view.py','render.py','summarize.py','syscall_catalog.py')}, 'artifacts': {name: digest(output / name) for name in names},
        'scope': 'OFFLINE_BOUND_APPLICATION_PRESENTATION; DOES_NOT_REPLACE_INDEPENDENT_RAW_REPLAY'})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--provider-scope', choices=PROVIDERS, default='UNVERIFIED',
                        help='external-evidence declaration only; fake controls must be explicitly labeled')
    parser.add_argument('--codex-version', help='version established externally for the manifest-bound binary')
    parser.add_argument('--provider-receipt', type=Path, help='public external verifier receipt matching this manifest/run')
    args = parser.parse_args(argv)
    export(args.run_dir, args.output, args.provider_scope, args.codex_version,args.provider_receipt)
    print(str((args.output / 'index.html').absolute()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
