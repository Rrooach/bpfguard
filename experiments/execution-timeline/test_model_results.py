"""Tiny synthetic evidence only: no paid API, VM or historical data."""
import csv
import json
from pathlib import Path
import tempfile
import unittest

from common import digest, write_new
import model_results as M


def dump(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_new(path, value)


def lines(path, rows):
    dump(path, b''.join(M.wire(row) + b'\n' for row in rows))


def request_fixture(label, *, rejected=False, finish=False):
    key = label + '-step-0'
    payload = {'model': 'deepseek-flash', 'messages': [{'role': 'user', 'content': 'public instruction'}],
        'tools': [], 'max_tokens': 1024, 'temperature': 0, 'stream': False, 'n': 1, 'thinking': {'type': 'disabled'}}
    start = {'schema_version': 1, 'event': 'MODEL_REQUEST_START', 'request_id': key, 'step': 0,
        'budget_label': label, 'model': 'deepseek-flash', 'boot_id': 'boot', 'clock': 'CLOCK_MONOTONIC',
        'begin_ns': 20, 'request_sha256': 'c' * 64, 'max_output_tokens': 1024}
    usage = {'prompt_tokens': 10, 'completion_tokens': 1}
    end = dict(start, event='MODEL_REQUEST_END', end_ns=30, status='BUDGET_OR_REQUEST_LIMIT' if rejected else 'RECEIVED',
        usage=None if rejected else usage, response_model='deepseek-flash', failure_kind=None)
    function = {'id': 'provider-function', 'function': {'name': 'finish' if finish else 'bash',
        'arguments': '{}' if finish else json.dumps({'command': 'cat /app/a'})}}
    response = {'model': 'deepseek-flash', 'choices': [{'message': {'role': 'assistant', 'content': None, 'tool_calls': [function]}}], 'usage': usage}
    transcript = [{'event': 'REQUEST', 'request_id': key, 'payload': payload}]
    if not rejected: transcript.append({'event': 'RESPONSE', 'request_id': key, 'response': response})
    return [start, end], transcript


def make_group(base, benchmark='SWE-bench Verified', concurrency=2, *, rejected=False, finish=False):
    bench = 'swe' if benchmark == M.BENCHMARKS[0] else 'terminal'
    root, report, resources = [base / (f'{bench}-c{concurrency}-' + name) for name in ('raw', 'report', 'resources')]
    for directory in (root, report, resources): directory.mkdir()
    originals, rows, acceptance = [], [], []
    for index in range(8):
        name, label = f'{bench}-{index:02d}', f'model-{bench}-c{concurrency}-{index:02d}'
        timeline, leaf = root / 'jobs' / name / 'timeline', report / 'reports' / name
        timeline.mkdir(parents=True); leaf.mkdir(parents=True)
        terminal = bench == 'terminal'; prefix = 'model-evidence' if terminal else 'application/api'
        events, transcript = request_fixture(label, rejected=rejected, finish=finish)
        lines(timeline / prefix / 'model-requests.jsonl', events)
        lines(timeline / prefix / 'model-transcript.jsonl', transcript)
        tid = 10 + index
        identity = {'tid': tid, 'start_ticks': 1, 'clock_ticks': 100}
        tool_id, agent = label + '-exec-0', ('model-agent:' if terminal else 'model:') + label
        gate = {'tool_call_id': tool_id, 'docker_exec_id': 'exec-' + name, 'root': identity, 'begin_ns': 40, 'end_ns': 50,
            'invocation_ns': 35, 'agent_id': agent, 'cgroup_id': 123, 'kind': 'MODEL_SHELL'}
        native_tool = {'tool_call_id': tool_id, 'root_key': 'boot:' + str(tid) + ':1', 'agent_id': agent,
            'selected_tool_timeline_status': 'COMPLETE_WITHIN_SELECTED_TOOL_SCOPE',
            'completion_path': {'state_totals_ns': {'ONCPU': 6, 'RUNNABLE': 2, 'SLEEP': 2}}}
        mappings = []
        if not rejected and not finish:
            mapping = {'request_id': label + '-step-0', 'root': identity, 'begin_ns': 40, 'end_ns': 50}
            if terminal:
                mapping.update(schema_version=1, event='MODEL_FUNCTION_BOUND', provider_function_call_id='provider-function',
                    observer_tool_call_id=tool_id, cgroup_id=123, agent_id=agent, task_id='task', budget_label=label, boot_id='boot',
                    command_sha256=M.sha(b'cat /app/a'))
            else: mapping.update(provider_tool_call_id='provider-function', tool_call_id=tool_id, docker_exec_id=gate['docker_exec_id'], command='cat /app/a')
            mappings.append(mapping)
        if terminal: lines(timeline / 'model-evidence/model-function-bindings.jsonl', mappings)
        app = {'mode': M.MODE, 'model': 'deepseek-flash', 'budget_label': label, 'boot_id': 'boot', 'clock': 'CLOCK_MONOTONIC',
            'termination': 'BUDGET_LIMIT' if rejected else 'MODEL_FINISH', 'usage': {'prompt_tokens': 0 if rejected else 10, 'completion_tokens': 0 if rejected else 1},
            'client_request_attempts': 1, 'request_attempts': 1, 'function_bindings' if terminal else 'mappings': mappings}
        app_name = 'model-evidence/model-agent.json' if terminal else 'application/agent-result.json'
        dump(timeline / app_name, app)
        files = {str(path.relative_to(timeline)): digest(path) for path in timeline.rglob('*') if path.is_file()}
        manifest = {'schema_version': 1, 'mode': M.MODE, 'boot_id': 'boot', 'run_id': 'run-' + label, 'agent_id': agent,
            'budget_label': label, 'begin_ns': 10, 'end_ns': 100, 'tools': [] if rejected or finish else [gate], 'artifacts': files}
        if terminal: manifest['model_application'] = {'budget_label': label, 'request_count': 1, 'function_bindings': len(mappings)}
        dump(timeline / 'manifest.json', manifest)
        worker = {'schema_version': 1, 'job_id': name, 'benchmark': benchmark, 'mode': M.MODE, 'budget_label': label,
            'timeline_directory': 'timeline', 'official_evaluated': True, 'official_passed': False,
            'official_result': {'resolved': False, 'reward': 0}, 'task_id': 'requests-1142' if not terminal else 'terminal-task' + str(index % 2),
            'agent_return_ns': 80, 'quiescent_ns': 90}
        dump(timeline.parent / 'worker-result.json', worker)
        verification = {'status': 'REPLAY_PASSED', 'manifest_identity': digest(timeline / 'manifest.json'),
            'worker_result_identity': digest(timeline.parent / 'worker-result.json')}
        dump(leaf / 'verification.json', verification)
        dump(leaf / 'summary.json', {'run': {'boot_id': 'boot', 'run_id': manifest['run_id']},
            'tools': [] if rejected or finish else [native_tool], 'selected_tool_timeline_status': 'NO_SELECTED_TOOLS' if rejected or finish else 'COMPLETE_WITHIN_SELECTED_TOOL_SCOPE',
            'whole_capture_attribution_status': 'UNASSIGNED_EVENTS_PRESENT'})
        accepted = {'mode': M.MODE, 'official_passed': False, 'verification': verification, 'health': {'status': 'COMPLETE_FOR_SELECTED_HOOKS'}}
        dump(leaf / 'acceptance.json', accepted)
        acceptance.append({'job_id': name, 'identity': digest(leaf / 'acceptance.json')})
        for filename in ('timeline.html', 'report.json'): dump(leaf / filename, b'tiny fixture')
        for filename in ('reads.csv', 'files.csv', 'excluded-reads.csv', 'unassigned-reads.csv'): dump(leaf / 'reads' / filename, b'fixture\n')
        originals.append({'job_id': name, 'release_issued_ns': 15, 'agent_return_ns': 80, 'quiescent_ns': 90})
        rows.append({'job_id': name, 'mode': M.MODE, 'source_run_id': manifest['run_id'], 'official_passed': False})
    campaign = {'schema_version': 1, 'benchmark': benchmark, 'concurrency': concurrency, 'total_jobs': 8,
        'boot_id': 'boot', 'batch_start_ns': 15, 'batch_end_ns': 90, 'jobs': originals}
    dump(root / 'campaign.json', campaign)
    dump(report / 'result.json', {'status': 'INDEPENDENT_LEAF_REPORTS_COMPOSED', 'total_jobs': 8,
        'source_campaign': {'path': str(root / 'campaign.json'), **digest(root / 'campaign.json')},
        'jobs': rows, 'leaf_acceptance': acceptance, 'timing': {'batch_wall_ns': 75, 'campaign_wall_ns': 150}})
    dump(resources / 'receipt.json', {'run': {'benchmark': benchmark, 'concurrency': concurrency, 'boot_id': 'boot', 'begin_ns': 15, 'end_ns': 90, 'total_jobs': 8},
        'sources': {'campaign.json': digest(root / 'campaign.json')}})
    for directory, names in ((report, ('index.html', 'timeline.html', 'jobs.csv', 'resources.csv')),
            (resources, ('index.html', 'guest-series.csv', 'cgroup-series.csv'))):
        for name in names: dump(directory / name, b'fixture')
    return report, root, resources


def make_ledger(path, groups):
    labels = [{'label': f'model-{bench}-c{concurrency}-{index:02d}', 'kind': 'FORMAL', 'cap_rmb': '.065'}
        for bench in ('swe', 'terminal') for concurrency in (2, 4, 6, 8) for index in range(8)]
    price = {'model': 'deepseek-flash', 'currency': 'CNY', 'input_rmb_per_million': '2', 'output_rmb_per_million': '8'}
    config = {'schema_version': 2, 'global_limit_rmb': '4.2', 'historical_bound_rmb': '.468350', 'labels': labels, 'pricing': price}
    key = M.sha(M.wire(config)); events = [{'event': 'CONFIGURED', 'config': config, 'config_sha256': key}]
    for group in groups:
        for job in group['jobs']:
            for request in job['application']['requests']:
                if request['status'] != 'RECEIVED': continue
                prompt, completion = request['normalized_input_tokens_bound'], request['max_output_tokens']
                reserve = {'event': 'RESERVED', 'request_id': request['request_id'], 'task_label': request['budget_label'],
                    'config_sha256': key, 'pricing': price, 'request_sha256': request['normalized_payload_sha256'],
                    'input_tokens_bound': prompt, 'output_tokens_bound': completion,
                    'cost_rmb_bound': str((M.Decimal(prompt) * 2 + M.Decimal(completion) * 8) / 1000000)}
                settled = {'event': 'SETTLED', 'request_id': request['request_id'], 'task_label': request['budget_label'],
                    'config_sha256': key, 'prompt_tokens': 10, 'completion_tokens': 1, 'cost_rmb_bound': '.000028'}
                events += [reserve, settled]
    lines(path, events)
    return events


class ModelResultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_swe_explicit_mapping_reward_zero_and_waits_separate(self):
        result = M.export_group(*make_group(self.root), self.root / 'app')
        self.assertEqual(len(result['jobs']), 8)
        job = result['jobs'][0]; app = job['application']
        self.assertFalse(job['official_passed'])
        self.assertTrue(job['official_evaluated'])
        self.assertEqual(app['client_wait_union_ns'], 10)
        mapping = app['requests'][0]['tool_mappings'][0]
        self.assertEqual(mapping['root_key'], 'boot:10:1')
        self.assertEqual(mapping['completion_path']['state_totals_ns']['RUNNABLE'], 2)
        page = (self.root / 'app/index.html').read_text()
        for text in ('未通过（原始得分保留）', 'API客户端等待', '显式模型工具', '不能解释远端GPU', 'UNASSIGNED_EVENTS_PRESENT', 'UNKNOWN', '八个Agent共享时轴', 'summary.csv'):
            self.assertIn(text, page)

    def test_terminal_schema_and_no_inferred_paid_call_count(self):
        result = M.export_group(*make_group(self.root, M.BENCHMARKS[1]), self.root / 'terminal')
        self.assertEqual(result['jobs'][0]['application']['request_attempts'], 1)
        self.assertEqual(result['jobs'][0]['application']['requests'][0]['tool_mappings'][0]['tool_call_id'], 'model-terminal-c2-00-exec-0')

    def test_finish_zero_native_tools_does_not_invent_bash(self):
        result = M.export_group(*make_group(self.root, M.BENCHMARKS[1], finish=True), self.root / 'finish')
        self.assertEqual(result['jobs'][0]['application']['requests'][0]['tool_mappings'], [])
        self.assertEqual(result['jobs'][0]['native_tools'], [])
        self.assertEqual(result['jobs'][0]['selected_tool_timeline_status'], 'NO_SELECTED_TOOLS')

    def test_budget_rejected_attempt_retained_and_not_automatically_paid(self):
        inputs = make_group(self.root, rejected=True)
        group = M.compose_group(*inputs, M.Sources())
        path = self.root / 'ledger.jsonl'; make_ledger(path, [group])
        result = M.export_group(*inputs, self.root / 'rejected', path)
        request = result['jobs'][0]['application']['requests'][0]
        self.assertEqual(request['status'], 'BUDGET_OR_REQUEST_LIMIT')
        self.assertEqual(request['broker_status'], 'REJECTED_BEFORE_RESERVATION')
        self.assertEqual(request['accounted_cost_rmb_bound'], '0')
        self.assertEqual(request['application_status'], 'PAIRED_DECLARED_CLIENT_WAIT')

    def test_artifact_tamper_is_rejected(self):
        inputs = make_group(self.root)
        path = inputs[1] / 'jobs/swe-00/timeline/application/api/model-requests.jsonl'
        path.write_bytes(path.read_bytes() + b'{}\n')
        with self.assertRaisesRegex(ValueError, 'saved receipt'): M.export_group(*inputs, self.root / 'tampered')

    def test_boot_clock_or_unbound_artifact_cannot_be_accepted(self):
        inputs = make_group(self.root)
        timeline = inputs[1] / 'jobs/swe-00/timeline'
        manifest = json.loads((timeline / 'manifest.json').read_bytes())
        worker = json.loads((timeline.parent / 'worker-result.json').read_bytes())
        summary = json.loads((inputs[0] / 'reports/swe-00/summary.json').read_bytes())
        manifest['artifacts'].pop('application/agent-result.json')
        with self.assertRaisesRegex(ValueError, 'not manifest-bound'): M.bound_application(timeline, manifest, summary, worker, M.Sources())
        events, transcript = request_fixture('model-swe-c2-00')
        events[-1]['clock'] = 'CLOCK_REALTIME'
        with self.assertRaisesRegex(ValueError, 'boot/clock'): M.application_requests(events, transcript, 'boot', 'model-swe-c2-00')

    def test_missing_request_end_preserves_unknown_duration(self):
        events, transcript = request_fixture('model-swe-c2-00')
        rows = M.application_requests(events[:1], transcript[:1], 'boot', 'model-swe-c2-00')
        self.assertIsNone(rows[0]['client_wait_ns'])
        self.assertIsNone(rows[0]['end_ns'])
        self.assertEqual(rows[0]['application_status'], 'UNPAIRED_APPLICATION_EVENT')

    def test_fake_provider_or_smoke_cannot_be_labeled_formal(self):
        inputs = make_group(self.root)
        directory = inputs[1] / 'jobs/swe-00/timeline'
        requests = directory / 'application/api/model-requests.jsonl'
        transcript = directory / 'application/api/model-transcript.jsonl'
        events = [json.loads(row) for row in requests.read_bytes().splitlines()]
        records = [json.loads(row) for row in transcript.read_bytes().splitlines()]
        events[-1]['response_model'] = 'FAKE_PROVIDER_NO_API'
        records[-1]['response']['model'] = 'FAKE_PROVIDER_NO_API'
        requests.write_bytes(b''.join(M.wire(row) + b'\n' for row in events))
        transcript.write_bytes(b''.join(M.wire(row) + b'\n' for row in records))
        manifest_path = directory / 'manifest.json'; manifest = json.loads(manifest_path.read_bytes())
        for path in (requests, transcript): manifest['artifacts'][str(path.relative_to(directory))] = digest(path)
        manifest_path.write_bytes(M.wire(manifest))
        leaf = inputs[0] / 'reports/swe-00'
        verification_path = leaf / 'verification.json'; verification = json.loads(verification_path.read_bytes())
        verification['manifest_identity'] = digest(manifest_path); verification_path.write_bytes(M.wire(verification))
        acceptance_path = leaf / 'acceptance.json'; acceptance = json.loads(acceptance_path.read_bytes())
        acceptance['verification'] = verification; acceptance_path.write_bytes(M.wire(acceptance))
        result_path = inputs[0] / 'result.json'; result = json.loads(result_path.read_bytes())
        result['leaf_acceptance'][0]['identity'] = digest(acceptance_path); result_path.write_bytes(M.wire(result))
        with self.assertRaisesRegex(ValueError, 'fake provider'): M.export_group(*inputs, self.root / 'fake')

    def test_wrong_root_mapping_cannot_be_rescued_by_nearby_time(self):
        inputs = make_group(self.root)
        timeline = inputs[1] / 'jobs/swe-00/timeline'
        manifest = json.loads((timeline / 'manifest.json').read_bytes())
        worker = json.loads((timeline.parent / 'worker-result.json').read_bytes())
        summary = json.loads((inputs[0] / 'reports/swe-00/summary.json').read_bytes())
        path = timeline / 'application/agent-result.json'; value = json.loads(path.read_bytes())
        value['mappings'][0]['root']['tid'] = 999
        path.write_bytes(M.wire(value)); manifest['artifacts']['application/agent-result.json'] = digest(path)
        with self.assertRaisesRegex(ValueError, 'gate root'): M.bound_application(timeline, manifest, summary, worker, M.Sources())

    def test_ledger_cost_usage_and_payload_binding_are_independent(self):
        inputs = make_group(self.root)
        group = M.compose_group(*inputs, M.Sources())
        path = self.root / 'ledger.jsonl'; events = make_ledger(path, [group])
        result = M.export_group(*inputs, self.root / 'accounted', path)
        self.assertEqual(result['jobs'][0]['accounting']['cost_rmb_bound'], '0.000028')
        self.assertEqual(result['ledger']['accounted_cost_rmb_bound'], '0.000224')
        events[1]['request_sha256'] = 'd' * 64
        other = self.root / 'wrong-ledger.jsonl'; lines(other, events)
        with self.assertRaisesRegex(ValueError, 'broker explicit request binding'): M.export_group(*inputs, self.root / 'wrong', other)

    def test_unknown_charge_keeps_entire_reservation_in_report(self):
        inputs = make_group(self.root)
        group = M.compose_group(*inputs, M.Sources())
        path = self.root / 'ledger.jsonl'; events = make_ledger(path, [group])
        events[2] = {**events[2], 'event': 'UNKNOWN_CHARGE', 'cost_rmb_bound': events[1]['cost_rmb_bound']}
        path.write_bytes(b''.join(M.wire(row) + b'\n' for row in events))
        result = M.export_group(*inputs, self.root / 'unknown', path)
        self.assertEqual(result['jobs'][0]['application']['requests'][0]['broker_status'], 'UNKNOWN_CHARGE')
        self.assertEqual(result['jobs'][0]['accounting']['cost_rmb_bound'], events[1]['cost_rmb_bound'])
        self.assertEqual(result['accounting_findings'][0]['kind'], 'UNKNOWN_CHARGE')

    def test_formal_matrix_requires_all8_and_does_not_mix_oracle(self):
        inputs = make_group(self.root)
        result = M.export_group(*inputs, self.root / 'single')
        with self.assertRaisesRegex(ValueError, 'exactly eight'): M.export_matrix([self.root / 'single'], self.root / 'ledger.jsonl', self.root / 'partial')
        path = inputs[0] / 'result.json'; document = json.loads(path.read_bytes()); document['jobs'][0]['mode'] = 'ORACLE_REFERENCE'
        path.write_bytes(M.wire(document))
        with self.assertRaisesRegex(ValueError, 'Oracle mixing'): M.compose_group(*inputs, M.Sources())
        self.assertEqual(result['mode'], M.MODE)
        document['jobs'][0]['mode'] = M.MODE
        document['jobs'][1] = document['jobs'][0]
        path.write_bytes(M.wire(document))
        with self.assertRaisesRegex(ValueError, 'eight unique'): M.compose_group(*inputs, M.Sources())

    def test_complete64_job_matrix_and_csv_zero_scores_are_retained(self):
        records, directories = [], []
        for benchmark in M.BENCHMARKS:
            for concurrency in (2, 4, 6, 8):
                inputs = make_group(self.root, benchmark, concurrency)
                directory = self.root / ('model-' + ('swe' if benchmark == M.BENCHMARKS[0] else 'terminal') + str(concurrency))
                records.append(M.export_group(*inputs, directory)); directories.append(directory)
        ledger = self.root / 'ledger.jsonl'; make_ledger(ledger, records)
        result = M.export_matrix(directories, ledger, self.root / 'matrix')
        self.assertEqual(result['job_rows'], 64)
        self.assertEqual(sum(job['official_passed'] for group in result['groups'] for job in group['jobs']), 0)
        with (self.root / 'matrix/jobs.csv').open(newline='') as stream: rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 64)
        self.assertTrue(all(row['official_passed'] == 'False' for row in rows))
        self.assertTrue(all(job['accounting']['cost_rmb_bound'] == '0.000028' for group in result['groups'] for job in group['jobs']))
        with self.assertRaisesRegex(ValueError, 'fresh'): M.export_matrix(directories, ledger, self.root / 'matrix')


if __name__ == '__main__': unittest.main()
