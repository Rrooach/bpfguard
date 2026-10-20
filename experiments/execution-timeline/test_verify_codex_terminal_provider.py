"""Entirely synthetic offline fixtures: no provider, Docker or native capture."""
import copy
from decimal import Decimal
from pathlib import Path
import tempfile
import unittest

from common import digest, write_new
import verify_codex_terminal_provider as V


class TerminalProviderTests(unittest.TestCase):
    mode = 'terminal'
    concurrency = 2

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.group = self.root / 'group'; self.group.mkdir()
        pricing = {'model': V.budget.MODEL, 'currency': 'CNY', 'input_rmb_per_million': '2', 'output_rmb_per_million': '8'}
        self.ledger = V.budget.Ledger(self.root / 'ledger', V.proxy.registration('OFFLINE_SYNTHETIC', self.mode),
            pricing, '4.0', provider_endpoint=V.proxy.ENDPOINT)
        self.addCleanup(self.ledger.close)
        self.campaign = {'schema_version': 1, 'benchmark': 'Terminal-Bench', 'concurrency': self.concurrency, 'boot_id': 'boot', 'jobs': []}
        self.data = []
        for index in range(8):
            self.make_job(index)
        self.save_campaign()

    def save_campaign(self):
        (self.group / 'campaign.json').write_bytes(V.budget.canonical(self.campaign))

    def save_manifest(self, index):
        row = self.data[index]
        root, manifest = row['timeline'], row['manifest']
        manifest['artifacts'] = {str(path.relative_to(root)): digest(path) for path in root.rglob('*')
            if path.is_file() and path.name != 'manifest.json'}
        manifest['codex_application']['artifacts'] = {name: identity for name, identity in manifest['artifacts'].items()
            if name.startswith('app/')}
        (root / 'manifest.json').write_bytes(V.budget.canonical(manifest))

    def save_app(self, index):
        row = self.data[index]; app = row['timeline'] / 'app'
        for name in ('steps.json', 'codex-result.json'):
            (app / name).write_bytes(V.budget.canonical(row['steps']))
        (app / 'codex-agent.json').write_bytes(V.budget.canonical(row['state']))
        self.save_manifest(index)

    def save_provider(self, index):
        row = self.data[index]
        key, response = row['request_id'], row['response']
        raw = b'data: ' + V.budget.canonical(response) + b'\n\n'
        path = self.ledger.directory / (key + '-upstream.sse'); path.write_bytes(raw)
        receipt = {'request_id': key, 'request_sha256': row['reservation']['request_sha256'], 'response_file': path.name,
            'response_sha256': V.budget.sha(raw), 'response_bytes': len(raw), 'upstream_endpoint': V.proxy.ENDPOINT}
        (self.ledger.directory / (key + '-response.json')).write_bytes(V.budget.canonical(receipt))

    def make_job(self, index):
        name, label, call = f'terminal-{index:02d}', f'codex-terminal-c{self.concurrency}-{index:02d}', f'call-{index}'
        task, agent = 'terminal-bench/task', 'codex-agent:' + label
        directory = self.group / 'jobs' / name; timeline = directory / 'timelines' / 'task'
        app = timeline / 'app'; app.mkdir(parents=True)
        controller = {'job_id': name, 'task_id': task, 'output': '/guest/group/jobs/' + name}
        self.campaign['jobs'].append(controller)
        root = {'tid': index + 100, 'start_ticks': 100, 'clock_ticks': 100}
        command, stdout, stderr = 'printf fixture-' + str(index), 'ok', ''
        span = {'tool_call_id': label + '-exec-0001', 'agent_id': agent, 'task_id': task, 'command': command,
            'root': root, 'cgroup_id': 50 + index, 'begin_ns': 100, 'end_ns': 200, 'invocation_ns': 99,
            'result': {'return_code': 0}}
        binding = {'call_id': call, 'rpc_request_id': index, 'command': command, 'root': root,
            'agent_id': agent, 'task_id': task, 'boot_id': 'boot', 'budget_label': label,
            'tool_call_id': span['tool_call_id'], 'cgroup_id': span['cgroup_id'], 'begin_ns': 100, 'end_ns': 200,
            'stdout_artifact': 'app/tool-0001.stdout', 'stderr_artifact': 'app/tool-0001.stderr',
            'command_sha256': V.budget.sha(command.encode()), 'gate_result': span['result']}
        enriched = dict(binding, thread_id='thread-' + str(index), turn_id='turn-' + str(index), tool='observer_bash')
        steps = {'schema_version': 1, 'model': V.budget.MODEL, 'agent_loop': V.AGENT_LOOP, 'status': 'completed',
            'thread_id': enriched['thread_id'], 'turn_id': enriched['turn_id'], 'function_bindings': [enriched],
            'steps': [{'kind': 'TOOL_CALL', **enriched, 'stdout': stdout, 'stderr': stderr, 'exit_code': 0},
                {'kind': 'AGENT_MESSAGE', 'text': 'done-' + str(index)}]}
        identity = {'agent_id': agent, 'task_id': task, 'boot_id': 'boot', 'budget_label': label, 'mode': 'MODEL_AGENT',
            'agent_implementation': V.IMPLEMENTATION, 'model': V.budget.MODEL, 'termination': 'CODEX_COMPLETED'}
        binary = {'sha256': V.CODEX_SHA256, 'size_bytes': 123}
        runtime = {'binary_identity': binary, 'kernel_observed': False}
        state = dict(identity, function_bindings=[binding], runtime=runtime)
        if self.mode == 'terminal-v2': state['max_output_tokens_enforced_by_external_broker'] = 4096
        manifest = {'schema_version': 1, 'run_id': 'run-' + str(index), 'boot_id': 'boot', 'agent_id': agent,
            'budget_label': label, 'mode': 'MODEL_AGENT', 'tools': [span],
            'codex_application': dict(identity, function_bindings=1, agent_loop=V.AGENT_LOOP, runtime=runtime)}
        worker = {'schema_version': 1, 'benchmark': 'Terminal-Bench', 'job_id': name, 'task_id': task,
            'budget_label': label, 'agent_id': agent, 'mode': 'MODEL_AGENT', 'agent_implementation': V.IMPLEMENTATION,
            'timeline_directory': 'timelines/task', 'model_termination': 'CODEX_COMPLETED',
            'official_evaluated': True, 'official_passed': False}
        write_new(directory / 'worker-result.json', worker)
        write_new(timeline / 'tool-spans.jsonl', b''.join(V.budget.canonical({'event': event, **span})
            + b'\n' for event in ('TOOL_ENROLLED', 'TOOL_START', 'TOOL_END')))
        write_new(app / 'function-bindings.jsonl', V.budget.canonical(enriched) + b'\n')
        write_new(app / 'docker-function-bindings.jsonl', V.budget.canonical(binding) + b'\n')
        rpc = {'direction': 'CODEX_TO_CLIENT', 'clock': 'CLOCK_MONOTONIC', 'boot_id': 'boot', 'message': {
            'id': index, 'method': 'item/tool/call', 'params': {'tool': 'observer_bash', 'callId': call,
            'threadId': enriched['thread_id'], 'turnId': enriched['turn_id'], 'arguments': {'command': command}}}}
        write_new(app / 'rpc.jsonl', V.budget.canonical(rpc) + b'\n')
        write_new(app / 'tool-0001.stdout', stdout.encode()); write_new(app / 'tool-0001.stderr', stderr.encode())
        write_new(app / 'model-catalog.json', b'{"OFFLINE_SYNTHETIC":true}')
        configuration = {'model': V.budget.MODEL, 'model_providers.observer_proxy.wire_api': 'responses'}
        if self.mode == 'terminal-v2': configuration['model_reasoning_effort'] = 'none'
        write_new(app / 'config.public.json', {'agent_loop': V.IMPLEMENTATION, 'budget_label': label,
            'codex_identity': binary, 'model_catalog_identity': digest(app / 'model-catalog.json'),
            'http_headers': {'X-Benchmark-Task': label},
            'config': configuration})
        key = label + '-step-0'
        request = V.budget.canonical({'model': V.budget.MODEL, 'max_output_tokens': 4096,
            'reasoning': {'effort': 'none'}, 'input': 'OFFLINE_ONLY', 'stream': True, 'store': False,
            'tools': [{'type': 'function', 'name': 'observer_bash', 'parameters': {}}]})
        reservation = self.ledger.reserve(request if self.mode == 'terminal-v2' else b'offline-only',
            4096 if self.mode == 'terminal-v2' else 1024, label, key)
        if self.mode == 'terminal-v2': write_new(self.ledger.directory / (key + '-request.json'), request)
        self.ledger.settle(reservation, {'prompt_tokens': 100, 'completion_tokens': 10}, V.budget.MODEL)
        response = {'type': 'response.completed', 'response': {'model': V.budget.MODEL, 'id': 'OFFLINE-' + str(index),
            'usage': {'input_tokens': 100, 'output_tokens': 10, 'total_tokens': 110}, 'output': [
                {'type': 'function_call', 'name': 'observer_bash', 'call_id': call,
                    'arguments': V.budget.canonical({'command': command}).decode()},
                {'type': 'message', 'content': [{'type': 'output_text', 'text': 'done-' + str(index)}]}]}}
        data_index = len(self.data)
        self.data.append({'timeline': timeline, 'manifest': manifest, 'state': state, 'steps': steps,
            'response': response, 'request_id': key, 'reservation': reservation})
        self.save_app(data_index); self.save_provider(data_index)

    def verify(self):
        return V.verify(self.group, self.ledger.path)

    def test_eight_exact_provider_commands_answers_and_costs(self):
        result = self.verify()
        self.assertEqual(result['status'], 'PROVIDER_BINDING_VERIFIED')
        self.assertEqual(len(result['jobs']), 8)
        self.assertEqual(result['group_cost_rmb_upper_bound'], '0.00224')
        self.assertEqual(result['all_terminal_campaign_cost_rmb_upper_bound'], '0.00224')
        self.assertTrue(all(not row['official_passed'] for row in result['jobs']))
        self.assertFalse(result['raw_evidence_rewritten'])

    def test_failed_turn_is_not_promoted_to_completed_and_needs_no_final_answer(self):
        row = self.data[0]; row['steps']['status'] = 'failed'; row['steps']['steps'].pop()
        row['state']['termination'] = row['manifest']['codex_application']['termination'] = 'CODEX_FAILED'
        path = row['timeline'].parents[1] / 'worker-result.json'; worker = V.load(path)
        worker['model_termination'] = 'CODEX_FAILED'; path.write_bytes(V.budget.canonical(worker))
        row['response']['response']['output'].pop(); self.save_provider(0); self.save_app(0)
        result = self.verify()
        self.assertEqual(result['jobs'][0]['agent_turn_status'], 'failed')
        self.assertFalse(result['jobs'][0]['completed_final_answer_matched'])
        self.assertEqual(result['jobs'][0]['status'], 'PROVIDER_BINDING_VERIFIED')

    def test_completed_missing_final_answer_stays_inconclusive(self):
        self.data[0]['response']['response']['output'].pop(); self.save_provider(0)
        result = self.verify()
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertIn('COMPLETED_TURN_FINAL_ANSWER_EVIDENCE_MISSING', result['jobs'][0]['issues'])

    def test_official_verifier_timeout_remains_unscored_with_typed_exception(self):
        path = self.data[0]['timeline'].parents[1] / 'worker-result.json'; worker = V.load(path)
        worker['official_evaluated'] = False
        worker['official_result'] = {'harbor_rewards': None, 'harbor_exception': {
            'exception_type': 'VerifierTimeoutError', 'exception_message': '1800 second timeout'}}
        path.write_bytes(V.budget.canonical(worker))
        result = self.verify(); row = result['jobs'][0]
        self.assertEqual(row['status'], 'PROVIDER_BINDING_VERIFIED')
        self.assertEqual(row['official_scoring_status'], 'UNSCORED')
        self.assertEqual(row['official_result']['harbor_exception']['exception_type'], 'VerifierTimeoutError')
        self.assertIsNone(row['official_result']['harbor_rewards'])

    def test_provider_call_cannot_be_borrowed_from_another_job(self):
        first, second = self.data[:2]
        first['response']['response']['output'][0]['call_id'] = 'call-1'
        self.save_provider(0)
        result = self.verify()
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertIn('EXACT_PROVIDER_CALL_EVIDENCE_MISSING', result['jobs'][0]['issues'])

    def test_provider_command_tamper_rejected_even_with_updated_source_receipt(self):
        self.data[0]['response']['response']['output'][0]['arguments'] = '{"command":"different"}'
        self.save_provider(0)
        with self.assertRaisesRegex(ValueError, 'provider command differs'): self.verify()

    def test_usage_tamper_rejected(self):
        self.data[0]['response']['response']['usage']['output_tokens'] = 9; self.save_provider(0)
        with self.assertRaisesRegex(ValueError, 'usage/model differs'): self.verify()

    def test_original_source_digest_tamper_rejected(self):
        path = self.ledger.directory / (self.data[0]['request_id'] + '-upstream.sse')
        path.write_bytes(path.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'source binding differs'): self.verify()

    def test_app_artifact_tamper_rejected(self):
        path = self.data[0]['timeline'] / 'app/tool-0001.stdout'; path.write_text('altered')
        with self.assertRaisesRegex(ValueError, 'artifact binding differs'): self.verify()

    def test_rpc_command_cannot_change_even_if_app_hashes_are_replaced(self):
        path = self.data[0]['timeline'] / 'app/rpc.jsonl'; rows = V.jsonl(path)
        rows[0]['message']['params']['arguments']['command'] = 'different'
        path.write_bytes(V.budget.canonical(rows[0]) + b'\n'); self.save_manifest(0)
        with self.assertRaisesRegex(ValueError, 'explicit Codex RPC command/ID differs'): self.verify()

    def test_wrong_official_codex_binary_identity_rejected(self):
        self.data[0]['state']['runtime']['binary_identity']['sha256'] = '0' * 64
        self.save_app(0)
        with self.assertRaisesRegex(ValueError, 'pinned official Codex binary'): self.verify()

    def test_tool_exit_cannot_be_changed_independently_of_docker_result(self):
        self.data[0]['steps']['steps'][0]['exit_code'] = 22; self.save_app(0)
        with self.assertRaisesRegex(ValueError, 'tool exit code differs'): self.verify()

    def test_mutated_gate_span_rejected_against_immutable_tool_end(self):
        self.data[0]['manifest']['tools'][0]['codex_call_id'] = 'late mutation'; self.save_manifest(0)
        with self.assertRaisesRegex(ValueError, 'final span differs'): self.verify()

    def test_budget_cost_tamper_rejected_by_independent_replay(self):
        rows = V.jsonl(self.ledger.path); rows[-1]['cost_rmb_bound'] = '0'
        self.ledger.path.write_bytes(b''.join(V.budget.canonical(row) + b'\n' for row in rows))
        with self.assertRaisesRegex(ValueError, 'settlement cost differs'): self.verify()

    def test_unknown_charge_preserved_instead_of_turned_green(self):
        label = 'codex-terminal-c2-00'
        item = self.ledger.reserve(b'unknown offline', 1024, label, label + '-step-1')
        self.ledger.unknown(item, 'synthetic timeout')
        result = self.verify()
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertEqual(result['outstanding_or_unknown_requests'], 1)
        self.assertEqual(Decimal(result['group_cost_rmb_upper_bound']), Decimal('0.00224') + Decimal(item['cost_rmb_bound']))

    def test_pending_request_in_other_group_prevents_global_green(self):
        label = 'codex-terminal-c8-00'; self.ledger.reserve(b'pending', 1024, label, label + '-step-0')
        result = self.verify()
        self.assertEqual(result['jobs'][0]['status'], 'PROVIDER_BINDING_VERIFIED')
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertEqual(result['outstanding_or_unknown_requests'], 1)

    def test_duplicate_or_wrong_concurrency_job_labels_rejected(self):
        path = self.data[0]['timeline'].parents[1] / 'worker-result.json'; worker = V.load(path)
        worker['budget_label'] = 'codex-terminal-c4-00'; path.write_bytes(V.budget.canonical(worker))
        with self.assertRaisesRegex(ValueError, 'distinct registered concurrency'): self.verify()

    def test_truncated_ledger_rejected(self):
        self.ledger.path.write_bytes(self.ledger.path.read_bytes()[:-1])
        with self.assertRaisesRegex(ValueError, 'complete budget ledger'): self.verify()


class TerminalV2ProviderTests(TerminalProviderTests):
    mode = 'terminal-v2'

    def test_new_version_is_separate_and_records4096_and_none(self):
        result = self.verify()
        self.assertEqual(result['registration_kind'], 'CODEX_TERMINAL_2468_V2')
        self.assertEqual(result['model_max_output_tokens'], 4096)
        self.assertEqual(result['reasoning_effort'], 'none')

    def test_v2_app_cannot_remain_on_low_reasoning(self):
        path = self.data[0]['timeline'] / 'app/config.public.json'; public = V.load(path)
        public['config']['model_reasoning_effort'] = 'low'; path.write_bytes(V.budget.canonical(public))
        self.save_manifest(0)
        with self.assertRaisesRegex(ValueError, 'Terminal V2 app must explicitly'): self.verify()

    def test_actual_normalized_request_cannot_be_changed_to_low_reasoning(self):
        path = self.ledger.directory / (self.data[0]['request_id'] + '-request.json'); request = V.load(path)
        request['reasoning']['effort'] = 'low'; path.write_bytes(V.budget.canonical(request))
        with self.assertRaisesRegex(ValueError, 'V2 normalized request digest'): self.verify()

    def test_settled_v2_requires_original_normalized_request_bytes(self):
        path = self.ledger.directory / (self.data[0]['request_id'] + '-request.json')
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'settled V2 normalized request is missing'): self.verify()


class CampaignSealTests(unittest.TestCase):
    def setUp(self):
        self.builder = TerminalV2ProviderTests('test_new_version_is_separate_and_records4096_and_none')
        self.builder.setUp(); self.addCleanup(self.builder.doCleanups)
        b = self.builder; self.root, self.ledger = b.root, b.ledger
        b.group.rename(self.root / 'terminal-c2-r001')
        for count in (4, 6, 8):
            b.concurrency = count; b.group = self.root / f'terminal-c{count}-r001'; b.group.mkdir()
            b.campaign = {'schema_version': 1, 'benchmark': 'Terminal-Bench', 'concurrency': count,
                'boot_id': 'boot', 'jobs': []}
            for index in range(8): b.make_job(index)
            b.save_campaign()
        self.summary = self.ledger.directory / 'budget-summary-fixture.json'
        write_new(self.summary, self.ledger.summary())
        self.ledger.close()
        self.receipts = []
        for count in (2, 4, 6, 8):
            path = self.root / f'provider-c{count}-final.json'
            write_new(path, V.verify(self.root / f'terminal-c{count}-r001', self.ledger.path))
            self.receipts.append(path)

    def seal(self):
        return V.seal_campaign(self.root, self.ledger.path, [], self.receipts, self.summary)

    def test_closed32_job_request_seal_and_exact_sha_evidence(self):
        value = self.seal()
        self.assertEqual(value['status'], 'CLOSED_LEDGER_CHAIN_AND_FOUR_GROUP_PROVIDER_BINDINGS_VERIFIED')
        self.assertEqual(value['formal_jobs'], 32)
        self.assertEqual(value['formal_reserved_requests'], 32)
        self.assertEqual(value['formal_settled_requests'], 32)
        self.assertEqual(len(value['formal_request_evidence']), 32)
        self.assertEqual(value['outstanding_or_unknown_requests'], 0)
        self.assertEqual(value['formal_cost_rmb_upper_bound'], '0.00896')

    def test_prior_history_cannot_be_silently_omitted(self):
        rows = V.jsonl(self.ledger.path)
        rows[0]['config']['prior_budget_evidence'] = {'missing': 'actual required ledger'}
        rows[0]['config_sha256'] = V.budget.sha(V.budget.canonical(rows[0]['config']))
        for row in rows[1:]: row['config_sha256'] = rows[0]['config_sha256']
        self.ledger.path.write_bytes(b''.join(V.budget.canonical(row) + b'\n' for row in rows))
        with self.assertRaisesRegex(ValueError, 'does not reach'): self.seal()

    def test_stale_interim_group_receipt_cannot_enter_final_seal(self):
        path = self.receipts[0]; value = V.load(path)
        value['budget_ledger_identity']['sha256'] = '0' * 64; path.write_bytes(V.budget.canonical(value))
        with self.assertRaisesRegex(ValueError, 'interim, incomplete'): self.seal()

    def test_closed_summary_must_exactly_match_replayed_fees(self):
        summary = V.load(self.summary); summary['accounted_cost_rmb_upper_bound'] = '0'
        self.summary.write_bytes(V.budget.canonical(summary))
        with self.assertRaisesRegex(ValueError, 'closed broker summary differs'): self.seal()

    def test_missing_group_receipt_cannot_claim_final_campaign(self):
        with self.assertRaisesRegex(ValueError, 'four final group'):
            V.seal_campaign(self.root, self.ledger.path, [], self.receipts[:3], self.summary)


if __name__ == '__main__':
    unittest.main()
