import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_access_results as gate
import test_access_select as select_fixtures


SPEC = importlib.util.spec_from_file_location('final_gate_collector_test_fixtures',
    Path(__file__).resolve().parent.parent / 'file-profile/test_access_analyze.py')
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)


class FinalGateTests(unittest.TestCase):
    """Synthetic receipts test the acceptance gate, not 160 real executions."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        factory = select_fixtures.SelectionTests(methodName='runTest')
        factory.setUp()
        self.addCleanup(factory.doCleanups)
        self.matrix = copy.deepcopy(factory.base)
        self.matrix.update(schedule=factory.plans, campaigns=[factory.entry(i) for i in range(160)])
        self.raw_root = self.root / 'selected'
        self.raw_root.mkdir()
        self.matrix_path = self.raw_root / 'matrix.json'
        self.write(self.matrix_path, self.matrix)
        self.batch_root = self.root / 'analyses'
        self.batch_root.mkdir()
        self.attempt = 'a' * 32
        self.batch_path = self.batch_root / ('attempt-' + self.attempt + '.json')
        self.cache_root = self.root / 'cache'
        self.cache_root.mkdir()
        self.receipts = self.cache_root / 'receipts'
        self.receipts.mkdir()
        self.cache_index = self.cache_root / 'index.json'
        self.report_path = self.root / 'comparison.json'
        self.selection_path = self.root / 'selection-verification.json'
        self.write(self.selection_path, {'verified': True,
            'status': 'VERIFIED_PAUSE_SELECTION_WITH_DECLARED_SCOPE', 'matrix_sha256': self.sha(self.matrix_path),
            'fixed_work_verification': {'verified': True, 'status': 'VERIFIED_WITH_DECLARED_SCOPE',
                'matrix_sha256': self.sha(self.matrix_path), 'total_trials': 160, 'unique_runs': 160,
                'actual_stdout_files_hashed': 1280, 'logical_queries_verified': 1280}})
        template = self.root / 'collector-template'
        template.mkdir()
        self.meta, self.final, self.capture = FIXTURES.AccessAnalyzeTests(methodName='runTest').kprobe_bundle(template)
        self.raw_event = (template / 'collector/events.bin').read_bytes()
        self.final['hash_error'] = None
        self.final['observation_health'] = 'COMPLETE_FOR_SELECTED_HOOKS'
        self.results, self.plan_cases, self.trials = {}, [], []
        for index, entry in enumerate(self.matrix['campaigns']):
            self.make_case(index, entry)
        selection = json.loads(self.selection_path.read_text())
        selection['fixed_work_verification']['read_artifacts'] = {
            str(path.resolve()): self.ref(path) for path in self.raw_root.rglob('*.json')}
        self.write(self.selection_path, selection)
        plan = {'available_full_detail_cases': 80, 'selected_prefix_limit': None,
            'matrix': self.ref(self.matrix_path), 'analyzer_sha256': 'f' * 64,
            'inventory_database': {'sha256': 'e' * 64}, 'cases': self.plan_cases,
            'omitted_sampler_cases': [entry['path'] for entry in self.matrix['campaigns']
                if entry['condition']['file_access_mode'] == 'sampler'],
            'full_campaign_last_end_ns': max(row['execution_window'][1] for row in self.trials)}
        self.write(self.batch_root / 'plan.json', plan)
        self.batch = {'schema_version': 1, 'attempt': self.attempt,
            'status': 'COMPLETE_FOR_SELECTED_CASES', 'selected_cases': 80,
            'available_full_detail_cases': 80, 'selected_prefix_limit': None,
            'results': self.results, 'failures': {}}
        self.write(self.batch_path, self.batch)
        receipt = gate.compare.load_analysis_receipt(self.batch_path)['source']
        for row in self.trials:
            row['file_analysis_receipt'] = receipt
        self.report = self.make_report(receipt)
        self.write(self.report_path, self.report)
        gate.index_cache(self.matrix_path, self.receipts, self.cache_index)

    @staticmethod
    def write(path, value):
        Path(path).write_text(json.dumps(value), encoding='utf-8')

    @staticmethod
    def sha(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def ref(self, path):
        return {'path': str(path), 'sha256': self.sha(path), 'bytes': Path(path).stat().st_size}

    def make_case(self, index, entry):
        case_id = entry['path']
        case = self.raw_root / case_id
        case.mkdir()
        trial_dir = case / 'trials/one'
        trial_dir.mkdir(parents=True)
        cfg = dict(entry['condition'], jobs=8, passes=1, cpus=[0, 1, 2, 3])
        begin = (index + 1) * 10000000000
        duration = 2000000000 if cfg['file_access_mode'] == 'access' else 1000000000
        group = {'path': '/sys/fs/cgroup/owned/case-%d' % index, 'device': 28, 'inode': index + 100}
        profile = {'status': 'COMPLETE', 'run_id': 'run-%d' % index, 'boot_id': self.matrix['boot_id'],
            'config': cfg, 'release_ns': begin, 'end_ns': begin + duration, 'makespan_ns': duration,
            'root_cgroup': group, 'tasks': [{'task_id': 'task', 'process': {'pid': index + 1, 'start_ticks': 3},
                                          'cgroup': group}]}
        profile_path = trial_dir / 'profile-run.json'
        self.write(profile_path, profile)
        gzip_path = trial_dir / 'cache-residency-files.json.gz'
        gzip_path.write_bytes(b'opaque-cache-test-not-read')
        compact_path = trial_dir / 'cache-residency.json'
        self.write(compact_path, {'file_details': {'sha256': self.sha(gzip_path)}})
        capture = {'boot_id': profile['boot_id'], 'profile_run_id': profile['run_id'],
            'profile_run_sha256': self.sha(profile_path), 'profile_path': 'trials/one/profile-run.json',
            'file_access_backend': 'kprobe-tracefs', 'collector_ring_bytes': 268435456,
            'release_ns': begin, 'end_ns': profile['end_ns'], 'makespan_ns': duration}
        row = {'run_id': profile['run_id'], 'boot_id': profile['boot_id'], 'config': cfg,
            'matrix': dict(entry, campaign=case_id), 'primary': {'seconds': duration / 1e9, 'usable_for_comparison': True},
            'cache_evidence': {'cache_condition_eligible': True},
            'resources': {'status': 'OBSERVED_ENCLOSING_INTERVAL'},
            'sources': {'profile-run.json': self.ref(profile_path)}, 'execution_window': [begin, profile['end_ns']],
            'file_analysis_status': 'NOT_ENABLED', 'file_metrics': {}}
        if cfg['file_access_mode'] == 'access':
            collector = case / 'file-access'
            collector.mkdir()
            meta, final = copy.deepcopy(self.meta), copy.deepcopy(self.final)
            meta.update(run_id='collector-%d' % index, boot_id=profile['boot_id'],
                        start_monotonic_ns=begin - 100, ring_bytes=268435456,
                        max_bytes=2147483648, bpf_sha256='c' * 64, binary_sha256='c' * 64,
                        domains=[dict(group, level=2)])
            for hook in meta['kprobe_events']:
                hook['collection_start_ns'], hook['collection_end_ns'] = begin - 90, begin - 80
            final.update(copy.deepcopy(meta))
            final['end_monotonic_ns'] = profile['end_ns'] + 100
            for hook in final['kprobe_event_health']:
                hook['collection_start_ns'] = profile['end_ns'] + 101
                hook['collection_end_ns'] = profile['end_ns'] + 102
            self.write(collector / 'meta.json', meta)
            self.write(collector / 'final.json', final)
            (collector / 'events.bin').write_bytes(self.raw_event)
            capture.update(collector_run_id=meta['run_id'], collector_cgroup=group, inner_root_cgroup=group,
                ready=dict(meta, type='READY'), started_monotonic_ns=begin - 110,
                ready_received_monotonic_ns=begin - 70, finalized_monotonic_ns=profile['end_ns'] + 110,
                hash_scope='DETACHED_DRAINED_FSYNCED_FD_PASS', final=final,
                final_sha256=self.sha(collector / 'final.json'), capture_budget=self.matrix['collector_budget'])
        self.write(case / 'capture.json', capture)
        row['capture_source'] = self.ref(case / 'capture.json')
        row['collector_boundaries'] = gate.compare.collector_boundaries(capture, row)
        if cfg['file_access_mode'] == 'access':
            output = self.batch_root / case_id
            output.mkdir()
            sources = {name: self.ref(path) for name, path in
                (('profile_run', profile_path), ('capture', case / 'capture.json'),
                 ('collector_meta', case / 'file-access/meta.json'), ('collector_final', case / 'file-access/final.json'))}
            summary = {'status': 'COMPLETE_FOR_SELECTED_HOOKS', 'issues': {},
                'run_id': profile['run_id'], 'boot_id': profile['boot_id'], 'collector_run_id': capture['collector_run_id'],
                'analyzer': {'sha256': 'f' * 64}, 'metrics': {name: 1 for name in gate.FILE_METRICS},
                'sources': dict(sources, inventory_database={'sha256': 'e' * 64}),
                'raw_events': {'sha256': final['events_sha256'], 'bytes': 192, 'records': 1, 'issues': {}}}
            self.write(output / 'summary.json', summary)
            for name in gate.SUMMARY_ARTIFACTS - {'summary.json'}:
                (output / name).write_bytes(b'opaque-derived-not-rehashed')
            self.results[case_id] = {'case_id': case_id, 'output': str(output),
                'analysis_status': summary['status'], 'issues': {}, 'sources': sources,
                'raw': summary['raw_events'], 'artifacts': {name: self.ref(output / name) for name in gate.SUMMARY_ARTIFACTS}}
            self.plan_cases.append({'case_id': case_id, 'sources': sources, 'raw': summary['raw_events']})
            row.update(file_analysis_status='COMPLETE_FOR_SELECTED_HOOKS', file_metrics=summary['metrics'],
                file_analysis={'summary': summary, 'sha256': self.sha(output / 'summary.json')})
        proof = {'status': 'PASS', 'cache_condition_replay': 'PASS', 'run_id': profile['run_id'],
            'boot_id': profile['boot_id'], 'cache': cfg['cache'], 'workspace_layout': cfg['workspace_layout'],
            'release_ns': begin, 'atomic_snapshot': False, 'pin_binding': 'UNKNOWN',
            'claim_scope': 'SAVED_CACHE_RECORD_REPLAY_ONLY_NOT_LIVE_CACHE_TRUTH',
            'readonly_quality': 'DECLARED_READ_ONLY_NOT_REATTESTED',
            'inputs': {'profile': self.ref(profile_path), 'summary': self.ref(compact_path),
                'file_details': self.ref(gzip_path), 'inventory': {'sha256': self.matrix['source_inventory_sha256']}}}
        self.write(self.receipts / (case_id + '.json'), proof)
        self.trials.append(row)

    def make_report(self, receipt):
        metric = gate.compare.metrics_summary([1] * 5, lambda value: value)
        conditions = []
        keys = sorted({tuple(plan[field] for field in ('cache', 'workspace_layout', 'concurrency', 'file_access_mode'))
                       for plan in self.matrix['schedule']})
        for key in keys:
            wanted = [row for row in self.trials if tuple(row['config'][field] for field in
                ('cache', 'workspace_layout', 'concurrency', 'file_access_mode')) == key]
            row = dict(zip(('cache', 'workspace_layout', 'concurrency', 'file_access_mode'), key))
            row.update(blocks=list(range(5)), timing_eligible_n=5, cache_eligible_n=5,
                run_ids=[trial['run_id'] for trial in wanted],
                makespan_seconds=gate.compare.metrics_summary(wanted, lambda trial: trial['primary']['seconds']),
                psi_stall_seconds={r: {k: metric for k in ('some', 'full')} for r in ('cpu', 'memory', 'io')},
                background={name: metric for name in gate.BACKGROUND_METRICS},
                file_metrics={name: metric for name in gate.FILE_METRICS},
                file_analysis_status_counts={'COMPLETE_FOR_SELECTED_HOOKS': 5} if key[-1] == 'access' else {'NOT_ENABLED': 5})
            row.update({name: metric for name in gate.RESOURCE_METRICS if name != 'makespan_seconds'})
            conditions.append(row)
        overhead = []
        for cache, layout, concurrency in sorted({key[:3] for key in keys}):
            pairs = []
            for block in range(5):
                wanted = {trial['config']['file_access_mode']: trial for trial in self.trials if
                    trial['matrix']['block'] == block and tuple(trial['config'][field] for field in
                    ('cache', 'workspace_layout', 'concurrency')) == (cache, layout, concurrency)}
                pairs.append({'block': block, 'sampler_seconds': 1., 'access_seconds': 2.,
                    'added_seconds': 1., 'added_percent': 100., 'eligible': True,
                    'sampler_run_id': wanted['sampler']['run_id'], 'access_run_id': wanted['access']['run_id']})
            overhead.append({'cache': cache, 'workspace_layout': layout, 'concurrency': concurrency,
                'paired_n': 5, 'eligible_paired_n': 5, 'missing_sampler_blocks': [], 'missing_access_blocks': [],
                'pairs': pairs, 'added_seconds': gate.compare.metrics_summary(pairs, lambda pair: pair['added_seconds']),
                'added_percent': gate.compare.metrics_summary(pairs, lambda pair: pair['added_percent'])})
        return {'schema_version': 1, 'matrix_sha256': self.sha(self.matrix_path),
            'status': 'DESCRIPTIVE_PAIRED_SEARCH_COMPARISON', 'issues': [],
            'primary_metric': 'ALL_EIGHT_FIXED_WORK_TASKS_MAKESPAN_SECONDS', 'trials': self.trials,
            'file_analysis_receipt': receipt, 'conditions': conditions, 'collector_overhead': overhead,
            'quality': {'resource_incomplete_trials': 0, 'access_analysis_incomplete_trials': 0,
                        'access_boundary_incomplete_trials': 0}}

    def run_gate(self, **kwargs):
        return gate.verify(self.matrix_path, self.report_path, self.batch_path, self.cache_index,
                           selection_verification_path=self.selection_path, **kwargs)

    def refresh_batch_binding(self):
        self.write(self.batch_path, self.batch)
        source = gate.compare.load_analysis_receipt(self.batch_path)['source']
        self.report['file_analysis_receipt'] = source
        for trial in self.report['trials']:
            trial['file_analysis_receipt'] = source
        self.write(self.report_path, self.report)

    def make_archived_batch(self):
        settings = {'schema_version': 1, 'codec': 'gzip', 'artifact_module_sha256':
            self.sha(Path(gate.compare.ARTIFACTS.__file__))}
        self.batch.update(schema_version=2, artifact_storage=settings)
        plan_path = self.batch_root / 'plan.json'
        plan = json.loads(plan_path.read_text())
        plan.update(schema_version=2, artifact_storage=settings)
        self.write(plan_path, plan)
        for row in self.results.values():
            row.update(artifact_storage_schema=2, artifact_storage=settings)
            for name in gate.compare.ARTIFACTS.ARCHIVED_NAMES:
                path = Path(row['output']) / name
                row['artifacts'][name] = gate.compare.ARTIFACTS.store_gzip(path, path.parent, name)
                path.unlink()
        self.refresh_batch_binding()

    def test_uninterrupted_strict_matrix_receipt_needs_no_fabricated_pause(self):
        strict = json.loads(self.selection_path.read_text())['fixed_work_verification']
        self.write(self.selection_path, strict)
        result = self.run_gate()
        self.assertTrue(result['verified'], result['issues'])
        self.assertIn('NOT_APPLICABLE', result['dimensions']['fixed_work_replay']['pause_selection'])

    def test_composed_matrix_cannot_bypass_its_pause_lineage_verification(self):
        self.matrix['composition'] = {'path': 'selection.json', 'sha256': 'd' * 64}
        self.write(self.matrix_path, self.matrix)
        strict = json.loads(self.selection_path.read_text())['fixed_work_verification']
        strict['matrix_sha256'] = self.sha(self.matrix_path)
        self.write(self.selection_path, strict)
        result = self.run_gate()
        self.assertFalse(result['verified'])
        self.assertIn('pause-selection', result['issues'][0]['detail'])

    def test_schema_two_archive_receipts_pass_without_fictitious_plain_files(self):
        self.make_archived_batch()
        result = self.run_gate()
        self.assertTrue(result['verified'], result['issues'])

    def test_archive_logical_hash_cannot_diverge_from_independent_proof(self):
        self.make_archived_batch()
        row = next(iter(self.results.values()))
        row['artifacts']['events.sqlite']['sha256'] = '0' * 64
        self.refresh_batch_binding()
        result = self.run_gate()
        self.assertFalse(result['verified'])
        self.assertIn('independent verification', result['issues'][0]['detail'])

    def test_missing_compressed_artifact_rejected(self):
        self.make_archived_batch()
        row = next(iter(self.results.values()))
        Path(row['artifacts']['events.sqlite']['storage']['path']).unlink()
        self.assertFalse(self.run_gate()['verified'])

    def test_full_acceptance_keeps_unknown_pin_quality_without_false_global_claim(self):
        original = Path.open
        def guard(path, *args, **kwargs):
            if path.suffix in ('.bin', '.sqlite', '.gz', '.csv'):
                raise AssertionError('final gate must not read huge opaque artifacts')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guard):
            result = self.run_gate()
        self.assertTrue(result['verified'], result['issues'])
        self.assertEqual(result['dimensions']['cache_replay']['pin_binding_counts'], {'UNKNOWN': 160})
        self.assertTrue(result['not_reperformed'])

    def test_descriptive_top_status_does_not_hide_missing_file_analysis(self):
        self.report['trials'][0]['file_analysis_status'] = 'MISSING_OR_INVALID'
        self.write(self.report_path, self.report)
        result = self.run_gate()
        self.assertFalse(result['verified'])
        self.assertIn('file-analysis', result['issues'][0]['detail'])

    def test_79_case_subset_cannot_pass(self):
        self.batch['selected_cases'] = self.batch['available_full_detail_cases'] = 79
        self.batch['results'].pop(next(iter(self.batch['results'])))
        self.write(self.batch_path, self.batch)
        self.assertFalse(self.run_gate()['verified'])

    def test_changed_summary_bytes_are_rejected(self):
        row = next(iter(self.results.values()))
        path = Path(row['output']) / 'summary.json'
        value = json.loads(path.read_text())
        value['metrics']['read_calls'] = 999
        self.write(path, value)
        result = self.run_gate()
        self.assertFalse(result['verified'])
        self.assertIn('SHA256', result['issues'][0]['detail'])

    def test_missing_cache_receipt_index_is_incomplete_and_persisted(self):
        (self.receipts / '000-r0.json').unlink()
        output = self.cache_root / 'missing-index.json'
        result = gate.index_cache(self.matrix_path, self.receipts, output)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertIn('000-r0', result['failures'])
        self.assertTrue(output.is_file())

    def test_cache_failure_is_not_skipped(self):
        self.write(self.receipts / '000-r0.json', {'status': 'FAIL', 'cache_condition_replay': 'FAIL'})
        output = self.cache_root / 'failed-index.json'
        result = gate.index_cache(self.matrix_path, self.receipts, output)
        self.assertEqual(len(result['results']), 160)
        self.assertEqual(result['failures']['000-r0'], 'CACHE_PROOF_DID_NOT_PASS')

    def test_cache_receipt_from_another_run_rejected_even_with_fresh_index(self):
        path = self.receipts / '000-r0.json'
        value = json.loads(path.read_text())
        value['run_id'] = 'unrelated-run'
        self.write(path, value)
        output = self.cache_root / 'wrong-run-index.json'
        gate.index_cache(self.matrix_path, self.receipts, output)
        result = gate.verify(self.matrix_path, self.report_path, self.batch_path, output,
                             selection_verification_path=self.selection_path)
        self.assertFalse(result['verified'])
        self.assertIn('cache replay', result['issues'][0]['detail'])

    def test_condition_or_pair_count_missing_rejected(self):
        for field in ('conditions', 'collector_overhead'):
            value = copy.deepcopy(self.report)
            value[field].pop()
            self.write(self.report_path, value)
            with self.subTest(field=field):
                self.assertFalse(self.run_gate()['verified'])

    def test_paired_wall_seconds_cannot_be_forged(self):
        self.report['collector_overhead'][0]['pairs'][0]['added_seconds'] = -1
        self.write(self.report_path, self.report)
        result = self.run_gate()
        self.assertFalse(result['verified'])
        self.assertIn('paired overhead', result['issues'][0]['detail'])

    def test_missing_network_metric_is_not_silently_ignored(self):
        self.report['conditions'][0]['background'].pop('guest_eth0_rx_bytes')
        self.write(self.report_path, self.report)
        result = self.run_gate()
        self.assertFalse(result['verified'])
        self.assertIn('guest_eth0_rx_bytes', result['issues'][0]['detail'])

    def test_incomplete_quality_counter_cannot_be_green(self):
        self.report['quality']['access_analysis_incomplete_trials'] = 1
        self.write(self.report_path, self.report)
        self.assertFalse(self.run_gate()['verified'])

    def test_external_byte_pin_mismatch_fails(self):
        result = self.run_gate(expected={'report': '0' * 64})
        self.assertFalse(result['verified'])
        self.assertIn('external SHA256', result['issues'][0]['detail'])

    def test_strict_verification_of_another_matrix_is_rejected(self):
        value = json.loads(self.selection_path.read_text())
        value['matrix_sha256'] = 'a' * 64
        self.write(self.selection_path, value)
        result = self.run_gate()
        self.assertFalse(result['verified'])
        self.assertIn('strict-160', result['issues'][0]['detail'])

    def test_later_derived_artifact_missing_is_rejected(self):
        row = next(iter(self.results.values()))
        (Path(row['output']) / 'events.sqlite').unlink()
        self.assertFalse(self.run_gate()['verified'])

    def test_four_known_rounds_cannot_be_reported_as_five(self):
        self.report['conditions'][0]['data_read_bytes'] = dict(
            self.report['conditions'][0]['data_read_bytes'], n=4, unknown_n=1, independent_n=4)
        self.write(self.report_path, self.report)
        result = self.run_gate()
        self.assertFalse(result['verified'])
        self.assertIn('five known independent', result['issues'][0]['detail'])

    def test_source_mutated_since_strict_replay_is_rejected(self):
        path = self.raw_root / '000-r0/capture.json'
        value = json.loads(path.read_text())
        value['extra_after_verification'] = 'changed-source'
        self.write(path, value)
        result = self.run_gate()
        self.assertFalse(result['verified'])
        self.assertIn('source SHA256/bytes', result['issues'][0]['detail'])

    def test_missing_strict_receipt_does_not_fall_back_to_report_status(self):
        result = gate.verify(self.matrix_path, self.report_path, self.batch_path, self.cache_index)
        self.assertFalse(result['verified'])
        self.assertIn('explicit pause-selection', result['issues'][0]['detail'])

    def test_raw_count_conflict_rejected_even_when_statuses_are_green(self):
        row = next(iter(self.results.values()))
        path = Path(row['output']) / 'summary.json'
        summary = json.loads(path.read_text())
        summary['raw_events']['records'] = 2
        self.write(path, summary)
        # Update all superficial summary hashes, leaving the bound collector
        # final count unchanged.  A top-level COMPLETE is still insufficient.
        row['artifacts']['summary.json'] = self.ref(path)
        case_id = row['case_id']
        trial = next(trial for trial in self.trials if trial['matrix']['campaign'] == case_id)
        trial['file_analysis']['summary'] = summary
        trial['file_analysis']['sha256'] = self.sha(path)
        self.write(self.batch_path, self.batch)
        reference = gate.compare.load_analysis_receipt(self.batch_path)['source']
        self.report['file_analysis_receipt'] = reference
        for trial in self.report['trials']:
            trial['file_analysis_receipt'] = reference
        self.write(self.report_path, self.report)
        result = self.run_gate()
        self.assertFalse(result['verified'])
        self.assertIn('raw replay', result['issues'][0]['detail'])


if __name__ == '__main__':
    unittest.main()
