import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import shutil
import sys
from unittest.mock import patch

import verify_large_matrix as verifier


class LargeMatrixVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old, self.new = self.root / 'old', self.root / 'new'
        self.old.mkdir(); self.new.mkdir()
        self.plans = [dict(cache='warm', workspace_layout='shared', concurrency=concurrency,
                           intervention='none', block=block, warmup=False)
                      for block in (0, 1) for concurrency in (1, 2)]
        self.binding = dict(schema_version=1, status='FAILED', source={'commit': '1' * 40},
            source_inventory_sha256='a' * 64, jobs=1, passes=1, queries=['needle'], cpus=[0, 1],
            measurement_coordinator_and_sampler_cpus=[2], boot_id='boot', seed=1,
            binaries={key: 'a' * 64 for key in verifier.BINARY_FIELDS}, measurement_mode='sampler')
        self.records = []
        for index, plan in enumerate(self.plans):
            parent = self.old if index < 3 else self.new
            local = index if index < 3 else index - 3
            name = '%03d-r%d' % (local, plan['block'])
            self.make_campaign(parent / name, plan, index)
            self.records.append(dict(path=name, block=plan['block'], stage='performance', condition=plan))
        self.original = dict(self.binding, schedule=self.plans, campaigns=self.records[:3])
        self.write(self.old / 'matrix.json', self.original)
        self.original_sha = self.sha(self.old / 'matrix.json')
        self.resumed = dict(self.binding, status='COMPLETE', output_equivalence='PASS',
                            schedule=self.plans[3:], campaigns=self.records[3:])
        self.write(self.new / 'matrix.json', self.resumed)
        self.combined = dict(self.binding, status='COMPLETE', output_equivalence='PASS', schedule=self.plans,
            campaigns=[dict(record, path=('old/' if index < 3 else 'new/') + record['path'],
                            original_schedule_index=index) for index, record in enumerate(self.records)],
            resume_provenance={'adapter_sha256': 'a' * 64, 'original_matrix_sha256': self.original_sha,
                'resumed_matrix_sha256': self.sha(self.new / 'matrix.json'), 'completed_prefix': 3, 'remaining_cases': 1,
                'begin_monotonic_ns': 900, 'end_monotonic_ns': 2000, 'frozen_analyzer_sha256': 'b' * 64,
                'timing_implementation': 'ORIGINAL_FROZEN_EXECUTE_AND_RUN_TRIAL; ONLY_SCHEDULE_PROVIDER_REPLACED_IN_MEMORY',
                'integrity': 'Frozen execute rechecked all source/copy contents and permissions after the remaining trials.'})
        self.combined_path = self.root / 'matrix-all.json'
        self.save_combined()
        canceled = self.old / '003-r1'
        (canceled / 'trials/canceled').mkdir(parents=True)
        self.write(canceled / 'campaign.json', {'status': 'RUNNING', 'trials': []})
        self.write(canceled / 'trials/canceled/profile-run.json', {'status': 'FAILED', 'boot_id': 'boot', 'run_id': 'canceled'})

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def save_combined(self):
        self.write(self.combined_path, self.combined)

    def trial(self, index):
        return (self.old if index < 3 else self.new) / self.records[index]['path'] / 'trials/one'

    def mutate(self, path, change):
        value = json.loads(path.read_bytes())
        change(value)
        self.write(path, value)

    def make_campaign(self, directory, plan, index):
        trial = directory / 'trials/one'
        trial.mkdir(parents=True)
        run_id, begin = 'run-%d' % index, 100 + 100 * index if index < 3 else 1000
        cg = {'path': '/sys/fs/cgroup/' + run_id, 'inode': 100 + index, 'device': 28}
        proc = {'pid': 100 + index, 'start_ticks': 10 + index}
        config = dict(jobs=1, passes=1, calibration_kind=None, calibration_seconds=.4,
            timing_scope='PREPARED_WORKER_SIGCONT_TO_WAIT4_OBSERVATION', query_measurement_version=1,
            cpu_time_scope='WAIT4_LIFETIME_MINUS_WORKER_PREFLIGHT_RUSAGE', corpus_sha256='c' * 64,
            queries_sha256=hashlib.sha256(verifier.canonical(['needle']).encode()).hexdigest(),
            permission_scope_sha256='d' * 64, repository_version='1' * 40, intervention='none',
            cgroup_layout='shared-leaf', memory_max_mb=0, memory_high_mb=0,
            memory_limit_start='AFTER_WORKER_PREFLIGHT_BEFORE_COLLECTOR_READY', sample_threads=False,
            cpus=[0, 1], interval_ms=100, process_interval_ms=0, repetition=0, mode='sampler',
            **{key: value for key, value in plan.items() if key not in ('block', 'intervention')})
        raw = b'z\0a\0'
        output_sha = hashlib.sha256(b'a\0z\0').hexdigest()
        task = dict(task_id='task-0000', agent_id='agent-0000', tool_call_id='search-0000', process=proc, cgroup=cg)
        row = dict(task_id=task['task_id'], query_index=0, exit_code=0, queue_ns=0, wall_ns=20,
            completion_latency_ns=20, user_usec=1, system_usec=1, output_bytes=len(raw), output_sha256=output_sha)
        identity = dict(run_id=run_id, task_id=task['task_id'], agent_id=task['agent_id'], tool_call_id=task['tool_call_id'],
            attempt=1, epoch=1, cgroup=cg, corpus_sha256=config['corpus_sha256'],
            grep_sha256=self.binding['binaries']['grep_sha256'], repository_version=config['repository_version'],
            cache_state=plan['cache'], workspace_layout=plan['workspace_layout'])
        job = dict(query='needle', query_index=0, passes=1, reuse=None, query_identity=identity,
                   corpus='/fixture/corpus', grep='/usr/bin/grep')
        query = dict(identity, process=proc, boot_id='boot', schema_version=1, query_ordinal=0,
            query_id='search-0000:query-000000', query_index=0,
            query_sha256=hashlib.sha256(b'needle').hexdigest(), mode='none', lock_wait_ns=0,
            begin_ns=begin + 1, end_ns=begin + 19, duration_ns=18,
            execution_kind='SCAN', status='COMPLETE', returncode=0)
        stats = dict(schema_version=2, logical_queries=1, physical_grep_executions=1, cache_hits=0,
            intervention='none', query_timing_contract='WORKER_MONOTONIC_PER_LOGICAL_QUERY_V1', query_spans=[query])
        compact = {'file_details': {'path': 'files.json.gz', 'sha256': 'f' * 64}}
        self.write(trial / 'cache-residency.json', compact)
        # Reader is forbidden to open this opaque artifact; no full-cache claim.
        (trial / 'files.json.gz').write_bytes(b'opaque, not reconstructed')
        profile = dict(schema_version=1, status='COMPLETE', cleanup_errors=[], boot_id='boot', run_id=run_id,
            release_ns=begin, end_ns=begin + 20, makespan_ns=20, config=config, root_cgroup=cg,
            tasks=[task], results=[row], cache_residency={'path': 'cache-residency.json',
                'sha256': self.sha(trial / 'cache-residency.json')})
        item = dict(path='trials/one', run_id=run_id, makespan_ns=20,
                    **{key: config[key] for key in ('mode', 'concurrency', 'repetition', 'warmup')})
        campaign = dict(status='COMPLETE', jobs=1, passes=1, queries=['needle'], binaries=self.binding['binaries'],
            grep_options=verifier.GREP_OPTIONS, trials=[item], **{key: config[key] for key in
                ('corpus_sha256', 'permission_scope_sha256', 'repository_version', 'cgroup_layout',
                 'memory_max_mb', 'memory_high_mb', 'sample_threads', 'calibration_kind')})
        self.write(directory / 'campaign.json', campaign)
        for name, value in (('profile-run.json', profile), ('task-0000-job.json', job),
                ('task-0000-statistics.json', stats), ('report.json', {'analysis': {'source_sha256': 'b' * 64}}),
                ('load/load-meta.json', {'label': run_id, 'boot_id': 'boot', 'cgroups': [dict(cg, available={})]}),
                ('load/load-sampler-stats.json', {'read_errors': 0})):
            self.write(trial / name, value)
        (trial / 'task-0000.stdout').write_bytes(raw)
        events = [dict(task, run_id=run_id, boot_id='boot', seq=0, event='START', monotonic_ns=begin),
                  dict(task, run_id=run_id, boot_id='boot', seq=1, event='COMPLETE', monotonic_ns=begin + 20,
                       **{key: row[key] for key in ('exit_code', 'output_sha256', 'output_bytes', 'user_usec', 'system_usec')})]
        (trial / 'task-events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))

    def verify(self):
        return verifier.verify(self.combined_path, self.old, self.original_sha)

    def test_complete_lineage_and_raw_reconstruction_without_gzip_reads(self):
        original_open = Path.open

        def no_gzip(path, *args, **kwargs):
            if path.suffix == '.gz':
                raise AssertionError('gzip must not be read')
            return original_open(path, *args, **kwargs)

        with patch.object(Path, 'open', no_gzip):
            result = self.verify()
        self.assertTrue(result['verified'], result['issues'])
        self.assertEqual((result['total_trials'], result['unique_runs'], result['original_prefix_trials'], result['resumed_trials']), (4, 4, 3, 1))
        self.assertEqual(result['split_pause_block'], 1)
        self.assertFalse(result['canceled_attempt']['included_in_performance_trials'])
        self.assertEqual(result['source_post_validation']['independent_content_permission_rehash'], 'NOT_PERFORMED')

    def test_manifest_anchor_mapping_count_and_source_declarations_fail_closed(self):
        for case in ('anchor', 'index', 'block', 'condition', 'path', 'count', 'fixed', 'resumed_source_hash'):
            with self.subTest(case=case):
                original = copy.deepcopy(self.combined)
                if case == 'anchor': self.combined['resume_provenance']['original_matrix_sha256'] = '0' * 64
                elif case == 'index': self.combined['campaigns'][-1]['original_schedule_index'] = 2
                elif case == 'block': self.combined['campaigns'][-1]['block'] = True
                elif case == 'condition': self.combined['campaigns'][-1]['condition'] = self.plans[0]
                elif case == 'path': self.combined['campaigns'][-1]['path'] = '../outside'
                elif case == 'count': self.combined['campaigns'].pop()
                elif case == 'fixed': self.combined['binaries']['grep_sha256'] = '0' * 64
                else: self.combined['resume_provenance']['resumed_matrix_sha256'] = '0' * 64
                self.save_combined()
                self.assertFalse(self.verify()['verified'])
                self.combined = original

    def test_raw_fixed_config_and_boolean_alias_drift_fail(self):
        path = self.trial(3) / 'profile-run.json'
        original = json.loads(path.read_bytes())
        for field, value in (('interval_ms', 200), ('process_interval_ms', True), ('sample_threads', 0),
                             ('corpus_sha256', 'e' * 64), ('new_unfrozen_option', True)):
            with self.subTest(field=field):
                changed = copy.deepcopy(original)
                changed['config'][field] = value
                self.write(path, changed)
                self.assertFalse(self.verify()['verified'])
        self.write(path, original)

    def test_raw_output_and_job_query_assignment_are_not_trusted_json_claims(self):
        trial = self.trial(3)
        stdout = trial / 'task-0000.stdout'
        stdout.write_bytes(b'tampered\0')
        self.assertFalse(self.verify()['verified'])
        stdout.write_bytes(b'z\0a\0')
        self.mutate(trial / 'task-0000-job.json', lambda v: v.update(query='different query'))
        self.assertFalse(self.verify()['verified'])

    def test_query_span_lifecycle_and_registry_mismatch_fail(self):
        for filename, mutate in (
                ('task-0000-statistics.json', lambda v: v['query_spans'][0].update(duration_ns=-1)),
                ('load/load-meta.json', lambda v: v.update(label='foreign-run')),
                ('profile-run.json', lambda v: v['results'][0].update(completion_latency_ns=19))):
            with self.subTest(filename=filename):
                path = self.trial(3) / filename
                original = path.read_bytes()
                self.mutate(path, mutate)
                self.assertFalse(self.verify()['verified'])
                path.write_bytes(original)

    def test_reused_raw_run_is_not_an_independent_trial(self):
        path = self.trial(3) / 'profile-run.json'
        self.mutate(path, lambda v: v.update(run_id='run-0'))
        self.assertFalse(self.verify()['verified'])

    def test_canceled_attempt_with_release_or_counted_run_is_rejected(self):
        path = self.old / '003-r1/trials/canceled/profile-run.json'
        for field, value in (('release_ns', 123), ('run_id', 'run-3')):
            with self.subTest(field=field):
                original = path.read_bytes()
                self.mutate(path, lambda v: v.update({field: value}))
                self.assertFalse(self.verify()['verified'])
                path.write_bytes(original)

    def test_producer_source_postcheck_is_only_bound_completion_claim(self):
        self.combined['resume_provenance']['integrity'] = 'trust me, all files verified'
        self.save_combined()
        self.assertFalse(self.verify()['verified'])

    def test_cross_pause_output_change_is_rejected_even_if_stored_digests_are_updated(self):
        trial = self.trial(3)
        raw = b'other\0'
        (trial / 'task-0000.stdout').write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        self.mutate(trial / 'profile-run.json',
                    lambda v: v['results'][0].update(output_sha256=digest, output_bytes=len(raw)))
        path = trial / 'task-events.jsonl'
        events = [json.loads(line) for line in path.read_text().splitlines()]
        events[-1].update(output_sha256=digest, output_bytes=len(raw))
        path.write_text(''.join(json.dumps(row) + '\n' for row in events))
        result = self.verify()
        self.assertFalse(result['verified'])
        self.assertIn('query output changed', result['issues'][0]['detail'])

    def test_prefix_copy_must_preserve_raw_bytes_not_only_canonical_output_digest(self):
        target = self.root / 'old-copy'
        shutil.copytree(self.old, target)
        for row in self.combined['campaigns'][:3]:
            row['path'] = row['path'].replace('old/', 'old-copy/', 1)
        (target / self.records[0]['path'] / 'trials/one/task-0000.stdout').write_bytes(b'a\0z\0')
        self.save_combined()
        result = self.verify()
        self.assertFalse(result['verified'])
        self.assertIn('prefix critical evidence was changed', result['issues'][0]['detail'])

    def test_cli_writes_fresh_receipt_and_refuses_existing_or_raw_output(self):
        output = self.root / 'receipt/verification.json'
        args = ['verify-large-matrix', '--combined', str(self.combined_path), '--original-prefix-dir', str(self.old),
                '--expected-original-sha256', self.original_sha, '--output', str(output)]
        with patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(verifier.main(), 0)
        original = output.read_bytes()
        with patch.object(sys, 'argv', args), self.assertRaisesRegex(ValueError, 'fresh'):
            verifier.main()
        self.assertEqual(output.read_bytes(), original)
        args[-1] = str(self.trial(3) / 'must-not-write.json')
        with patch.object(sys, 'argv', args), self.assertRaisesRegex(ValueError, 'outside raw'):
            verifier.main()
        self.assertFalse((self.trial(3) / 'must-not-write.json').exists())


if __name__ == '__main__':
    unittest.main()
