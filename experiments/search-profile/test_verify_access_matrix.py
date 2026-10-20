import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_access_matrix as verify


class AccessMatrixTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.plans = verify.expected_schedule(7, 1, (2,), ('warm',), ('shared',))
        self.binding = {'schema_version': 1, 'status': 'COMPLETE', 'jobs': 8, 'passes': 1,
            'queries': ['one', 'two', 'three', 'absent'], 'cpus': [0, 1, 2, 3], 'boot_id': 'boot',
            'source': {'commit': '1' * 40}, 'file_access_backend': 'fentry',
            'collector_budget': {'ring_bytes': 268435456, 'max_bytes': 2147483648, 'max_seconds': 1200},
            'binaries': {**{field: 'a' * 64 for field in verify.BINARY_DIGESTS}, 'file_access_backend': 'fentry'},
            'participating_source_roots': ['/fixture/corpus'], 'campaigns': []}
        for index, plan in enumerate(self.plans):
            self.make_campaign(index, plan)

    @staticmethod
    def write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def directory(self, index):
        return self.root / ('%03d-r0' % index)

    def trial(self, index):
        return self.directory(index) / 'trials/one'

    def mutate(self, path, operation):
        value = json.loads(path.read_bytes())
        operation(value)
        self.write(path, value)

    def make_campaign(self, index, plan):
        directory, trial = self.directory(index), self.trial(index)
        trial.mkdir(parents=True)
        begin, run_id = 100 + index * 1000, 'run-%d' % index
        parent = {'path': '/sys/fs/cgroup/owned/capture-%d' % index, 'device': 28, 'inode': 30 + index * 2}
        group = {'path': parent['path'] + '/' + run_id, 'device': 28, 'inode': 31 + index * 2}
        config = {'jobs': 8, 'passes': 1, 'calibration_kind': None, 'calibration_seconds': .4,
            'timing_scope': 'PREPARED_WORKER_SIGCONT_TO_WAIT4_OBSERVATION', 'query_measurement_version': 1,
            'cpu_time_scope': 'WAIT4_LIFETIME_MINUS_WORKER_PREFLIGHT_RUSAGE',
            'corpus_sha256': 'c' * 64, 'permission_scope_sha256': 'd' * 64,
            'queries_sha256': hashlib.sha256(verify.core.canonical(self.binding['queries']).encode()).hexdigest(),
            'repository_version': '1' * 40, 'intervention': 'none', 'cgroup_layout': 'shared-leaf',
            'memory_max_mb': 0, 'memory_high_mb': 0, 'memory_limit_start': 'AFTER_WORKER_PREFLIGHT_BEFORE_COLLECTOR_READY',
            'sample_threads': False, 'cpus': [0, 1, 2, 3], 'interval_ms': 100, 'process_interval_ms': 0,
            'repetition': 0, 'mode': 'sampler', 'file_access_backend': 'fentry', 'collector_ring_bytes': 268435456,
            **{key: value for key, value in plan.items() if key != 'block'}}
        tasks, results, events = [], [], []
        for number in range(8):
            task_id, qindex = 'task-%04d' % number, number % 4
            proc = {'pid': 1000 + index * 8 + number, 'start_ticks': 10 + number}
            low = begin + (number // 2) * 20
            high = low + 20
            prepared = {'schema_version': 1, 'process': proc, 'boot_id': 'boot',
                        'monotonic_ns': begin - 10, 'rusage_user_usec': 1, 'rusage_system_usec': 2}
            task = {'task_id': task_id, 'agent_id': 'agent-%04d' % number, 'tool_call_id': 'search-%04d' % number,
                    'process': proc, 'cgroup': group, 'preparation': prepared}
            identity = {'run_id': run_id, 'task_id': task_id, 'agent_id': task['agent_id'],
                'tool_call_id': task['tool_call_id'], 'attempt': 1, 'epoch': 1, 'cgroup': group,
                'corpus_sha256': config['corpus_sha256'], 'grep_sha256': self.binding['binaries']['grep_sha256'],
                'repository_version': config['repository_version'], 'cache_state': plan['cache'],
                'workspace_layout': plan['workspace_layout']}
            query = dict(identity, process=proc, boot_id='boot', schema_version=1, query_ordinal=0,
                query_id=task['tool_call_id'] + ':query-000000', query_index=qindex,
                query_sha256=hashlib.sha256(self.binding['queries'][qindex].encode()).hexdigest(),
                mode='none', lock_wait_ns=0, begin_ns=low + 1, end_ns=high - 1, duration_ns=18,
                execution_kind='SCAN', status='COMPLETE', returncode=1 if qindex == 3 else 0)
            statistics = {'schema_version': 2, 'logical_queries': 1, 'physical_grep_executions': 1,
                'cache_hits': 0, 'intervention': 'none', 'query_timing_contract': 'WORKER_MONOTONIC_PER_LOGICAL_QUERY_V1',
                'query_spans': [query]}
            raw = b'' if qindex == 3 else ('z%d\0a%d\0' % (qindex, qindex)).encode()
            digest = hashlib.sha256(b'\0'.join(sorted(raw.split(b'\0')[:-1])) + b'\0').hexdigest()
            row = {'task_id': task_id, 'query_index': qindex, 'exit_code': 0, 'queue_ns': low - begin,
                'wall_ns': 20, 'completion_latency_ns': high - begin, 'user_usec': 3, 'system_usec': 4,
                'lifetime_user_usec': 4, 'lifetime_system_usec': 6, 'output_bytes': len(raw),
                'output_sha256': digest, 'query_statistics': statistics}
            tasks.append(task)
            results.append(row)
            events += [dict(task, run_id=run_id, boot_id='boot', event='START', monotonic_ns=low),
                dict(task, run_id=run_id, boot_id='boot', event='COMPLETE', monotonic_ns=high,
                     **{key: row[key] for key in ('exit_code', 'output_sha256', 'output_bytes', 'user_usec', 'system_usec')})]
            self.write(trial / (task_id + '-job.json'), {'query': self.binding['queries'][qindex], 'query_index': qindex,
                'passes': 1, 'reuse': None, 'query_identity': identity, 'corpus': '/fixture/corpus', 'grep': '/usr/bin/grep'})
            self.write(trial / (task_id + '-statistics.json'), statistics)
            self.write(trial / (task_id + '-ready.json'), prepared)
            (trial / (task_id + '.stdout')).write_bytes(raw)
        compact = {'file_details': {'path': 'files.json.gz', 'sha256': 'f' * 64}}
        self.write(trial / 'cache-residency.json', compact)
        (trial / 'files.json.gz').write_bytes(b'opaque cache proof must not be read')
        profile = {'schema_version': 1, 'status': 'COMPLETE', 'cleanup_errors': [], 'boot_id': 'boot', 'run_id': run_id,
            'release_ns': begin, 'end_ns': begin + 80, 'makespan_ns': 80, 'config': config, 'root_cgroup': group,
            'tasks': tasks, 'results': results, 'cache_residency': {'path': 'cache-residency.json',
                'sha256': self.sha(trial / 'cache-residency.json')}}
        self.write(trial / 'profile-run.json', profile)
        sorted_events = sorted(events, key=lambda event: (event['monotonic_ns'], event['event'] == 'START'))
        (trial / 'task-events.jsonl').write_text(''.join(json.dumps(dict(event, seq=i)) + '\n' for i, event in enumerate(sorted_events)))
        self.write(trial / 'report.json', {'analysis': {'source_sha256': 'b' * 64}})
        self.write(trial / 'load/load-meta.json', {'label': run_id, 'boot_id': 'boot', 'cgroups': [group]})
        self.write(trial / 'load/load-sampler-stats.json', {'read_errors': 0, 'missed_ticks': 0})
        item = {'path': 'trials/one', 'run_id': run_id, 'makespan_ns': 80,
                **{key: config[key] for key in ('mode', 'concurrency', 'repetition', 'warmup')}}
        campaign = {'status': 'COMPLETE', 'jobs': 8, 'passes': 1, 'queries': self.binding['queries'],
            'binaries': self.binding['binaries'], 'grep_options': verify.core.GREP_OPTIONS, 'trials': [item],
            **{key: config[key] for key in ('corpus_sha256', 'permission_scope_sha256', 'repository_version',
                'cgroup_layout', 'memory_max_mb', 'memory_high_mb', 'sample_threads', 'calibration_kind')}}
        self.write(directory / 'campaign.json', campaign)
        condition = {key: value for key, value in plan.items() if key != 'block'}
        condition.update(mode='sampler', repetition=0, file_access_backend='fentry', collector_ring_bytes=268435456)
        self.binding['campaigns'].append({'path': directory.name, 'block': 0, 'stage': 'performance', 'condition': condition})
        capture = {'schema_version': 1, 'status': 'NOT_ENABLED', 'mode': plan['file_access_mode'],
            'boot_id': 'boot', 'cgroup': parent, 'file_access_backend': 'fentry', 'collector_ring_bytes': 268435456,
            'profile_run_id': run_id, 'profile_path': 'trials/one/profile-run.json',
            'profile_run_sha256': self.sha(trial / 'profile-run.json'), 'profile_sha256': self.sha(trial / 'profile-run.json'),
            'release_ns': begin, 'end_ns': begin + 80, 'makespan_ns': 80, 'inner_root_cgroup': group}
        if plan['file_access_mode'] == 'access':
            self.add_collector(directory, capture, parent, begin)
        self.write(directory / 'capture.json', capture)

    def add_collector(self, directory, capture, parent, begin):
        collector = directory / 'file-access'
        collector.mkdir()
        meta = {'schema_version': 1, 'run_id': directory.name, 'boot_id': 'boot', 'start_monotonic_ns': begin - 25,
            'domains': [dict(parent, level=len(Path(parent['path']).parts) - 4)],
            'bpf_sha256': 'a' * 64, 'binary_sha256': 'a' * 64, 'bpf_source_sha256': 'c' * 64,
            'header_sha256': 'd' * 64, 'record_bytes': 192, 'event_magic': verify.ACCESS.MAGIC,
            'event_abi_version': 1, 'endian': 'little', 'mode': 'events', 'max_bytes': 2147483648,
            'ring_bytes': 268435456, 'possible_cpus': 6, 'cpu_seq_contract': 'ONE_BASED_ATTEMPT_BEFORE_RESERVATION_PER_CPU',
            'native_syscall_abi': 'X86_64_EXCLUDING_TS_COMPAT_AND_X32', 'page_size': 4096,
            'vm_fault_flags_contract': verify.ACCESS.FAULT_FLAGS_CONTRACT, 'required_programs': sorted(verify.ACCESS.PROGRAMS),
            'hash_scope': 'DETACHED_DRAINED_FSYNCED_FD_PASS', 'backend': 'fentry', 'online_cpus': '0-5',
            'kprobe_events': [], 'hook_abi': {'status': 'FENTRY_BTF_PROTOTYPE_VERIFIED_BY_KERNEL_LOADER'}}
        final = dict(meta, end_monotonic_ns=begin + 90, observation_health='COMPLETE_FOR_SELECTED_HOOKS',
            timed_out=False, health={key: 0 for key in verify.ACCESS.HEALTH},
            programs=[{'name': name, 'id': i + 1, 'recursion_misses': 0} for i, name in enumerate(sorted(verify.ACCESS.PROGRAMS))],
            cpus=[{'cpu': i, 'attempted': 10 if i == 0 else 0, 'emitted': 10 if i == 0 else 0, 'ring_drops': 0} for i in range(6)],
            pending_syscalls=0, pending_vfs_calls=0, pending_fault_calls=0, pending_mm_fault_calls=0,
            persisted_records=10, bytes=1920, events_sha256='f' * 64, parser_errors=0, sequence_errors=0,
            cap_discarded=0, write_errors=0, write_error=None, flush_error=None, hash_error=None,
            kprobe_event_health=[], tracefs_cleanup={'status': 'COMPLETE', 'owned_events': 0, 'remaining_owned_events': 0, 'errors': []},
            online_cpu_identity={'status': 'STABLE', 'initial': '0-5', 'current': '0-5'})
        self.write(collector / 'meta.json', meta)
        self.write(collector / 'final.json', final)
        (collector / 'events.bin').write_bytes(b'x' * 1920)
        capture.update(status='COMPLETE_FOR_SELECTED_HOOKS', collector_run_id=directory.name,
            collector_cgroup=parent, binary_sha256='a' * 64, bpf_sha256='a' * 64,
            capture_budget=self.binding['collector_budget'], ready=dict(meta, type='READY'),
            started_monotonic_ns=begin - 30, ready_received_monotonic_ns=begin - 20,
            finalized_monotonic_ns=begin + 95, finalized=True, returncode=0, cpu_affinity=[4, 5],
            hash_scope=meta['hash_scope'], final=final, final_sha256=self.sha(collector / 'final.json'), issues=[])

    def replay(self):
        reader = verify.core.Evidence()
        return verify.verify_entries(reader, self.root, self.binding, self.plans), reader

    def access_index(self):
        return next(i for i, plan in enumerate(self.plans) if plan['file_access_mode'] == 'access')

    def test_two_real_eight_task_modes_read_all_sixteen_stdout_not_opaque_artifacts(self):
        original = Path.open
        def guarded(path, *args, **kwargs):
            if path.name == 'events.bin' or path.suffix == '.gz':
                raise AssertionError('large opaque artifact must not be read')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            (runs, fixed, outputs), reader = self.replay()
        self.assertEqual(len(runs), 2)
        self.assertEqual(len(outputs), 4)
        self.assertEqual(sum(path.endswith('.stdout') for path in reader.receipts), 16)
        self.assertEqual(runs[0]['work_details']['maximum_overlapping_worker_intervals'], 2)
        self.assertEqual({r['file_access']['status'] for r in runs}, {'NOT_ENABLED', 'DECLARED_COMPLETE_METADATA_CONSISTENT'})
        self.assertEqual(reader.cache, {})

    def test_raw_stdout_corruption_is_not_hidden_by_json_claims(self):
        (self.trial(0) / 'task-0000.stdout').write_bytes(b'changed\0')
        with self.assertRaisesRegex(ValueError, 'stdout'):
            self.replay()

    def test_query_span_corruption_is_rejected(self):
        self.mutate(self.trial(0) / 'task-0000-statistics.json', lambda value: value['query_spans'][0].update(duration_ns=999))
        with self.assertRaisesRegex(ValueError, 'query span'):
            self.replay()

    def test_capture_wrong_profile_sha_is_rejected(self):
        self.mutate(self.directory(self.access_index()) / 'capture.json', lambda value: value.update(profile_run_sha256='0' * 64))
        with self.assertRaisesRegex(ValueError, 'capture'):
            self.replay()

    def test_opaque_artifact_length_is_checked_without_byte_read(self):
        (self.directory(self.access_index()) / 'file-access/events.bin').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'artifact length'):
            self.replay()

    def test_sampler_gap_survives_as_independent_incomplete_dimension(self):
        self.mutate(self.trial(0) / 'load/load-sampler-stats.json', lambda value: value.update(missed_ticks=1))
        (runs, _, _), _ = self.replay()
        self.assertEqual(runs[0]['sampler_health']['status'], 'INCOMPLETE')
        self.assertEqual(runs[0]['sampler_health']['gaps']['missed_ticks'], 1)

    def test_collector_loss_is_preserved_not_made_green(self):
        directory = self.directory(self.access_index())
        final = json.loads((directory / 'file-access/final.json').read_text())
        final['health']['ring_drops'] = 1
        final['cpus'][0].update(attempted=11, ring_drops=1)
        final['observation_health'] = 'INCOMPLETE'
        self.write(directory / 'file-access/final.json', final)
        self.mutate(directory / 'capture.json', lambda value: value.update(final=final,
            final_sha256=self.sha(directory / 'file-access/final.json'), status='INCOMPLETE'))
        (runs, _, _), _ = self.replay()
        full = next(row for row in runs if row['condition']['file_access_mode'] == 'access')
        self.assertEqual(full['file_access']['status'], 'INCOMPLETE')
        self.assertGreater(full['file_access']['issues']['CPU_RING_DROPS'], 0)

    def test_different_actual_cross_mode_query_outputs_are_rejected(self):
        index = self.access_index()
        trial = self.trial(index)
        changed = b'x\0'
        digest = hashlib.sha256(changed).hexdigest()
        profile = json.loads((trial / 'profile-run.json').read_text())
        names = {'task-0000', 'task-0004'}
        for row in profile['results']:
            if row['task_id'] in names:
                row.update(output_sha256=digest, output_bytes=len(changed))
        self.write(trial / 'profile-run.json', profile)
        events = [json.loads(line) for line in (trial / 'task-events.jsonl').read_text().splitlines()]
        for event in events:
            if event['task_id'] in names and event['event'] == 'COMPLETE':
                event.update(output_sha256=digest, output_bytes=len(changed))
        (trial / 'task-events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))
        for name in names:
            (trial / (name + '.stdout')).write_bytes(changed)
        self.mutate(self.directory(index) / 'capture.json', lambda value: value.update(
            profile_sha256=self.sha(trial / 'profile-run.json'), profile_run_sha256=self.sha(trial / 'profile-run.json')))
        with self.assertRaisesRegex(ValueError, 'actual stdout differs'):
            self.replay()

    def test_complete_schedule_has_exactly_160_unique_cells(self):
        schedule = verify.expected_schedule(101646)
        self.assertEqual(len(schedule), 160)
        for block in range(5):
            selected = [row for row in schedule if row['block'] == block]
            self.assertEqual(len(selected), 32)
            self.assertEqual({row['concurrency'] for row in selected}, {2, 4, 6, 8})
            self.assertEqual(len({tuple(row[key] for key in ('cache', 'workspace_layout', 'concurrency', 'file_access_mode')) for row in selected}), 32)

    def test_formal_manifest_cannot_silently_accept_preflight_or_missing_cells(self):
        with self.assertRaises(ValueError):
            verify.validate_manifest(self.binding)

    def formal_manifest(self):
        return {**self.binding, 'output_equivalence': 'PASS', 'seed': 101646,
            'schedule': verify.expected_schedule(101646), 'campaigns': [{} for _ in range(160)],
            'queries': verify.FIXED_QUERIES, 'measurement_coordinator_sampler_collector_cpus': [4, 5],
            'measurement_modes': ['sampler', 'access'], 'source_inventory_sha256': 'e' * 64,
            'source': {'commit': '519a81750493f6fb35ee282ba3ff5bafdd58b81b', 'regular_files': 95989,
                       'regular_file_bytes': 1641397655, 'archive_sha256': 'f' * 64},
            'file_access_backend': 'kprobe-tracefs',
            'binaries': {**self.binding['binaries'], 'file_access_backend': 'kprobe-tracefs'},
            'source_integrity': 'PARTICIPATING_ROOTS_POST_CAMPAIGN_REHASHED_IDENTICAL',
            'participating_source_roots': ['/source-%d' % i for i in range(9)]}

    def test_full_formal_manifest_is_independently_accepted(self):
        self.assertEqual(len(verify.validate_manifest(self.formal_manifest(), 'boot')), 160)

    def test_formal_schedule_budget_cpu_or_boot_changes_fail_closed(self):
        for field, value in (('cpus', [0, 1, 2, 4]), ('measurement_modes', ['sampler']),
                             ('seed', 1), ('boot_id', 'changed')):
            manifest = self.formal_manifest()
            manifest[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify.validate_manifest(manifest, 'boot')
        manifest = self.formal_manifest()
        manifest['schedule'][0]['concurrency'] = 1
        with self.assertRaises(ValueError):
            verify.validate_manifest(manifest)
        manifest = self.formal_manifest()
        manifest['collector_budget']['ring_bytes'] = 64 * 1024 ** 2
        with self.assertRaises(ValueError):
            verify.validate_manifest(manifest)

    def test_actual_interval_overlap_cap_checked_separately(self):
        trial = self.trial(0)
        profile = json.loads((trial / 'profile-run.json').read_text())
        for row in profile['results']:
            row.update(queue_ns=0, completion_latency_ns=80)
        with self.assertRaisesRegex(ValueError, 'concurrency cap'):
            verify.verify_work_details(verify.core.Evidence(), trial, profile, self.plans[0], self.binding)

    def test_duplicate_or_reordered_campaign_path_is_rejected(self):
        self.binding['campaigns'][1]['path'] = self.binding['campaigns'][0]['path']
        with self.assertRaisesRegex(ValueError, 'index/order'):
            self.replay()


if __name__ == '__main__':
    unittest.main()
