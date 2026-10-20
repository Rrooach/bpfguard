#!/usr/bin/env python3
"""Unprivileged contract tests for the cooperative search experiment runner."""
from __future__ import annotations

import contextlib
import argparse
import copy
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import run as runner


class IoPrimeTests(unittest.TestCase):
    def test_repeatable_and_legacy_device_lists(self):
        devices = [Path('/dev/example-data'), Path('/dev/example-root')]
        args = argparse.Namespace(io_prime_devices=devices)
        self.assertEqual(runner.requested_io_prime_devices(args), devices)
        self.assertIsNot(runner.requested_io_prime_devices(args), devices)
        self.assertEqual(runner.requested_io_prime_devices(argparse.Namespace(
            io_prime_device=devices[0])), devices[:1])
        self.assertEqual(runner.requested_io_prime_devices(argparse.Namespace()), [])

    @unittest.skipUnless(shutil.which('dd'), 'dd required')
    def test_stopped_launch_uses_absolute_executable_and_read_only_device_command(self):
        command = runner.io_prime_command(Path('/dev/example-device'))
        self.assertTrue(Path(command[0]).is_absolute())
        self.assertEqual(command[1:], ['if=/dev/example-device', 'of=/dev/null',
            'iflag=direct', 'bs=4096', 'count=1', 'status=none'])

    def test_missing_dd_is_explicit(self):
        with mock.patch.object(runner.shutil, 'which', return_value=None), self.assertRaises(RuntimeError):
            runner.io_prime_command('/dev/example-device')


class QueryReuseTests(unittest.TestCase):
    def test_key_binds_every_equivalence_dimension(self):
        inventory = {'sha256': 'content', 'permission_scope_sha256': 'permission'}
        context = {'euid': 1, 'egid': 2, 'groups': [2], 'namespaces': {'user': 8, 'mnt': 9}, 'lsm_label': 'a'}
        params = [inventory, 'query', runner.GREP_OPTIONS, 'grep-digest', 'repo-v1', context]
        original = runner.query_reuse_key(*params)
        for index, changed in [(1, 'other-query'), (2, ['-F']), (3, 'new-grep'), (4, 'repo-v2')]:
            altered = copy.deepcopy(params)
            altered[index] = changed
            self.assertNotEqual(original, runner.query_reuse_key(*altered))
        for field in ('sha256', 'permission_scope_sha256'):
            altered = copy.deepcopy(params)
            altered[0][field] += '-changed'
            self.assertNotEqual(original, runner.query_reuse_key(*altered))
        for field in context:
            altered = copy.deepcopy(params)
            altered[5][field] = 'changed'
            self.assertNotEqual(original, runner.query_reuse_key(*altered))

    @unittest.skipUnless(shutil.which('grep'), 'GNU grep required')
    def test_real_reuse_computes_first_scan_and_preserves_exact_output(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            corpus, cache = root / 'corpus', root / 'cache'
            corpus.mkdir(); cache.mkdir()
            (corpus / 'with space').write_text('needle\n')
            (corpus / 'no-match').write_text('hay\n')
            context = runner.security_context()
            key = runner.query_reuse_key(runner.corpus_inventory(corpus), 'needle', runner.GREP_OPTIONS,
                runner.sha_file(shutil.which('grep')), 'fixture-v1', context)
            outputs = []
            for i, reuse in enumerate([None, {'directory': str(cache), 'key': key, 'security_context': context},
                                     {'directory': str(cache), 'key': key, 'security_context': context}]):
                job = root / ('job-%d.json' % i)
                stats = root / ('stats-%d.json' % i)
                runner.dump(job, {'grep': shutil.which('grep'), 'corpus': str(corpus), 'passes': 3,
                    'query': 'needle', 'reuse': reuse, 'statistics_file': str(stats)})
                result = subprocess.run([sys.executable, '-B', runner.__file__, '--worker', str(job)], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append(result.stdout)
                report = json.loads(stats.read_text())
                self.assertEqual(report['physical_grep_executions'], [3, 1, 0][i])
                self.assertEqual(report['cache_hits'], [0, 2, 3][i])
                self.assertEqual(report['schema_version'], 2)
                self.assertEqual(len(report['query_spans']), 3)
                self.assertEqual([row['execution_kind'] for row in report['query_spans']],
                                 [['SCAN'] * 3, ['SCAN', 'CACHE_HIT', 'CACHE_HIT'], ['CACHE_HIT'] * 3][i])
                for ordinal, row in enumerate(report['query_spans']):
                    self.assertEqual(row['query_ordinal'], ordinal)
                    self.assertEqual(row['end_ns'] - row['begin_ns'], row['duration_ns'])
                    self.assertGreaterEqual(row['duration_ns'], row['lock_wait_ns'])
                    self.assertEqual(row['status'], 'COMPLETE')
                    self.assertEqual(row['process'], report['query_spans'][0]['process'])
                    self.assertGreater(row['process']['start_ticks'], 0)
                    if ordinal:
                        self.assertGreaterEqual(row['begin_ns'], report['query_spans'][ordinal - 1]['end_ns'])
            self.assertEqual(outputs, [b'./with space\0' * 3] * 3)

    def test_permission_only_mutation_invalidates_inventory(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / 'file'
            path.write_text('same-content')
            before = runner.corpus_inventory(root)
            path.chmod(0o600)
            after = runner.corpus_inventory(root)
            self.assertEqual(before['sha256'], after['sha256'])
            self.assertNotEqual(before['permission_scope_sha256'], after['permission_scope_sha256'])

    @unittest.skipUnless(shutil.which('grep'), 'GNU grep required')
    def test_concurrent_reuse_performs_only_one_physical_scan(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            corpus, cache = root / 'corpus', root / 'cache'
            corpus.mkdir(); cache.mkdir()
            (corpus / 'a').write_text('needle\n' * 1000)
            context = runner.security_context()
            key = runner.query_reuse_key(runner.corpus_inventory(corpus), 'needle', runner.GREP_OPTIONS,
                runner.sha_file(shutil.which('grep')), 'fixture-v1', context)
            processes, reports = [], []
            for i in range(4):
                job, stats = root / ('job%d.json' % i), root / ('stats%d.json' % i)
                runner.dump(job, {'grep': shutil.which('grep'), 'corpus': str(corpus), 'query': 'needle', 'passes': 2,
                    'reuse': {'directory': str(cache), 'key': key, 'security_context': context}, 'statistics_file': str(stats)})
                processes.append(subprocess.Popen([sys.executable, '-B', runner.__file__, '--worker', str(job)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE))
                reports.append(stats)
            for process in processes:
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stdout, b'./a\0' * 2)
            values = [json.loads(path.read_text()) for path in reports]
            self.assertEqual(sum(row['physical_grep_executions'] for row in values), 1)
            self.assertEqual(sum(row['cache_hits'] for row in values), 7)


class SchedulingTests(unittest.TestCase):
    def test_each_randomized_block_contains_the_same_work_conditions(self):
        concurrency, modes = [1, 2, 4], ['baseline', 'sampler']
        conditions = runner.schedule(concurrency, modes, 3, 1, 7)
        self.assertEqual(len(conditions), 24)
        expected = {(c, m) for c in concurrency for m in modes}
        for offset in range(0, len(conditions), 6):
            block = conditions[offset:offset + 6]
            self.assertEqual({(row['concurrency'], row['mode']) for row in block}, expected)
            self.assertEqual(len({(row['warmup'], row['repetition']) for row in block}), 1)
        self.assertTrue(all(row['warmup'] for row in conditions[:6]))
        self.assertTrue(all(not row['warmup'] for row in conditions[6:]))
        self.assertEqual(conditions, runner.schedule(concurrency, modes, 3, 1, 7))
        self.assertNotEqual(conditions, runner.schedule(concurrency, modes, 3, 1, 8))

    def test_integer_lists_reject_duplicate_zero_and_empty_values(self):
        self.assertEqual(runner.parse_ints('1,2,8'), [1, 2, 8])
        for value in ('', '0', '-1', '1,1', '1,,2', 'x'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.parse_ints(value)

    @staticmethod
    def trial(mode='baseline', warmup=False, repetition=0):
        return {'mode': mode, 'concurrency': 1, 'warmup': warmup,
                'repetition': repetition, 'makespan_ns': 2_000_000_000,
                'results': [
                    {'query_index': query, 'exit_code': 0, 'output_sha256': str(query),
                     'output_bytes': query + 1, 'completion_latency_ns': 1_000_000_000,
                     'user_usec': 10, 'system_usec': 20}
                    for query in (0, 1)]}

    def test_equivalence_covers_warmup_and_all_conditions(self):
        first, second = self.trial(warmup=True), self.trial(mode='sampler')
        report = runner.summarize([first, second])
        self.assertEqual(report['output_equivalence'], 'PASS')
        self.assertEqual(len(report['conditions']), 1)
        self.assertEqual(report['conditions'][0]['samples'], 1)
        for field, value in [('output_sha256', 'different'), ('output_bytes', 99), ('exit_code', 2)]:
            bad = self.trial(mode='sampler')
            bad['results'][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'output differs'):
                runner.summarize([first, bad])

    def test_overhead_is_paired_by_repetition_and_same_concurrency(self):
        base, measured = self.trial(), self.trial(mode='sampler')
        measured['makespan_ns'] = 3_000_000_000
        unpaired = self.trial(mode='sampler', repetition=5)
        unpaired['makespan_ns'] = 900_000_000_000
        report = runner.summarize([base, measured, unpaired])
        self.assertEqual(report['paired_overhead'][0]['pairs'], 1)
        self.assertEqual(report['paired_overhead'][0]['median_slowdown'], 0.5)
        self.assertIsNone(report['paired_overhead'][0]['mean_slowdown_ci95_bootstrap'])

    def test_ready_requires_matching_run_boot_cgroups_and_flushed_window(self):
        identity = {'path': '/cg/work', 'inode': 1, 'device': 28}
        meta = {'label': 'run', 'boot_id': 'boot', 'cgroups': [identity]}
        first = {'seq': 0, 'monotonic_ns': 1, 'collection_end_ns': 2, 'cgroups': [{'present': True}]}
        runner.validate_first_sample(meta, first, 'run', 'boot', [identity])
        for key, changed in [('label', 'other'), ('boot_id', 'other'), ('cgroups', [])]:
            broken = dict(meta, **{key: changed})
            with self.assertRaises(RuntimeError):
                runner.validate_first_sample(broken, first, 'run', 'boot', [identity])
        for key, changed in [('seq', 1), ('collection_end_ns', 0), ('cgroups', [{'present': False}])]:
            broken = dict(first, **{key: changed})
            with self.assertRaises(RuntimeError):
                runner.validate_first_sample(meta, broken, 'run', 'boot', [identity])


class IdentityAndCorpusTests(unittest.TestCase):
    def test_cleanup_refuses_each_mismatched_cgroup_identity_field(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            expected = runner.cgroup_identity(path)
            for field, different in [('path', name + '-replacement'),
                                     ('inode', expected['inode'] + 1),
                                     ('device', expected['device'] + 1)]:
                with self.subTest(field=field):
                    actual = dict(expected, **{field: different})
                    errors = []
                    with mock.patch.object(runner, 'cgroup_identity', return_value=actual), \
                            mock.patch.object(Path, 'write_text') as write, \
                            mock.patch.object(Path, 'rmdir') as remove:
                        self.assertFalse(runner.cleanup_owned_cgroup(path, expected, errors))
                        write.assert_not_called()
                        remove.assert_not_called()
                    self.assertTrue(errors)

    def test_cleanup_read_failure_is_recorded_instead_of_aborting_finalization(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            expected = runner.cgroup_identity(path)
            errors = []
            with mock.patch.object(Path, 'read_text', side_effect=OSError('events unavailable')), \
                    mock.patch.object(Path, 'write_text') as write, \
                    mock.patch.object(Path, 'rmdir') as remove:
                self.assertFalse(runner.cleanup_owned_cgroup(path, expected, errors))
                write.assert_not_called()
                remove.assert_not_called()
            self.assertTrue(any('events unavailable' in message for message in errors))

    def test_cleanup_rechecks_identity_before_removing_empty_cgroup(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            expected = runner.cgroup_identity(path)
            replacement = dict(expected, inode=expected['inode'] + 1)
            errors = []
            with mock.patch.object(runner, 'cgroup_identity', side_effect=[expected, replacement]), \
                    mock.patch.object(Path, 'read_text', return_value='populated 0\nfrozen 0\n'), \
                    mock.patch.object(Path, 'write_text') as write, \
                    mock.patch.object(Path, 'rmdir') as remove:
                self.assertFalse(runner.cleanup_owned_cgroup(path, expected, errors))
                write.assert_not_called()
                remove.assert_not_called()
            self.assertTrue(errors)

    def test_cleanup_removes_verified_empty_cgroup_without_kill(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            expected = runner.cgroup_identity(path)
            errors = []
            with mock.patch.object(Path, 'read_text', return_value='populated 0\nfrozen 0\n'), \
                    mock.patch.object(Path, 'write_text') as write, \
                    mock.patch.object(Path, 'rmdir') as remove:
                self.assertTrue(runner.cleanup_owned_cgroup(path, expected, errors))
                write.assert_not_called()
                remove.assert_called_once()
            self.assertEqual(errors, [])

    def test_failed_stopped_launch_does_not_signal_an_already_reaped_pid(self):
        with mock.patch.object(runner.os, 'fork', return_value=4242), \
                mock.patch.object(runner.os, 'waitpid', return_value=(4242, 127 << 8)), \
                mock.patch.object(runner, 'terminate_child') as terminate:
            with self.assertRaisesRegex(RuntimeError, 'before stopped launch'):
                runner.launch_stopped(['/bin/false'], '.', 'unused-out', 'unused-err',
                                      Path('/sys/fs/cgroup/test-fixture'), {0})
            terminate.assert_not_called()

    def test_failed_second_stop_does_not_signal_an_already_reaped_worker(self):
        stopped_status = (signal.SIGSTOP << 8) | 0x7f
        with mock.patch.object(runner.os, 'fork', return_value=4242), \
                mock.patch.object(runner, 'wait_child_stop', side_effect=[stopped_status, 127 << 8]), \
                mock.patch.object(Path, 'write_text'), \
                mock.patch.object(Path, 'read_text', return_value='0::/test-fixture\n'), \
                mock.patch.object(runner.os, 'kill') as send_signal, \
                mock.patch.object(runner, 'terminate_child') as terminate:
            with self.assertRaisesRegex(RuntimeError, 'before prepared gate'):
                runner.launch_stopped(['/bin/false'], '.', 'unused-out', 'unused-err',
                                      Path('/sys/fs/cgroup/test-fixture'), {0}, prepare_worker=True)
            send_signal.assert_called_once_with(4242, signal.SIGCONT)
            terminate.assert_not_called()

    def test_stopped_launch_timeout_reaps_only_the_owned_child(self):
        with mock.patch.object(runner.os, 'fork', return_value=4242), \
                mock.patch.object(runner, 'wait_child_stop',
                                  side_effect=RuntimeError('preparation timed out')), \
                mock.patch.object(runner, 'terminate_child') as terminate:
            with self.assertRaisesRegex(RuntimeError, 'timed out'):
                runner.launch_stopped(['/bin/false'], '.', 'unused-out', 'unused-err',
                                      Path('/sys/fs/cgroup/test-fixture'), {0}, prepare_worker=True)
            terminate.assert_called_once_with(4242)

    def test_pid_stat_parsing_handles_parentheses_and_spaces_in_comm(self):
        # Token 0 after the final ')' is kernel stat field 3; token 19 is starttime.
        fields = ['S'] + ['0'] * 18 + ['987654'] + ['0'] * 6
        hostile_stat = '42 (name ) ( tricky)) ' + ' '.join(fields) + '\n'
        with mock.patch.object(Path, 'read_text', return_value=hostile_stat):
            self.assertEqual(runner.process_identity(42), {'pid': 42, 'start_ticks': 987654})

    def test_real_process_identity_uses_start_ticks_not_pid_only(self):
        identity = runner.process_identity(os.getpid())
        self.assertEqual(identity['pid'], os.getpid())
        self.assertGreater(identity['start_ticks'], 0)

    def test_semantic_events_bind_boot_run_cgroup_and_process(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            identity = runner.cgroup_identity(directory)
            self.assertEqual(identity['inode'], directory.stat().st_ino)
            self.assertEqual(identity['device'], directory.stat().st_dev)
            task = {'task_id': 'task-1', 'agent_id': 'agent-1', 'tool_call_id': 'call-1',
                    'process': {'pid': 42, 'start_ticks': 9}, 'cgroup': identity}
            events = runner.SemanticEvents(directory / 'events.jsonl', 'run-1', 'boot-1')
            events.emit(task, 'START', now=10)
            events.emit(task, 'COMPLETE', now=20)
            events.close()
            rows = [json.loads(line) for line in (directory / 'events.jsonl').read_text().splitlines()]
            self.assertEqual([row['seq'] for row in rows], [0, 1])
            self.assertEqual([row['monotonic_ns'] for row in rows], [10, 20])
            for row in rows:
                self.assertEqual(row['boot_id'], 'boot-1')
                self.assertEqual(row['run_id'], 'run-1')
                self.assertEqual(row['process']['start_ticks'], 9)
                self.assertEqual(row['cgroup']['inode'], identity['inode'])

    def test_inventory_is_stable_excludes_git_and_detects_content_changes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'b').write_text('second')
            (root / 'a').write_text('first')
            (root / '.git').mkdir()
            (root / '.git' / 'config').write_text('ignored')
            first = runner.corpus_inventory(root)
            self.assertEqual([row['path'] for row in first['files']], ['a', 'b'])
            self.assertEqual(first, runner.corpus_inventory(root))
            (root / '.git' / 'config').write_text('still ignored')
            self.assertEqual(first, runner.corpus_inventory(root))
            (root / 'a').write_text('other')
            self.assertNotEqual(first['sha256'], runner.corpus_inventory(root)['sha256'])

    def test_inventory_refuses_file_and_directory_symlinks(self):
        for directory_link in (False, True):
            with self.subTest(directory_link=directory_link), tempfile.TemporaryDirectory() as name:
                base = Path(name)
                corpus = base / 'corpus'
                corpus.mkdir()
                (corpus / 'real').write_text('x')
                (corpus / 'link').symlink_to(base if directory_link else corpus / 'real',
                                           target_is_directory=directory_link)
                with self.assertRaisesRegex(ValueError, 'symlinks'):
                    runner.corpus_inventory(corpus)

    def test_inventory_bounds_fail_closed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with self.assertRaisesRegex(ValueError, 'empty corpus'):
                runner.corpus_inventory(root)
            (root / 'one').write_text('ab')
            with mock.patch.object(runner, 'MAX_BYTES', 1), self.assertRaisesRegex(ValueError, 'budget'):
                runner.corpus_inventory(root)
            with mock.patch.object(runner, 'MAX_FILES', 0), self.assertRaisesRegex(ValueError, 'budget'):
                runner.corpus_inventory(root)


class WorkerTests(unittest.TestCase):
    def test_query_measurements_are_buffered_and_keep_failed_span(self):
        identity = {'run_id': 'run-1', 'task_id': 'task-1', 'agent_id': 'agent-1',
                    'tool_call_id': 'call-1', 'process': {'pid': 42, 'start_ticks': 90}}
        measurements = runner.QueryMeasurements(identity, 'a' * 64, 3)
        with mock.patch.object(runner.time, 'monotonic_ns', side_effect=[100, 160, 200, 290]):
            with measurements.span(0) as span:
                span.update(execution_kind='SCAN', returncode=0)
            with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
                with measurements.span(1):
                    raise RuntimeError('fixture failure')
        self.assertEqual([row['duration_ns'] for row in measurements.rows], [60, 90])
        self.assertEqual([row['status'] for row in measurements.rows], ['COMPLETE', 'FAILED'])
        self.assertEqual(measurements.rows[0]['query_id'], 'call-1:query-000000')
        self.assertEqual(measurements.rows[0]['query_index'], 3)
        self.assertEqual(measurements.rows[0]['process'], identity['process'])

    def test_failed_grep_retains_raw_partial_query_statistics(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            job, stats = root / 'job.json', root / 'stats.json'
            runner.dump(job, {'grep': '/not/executed', 'corpus': name, 'query': 'literal',
                              'passes': 2, 'statistics_file': str(stats)})
            with mock.patch.object(runner.subprocess, 'run', return_value=mock.Mock(returncode=2)):
                self.assertEqual(runner.worker(job), 2)
            raw = json.loads(stats.read_text())
            self.assertEqual(len(raw['query_spans']), 1)
            self.assertEqual(raw['logical_queries'], 2)
            self.assertEqual(raw['query_spans'][0]['status'], 'FAILED')
            self.assertEqual(raw['query_spans'][0]['returncode'], 2)

    @unittest.skipUnless(shutil.which('grep'), 'grep is required')
    def test_preflight_worker_is_initialized_and_stopped_before_search_release(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            corpus = base / 'corpus'
            corpus.mkdir()
            (corpus / 'match.txt').write_text('needle\n')
            ready_file, stdout = base / 'ready.json', base / 'stdout'
            job = base / 'job.json'
            job.write_text(json.dumps({'grep': shutil.which('grep'), 'corpus': str(corpus),
                                       'query': 'needle', 'passes': 1,
                                       'preflight_stop': True, 'ready_file': str(ready_file)}))
            with stdout.open('xb') as out:
                proc = subprocess.Popen([sys.executable, runner.__file__, '--worker', str(job)],
                                        cwd=base, stdout=out, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 5
                    waited, status = 0, 0
                    while not waited and time.monotonic() < deadline:
                        waited, status = os.waitpid(proc.pid, os.WNOHANG | os.WUNTRACED)
                        if not waited:
                            time.sleep(0.005)
                    if waited and not os.WIFSTOPPED(status):
                        proc.returncode = os.waitstatus_to_exitcode(status)
                    self.assertEqual(waited, proc.pid, 'worker did not reach its readiness barrier')
                    self.assertTrue(os.WIFSTOPPED(status), 'worker exited before the readiness barrier')
                    self.assertEqual(os.WSTOPSIG(status), signal.SIGSTOP)
                    ready = json.loads(ready_file.read_text())
                    self.assertEqual(ready['process'], runner.process_identity(proc.pid))
                    self.assertEqual(ready['boot_id'],
                                     Path('/proc/sys/kernel/random/boot_id').read_text().strip())
                    self.assertGreaterEqual(ready['rusage_user_usec'], 0)
                    self.assertGreaterEqual(ready['rusage_system_usec'], 0)
                    self.assertGreater(ready['rusage_user_usec'] + ready['rusage_system_usec'], 0)
                    self.assertEqual(stdout.stat().st_size, 0, 'search started before release')
                    proc.send_signal(signal.SIGCONT)
                    _, stderr = proc.communicate(timeout=10)
                    self.assertEqual(proc.returncode, 0, stderr)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                    proc.communicate(timeout=5)
            self.assertEqual(stdout.read_bytes(), b'./match.txt\x00')

    @unittest.skipUnless(shutil.which('grep'), 'grep is required')
    def test_hostile_query_is_literal_and_stdout_contains_only_matching_paths(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            corpus = base / 'corpus'
            corpus.mkdir()
            query = '-n;$(touch SHOULD_NOT_EXIST)'
            (corpus / 'match.txt').write_text(query + '\nSECRET_BODY_NOT_FOR_STDOUT\n')
            (corpus / 'newline\nfilename.txt').write_text(query)
            (corpus / 'miss.txt').write_text('SECRET_BODY_NOT_FOR_STDOUT\n')
            (corpus / '.git').mkdir()
            (corpus / '.git' / 'ignored.txt').write_text(query)
            job = base / 'job.json'
            job.write_text(json.dumps({'grep': shutil.which('grep'), 'corpus': str(corpus),
                                       'query': query, 'passes': 2}))
            result = subprocess.run([sys.executable, runner.__file__, '--worker', str(job)],
                                    cwd=base, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sorted(result.stdout.split(b'\x00')[:-1]),
                             sorted([b'./match.txt', b'./newline\nfilename.txt'] * 2))
            self.assertTrue(result.stdout.endswith(b'\x00'))
            self.assertNotIn(b'SECRET_BODY', result.stdout)
            self.assertFalse((corpus / 'SHOULD_NOT_EXIST').exists())
            self.assertFalse((base / 'SHOULD_NOT_EXIST').exists())
            values = json.loads(job.read_text())
            values['query'] = 'no-match-at-all'
            job.write_text(json.dumps(values))
            result = subprocess.run([sys.executable, runner.__file__, '--worker', str(job)],
                                    cwd=base, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'')

    def test_grep_error_is_not_treated_as_no_match(self):
        with tempfile.TemporaryDirectory() as name:
            job = Path(name) / 'job.json'
            job.write_text(json.dumps({'grep': '/not/executed', 'corpus': name,
                                       'query': 'literal', 'passes': 2}))
            with mock.patch.object(runner.subprocess, 'run', return_value=mock.Mock(returncode=2)) as execute:
                self.assertEqual(runner.worker(job), 2)
                self.assertEqual(execute.call_count, 1)
                self.assertIn('--', execute.call_args.args[0])


class KernelWakeupTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'), 'a native C compiler is required')
    def test_exact_bpf_wakeup_helper_handles_first_and_repeated_wakeups(self):
        # Compile the actual helper, not a separately translated state machine.
        # Native stubs isolate transition semantics; verifier/attachment remains
        # a separate VM test and is not established by this replay.
        source = (Path(runner.__file__).resolve().parents[2] /
                  'bpf/kernel_hist.bpf.c').read_text()
        begin = source.index('static __always_inline void kh_wakeup(')
        end = source.index('SEC("tp_btf/sched_wakeup")', begin)
        helper = source[begin:end]
        fixture = r'''
#include <assert.h>
#include <stdint.h>
#undef __always_inline
#define __always_inline inline
typedef uint64_t __u64;
typedef uint32_t __u32;
#define KH_TASK_UNINTERRUPTIBLE 2
enum { KH_SCHED_OFFCPU_D, KH_SCHED_OFFCPU_S, KH_C_WAKEUPS };
struct task_struct { int unused; };
struct kh_task { __u64 runq_ts, block_ts; unsigned int block_state, domain_mask; };
static struct kh_task state;
static __u64 clock_ns, recorded_start, recorded_end;
static int matches = 1, storage = 1, recordings, wakeups, recorded_metric;
static struct kh_task *kh_task(struct task_struct *task)
{ (void)task; state.domain_mask = 1; return storage && matches ? &state : 0; }
static __u64 bpf_ktime_get_ns(void) { return clock_ns; }
static void kh_record(__u32 mask, int metric, __u64 start, __u64 end)
{ assert(mask == 1); recordings++; recorded_metric = metric; recorded_start = start; recorded_end = end; }
static void kh_count(__u32 mask, int counter) { assert(mask == 1); assert(counter == KH_C_WAKEUPS); wakeups++; }
''' + helper + r'''
int main(void)
{
    struct task_struct task = {0};
    clock_ns = 100;
    kh_wakeup(&task);
    assert(state.runq_ts == 100 && recordings == 0 && wakeups == 0);
    clock_ns = 200;
    kh_wakeup(&task);
    assert(state.runq_ts == 100 && recordings == 0 && wakeups == 0);
    state.runq_ts = 0;
    state.block_ts = 150;
    state.block_state = KH_TASK_UNINTERRUPTIBLE;
    clock_ns = 250;
    kh_wakeup(&task);
    assert(state.runq_ts == 250 && state.block_ts == 0);
    assert(recordings == 1 && wakeups == 1 && recorded_metric == KH_SCHED_OFFCPU_D);
    assert(recorded_start == 150 && recorded_end == 250);
    clock_ns = 300;
    kh_wakeup(&task);
    assert(state.runq_ts == 250 && recordings == 1 && wakeups == 1);
    state.runq_ts = 0;
    state.block_ts = 300;
    state.block_state = 1;
    clock_ns = 400;
    kh_wakeup(&task);
    assert(state.runq_ts == 400 && state.block_ts == 0);
    assert(recordings == 2 && wakeups == 2 && recorded_metric == KH_SCHED_OFFCPU_S);
    state.runq_ts = 0;
    matches = 0;
    kh_wakeup(&task);
    assert(state.runq_ts == 0 && recordings == 2 && wakeups == 2);
    matches = 1;
    storage = 0;
    kh_wakeup(&task);
    assert(state.runq_ts == 0 && recordings == 2 && wakeups == 2);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as name:
            executable = Path(name) / 'wakeup-replay'
            build = subprocess.run([shutil.which('cc'), '-std=c11', '-Wall', '-Wextra',
                                    '-Werror', '-O2', '-x', 'c', '-', '-o', str(executable)],
                                   input=fixture, text=True, capture_output=True, timeout=15)
            self.assertEqual(build.returncode, 0, build.stderr)
            replay = subprocess.run([str(executable)], capture_output=True, timeout=5)
            self.assertEqual(replay.returncode, 0, replay.stderr)


class CliTests(unittest.TestCase):
    def test_invalid_configuration_is_rejected_before_cgroup_setup(self):
        for options in (['--jobs', '0'], ['--passes', '0'], ['--repetitions', '0'],
                        ['--warmups', '-1'], ['--timeout-seconds', '0'],
                        ['--modes', 'baseline,baseline'], ['--modes', 'bogus'],
                        ['--concurrency', '129'], ['--interval-ms', '0'],
                        ['--interval-ms', '60001'], ['--process-interval-ms', '1']):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as name:
                base = Path(name)
                corpus = base / 'corpus'
                corpus.mkdir()
                (corpus / 'a').write_text('match')
                queries = base / 'queries.json'
                queries.write_text('["match"]')
                argv = ['run.py', '--corpus', str(corpus), '--queries-file', str(queries),
                        '--output-dir', str(base / 'output'), '--sampler', sys.executable, *options]
                with mock.patch.object(sys, 'argv', argv), mock.patch.object(runner, 'ensure_cgroup_parent') as setup:
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                        runner.main()
                    self.assertNotEqual(error.exception.code, 0)
                    setup.assert_not_called()
                self.assertFalse((base / 'output').exists())


if __name__ == '__main__':
    unittest.main()
