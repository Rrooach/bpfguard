import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('file_access_analyze', Path(__file__).with_name('access_analyze.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IngestConnection:
    """Count bounded batches/transactions and inject a disposable SQL failure."""
    def __init__(self, connection, fail_batch=None, fail_commit=False):
        self.connection = connection
        self.fail_batch = fail_batch
        self.fail_commit = fail_commit
        self.event_batches = []
        self.commits = 0
        self.rollbacks = 0

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def executemany(self, query, rows):
        if query.startswith('INSERT INTO events VALUES('):
            self.event_batches.append(len(rows))
            if len(self.event_batches) == self.fail_batch:
                raise sqlite3.OperationalError('fixture event insert failure')
        return self.connection.executemany(query, rows)

    def commit(self):
        self.commits += 1
        if self.fail_commit:
            raise sqlite3.OperationalError('fixture commit failure')
        return self.connection.commit()

    def rollback(self):
        self.rollbacks += 1
        return self.connection.rollback()


class AccessAnalyzeTests(unittest.TestCase):
    def event(self, **changes):
        value = dict.fromkeys(MODULE.EVENT_FIELDS, 0)
        value.update(magic=MODULE.MAGIC, version=1, kind=1, size=MODULE.EVENT.size,
            flags=MODULE.OBJECT_VALID | MODULE.REQUESTED_VALID | MODULE.SYSCALL_VALID,
            sequence=1, domain_id=2, caller_cgroup_id=3, process_birth_ns=10,
            thread_birth_ns=10, start_ns=110, end_ns=120, sys_start_ns=105, sys_end_ns=125,
            mount_id=4, inode=42, file_size=100, requested_bytes=20, result=10,
            syscall_result=10, device=253 << 20, generation=1, tgid=5, tid=5)
        value.update(changes)
        return MODULE.EVENT.pack(*(value[key] for key in MODULE.EVENT_FIELDS))

    def profile(self):
        return {'status': 'COMPLETE', 'boot_id': 'boot', 'run_id': 'run',
            'release_ns': 100, 'end_ns': 200, 'makespan_ns': 100,
            'root_cgroup': {'path': '/sys/fs/cgroup/owned/run', 'inode': 2, 'device': 28},
            'tasks': [{'task_id': 'task', 'process': {'pid': 5, 'start_ticks': 12},
                'cgroup': {'path': '/sys/fs/cgroup/owned/run/task', 'inode': 3, 'device': 28}}]}

    def inventory(self):
        return {'boot_id': 'boot', 'pre_post_identical': True, 'read_only': True,
            'objects': [{'path': 'a', 'inode': 42, 'kernel_device': 253 << 20,
                'size': 100, 'mtime_sec': 2, 'mtime_nsec': 0, 'ctime_sec': 3, 'ctime_nsec': 0}]}

    def test_window_binds_exact_wallclock(self):
        window = MODULE.profile_window(self.profile())
        self.assertEqual(window['associations'], {3: 'task'})
        self.assertEqual((window['release_ns'], window['end_ns']), (100, 200))

    def test_invalid_window_not_guessed(self):
        for key, value in (('boot_id', None), ('release_ns', True), ('end_ns', 100),
                ('makespan_ns', 101), ('status', 'FAILED')):
            profile = self.profile()
            profile[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                MODULE.profile_window(profile)

    def test_group_shared_by_two_tasks_not_time_attributed(self):
        profile = self.profile()
        profile['tasks'].append(copy.deepcopy(profile['tasks'][0]))
        profile['tasks'][-1]['task_id'] = 'other'
        window = MODULE.profile_window(profile)
        self.assertEqual(window['associations'], {})
        self.assertEqual(window['shared_cgroups'], [3])

    def test_group_must_descend_root_and_keep_device(self):
        for key, value in (('path', '/sys/fs/cgroup/another/task'), ('device', 29)):
            profile = self.profile()
            profile['tasks'][0]['cgroup'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                MODULE.profile_window(profile)

    def test_boundary_crossings_are_not_silently_discarded(self):
        self.assertEqual(MODULE.temporal_scope(100, 200, 100, 200), 'IN_WINDOW')
        self.assertEqual(MODULE.temporal_scope(99, 101, 100, 200), 'CROSSES_WINDOW_BOUNDARY')
        self.assertEqual(MODULE.temporal_scope(199, 201, 100, 200), 'CROSSES_WINDOW_BOUNDARY')
        self.assertEqual(MODULE.temporal_scope(0, 99, 100, 200), 'BEFORE')
        self.assertEqual(MODULE.temporal_scope(201, 300, 100, 200), 'AFTER')

    def test_histogram_zero_and_binned_quantiles_are_explicit(self):
        counter = MODULE.Counter()
        for value in (0, 1, 2, 3, 4):
            counter[MODULE.log2_bin(value)] += 1
        result = MODULE.histogram(counter, 'bytes')
        self.assertEqual(result['observations'], 5)
        self.assertEqual(result['quantiles']['p50'], {'lower_inclusive': 2, 'upper_inclusive': 3})
        self.assertIn('NOT_EXACT', result['quantile_quality'])

    def test_empty_histogram_has_no_phantom_quantiles(self):
        result = MODULE.histogram(MODULE.Counter(), 'bytes')
        self.assertEqual(result['quantiles'], {'p50': None, 'p95': None, 'p99': None})

    def test_fault_retry_is_not_a_completed_fault(self):
        outcome, flags = MODULE.fault_classification(0x400 | 0x4)
        self.assertEqual(outcome, 'RETRY_ATTEMPT')
        self.assertEqual(flags, ['MAJOR', 'RETRY'])

    def test_current_kernel_fault_bits_and_unknown_are_kept(self):
        self.assertEqual(MODULE.fault_classification(0x800)[0], 'ERROR_OR_FALLBACK_ATTEMPT')
        self.assertEqual(MODULE.fault_classification(0x4000)[1], ['COMPLETED'])
        self.assertEqual(MODULE.fault_classification(0x8)[1], ['UNKNOWN_RETURN_BITS'])

    def test_inventory_cannot_cross_boot_or_skip_readonly_prepost(self):
        for key, value in (('boot_id', 'other'), ('read_only', False), ('pre_post_identical', False)):
            inventory = self.inventory()
            inventory[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                MODULE.inventory_rows(inventory, 'boot')

    def test_content_inventory_alone_cannot_claim_runtime_path(self):
        inventory = self.inventory()
        del inventory['objects'][0]['inode']
        with self.assertRaises(ValueError):
            MODULE.inventory_rows(inventory, 'boot')

    def test_inventory_mount_and_generation_remain_optional_unproven(self):
        row = MODULE.inventory_rows(self.inventory(), 'boot')[0]
        self.assertEqual(row[-3:-1], (None, None))

    def test_database_is_not_a_json_array(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / 'events.sqlite'
            connection = MODULE.initialize_database(database, MODULE.inventory_rows(self.inventory(), 'boot'))
            try:
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM inventory').fetchone()[0], 1)
                self.assertEqual(connection.execute('PRAGMA temp_store').fetchone()[0], 1)
            finally:
                connection.close()

    def test_detail_requires_exact_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / 'events.sqlite'
            MODULE.initialize_database(database).close()
            with self.assertRaises(ValueError):
                MODULE.export_detail(database, Path(temporary) / 'bad.jsonl')

    def analyze_fixture(self, raw, callback):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            binary = temporary / 'events.bin'
            binary.write_bytes(raw)
            inventory = MODULE.inventory_rows(self.inventory(), 'boot')
            connection = MODULE.initialize_database(temporary / 'events.sqlite', inventory)
            try:
                result = MODULE.ingest_events(binary, connection, MODULE.profile_window(self.profile()), {2},
                    {(253 << 20, 42, 100)})
                top = MODULE.export_file_rows(connection, temporary / 'per-file.csv')
                callback(connection, result, top, temporary)
            finally:
                connection.close()

    def test_exact_binary_abi_is_192_bytes(self):
        self.assertEqual(MODULE.EVENT.size, 192)
        self.assertEqual(len(self.event()), 192)

    def test_ingest_commits_once_with_bounded_batches_across_4096_boundary(self):
        for count in (0, 1, 4095, 4096, 4097, 8193):
            with self.subTest(records=count), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binary, database = root / 'events.bin', root / 'events.sqlite'
                raw = b''.join(self.event(sequence=i) for i in range(1, count + 1))
                binary.write_bytes(raw)
                connection = IngestConnection(MODULE.initialize_database(database))
                statements = []
                connection.set_trace_callback(lambda sql: statements.append(sql) if
                    sql in ('BEGIN ', 'COMMIT', 'ROLLBACK') else None)
                try:
                    receipt = MODULE.ingest_events(binary, connection,
                        MODULE.profile_window(self.profile()), {2})
                    self.assertEqual(connection.commits, 1)
                    self.assertEqual(connection.rollbacks, 0)
                    self.assertFalse(connection.in_transaction)
                    self.assertEqual(connection.event_batches,
                        [4096] * (count // 4096) + ([count % 4096] if count % 4096 else []))
                    self.assertEqual(statements.count('COMMIT'), int(count > 0))
                    self.assertEqual(statements.count('BEGIN '), int(count > 0))
                    self.assertEqual(connection.execute('PRAGMA journal_mode').fetchone()[0], 'delete')
                    self.assertEqual(connection.execute('PRAGMA synchronous').fetchone()[0], 2)
                    self.assertEqual(receipt.get('records', 0), count)
                    self.assertEqual(receipt['sha256'], hashlib.sha256(raw).hexdigest())
                    self.assertEqual(receipt['issues'], {})
                    self.assertEqual(b''.join(row[0] for row in connection.execute(
                        'SELECT raw FROM events ORDER BY record_number')), raw)
                    self.assertEqual(connection.execute('SELECT COUNT(*) FROM cpu_sequences').fetchone()[0], count)
                finally:
                    connection.close()
                with sqlite3.connect(str(database)) as reopened:
                    self.assertEqual(reopened.execute('SELECT COUNT(*) FROM events').fetchone()[0], count)

    def test_ingest_bad_records_after_flush_are_retained_in_same_transaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'events.bin'
            bad_record = self.event(magic=0, sequence=4097)
            raw = b''.join(self.event(sequence=i) for i in range(1, 4097))
            raw += bad_record + self.event(sequence=4097) + b'abc'
            binary.write_bytes(raw)
            connection = IngestConnection(MODULE.initialize_database(root / 'events.sqlite'))
            try:
                receipt = MODULE.ingest_events(binary, connection,
                    MODULE.profile_window(self.profile()), {2})
                self.assertEqual(connection.event_batches, [4096, 3])
                self.assertEqual(connection.commits, 1)
                self.assertEqual(connection.rollbacks, 0)
                self.assertEqual(receipt['records'], 4099)
                self.assertEqual(receipt['sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(receipt['issues'], {'EVENT_MAGIC_VERSION_SIZE': 1, 'TRUNCATED_EVENT': 1})
                self.assertEqual(list(connection.execute('SELECT record_number,raw FROM events WHERE valid=0 ORDER BY record_number')),
                    [(4097, bad_record), (4099, b'abc')])
                self.assertEqual(list(connection.execute('SELECT * FROM malformed ORDER BY record_number')),
                    [(4097, 'EVENT_MAGIC_VERSION_SIZE'), (4099, 'TRUNCATED_EVENT')])
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM cpu_sequences').fetchone()[0], 4097)
            finally:
                connection.close()

    def test_ingest_failure_rolls_back_all_preceding_batches(self):
        for failure in ('second_batch', 'commit', 'raw_read'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binary, database = root / 'events.bin', root / 'events.sqlite'
                binary.write_bytes(self.event(magic=0) +
                    b''.join(self.event(sequence=i) for i in range(1, 4097)))
                connection = IngestConnection(MODULE.initialize_database(database),
                    fail_batch=2 if failure == 'second_batch' else None,
                    fail_commit=failure == 'commit')
                original_decode = MODULE.decode_event
                decoded = [0]
                def decode(raw):
                    decoded[0] += 1
                    if failure == 'raw_read' and decoded[0] == 4097:
                        raise OSError('fixture raw read failure after first SQL batch')
                    return original_decode(raw)
                try:
                    with patch.object(MODULE, 'decode_event', side_effect=decode), self.assertRaises(
                            (sqlite3.OperationalError, OSError)):
                        MODULE.ingest_events(binary, connection,
                            MODULE.profile_window(self.profile()), {2})
                    self.assertEqual(connection.rollbacks, 1)
                    self.assertEqual(connection.commits, int(failure == 'commit'))
                    self.assertFalse(connection.in_transaction)
                    for table in ('events', 'malformed', 'cpu_sequences'):
                        self.assertEqual(connection.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 0)
                finally:
                    connection.close()
                with sqlite3.connect(str(database)) as reopened:
                    self.assertEqual(reopened.execute('SELECT COUNT(*) FROM events').fetchone()[0], 0)

    def test_analyze_failure_after_first_flush_cannot_emit_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = b''.join(self.event(sequence=i) for i in range(1, 4098))
            self.bundle(root, raw=raw)
            original = MODULE.initialize_database
            def failing_database(*args, **kwargs):
                return IngestConnection(original(*args, **kwargs), fail_batch=2)
            output = root / 'analysis'
            with patch.object(MODULE, 'initialize_database', side_effect=failing_database), self.assertRaises(
                    sqlite3.OperationalError):
                MODULE.analyze(root / 'collector', root / 'profile-run.json', output)
            self.assertFalse((output / 'summary.json').exists())
            with sqlite3.connect(str(output / 'events.sqlite')) as reopened:
                for table in ('events', 'malformed', 'cpu_sequences'):
                    self.assertEqual(reopened.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0], 0)

    def test_read_records_remain_individually_exportable(self):
        raw = self.event() + self.event(sequence=2, result=0, syscall_result=0)
        def check(connection, receipt, top, root):
            result = MODULE.database_summary(connection)
            self.assertEqual(receipt['records'], 2)
            self.assertEqual(result['read_calls'], 2)
            self.assertEqual(result['read_requested_bytes'], 40)
            self.assertEqual(result['read_returned_bytes'], 10)
            self.assertEqual(result['read_duration_ns'], 20)
            self.assertEqual(result['unique_regular_files'], 1)
            self.assertEqual(top[0]['inventory_paths'], ['a'])
            self.assertIn('NO_RUNTIME', top[0]['path_quality'])
            output = root / 'details.jsonl'
            self.assertEqual(MODULE.export_detail(root / 'events.sqlite', output, tid=5, start_ns=100, end_ns=200), 2)
            events = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(events[0]['result'], 10)
            self.assertEqual(events[1]['result'], 0)
            self.assertEqual(bytes.fromhex(events[0]['raw_hex']), self.event())
        self.analyze_fixture(raw, check)

    def test_unique_object_not_number_of_reads_or_inventory_files(self):
        def check(connection, receipt, top, root):
            result = MODULE.database_summary(connection)
            self.assertEqual(result['unique_regular_files_read_attempted'], 1)
            self.assertEqual(result['read_calls'], 3)
            self.assertEqual(len(top), 1)
        self.analyze_fixture(b''.join(self.event(sequence=i) for i in range(1, 4)), check)

    def test_failed_read_does_not_generate_negative_bytes(self):
        def check(connection, receipt, top, root):
            result = MODULE.database_summary(connection)
            self.assertEqual(result['read_returned_bytes'], 0)
            self.assertEqual(result['read_error_calls'], 1)
            self.assertEqual(result['unique_regular_files_read_positive_bytes'], 0)
        self.analyze_fixture(self.event(result=-13, syscall_result=-13), check)

    def test_unknown_requested_count_is_not_zero(self):
        def check(connection, receipt, top, root):
            result = MODULE.database_summary(connection)
            self.assertEqual(result['read_requested_unknown_calls'], 1)
            self.assertEqual(result['read_requested_size_histogram']['observations'], 0)
            self.assertIsNone(connection.execute('SELECT requested_bytes FROM events').fetchone()[0])
        self.analyze_fixture(self.event(flags=MODULE.OBJECT_VALID | MODULE.SYSCALL_VALID), check)

    def test_boundary_crossing_retained_but_not_counted_as_whole_window(self):
        def check(connection, receipt, top, root):
            result = MODULE.database_summary(connection)
            self.assertEqual(result['read_calls'], 0)
            self.assertEqual(receipt['issues']['OPERATION_CROSSES_TIMING_WINDOW'], 1)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)
        self.analyze_fixture(self.event(start_ns=99, sys_start_ns=90), check)

    def test_malformed_tail_keeps_raw_bytes(self):
        def check(connection, receipt, top, root):
            self.assertEqual(receipt['issues']['TRUNCATED_EVENT'], 1)
            self.assertEqual(receipt['bytes'], 195)
            self.assertEqual(connection.execute('SELECT raw FROM events WHERE valid=0').fetchone()[0], b'abc')
        self.analyze_fixture(self.event() + b'abc', check)

    def test_cpu_sequence_gap_is_not_hidden_by_valid_event(self):
        def check(connection, receipt, top, root):
            self.assertEqual(receipt['issues']['CPU_SEQUENCE_RANGE_GAP'], 1)
            self.assertEqual(MODULE.database_summary(connection)['read_calls'], 1)
        self.analyze_fixture(self.event(sequence=2), check)

    def test_unregistered_cgroup_record_is_invalid_not_reassigned(self):
        def check(connection, receipt, top, root):
            self.assertEqual(receipt['issues']['UNREGISTERED_DOMAIN'], 1)
            self.assertEqual(MODULE.database_summary(connection)['read_calls'], 0)
        self.analyze_fixture(self.event(domain_id=77), check)

    def test_fault_attempt_stays_separate_from_read_bytes(self):
        def check(connection, receipt, top, root):
            result = MODULE.database_summary(connection)
            self.assertEqual(result['read_calls'], 0)
            self.assertEqual(result['filemap_fault_attempts'], 1)
            self.assertEqual(result['filemap_fault_outcomes'], {'RETRY_ATTEMPT': 1})
            self.assertEqual(result['filemap_fault_return_flags'], {'MAJOR': 1, 'RETRY': 1})
            self.assertEqual(result['unique_regular_files_with_filemap_fault_attempt'], 1)
        self.analyze_fixture(self.event(kind=5, result=1028, flags=MODULE.OBJECT_VALID | MODULE.FAULT_FLAGS_VALID | MODULE.FAULT_RETURN_VALID,
            vm_fault_result=0x404, syscall_nr=0xffffffff), check)

    def test_unknown_object_preserved_without_inventing_inventory_access(self):
        def check(connection, receipt, top, root):
            result = MODULE.database_summary(connection)
            self.assertEqual(result['read_calls'], 1)
            self.assertEqual(result['unique_regular_files'], 0)
            self.assertEqual(result['unresolved_object_events'], 1)
            self.assertEqual(top, [])
        self.analyze_fixture(self.event(flags=MODULE.REQUESTED_VALID | MODULE.SYSCALL_VALID), check)

    def test_strict_abi_and_time_and_requested_bounds(self):
        for fields in ({'magic': 0}, {'version': 2}, {'size': 191}, {'kind': 20},
                {'flags': 0x80000000}, {'end_ns': 100}, {'sys_end_ns': 115},
                {'requested_bytes': 9}, {'tid': 0}, {'thread_birth_ns': 0}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                MODULE.decode_event(self.event(**fields))

    def bundle(self, root, raw=None, label='run'):
        raw = self.event() if raw is None else raw
        collector = root / 'collector'
        collector.mkdir()
        profile = self.profile()
        profile_raw = json.dumps(profile).encode()
        (root / 'profile-run.json').write_bytes(profile_raw)
        meta = {'schema_version': 1, 'run_id': label, 'boot_id': 'boot',
            'record_bytes': 192, 'mode': 'events', 'start_monotonic_ns': 90,
            'event_magic': MODULE.MAGIC, 'event_abi_version': 1, 'endian': 'little',
            'native_syscall_abi': 'X86_64_EXCLUDING_TS_COMPAT_AND_X32',
            'cpu_seq_contract': 'ONE_BASED_ATTEMPT_BEFORE_RESERVATION_PER_CPU',
            'possible_cpus': 1, 'max_bytes': 1024 ** 3, 'required_programs': sorted(MODULE.PROGRAMS),
            'ring_bytes': 64 * 1024 ** 2,
            'page_size': 4096,
            'backend': 'fentry', 'online_cpus': '0', 'kprobe_events': [],
            'hook_abi': {'status': 'FENTRY_BTF_PROTOTYPE_VERIFIED_BY_KERNEL_LOADER'},
            'bpf_sha256': 'a' * 64, 'binary_sha256': 'b' * 64,
            'bpf_source_sha256': 'c' * 64, 'header_sha256': 'd' * 64,
            'domains': [{**profile['root_cgroup'], 'level': 2}],
            'vm_fault_flags_contract': MODULE.FAULT_FLAGS_CONTRACT.copy()}
        final = {**meta, 'end_monotonic_ns': 220, 'persisted_records': len(raw) // 192,
            'bytes': len(raw), 'events_sha256': hashlib.sha256(raw).hexdigest(),
            'health': {name: 0 for name in MODULE.HEALTH}, 'pending_syscalls': 0,
            'pending_vfs_calls': 0, 'pending_fault_calls': 0, 'pending_mm_fault_calls': 0, 'timed_out': False,
            'programs': [{'name': name, 'id': i + 1, 'recursion_misses': 0} for i, name in enumerate(sorted(MODULE.PROGRAMS))],
            'cpus': [{'cpu': 0, 'attempted': len(raw) // 192, 'emitted': len(raw) // 192, 'ring_drops': 0}],
            'parser_errors': 0, 'sequence_errors': 0, 'cap_discarded': 0, 'write_errors': 0,
            'write_error': None, 'flush_error': None, 'observation_health': 'COMPLETE_FOR_SELECTED_HOOKS'}
        final.update(kprobe_event_health=[], tracefs_cleanup={'status': 'COMPLETE', 'owned_events': 0,
            'remaining_owned_events': 0, 'errors': []}, online_cpu_identity={'initial': '0', 'current': '0', 'status': 'STABLE'})
        capture = {'collector_run_id': label, 'profile_run_id': 'run', 'boot_id': 'boot',
            'file_access_backend': 'fentry',
            'profile_run_sha256': hashlib.sha256(profile_raw).hexdigest(), 'release_ns': 100, 'end_ns': 200,
            'makespan_ns': 100, 'collector_cgroup': profile['root_cgroup'], 'inner_root_cgroup': profile['root_cgroup'],
            'ready': {**meta, 'type': 'READY'}, 'ready_received_monotonic_ns': 95,
            'finalized_monotonic_ns': 230}
        (collector / 'events.bin').write_bytes(raw)
        self.write_bundle(root, meta, final, capture)
        (root / 'inventory.json').write_text(json.dumps(self.inventory()))
        return meta, final, capture

    def write_bundle(self, root, meta, final, capture):
        final_raw = json.dumps(final).encode()
        capture['final_sha256'] = hashlib.sha256(final_raw).hexdigest()
        (root / 'collector' / 'meta.json').write_text(json.dumps(meta))
        (root / 'collector' / 'final.json').write_bytes(final_raw)
        (root / 'capture.json').write_text(json.dumps(capture))

    def run_bundle(self, root):
        return MODULE.analyze(root / 'collector', root / 'profile-run.json', root / 'analysis', [root / 'inventory.json'])

    def test_full_cli_pipeline_binds_raw_not_saved_aggregates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.bundle(root)
            summary = self.run_bundle(root)
            self.assertEqual(summary['status'], 'COMPLETE_FOR_SELECTED_HOOKS')
            self.assertEqual(summary['metrics']['read_returned_bytes'], 10)
            self.assertTrue((root / 'analysis' / 'per-file.csv').is_file())
            self.assertEqual(summary['raw_events']['sha256'], hashlib.sha256(self.event()).hexdigest())

    def test_distinct_coordinator_label_requires_exact_capture_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.bundle(root, label='outer')
            summary = self.run_bundle(root)
            self.assertEqual(summary['run_id'], 'run')
            self.assertEqual(summary['collector_run_id'], 'outer')

    def test_capture_digest_cannot_be_replaced_with_another_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            meta, final, capture = self.bundle(root)
            capture['profile_run_sha256'] = '0' * 64
            self.write_bundle(root, meta, final, capture)
            with self.assertRaises(ValueError):
                self.run_bundle(root)

    def test_raw_sha_mismatch_keeps_metrics_but_not_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            meta, final, capture = self.bundle(root)
            final['events_sha256'] = '0' * 64
            self.write_bundle(root, meta, final, capture)
            summary = self.run_bundle(root)
            self.assertEqual(summary['status'], 'INCOMPLETE')
            self.assertIn('RAW_COUNT_BYTES_OR_SHA256_MISMATCH', summary['issues'])

    def test_complete_label_cannot_hide_pending_cap_recursion_or_missing_health(self):
        for mutation in ('pending', 'cap', 'recursion', 'health', 'program', 'declared_incomplete'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                meta, final, capture = self.bundle(root)
                if mutation == 'pending':
                    final['pending_fault_calls'] = 1
                elif mutation == 'cap':
                    final['cap_discarded'] = 1
                elif mutation == 'recursion':
                    final['programs'][0]['recursion_misses'] = 1
                elif mutation == 'health':
                    del final['health']['ring_drops']
                elif mutation == 'program':
                    final['programs'].pop()
                else:
                    final['observation_health'] = 'INCOMPLETE'
                self.write_bundle(root, meta, final, capture)
                self.assertEqual(self.run_bundle(root)['status'], 'INCOMPLETE')

    def test_nested_outer_hook_suppression_is_not_extra_promised_operation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            meta, final, capture = self.bundle(root)
            final['health']['nested_hooks'] = 3
            self.write_bundle(root, meta, final, capture)
            self.assertEqual(self.run_bundle(root)['status'], 'COMPLETE_FOR_SELECTED_HOOKS')

    def test_reordered_unique_sequence_is_not_event_loss(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.bundle(root, self.event(sequence=2) + self.event(sequence=1))
            summary = self.run_bundle(root)
            self.assertEqual(summary['status'], 'COMPLETE_FOR_SELECTED_HOOKS')
            self.assertEqual(summary['raw_events']['cpu_reordered_observations'], {0: 1})

    def test_duplicate_sequence_cannot_be_hidden_by_record_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.bundle(root, self.event() + self.event())
            summary = self.run_bundle(root)
            self.assertEqual(summary['status'], 'INCOMPLETE')
            self.assertIn('DUPLICATE_CPU_SEQUENCE', summary['issues'])

    def test_new_ready_cannot_silently_replace_original_meta(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            meta, final, capture = self.bundle(root)
            capture['ready']['bpf_sha256'] = '0' * 64
            self.write_bundle(root, meta, final, capture)
            with self.assertRaises(ValueError):
                self.run_bundle(root)

    def test_missing_ready_gate_not_called_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.bundle(root)
            (root / 'capture.json').unlink()
            summary = self.run_bundle(root)
            self.assertEqual(summary['status'], 'INCOMPLETE')
            self.assertIn('READY_GATE_NOT_ESTABLISHED', summary['issues'])

    def test_source_scope_is_separate_from_other_regular_objects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.bundle(root)
            inventory = self.inventory()
            inventory['objects'][0]['scope_kind'] = 'SOURCE_CORPUS'
            (root / 'inventory.json').write_text(json.dumps(inventory))
            metrics = self.run_bundle(root)['metrics']
            self.assertEqual(metrics['source_unique_regular_files_read_attempted'], 1)
            self.assertEqual(metrics['system_runtime_unique_regular_files_read_attempted'], 0)

    def test_mm_file_and_nested_filemap_attempts_are_not_added(self):
        flags = MODULE.OBJECT_VALID | MODULE.REGULAR_FILE | MODULE.FAULT_FLAGS_VALID | MODULE.FAULT_RETURN_VALID
        raw = self.event(kind=6, flags=flags, syscall_nr=0xffffffff, vm_fault_result=0) + self.event(
            kind=5, flags=flags, syscall_nr=0xffffffff, sequence=2, vm_fault_result=4)
        def check(connection, receipt, top, root):
            metrics = MODULE.database_summary(connection)
            self.assertEqual(metrics['mm_fault_attempts'], 1)
            self.assertEqual(metrics['mm_file_backed_fault_attempts'], 1)
            self.assertEqual(metrics['filemap_fault_attempts'], 1)
            self.assertEqual(metrics['unique_regular_files'], 1)
            self.assertEqual(metrics['read_returned_bytes'], 0)
            self.assertIn('NESTED_NOT_ADDITIVE', metrics['fault_scope'])
        self.analyze_fixture(raw, check)

    def test_no_file_vma_is_not_invented_file_or_strict_anonymous(self):
        flags = MODULE.NO_FILE_VMA | MODULE.FAULT_FLAGS_VALID | MODULE.FAULT_RETURN_VALID
        def check(connection, receipt, top, root):
            metrics = MODULE.database_summary(connection)
            self.assertEqual(metrics['mm_no_file_vma_fault_attempts'], 1)
            self.assertEqual(metrics['mm_unresolved_fault_attempts'], 0)
            self.assertEqual(metrics['unresolved_object_events'], 0)
            self.assertEqual(metrics['unique_regular_files'], 0)
            self.assertIn('NOT_VMA_IS_ANONYMOUS_PROOF', metrics['no_file_vma_quality'])
            self.assertEqual(top, [])
        self.analyze_fixture(self.event(kind=6, flags=flags, syscall_nr=0xffffffff, inode=0, vm_fault_result=0), check)

    def test_fault_backing_unknown_not_counted_no_file_vma(self):
        flags = MODULE.FAULT_FLAGS_VALID | MODULE.FAULT_RETURN_VALID
        def check(connection, receipt, top, root):
            metrics = MODULE.database_summary(connection)
            self.assertEqual(metrics['mm_no_file_vma_fault_attempts'], 0)
            self.assertEqual(metrics['mm_unresolved_fault_attempts'], 1)
            self.assertEqual(metrics['unresolved_object_events'], 1)
        self.analyze_fixture(self.event(kind=6, flags=flags, syscall_nr=0xffffffff), check)

    def test_regular_inode_flag_counts_unmapped_file_without_inventing_path(self):
        flags = MODULE.OBJECT_VALID | MODULE.REGULAR_FILE | MODULE.SYSCALL_VALID | MODULE.REQUESTED_VALID
        def check(connection, receipt, top, root):
            metrics = MODULE.database_summary(connection)
            self.assertEqual(metrics['unique_regular_files'], 1)
            self.assertEqual(metrics['path_resolved_objects'], 0)
            self.assertEqual(metrics['source_unique_regular_files_read_attempted'], 0)
        self.analyze_fixture(self.event(inode=99, flags=flags), check)

    def test_pre_vfs_failure_interval_is_not_reported_as_vfs_latency(self):
        def check(connection, receipt, top, root):
            metrics = MODULE.database_summary(connection)
            self.assertEqual(metrics['read_calls'], 1)
            self.assertEqual(metrics['read_vfs_calls'], 0)
            self.assertEqual(metrics['read_duration_ns'], 0)
            self.assertIsNone(metrics['read_mean_duration_ns'])
            self.assertEqual(metrics['read_syscall_duration_ns'], 20)
            self.assertEqual(metrics['read_duration_histogram']['observations'], 0)
        self.analyze_fixture(self.event(flags=MODULE.REQUESTED_VALID | MODULE.SYSCALL_VALID,
            result=-9, syscall_result=-9), check)

    def test_inventory_index_is_shared_readonly_not_cloned_per_trace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.bundle(root)
            inventory = self.inventory()
            inventory['objects'][0]['scope_kind'] = 'SOURCE_CORPUS'
            (root / 'inventory.json').write_text(json.dumps(inventory))
            index = root / 'inventory.sqlite'
            receipt = MODULE.build_inventory_index([root / 'inventory.json'], index, 'boot')
            before = index.read_bytes()
            summary = MODULE.analyze(root / 'collector', root / 'profile-run.json', root / 'analysis',
                inventory_database=index, expected_inventory_sha256=receipt['artifact']['sha256'])
            self.assertEqual(summary['metrics']['source_unique_regular_files_read_attempted'], 1)
            self.assertEqual(before, index.read_bytes())
            connection = MODULE.sqlite3.connect(str(root / 'analysis' / 'events.sqlite'))
            try:
                self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='inventory'").fetchone())
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM object_paths').fetchone()[0], 1)
            finally:
                connection.close()

    def test_inventory_index_keeps_prepost_contract_and_boot_and_external_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.bundle(root)
            index = root / 'inventory.sqlite'
            MODULE.build_inventory_index([root / 'inventory.json'], index, 'boot')
            with self.assertRaises(ValueError):
                MODULE.inventory_index_manifest(index, 'different-boot')
            with self.assertRaises(ValueError):
                MODULE.analyze(root / 'collector', root / 'profile-run.json', root / 'analysis',
                    inventory_database=index, expected_inventory_sha256='0' * 64)

    def test_inventory_index_refuses_unverified_prepost_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = self.inventory()
            inventory['pre_post_identical'] = False
            (root / 'inventory.json').write_text(json.dumps(inventory))
            with self.assertRaises(ValueError):
                MODULE.build_inventory_index([root / 'inventory.json'], root / 'bad.sqlite', 'boot')

    def test_streaming_batch_boundary_preserves_every_record(self):
        raw = b''.join(self.event(sequence=i) for i in range(1, 4100))
        def check(connection, receipt, top, root):
            self.assertEqual(receipt['records'], 4099)
            self.assertEqual(receipt['issues'], {})
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM events').fetchone()[0], 4099)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM cpu_sequences').fetchone()[0], 4099)
        self.analyze_fixture(raw, check)

    def kprobe_bundle(self, root):
        meta, final, capture = self.bundle(root)
        meta.update(backend='kprobe-tracefs', kretprobe_maxactive=4096)
        anchors = [('vfs_read', 4, 8, 'file'), ('vfs_readv', 5, 8, 'file'),
            ('iterate_dir', 2, 4, 'file'), ('security_file_open', 1, 4, 'file'),
            ('filemap_fault', 1, 4, 'vm_fault'), ('handle_mm_fault', 4, 4, 'vm_area_struct')]
        meta['hook_abi'] = {'status': 'VALIDATED', 'architecture': 'x86_64',
            'registers': ['di', 'si', 'dx', 'cx', 'ax'], 'kretprobe_maxactive': 4096,
            'anchors': [{'name': name, 'btf_function_id': 100 + i, 'parameter_count': argc,
                'return_bytes': size, 'first_argument_struct': first} for i, (name, argc, size, first) in enumerate(anchors)]}
        initial, terminal = [], []
        for index, (program, (anchor, is_return)) in enumerate(sorted(MODULE.TRACE_ANCHORS.items())):
            name = 'alloxfa_' + format(index, '032x') + '_' + program
            prefix = 'r4096' if is_return else 'p'
            start = {'program_name': program, 'anchor': anchor, 'is_return': is_return,
                'maxactive': 4096 if is_return else None, 'name': name,
                'group': 'allox_file_access', 'tracefs_root': '/sys/kernel/tracing',
                'definition': prefix + ':allox_file_access/' + name + ' ' + anchor,
                'device': 28, 'directory_inode': 1000 + index, 'event_id': 2000 + index,
                'initial_hits': 0, 'initial_misses': 0, 'hits': 2, 'misses': 0,
                'misses_delta': 0, 'profile_status': 'OBSERVED', 'identity_status': 'MATCH', 'error': None,
                'collection_start_ns': 91, 'collection_end_ns': 92}
            end = {**start, 'hits': 10, 'collection_start_ns': 221, 'collection_end_ns': 222}
            initial.append(start)
            terminal.append(end)
        meta['kprobe_events'] = initial
        final.update(copy.deepcopy(meta))
        final['kprobe_event_health'] = terminal
        final['tracefs_cleanup']['owned_events'] = 11
        capture['ready'] = {**meta, 'type': 'READY'}
        capture['file_access_backend'] = 'kprobe-tracefs'
        self.write_bundle(root, meta, final, capture)
        return meta, final, capture

    def test_kprobe_backend_full_owned_receipts_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.kprobe_bundle(root)
            summary = self.run_bundle(root)
            self.assertEqual(summary['status'], 'COMPLETE_FOR_SELECTED_HOOKS')
            self.assertEqual(summary['file_access_backend'], 'kprobe-tracefs')

    def test_kprobe_misses_identity_abi_cleanup_and_unknown_fail_closed(self):
        for mutation in ('miss', 'missing', 'identity', 'maxactive', 'definition',
                'profile', 'cleanup', 'cpu', 'abi', 'rollback'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                meta, final, capture = self.kprobe_bundle(root)
                if mutation == 'miss':
                    final['kprobe_event_health'][0].update(misses=1, misses_delta=1)
                elif mutation == 'missing':
                    final['kprobe_event_health'].pop()
                elif mutation == 'identity':
                    final['kprobe_event_health'][0]['event_id'] += 1
                elif mutation == 'maxactive':
                    target = next(row for row in final['kprobe_event_health'] if row['is_return'])
                    target['maxactive'] = 64
                elif mutation == 'definition':
                    final['kprobe_event_health'][0]['definition'] += ' $arg1'
                elif mutation == 'profile':
                    final['kprobe_event_health'][0]['profile_status'] = 'UNKNOWN'
                elif mutation == 'cleanup':
                    final['tracefs_cleanup']['remaining_owned_events'] = 1
                elif mutation == 'cpu':
                    final['online_cpu_identity']['current'] = '0-1'
                elif mutation == 'abi':
                    meta['hook_abi']['anchors'][0]['parameter_count'] = 1
                    final['hook_abi'] = copy.deepcopy(meta['hook_abi'])
                    capture['ready'] = {**meta, 'type': 'READY'}
                else:
                    final['kprobe_event_health'][0]['hits'] = 1
                self.write_bundle(root, meta, final, capture)
                self.assertEqual(self.run_bundle(root)['status'], 'INCOMPLETE')

    def test_kprobe_profile_is_global_not_assumed_agent_event_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            meta, final, capture = self.kprobe_bundle(root)
            for row in final['kprobe_event_health']:
                row['hits'] = 1000000
            self.write_bundle(root, meta, final, capture)
            self.assertEqual(self.run_bundle(root)['status'], 'COMPLETE_FOR_SELECTED_HOOKS')

    def test_reserved_flags_and_no_file_object_contradictions_rejected(self):
        for fields in ({'flags': 16}, {'flags': MODULE.NO_FILE_VMA | MODULE.OBJECT_VALID},
                {'flags': MODULE.REGULAR_FILE | MODULE.DIRECTORY | MODULE.OBJECT_VALID},
                {'kind': 6, 'flags': MODULE.FAULT_RETURN_VALID, 'syscall_nr': 0}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                MODULE.decode_event(self.event(**fields))

    def test_read_examples_are_bounded_and_show_units_and_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = b''.join(self.event(sequence=i) for i in range(1, 151))
            self.bundle(root, raw)
            inventory = self.inventory()
            inventory['objects'][0]['scope_kind'] = 'SOURCE_CORPUS'
            (root / 'inventory.json').write_text(json.dumps(inventory))
            summary = self.run_bundle(root)
            self.assertEqual(summary['metrics']['read_calls'], 150)
            self.assertEqual(summary['artifacts']['source_read_examples']['records'], 100)
            with (root / 'analysis' / 'source-read-samples.csv').open() as stream:
                rows = list(MODULE.csv.DictReader(stream))
            self.assertEqual(len(rows), 100)
            self.assertEqual(rows[0]['requested_bytes'], '20')
            self.assertEqual(rows[0]['returned_bytes'], '10')
            self.assertEqual(float(rows[0]['selected_interval_microseconds']), .01)
            self.assertEqual(json.loads(rows[0]['inventory_paths_json']), ['a'])

    def test_multiple_inventory_paths_do_not_multiply_read_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.bundle(root)
            inventory = self.inventory()
            inventory['objects'][0]['scope_kind'] = 'SOURCE_CORPUS'
            inventory['objects'].append({**inventory['objects'][0], 'path': 'hardlink-alias'})
            (root / 'inventory.json').write_text(json.dumps(inventory))
            metrics = self.run_bundle(root)['metrics']
            self.assertEqual(metrics['source_unique_regular_files_read_attempted'], 1)
            self.assertEqual(metrics['source_read_returned_bytes'], 10)

    def test_inode_generations_and_mounts_are_not_merged_by_path(self):
        raw = self.event() + self.event(sequence=2, generation=2) + self.event(sequence=3, mount_id=5)
        def check(connection, receipt, top, root):
            self.assertEqual(MODULE.database_summary(connection)['unique_regular_files_read_attempted'], 3)
            self.assertEqual(len(top), 3)
            self.assertEqual({tuple(row['inventory_paths']) for row in top}, {('a',)})
        self.analyze_fixture(raw, check)

    def test_explicit_256_mib_ring_is_accepted_not_assumed_64_mib(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            meta, final, capture = self.bundle(root)
            meta['ring_bytes'] = 256 * 1024 ** 2
            final.update(meta)
            capture['ready'] = {**meta, 'type': 'READY'}
            self.write_bundle(root, meta, final, capture)
            self.assertEqual(self.run_bundle(root)['status'], 'COMPLETE_FOR_SELECTED_HOOKS')

    def test_ring_budget_must_be_explicit_bounded_power_of_two(self):
        for value in (None, 0, True, 1024 ** 2, 24 * 1024 ** 2, 1024 ** 3):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                meta, final, capture = self.bundle(root)
                meta['ring_bytes'] = value
                final.update(meta)
                capture['ready'] = {**meta, 'type': 'READY'}
                self.write_bundle(root, meta, final, capture)
                with self.assertRaises(ValueError):
                    self.run_bundle(root)

    def test_deferred_hash_errors_do_not_become_complete(self):
        for error in ('read failed', None):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                meta, final, capture = self.bundle(root)
                meta['event_hashing'] = 'AFTER_DRAIN_FSYNC'
                final.update(meta)
                capture['ready'] = {**meta, 'type': 'READY'}
                if error is not None:
                    final['hash_error'] = error
                self.write_bundle(root, meta, final, capture)
                summary = self.run_bundle(root)
                self.assertEqual(summary['status'], 'INCOMPLETE')
                self.assertIn('COLLECTOR_ERROR_OR_MISSING_hash_error', summary['issues'])


if __name__ == '__main__':
    unittest.main()
