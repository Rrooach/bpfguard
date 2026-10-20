import importlib.util
import copy
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('file_profile_analyze', Path(__file__).with_name('analyze.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Tests(unittest.TestCase):
    def row(self):
        return {'boot_id': 'boot', 'domain_id': 1,
            'object': {'size': 100, 'inode': 42, 'version_quality': 'METADATA_VERSION_HINT'},
            'operation': 'read_or_pread', 'calls': 2, 'success_calls': 2, 'errors': 0,
            'returned_bytes': 200, 'duration_ns': 50, 'max_duration_ns': 30, 'first_start_ns': 20, 'last_end_ns': 80,
            'thread': {'tid': 5, 'start_boottime_ns': 100},
            'process': {'pid': 5, 'start_boottime_ns': 100}}

    def interval(self, task='task'):
        return {'task_id': task, 'boot_id': 'boot', 'domain_id': 1,
                'start_ns': 10, 'end_ns': 90}

    def profile(self, records=None):
        return {'schema_version': 2, 'boot_id': 'boot', 'start_monotonic_ns': 0,
            'end_monotonic_ns': 100, 'pending_syscalls': 0, 'pending_vfs_calls': 0,
            'records': [self.row()] if records is None else records,
            'health': {name: 0 for name in module.HEALTH_V2},
            'programs': [{'name': name, 'id': index, 'recursion_misses': 0}
                         for index, name in enumerate(sorted(module.HOOKS), 1)],
            'registered_domains': [{'path': '/sys/fs/cgroup/one', 'inode': 1, 'device': 28, 'level': 1},
                                   {'path': '/sys/fs/cgroup/two', 'inode': 2, 'device': 28, 'level': 1}],
            'timed_out': False, 'limits': [],
            'observation_health': 'COMPLETE_FOR_SELECTED_HOOKS'}

    def meta(self, profile=None):
        profile = self.profile() if profile is None else profile
        return {'schema_version': profile['schema_version'], 'boot_id': 'boot', 'start_monotonic_ns': 0,
                'domains': copy.deepcopy(profile['registered_domains']), 'entry_limit': 8192, 'label': 'run'}

    def events(self):
        value = {'run_id': 'run', 'boot_id': 'boot', 'task_id': 'task', 'agent_id': 'agent',
                 'tool_call_id': 'grep', 'phase': 'SEARCH', 'attempt': 1, 'epoch': 1,
                 'process': {'pid': 5, 'start_ticks': 1},
                 'cgroup': {'path': '/sys/fs/cgroup/one', 'inode': 1, 'device': 28}}
        return [{**value, 'event': 'START', 'monotonic_ns': 10},
                {**value, 'event': 'COMPLETE', 'monotonic_ns': 90}]

    def test_domain_interval(self):
        self.assertEqual(module.associate(self.row(), [self.interval()])['task_id'], 'task')

    def test_shared_service_not_all_charged_to_one_request(self):
        value = module.associate(self.row(), [self.interval('one'), self.interval('two')])
        self.assertEqual(value['quality'], 'UNRESOLVED')

    def test_pid_reuse_and_boot_mismatch_not_guessed(self):
        interval = self.interval()
        interval['boot_id'] = 'another'
        self.assertEqual(module.associate(self.row(), [interval])['quality'], 'UNRESOLVED')

    def test_counter_span_crossing_request_boundaries_unresolved(self):
        interval = self.interval()
        interval['start_ns'] = 25
        self.assertEqual(module.associate(self.row(), [interval])['quality'], 'UNRESOLVED')

    def test_repetition_is_volume_hint_not_saved_work(self):
        profile = self.profile()
        result = module.analyze(profile)
        self.assertEqual(result['objects_by_cost'][0]['byte_volume_over_object_size'], 2)
        self.assertEqual(result['unresolved_association_calls'], 2)

    def test_mmap_cannot_become_read_bytes(self):
        row = self.row()
        row['operation'] = 'file_mmap'
        with self.assertRaises(ValueError):
            module.analyze(self.profile([row]))

    def test_cross_boot_inventory_not_promoted_to_path(self):
        with self.assertRaises(ValueError):
            module.analyze(self.profile([]), inventory={
                'boot_id': 'other', 'pre_post_identical': True, 'objects': []})

    def test_unchecked_inventory_rejected(self):
        with self.assertRaises(ValueError):
            module.analyze(self.profile([]), inventory={
                'boot_id': 'boot', 'pre_post_identical': False, 'objects': []})

    def test_query_flag_is_not_a_file_version_change(self):
        first, second = self.row(), self.row()
        first['object'].update(ctime_nsec=42, raw_ctime_nsec=42, ctime_queried_flag=False)
        second['object'].update(ctime_nsec=42, raw_ctime_nsec=(1 << 31) | 42, ctime_queried_flag=True)
        second['domain_id'] = 2
        result = module.analyze(self.profile([first, second]))
        self.assertEqual(len(result['shared_file_access']), 1)
        self.assertEqual(result['shared_file_access'][0]['returned_bytes'], 400)
        self.assertEqual(result['shared_file_access'][0]['raw_ctime_storage_variants'], [42, (1 << 31) | 42])

    def test_collector_boot_mismatch_rejected(self):
        profile = self.profile()
        profile['records'][0]['boot_id'] = 'another'
        with self.assertRaises(ValueError):
            module.analyze(profile)

    def test_span_outside_collector_window_rejected(self):
        profile = self.profile()
        profile['records'][0]['last_end_ns'] = 101
        with self.assertRaises(ValueError):
            module.analyze(profile)

    def test_loss_cannot_be_hidden_by_complete_label(self):
        for section in ('health', 'programs', 'pending'):
            profile = self.profile()
            if section == 'health':
                profile['health']['aggregate_full'] = 1
            elif section == 'programs':
                profile['programs'] = [{'recursion_misses': 1}]
            else:
                profile['pending_syscalls'] = 1
            with self.subTest(section=section), self.assertRaises(ValueError):
                module.analyze(profile)

    def test_thread_birth_identity_is_required(self):
        profile = self.profile()
        del profile['records'][0]['thread']['start_boottime_ns']
        with self.assertRaises(ValueError):
            module.analyze(profile)

    def test_intentional_nested_hook_skip_is_not_missing_outer_operation(self):
        profile = self.profile()
        profile['health']['nested_hooks_skipped'] = 2
        result = module.analyze(profile)
        self.assertEqual(result['observation_health'], 'COMPLETE_FOR_SELECTED_HOOKS')
        self.assertEqual(result['health']['nested_hooks_skipped'], 2)

    def test_required_health_hook_tables_and_status_are_strict(self):
        for mutation in ('missing_health', 'empty_health', 'unknown_health', 'missing_hooks',
                         'empty_hooks', 'duplicate_hook', 'unknown_hook', 'missing_program_id',
                         'duplicate_program_id', 'missing_recursion', 'unknown_status', 'missing_timeout'):
            profile = self.profile([])
            if mutation == 'missing_health':
                del profile['health']['unpaired_exit']
            elif mutation == 'empty_health':
                profile['health'] = {}
            elif mutation == 'unknown_health':
                profile['health']['invented'] = 0
            elif mutation == 'missing_hooks':
                profile['programs'].pop()
            elif mutation == 'empty_hooks':
                profile['programs'] = []
            elif mutation == 'duplicate_hook':
                profile['programs'][1]['name'] = profile['programs'][0]['name']
            elif mutation == 'unknown_hook':
                profile['programs'][1]['name'] = 'invented'
            elif mutation == 'missing_program_id':
                del profile['programs'][0]['id']
            elif mutation == 'duplicate_program_id':
                profile['programs'][1]['id'] = profile['programs'][0]['id']
            elif mutation == 'missing_recursion':
                del profile['programs'][0]['recursion_misses']
            elif mutation == 'unknown_status':
                profile['observation_health'] = 'SAFE'
            else:
                del profile['timed_out']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                module.analyze(profile)

    def test_version_two_domain_registration_and_numeric_bounds(self):
        for mutation in ('missing', 'unregistered', 'duplicate', 'overlapping', 'bad_level',
                         'negative_counter', 'bool_counter', 'unbounded_counter', 'bad_duration'):
            profile = self.profile()
            if mutation == 'missing':
                del profile['registered_domains']
            elif mutation == 'unregistered':
                profile['records'][0]['domain_id'] = 3
            elif mutation == 'duplicate':
                profile['registered_domains'][1]['inode'] = 1
            elif mutation == 'overlapping':
                profile['registered_domains'][1].update(path='/sys/fs/cgroup/one/child', level=2)
            elif mutation == 'bad_level':
                profile['registered_domains'][0]['level'] = 2
            elif mutation == 'negative_counter':
                profile['records'][0]['returned_bytes'] = -1
            elif mutation == 'bool_counter':
                profile['health']['unsupported_syscall_abi'] = False
            elif mutation == 'unbounded_counter':
                profile['records'][0]['returned_bytes'] = 1 << 64
            else:
                profile['records'][0]['max_duration_ns'] = 51
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                module.analyze(profile)

    def test_meta_binds_domain_boot_start_schema_label_and_task_run(self):
        profile, events = self.profile(), self.events()
        result = module.analyze(profile, events, meta=self.meta())
        self.assertEqual(result['validation']['metadata_binding'], 'BOUND_DECLARATIONS_NOT_AUTHENTICATION')
        self.assertEqual(result['objects_by_cost'][0]['association']['task_id'], 'task')
        for mutation in ('boot', 'start', 'schema', 'domain', 'label', 'unknown_budget'):
            meta = self.meta()
            if mutation == 'boot':
                meta['boot_id'] = 'another'
            elif mutation == 'start':
                meta['start_monotonic_ns'] = 1
            elif mutation == 'schema':
                meta['schema_version'] = 1
            elif mutation == 'domain':
                meta['domains'][0]['inode'] = 3
            elif mutation == 'label':
                meta['label'] = 'another'
            else:
                del meta['entry_limit']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                module.analyze(profile, events, meta=meta)
        for field, value in (('run_id', 'another'), ('boot_id', 'another'), ('monotonic_ns', 101)):
            changed = copy.deepcopy(events)
            changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.analyze(profile, changed, meta=self.meta())

    def test_legacy_v1_is_not_promoted_to_abi_guard_or_implicit_domain_validation(self):
        profile = self.profile()
        meta = self.meta(profile)
        profile['schema_version'] = meta['schema_version'] = 1
        del profile['registered_domains']
        del profile['health']['unsupported_syscall_abi']
        result = module.analyze(profile)
        self.assertEqual(result['validation']['syscall_abi_guard'], 'NOT_ESTABLISHED_LEGACY_V1')
        self.assertEqual(result['validation']['registered_domain_validation'], 'UNKNOWN_LEGACY_WITHOUT_META')
        self.assertEqual(module.analyze(profile, meta=meta)['validation']['registered_domain_validation'], 'CHECKED_DECLARATIONS')
        profile['records'][0]['domain_id'] = 3
        with self.assertRaises(ValueError):
            module.analyze(profile, meta=meta)

    def test_unsupported_abi_is_exposed_and_cannot_be_marked_complete(self):
        profile = self.profile()
        profile['health']['unsupported_syscall_abi'] = 1
        with self.assertRaises(ValueError):
            module.analyze(profile)
        profile['observation_health'] = 'INCOMPLETE'
        self.assertEqual(module.analyze(profile)['health']['unsupported_syscall_abi'], 1)

    def test_directory_positive_status_is_not_read_bytes(self):
        profile = self.profile()
        profile['records'][0]['operation'] = 'directory_iteration'
        with self.assertRaises(ValueError):
            module.analyze(profile)
        profile['records'][0]['returned_bytes'] = 0
        self.assertEqual(module.analyze(profile)['objects_by_cost'][0]['returned_bytes'], 0)
