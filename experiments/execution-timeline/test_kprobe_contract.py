"""Synthetic receipt consistency tests; no kernel observations are generated."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from common import canonical, digest
from kprobe_contract import BACKEND, HOOKS, validate_receipt
from replay import health_issues, verify_run


def fixture():
    meta = {'read_hook_backend': BACKEND, 'boot_id': 'synthetic-boot', 'root_cgroup_id': 12,
            'enabled_monotonic_ns': 30, 'kretprobe_maxactive': 4096}
    health = {'read_hook_backend': BACKEND, 'status': 'COMPLETE_FOR_SELECTED_HOOKS',
              'start_ns': 10, 'end_ns': 100, 'kprobe_profile_errors': 0,
              'kprobe_cleanup_errors': 0, 'kprobe_misses': 0, 'programs': []}
    receipt = {'schema_version': 1, 'backend': BACKEND, 'boot_id': 'synthetic-boot',
               'root_cgroup_id': 12, 'capture_start_ns': 10, 'capture_end_ns': 100,
               'kretprobe_maxactive': 4096, 'btf_abi': {'status': 'VALIDATED_NATIVE_X86_64',
                   'registers': ['di', 'si', 'dx', 'cx', 'ax'], 'vfs_read_function_id': 1,
                   'vfs_readv_function_id': 2, 'pt_regs_struct_id': 3},
               'errors': 0, 'cleanup_errors': 0, 'misses_delta': 0, 'hooks': []}
    for i, (program, (anchor, returned)) in enumerate(HOOKS.items()):
        name = 'alloxet_' + 'a'*32 + '_' + program
        receipt['hooks'].append({'program': program, 'name': name,
            'tracefs_root': '/sys/kernel/tracing', 'definition':
                ('r4096' if returned else 'p') + ':allox_execution_timeline/' + name + ' ' + anchor,
            'device': 1, 'directory_inode': i+1, 'event_id': 200+i,
            'maxactive': 4096 if returned else 0, 'initial_valid': True, 'final_valid': True,
            'initial_hits': 4, 'initial_misses': 0, 'hits': 100, 'misses': 0,
            'initial_begin_ns': 12, 'initial_end_ns': 20, 'final_begin_ns': 101,
            'final_end_ns': 102, 'removed': True, 'cleanup_error': False})
        health['programs'].append({'program': program,
            'section': ('kretprobe/' if returned else 'kprobe/') + anchor})
    return receipt, meta, health


class ContractTests(unittest.TestCase):
    def test_valid_receipt(self):
        self.assertEqual(validate_receipt(*fixture())['status'], 'VALIDATED_BOUND_RECEIPT')

    def test_required_identities_windows_and_abi(self):
        for key, value in [('boot_id', 'other'), ('root_cgroup_id', 99), ('capture_start_ns', 11),
                           ('capture_end_ns', 101), ('kretprobe_maxactive', 1), ('hooks', [])]:
            with self.subTest(key=key):
                r, m, h = fixture()
                r[key] = value
                with self.assertRaises(ValueError):
                    validate_receipt(r, m, h)
        r, m, h = fixture()
        r['btf_abi']['registers'] = ['di']
        with self.assertRaises(ValueError):
            validate_receipt(r, m, h)

    def test_changed_hook_or_unknown_is_not_green(self):
        for key, value in [('definition', 'p:other vfs_read'), ('event_id', 0),
                           ('name', 'unowned'), ('initial_hits', None), ('initial_valid', False),
                           ('hits', 1), ('initial_end_ns', 31), ('final_begin_ns', 99),
                           ('removed', False), ('cleanup_error', True)]:
            with self.subTest(key=key):
                r, m, h = fixture()
                r['hooks'][0][key] = value
                with self.assertRaises(ValueError):
                    validate_receipt(r, m, h)

    def test_actual_miss_retained_but_never_green(self):
        r, m, h = fixture()
        r['hooks'][0]['misses'] = r['misses_delta'] = h['kprobe_misses'] = 2
        with self.assertRaises(ValueError):
            validate_receipt(r, m, h)
        h['status'] = 'INCOMPLETE'
        self.assertEqual(validate_receipt(r, m, h)['misses'], 2)
        self.assertTrue(any(i.get('field') == 'kprobe_misses' for i in health_issues(h, [])))

    def test_counter_and_section_cross_checks(self):
        r, m, h = fixture()
        h['programs'][0]['section'] = 'fentry/vfs_read'
        with self.assertRaises(ValueError):
            validate_receipt(r, m, h)
        r, m, h = fixture()
        h['kprobe_profile_errors'] = 3
        with self.assertRaises(ValueError):
            validate_receipt(r, m, h)

    def test_receipt_is_not_mutated(self):
        values = fixture()
        before = copy.deepcopy(values)
        validate_receipt(*values)
        self.assertEqual(values, before)

    def test_live_hooks_cannot_share_directory_or_mix_tracefs_mounts(self):
        for mutation in ('duplicate-directory', 'mixed-root', 'mixed-device'):
            with self.subTest(mutation=mutation):
                receipt, meta, health = fixture()
                if mutation == 'duplicate-directory':
                    receipt['hooks'][1]['directory_inode'] = receipt['hooks'][0]['directory_inode']
                elif mutation == 'mixed-root':
                    receipt['hooks'][1]['tracefs_root'] = '/sys/kernel/debug/tracing'
                else:
                    receipt['hooks'][1]['device'] += 1
                with self.assertRaisesRegex(ValueError, 'directory identity|mixed tracefs'):
                    validate_receipt(receipt, meta, health)


class ReplayBindingTests(unittest.TestCase):
    """Tiny synthetic transport only: mock decode, never attach or observe BPF."""
    def fixture(self, root):
        capture = root / 'capture'
        capture.mkdir()
        decoder = root / 'decoder'
        decoder.mkdir()
        native = decoder / 'collect'
        native.write_bytes(b'synthetic decoder: never executed')
        bpf = decoder / 'execution_timeline.bpf.o'
        bpf.write_bytes(b'synthetic BPF: never loaded')
        receipt, meta, health = fixture()
        meta['kprobe_evidence'] = 'kprobe-hooks.json'
        raw = b'synthetic raw bytes; no native event claims'
        health.update(records=0, raw_bytes=len(raw))
        (capture / 'events.bin').write_bytes(raw)
        (capture / 'events.jsonl').write_bytes(b'')
        for name, value in (('meta.json', meta), ('health.json', health), ('kprobe-hooks.json', receipt)):
            (capture / name).write_bytes(canonical(value))
        (root / 'enrollment.json').write_bytes(canonical([]))
        ready = {'schema_version': 1, 'event': 'READY', 'status': 'READY', 'clock': 'CLOCK_MONOTONIC',
                 'boot_id': meta['boot_id'], 'root_cgroup_id': meta['root_cgroup_id'], 'timestamp_ns': 31}
        (root / 'ready.json').write_bytes(canonical(ready))
        manifest = {'schema_version': 1, 'run_id': 'synthetic-receipt-binding-only', 'boot_id': meta['boot_id'],
            'clock': 'CLOCK_MONOTONIC', 'begin_ns': 10, 'end_ns': 100, 'tools': [],
            'cgroup_id': meta['root_cgroup_id'],
            'collector_ready': copy.deepcopy(ready),
            'collector_binary': str(native), 'collector_identity': digest(native),
            'bpf_object': str(bpf), 'bpf_object_identity': digest(bpf), 'capture_directory': 'capture',
            'artifacts': {str(path.relative_to(root)): digest(path)
                          for path in list(capture.iterdir()) + [root / 'enrollment.json', root / 'ready.json']}}
        self.persist(root, manifest)
        return manifest, native, bpf

    def persist(self, root, manifest):
        (root / 'manifest.json').write_bytes(canonical(manifest))

    def change_bound(self, root, manifest, relative, change):
        path = root / relative
        value = json.loads(path.read_bytes())
        change(value)
        path.write_bytes(canonical(value))
        manifest['artifacts'][relative] = digest(path)
        self.persist(root, manifest)

    def verify(self, root, native, expected_manifest=None):
        def decode(command, **kwargs):
            self.assertEqual(Path(command[0]), native)
            self.assertEqual(command[1], '--decode')
            Path(command[command.index('--output') + 1]).write_bytes(b'')
            return mock.Mock(returncode=0)
        with mock.patch('replay.subprocess.run', side_effect=decode), \
                mock.patch('replay.build_report', return_value={'synthetic_gate_passed': True}) as build:
            value = verify_run(root, native, expected_manifest)
        return value, build

    def test_pinned_sibling_and_bound_receipt_reach_reducer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _manifest, native, _bpf = self.fixture(root)
            value, build = self.verify(root, native, digest(root / 'manifest.json')['sha256'])
            self.assertEqual(value, {'synthetic_gate_passed': True})
            self.assertEqual(build.call_count, 1)

    def test_present_but_unbound_owned_receipt_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, native, _bpf = self.fixture(root)
            del manifest['artifacts']['capture/kprobe-hooks.json']
            self.persist(root, manifest)
            with self.assertRaisesRegex(ValueError, 'missing or not bound'):
                self.verify(root, native)

    def test_receipt_cannot_be_valid_for_a_different_declared_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, native, _bpf = self.fixture(root)
            manifest['cgroup_id'] += 1
            self.persist(root, manifest)
            with self.assertRaisesRegex(ValueError, 'root differs from declared run scope'):
                self.verify(root, native)

    def test_present_ready_must_be_bound_and_match_the_manifest_declaration(self):
        for mutation in ('unbound', 'root', 'boot', 'clock', 'manifest-copy'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, native, _bpf = self.fixture(root)
                if mutation == 'unbound':
                    del manifest['artifacts']['ready.json']
                    self.persist(root, manifest)
                elif mutation == 'manifest-copy':
                    manifest['collector_ready']['timestamp_ns'] += 1
                    self.persist(root, manifest)
                else:
                    field, replacement = {'root': ('root_cgroup_id', 99), 'boot': ('boot_id', 'another'),
                        'clock': ('clock', 'CLOCK_REALTIME')}[mutation]
                    self.change_bound(root, manifest, 'ready.json', lambda value: value.update({field: replacement}))
                with self.assertRaisesRegex(ValueError, 'READY'):
                    self.verify(root, native)

    def test_recorded_receipt_tampering_is_not_hidden_by_valid_raw_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _manifest, native, _bpf = self.fixture(root)
            receipt = root / 'capture/kprobe-hooks.json'
            receipt.write_bytes(receipt.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'artifact binding differs'):
                self.verify(root, native)

    def test_wrong_receipt_filename_and_one_sided_backend_cannot_bypass_contract(self):
        for change in (lambda meta: meta.update(kprobe_evidence='elsewhere.json'),
                       lambda meta: meta.update(read_hook_backend='LEGACY_NOT_OWNED')):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, native, _bpf = self.fixture(root)
                self.change_bound(root, manifest, 'capture/meta.json', change)
                with self.assertRaisesRegex(ValueError, 'missing or not bound|backend differs'):
                    self.verify(root, native)

    def test_changed_sibling_is_rejected_even_when_manifest_path_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, native, bpf = self.fixture(root)
            fallback = root / 'exact-original.o'
            fallback.write_bytes(bpf.read_bytes())
            manifest['bpf_object'] = str(fallback)
            self.persist(root, manifest)
            bpf.write_bytes(b'different sibling must not pass because of its filename')
            with self.assertRaisesRegex(ValueError, 'BPF object identity'):
                self.verify(root, native)

    def test_exact_manifest_fallback_is_allowed_only_without_sibling(self):
        for correct in (True, False):
            with self.subTest(correct=correct), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, native, bpf = self.fixture(root)
                fallback = root / 'fallback.o'
                bpf.rename(fallback)
                manifest['bpf_object'] = str(fallback)
                if not correct:
                    fallback.write_bytes(b'incorrect fallback')
                self.persist(root, manifest)
                if correct:
                    self.assertEqual(self.verify(root, native)[1].call_count, 1)
                else:
                    with self.assertRaisesRegex(ValueError, 'BPF object identity'):
                        self.verify(root, native)

    def test_missing_object_identity_is_not_a_legacy_bypass_for_owned_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, native, _bpf = self.fixture(root)
            del manifest['bpf_object_identity']
            self.persist(root, manifest)
            with self.assertRaisesRegex(ValueError, 'BPF object identity'):
                self.verify(root, native)

    def test_declared_real_miss_reaches_reducer_unchanged_as_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, native, _bpf = self.fixture(root)
            def receipt_miss(value):
                value['hooks'][0]['misses'] = value['misses_delta'] = 2
            self.change_bound(root, manifest, 'capture/kprobe-hooks.json', receipt_miss)
            self.change_bound(root, manifest, 'capture/health.json', lambda value:
                value.update(status='INCOMPLETE', kprobe_misses=2))
            _value, build = self.verify(root, native)
            health = build.call_args.args[2]
            self.assertEqual(health['status'], 'INCOMPLETE')
            self.assertEqual(health['kprobe_misses'], 2)
            self.assertTrue(any(issue.get('field') == 'kprobe_misses' for issue in health_issues(health, [])))

    def test_external_manifest_anchor_rejects_rebound_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, native, _bpf = self.fixture(root)
            expected = digest(root / 'manifest.json')['sha256']
            self.change_bound(root, manifest, 'capture/kprobe-hooks.json', lambda value: value.update(note='new'))
            with self.assertRaisesRegex(ValueError, 'externally supplied manifest'):
                self.verify(root, native, expected)


if __name__ == '__main__':
    unittest.main()
