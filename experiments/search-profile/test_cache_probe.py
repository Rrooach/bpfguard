import copy
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cache_probe


class CacheProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'corpus'
        self.root.mkdir()
        self.page_size = os.sysconf('SC_PAGE_SIZE')
        self.guest = patch.object(cache_probe, '_ensure_guest')
        self.guest.start()

    def tearDown(self):
        self.guest.stop()
        self.temp.cleanup()

    def file(self, name='nested/file.bin', content=b'known pre-hash corpus data'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return {'path': name, 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}

    def test_real_mincore_on_written_owned_file_has_byte_and_page_counts(self):
        row = self.file(content=b'x' * (self.page_size + 17))
        pinned = cache_probe.pin_inventory(self.root, [row])
        report = cache_probe.probe_inventory(self.root, pinned)
        self.assertEqual(report['status'], 'OBSERVED_NON_ATOMIC')
        self.assertEqual(report['data_page_state'], 'ALL_RESIDENT_AT_EACH_FILE_PROBE')
        self.assertEqual(report['total_pages'], 2)
        self.assertEqual(report['resident_pages'], 2)
        self.assertEqual(report['total_bytes'], self.page_size + 17)
        self.assertEqual(report['resident_bytes'], self.page_size + 17)
        self.assertEqual(report['unknown_file_count'], 0)

    def test_real_probe_does_not_fault_sparse_unwritten_data_pages(self):
        path = self.root / 'sparse.bin'
        with path.open('wb') as stream:
            stream.truncate(self.page_size * 3 + 17)
        row = {'path': 'sparse.bin', 'size': path.stat().st_size,
               'sha256': hashlib.sha256(bytes(path.stat().st_size)).hexdigest()}
        pinned = cache_probe.pin_inventory(self.root, [row])
        for _ in range(2):
            report = cache_probe.probe_inventory(self.root, pinned)
            self.assertEqual(report['status'], 'OBSERVED_NON_ATOMIC')
            self.assertEqual(report['resident_pages'], 0)
            self.assertEqual(report['resident_bytes'], 0)
            self.assertEqual(report['total_pages'], 4)
            self.assertEqual(report['data_page_state'], 'ALL_NONRESIDENT_AT_EACH_FILE_PROBE')

    def test_pin_and_probe_never_read_or_rehash_corpus_contents(self):
        row = self.file()
        # Manifest hashes are supplied, not recomputed by the cache sensor.
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('corpus read forbidden')):
            with patch.object(os, 'read', side_effect=AssertionError('data read forbidden')):
                pinned = cache_probe.pin_inventory(self.root, [row])
                report = cache_probe.probe_inventory(self.root, pinned)
        self.assertEqual(report['status'], 'OBSERVED_NON_ATOMIC')
        self.assertTrue(any('Metadata' in note for note in report['limitations']))

    def test_empty_file_is_not_falsely_called_cold_or_hot_working_set(self):
        row = self.file(content=b'')
        report = cache_probe.probe_inventory(self.root, cache_probe.pin_inventory(self.root, [row]))
        self.assertEqual(report['data_page_state'], 'EMPTY_DATA_SCOPE')
        self.assertEqual(report['resident_pages'], 0)
        self.assertIsNone(report['resident_fraction'])

    def test_hash_only_legacy_inventory_cannot_prove_identity_stability(self):
        row = self.file()
        with self.assertRaisesRegex(ValueError, 'pre-cache-preparation identity pin'):
            cache_probe.probe_inventory(self.root, {'files': [row]})

    def test_replacement_same_size_and_path_after_pin_is_unknown(self):
        row = self.file()
        pinned = cache_probe.pin_inventory(self.root, [row])
        path = self.root / row['path']
        path.rename(path.with_name('old-file'))
        path.write_bytes(b'x' * row['size'])
        report = cache_probe.probe_inventory(self.root, pinned)
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertIsNone(report['resident_pages'])
        self.assertEqual(report['unknown_file_count'], 1)
        self.assertIn('identity/type/size/version', report['files'][0]['error']['detail'])

    def test_size_or_version_changes_cannot_be_accepted_after_preparation(self):
        for change_size in (True, False):
            with self.subTest(change_size=change_size):
                row = self.file()
                pinned = cache_probe.pin_inventory(self.root, [row])
                path = self.root / row['path']
                if change_size:
                    path.write_bytes(b'z')
                else:
                    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000))
                report = cache_probe.probe_inventory(self.root, pinned)
                self.assertEqual(report['status'], 'INCOMPLETE')
                self.assertIsNone(report['files'][0]['resident_bytes'])

    def test_root_replacement_is_detected_even_with_identical_file_content(self):
        row = self.file()
        pinned = cache_probe.pin_inventory(self.root, [row])
        self.root.rename(self.root.with_name('old-corpus'))
        self.root.mkdir()
        self.file()
        report = cache_probe.probe_inventory(self.root, pinned)
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertEqual(report['data_page_state'], 'UNKNOWN')
        self.assertEqual(report['unknown_file_count'], 1)

    def test_symlink_at_leaf_ancestor_or_root_is_rejected(self):
        for kind in ('leaf', 'ancestor', 'root'):
            with self.subTest(kind=kind):
                base = Path(self.temp.name) / kind
                base.mkdir()
                original = base / 'real'
                original.mkdir()
                (original / 'file').write_bytes(b'x')
                if kind == 'root':
                    root = base / 'linked'
                    root.symlink_to(original, target_is_directory=True)
                    relative = 'file'
                elif kind == 'ancestor':
                    root = base
                    (base / 'linked').symlink_to(original, target_is_directory=True)
                    relative = 'linked/file'
                else:
                    root = base
                    (base / 'linked').symlink_to(original / 'file')
                    relative = 'linked'
                row = {'path': relative, 'size': 1, 'sha256': '0' * 64}
                pinned = cache_probe.pin_inventory(root, [row])
                self.assertEqual(pinned['status'], 'INCOMPLETE')
                report = cache_probe.probe_inventory(root, pinned)
                self.assertEqual(report['status'], 'INCOMPLETE')
                self.assertEqual(report['unknown_file_count'], 1)

    def test_named_pipe_is_rejected_without_blocking_or_opening_device(self):
        os.mkfifo(self.root / 'fifo')
        row = {'path': 'fifo', 'size': 0, 'sha256': '0' * 64}
        pinned = cache_probe.pin_inventory(self.root, [row])
        self.assertEqual(pinned['status'], 'INCOMPLETE')
        self.assertIn('non-regular', pinned['files'][0]['error']['detail'])

    def test_invalid_duplicate_or_traversal_inventory_is_rejected(self):
        row = self.file()
        for entries in ([], [row, row], [{**row, 'path': '../escape'}], [{**row, 'path': '/absolute'}],
                        [{**row, 'path': 'a//b'}], [{**row, 'path': './a'}], [{**row, 'size': True}],
                        [{**row, 'size': -1}], [{**row, 'sha256': 'not-a-fixed-hash'}]):
            with self.subTest(entries=entries):
                with self.assertRaises(ValueError):
                    cache_probe.pin_inventory(self.root, entries)

    def test_bounded_file_and_byte_inventory(self):
        row = self.file()
        with patch.object(cache_probe, 'MAX_FILES', 1):
            with self.assertRaises(ValueError):
                cache_probe.pin_inventory(self.root, [row, {**row, 'path': 'other'}])
        with patch.object(cache_probe, 'MAX_BYTES', 1):
            with self.assertRaises(ValueError):
                cache_probe.pin_inventory(self.root, [row])

    def test_failed_mincore_keeps_totals_but_resident_values_unknown(self):
        row = self.file()
        pinned = cache_probe.pin_inventory(self.root, [row])
        with patch.object(cache_probe._Mincore, 'counts', side_effect=OSError(errno.ENOMEM, 'test mincore failure')):
            report = cache_probe.probe_inventory(self.root, pinned)
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertIsNone(report['resident_pages'])
        self.assertIsNone(report['resident_bytes'])
        self.assertEqual(report['observed_resident_pages'], 0)
        self.assertEqual(report['unknown_file_count'], 1)
        self.assertEqual(report['total_bytes'], row['size'])
        self.assertEqual(report['files'][0]['error']['errno'], errno.ENOMEM)

    def test_file_changed_during_probe_invalidates_raw_observation(self):
        row = self.file()
        pinned = cache_probe.pin_inventory(self.root, [row])

        def changed(descriptor, size):
            os.utime(self.root / row['path'], ns=(0, 12345))
            return {'total_pages': 1, 'resident_pages': 1, 'total_bytes': size, 'resident_bytes': size}

        with patch.object(cache_probe._Mincore, 'counts', side_effect=changed):
            report = cache_probe.probe_inventory(self.root, pinned)
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertIsNone(report['resident_pages'])
        self.assertIn('raw_observation_invalidated_by_identity_change', report['files'][0])

    def test_unproven_mincore_permissions_are_not_all_ones_warm_success(self):
        row = self.file()
        pinned = cache_probe.pin_inventory(self.root, [row])
        with patch.object(cache_probe, '_fsuid', return_value=os.geteuid() + 1):
            report = cache_probe.probe_inventory(self.root, pinned)
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertIsNone(report['resident_fraction'])
        self.assertEqual(report['files'][0]['error']['errno'], errno.EACCES)

    def test_multiple_independent_roots_are_reported_separately(self):
        row = self.file(content=b'x' * 17)
        second = self.root.with_name('second')
        (second / 'nested').mkdir(parents=True)
        (second / row['path']).write_bytes(b'x' * 17)
        pinned = cache_probe.pin_roots([self.root, second], [row], independent=True)
        report = cache_probe.probe_roots(pinned)
        self.assertEqual(pinned['status'], 'PINNED')
        self.assertEqual(report['status'], 'OBSERVED_NON_ATOMIC')
        self.assertEqual(len(report['roots']), 2)
        self.assertNotIn('resident_bytes', report)
        self.assertEqual(pinned['shared_dev_inode_identities'], [])

    def test_hardlinked_roots_cannot_claim_independent_file_cache(self):
        row = self.file()
        second = self.root.with_name('second')
        (second / 'nested').mkdir(parents=True)
        os.link(self.root / row['path'], second / row['path'])
        pinned = cache_probe.pin_roots([self.root, second], [row], independent=True)
        report = cache_probe.probe_roots(pinned)
        self.assertEqual(pinned['status'], 'INCOMPLETE')
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertEqual(len(pinned['shared_dev_inode_identities']), 1)
        self.assertTrue(all(row['status'] == 'OBSERVED_NON_ATOMIC' for row in report['roots']))

    def test_modified_pin_digest_or_other_root_is_rejected(self):
        row = self.file()
        pinned = cache_probe.pin_inventory(self.root, [row])
        with self.assertRaises(ValueError):
            cache_probe.probe_inventory(self.root.with_name('other'), pinned)
        forged = copy.deepcopy(pinned)
        forged['files'][0]['size'] += 1
        with self.assertRaisesRegex(ValueError, 'digest'):
            cache_probe.probe_inventory(self.root, forged)

    def test_actual_guest_guard_refuses_non_guest_context(self):
        self.guest.stop()
        try:
            with patch.object(Path, 'exists', return_value=False):
                with self.assertRaisesRegex(RuntimeError, 'restricted'):
                    cache_probe._ensure_guest()
        finally:
            self.guest.start()


class MincoreBackendTests(unittest.TestCase):
    class FakeLibc:
        def __init__(self, bits, page_size):
            self.bits, self.page_size, self.mappings, self.unmappings = bits, page_size, [], []
            self.offset = 0

        def mmap(self, addr, length, prot, flags, descriptor, offset):
            self.mappings.append((length, prot, flags, descriptor, offset))
            self.offset = offset // self.page_size
            return 0x100000

        def mincore(self, address, length, vector):
            for index in range(len(vector)):
                vector[index] = self.bits[self.offset + index]
            return 0

        def munmap(self, address, length):
            self.unmappings.append((address, length))
            return 0

    def backend(self, bits):
        backend = cache_probe._Mincore()
        backend.libc = self.FakeLibc(bits, backend.page_size)
        return backend

    def test_chunked_prot_none_counts_tail_bytes_and_only_low_residency_bit(self):
        backend = self.backend([1, 2, 3])
        with patch.object(cache_probe, 'CHUNK_PAGES', 2):
            result = backend.counts(99, backend.page_size * 2 + 17)
        self.assertEqual(result, {'total_pages': 3, 'resident_pages': 2,
            'total_bytes': backend.page_size * 2 + 17, 'resident_bytes': backend.page_size + 17})
        self.assertEqual(len(backend.libc.mappings), 2)
        self.assertTrue(all(prot == 0 and flags == 1 for _, prot, flags, _, _ in backend.libc.mappings))
        self.assertEqual(backend.libc.mappings[1][-1], backend.page_size * 2)
        self.assertEqual(len(backend.libc.unmappings), 2)

    def test_empty_file_does_not_attempt_zero_length_mmap(self):
        backend = self.backend([])
        self.assertEqual(backend.counts(99, 0)['total_pages'], 0)
        self.assertEqual(backend.libc.mappings, [])

    def test_mincore_error_still_unmaps(self):
        backend = self.backend([1])

        def failure(*args):
            ctypes.set_errno(errno.ENOMEM)
            return -1

        backend.libc.mincore = failure
        with self.assertRaises(OSError):
            backend.counts(99, 17)
        self.assertEqual(len(backend.libc.unmappings), 1)

    def test_map_failed_is_not_a_resident_zero_page(self):
        backend = self.backend([1])
        backend.libc.mmap = lambda *args: ctypes.c_void_p(-1).value
        ctypes.set_errno(errno.EACCES)
        with self.assertRaises(OSError):
            backend.counts(99, 17)
        self.assertEqual(backend.libc.unmappings, [])


if __name__ == '__main__':
    unittest.main()
