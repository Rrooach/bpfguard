import copy
import gzip
import hashlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib


SPEC = importlib.util.spec_from_file_location(
    'file_access_artifacts_tests_subject', Path(__file__).with_name('access_artifacts.py'))
ARTIFACTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACTS)

NAMES = ('summary.json', 'events.sqlite', 'per-file.csv',
    'read-samples.csv', 'source-read-samples.csv')
ARCHIVED_NAMES = ('events.sqlite', 'per-file.csv')
INVALID = (ValueError, OSError, zlib.error)


class AccessArtifactTests(unittest.TestCase):
    def source(self, root, name='events.sqlite', data=b'SQLite fixture\x00\xff' * 257):
        path = root / name
        path.write_bytes(data)
        return path, data

    def plain(self, path, data):
        return {'path': str(path.absolute()), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}

    def archived(self, root, data=b'compressed fixture\n' * 257, name='events.sqlite'):
        source, data = self.source(root, name, data)
        record = ARTIFACTS.store_gzip(source, root, name)
        return source, data, record

    def rewrite_storage(self, record, data):
        path = Path(record['storage']['path'])
        path.write_bytes(data)
        record['storage'].update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

    def assert_proof(self, proof, data, status):
        self.assertEqual(proof['status'], status)
        self.assertEqual(proof['bytes'], len(data))
        self.assertEqual(proof['sha256'], hashlib.sha256(data).hexdigest())

    def test_digest_file_hashes_actual_bytes_without_changing_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, data = self.source(Path(temporary))
            result = ARTIFACTS.digest_file(path)
            self.assertEqual(result, self.plain(path, data))
            self.assertEqual(path.read_bytes(), data)

    def test_digest_file_enforces_the_explicit_size_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, data = self.source(Path(temporary))
            self.assertEqual(ARTIFACTS.digest_file(path, max_bytes=len(data))['bytes'], len(data))
            with self.assertRaises(INVALID):
                ARTIFACTS.digest_file(path, max_bytes=len(data) - 1)

    def test_digest_file_rejects_symlink_instead_of_hashing_its_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _ = self.source(root)
            alias = root / 'alias'
            alias.symlink_to(source)
            with self.assertRaises(INVALID):
                ARTIFACTS.digest_file(alias)

    def test_digest_and_store_reject_a_symlink_source_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            actual = base / 'actual'
            actual.mkdir()
            source, _ = self.source(actual)
            alias = base / 'alias'
            alias.symlink_to(actual, target_is_directory=True)
            output = base / 'output'
            output.mkdir()
            with self.assertRaises(INVALID):
                ARTIFACTS.digest_file(alias / source.name)
            with self.assertRaises(INVALID):
                ARTIFACTS.store_gzip(alias / source.name, output, source.name)

    def test_digest_file_rejects_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(INVALID):
                ARTIFACTS.digest_file(Path(temporary))

    def test_plain_record_remains_backward_compatible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in NAMES:
                with self.subTest(name=name):
                    source, data = self.source(root, name)
                    proof = ARTIFACTS.verify_artifact(self.plain(source, data), root, source.name)
                    self.assert_proof(proof, data, 'VERIFIED_PLAIN_BYTES')

    def test_every_supported_logical_name_can_be_archived_and_replayed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ARCHIVED_NAMES:
                with self.subTest(name=name):
                    source, data = self.source(root, name)
                    record = ARTIFACTS.store_gzip(source, root, name)
                    self.assertEqual(record['logical_name'], name)
                    self.assertEqual(record['bytes'], len(data))
                    self.assertEqual(record['sha256'], hashlib.sha256(data).hexdigest())
                    self.assertNotIn('path', record)
                    storage = record['storage']
                    self.assertEqual(storage['schema_version'], 1)
                    self.assertEqual(storage['codec'], 'gzip')
                    self.assertEqual(Path(storage['path']), root / (name + '.gz'))
                    compressed = Path(storage['path']).read_bytes()
                    self.assertEqual(storage['bytes'], len(compressed))
                    self.assertEqual(storage['sha256'], hashlib.sha256(compressed).hexdigest())
                    self.assertEqual(gzip.decompress(compressed), data)
                    self.assertEqual(source.read_bytes(), data)
                    self.assert_proof(record['verification'], data, 'VERIFIED_DECOMPRESSED_BYTES')
                    proof = ARTIFACTS.verify_artifact(record, root, name)
                    self.assert_proof(proof, data, 'VERIFIED_DECOMPRESSED_BYTES')
                    for key in ('path', 'bytes', 'sha256'):
                        self.assertEqual(proof['storage'][key], storage[key])

    def test_small_json_and_sample_artifacts_remain_plain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in set(NAMES) - set(ARCHIVED_NAMES):
                with self.subTest(name=name):
                    source, _ = self.source(root, name)
                    with self.assertRaises(INVALID):
                        ARTIFACTS.store_gzip(source, root, name)

    def test_empty_file_is_a_valid_single_member_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, data, record = self.archived(root, b'')
            self.assert_proof(ARTIFACTS.verify_artifact(record, root, 'events.sqlite'),
                data, 'VERIFIED_DECOMPRESSED_BYTES')

    def test_compressed_storage_corruption_cannot_pass_using_old_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, record = self.archived(root)
            path = Path(record['storage']['path'])
            raw = bytearray(path.read_bytes())
            raw[len(raw) // 2] ^= 1
            path.write_bytes(raw)
            with self.assertRaises(INVALID):
                ARTIFACTS.verify_artifact(record, root, 'events.sqlite')

    def test_valid_gzip_header_change_still_requires_the_compressed_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, data, record = self.archived(root)
            path = Path(record['storage']['path'])
            raw = bytearray(path.read_bytes())
            raw[4] ^= 1  # Harmless mtime change: decompressed bytes and CRC remain identical.
            self.assertEqual(gzip.decompress(raw), data)
            path.write_bytes(raw)
            with self.assertRaises(INVALID):
                ARTIFACTS.verify_artifact(record, root, 'events.sqlite')

    def test_logical_digest_and_length_are_independently_checked(self):
        for key in ('sha256', 'bytes'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, _, record = self.archived(root)
                record[key] = '0' * 64 if key == 'sha256' else record[key] + 1
                # Also changing the claimed verification is not independent evidence.
                record['verification'][key] = record[key]
                with self.assertRaises(INVALID):
                    ARTIFACTS.verify_artifact(record, root, 'events.sqlite')

    def test_plain_record_digest_and_length_are_independently_checked(self):
        for key in ('sha256', 'bytes'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, data = self.source(root)
                record = self.plain(source, data)
                record[key] = '0' * 64 if key == 'sha256' else len(data) + 1
                with self.assertRaises(INVALID):
                    ARTIFACTS.verify_artifact(record, root, source.name)

    def test_crc_truncation_trailing_bytes_and_concatenated_members_are_rejected(self):
        for mutation in ('crc', 'truncated', 'trailing', 'concatenated'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, _, record = self.archived(root)
                raw = Path(record['storage']['path']).read_bytes()
                if mutation == 'crc':
                    changed = bytearray(raw)
                    changed[-8] ^= 1
                    raw = bytes(changed)
                elif mutation == 'truncated':
                    raw = raw[:-1]
                elif mutation == 'trailing':
                    raw += b'untrusted trailing bytes'
                else:
                    raw += gzip.compress(b'second gzip member', mtime=0)
                # The compressed digest is updated, so decompression itself must reject it.
                self.rewrite_storage(record, raw)
                with self.assertRaises(INVALID):
                    ARTIFACTS.verify_artifact(record, root, 'events.sqlite')

    def test_high_ratio_data_respects_actual_decompressed_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, data, record = self.archived(root, b'\x00' * (2 * 1024 * 1024))
            self.assertLess(record['storage']['bytes'], len(data) // 100)
            # Lie about both logical size claims: verifier must count actual output.
            record['bytes'] = 1024
            record['verification']['bytes'] = 1024
            with self.assertRaises(INVALID):
                ARTIFACTS.verify_artifact(record, root, 'events.sqlite', max_logical_bytes=1024)

    def test_streaming_decompress_calls_always_bound_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, record = self.archived(root, b'\x00' * (2 * 1024 * 1024))
            calls = []
            original = zlib.decompressobj

            class BoundedDecompressor:
                def __init__(self, *args, **kwargs):
                    self.delegate = original(*args, **kwargs)

                def __getattr__(self, name):
                    return getattr(self.delegate, name)

                def decompress(self, data, max_length=0):
                    calls.append(max_length)
                    if not 0 < max_length <= 16 * 1024 * 1024:
                        raise AssertionError('gzip output must be bounded per decoding call')
                    return self.delegate.decompress(data, max_length)

            with patch.object(ARTIFACTS.zlib, 'decompressobj', BoundedDecompressor):
                ARTIFACTS.verify_artifact(record, root, 'events.sqlite')
            self.assertTrue(calls)

    def test_compressed_storage_limit_is_not_the_logical_size_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, record = self.archived(root)
            with self.assertRaises(INVALID):
                ARTIFACTS.verify_artifact(record, root, 'events.sqlite',
                    max_storage_bytes=record['storage']['bytes'] - 1)

    def test_unsupported_codec_and_storage_schema_fail_explicitly(self):
        for key, value in (('codec', 'zstd'), ('schema_version', 2), ('schema_version', True)):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, _, record = self.archived(root)
                record['storage'][key] = value
                with self.assertRaises(INVALID):
                    ARTIFACTS.verify_artifact(record, root, 'events.sqlite')

    def test_logical_name_is_required_and_bound_to_exact_call(self):
        for mismatch in ('absent', 'other'):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, _, record = self.archived(root)
                if mismatch == 'absent':
                    del record['logical_name']
                else:
                    record['logical_name'] = 'summary.json'
                with self.assertRaises(INVALID):
                    ARTIFACTS.verify_artifact(record, root, 'events.sqlite')

    def test_unrecognized_or_traversing_logical_names_are_rejected(self):
        for name in ('extra.json', '../events.sqlite', 'dir/events.sqlite', '/events.sqlite', ''):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, _ = self.source(root)
                with self.assertRaises(INVALID):
                    ARTIFACTS.store_gzip(source, root, name)
                with self.assertRaises(INVALID):
                    ARTIFACTS.verify_artifact(self.plain(source, source.read_bytes()), root, name)

    def test_storage_path_must_be_exactly_the_root_logical_name(self):
        for path_kind in ('other_name', 'subdirectory', 'parent', 'outside'):
            with self.subTest(path_kind=path_kind), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / 'root'
                root.mkdir()
                _, _, record = self.archived(root)
                expected = Path(record['storage']['path'])
                if path_kind == 'other_name':
                    changed = root / 'alias.gz'
                elif path_kind == 'subdirectory':
                    (root / 'nested').mkdir()
                    changed = root / 'nested' / expected.name
                elif path_kind == 'parent':
                    changed = root / 'nested' / '..' / expected.name
                else:
                    changed = base / expected.name
                if path_kind != 'parent':
                    changed.write_bytes(expected.read_bytes())
                record['storage']['path'] = str(changed)
                with self.assertRaises(INVALID):
                    ARTIFACTS.verify_artifact(record, root, 'events.sqlite')

    def test_plain_path_cannot_escape_root_or_use_an_alias_name(self):
        for path_kind in ('outside', 'alias', 'parent'):
            with self.subTest(path_kind=path_kind), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / 'root'
                root.mkdir()
                source, data = self.source(root)
                record = self.plain(source, data)
                if path_kind == 'outside':
                    changed = base / source.name
                    changed.write_bytes(data)
                elif path_kind == 'alias':
                    changed = root / 'alias'
                    changed.write_bytes(data)
                else:
                    changed = root / 'nested' / '..' / source.name
                record['path'] = str(changed)
                with self.assertRaises(INVALID):
                    ARTIFACTS.verify_artifact(record, root, source.name)

    def test_storage_symlink_is_not_followed_even_to_an_identical_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, record = self.archived(root)
            path = Path(record['storage']['path'])
            target = root / 'same-bytes.gz'
            path.rename(target)
            path.symlink_to(target)
            with self.assertRaises(INVALID):
                ARTIFACTS.verify_artifact(record, root, 'events.sqlite')

    def test_plain_symlink_is_not_followed_even_inside_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, data = self.source(root)
            record = self.plain(source, data)
            source.rename(root / 'same-bytes')
            source.symlink_to(root / 'same-bytes')
            with self.assertRaises(INVALID):
                ARTIFACTS.verify_artifact(record, root, 'events.sqlite')

    def test_symlink_root_or_ancestor_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            actual = base / 'actual'
            actual.mkdir()
            root = actual / 'root'
            root.mkdir()
            _, _, record = self.archived(root)
            alias = base / 'alias'
            alias.symlink_to(actual, target_is_directory=True)
            alias_root = alias / 'root'
            changed = copy.deepcopy(record)
            changed['storage']['path'] = str(alias_root / 'events.sqlite.gz')
            with self.assertRaises(INVALID):
                ARTIFACTS.verify_artifact(changed, alias_root, 'events.sqlite')

    def test_store_rejects_existing_archive_without_overwriting_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _ = self.source(root)
            destination = root / 'events.sqlite.gz'
            destination.write_bytes(b'keep original archive')
            with self.assertRaises(INVALID):
                ARTIFACTS.store_gzip(source, root, 'events.sqlite')
            self.assertEqual(destination.read_bytes(), b'keep original archive')

    def test_store_rejects_symlink_output_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source, _ = self.source(base)
            actual = base / 'actual'
            actual.mkdir()
            alias = base / 'alias'
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(INVALID):
                ARTIFACTS.store_gzip(source, alias, 'events.sqlite')

    def test_store_size_or_space_failure_cannot_return_a_verified_record(self):
        for limit in ('logical', 'storage', 'space'):
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, data = self.source(root)
                arguments = ({'max_logical_bytes': len(data) - 1} if limit == 'logical'
                    else {'max_storage_bytes': 1} if limit == 'storage'
                    else {'min_free_bytes': 1 << 100})
                with self.assertRaises(INVALID):
                    ARTIFACTS.store_gzip(source, root, 'events.sqlite', **arguments)
                self.assertEqual(source.read_bytes(), data)

    def test_store_checks_actual_free_space_before_writing_archive_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, data = self.source(root)
            with patch.object(ARTIFACTS.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)):
                with self.assertRaises(INVALID):
                    ARTIFACTS.store_gzip(source, root, 'events.sqlite', min_free_bytes=1)
            self.assertEqual(source.read_bytes(), data)

    def test_restore_checks_actual_free_space_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, record = self.archived(root)
            output = root / 'no-space.sqlite'
            with patch.object(ARTIFACTS.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)):
                with self.assertRaises(INVALID):
                    ARTIFACTS.restore_artifact(record, root, 'events.sqlite', output)
            self.assertFalse(output.exists())

    def test_store_requires_independent_replay_before_returning_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, data = self.source(root)
            original = ARTIFACTS.verify_artifact
            replayed = []

            def track(record, directory, logical_name, *args, **kwargs):
                replayed.append((directory, logical_name))
                return original(record, directory, logical_name, *args, **kwargs)

            with patch.object(ARTIFACTS, 'verify_artifact', side_effect=track):
                record = ARTIFACTS.store_gzip(source, root, 'events.sqlite')
            self.assertTrue(replayed)
            self.assert_proof(record['verification'], data, 'VERIFIED_DECOMPRESSED_BYTES')

    def test_store_failed_independent_replay_does_not_return_a_complete_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, data = self.source(root)
            with patch.object(ARTIFACTS, 'verify_artifact', side_effect=ValueError('fixture replay failure')):
                with self.assertRaises(ValueError):
                    ARTIFACTS.store_gzip(source, root, 'events.sqlite')
            self.assertEqual(source.read_bytes(), data)

    def test_restore_gzip_and_plain_preserve_exact_logical_bytes(self):
        for archived in (False, True):
            with self.subTest(archived=archived), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, data = self.source(root)
                record = (ARTIFACTS.store_gzip(source, root, source.name) if archived
                    else self.plain(source, data))
                output = root / 'restored.sqlite'
                proof = ARTIFACTS.restore_artifact(record, root, source.name, output)
                self.assertEqual(output.read_bytes(), data)
                self.assertEqual(proof['path'], str(output.absolute()))
                self.assert_proof(proof, data,
                    'VERIFIED_DECOMPRESSED_BYTES' if archived else 'VERIFIED_PLAIN_BYTES')

    def test_restore_never_overwrites_existing_regular_file_or_symlink(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, _, record = self.archived(root)
                output = root / 'restored.sqlite'
                target = root / 'keep'
                target.write_bytes(b'keep existing data')
                if symlink:
                    output.symlink_to(target)
                else:
                    output.write_bytes(b'keep existing data')
                with self.assertRaises(INVALID):
                    ARTIFACTS.restore_artifact(record, root, 'events.sqlite', output)
                self.assertEqual(target.read_bytes(), b'keep existing data')
                self.assertEqual(output.read_bytes(), b'keep existing data')

    def test_restore_does_not_replace_a_dangling_output_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, record = self.archived(root)
            output = root / 'restored.sqlite'
            target = root / 'missing-target'
            output.symlink_to(target)
            with self.assertRaises(INVALID):
                ARTIFACTS.restore_artifact(record, root, 'events.sqlite', output)
            self.assertTrue(output.is_symlink())
            self.assertFalse(target.exists())

    def test_failed_restore_retains_source_but_never_returns_a_verified_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, record = self.archived(root)
            archive = Path(record['storage']['path'])
            before = archive.read_bytes()
            record['sha256'] = '0' * 64
            with self.assertRaises(INVALID):
                ARTIFACTS.restore_artifact(record, root, 'events.sqlite', root / 'bad.sqlite')
            self.assertEqual(archive.read_bytes(), before)

    def test_restore_rejects_symlink_parent_without_writing_target_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, record = self.archived(root)
            actual = root / 'actual'
            actual.mkdir()
            alias = root / 'alias'
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(INVALID):
                ARTIFACTS.restore_artifact(record, root, 'events.sqlite', alias / 'restored.sqlite')
            self.assertFalse((actual / 'restored.sqlite').exists())

    def test_restore_size_limit_is_enforced_before_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, data, record = self.archived(root)
            with self.assertRaises(INVALID):
                ARTIFACTS.restore_artifact(record, root, 'events.sqlite', root / 'too-large.sqlite',
                    max_logical_bytes=len(data) - 1)


if __name__ == '__main__':
    unittest.main()
