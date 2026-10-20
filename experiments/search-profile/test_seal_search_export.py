"""Tiny dedicated exports only; no Guest or actual experiment directory reads."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('search_export_seal_tests', Path(__file__).with_name('seal_search_export.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class SealExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'final-export'
        self.root.mkdir()
        (self.root / 'nested').mkdir()
        self.contents = {'a.json': b'{"saved":true}\n', 'nested/z.bin': b'\0\xff\x10', 'empty': b''}
        for relative, data in self.contents.items():
            (self.root / relative).write_bytes(data)
        self.output = self.base / 'inventory.json'

    def seal(self):
        return M.seal_export(self.root, self.output)

    def rewrite(self, value, refresh=True):
        if refresh:
            value['inventory_sha256'] = M._digest_manifest(value)
        self.output.write_text(json.dumps(value))

    def test_all_files_sorted_sha_bytes_canonical_digest_and_successful_rehash(self):
        result = self.seal()
        self.assertEqual(result['files'], [{'path': name, 'bytes': len(self.contents[name]),
            'sha256': hashlib.sha256(self.contents[name]).hexdigest()} for name in sorted(self.contents)])
        self.assertEqual(result['file_count'], 3)
        self.assertEqual(result['total_bytes'], sum(map(len, self.contents.values())))
        self.assertEqual(result['inventory_sha256'], M._digest_manifest(result))
        self.assertEqual(result['scope'], M.SCOPE)
        self.assertEqual(result['source_sha256'], hashlib.sha256(Path(M.__file__).read_bytes()).hexdigest())
        self.assertEqual(result['stability_checked_fields'], list(M.STABLE_FIELDS))
        self.assertIn('No signature', result['not_claimed'])
        self.assertEqual(M.verify_export(self.root, self.output)['status'], 'VERIFIED_ARTIFACT_BYTES')
        second = M.seal_export(self.root, self.base / 'second.json')
        self.assertEqual(second['inventory_sha256'], result['inventory_sha256'])

    def test_byte_identical_copy_can_be_verified_without_original_inode_or_path(self):
        self.seal()
        copied = self.base / 'portable-copy'
        shutil.copytree(self.root, copied)
        result = M.verify_export(copied, self.output)
        self.assertEqual(result['root'], str(copied))
        self.assertEqual(result['recorded_root'], str(self.root))

    def test_no_implicit_raw_filename_exclusions(self):
        (self.root / 'data.raw').write_bytes(b'raw fixture')
        (self.root / 'source.tar').write_bytes(b'small tar-named fixture')
        result = self.seal()
        self.assertEqual(result['file_count'], 5)
        self.assertTrue({'data.raw', 'source.tar'} <= {row['path'] for row in result['files']})

    def test_added_missing_and_same_size_changed_files_are_rejected(self):
        self.seal()
        extra = self.root / 'new.txt'; extra.write_bytes(b'new')
        with self.assertRaisesRegex(ValueError, 'files added or missing'):
            M.verify_export(self.root, self.output)
        extra.unlink()
        missing = self.root / 'empty'; missing.unlink()
        with self.assertRaisesRegex(ValueError, 'files added or missing'):
            M.verify_export(self.root, self.output)
        missing.write_bytes(b'')
        target = self.root / 'a.json'; target.write_bytes(b'x' * len(self.contents['a.json']))
        with self.assertRaisesRegex(ValueError, 'bytes or SHA256 differ'):
            M.verify_export(self.root, self.output)

    def test_inventory_json_reformatting_is_not_byte_artifact_tampering(self):
        result = self.seal()
        self.output.write_text(json.dumps(result, indent=4, sort_keys=False))
        self.assertEqual(M.verify_export(self.root, self.output)['status'], 'VERIFIED_ARTIFACT_BYTES')

    def test_inventory_self_digest_tampering_or_duplicate_json_keys_rejected(self):
        result = self.seal()
        result['total_bytes'] += 1
        self.rewrite(result, refresh=False)
        with self.assertRaisesRegex(ValueError, 'canonical digest is invalid'):
            M.verify_export(self.root, self.output)
        self.output.write_text('{"schema_version":1,' + json.dumps(result)[1:])
        with self.assertRaisesRegex(ValueError, 'duplicate JSON object key'):
            M.verify_export(self.root, self.output)

    def test_valid_self_digest_does_not_allow_unsafe_paths_duplicates_or_bad_declarations(self):
        original = self.seal()
        mutations = []
        for name in ('../outside', '/absolute', './a.json', 'nested//z.bin', 'back\\slash', 'new\nline'):
            value = copy.deepcopy(original); value['files'][0]['path'] = name; mutations.append(value)
        value = copy.deepcopy(original); value['files'].append(copy.deepcopy(value['files'][0])); mutations.append(value)
        value = copy.deepcopy(original); value['files'].reverse(); mutations.append(value)
        value = copy.deepcopy(original); value['files'][0]['bytes'] = True; mutations.append(value)
        value = copy.deepcopy(original); value['file_count'] = True; mutations.append(value)
        value = copy.deepcopy(original); value['source_sha256'] = 'not-a-digest'; mutations.append(value)
        value = copy.deepcopy(original); value['unexpected_policy'] = 'ignore missing'; mutations.append(value)
        for index, value in enumerate(mutations):
            self.rewrite(value)
            with self.subTest(index=index), self.assertRaises(ValueError):
                M.verify_export(self.root, self.output)

    def test_root_filesystem_home_and_workspace_are_rejected_before_reading(self):
        with patch.object(M, '_collect', side_effect=AssertionError('broad root must not be traversed')):
            for root in (Path('/'), Path.home(), Path(M.__file__).parent, Path(M.__file__).parents[3]):
                with self.subTest(root=root), self.assertRaisesRegex(ValueError, 'dedicated export directory'):
                    M.seal_export(root, self.output)
        self.assertFalse(self.output.exists())

    def test_inside_or_existing_output_is_rejected_without_overwriting(self):
        with self.assertRaisesRegex(ValueError, 'outside the input'):
            M.seal_export(self.root, self.root / 'inventory.json')
        self.output.write_bytes(b'keep existing inventory')
        with self.assertRaises(FileExistsError):
            self.seal()
        self.assertEqual(self.output.read_bytes(), b'keep existing inventory')

    def test_file_directory_root_and_inventory_symlinks_are_rejected(self):
        link = self.root / 'link'; link.symlink_to(self.root / 'a.json')
        with self.assertRaisesRegex(ValueError, 'symlink or special'):
            self.seal()
        link.unlink(); link.symlink_to(self.root / 'nested', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink or special'):
            self.seal()
        link.unlink()
        root_link = self.base / 'root-link'; root_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink path component'):
            M.seal_export(root_link, self.output)
        self.seal()
        inventory_link = self.base / 'inventory-link'; inventory_link.symlink_to(self.output)
        with self.assertRaisesRegex(ValueError, 'symlink path component'):
            M.verify_export(self.root, inventory_link)

    def test_special_fifo_is_rejected_without_opening_or_waiting(self):
        os.mkfifo(self.root / 'pipe')
        with self.assertRaisesRegex(ValueError, 'symlink or special'):
            self.seal()
        self.assertFalse(self.output.exists())

    def test_bounded_file_count_and_invalid_limits_do_not_create_output(self):
        with self.assertRaisesRegex(ValueError, 'file count exceeds bound'):
            M.seal_export(self.root, self.output, max_files=2)
        for limit in (0, -1, True, '10', M.HARD_MAX_FILES + 1):
            with self.subTest(limit=limit), self.assertRaisesRegex(ValueError, 'max_files must be an integer'):
                M.seal_export(self.root, self.output, max_files=limit)
        self.assertFalse(self.output.exists())
        self.seal()
        with self.assertRaisesRegex(ValueError, 'inventory file count exceeds verifier bound'):
            M.verify_export(self.root, self.output, max_files=2)

    def test_fstat_change_or_replacement_while_hashing_is_rejected(self):
        stream_digest = M._stream_digest
        def mutate(fd):
            result = stream_digest(fd)
            (self.root / 'a.json').write_bytes(b'changed during hashing')
            return result
        with patch.object(M, '_stream_digest', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'file changed while hashing'):
                self.seal()
        self.assertFalse(self.output.exists())

    def test_tree_addition_during_hashing_is_rejected_by_second_scan(self):
        stream_digest = M._stream_digest
        def mutate(fd):
            result = stream_digest(fd)
            (self.root / 'extra').write_bytes(b'created mid-seal')
            return result
        with patch.object(M, '_stream_digest', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'tree changed during'):
                self.seal()
        self.assertFalse(self.output.exists())

    def test_permissions_and_empty_directories_are_explicitly_outside_byte_scope(self):
        result = self.seal()
        (self.root / 'a.json').chmod(0o600)
        (self.root / 'new-empty-directory').mkdir()
        self.assertEqual(M.verify_export(self.root, self.output)['status'], 'VERIFIED_ARTIFACT_BYTES')
        self.assertIn('file permissions or empty-directory', result['not_claimed'])

    def test_cli_seal_verify_and_refuse_existing_output(self):
        command = [sys.executable, '-B', str(Path(M.__file__)), '--root', str(self.root)]
        result = subprocess.run(command + ['--output', str(self.output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'SEALED_ARTIFACT_BYTES')
        result = subprocess.run(command + ['--verify', str(self.output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'VERIFIED_ARTIFACT_BYTES')
        result = subprocess.run(command + ['--output', str(self.output)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('already exists', result.stderr)


if __name__ == '__main__':
    unittest.main()
