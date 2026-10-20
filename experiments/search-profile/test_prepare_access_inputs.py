import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import prepare_access_inputs as PREPARE
import verify_access_inputs as VERIFY


class PrepareAccessInputTests(unittest.TestCase):
    def test_regular_mapping_includes_scope_and_native_device(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / 'a'
            path.write_bytes(b'abc')
            row = PREPARE.object_row(path, root, 'SOURCE_CORPUS')
            self.assertEqual(row['relative_path'], 'a')
            self.assertEqual(row['size'], 3)
            self.assertEqual(row['scope_kind'], 'SOURCE_CORPUS')
            self.assertEqual(VERIFY.compare_rows({'source_root': str(root), 'objects': [row]}), 1)

    def test_changed_metadata_cannot_qualify_as_identical(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / 'a'
            path.write_bytes(b'abc')
            row = PREPARE.object_row(path, root, 'SOURCE_CORPUS')
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                VERIFY.compare_rows({'source_root': str(root), 'objects': [row]})

    def test_repeated_path_and_symlink_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / 'a'
            path.write_bytes(b'abc')
            row = PREPARE.object_row(path, root, 'SOURCE_CORPUS')
            with self.assertRaises(ValueError):
                VERIFY.compare_rows({'source_root': str(root), 'objects': [row, row]})
            alias = root / 'alias'; alias.symlink_to(path)
            self.assertIsNone(PREPARE.object_row(alias, root, 'SOURCE_CORPUS'))

    def test_missing_declared_file_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(FileNotFoundError):
                list(PREPARE.inventory_rows(Path(temporary), 'SOURCE_CORPUS',
                                           [{'path': 'missing', 'size': 0}]))


if __name__ == '__main__': unittest.main()
