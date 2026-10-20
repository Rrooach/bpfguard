import json
from pathlib import Path
import tempfile
import unittest

import verify_profile_export as export
from seal_profiles import sha


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        inputs = []
        for index in range(12):
            path = self.root / ('asset-%02d' % index)
            path.write_bytes(str(index).encode())
            inputs.append(dict(target=path.name, sha256=sha(path), bytes=path.stat().st_size,
                               pin_source='artifacts.json:key'))
        (self.root / 'export-inputs.json').write_text(json.dumps({'inputs': inputs}))
        (self.root / 'export-environment.json').write_text(json.dumps({'boot_id': 'fixture'}))
        inventory = {p.name: dict(sha256=sha(p), bytes=p.stat().st_size) for p in self.root.iterdir()}
        (self.root / 'export-inventory.json').write_text(json.dumps(inventory))
        self.anchor = sha(self.root / 'export-inventory.json')

    def tearDown(self):
        self.temp.cleanup()

    def test_intact_export(self):
        result = export.verify(self.root, self.anchor)
        self.assertEqual(result['files'], 14)
        self.assertEqual(result['pinned_runtime_assets_verified'], 12)

    def test_anchor_mismatch(self):
        with self.assertRaisesRegex(ValueError, 'pre-export digest'):
            export.verify(self.root, '0' * 64)

    def test_modified_content_rejected_even_same_size(self):
        (self.root / 'asset-00').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'content/size differs'):
            export.verify(self.root, self.anchor)

    def test_missing_extra_and_symlink_rejected(self):
        (self.root / 'extra').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'file set differs'):
            export.verify(self.root, self.anchor)
        (self.root / 'extra').unlink()
        (self.root / 'asset-00').unlink()
        with self.assertRaisesRegex(ValueError, 'file set differs'):
            export.verify(self.root, self.anchor)
        (self.root / 'asset-00').symlink_to(self.root / 'asset-01')
        with self.assertRaisesRegex(ValueError, 'symlink/special'):
            export.verify(self.root, self.anchor)

    def test_duplicate_json_keys_rejected(self):
        path = self.root / 'export-inventory.json'
        path.write_text('{"x": {}, "x": {}}')
        with self.assertRaisesRegex(ValueError, 'duplicate inventory'):
            export.verify(self.root, sha(path))


if __name__ == '__main__':
    unittest.main()
