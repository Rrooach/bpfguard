"""Native64 naming is presentation only; this never extends hook coverage."""
import hashlib
from pathlib import Path
import unittest

import syscall_catalog as C


class CatalogTests(unittest.TestCase):
    def test_catalog_exactly_matches_selected_local_table(self):
        table = next((parent / C.TABLE_SOURCE for parent in Path(__file__).resolve().parents
                      if (parent / C.TABLE_SOURCE).is_file()), None)
        if table is None:
            self.skipTest('source kernel table not shipped with standalone viewer')
        self.assertEqual(hashlib.sha256(table.read_bytes()).hexdigest(), C.TABLE_SHA256)
        entries = {}
        for line in table.read_text().splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[0].isdigit() and fields[1] in ('common', '64'):
                entries[int(fields[0])] = fields[2]
        self.assertEqual(C.NAMES, entries)
        self.assertGreaterEqual(len(entries), 380)

    def test_unknown_x32_and_boolean_numbers_are_not_reinterpreted(self):
        for number in ((1 << 30) + 257, 99999, True, None):
            self.assertEqual(C.describe(number)['name_source'], 'RECORDED_OR_UNKNOWN_NO_CATALOG_MATCH')
        self.assertEqual(C.describe(90)['name'], 'chmod')
        self.assertEqual(C.describe(264)['name'], 'renameat')
        self.assertEqual(C.describe(99999, 'custom') ['name'], 'custom')


if __name__ == '__main__':
    unittest.main()
