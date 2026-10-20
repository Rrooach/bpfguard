import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('access_calibration_tested', Path(__file__).with_name('access_calibrate.py'))
CAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAL)


def event(kind, result=0, inode=99, tid=1):
    raw = bytearray(192)
    struct.pack_into('<IHHII', raw, 0, 0x46414343, 1, kind, 192, 129 if inode else 8)
    struct.pack_into('<QQ', raw, 56, 100, 200)
    struct.pack_into('<Q', raw, 96, inode)
    struct.pack_into('<q', raw, 128, result)
    struct.pack_into('<I', raw, 160, 253 << 20)
    struct.pack_into('<I', raw, 172, tid)
    return bytes(raw)


class AccessCalibrationTests(unittest.TestCase):
    def rows(self):
        reads = [event(1, result, tid=1 + index % 3)
                 for index, result in enumerate((97, 193, 77, 11, 15, 17, 17, 0, 11))]
        return reads + [event(4), event(1, -9, inode=0), event(5)] + [event(6) for _ in range(4)]

    def check(self, rows):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'events.bin'
            path.write_bytes(b''.join(rows))
            return CAL.validate_raw(path, 99, 253 << 20)

    def test_known_reads_threads_fault_paths_and_alias(self):
        result = self.check(self.rows())
        self.assertEqual(result['fixture_returned_bytes'], 438)
        self.assertEqual(result['fixture_read_calls'], 9)
        self.assertEqual(result['fixture_mm_fault_attempts'], 4)
        self.assertEqual(result['fixture_filemap_fault_attempts'], 1)

    def test_filemap_subset_does_not_replace_mm_fault_observation(self):
        rows = [row for row in self.rows() if struct.unpack_from('<H', row, 6)[0] != 6]
        with self.assertRaises(ValueError):
            self.check(rows)

    def test_missing_read_cannot_pass(self):
        with self.assertRaises(ValueError): self.check(self.rows()[1:])

    def test_truncated_record_cannot_pass(self):
        with self.assertRaises(ValueError): self.check(self.rows() + [b'bad'])

    def test_wrong_record_size_cannot_pass(self):
        rows = self.rows()
        first = bytearray(rows[0]); struct.pack_into('<I', first, 8, 184)
        rows[0] = bytes(first)
        with self.assertRaises(ValueError): self.check(rows)


if __name__ == '__main__': unittest.main()
