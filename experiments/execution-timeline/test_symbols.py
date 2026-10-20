#!/usr/bin/env python3
from pathlib import Path
import tempfile
import unittest

from replay import Symbols


class SymbolTests(unittest.TestCase):
    def test_unknown_jit_gap_is_not_named_after_an_older_program(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kallsyms"
            path.write_text("00000100 t bpf_prog_aabbccddeeff0011\n"
                            "00000200 T io_schedule\n"
                            "00000300 T bpf_prog_run\n"
                            "00000400 t module_fn [module]\n"
                            "00000500 D kernel_data\n")
            result = Symbols(path).resolve([0x110, 0x210, 0x310, 0x410, 0x510])
            self.assertIn("UNRESOLVED_DYNAMIC_JIT_OR_MODULE_RANGE", result[0])
            self.assertNotIn("aabbccddeeff0011", result[0])
            self.assertEqual(result[1], "io_schedule+0x10")
            self.assertEqual(result[2], "bpf_prog_run+0x10")
            self.assertIn("UNRESOLVED_DYNAMIC_JIT_OR_MODULE_RANGE", result[3])
            self.assertIn("UNRESOLVED_NON_TEXT_RANGE", result[4])

    def test_missing_and_zero_symbols_leave_addresses_unresolved(self):
        self.assertEqual(Symbols().resolve([0x123]), ["0x123"])


if __name__ == "__main__":
    unittest.main()
