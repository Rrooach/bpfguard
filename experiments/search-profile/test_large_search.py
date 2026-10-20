import unittest

import large_search as large


class LargeSearchTests(unittest.TestCase):
    def test_fixed_blocks_and_random_order(self):
        rows = large.cases(5, 73)
        self.assertEqual(len(rows), 80)
        self.assertEqual(rows, large.cases(5, 73))
        expected = {(c, w, n) for c in ('warm', 'guest-cold') for w in ('shared', 'independent') for n in (1, 2, 4, 8)}
        for block in range(5):
            selected = [row for row in rows if row['block'] == block]
            self.assertEqual({(row['cache'], row['workspace_layout'], row['concurrency']) for row in selected}, expected)

    def test_interventions_interleaved_within_random_blocks(self):
        rows = large.cases(5, 7, 'paired', (4, 8), ('warm',), ('shared',))
        self.assertEqual(len(rows), 20)
        for block in range(5):
            self.assertEqual({(row['concurrency'], row['intervention']) for row in rows if row['block'] == block},
                             {(4, 'none'), (4, 'exact-reuse'), (8, 'none'), (8, 'exact-reuse')})

    def test_cache_condition_rejects_incomplete_or_wrong_residency(self):
        for fraction, mode in ((.1, 'guest-cold'), (.99, 'warm'), (None, 'warm')):
            with self.assertRaises(RuntimeError):
                large.verify_cache({'status': 'OBSERVED_NON_ATOMIC', 'roots': [{'resident_fraction': fraction}]}, mode)
        for mode, fraction in (('guest-cold', 0), ('warm', 1)):
            large.verify_cache({'status': 'OBSERVED_NON_ATOMIC', 'roots': [{'resident_fraction': fraction}]}, mode)
        with self.assertRaises(RuntimeError):
            large.verify_cache({'status': 'INCOMPLETE', 'roots': [{'resident_fraction': 0}]}, 'guest-cold')


if __name__ == '__main__':
    unittest.main()
