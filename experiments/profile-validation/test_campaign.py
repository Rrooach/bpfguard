import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('validation_campaign', Path(__file__).with_name('campaign.py'))
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)


class ConfidenceTests(unittest.TestCase):
    def test_requires_independent_repetitions(self):
        self.assertIsNone(campaign.confidence([]))
        self.assertIsNone(campaign.confidence([-.9, -.9]))

    def test_reports_direction_without_inventing_benefit(self):
        self.assertEqual(campaign.confidence([-.5] * 5), [-.5, -.5])
        self.assertEqual(campaign.confidence([.5] * 5), [.5, .5])
        interval = campaign.confidence([-.1, .1, 0, -.1, .1])
        self.assertLess(interval[0], 0)
        self.assertGreater(interval[1], 0)

    def test_deterministic_ci(self):
        self.assertEqual(campaign.confidence([1, 2, 5, 8]), campaign.confidence([1, 2, 5, 8]))


if __name__ == '__main__':
    unittest.main()
