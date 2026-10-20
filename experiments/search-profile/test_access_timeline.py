import copy
import unittest

import access_timeline as timeline
from test_access_comparison import trial


class TimelineTests(unittest.TestCase):
    def test_choose_one_real_median_run_not_resource_median(self):
        rows = [trial(i, seconds=seconds) for i, seconds in enumerate((10, 1, 4, 2, 8))]
        rows[2]['resources']['unrelated'] = 300
        selected = timeline.choose_representatives(rows)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]['median_wall_seconds'], 4)
        self.assertIs(selected[0]['representative'], rows[2])

    def test_modes_and_concurrency_six_stay_separate(self):
        rows = [trial(i, mode, n, seconds=4) for i in range(2) for mode in ('sampler', 'access') for n in (2, 4, 6, 8)]
        self.assertEqual(len(timeline.choose_representatives(rows)), 8)

    def test_unknown_condition_does_not_make_zero_curve(self):
        row = trial()
        row['cache_evidence']['cache_condition_eligible'] = False
        selected = timeline.choose_representatives([row])[0]
        self.assertIsNone(selected['representative'])
        self.assertIsNone(selected['median_wall_seconds'])

    def test_delta_missing_reset_and_real_zero(self):
        self.assertEqual(timeline.delta([{'x': [3]}, {'x': [3]}], ('x', 0)), 0)
        self.assertIsNone(timeline.delta([{'x': [3]}, {'x': [2]}], ('x', 0)))
        self.assertIsNone(timeline.delta([{'x': [3]}, {}], ('x', 0)))

    def test_rate_uses_actual_time_and_breaks_long_gap(self):
        run = {'release_ns': 1000000000}
        meta = {'interval_ms': 100, 'online_cpus': 2, 'clk_tck': 100,
                'thread_sampling': {'schedstats_runtime_enabled_at_start': False}}
        first = {'monotonic_ns': 1000000000, 'stat': {'ctxt': 10}}
        second = {'monotonic_ns': 1100000000, 'stat': {'ctxt': 20}}
        third = {'monotonic_ns': 1500000000, 'stat': {'ctxt': 30}}
        panels = timeline.panels(run, meta, [first, second, third])
        series = panels[7][2][0][1]
        self.assertEqual(series[0], (.1, 100.0))
        self.assertEqual(series[1], (.5, None))
        self.assertEqual(panels[4][2][0][1], [])

    def test_svg_contains_nine_panels_and_actual_query_bar(self):
        run = {'release_ns': 1000000000, 'makespan_ns': 100000000,
            'results': [{'task_id': 'task-0000', 'query_statistics': {'query_spans': [
                {'begin_ns': 1000000000, 'end_ns': 1100000000}]}}]}
        meta = {'interval_ms': 100, 'online_cpus': 2, 'clk_tck': 100,
                'thread_sampling': {'schedstats_runtime_enabled_at_start': False}}
        rows = [{'monotonic_ns': t} for t in (900000000, 1000000000, 1100000000, 1200000000)]
        value = timeline.svg_plot(run, meta, rows)
        self.assertIn('task-0000', value)
        self.assertIn('CPU', value)
        self.assertIn('page faults', value)
        self.assertIn('没有模型调用', value)
        self.assertTrue(value.endswith('</svg>'))


if __name__ == '__main__':
    unittest.main()
