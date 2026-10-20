import json
import unittest

import access_progress
import access_search


def logs(plans, first, count):
    text = ''
    for index in range(first, first + count):
        text += json.dumps(dict(plans[index], trial_index=index)) + '\n'
        text += json.dumps({'completed': index, 'wall_seconds': 2.0,
            'file_access_health': 'COMPLETE_FOR_SELECTED_HOOKS' if plans[index]['file_access_mode'] == 'access' else 'NOT_ENABLED'}) + '\n'
    return text


class ProgressContracts(unittest.TestCase):
    def setUp(self):
        self.plans = access_search.schedule(5, 101646)
        self.old = {'schedule': self.plans, 'seed': 101646, 'status': 'FAILED', 'campaigns': [{}] * 54}
        self.old_log = logs(self.plans, 0, 54)

    def test_all_logged_is_explicitly_not_final_verified(self):
        result = access_progress.report(self.old, self.old_log, logs(self.plans, 32, 128))
        self.assertEqual(result['status'], 'LOGGED_ALL_CONTINUATION_TRIALS_NOT_VERIFIED')
        self.assertEqual(result['selected_completed_log_count'], 160)
        self.assertEqual(result['selected_declared_health_counts'], {'COMPLETE_FOR_SELECTED_HOOKS': 80, 'NOT_ENABLED': 80})
        self.assertIsNone(result['estimated_outer_schedule_seconds_remaining'])

    def test_empty_pinning_log_and_partial_tail_are_not_failure(self):
        text = '{"pinning":"independent","roots":8}\n{"trial_'
        result = access_progress.report(self.old, self.old_log, text, 4107)
        self.assertEqual(result['selected_completed_log_count'], 32)
        self.assertTrue(result['ignored_partial_last_line'])
        self.assertIsNone(result['current_logical_index'])
        self.assertEqual(result['next_expected_logical_index'], 32)
        self.assertEqual(result['issues'], [])
        self.assertAlmostEqual(result['estimated_outer_schedule_seconds_remaining'], 4107 / 54 * 128)

    def test_current_started_trial_and_completed_prefix(self):
        text = logs(self.plans, 32, 2) + json.dumps(dict(self.plans[34], trial_index=34)) + '\n'
        result = access_progress.report(self.old, self.old_log, text)
        self.assertEqual(result['selected_completed_log_count'], 34)
        self.assertEqual(result['current_logical_index'], 34)
        self.assertEqual(result['current_condition'], self.plans[34])

    def test_hole_duplicate_changed_condition_and_bad_health_are_visible(self):
        for text in (logs(self.plans, 33, 1), logs(self.plans, 32, 1) * 2,
                     json.dumps(dict(self.plans[32], concurrency=99, trial_index=32)) + '\n',
                     logs(self.plans, 32, 1).replace('COMPLETE_FOR_SELECTED_HOOKS', 'INCOMPLETE')):
            result = access_progress.report(self.old, self.old_log, text)
            self.assertEqual(result['status'], 'PROGRESS_LOG_REQUIRES_INSPECTION')
            self.assertTrue(result['issues'])

    def test_interior_bad_json_and_bool_duration_not_silently_accepted(self):
        for text in ('broken\n', logs(self.plans, 32, 1).replace('2.0', 'true')):
            self.assertTrue(access_progress.progress(text, self.plans, 32)['issues'])


if __name__ == '__main__':
    unittest.main()
