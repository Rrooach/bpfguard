import unittest
import test_render as fixture


class PreferredViewTests(unittest.TestCase):
    def test_hint_is_display_only_and_keeps_all_threads_and_full_duration(self):
        report=fixture.fixture()
        original=fixture.render.model_for(report)
        begin=report['run']['begin_ns']
        report['preferred_view']={'begin_ns':begin+10,'end_ns':begin+20}
        model=fixture.render.model_for(report)
        self.assertEqual(model['default_view']['t0'],10)
        self.assertEqual(model['default_view']['t1'],20)
        self.assertEqual(model['threads'],original['threads'])
        self.assertEqual(model['duration_ns'],original['duration_ns'])
        self.assertIn("RESET_SHOWS_FULL_CAPTURE",model['default_view']['source'])

    def test_invalid_hint_falls_back_to_full_view_without_hiding_records(self):
        report=fixture.fixture()
        report['preferred_view']={'begin_ns':0,'end_ns':1}
        model=fixture.render.model_for(report)
        self.assertEqual(model['default_view']['t0'],0)
        self.assertEqual(model['default_view']['t1'],model['duration_ns'])


if __name__=='__main__':
    unittest.main()
