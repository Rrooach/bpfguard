import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import codex_terminal_campaign as campaign


class PlanTests(unittest.TestCase):
    def test_four_conditions_have_equal_eight_attempts_not_reference_worker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = []
            for index in range(8):
                task = ('bun-sourcemap-leak', 'html-js-filter')[index % 2]
                jobs.append({'job_id': f'terminal-{index:02d}', 'task_id': 'terminal-bench/'+task,
                    'command': ['python', '-B', 'model_terminal.py', '--output', '@JOB_OUTPUT@',
                        '--control-dir', '@CONTROL_DIR@', '--job-id', '@JOB_ID@', '--max-rounds', '4',
                        '--collector', 'old', '--object', 'old', '--budget-label', 'old',
                        '--broker-token-file', 'old', '--max-output', '1024']})
            template = root/'template.json'
            template.write_text(json.dumps({'schema_version': 1, 'benchmark': 'Terminal-Bench',
                'jobs': jobs, 'resource_configuration': {}}))
            with patch.object(campaign, 'digest', return_value={'sha256': 'a'*64, 'size_bytes': 1}):
                result = campaign.prepare(template, root/'out', '/runtime', '/native', '/codex', '/catalog', '/private/token')
            self.assertEqual(result['total_attempts'], 32)
            for count in campaign.COUNTS:
                plan = json.loads((root/f'out/terminal-c{count}.json').read_text())
                self.assertEqual(plan['concurrency'], count)
                self.assertEqual([row['task_id'] for row in plan['jobs']], [row['task_id'] for row in jobs])
                for index, row in enumerate(plan['jobs']):
                    argv = row['command']
                    self.assertEqual(argv[2], '/runtime/codex_terminal.py')
                    self.assertNotIn('--max-rounds', argv)
                    self.assertIn(f'codex-terminal-c{count}-{index:02d}', argv)
                    self.assertEqual(argv[argv.index('--max-calls')+1], '8')
                    self.assertEqual(argv[argv.index('--max-output')+1], '4096')

    def test_rejects_wrong_task_pool(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'template.json'
            jobs = [{'job_id': str(i), 'task_id': 'unexpected', 'command': ['x', '@JOB_OUTPUT@', '@CONTROL_DIR@', '@JOB_ID@']} for i in range(8)]
            path.write_text(json.dumps({'schema_version': 1, 'benchmark': 'Terminal-Bench', 'jobs': jobs}))
            with self.assertRaisesRegex(ValueError, 'four attempts'):
                campaign.prepare(path, path.parent/'out', 'a', 'b', 'c', 'd', 'e')


if __name__ == '__main__':
    unittest.main()
