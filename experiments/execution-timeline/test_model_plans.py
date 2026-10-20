"""Offline plan/registry invariants; no Guest, provider, or privileged operation."""
import json
from pathlib import Path
import tempfile
import unittest

from common import write_new
from prepare_model_plans import generate


class ModelPlanTests(unittest.TestCase):
    def test_exact64_labels_fixed_work_and_explicit_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native = root/'native'; native.mkdir()
            (native/'collect').write_bytes(b'fixture executable identity')
            (native/'execution_timeline.bpf.o').write_bytes(b'fixture object identity')
            for label in ('swe', 'terminal'):
                template = {'schema_version': 1, 'benchmark': 'SWE-bench Verified' if label == 'swe' else 'Terminal-Bench',
                    'resource_configuration': {'total_preloaded_collectors': 8, 'sample_size_per_condition': 1},
                    'jobs': [{'job_id': f'{label}-{i:02d}', 'task_id': f'{label}-task',
                        'command': ['/opt/python', '-B', f'/opt/execution-timeline/parallel_{label}.py',
                            '--collector', '/opt/execution-timeline/native021/collect',
                            '--object', '/opt/execution-timeline/native021/execution_timeline.bpf.o',
                            '--output', '@JOB_OUTPUT@', '--control-dir', '@CONTROL_DIR@', '--job-id', '@JOB_ID@']} for i in range(8)]}
                write_new(root/(label+'.json'), template)
            paths = generate(root/'plans', root/'terminal.json', root/'swe.json', native,
                guest_native='/opt/model-execution-timeline/native022', campaign_id='new-real-trial', historical_bound='.753668')
            self.assertEqual(len(paths), 8)
            registry = json.loads((root/'plans/budget-labels.json').read_bytes())
            self.assertEqual(len([row for row in registry['labels'] if row['kind'] == 'FORMAL']), 64)
            self.assertEqual(registry['campaign_id'], 'new-real-trial')
            labels = set()
            for path in paths:
                plan = json.loads(path.read_bytes())
                self.assertEqual(plan['mode'], 'MODEL_AGENT')
                self.assertEqual(len(plan['jobs']), 8)
                self.assertEqual(plan['resource_configuration']['model_rounds'], 4)
                self.assertEqual(plan['resource_configuration']['model_max_output_tokens'], 1024)
                self.assertEqual(plan['resource_configuration']['historical_bound_rmb'], '0.753668')
                for job in plan['jobs']:
                    command = job['command']; label = command[command.index('--budget-label')+1]
                    self.assertNotIn(label, labels); labels.add(label)
                    self.assertIn('/opt/model-execution-timeline/model_', command[2])
                    self.assertEqual(command[command.index('--collector')+1], '/opt/model-execution-timeline/native022/collect')
                    self.assertEqual(command[command.index('--object')+1], '/opt/model-execution-timeline/native022/execution_timeline.bpf.o')
            self.assertEqual(labels, {row['label'] for row in registry['labels'] if row['kind'] == 'FORMAL'})


if __name__ == '__main__': unittest.main()
