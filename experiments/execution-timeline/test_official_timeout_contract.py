import official_timeout_contract as contract
import copy
import json
from pathlib import Path
import tempfile
import unittest



def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class TimeoutContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.boot = 'boot'
        self.remote = '/opt/model-timeline-data/terminal-codex-2468-20261019-002/terminal-c4-r001'
        rows = []
        for index in range(8):
            name = f'terminal-{index:02d}'
            begin, returned, quiet = 100 + index*10, 104 + index*10, 105 + index*10
            meta = {'agent_return_ns': returned, 'quiescent_ns': quiet, 'quiescent': True, 'frozen': True,
                    'boot_id': self.boot, 'cgroup_id': index+1, 'cgroup_root': '/cg/'+name, 'run_id': 'run-'+name}
            row = {'job_id': name, 'release_issued_ns': begin, 'agent_return_ns': returned, 'quiescent_ns': quiet,
                   'done_metadata': meta, 'worker_exit_code': int(index == 3)}
            rows.append(row)
            control = self.root/'control'/name
            save(control/'release.json', {'event': 'RELEASE', 'job_id': name, 'monotonic_ns': begin})
            save(control/'agent-done.json', {'event': 'AGENT_DONE', 'job_id': name, 'monotonic_ns': quiet+5, 'metadata': meta})
            save(control/'resources-before.json', {'status': 'CAPTURED_BOUNDARY_COUNTERS', 'errors': {},
                'begin_ns': begin, 'end_ns': begin+1, 'cgroup_id': index+1, 'cgroup_root': '/cg/'+name,
                'frozen_before': {'frozen': '1'}, 'frozen_after': {'frozen': '1'}})
            save(control/'resources-after.json', {'status': 'CAPTURED_BOUNDARY_COUNTERS', 'errors': {},
                'begin_ns': quiet, 'end_ns': quiet+1, 'cgroup_id': index+1, 'cgroup_root': '/cg/'+name,
                'frozen_before': {'frozen': '1'}, 'frozen_after': {'frozen': '1'}})
            task = 'terminal-bench/html-js-filter'
            exception = {'exception_type': 'VerifierTimeoutError', 'exception_message': 'Verifier execution timed out after 1800.0 seconds',
                         'exception_traceback': 'original stack', 'occurred_at': '2026-10-19T00:30:02Z'} if index == 3 else None
            reward = None if index == 3 else {'reward': 0.0}
            worker = {'job_id': name, 'task_id': task, 'timeline_directory': 'timelines/html-js-filter',
                'agent_return_ns': returned, 'quiescent_ns': quiet, 'official_evaluated': index != 3,
                'official_passed': False, 'error': None,
                'official_result': {'harbor_result': self.remote+'/jobs/'+name+'/harbor/result.json',
                    'harbor_exception': exception, 'harbor_rewards': reward}}
            result = {'task_name': task, 'exception_info': exception,
                'verifier_result': None if index == 3 else {'rewards': reward},
                'config': {'verifier': {'override_timeout_sec': None, 'max_timeout_sec': None, 'disable': False},
                           'verifier_timeout_multiplier': None},
                'agent_execution': {'finished_at': '2026-10-19T00:00:01Z'},
                'verifier': {'started_at': '2026-10-19T00:00:02Z', 'finished_at': '2026-10-19T00:30:02Z'},
                'finished_at': '2026-10-19T00:30:03Z'}
            job = self.root/'jobs'/name
            save(job/'worker-result.json', worker); save(job/'harbor/result.json', result)
            save(job/'timelines/html-js-filter/manifest.json', {'boot_id': self.boot, 'run_id': 'run-'+name,
                 'cgroup_id': index+1, 'collector_return_code': 0,
                 'closure': {'frozen': True, 'nonbaseline_thread_candidates': []}, 'end_ns': 1000})
        self.campaign = {'status': 'ABORTED', 'boot_id': self.boot, 'total_jobs': 8, 'jobs': rows,
            'batch_start_ns': 100, 'batch_end_ns': 175, 'batch_wall_ns': 75, 'agent_return_end_ns': 174,
            'controller_observed_batch_end_ns': 200, 'sampler_first_sample_ns': 90, 'sampler_last_sample_ns': 210,
            'sampler_return_code': 0, 'postprocessing_released_ns': 300, 'campaign_end_ns': 10000}
        save(self.root/'control/all-agents-done.json', {'event': 'ALL_AGENTS_DONE', 'total_jobs': 8, 'monotonic_ns': 300})
        save(self.root/'control/abort.json', {'event': 'ABORT', 'job_id': 'terminal-03', 'monotonic_ns': 9000})

    def validate(self):
        return contract.tc_validate_group(self.root, self.campaign, self.boot, self.remote)

    def mutate(self, relative, callback):
        path = self.root/relative; row=json.loads(path.read_text()); callback(row); save(path,row)

    def test_preserves_original_and_unscored_timeout(self):
        original = copy.deepcopy(self.campaign)
        result = self.validate()
        self.assertEqual(result['official_evaluated_total'], 7)
        self.assertEqual(result['official_timeout_total'], 1)
        self.assertIsNone(result['outcomes']['terminal-03']['official_passed'])
        self.assertFalse(result['outcomes']['terminal-03']['raw_worker_official_passed'])
        self.assertEqual(self.campaign, original)
        self.assertFalse(json.loads((self.root/'jobs/terminal-03/worker-result.json').read_text())['official_passed'])

    def test_normal_campaign_not_exception_path(self):
        self.campaign['status']='WORKERS_COMPLETED'
        with self.assertRaises(ValueError):self.validate()

    def test_seven_jobs_rejected(self):
        self.campaign['jobs'].pop()
        with self.assertRaises(ValueError):self.validate()

    def test_abort_during_agent_not_excused(self):
        self.mutate('control/abort.json',lambda x:x.update(monotonic_ns=299))
        with self.assertRaises(ValueError):self.validate()

    def test_abort_other_worker_not_excused(self):
        self.mutate('control/abort.json',lambda x:x.update(job_id='terminal-00'))
        with self.assertRaises(ValueError):self.validate()

    def test_sampler_failure_not_excused(self):
        self.campaign['sampler_return_code']=1
        with self.assertRaises(ValueError):self.validate()

    def test_collector_failure_not_excused(self):
        self.mutate('jobs/terminal-03/timelines/html-js-filter/manifest.json',lambda x:x.update(collector_return_code=1))
        with self.assertRaises(ValueError):self.validate()

    def test_unfrozen_end_not_excused(self):
        self.mutate('control/terminal-03/resources-after.json',lambda x:x.update(frozen_after={'frozen':'0'}))
        with self.assertRaises(ValueError):self.validate()

    def test_unfrozen_start_not_excused(self):
        self.mutate('control/terminal-03/resources-before.json',lambda x:x.update(frozen_after={'frozen':'0'}))
        with self.assertRaises(ValueError):self.validate()

    def test_other_worker_error_not_excused(self):
        self.mutate('jobs/terminal-02/worker-result.json',lambda x:x.update(error='observer failure'))
        with self.assertRaises(ValueError):self.validate()

    def test_shortened_original_timeout_not_excused(self):
        self.mutate('jobs/terminal-03/harbor/result.json',lambda x:x['verifier'].update(finished_at='2026-10-19T00:01:02Z'))
        with self.assertRaises(ValueError):self.validate()

    def test_timeout_override_not_excused(self):
        self.mutate('jobs/terminal-03/harbor/result.json',lambda x:x['config']['verifier'].update(override_timeout_sec=60))
        with self.assertRaises(ValueError):self.validate()

    def test_false_grade_not_substituted(self):
        self.mutate('jobs/terminal-03/harbor/result.json',lambda x:x.update(verifier_result={'rewards':{'reward':0}}))
        with self.assertRaises(ValueError):self.validate()

    def test_wrong_exception_not_excused(self):
        self.mutate('jobs/terminal-03/harbor/result.json',lambda x:x['exception_info'].update(exception_type='AgentTimeoutError'))
        with self.assertRaises(ValueError):self.validate()

    def test_worker_and_harbor_exception_must_match(self):
        self.mutate('jobs/terminal-03/worker-result.json',lambda x:x['official_result'].update(harbor_exception=None))
        with self.assertRaises(ValueError):self.validate()


if __name__=='__main__':unittest.main()
