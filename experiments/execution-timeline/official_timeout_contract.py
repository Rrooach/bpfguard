"""Read-only exception contract: completed Agent timing, official grader timeout.

This does not convert Harbor timeout into reward=0, rewrite a campaign, retry a
task, relax a collector failure, or assert that application work was equivalent.
"""
import json
from pathlib import Path
from datetime import datetime


def tc_require(value, message):
    if not value:
        raise ValueError(message)


def tc_json(path):
    path = Path(path)
    tc_require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 * 1024**2,
               'bounded regular timeout-contract JSON required: ' + str(path))
    return json.loads(path.read_bytes())


def tc_int(value):
    return type(value) is int and value >= 0


def tc_path(root, remote_root, value):
    original = Path(value)
    tc_require(original.is_absolute(), 'Harbor result must bind its absolute original path')
    relative = original.relative_to(Path(remote_root))
    tc_require('..' not in relative.parts, 'Harbor result escaped original group')
    path = Path(root) / relative
    tc_require(Path(root).resolve(strict=True) in path.resolve(strict=True).parents and not path.is_symlink(),
               'Harbor evidence escapes exported group')
    return path


def tc_time(value):
    tc_require(isinstance(value, str), 'finished official timing required')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    tc_require(parsed.tzinfo is not None, 'official timing lacks timezone')
    return parsed


def tc_validate_group(root, campaign, boot, remote_root):
    root = Path(root)
    tc_require(campaign.get('status') in ('ABORTED', 'WORKER_FAILURE_RETAINED'),
               'timeout exception exporter requires original non-success campaign status')
    tc_require(campaign.get('boot_id') == boot and campaign.get('total_jobs') == 8,
               'timeout group boot/count differs')
    rows = campaign.get('jobs', [])
    tc_require(len(rows) == 8 and len({row['job_id'] for row in rows}) == 8, 'eight unique timed jobs required')
    for field in ('batch_start_ns', 'batch_end_ns', 'batch_wall_ns', 'agent_return_end_ns',
                  'controller_observed_batch_end_ns', 'sampler_first_sample_ns', 'sampler_last_sample_ns',
                  'postprocessing_released_ns', 'campaign_end_ns'):
        tc_require(tc_int(campaign.get(field)), 'incomplete timed phase: ' + field)
    tc_require(campaign['batch_end_ns'] - campaign['batch_start_ns'] == campaign['batch_wall_ns']
               and campaign['batch_start_ns'] < campaign['batch_end_ns'] <= campaign['controller_observed_batch_end_ns']
               <= campaign['postprocessing_released_ns'] < campaign['campaign_end_ns'], 'batch wall/order differs')
    tc_require(campaign.get('sampler_return_code') == 0 and campaign['sampler_first_sample_ns'] <= campaign['batch_start_ns']
               and campaign['sampler_last_sample_ns'] >= campaign['batch_end_ns'], 'sampler did not enclose completed timed window')
    released = tc_json(root / 'control/all-agents-done.json')
    tc_require(released.get('event') == 'ALL_AGENTS_DONE' and released.get('total_jobs') == 8
               and released.get('monotonic_ns') == campaign['postprocessing_released_ns'], 'post-Agent gate differs')
    outcomes, timeouts, quiets, returns, releases = {}, [], [], [], []
    for row in rows:
        name = row['job_id']
        tc_require(Path(name).name == name and name.startswith('terminal-'), 'unsafe worker name')
        control = root / 'control' / name
        release = tc_json(control / 'release.json')
        done = tc_json(control / 'agent-done.json')
        metadata = done.get('metadata', {})
        tc_require(release.get('event') == 'RELEASE' and release.get('job_id') == name
                   and done.get('event') == 'AGENT_DONE' and done.get('job_id') == name,
                   'missing exact release/Agent-done proof')
        begin, returned, quiet = row.get('release_issued_ns'), row.get('agent_return_ns'), row.get('quiescent_ns')
        tc_require(all(tc_int(x) for x in (begin, returned, quiet, done.get('monotonic_ns')))
                   and begin == release['monotonic_ns'] <= returned <= quiet <= done['monotonic_ns']
                   <= released['monotonic_ns'], 'Agent timing did not finish before postprocessing')
        tc_require(metadata == row.get('done_metadata') and metadata.get('agent_return_ns') == returned
                   and metadata.get('quiescent_ns') == quiet and metadata.get('quiescent') is True
                   and metadata.get('frozen') is True and metadata.get('boot_id') == boot,
                   'Agent frozen quiescence/identity differs')
        before = tc_json(control / 'resources-before.json')
        tc_require(before.get('status') == 'CAPTURED_BOUNDARY_COUNTERS' and not before.get('errors')
                   and before.get('cgroup_id') == metadata.get('cgroup_id')
                   and before.get('cgroup_root') == metadata.get('cgroup_root')
                   and before.get('frozen_before', {}).get('frozen') == '1'
                   and before.get('frozen_after', {}).get('frozen') == '1'
                   and begin <= before.get('begin_ns', -1) <= before.get('end_ns', -1) <= returned,
                   'missing frozen starting resource boundary')
        after = tc_json(control / 'resources-after.json')
        tc_require(after.get('status') == 'CAPTURED_BOUNDARY_COUNTERS' and not after.get('errors')
                   and after.get('cgroup_id') == metadata.get('cgroup_id')
                   and after.get('cgroup_root') == metadata.get('cgroup_root')
                   and after.get('frozen_before', {}).get('frozen') == '1'
                   and after.get('frozen_after', {}).get('frozen') == '1'
                   and quiet <= after.get('begin_ns', -1) <= after.get('end_ns', -1) <= done['monotonic_ns'],
                   'missing frozen end resource boundary')
        job = root / 'jobs' / name
        worker = tc_json(job / 'worker-result.json')
        relative = Path(worker['timeline_directory'])
        tc_require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe timeline directory')
        timeline = job / relative
        manifest = tc_json(timeline / 'manifest.json')
        tc_require(worker.get('job_id') == name and worker.get('agent_return_ns') == returned
                   and worker.get('quiescent_ns') == quiet and manifest.get('boot_id') == boot
                   and manifest.get('run_id') == metadata.get('run_id')
                   and manifest.get('cgroup_id') == metadata.get('cgroup_id')
                   and manifest.get('collector_return_code') == 0
                   and manifest.get('closure', {}).get('frozen') is True
                   and not manifest.get('closure', {}).get('nonbaseline_thread_candidates')
                   and tc_int(manifest.get('end_ns')) and manifest['end_ns'] >= quiet,
                   'unsealed/failed capture cannot be excused as official timeout')
        official = worker.get('official_result') or {}
        result_path = tc_path(root, remote_root, official.get('harbor_result', ''))
        result = tc_json(result_path)
        exception = result.get('exception_info')
        tc_require(result.get('task_name') == worker.get('task_id'), 'official result task differs')
        tc_require(exception == official.get('harbor_exception'), 'worker and raw Harbor exception differ')
        rewards = (result.get('verifier_result') or {}).get('rewards')
        tc_require(rewards == official.get('harbor_rewards'), 'worker and raw Harbor rewards differ')
        if exception:
            tc_require(worker.get('task_id') == 'terminal-bench/html-js-filter'
                       and exception.get('exception_type') == 'VerifierTimeoutError'
                       and exception.get('exception_message') == 'Verifier execution timed out after 1800.0 seconds'
                       and result.get('verifier_result') is None and rewards is None
                       and worker.get('official_evaluated') is False and worker.get('official_passed') is False
                       and row.get('worker_exit_code') == 1,
                       'not the narrowly allowed official HTML verifier timeout')
            config = result.get('config', {})
            tc_require(config.get('verifier', {}).get('override_timeout_sec') is None
                       and config.get('verifier', {}).get('max_timeout_sec') is None
                       and config.get('verifier', {}).get('disable') is False
                       and config.get('verifier_timeout_multiplier') is None,
                       'timeout override/reduction cannot use original-timeout contract')
            agent_times, verifier_times = result.get('agent_execution') or {}, result.get('verifier') or {}
            tc_require(tc_time(agent_times.get('finished_at')) <= tc_time(verifier_times.get('started_at'))
                       < tc_time(verifier_times.get('finished_at')) <= tc_time(result.get('finished_at')),
                       'official exception did not finish after Agent return')
            tc_require((tc_time(verifier_times['finished_at']) - tc_time(verifier_times['started_at'])).total_seconds() >= 1799,
                       'original 1800s verifier budget was shortened')
            timeouts.append(name)
            outcomes[name] = {'official_evaluated': False, 'official_passed': None,
                'grading_status': 'OFFICIAL_VERIFIER_TIMEOUT_NOT_SCORED', 'raw_worker_official_passed': False,
                'harbor_result_relative': str(result_path.relative_to(root)), 'exception_type': 'VerifierTimeoutError'}
        else:
            tc_require(worker.get('official_evaluated') is True and type(worker.get('official_passed')) is bool
                       and rewards is not None and not worker.get('error') and row.get('worker_exit_code') == 0,
                       'another worker failed infrastructure/official grading')
            outcomes[name] = {'official_evaluated': True, 'official_passed': worker['official_passed'],
                'grading_status': 'OFFICIAL_GRADED', 'raw_worker_official_passed': worker['official_passed'],
                'harbor_result_relative': str(result_path.relative_to(root)), 'exception_type': None}
        releases.append(begin); returns.append(returned); quiets.append(quiet)
    tc_require(timeouts and campaign['batch_start_ns'] == min(releases) and campaign['batch_end_ns'] == max(quiets)
               and campaign['agent_return_end_ns'] == max(returns), 'original timing endpoints differ')
    abort_path = root / 'control/abort.json'
    if campaign['status'] == 'ABORTED':
        abort = tc_json(abort_path)
        tc_require(abort.get('event') == 'ABORT' and abort.get('job_id') in timeouts
                   and tc_int(abort.get('monotonic_ns')) and abort['monotonic_ns'] > released['monotonic_ns'],
                   'controller abort predates all-Agent-done or belongs to another failure')
    return {'status': 'TIMED_PHASE_COMPLETED_POST_AGENT_OFFICIAL_VERIFIER_TIMEOUT_ONLY',
        'original_campaign_status': campaign['status'], 'official_attempts': 8,
        'official_evaluated_total': 8 - len(timeouts), 'official_timeout_total': len(timeouts),
        'official_passed': sum(row['official_passed'] is True for row in outcomes.values()),
        'timeout_jobs': timeouts, 'outcomes': outcomes, 'batch_wall_ns': campaign['batch_wall_ns'],
        'score_scope': 'TIMED_OUT_OFFICIAL_ATTEMPT_IS_UNSCORED_NOT_REWRITTEN_TO_ZERO; ORIGINAL_FILES_UNCHANGED'}
