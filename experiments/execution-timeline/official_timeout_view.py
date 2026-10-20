"""Read-only UI admission for a sealed, post-Agent official grader timeout.

This is not a recovery operation, a worker retry, or a general exception
allowlist. It consumes the durable export/replay receipt and reruns the exact
version-pinned timeout contract without executing code from an evidence folder.
"""
from pathlib import Path

from common import digest
from matrix_summary import Sources, require
import official_timeout_contract as contract

FINAL = 'ALL_EIGHT_HOST_REPLAYS_FINISHED_POST_AGENT_GRADER_TIMEOUT_RETAINED'
DURABLE = 'GROUP_SELECTED_FILES_DURABLE_COPY_AND_GUEST_REHASH_PASSED'
CLASSIFICATION = 'TIMED_PHASE_COMPLETED_POST_AGENT_OFFICIAL_VERIFIER_TIMEOUT_ONLY'


def validate_timeout_admission(root, campaign):
    root = Path(root).resolve(strict=True)
    sources = Sources()
    final_path = root.with_name(root.name+'-export-replay.json')
    export_path = root.with_name(root.name+'-export.json')
    inventory_path = root.with_name(root.name+'-source-inventory.json')
    final = sources.read(final_path)
    require(final.get('status') == FINAL and final.get('group') == root.name
        and final.get('source_deleted') is False and final.get('automatic_next_or_model_call') is False
        and final.get('incomplete_statuses_preserved') is True, 'sealed post-Agent timeout replay receipt required')
    durable = sources.read(export_path, final.get('export_identity'))
    require(durable.get('status') == DURABLE and durable.get('group') == root.name
        and durable.get('source_deleted') is False and durable.get('destination') == str(root),
        'durable timeout export identity/status differs')
    require(isinstance(final.get('export_identity'), dict) and isinstance(final.get('source_inventory_identity'), dict)
        and final['source_inventory_identity'] == durable.get('source_inventory_identity'),
        'explicit export/inventory binding required')
    inventory = sources.read(inventory_path, final['source_inventory_identity'])
    require(isinstance(inventory.get('inventory', {}).get('files'), dict), 'source inventory files required')
    files = inventory['inventory']['files']
    source = durable.get('source')
    require(isinstance(source, str) and Path(source).is_absolute() and Path(source).name == root.name,
        'original absolute group path required')
    boot = campaign.get('boot_id')
    require(final.get('boot_id') == durable.get('boot_id') == boot, 'timeout export boot differs')
    for phase in (durable.get('before', {}), durable.get('after', {}),
                  durable.get('transfer_done', {}).get('after_phase', {}), inventory.get('phase', {})):
        require(phase.get('boot_id') == boot and phase.get('group') == root.name
            and phase.get('campaign_identity') == digest(root/'campaign.json'), 'timeout campaign source anchor differs')
    source_contracts = [value for name, value in final.get('source_identities', {}).items()
        if Path(name).name == 'timeout-contract.py']
    require(len(source_contracts) == 1 and source_contracts[0] == digest(Path(contract.__file__)),
        'timeout validator version differs from export; evidence-folder code is never executed')
    require(final.get('source_identities') == durable.get('source_identities'), 'timeout export/replay source versions differ')

    def bind_source(relative):
        relative = Path(relative)
        require(not relative.is_absolute() and '..' not in relative.parts, 'safe source-relative timeout artifact required')
        expected = files.get(str(relative))
        require(isinstance(expected, dict) and expected.get('sha256'), 'timeout artifact not source-inventory bound: '+str(relative))
        sources.bind(root/relative, expected)

    bind_source('campaign.json'); bind_source('control/all-agents-done.json')
    if campaign.get('status') == 'ABORTED':
        bind_source('control/abort.json')
    for row in campaign.get('jobs', []):
        name = row['job_id']
        require(Path(name).name == name and name.startswith('terminal-'), 'safe timeout worker name required')
        for filename in ('release.json', 'agent-done.json', 'resources-before.json', 'resources-after.json'):
            bind_source(Path('control')/name/filename)
        worker_path = Path('jobs')/name/'worker-result.json'; bind_source(worker_path)
        worker = sources.read(root/worker_path)
        timeline = Path(worker['timeline_directory'])
        require(not timeline.is_absolute() and '..' not in timeline.parts, 'safe timeout timeline directory required')
        bind_source(Path('jobs')/name/timeline/'manifest.json')
        original_result = Path((worker.get('official_result') or {}).get('harbor_result', ''))
        require(original_result.is_absolute(), 'absolute Harbor result source required')
        bind_source(original_result.relative_to(Path(source)))

    computed = contract.tc_validate_group(root, campaign, boot, source)
    require(computed.get('status') == CLASSIFICATION
        and computed == final.get('timeout_contract') == durable.get('timeout_contract')
        == inventory.get('phase', {}).get('timeout_contract'), 'recomputed post-Agent timeout classification differs')
    for phase in (durable.get('before', {}), durable.get('after', {}), durable.get('transfer_done', {}).get('after_phase', {})):
        require(phase.get('timeout_contract') == computed, 'timeout contract changed during durable export')
    require(final.get('official_total') == computed['official_attempts']
        and final.get('official_evaluated_total') == computed['official_evaluated_total']
        and final.get('official_timeout_total') == computed['official_timeout_total']
        and final.get('official_passed') == computed['official_passed'], 'timeout group score totals differ')
    final_jobs = {row['job_id']: row for row in final.get('jobs', [])}
    durable_jobs = {row['job_id']: row for row in durable.get('jobs', [])}
    expected_jobs = set(computed['outcomes'])
    require(len(final.get('jobs', [])) == len(durable.get('jobs', [])) == 8
        and set(final_jobs) == set(durable_jobs) == expected_jobs, 'eight exact timeout export/replay jobs required')
    for name, outcome in computed['outcomes'].items():
        row, exported = final_jobs[name], durable_jobs[name]
        for field in ('official_evaluated', 'official_passed', 'grading_status', 'raw_worker_official_passed'):
            require(row.get(field) == exported.get(field) == outcome[field], 'timeout job score/outcome differs: '+field)
        require(row.get('verification_status') == 'REPLAY_PASSED', 'all eight raw replays must pass for timeout admission')
        analysis = root.parent/'analysis'/root.name/name
        require(isinstance(row.get('verification_identity'), dict) and isinstance(row.get('report_identity'), dict),
            'timeout analysis identities required')
        verification = sources.read(analysis/'verification.json', row['verification_identity'])
        report_path = analysis/'report-host.json'
        sources.bind(report_path, row['report_identity'])
        worker = sources.read(root/'jobs'/name/'worker-result.json')
        manifest = root/'jobs'/name/worker['timeline_directory']/'manifest.json'
        require(row.get('manifest_identity') == exported.get('manifest_identity') == digest(manifest)
            == verification.get('manifest_identity'), 'timeout manifest replay binding differs')
        require(verification.get('verification_status') == 'REPLAY_PASSED'
            and verification.get('report_identity') == row['report_identity'], 'timeout verification/report differs')
        raw_binding = verification.get('artifacts', {}).get('raw-replay.json')
        require(isinstance(raw_binding, dict) and raw_binding.get('sha256'), 'explicit raw replay artifact binding required')
        raw = sources.read(analysis/'raw-replay.json', raw_binding)
        require(raw.get('verification_status') == 'REPLAY_PASSED'
            and raw.get('manifest_identity') == row['manifest_identity']
            and raw.get('report_identity') == row['report_identity'], 'timeout raw replay evidence identity differs')
    sources.unchanged()
    return {'status': CLASSIFICATION, 'original_campaign_status': campaign['status'],
        'contract': computed, 'official_outcomes': computed['outcomes'], 'source_identities': sources.identities,
        'receipt': str(final_path), 'receipt_identity': digest(final_path),
        'scope': 'READ_ONLY_POST_TIMED_OFFICIAL_1800S_VERIFIER_TIMEOUT_ADMISSION; ORIGINAL_CAMPAIGN_NOT_REWRITTEN'}
