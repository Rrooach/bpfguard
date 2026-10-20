"""Synthetic sealed timeout evidence only; never VM, Docker, model or API."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from common import digest
import official_timeout_contract as contract
import official_timeout_view as view
import test_official_timeout_contract as fixture


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        fixture.TimeoutContract.setUp(self)
        self.outer = tempfile.TemporaryDirectory(); self.addCleanup(self.outer.cleanup)
        target = Path(self.outer.name)/'terminal-c4-r001'
        self.root.rename(target); self.root = target
        self.campaign['concurrency'] = 4
        self.final_path = self.root.with_name(self.root.name+'-export-replay.json')
        self.export_path = self.root.with_name(self.root.name+'-export.json')
        self.inventory_path = self.root.with_name(self.root.name+'-source-inventory.json')

    def seal(self):
        fixture.save(self.root/'campaign.json', self.campaign)
        classified = contract.tc_validate_group(self.root, self.campaign, self.boot, self.remote)
        final_jobs, durable_jobs = [], []
        for campaign_row in self.campaign['jobs']:
            name = campaign_row['job_id']; outcome = classified['outcomes'][name]
            job = self.root/'jobs'/name
            manifest = job/'timelines/html-js-filter/manifest.json'
            manifest_id = digest(manifest)
            analysis = self.root.parent/'analysis'/self.root.name/name
            fixture.save(analysis/'report-host.json', {'scope': 'SYNTHETIC_BINDING_TEST_NOT_NATIVE_COVERAGE'})
            report_id = digest(analysis/'report-host.json')
            fixture.save(analysis/'raw-replay.json', {'verification_status': 'REPLAY_PASSED',
                'manifest_identity': manifest_id, 'report_identity': report_id})
            verification = {'verification_status': 'REPLAY_PASSED', 'manifest_identity': manifest_id,
                'report_identity': report_id, 'artifacts': {'raw-replay.json': digest(analysis/'raw-replay.json')}}
            fixture.save(analysis/'verification.json', verification)
            common = {'job_id': name, 'manifest_identity': manifest_id,
                **{key: outcome[key] for key in ('official_evaluated', 'official_passed', 'grading_status', 'raw_worker_official_passed')}}
            durable_jobs.append(dict(common))
            final_jobs.append({**common, 'verification_status': 'REPLAY_PASSED', 'report_identity': report_id,
                'verification_identity': digest(analysis/'verification.json')})
        source_ids = {'/synthetic/timeout-contract.py': digest(Path(contract.__file__))}
        phase = {'boot_id': self.boot, 'group': self.root.name, 'campaign_identity': digest(self.root/'campaign.json'),
            'timeout_contract': classified}
        files = {str(path.relative_to(self.root)): digest(path) for path in self.root.rglob('*') if path.is_file()}
        fixture.save(self.inventory_path, {'phase': phase, 'inventory': {'files': files}})
        inventory_id = digest(self.inventory_path)
        durable = {'status': view.DURABLE, 'group': self.root.name, 'boot_id': self.boot,
            'source_deleted': False, 'destination': str(self.root), 'source': self.remote,
            'source_inventory_identity': inventory_id, 'before': phase, 'after': phase,
            'transfer_done': {'after_phase': phase}, 'timeout_contract': classified,
            'source_identities': source_ids, 'jobs': durable_jobs}
        fixture.save(self.export_path, durable)
        final = {'status': view.FINAL, 'group': self.root.name, 'boot_id': self.boot,
            'source_deleted': False, 'automatic_next_or_model_call': False, 'incomplete_statuses_preserved': True,
            'export_identity': digest(self.export_path), 'source_inventory_identity': inventory_id,
            'timeout_contract': classified, 'source_identities': source_ids, 'jobs': final_jobs,
            'official_total': 8, 'official_evaluated_total': 7, 'official_timeout_total': 1, 'official_passed': 0}
        fixture.save(self.final_path, final)

    def mutate(self, path, callback):
        value = json.loads(path.read_bytes()); callback(value); fixture.save(path, value)

    def test_admits_only_bound_replayed_post_timing_timeout_and_preserves_original(self):
        self.seal(); original = (self.root/'campaign.json').read_bytes()
        result = view.validate_timeout_admission(self.root, self.campaign)
        self.assertEqual(result['original_campaign_status'], 'ABORTED')
        self.assertEqual(result['contract']['official_evaluated_total'], 7)
        self.assertIsNone(result['official_outcomes']['terminal-03']['official_passed'])
        self.assertEqual((self.root/'campaign.json').read_bytes(), original)

    def test_missing_sealed_final_receipt_is_not_accepted(self):
        with self.assertRaises((ValueError, FileNotFoundError)):
            view.validate_timeout_admission(self.root, self.campaign)

    def test_changing_timeout_to_zero_or_ungraded_denominator_to_eight_rejected(self):
        for key, value in (('official_evaluated_total', 8), ('official_timeout_total', 0)):
            with self.subTest(key=key):
                self.seal(); self.mutate(self.final_path, lambda row: row.update({key: value}))
                with self.assertRaisesRegex(ValueError, 'score totals'):
                    view.validate_timeout_admission(self.root, self.campaign)

    def test_unknown_post_exception_receipt_status_not_admitted(self):
        self.seal(); self.mutate(self.final_path, lambda row: row.update(status='EARLY_TERMINATION'))
        with self.assertRaisesRegex(ValueError, 'sealed post-Agent'):
            view.validate_timeout_admission(self.root, self.campaign)

    def test_different_contract_source_version_not_executed_or_admitted(self):
        self.seal(); self.mutate(self.final_path, lambda row: row['source_identities'].update({
            '/synthetic/timeout-contract.py': {'sha256': '0'*64, 'size_bytes': 1}}))
        with self.assertRaisesRegex(ValueError, 'validator version'):
            view.validate_timeout_admission(self.root, self.campaign)

    def test_modified_control_file_fails_source_inventory_binding(self):
        self.seal(); self.mutate(self.root/'control/all-agents-done.json', lambda row: row.update(monotonic_ns=1))
        with self.assertRaisesRegex(ValueError, 'source differs'):
            view.validate_timeout_admission(self.root, self.campaign)

    def test_missing_or_failed_raw_replay_does_not_excuse_collector_failure(self):
        self.seal(); self.mutate(self.final_path, lambda row: row['jobs'][3].update(verification_status='FAILED_OR_INCOMPLETE'))
        with self.assertRaisesRegex(ValueError, 'all eight raw replays'):
            view.validate_timeout_admission(self.root, self.campaign)

    def test_missing_export_identity_never_becomes_unbound_optional_source(self):
        self.seal(); self.mutate(self.final_path, lambda row: row.pop('export_identity'))
        with self.assertRaisesRegex(ValueError, 'explicit export/inventory'):
            view.validate_timeout_admission(self.root, self.campaign)


if __name__ == '__main__':
    unittest.main()
