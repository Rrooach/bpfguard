import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import access_select as select


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.original = self.root / 'main-001'
        self.continuation = self.root / 'resume-001'
        self.original.mkdir()
        self.continuation.mkdir()
        self.pause_path = self.root / 'pause-001.json'
        self.output = self.root / 'selected-001'
        self.plans = select.contract.expected_schedule(101646)
        self.base = {'schema_version': 1, 'status': 'COMPLETE', 'output_equivalence': 'PASS',
            'seed': 101646, 'jobs': 8, 'passes': 1, 'queries': select.contract.FIXED_QUERIES,
            'cpus': [0, 1, 2, 3], 'measurement_coordinator_sampler_collector_cpus': [4, 5],
            'measurement_modes': ['sampler', 'access'], 'boot_id': 'fixture-boot',
            'source': {'commit': '519a81750493f6fb35ee282ba3ff5bafdd58b81b',
                'regular_files': 95989, 'regular_file_bytes': 1641397655, 'archive_sha256': 'a' * 64},
            'source_inventory_sha256': 'b' * 64, 'file_access_backend': 'kprobe-tracefs',
            'collector_budget': {'ring_bytes': 268435456, 'max_bytes': 2147483648, 'max_seconds': 1200},
            'binaries': {**{key: 'c' * 64 for key in select.contract.BINARY_DIGESTS},
                         'file_access_backend': 'kprobe-tracefs'},
            'source_integrity': 'PARTICIPATING_ROOTS_POST_CAMPAIGN_REHASHED_IDENTICAL',
            'participating_source_roots': ['/source/%d' % index for index in range(9)]}
        old = copy.deepcopy(self.base)
        old.update(status='FAILED', error='InterruptedCollectorTimeout', schedule=self.plans,
                   campaigns=[self.entry(index) for index in range(54)])
        old.pop('source_integrity')
        old.pop('output_equivalence')
        self.write(self.original / 'matrix.json', old)
        self.pause = {'status': 'PAUSED_AT_USER_REQUEST', 'vm_boot_id': 'fixture-boot',
            'completed_trials': 54, 'last_completed_trial_index': 53,
            'in_progress_trial_index': 54, 'in_progress_block': 1}
        self.write(self.pause_path, self.pause)
        new = copy.deepcopy(self.base)
        new.update(schedule=self.plans[32:], campaigns=[self.entry(index, True) for index in range(32, 160)],
            continuation={'original_matrix_sha256': self.sha(self.original / 'matrix.json'),
                'pause_receipt_sha256': self.sha(self.pause_path), 'source_start_index': 32,
                'original_schedule_indices': list(range(32, 160)), 'adapter_sha256': 'd' * 64})
        self.write(self.continuation / 'matrix.json', new)
        for index in range(160):
            root = self.original if index < 32 else self.continuation
            case = root / self.entry(index)['path']
            case.mkdir()
            self.write(case / 'campaign.json', {'index': index})
            self.write(case / 'capture.json', {'collector_run_id': 'original-id-' + str(index)})
            (case / 'events.bin').write_bytes(b'x' * 192)
            (case / 'files.json.gz').write_bytes(b'opaque-gzip')

    @staticmethod
    def write(path, value):
        Path(path).write_text(json.dumps(value), encoding='utf-8')

    @staticmethod
    def sha(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def entry(self, index, resumed=False):
        plan = self.plans[index]
        condition = {key: value for key, value in plan.items() if key != 'block'}
        condition.update(mode='sampler', repetition=0, file_access_backend='kprobe-tracefs',
                         collector_ring_bytes=268435456)
        row = {'path': '%03d-r%d' % (index, plan['block']), 'block': plan['block'],
               'stage': 'performance', 'condition': condition}
        if resumed:
            row['original_schedule_index'] = index
        return row

    def build(self):
        return select.make_selection(self.original / 'matrix.json', self.continuation / 'matrix.json',
                                     self.pause_path, self.output)

    def source_validation(self, mutate_original=None, mutate_new=None, mutate_pause=None):
        old = json.loads((self.original / 'matrix.json').read_text())
        new = json.loads((self.continuation / 'matrix.json').read_text())
        pause = copy.deepcopy(self.pause)
        if mutate_original:
            mutate_original(old)
        if mutate_new:
            mutate_new(new)
        if mutate_pause:
            mutate_pause(pause)
        return select.validate_sources(old, new, pause,
            self.sha(self.original / 'matrix.json'), self.sha(self.pause_path))

    def mocked_verify(self, **kwargs):
        # These fixtures deliberately contain no real 8-task outputs.  The
        # existing strict verifier has its own real-output tests; no green
        # fixed-work claim is inferred from our minimal composition fixtures.
        with patch.object(select.contract, 'verify', return_value={
                'verified': True, 'status': 'MOCKED_FIXED_WORK_NOT_A_REAL_DATASET'}):
            return select.verify_selection(self.output / 'matrix.json', **kwargs)

    def test_failed_original_not_mutated_and_partial_block_wholly_replaced(self):
        old_bytes = (self.original / 'matrix.json').read_bytes()
        matrix = self.build()
        self.assertEqual(len(matrix['campaigns']), 160)
        self.assertEqual((self.original / 'matrix.json').read_bytes(), old_bytes)
        lineage = json.loads((self.output / 'selection.json').read_text())
        self.assertEqual(lineage['original_producer_status_preserved'], 'FAILED')
        self.assertEqual(lineage['excluded_original_completed_schedule_indices'], list(range(32, 54)))
        self.assertEqual(lineage['cases'][31]['source'], 'original_matrix')
        self.assertEqual(lineage['cases'][32]['source'], 'continuation_matrix')
        self.assertEqual(os.stat(self.output / '032-r1/events.bin').st_ino,
                         os.stat(self.continuation / '032-r1/events.bin').st_ino)
        self.assertTrue(self.mocked_verify()['verified'])

    def test_never_reads_opaque_event_or_gzip_payloads(self):
        original = Path.open
        def guarded(path, *args, **kwargs):
            if path.name == 'events.bin' or path.suffix == '.gz':
                raise AssertionError('selection must not read large raw artifacts')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            self.build()
            result = self.mocked_verify()
        self.assertTrue(result['verified'])
        self.assertEqual(result['raw_event_validation'],
                         'NOT_PERFORMED; REQUIRES_INDEPENDENT_ACCESS_ANALYSIS')

    def test_capture_collector_id_is_not_rewritten_to_alias_name(self):
        self.build()
        value = json.loads((self.output / '032-r1/capture.json').read_text())
        self.assertEqual(value['collector_run_id'], 'original-id-32')

    def test_wrong_fixed_work_scope_rejected(self):
        with self.assertRaisesRegex(ValueError, 'fixed scope'):
            self.source_validation(mutate_new=lambda value: value.update(cpus=[0, 1]))

    def test_wrong_schedule_rejected(self):
        with self.assertRaisesRegex(ValueError, 'schedule'):
            self.source_validation(mutate_new=lambda value: value['schedule'].reverse())

    def test_unfinished_original_or_continuation_rejected(self):
        for target in ('original', 'new'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                kwargs = {'mutate_' + target: lambda value: value.update(status='RUNNING')}
                self.source_validation(**kwargs)

    def test_changed_boot_or_different_pause_block_rejected(self):
        for mutation in (lambda value: value.update(vm_boot_id='other-boot'),
                         lambda value: value.update(in_progress_block=0),
                         lambda value: value.update(in_progress_trial_index=90, completed_trials=90,
                                                    last_completed_trial_index=89)):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'pause receipt'):
                self.source_validation(mutate_pause=mutation)

    def test_continuation_source_hash_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, 'continuation does not bind'):
            self.source_validation(mutate_new=lambda value:
                value['continuation'].update(original_matrix_sha256='0' * 64))

    def test_wrong_logical_index_or_case_condition_rejected(self):
        for mutation in (lambda value: value['campaigns'][0].update(original_schedule_index=99),
                         lambda value: value['campaigns'][0]['condition'].update(concurrency=1)):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.source_validation(mutate_new=mutation)

    def test_missing_final_source_rehash_rejected(self):
        with self.assertRaisesRegex(ValueError, 'rehash'):
            self.source_validation(mutate_new=lambda value: value.pop('source_integrity'))

    def test_metadata_mutation_rejected_even_when_hardlink_changes_both_copies(self):
        self.build()
        self.write(self.output / '032-r1/capture.json', {'changed': True})
        result = self.mocked_verify()
        self.assertFalse(result['verified'])
        self.assertIn('artifact', result['issues'][0]['detail'])

    def test_opaque_length_change_rejected_without_opening_payload(self):
        self.build()
        path = self.output / '032-r1/events.bin'
        path.unlink()
        path.write_bytes(b'different length')
        result = self.mocked_verify()
        self.assertFalse(result['verified'])

    def test_source_manifest_mutation_rejected(self):
        self.build()
        self.write(self.original / 'matrix.json', {'status': 'COMPLETE'})
        result = self.mocked_verify()
        self.assertFalse(result['verified'])
        self.assertIn('source receipt', result['issues'][0]['detail'])

    def test_selection_matrix_scope_change_rejected(self):
        self.build()
        matrix = json.loads((self.output / 'matrix.json').read_text())
        matrix['cpus'] = [0, 1]
        self.write(self.output / 'matrix.json', matrix)
        result = self.mocked_verify()
        self.assertFalse(result['verified'])
        self.assertIn('reconstructed', result['issues'][0]['detail'])

    def test_symlink_artifact_or_tree_rejected(self):
        path = self.original / '000-r0/escape'
        path.symlink_to(self.pause_path)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.build()
        self.assertFalse(self.output.exists())

    def test_top_case_symlink_is_not_silently_resolved(self):
        source = self.original / '000-r0'
        source.rename(self.original / 'unrelated-case')
        source.symlink_to(self.original / 'unrelated-case', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'nonsymlink'):
            self.build()

    def test_incomplete_fixed_work_dimension_remains_incomplete(self):
        self.build()
        with patch.object(select.contract, 'verify', return_value={
                'verified': True, 'status': 'VERIFIED_BINDINGS_WITH_INCOMPLETE_DIMENSIONS'}):
            result = select.verify_selection(self.output / 'matrix.json')
        self.assertTrue(result['verified'])
        self.assertIn('INCOMPLETE_DIMENSIONS', result['status'])

    def test_fresh_destination_required(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, 'fresh'):
            self.build()

    def test_relocated_source_paths_require_matching_receipt_bytes(self):
        self.build()
        replacement = self.root / 'copied-pause.json'
        replacement.write_bytes(self.pause_path.read_bytes())
        self.assertTrue(self.mocked_verify(pause_path=replacement)['verified'])
        self.write(replacement, {'wrong': 'receipt'})
        self.assertFalse(self.mocked_verify(pause_path=replacement)['verified'])

    def test_strict_verifier_failure_cannot_be_hidden_by_lineage(self):
        self.build()
        with patch.object(select.contract, 'verify', return_value={'verified': False, 'issues': ['bad fixed work']}):
            result = select.verify_selection(self.output / 'matrix.json')
        self.assertFalse(result['verified'])
        self.assertEqual(result['fixed_work_verification']['issues'], ['bad fixed work'])


if __name__ == '__main__':
    unittest.main()
