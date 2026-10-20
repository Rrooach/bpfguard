import copy
import gzip
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

import verify_cache_proof as verify


def fixture(mode='warm', layout='shared'):
    files = [{'path': 'a.txt', 'size': 4097, 'sha256': 'a' * 64},
             {'path': 'empty', 'size': 0, 'sha256': 'b' * 64}]
    perms = [{'path': '.', 'mode': 0o755, 'uid': 1000, 'gid': 1000, 'xattrs': {}}] + [
        {'path': f['path'], 'mode': 0o644, 'uid': 1000, 'gid': 1000, 'xattrs': {}} for f in files]
    inventory = {'files': files, 'bytes': 4097, 'sha256': verify.digest(files),
        'permissions': perms, 'permission_scope_sha256': verify.digest(perms)}
    roots = []
    for index in range(8 if layout == 'independent' else 1):
        start = 100 + index * 1000
        entries = []
        for i, source in enumerate(files):
            pages = (source['size'] + 4095) // 4096
            entries.append({**source, 'status': 'OBSERVED_NON_ATOMIC',
                'start_monotonic_ns': start + 10 + i * 20, 'end_monotonic_ns': start + 20 + i * 20,
                'total_pages': pages, 'total_bytes': source['size'],
                'resident_pages': pages if mode == 'warm' else 0,
                'resident_bytes': source['size'] if mode == 'warm' else 0,
                'identity': {'device': 2049, 'inode': 100 + index * 10 + i, 'size': source['size'],
                    'mtime_ns': 123, 'ctime_ns': 234, 'mode': stat.S_IFREG | 0o644,
                    'uid': 1000, 'gid': 1000, 'nlink': 1}})
        root = {'schema_version': 1, 'kind': 'MINCORE_FILE_DATA_RESIDENCY',
            'root': '/repo/shared' if layout == 'shared' else '/repo/private-' + str(index),
            'inventory_sha256': verify.digest(files), 'pin_sha256': 'c' * 64, 'page_size': 4096,
            'start_monotonic_ns': start, 'end_monotonic_ns': start + 100, 'duration_ns': 100,
            'status': 'OBSERVED_NON_ATOMIC', 'errors': [], 'files': entries,
            'mincore_authority': verify.AUTHORITY, 'filesystem_uid': 1000,
            'declared_file_count': 2, 'observed_file_count': 2, 'unknown_file_count': 0,
            'total_pages': 2, 'total_bytes': 4097, 'observed_total_pages': 2, 'observed_total_bytes': 4097,
            'resident_pages': 2 if mode == 'warm' else 0, 'resident_bytes': 4097 if mode == 'warm' else 0,
            'observed_resident_pages': 2 if mode == 'warm' else 0,
            'observed_resident_bytes': 4097 if mode == 'warm' else 0,
            'resident_fraction': 1.0 if mode == 'warm' else 0.0,
            'data_page_state': 'ALL_RESIDENT_AT_EACH_FILE_PROBE' if mode == 'warm' else 'ALL_NONRESIDENT_AT_EACH_FILE_PROBE'}
        roots.append(root)
    full = {'schema_version': 1, 'kind': 'MINCORE_MULTIPLE_ROOT_RESIDENCY',
        'status': 'OBSERVED_NON_ATOMIC', 'roots': roots, 'independent_roots_required': layout == 'independent',
        'shared_dev_inode_identities': [], 'aggregation': verify.AGGREGATION}
    profile = {'status': 'COMPLETE', 'run_id': 'search-toy', 'boot_id': 'toy-boot', 'release_ns': 10000,
        'cache_probe_end_to_release_ns': 10000 - roots[-1]['end_monotonic_ns'],
        'config': {'jobs': 8, 'cache': mode, 'workspace_layout': layout,
            'corpus_sha256': inventory['sha256'], 'permission_scope_sha256': inventory['permission_scope_sha256']}}
    return profile, full, inventory


def compact(full):
    result = copy.deepcopy(full)
    for root in result['roots']:
        root.pop('files')
    return result


class CacheProofReplayTests(unittest.TestCase):
    def replay(self, profile, full, inventory, **kwargs):
        return verify.replay(profile, compact(full), full, inventory, expected_files=2, **kwargs)

    def test_warm_and_cold_shared_and_independent_replay(self):
        for mode in ('warm', 'guest-cold'):
            for layout in ('shared', 'independent'):
                p, f, i = fixture(mode, layout)
                result = self.replay(p, f, i)
                self.assertEqual(result['cache_condition_replay'], 'PASS')
                self.assertEqual(result['pin_binding'], 'UNKNOWN')
                self.assertFalse(result['atomic_snapshot'])
                self.assertEqual(len(result['roots']), 8 if layout == 'independent' else 1)
                self.assertEqual(result['roots'][0]['resident_bytes'], 4097 if mode == 'warm' else 0)

    def test_default_exact_experiment_file_count_not_inferred_from_input(self):
        p, f, i = fixture()
        with self.assertRaisesRegex(verify.ProofError, 'cardinality'):
            verify.replay(p, compact(f), f, i)

    def test_summary_cannot_be_trusted_instead_of_raw_rows(self):
        p, f, i = fixture()
        f['roots'][0]['resident_pages'] = 1
        with self.assertRaisesRegex(verify.ProofError, 'aggregate'):
            self.replay(p, f, i)

    def test_warm_cold_thresholds_recomputed_with_integer_boundary(self):
        for mode, resident, succeeds in [('warm', 999, True), ('warm', 998, False),
                                         ('guest-cold', 1, True), ('guest-cold', 2, False)]:
            p, f, i = fixture(mode)
            size = 1000 * 4096
            i['files'][0]['size'] = size
            i['bytes'] = size
            i['sha256'] = verify.digest(i['files'])
            p['config']['corpus_sha256'] = i['sha256']
            root = f['roots'][0]
            root['inventory_sha256'] = i['sha256']
            row = root['files'][0]
            row.update(size=size, total_pages=1000, total_bytes=size,
                       resident_pages=resident, resident_bytes=resident * 4096)
            row['identity']['size'] = size
            root.update(total_pages=1000, observed_total_pages=1000, total_bytes=size,
                observed_total_bytes=size, resident_pages=resident, observed_resident_pages=resident,
                resident_bytes=resident * 4096, observed_resident_bytes=resident * 4096,
                resident_fraction=resident / 1000, data_page_state='MIXED_RESIDENCY')
            if succeeds:
                self.assertEqual(self.replay(p, f, i)['cache_condition_replay'], 'PASS')
            else:
                with self.assertRaisesRegex(verify.ProofError, 'threshold'): self.replay(p, f, i)

    def test_compact_full_mismatch_detected(self):
        p, f, i = fixture()
        summary = compact(f)
        summary['roots'][0]['duration_ns'] += 1
        with self.assertRaisesRegex(verify.ProofError, 'compact'):
            verify.replay(p, summary, f, i, expected_files=2)

    def test_missing_duplicate_wrong_file_or_size_rejected(self):
        for mutation in ('missing', 'duplicate', 'size', 'hash', 'unsafe-path'):
            p, f, i = fixture()
            rows = f['roots'][0]['files']
            if mutation == 'missing': rows.pop()
            elif mutation == 'duplicate': rows[1] = copy.deepcopy(rows[0])
            elif mutation == 'size': rows[0]['size'] += 1
            elif mutation == 'hash': rows[0]['sha256'] = 'd' * 64
            else: rows[0]['path'] = '../escape'
            with self.assertRaises(verify.ProofError): self.replay(p, f, i)

    def test_partial_last_page_bounds_not_falsely_resident_times_page_size(self):
        self.assertEqual(verify.legal_resident_bounds(4097, 2, 1, 4096), (1, 4096))
        self.assertEqual(verify.legal_resident_bounds(4097, 2, 2, 4096), (4097, 4097))
        self.assertEqual(verify.legal_resident_bounds(0, 0, 0, 4096), (0, 0))
        p, f, i = fixture()
        f['roots'][0]['files'][0]['resident_bytes'] = 8192
        with self.assertRaisesRegex(verify.ProofError, 'partial-page'): self.replay(p, f, i)

    def test_owner_permission_and_type_authority_required(self):
        for key, value in [('uid', 0), ('mode', stat.S_IFLNK | 0o644), ('size', 4096), ('nlink', 0)]:
            p, f, i = fixture()
            f['roots'][0]['files'][0]['identity'][key] = value
            with self.assertRaises(verify.ProofError): self.replay(p, f, i)

    def test_nonfinite_or_boolean_counters_rejected(self):
        for value in (True, -1, None, 3):
            p, f, i = fixture()
            f['roots'][0]['files'][0]['resident_pages'] = value
            with self.assertRaises(verify.ProofError): self.replay(p, f, i)
        with self.assertRaises(verify.ProofError): verify.json_value('{"x":NaN}')
        with self.assertRaises(verify.ProofError): verify.json_value('{"x":1,"x":2}')

    def test_all_ages_reported_not_only_newest_root(self):
        p, f, i = fixture(layout='independent')
        result = self.replay(p, f, i)
        self.assertEqual(result['global_oldest_file_start_to_release_ns'], 9890)
        self.assertEqual(result['roots'][-1]['root_end_to_release_ns'], 2800)

    def test_release_or_nonsequential_file_probes_rejected(self):
        for mutation in ('release', 'sequence', 'age'):
            p, f, i = fixture()
            if mutation == 'release': p['release_ns'] = 150
            elif mutation == 'sequence': f['roots'][0]['files'][1]['start_monotonic_ns'] = 110
            else: p['cache_probe_end_to_release_ns'] += 1
            with self.assertRaises(verify.ProofError): self.replay(p, f, i)

    def test_independent_files_cannot_be_hardlinked_between_roots(self):
        p, f, i = fixture(layout='independent')
        f['roots'][1]['files'][0]['identity']['inode'] = f['roots'][0]['files'][0]['identity']['inode']
        with self.assertRaisesRegex(verify.ProofError, 'share a device/inode'): self.replay(p, f, i)

    def test_readonly_declaration_not_upgraded_to_runtime_attestation(self):
        p, f, i = fixture()
        prep = {'boot_id': p['boot_id'], 'completed_monotonic_ns': 50,
            'corpus': '/repo/shared', 'read_only_bind_mounts': True}
        result = self.replay(p, f, i, preparation=prep)
        self.assertEqual(result['readonly_quality'], 'DECLARED_READ_ONLY_NOT_REATTESTED')
        prep['corpus'] = '/another/scope'
        with self.assertRaises(verify.ProofError): self.replay(p, f, i, preparation=prep)

    def test_retained_original_pin_identity_and_digest_are_replayed(self):
        p, f, i = fixture()
        pin = {'kind': 'MINCORE_PRE_CACHE_PREPARATION_PIN', 'schema_version': 1,
            'root': '/repo/shared', 'status': 'PINNED', 'errors': [],
            'inventory_sha256': verify.digest(i['files']), 'pin_started_ns': 10, 'pin_completed_ns': 20,
            'files': [{**source, 'pin_status': 'PINNED', 'identity': row['identity']} for source, row in
                zip(i['files'], f['roots'][0]['files'])]}
        f['roots'][0]['pin_sha256'] = verify.digest(pin)
        pins = {'schema_version': 1, 'kind': 'MINCORE_MULTIPLE_ROOT_PINS', 'status': 'PINNED',
            'independent_roots_required': False, 'shared_dev_inode_identities': [], 'roots': [pin]}
        self.assertEqual(self.replay(p, f, i, pinned=pins)['pin_binding'], 'MATCHES_ORIGINAL_PIN_RECORDS')
        duplicate = copy.deepcopy(pins)
        duplicate['roots'].append(copy.deepcopy(pin))
        with self.assertRaisesRegex(verify.ProofError, 'root cardinality'):
            self.replay(p, f, i, pinned=duplicate)
        pins['roots'][0]['pin_completed_ns'] += 1
        with self.assertRaisesRegex(verify.ProofError, 'pin digest'): self.replay(p, f, i, pinned=pins)

    def write_trial(self, root):
        p, f, i = fixture()
        inv = root / 'inventory.json'
        inv.write_text(json.dumps(i))
        details = root / 'cache-residency-files.json.gz'
        with gzip.open(str(details), 'wt') as stream: json.dump(f, stream)
        summary = compact(f)
        summary['file_details'] = {'path': details.name, 'sha256': hashlib.sha256(details.read_bytes()).hexdigest()}
        summary_path = root / 'cache-residency.json'
        summary_path.write_text(json.dumps(summary))
        p['cache_residency'] = {'path': summary_path.name, 'sha256': hashlib.sha256(summary_path.read_bytes()).hexdigest()}
        (root / 'profile-run.json').write_text(json.dumps(p))
        return inv, hashlib.sha256(inv.read_bytes()).hexdigest()

    def test_real_toy_gzip_and_two_byte_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inv, anchor = self.write_trial(root)
            result = verify.verify_trial(root, inv, anchor, expected_files=2)
            self.assertEqual(result['status'], 'PASS')
            with self.assertRaisesRegex(verify.ProofError, 'external inventory'):
                verify.verify_trial(root, inv, '0' * 64, expected_files=2)
            details = root / 'cache-residency-files.json.gz'
            details.write_bytes(details.read_bytes() + b'garbage')
            with self.assertRaises((OSError, ValueError, EOFError)):
                verify.verify_trial(root, inv, anchor, expected_files=2)

    def test_decoded_gzip_budget_and_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inv, anchor = self.write_trial(root)
            with self.assertRaisesRegex(verify.ProofError, 'decoded cache proof'):
                verify.verify_trial(root, inv, anchor, expected_files=2, max_proof_bytes=32)
            link = root / 'link'
            link.symlink_to(inv)
            with self.assertRaises(OSError): verify.read_document(link)

    def test_cli_fresh_receipt_and_fail_receipt_never_overwrite_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inv, anchor = self.write_trial(root)
            receipt = root / 'receipt.json'
            command = [sys.executable, '-B', verify.__file__, '--trial', str(root), '--inventory', str(inv),
                '--expected-inventory-sha256', anchor, '--expected-files', '2', '--output', str(receipt)]
            done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(receipt.read_text())['status'], 'PASS')
            original = receipt.read_bytes()
            self.assertNotEqual(subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode, 0)
            self.assertEqual(receipt.read_bytes(), original)
            command[-1] = str(root / 'failure.json')
            command[command.index('--expected-inventory-sha256') + 1] = '0' * 64
            self.assertEqual(subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode, 1)
            self.assertEqual(json.loads((root / 'failure.json').read_text())['cache_condition_replay'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
