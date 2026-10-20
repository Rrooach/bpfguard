import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import seal_profiles as seal


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class SealTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'raw'
        self.root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_all_fresh_markers_reject_before_any_mutation_or_checks(self):
        for marker in seal.MARKERS:
            with self.subTest(marker=marker):
                target = self.root / marker
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('existing-user-evidence')
                with patch.object(seal, 'validate_campaigns') as validate, self.assertRaisesRegex(ValueError, 'existing seal'):
                    seal.seal(self.root)
                validate.assert_not_called()
                self.assertEqual(target.read_text(), 'existing-user-evidence')
                target.unlink()

    def test_tree_refuses_symlink_and_fifo_not_silently_skipped(self):
        outside = Path(self.temp.name) / 'outside'
        outside.write_text('private-not-to-export')
        link = self.root / 'escape'
        link.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'symlink/special'):
            seal.tree_files(self.root)
        link.unlink()
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'symlink/special'):
            seal.tree_files(self.root)

    def test_scope_path_rejects_traversal_absolute_and_symlink(self):
        for relative in ('../outside', '/etc/passwd', ''):
            with self.assertRaises(ValueError):
                seal.inside(self.root, relative)
        (self.root / 'normal').mkdir()
        self.assertEqual(seal.inside(self.root, 'normal'), self.root / 'normal')
        (self.root / 'link').symlink_to(self.root / 'normal', target_is_directory=True)
        with self.assertRaises(ValueError):
            seal.inside(self.root, 'link')

    def test_missing_required_inputs_fail_before_creating_outputs(self):
        with patch.object(seal, 'validate_campaigns', return_value=[]), self.assertRaises((OSError, ValueError)):
            seal.seal(self.root)
        self.assertFalse((self.root / 'executed-sources').exists())
        self.assertFalse((self.root / 'export-environment.json').exists())

    def test_query_duplicate_intervention_rejected_without_reading_trials(self):
        query = self.root / 'queries'
        write(query / 'source-query-campaign.json', {'schema_version': 1, 'benchmark': 'swe', 'runs': [
            {'intervention': 'none', 'returncode': 0}, {'intervention': 'none', 'returncode': 0}]})
        with self.assertRaisesRegex(ValueError, 'duplicated or unfinished'):
            seal.validate_query(query, 'swe')

    def test_official_incomplete_or_wrong_modes_not_sent_to_replay(self):
        name = self.root / 'paired-swe-001'
        manifest = {'benchmark': 'swe', 'tasks': ['psf__requests-1142'],
            'modes': ['baseline', 'threads', 'kernel', 'files', 'perf'], 'repetitions': 5, 'status': 'RUNNING'}
        write(name / 'campaign.json', manifest)
        with patch.object(seal.paired_profiles, 'replay') as replay, self.assertRaisesRegex(ValueError, 'contract incomplete'):
            seal.validate_campaigns(self.root)
        replay.assert_not_called()
        manifest.update(status='COMPLETE', modes=['baseline'] * 5)
        write(name / 'campaign.json', manifest)
        with self.assertRaisesRegex(ValueError, 'contract incomplete'):
            seal.validate_campaigns(self.root)

    def test_full_query_raw_span_schema_and_missing_duration_rejected(self):
        query = self.root / 'queries'
        write(query / 'source-query-campaign.json', {'schema_version': 1, 'benchmark': 'swe',
            'source': {'image_id': 'image'}, 'runs': [{'intervention': name, 'returncode': 0, 'path': str(query / name)}
                for name in ('none', 'exact-reuse')]})
        for intervention in ('none', 'exact-reuse'):
            directory = query / intervention
            manifest = {'status': 'COMPLETE', 'intervention': intervention, 'repository_version': 'image',
                'jobs': 8, 'passes': 8, 'corpus_sha256': 'corpus', 'conditions': [], 'trials': []}
            for c in (1, 8):
                for mode in ('baseline', 'sampler'):
                    for warm in (False, True):
                        for rep in (range(1) if warm else range(5)):
                            condition = dict(concurrency=c, mode=mode, repetition=rep, warmup=warm)
                            index = len(manifest['trials'])
                            item = {**condition, 'path': 'trials/%02d' % index, 'run_id': 'query-%d' % index}
                            manifest['conditions'].append(condition)
                            manifest['trials'].append(item)
                            results = []
                            trial = directory / item['path']
                            for task_index in range(8):
                                task = 'task-%04d' % task_index
                                raw = b'./one\0' * 8
                                digest = hashlib.sha256(raw).hexdigest()
                                results.append(dict(task_id=task, output_sha256=digest, output_bytes=len(raw)))
                                write(trial / (task + '-statistics.json'), {'logical_queries': 8, 'query_spans': [
                                    dict(run_id=item['run_id'], task_id=task, query_ordinal=i, status='COMPLETE',
                                        begin_ns=i * 10, end_ns=i * 10 + 2, duration_ns=2) for i in range(8)]})
                                (trial / (task + '.stdout')).write_bytes(raw)
                            write(trial / 'profile-run.json', dict(status='COMPLETE', run_id=item['run_id'],
                                config={**condition, 'corpus_sha256': 'corpus'}, results=results))
            write(directory / 'campaign.json', manifest)
        receipt = seal.validate_query(query, 'swe')
        self.assertEqual(receipt['raw_logical_query_spans'], 3072)
        path = query / 'none/trials/00/task-0000-statistics.json'
        changed = json.loads(path.read_text())
        changed['query_spans'][0]['duration_ns'] = None
        write(path, changed)
        with self.assertRaisesRegex(ValueError, 'raw timing/identity incomplete'):
            seal.validate_query(query, 'swe')

    def test_seal_sorted_inventory_excludes_itself_and_preserves_unknown(self):
        (self.root / 'z-raw').write_bytes(b'raw')
        source = Path(self.temp.name) / 'required'
        source.write_bytes(b'pinned')
        plan = [{'source': source, 'target': Path('pinned-assets/observer_binary'), 'sha256': seal.sha(source), 'pin_source': 'fixture'}]
        def command(argv, **kwargs):
            return '' if argv == ['docker', 'ps', '-q'] else 'fixture-version'
        with patch.object(seal, 'validate_campaigns', return_value=[{'measurement_health': 'INCOMPLETE'}]), \
                patch.object(seal, 'input_plan', return_value=plan), patch.object(seal.subprocess, 'check_output', side_effect=command):
            result = seal.seal(self.root)
        inventory = json.loads((self.root / 'export-inventory.json').read_text())
        self.assertEqual(list(inventory), sorted(inventory))
        self.assertNotIn('export-inventory.json', inventory)
        self.assertIn('export-inputs.json', inventory)
        self.assertEqual(result['inventory_sha256'], seal.sha(self.root / 'export-inventory.json'))
        for relative, evidence in inventory.items():
            self.assertEqual(seal.sha(self.root / relative), evidence['sha256'])
        self.assertEqual(json.loads((self.root / 'export-inputs.json').read_text())['campaign_preflight'][0]['measurement_health'], 'INCOMPLETE')
        self.assertEqual((self.root / 'z-raw').read_bytes(), b'raw')

    def test_running_container_refused_before_any_copy(self):
        with patch.object(seal, 'validate_campaigns', return_value=[]), \
                patch.object(seal, 'input_plan', return_value=[]), \
                patch.object(seal.subprocess, 'check_output', return_value='still-running\n'), \
                self.assertRaisesRegex(RuntimeError, 'running containers'):
            seal.seal(self.root)
        self.assertFalse((self.root / 'executed-sources').exists())

    def test_every_declared_pinned_asset_is_archived_and_sha_and_scope_rechecked(self):
        runtime = Path(self.temp.name) / 'runtime'
        observer = Path(self.temp.name) / 'observer'
        legacy = Path(self.temp.name) / 'legacy-search'
        tasks = Path(self.temp.name) / 'tasks'
        names = ('diagnostics.py', 'paired_profiles.py', 'source_queries.py', 'prepare_profiles.py',
            'seal_profiles.py', 'terminal-bridge.py', 'swe/run.py', 'terminal/run.py',
            'terminal/prebuilt-images.example.json', 'swe-inputs/task.json', 'swe-inputs/provenance.json',
            'swe-inputs/harness.tar.gz', 'swe-image-requests-1142.tar.json')
        for source in [runtime / name for name in names] + [observer / 'selected-tasks.json', legacy / 'analyze.py',
                tasks / 'html-js-filter/task.toml', tasks / 'bun-sourcemap-leak/task.toml']:
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b'source-fixture')
        perf = Path(self.temp.name) / 'perf'
        perf.write_bytes(b'perf-fixture')
        for manifest, declarations in (('artifacts.json', seal.ASSETS), ('diagnostic-assets.json', seal.DIAGNOSTIC_ASSETS)):
            values = {}
            for key, digest_key in declarations:
                source = perf if key == 'perf_binary' else self.root / 'bin' / key
                source.parent.mkdir(parents=True, exist_ok=True)
                if source != perf:
                    source.write_bytes(key.encode())
                values[key], values[digest_key] = str(source), seal.sha(source)
            write(self.root / manifest, values)

        def mapped_path(*arguments):
            return perf if arguments == ('/usr/bin/perf',) else Path(*arguments)

        with patch.multiple(seal, RUNTIME=runtime, OBSERVER=observer, LEGACY_SEARCH=legacy, TASKS=tasks), \
                patch.object(seal, 'Path', side_effect=mapped_path):
            plan = seal.input_plan(self.root)
            pinned = {row['target'].name for row in plan if row['target'].parts[0] == 'pinned-assets'}
            expected = {key for key, _ in seal.ASSETS + seal.DIAGNOSTIC_ASSETS}
            self.assertEqual(pinned, expected)
            self.assertEqual(len(pinned), 12)
            self.assertTrue(all(not row['target'].is_absolute() and '..' not in row['target'].parts for row in plan))
            (self.root / 'bin/observer_binary').write_bytes(b'changed-after-capture')
            with self.assertRaisesRegex(ValueError, 'scope/SHA256 mismatch'):
                seal.input_plan(self.root)
            (self.root / 'bin/observer_binary').write_bytes(b'observer_binary')
            metadata = json.loads((self.root / 'artifacts.json').read_text())
            outside = Path(self.temp.name) / 'outside-not-authorized'
            outside.write_bytes(b'never-copy')
            metadata.update(observer_binary=str(outside), observer_sha256=seal.sha(outside))
            write(self.root / 'artifacts.json', metadata)
            with self.assertRaisesRegex(ValueError, 'scope/SHA256 mismatch'):
                seal.input_plan(self.root)


if __name__ == '__main__':
    unittest.main()
