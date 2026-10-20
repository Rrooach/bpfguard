import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import prepare_large_corpus as preparation


class PrepareLargeCorpusTests(unittest.TestCase):
    """Small, real Git repositories; no Guest, cache drops or large inputs."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repository = self.base / 'repository'
        self.repository.mkdir()
        self.environment = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull,
                                GIT_CONFIG_NOSYSTEM='1')
        self.git('init', '-q')
        self.git('config', 'user.name', 'Corpus Fixture')
        self.git('config', 'user.email', 'corpus-fixture@example.invalid')
        self.git('config', 'core.filemode', 'true')
        self.git('config', 'core.autocrlf', 'false')
        self.files = {
            'README.md': b'committed repository contents\n',
            'data/payload.bin': b'\x00\xff\x01immutable binary contents\x00',
            'scripts/run.sh': b'#!/bin/sh\nprintf "fixture\\n"\n',
            'empty.txt': b'',
        }
        for relative, content in self.files.items():
            path = self.repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o755 if relative == 'scripts/run.sh' else 0o644)
        (self.repository / 'readme-link').symlink_to('README.md')
        (self.repository / 'data-link').symlink_to('data', target_is_directory=True)
        self.git('add', '--all')
        self.git('commit', '-q', '-m', 'immutable fixture')
        self.commit = self.git('rev-parse', 'HEAD').decode().strip()

    def git(self, *arguments):
        result = subprocess.run(
            ['git', '-c', 'core.hooksPath=' + os.devnull,
             '-c', 'commit.gpgsign=false', '-C', str(self.repository)] + list(arguments),
            env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=True)
        return result.stdout

    def prepare(self, name='output', revision=None):
        output = self.base / name
        manifest = preparation.prepare(self.repository, revision or self.commit, output)
        return output, manifest

    def archived_files(self, output):
        with tarfile.open(str(output / 'source.tar'), 'r:') as archive:
            return {entry.name: archive.extractfile(entry).read()
                    for entry in archive.getmembers() if entry.isfile()}

    def assert_regular_scope(self, output, manifest, expected):
        archived = self.archived_files(output)
        self.assertEqual(archived, expected)
        self.assertEqual(manifest['regular_files'], len(archived))
        self.assertEqual(manifest['regular_file_bytes'], sum(map(len, archived.values())))

    def test_fixed_commit_ignores_new_head_staged_dirty_deleted_and_untracked_files(self):
        (self.repository / 'README.md').write_bytes(b'new HEAD, not requested\n')
        self.git('add', 'README.md')
        self.git('commit', '-q', '-m', 'newer unrelated revision')
        newer_head = self.git('rev-parse', 'HEAD').decode().strip()
        self.assertNotEqual(newer_head, self.commit)
        (self.repository / 'README.md').write_bytes(b'staged, not committed\n')
        self.git('add', 'README.md')
        (self.repository / 'scripts/run.sh').write_bytes(b'dirty executable\n')
        (self.repository / 'data/payload.bin').unlink()
        (self.repository / 'untracked-build-output').write_bytes(b'untracked\n')
        before = self.git('status', '--porcelain=v1', '-z')

        output, manifest = self.prepare()

        self.assertEqual(manifest['commit'], self.commit)
        self.assertEqual(manifest['source'], 'GIT_OBJECT_DATABASE_NOT_WORKTREE')
        self.assert_regular_scope(output, manifest, self.files)
        self.assertEqual(self.git('rev-parse', 'HEAD').decode().strip(), newer_head)
        self.assertEqual(self.git('status', '--porcelain=v1', '-z'), before)

    def test_symlinks_are_excluded_and_their_git_identities_are_recorded(self):
        output, manifest = self.prepare()

        expected = [{'path': name, 'mode': '120000',
                     'object': self.git('rev-parse', self.commit + ':' + name).decode().strip()}
                    for name in ('data-link', 'readme-link')]
        self.assertEqual(manifest['excluded_nonregular_entries'], expected)
        with tarfile.open(str(output / 'source.tar'), 'r:') as archive:
            self.assertFalse(any(entry.issym() or entry.islnk() for entry in archive))
        self.assert_regular_scope(output, manifest, self.files)

    def test_executable_mode_binary_contents_and_empty_file_are_preserved(self):
        output, manifest = self.prepare()

        with tarfile.open(str(output / 'source.tar'), 'r:') as archive:
            for relative in self.files:
                entry = archive.getmember(relative)
                self.assertTrue(entry.isfile())
                # Git stores executable vs non-executable, not the entire
                # working-tree chmod. git archive's tar.umask may add/remove
                # group write bits; it must preserve the executable property.
                self.assertEqual(entry.mode & 0o111,
                                 0o111 if relative == 'scripts/run.sh' else 0)
                self.assertEqual(entry.mode & 0o600, 0o600)
                self.assertEqual(entry.mode & 0o6000, 0)
        self.assert_regular_scope(output, manifest, self.files)

    def test_manifest_matches_archive_count_bytes_size_sha_and_saved_json(self):
        output, manifest = self.prepare()

        archive = (output / 'source.tar').read_bytes()
        self.assertEqual(manifest['schema_version'], 1)
        self.assertEqual(manifest['repository'], str(self.repository.resolve()))
        self.assertEqual(manifest['commit'], self.commit)
        self.assertEqual(manifest['archive_bytes'], len(archive))
        self.assertEqual(manifest['archive_sha256'], hashlib.sha256(archive).hexdigest())
        self.assertEqual(manifest['archive_validation'], {
            'status': 'EXACT_GIT_BLOBS_VERIFIED', 'regular_files': len(self.files),
            'regular_file_bytes': sum(map(len, self.files.values())),
            'git_object_hash_algorithms': ['sha1'],
            'mode_policy': 'GIT_REGULAR_MODES_0644_OR_0755', 'archive_umask': '0022'})
        self.assertEqual(json.loads((output / 'source.json').read_text()), manifest)
        self.assert_regular_scope(output, manifest, self.files)

    def test_revision_tag_is_resolved_to_the_actual_commit(self):
        self.git('tag', 'fixture-base', self.commit)

        output, manifest = self.prepare(revision='fixture-base')

        self.assertEqual(manifest['commit'], self.commit)
        self.assert_regular_scope(output, manifest, self.files)

    def test_gitlink_is_excluded_without_reading_a_submodule_worktree(self):
        self.git('update-index', '--add', '--cacheinfo',
                 '160000,' + self.commit + ',vendor/submodule')
        self.git('commit', '-q', '-m', 'gitlink fixture')
        revision = self.git('rev-parse', 'HEAD').decode().strip()

        output, manifest = self.prepare(revision=revision)

        self.assertIn({'path': 'vendor/submodule', 'mode': '160000',
                       'object': self.commit}, manifest['excluded_nonregular_entries'])
        self.assert_regular_scope(output, manifest, self.files)
        self.assertFalse((self.repository / 'vendor/submodule').exists())

    def test_preexisting_empty_directory_is_rejected_without_creating_artifacts(self):
        output = self.base / 'existing'
        output.mkdir()

        with self.assertRaises(FileExistsError):
            preparation.prepare(self.repository, self.commit, output)

        self.assertEqual(list(output.iterdir()), [])

    def test_preexisting_nonempty_directory_is_rejected_without_overwriting(self):
        output = self.base / 'existing'
        output.mkdir()
        original = {'source.tar': b'existing archive', 'source.json': b'existing manifest',
                    'unrelated': b'preserve this too'}
        for name, content in original.items():
            (output / name).write_bytes(content)

        with self.assertRaises(FileExistsError):
            preparation.prepare(self.repository, self.commit, output)

        self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, original)

    def test_rerunning_successful_output_does_not_overwrite_archive_or_manifest(self):
        output, _ = self.prepare()
        original = {path.name: path.read_bytes() for path in output.iterdir()}

        with self.assertRaises(FileExistsError):
            preparation.prepare(self.repository, 'HEAD', output)

        self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, original)

    def test_existing_file_or_output_symlink_cannot_overwrite_its_target(self):
        target = self.base / 'preserved'
        target.mkdir()
        sentinel = target / 'sentinel'
        sentinel.write_bytes(b'not an output directory')
        output_link = self.base / 'output-link'
        output_link.symlink_to(target, target_is_directory=True)
        for output in (sentinel, output_link):
            with self.subTest(output=output.name):
                with self.assertRaises(FileExistsError):
                    preparation.prepare(self.repository, self.commit, output)
        self.assertEqual(sentinel.read_bytes(), b'not an output directory')
        self.assertEqual(list(target.iterdir()), [sentinel])

    def test_export_ignore_is_rejected_archive_retained_and_no_success_manifest(self):
        (self.repository / '.gitattributes').write_text('README.md export-ignore\n')
        self.git('add', '.gitattributes')
        self.git('commit', '-q', '-m', 'export omission fixture')
        revision = self.git('rev-parse', 'HEAD').decode().strip()
        output = self.base / 'output'

        with self.assertRaisesRegex(ValueError, 'archive omits tracked regular files'):
            preparation.prepare(self.repository, revision, output)

        self.assertTrue((output / 'source.tar').is_file())
        self.assertFalse((output / 'source.json').exists())
        self.assertNotIn('README.md', self.archived_files(output))

    def test_same_size_export_subst_is_rejected_by_git_blob_hash(self):
        payload = b'$Format:%s$'
        substituted = b'r' * len(payload)
        (self.repository / 'substitution.txt').write_bytes(payload)
        (self.repository / '.gitattributes').write_text('substitution.txt export-subst\n')
        self.git('add', '.gitattributes', 'substitution.txt')
        self.git('commit', '-q', '-m', substituted.decode())
        revision = self.git('rev-parse', 'HEAD').decode().strip()
        output = self.base / 'output'

        with self.assertRaisesRegex(ValueError, 'archive content differs from Git blob'):
            preparation.prepare(self.repository, revision, output)

        self.assertEqual(self.archived_files(output)['substitution.txt'], substituted)
        self.assertEqual(len(payload), len(substituted))
        self.assertFalse((output / 'source.json').exists())
        self.assertEqual((self.repository / 'substitution.txt').read_bytes(), payload)

    def test_archive_modes_are_explicit_not_inherited_from_git_tar_umask(self):
        self.git('config', 'tar.umask', '0077')

        output, _ = self.prepare()

        with tarfile.open(str(output / 'source.tar'), 'r:') as archive:
            self.assertEqual(archive.getmember('README.md').mode, 0o644)
            self.assertEqual(archive.getmember('scripts/run.sh').mode, 0o755)

    def legacy_archive(self):
        # Small historical-style tar: Git's source modes are still canonical
        # 100644/100755, while tar.umask=0002 yields 0664/0775 in the archive.
        (self.repository / '.clang-format').write_bytes(b'BasedOnStyle: LLVM\n')
        self.git('add', '.clang-format')
        self.git('commit', '-q', '-m', 'legacy archive mode fixture')
        commit = self.git('rev-parse', 'HEAD').decode().strip()
        contents = dict(self.files, **{'.clang-format': b'BasedOnStyle: LLVM\n'})
        expected = {name: {'mode': '100755' if name == 'scripts/run.sh' else '100644',
                           'object': self.git('rev-parse', commit + ':' + name).decode().strip(),
                           'size': len(content)} for name, content in contents.items()}
        path = self.base / 'legacy.tar'
        path.write_bytes(self.git('-c', 'tar.umask=0002', 'archive', '--format=tar', commit,
                                  '--', '.', ':(exclude)readme-link', ':(exclude)data-link'))
        return path, expected

    def mutate_small_archive(self, original, name, mutate):
        with tarfile.open(str(original), 'r:') as archive:
            members = [(entry, archive.extractfile(entry).read() if entry.isfile() else None)
                       for entry in archive]
        mutate(members)
        target = self.base / name
        with tarfile.open(str(target), 'w', format=tarfile.PAX_FORMAT) as archive:
            for entry, content in members:
                archive.addfile(entry, io.BytesIO(content) if content is not None else None)
        return target

    def test_legacy_umask_requires_explicit_policy_and_exact_group_write_modes(self):
        path, expected = self.legacy_archive()
        original = path.read_bytes()
        with tarfile.open(str(path), 'r:') as archive:
            self.assertEqual(archive.getmember('.clang-format').mode, 0o664)
            self.assertEqual(archive.getmember('scripts/run.sh').mode, 0o775)
            self.assertEqual(archive.getmember('scripts').mode, 0o775)
        with self.assertRaisesRegex(ValueError, 'archive mode differs from Git tree'):
            preparation.verify_archive(path, expected)
        result = preparation.verify_archive(path, expected, archive_umask='0002')
        self.assertEqual(result['status'], 'EXACT_GIT_BLOBS_VERIFIED')
        self.assertEqual(result['archive_umask'], '0002')
        self.assertEqual(result['mode_policy'], 'GIT_REGULAR_MODES_0664_OR_0775')
        self.assertEqual(result['regular_files'], len(expected))
        self.assertEqual(path.read_bytes(), original)

    def test_legacy_policy_does_not_accept_arbitrary_permissions(self):
        original, expected = self.legacy_archive()
        for index, (member, invalid_mode) in enumerate((('.clang-format', 0o644),
                ('.clang-format', 0o666), ('.clang-format', 0o764), ('.clang-format', 0o4664),
                ('scripts/run.sh', 0o755), ('scripts/run.sh', 0o777), ('scripts/run.sh', 0o4775))):
            def mutate(members, name=member, mode=invalid_mode):
                next(entry for entry, _ in members if entry.name == name).mode = mode
            path = self.mutate_small_archive(original, 'bad-mode-{}.tar'.format(index), mutate)
            with self.subTest(member=member, mode=oct(invalid_mode)):
                with self.assertRaisesRegex(ValueError, 'archive mode differs from Git tree'):
                    preparation.verify_archive(path, expected, archive_umask='0002')

    def test_legacy_mode_policy_never_washes_changed_same_size_blob_contents(self):
        original, expected = self.legacy_archive()
        def mutate(members):
            index = next(index for index, row in enumerate(members) if row[0].name == '.clang-format')
            entry, content = members[index]
            members[index] = (entry, b'x' * len(content))
        path = self.mutate_small_archive(original, 'bad-content.tar', mutate)
        with self.assertRaisesRegex(ValueError, 'archive content differs from Git blob'):
            preparation.verify_archive(path, expected, archive_umask='0002')

    def test_archive_umask_policy_is_canonical_and_limited_not_silently_coerced(self):
        for value in ('2', '002', '0002 ', '0000', '0077', 0o2, False, None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'archive_umask must explicitly'):
                preparation.verify_archive(self.base / 'not-opened.tar', {}, archive_umask=value)

    def test_legacy_directory_permissions_follow_the_same_explicit_policy(self):
        original, expected = self.legacy_archive()
        def mutate(members):
            next(entry for entry, _ in members if entry.name == 'scripts').mode = 0o777
        path = self.mutate_small_archive(original, 'bad-directory.tar', mutate)
        with self.assertRaisesRegex(ValueError, 'directory mode differs from declared archive_umask'):
            preparation.verify_archive(path, expected, archive_umask='0002')

    def test_unexpected_duplicate_nonregular_mode_size_and_content_are_rejected(self):
        real_run = subprocess.run

        def extra_regular(members):
            entry = tarfile.TarInfo('untracked-build-artifact')
            entry.mode, entry.size = 0o644, 1
            members.append((entry, b'x'))

        def duplicate(members):
            members.append(next(row for row in members if row[0].name == 'README.md'))

        def nonregular(members):
            entry = tarfile.TarInfo('unexpected-link')
            entry.type, entry.linkname = tarfile.SYMTYPE, 'README.md'
            members.append((entry, None))

        def unexpected_directory(members):
            entry = tarfile.TarInfo('untracked-directory')
            entry.type = tarfile.DIRTYPE
            members.append((entry, None))

        def wrong_mode(members):
            next(entry for entry, _ in members if entry.name == 'README.md').mode = 0o755

        def wrong_size(members):
            index = next(i for i, row in enumerate(members) if row[0].name == 'README.md')
            entry, content = members[index]
            entry.size += 1
            members[index] = (entry, content + b'x')

        def wrong_content(members):
            index = next(i for i, row in enumerate(members) if row[0].name == 'README.md')
            entry, content = members[index]
            members[index] = (entry, b'x' * len(content))

        for mutation, reason in (
                (extra_regular, 'unexpected archive regular file'),
                (duplicate, 'duplicate archive member'),
                (nonregular, 'unexpected nonregular archive member'),
                (unexpected_directory, 'unexpected archive directory'),
                (wrong_mode, 'archive mode differs from Git tree'),
                (wrong_size, 'archive size differs from Git blob'),
                (wrong_content, 'archive content differs from Git blob')):
            with self.subTest(mutation=mutation.__name__):
                output = self.base / mutation.__name__

                def intercept(command, *args, **kwargs):
                    result = real_run(command, *args, **kwargs)
                    if command[0] == 'git' and 'archive' in command:
                        archive_path = Path(next(value[len('--output='):] for value in command
                                                 if value.startswith('--output=')))
                        with tarfile.open(str(archive_path), 'r:') as archive:
                            members = [(entry, archive.extractfile(entry).read()
                                        if entry.isfile() else None) for entry in archive]
                        mutation(members)
                        with tarfile.open(str(archive_path), 'w', format=tarfile.PAX_FORMAT) as archive:
                            for entry, content in members:
                                archive.addfile(entry, io.BytesIO(content) if content is not None else None)
                    return result

                with patch.object(preparation.subprocess, 'run', side_effect=intercept):
                    with self.assertRaisesRegex(ValueError, reason):
                        preparation.prepare(self.repository, self.commit, output)
                self.assertTrue((output / 'source.tar').is_file())
                self.assertFalse((output / 'source.json').exists())


if __name__ == '__main__':
    unittest.main()
