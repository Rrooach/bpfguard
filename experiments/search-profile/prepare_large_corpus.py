#!/usr/bin/env python3
"""Archive immutable tracked regular source files, never a dirty working tree."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile


def verify_archive(archive, expected, archive_umask='0022'):
    """Verify exported bytes, not merely Git's pre-export tree declaration.

    export-ignore can remove tracked files and export-subst can replace blob
    contents. Neither is compatible with an exact fixed-commit corpus. No
    extraction is needed; member contents are hashed in bounded chunks.

    The default matches new prepare() exports. Legacy tar.umask=0002 exports
    must opt in explicitly; that changes exact expected permission bits, never
    the required member set, lengths, or Git blob object IDs.
    """
    policies = {'0022': {'100644': 0o644, '100755': 0o755, 'directory': 0o755},
                '0002': {'100644': 0o664, '100755': 0o775, 'directory': 0o775}}
    if not isinstance(archive_umask, str) or archive_umask not in policies:
        raise ValueError('archive_umask must explicitly be canonical 0022 or 0002')
    modes = policies[archive_umask]
    directories = set()
    for name in expected:
        directories.update(str(parent) for parent in PurePosixPath(name).parents
                           if str(parent) != '.')
    seen, regular, algorithms, size = set(), set(), set(), 0
    try:
        with tarfile.open(str(archive), 'r|') as source:
            for member in source:
                name = member.name
                path = PurePosixPath(name)
                if (not name or path.is_absolute() or '..' in path.parts or
                        path.as_posix() != name or name == '.'):
                    raise ValueError('noncanonical archive member: ' + repr(name))
                if name in seen:
                    raise ValueError('duplicate archive member: ' + repr(name))
                seen.add(name)
                if member.isdir():
                    if name not in directories or member.size != 0:
                        raise ValueError('unexpected archive directory: ' + repr(name))
                    if member.mode != modes['directory']:
                        raise ValueError('archive directory mode differs from declared archive_umask: ' + repr(name))
                    continue
                if not member.isfile() or member.sparse is not None:
                    raise ValueError('unexpected nonregular archive member: ' + repr(name))
                if name not in expected:
                    raise ValueError('unexpected archive regular file: ' + repr(name))
                declaration = expected[name]
                if declaration.get('mode') not in ('100644', '100755'):
                    raise ValueError('unsupported Git regular file mode: ' + repr(name))
                if member.mode != modes[declaration['mode']]:
                    raise ValueError('archive mode differs from Git tree/archive_umask policy: ' + repr(name))
                if member.size != declaration['size']:
                    raise ValueError('archive size differs from Git blob: ' + repr(name))
                oid = declaration['object']
                if len(oid) not in (40, 64):
                    raise ValueError('unsupported Git object hash length')
                algorithm = 'sha1' if len(oid) == 40 else 'sha256'
                digest = hashlib.new(algorithm)
                digest.update(b'blob ' + str(member.size).encode('ascii') + b'\0')
                with source.extractfile(member) as contents:
                    for block in iter(lambda: contents.read(1024 * 1024), b''):
                        digest.update(block)
                if digest.hexdigest() != oid:
                    raise ValueError('archive content differs from Git blob: ' + repr(name))
                algorithms.add(algorithm)
                regular.add(name)
                size += member.size
    except tarfile.TarError as error:
        raise ValueError('invalid exported source archive: ' + str(error)) from error
    missing = set(expected) - regular
    if missing:
        raise ValueError('archive omits tracked regular files: ' + repr(sorted(missing)[:10]))
    return {'status': 'EXACT_GIT_BLOBS_VERIFIED', 'regular_files': len(regular),
            'regular_file_bytes': size, 'git_object_hash_algorithms': sorted(algorithms),
            'mode_policy': ('GIT_REGULAR_MODES_0644_OR_0755' if archive_umask == '0022'
                            else 'GIT_REGULAR_MODES_0664_OR_0775'),
            'archive_umask': archive_umask}


def prepare(repository, revision, output):
    repository = Path(repository).resolve(strict=True)
    output = Path(output).absolute()
    output.mkdir(mode=0o700)
    commit = subprocess.check_output(['git', '-C', str(repository), 'rev-parse', revision + '^{commit}'], text=True).strip()
    raw = subprocess.check_output(['git', '-C', str(repository), 'ls-tree', '-rzl', commit])
    exclusions, expected, count, size = [], {}, 0, 0
    for entry in raw.rstrip(b'\0').split(b'\0'):
        header, path = entry.split(b'\t', 1)
        mode, kind, oid, length = header.decode().split()
        name = path.decode()
        if mode not in ('100644', '100755') or kind != 'blob':
            exclusions.append({'path': name, 'mode': mode, 'object': oid})
        else:
            expected[name] = {'mode': mode, 'object': oid, 'size': int(length)}
            count += 1
            size += int(length)
    archive = output / 'source.tar'
    command = ['git', '-c', 'tar.umask=0022', '-C', str(repository), 'archive',
               '--format=tar', '--output=' + str(archive), commit, '--', '.']
    command.extend(':(exclude)' + row['path'] for row in exclusions)
    subprocess.run(command, check=True)
    validation = verify_archive(archive, expected)
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    manifest = {'schema_version': 1, 'repository': str(repository), 'commit': commit,
        'regular_files': count, 'regular_file_bytes': size, 'excluded_nonregular_entries': exclusions,
        'archive_sha256': digest.hexdigest(), 'archive_bytes': archive.stat().st_size,
        'archive_validation': validation,
        'source': 'GIT_OBJECT_DATABASE_NOT_WORKTREE',
        'scope': 'All tracked regular files at the commit; symlinks/submodules explicitly excluded; no build artifacts or .git'}
    with (output / 'source.json').open('x') as stream:
        json.dump(manifest, stream, indent=2)
        stream.write('\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True, type=Path)
    parser.add_argument('--revision', default='HEAD')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.repository, args.revision, args.output)))


if __name__ == '__main__':
    main()
