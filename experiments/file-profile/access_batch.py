#!/usr/bin/env python3
"""Post-campaign parallel file-access conversion. Never run in timed windows.

Each case has a fresh output. Progress is append-only; resume checks source,
raw and output hashes instead of treating an existing directory as success.
"""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import tempfile
import time
import uuid


SPEC = importlib.util.spec_from_file_location('access_batch_analyzer', Path(__file__).with_name('access_analyze.py'))
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)
ARTIFACT_SPEC = importlib.util.spec_from_file_location('access_batch_artifact_storage',
    Path(__file__).with_name('access_artifacts.py'))
ARTIFACTS = importlib.util.module_from_spec(ARTIFACT_SPEC)
ARTIFACT_SPEC.loader.exec_module(ARTIFACTS)
SMALL_INPUTS = {'capture': 'capture.json', 'collector_meta': 'file-access/meta.json',
    'collector_final': 'file-access/final.json'}


def contained(root, value):
    relative = Path(value)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('relative descendant input path required')
    path = root / relative
    path.resolve(strict=True).relative_to(root.resolve(strict=True))
    return path


def small_sources(root, profile_path):
    inputs = {key: ANALYZER.json_input(root / relative) for key, relative in SMALL_INPUTS.items()}
    inputs['profile_run'] = ANALYZER.json_input(profile_path)
    return {key: row[0] for key, row in inputs.items()}, {key: row[1] for key, row in inputs.items()}


def plan_batch(matrix_path, inventory_path, expected_inventory_sha256, limit=None, archive_settings=None):
    matrix_path, inventory_path = Path(matrix_path).resolve(), Path(inventory_path).resolve()
    matrix, matrix_source = ANALYZER.json_input(matrix_path)
    if (matrix.get('schema_version') != 1 or matrix.get('status') != 'COMPLETE'
            or not isinstance(matrix.get('boot_id'), str) or not matrix['boot_id']
            or not isinstance(matrix.get('campaigns'), list) or not isinstance(matrix.get('schedule'), list)
            or len(matrix['campaigns']) != len(matrix['schedule'])):
        raise ValueError('complete supported access-search matrix and schedule required')
    inventory_source, inventory_manifest = ANALYZER.inventory_index_manifest(inventory_path, matrix['boot_id'])
    if inventory_source['sha256'] != expected_inventory_sha256:
        raise ValueError('post-final inventory index digest mismatch')
    cases, omitted, seen, run_ids, last_end = [], [], set(), set(), 0
    budget = matrix.get('collector_budget', {})
    for row, scheduled in zip(matrix['campaigns'], matrix['schedule']):
        case_id = row.get('path')
        if (not isinstance(case_id, str) or len(Path(case_id).parts) != 1 or case_id in seen
                or not isinstance(row.get('condition'), dict) or row.get('block') != scheduled.get('block')
                or any(row['condition'].get(key) != value for key, value in scheduled.items() if key != 'block')):
            raise ValueError('case identity, order or declared schedule mismatch')
        seen.add(case_id)
        root = contained(matrix_path.parent, case_id)
        capture, _ = ANALYZER.json_input(root / 'capture.json')
        profile_path = contained(root, capture.get('profile_path', ''))
        profile, profile_source = ANALYZER.json_input(profile_path)
        if profile.get('boot_id') != matrix['boot_id'] or profile.get('status') != 'COMPLETE':
            raise ValueError('profile boot or completion differs from matrix')
        if profile.get('run_id') in run_ids:
            raise ValueError('a run identity was reused by two matrix cases')
        run_ids.add(profile.get('run_id'))
        if not ANALYZER.integer(profile.get('end_ns')):
            raise ValueError('profile end timestamp missing')
        last_end = max(last_end, profile['end_ns'])
        condition = row['condition']
        if any(profile.get('config', {}).get(key) != value for key, value in condition.items()):
            raise ValueError('raw execution configuration differs from scheduled condition')
        if condition.get('file_access_mode') == 'sampler':
            omitted.append(case_id)
            continue
        if condition.get('file_access_mode') != 'access':
            raise ValueError('unsupported file-access measurement mode')
        inputs, sources = small_sources(root, profile_path)
        meta, final = inputs['collector_meta'], inputs['collector_final']
        ANALYZER.bind_collector(meta, final, inputs['profile_run'], sources['profile_run'], inputs['capture'])
        if (capture.get('final_sha256') != sources['collector_final']['sha256']
                or meta.get('backend') != condition.get('file_access_backend')
                or meta.get('backend') != matrix.get('file_access_backend')
                or meta.get('ring_bytes') != condition.get('collector_ring_bytes')
                or meta.get('ring_bytes') != budget.get('ring_bytes')
                or meta.get('max_bytes') != budget.get('max_bytes')
                or capture.get('capture_budget') != budget):
            raise ValueError('matrix/capture/collector backend, budget or final binding differs')
        raw_path = ANALYZER.regular(root / 'file-access/events.bin', ANALYZER.MAX_TRACE_BYTES)
        cases.append({'case_id': case_id, 'root': str(root), 'profile_path': str(profile_path),
            'sources': sources, 'raw': {'path': str(raw_path), 'bytes': raw_path.stat().st_size,
                'sha256': final.get('events_sha256')}, 'condition': condition})
    post_sources = []
    # This one-time read is deliberately AFTER all timing. It prevents a
    # same-boot preflight receipt from masquerading as formal post-verification.
    for source in inventory_manifest['sources']:
        value, actual = ANALYZER.json_input(source['path'])
        post = value.get('post_verification', {})
        if (actual['sha256'] != source['sha256'] or value.get('boot_id') != matrix['boot_id']
                or value.get('pre_post_identical') is not True or value.get('read_only') is not True
                or post.get('status') != 'IDENTICAL_READONLY_METADATA_WITHIN_DECLARED_SCOPE'
                or not ANALYZER.integer(post.get('started_ns')) or not ANALYZER.integer(post.get('ended_ns'))
                or not last_end <= post['started_ns'] <= post['ended_ns']):
            raise ValueError('inventory lacks a matching verification AFTER the full campaign')
        post_sources.append(actual)
    if not post_sources:
        raise ValueError('post-final inventory evidence is missing')
    if limit is not None and (not ANALYZER.integer(limit, True) or limit > len(cases)):
        raise ValueError('limit must select a nonempty prefix of full-detail cases')
    plan = {'schema_version': 1, 'purpose': 'POST_CAMPAIGN_OFFLINE_CONVERSION_ONLY',
        'matrix': matrix_source, 'inventory_database': inventory_source,
        'inventory_post_sources': post_sources, 'full_campaign_last_end_ns': last_end,
        'analyzer_sha256': hashlib.sha256(Path(ANALYZER.__file__).read_bytes()).hexdigest(),
        'available_full_detail_cases': len(cases), 'selected_prefix_limit': limit,
        'omitted_sampler_cases': omitted, 'cases': cases if limit is None else cases[:limit]}
    if archive_settings is not None:
        plan.update(schema_version=2, artifact_storage=validate_archive_settings(archive_settings))
    return plan


def validate_archive_settings(value):
    if (not isinstance(value, dict) or value.get('codec') != 'gzip'
            or not ANALYZER.integer(value.get('scratch_per_case_bytes'), True, maximum=ARTIFACTS.MAX_BYTES)
            or not ANALYZER.integer(value.get('min_output_free_bytes'), maximum=ARTIFACTS.MAX_BYTES)):
        raise ValueError('explicit supported gzip codec and bounded scratch/output budgets required')
    root = Path(value.get('scratch_root', '')).absolute()
    if (root.resolve(strict=True) != root or not root.is_dir()
            or root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077):
        raise ValueError('existing private owned canonical scratch root required (mode 0700)')
    expected_module = hashlib.sha256(Path(ARTIFACTS.__file__).read_bytes()).hexdigest()
    if value.get('artifact_module_sha256', expected_module) != expected_module:
        raise ValueError('artifact storage implementation differs from the batch plan')
    return {'schema_version': 1, 'codec': 'gzip', 'scratch_root': str(root),
        'scratch_per_case_bytes': value['scratch_per_case_bytes'],
        'min_output_free_bytes': value['min_output_free_bytes'],
        'artifact_module_sha256': expected_module,
        'limits_scope': 'WORKER_ADMISSION_RESERVATION_AND_PER_FILE_RLIMIT; NOT_A_FILESYSTEM_TOTAL_QUOTA',
        'scratch_cleanup': 'ONLY_OWN_SUCCESSFULLY_ARCHIVED_AND_INDEPENDENTLY_VERIFIED_CASE_SUBDIRECTORIES'}


def archive_preflight(settings, workers, output):
    settings = validate_archive_settings(settings)
    scratch, output = Path(settings['scratch_root']), Path(output).absolute()
    if scratch == output or scratch in output.parents or output in scratch.parents:
        raise ValueError('scratch and persistent output must not overlap')
    requested = workers * settings['scratch_per_case_bytes']
    if shutil.disk_usage(str(scratch)).free < requested:
        raise ValueError('scratch free space below workers times explicit per-case reservation')
    # /dev/shm capacity is not physical memory availability. Treat every
    # scratch reservation conservatively as RAM even on a disk-backed path.
    meminfo = Path('/proc/meminfo').read_text().splitlines()
    available = next((int(line.split()[1]) * 1024 for line in meminfo if line.startswith('MemAvailable:')), None)
    if available is None or available < requested + 1024 ** 3:
        raise ValueError('MemAvailable below bounded scratch reservation plus 1GiB safety margin')
    parent = output
    while not parent.exists():
        parent = parent.parent
    if shutil.disk_usage(str(parent)).free < settings['min_output_free_bytes']:
        raise ValueError('persistent output free space below explicit reserve')
    return settings


def verify_inputs(case):
    _, sources = small_sources(Path(case['root']), Path(case['profile_path']))
    if sources != case['sources']:
        raise ValueError('case input metadata changed after batch plan')


def artifact_digest(path):
    # Keep the analyzer's small index-verification cache for inventory indexes,
    # rather than evicting it with five fresh output artifacts per case.
    path = ANALYZER.regular(path, 64 * 1024 ** 3)
    before, digest = path.stat(), hashlib.sha256()
    with path.open('rb') as stream:
        while True:
            chunk = stream.read(1024 ** 2)
            if not chunk:
                break
            digest.update(chunk)
    after = path.stat()
    if any(getattr(before, key) != getattr(after, key) for key in
            ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
        raise ValueError('artifact changed while hashing')
    return {'path': str(path), 'bytes': after.st_size, 'sha256': digest.hexdigest()}


def analyze_case(case, output, inventory, inventory_sha256):
    verify_inputs(case)
    start, cpu_start = time.monotonic(), time.process_time()
    summary = ANALYZER.analyze(Path(case['root']) / 'file-access', case['profile_path'], output,
        inventory_database=inventory, expected_inventory_sha256=inventory_sha256)
    verify_inputs(case)
    artifacts = {name: artifact_digest(Path(output) / name) for name in
        ('summary.json', 'events.sqlite', 'per-file.csv', 'read-samples.csv', 'source-read-samples.csv')}
    return {'case_id': case['case_id'], 'output': str(output), 'analysis_status': summary['status'],
        'issues': summary['issues'], 'sources': case['sources'], 'raw': summary['raw_events'],
        'artifacts': artifacts, 'elapsed_seconds': time.monotonic() - start,
        'process_cpu_seconds': time.process_time() - cpu_start,
        'worker_lifetime_max_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'rss_scope': 'PROCESS_LIFETIME_HIGH_WATER_NOT_PER_CASE_STEADY_MEMORY',
        'observed_metrics': {key: summary['metrics'].get(key) for key in
            ('source_unique_regular_files_read_attempted', 'source_read_calls', 'source_read_returned_bytes',
             'read_calls', 'mm_fault_attempts', 'filemap_fault_attempts')}}


def analyze_archived_case(case, output, inventory, inventory_sha256, settings, worker=analyze_case):
    """Archive only freshly generated derived artifacts; never remove raw input."""
    settings = archive_preflight(settings, 1, output)
    output = Path(output).absolute()
    output.mkdir(parents=True)
    scratch = Path(tempfile.mkdtemp(prefix='access-' + uuid.uuid4().hex + '-', dir=settings['scratch_root']))
    identity = scratch.stat()
    payload, temporary = scratch / 'analysis', scratch / 'sqlite-tmp'
    temporary.mkdir(mode=0o700)
    env = {name: os.environ.get(name) for name in ('TMPDIR', 'SQLITE_TMPDIR')}
    previous_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
    previous_signal = signal.getsignal(signal.SIGXFSZ)
    limit = settings['scratch_per_case_bytes']
    if previous_limit[0] != resource.RLIM_INFINITY:
        limit = min(limit, previous_limit[0])
    started, cpu_start = time.monotonic(), time.process_time()
    try:
        os.environ.update(TMPDIR=str(temporary), SQLITE_TMPDIR=str(temporary))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, previous_limit[1]))
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        result = worker(case, payload, inventory, inventory_sha256)
        # A single-file rlimit and an admission reservation are not advertised
        # as a filesystem quota; enforce the measured case footprint as well.
        footprint = sum(p.stat().st_size for p in scratch.rglob('*') if p.is_file())
        if footprint > settings['scratch_per_case_bytes']:
            raise ValueError('derived case footprint exceeds explicit scratch reservation')
        archived = {}
        for name in sorted(ARTIFACTS.ARTIFACT_NAMES):
            source = payload / name
            old = result['artifacts'][name]
            if name in ARTIFACTS.ARCHIVED_NAMES:
                saved = ARTIFACTS.store_gzip(source, output, name, limit, limit,
                                            settings['min_output_free_bytes'])
            else:
                if shutil.disk_usage(str(output)).free < settings['min_output_free_bytes'] + source.stat().st_size:
                    raise ValueError('persistent output reserve exhausted before small artifact copy')
                with source.open('rb') as src, (output / name).open('xb') as dst:
                    shutil.copyfileobj(src, dst, 64 * 1024)
                    dst.flush()
                    os.fsync(dst.fileno())
                saved = ARTIFACTS.digest_file(output / name, limit)
                ARTIFACTS.verify_artifact(saved, output, name, limit, limit)
            if saved['bytes'] != old['bytes'] or saved['sha256'] != old['sha256']:
                raise ValueError('lossless archived artifact differs from analyzer bytes: ' + name)
            archived[name] = saved
        verify_inputs(case)
        # Validate the exact mkdtemp target before deleting only these temporary
        # derived copies. Failure at any preceding step retains the scratch.
        current = scratch.lstat()
        if (scratch.is_symlink() or (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)
                or scratch.parent != Path(settings['scratch_root'])):
            raise ValueError('owned scratch identity changed; refusing cleanup')
        shutil.rmtree(str(scratch))
        result.update(output=str(output), artifacts=archived, artifact_storage_schema=2,
            artifact_storage=settings, producer_output=str(payload),
            summary_path_semantics='ANALYZER_BYTES_PRESERVED; EMBEDDED_SAMPLE_PATHS_NAME_PRODUCER_SCRATCH; RECEIPT_STORAGE_PATHS_ARE_AUTHORITATIVE',
            scratch={'path': str(scratch), 'status': 'OWN_DERIVED_COPIES_REMOVED_AFTER_ARCHIVE_AND_DECOMPRESSED_VERIFICATION',
                     'observed_footprint_bytes': footprint},
            elapsed_seconds=time.monotonic() - started,
            process_cpu_seconds=time.process_time() - cpu_start)
        return result
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, previous_limit)
        signal.signal(signal.SIGXFSZ, previous_signal)
        for name, old in env.items():
            if old is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old


def verify_completed(case, receipt, inventory_sha256, output_root=None, analyzer_sha256=None):
    try:
        verify_inputs(case)
        if receipt.get('sources') != case['sources']:
            return False, 'SAVED_SOURCE_BINDINGS_DIFFER'
        output = Path(receipt['output'])
        if output_root is not None:
            output.resolve(strict=True).relative_to(Path(output_root).resolve(strict=True))
        expected_artifacts = {'summary.json', 'events.sqlite', 'per-file.csv', 'read-samples.csv', 'source-read-samples.csv'}
        if (receipt.get('case_id') != case['case_id'] or not isinstance(receipt.get('artifacts'), dict)
                or set(receipt['artifacts']) != expected_artifacts):
            return False, 'SAVED_RECEIPT_IDENTITY_OR_ARTIFACT_SET_DIFFER'
        archived = receipt.get('artifact_storage_schema') == 2
        if archived:
            settings = validate_archive_settings(receipt.get('artifact_storage'))
            for name, old in receipt['artifacts'].items():
                proof = ARTIFACTS.verify_artifact(old, output, name, settings['scratch_per_case_bytes'],
                                                 settings['scratch_per_case_bytes'])
                if 'storage' in old and old.get('verification') != proof:
                    return False, 'SAVED_ARCHIVE_VERIFICATION_DIFFERS:' + name
        else:
            if 'artifact_storage_schema' in receipt or any('storage' in a for a in receipt['artifacts'].values()):
                return False, 'UNSUPPORTED_OR_UNDECLARED_ARTIFACT_STORAGE_SCHEMA'
            for name, old in receipt['artifacts'].items():
                actual = artifact_digest(output / name)
                if actual['sha256'] != old['sha256'] or actual['bytes'] != old['bytes']:
                    return False, 'SAVED_ARTIFACT_CHANGED:' + name
        summary, _ = ANALYZER.json_input(output / 'summary.json')
        if (summary.get('sources', {}).get('inventory_database', {}).get('sha256') != inventory_sha256
                or any(summary.get('sources', {}).get(key) != value for key, value in case['sources'].items())
                or summary.get('status') != receipt.get('analysis_status')
                or summary.get('status') not in ('COMPLETE_FOR_SELECTED_HOOKS', 'INCOMPLETE')
                or analyzer_sha256 is not None and summary.get('analyzer', {}).get('sha256') != analyzer_sha256):
            return False, 'SAVED_SUMMARY_BINDINGS_DIFFER'
        actual = artifact_digest(Path(case['raw']['path']))
        if actual['sha256'] != receipt.get('raw', {}).get('sha256') or actual['bytes'] != receipt['raw'].get('bytes'):
            return False, 'SAVED_RAW_SOURCE_CHANGED'
        if (summary.get('raw_events', {}).get('sha256') != actual['sha256']
                or summary.get('raw_events', {}).get('bytes') != actual['bytes']):
            return False, 'SAVED_SUMMARY_RAW_BINDING_DIFFERS'
        return True, None
    except (OSError, ValueError, KeyError, TypeError) as error:
        return False, type(error).__name__ + ':' + str(error)


def journal_append(stream, value):
    stream.write(json.dumps(value, sort_keys=True) + '\n')
    stream.flush()
    os.fsync(stream.fileno())


def journal_completed(path):
    found = {}
    if not path.exists():
        return found
    with ANALYZER.regular(path, 64 * 1024 ** 2).open() as stream:
        for number, line in enumerate(stream, 1):
            if len(line) > 2 * 1024 ** 2:
                raise ValueError('progress journal record too large')
            try:
                row = json.loads(line)
            except ValueError as error:
                raise ValueError('invalid progress journal line %d; preserve and inspect it' % number) from error
            if row.get('event') == 'RESULT':
                found[row['case_id']] = row['receipt']
    return found


def run_batch(plan, output, workers=2, resume=False, worker=analyze_case):
    started = time.monotonic()
    if not ANALYZER.integer(workers, True, maximum=8):
        raise ValueError('workers must be explicitly 1..8')
    output = Path(output).absolute()
    settings = None
    if 'artifact_storage' in plan:
        if type(plan.get('schema_version')) is not int or plan['schema_version'] != 2:
            raise ValueError('archive storage requires explicit batch plan schema 2')
        settings = archive_preflight(plan['artifact_storage'], workers, output)
    if resume:
        if output.is_symlink() or not output.is_dir():
            raise ValueError('resume requires existing owned output directory')
        old, _ = ANALYZER.json_input(output / 'plan.json')
        if old != plan:
            raise ValueError('resume plan/source/analyzer bindings differ; use a fresh output directory')
    else:
        output.mkdir(parents=True)
        ANALYZER.write_json(output / 'plan.json', plan)
    with (output / '.batch.lock').open('a+') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('another batch owns this output') from error
        completed = journal_completed(output / 'progress.jsonl')
        attempt = uuid.uuid4().hex
        results, failures, pending, skipped = {}, {}, [], []
        with (output / 'progress.jsonl').open('a', encoding='utf-8') as journal:
            journal_append(journal, {'event': 'ATTEMPT', 'attempt': attempt, 'workers': workers,
                'resume': resume, 'monotonic_ns': time.monotonic_ns()})
            for case in plan['cases']:
                case_id = case['case_id']
                previous = completed.get(case_id)
                if previous is not None:
                    if ((settings is not None and (previous.get('artifact_storage_schema') != 2
                            or previous.get('artifact_storage') != settings))
                            or (settings is None and 'artifact_storage_schema' in previous)):
                        valid, reason = False, 'SAVED_ARTIFACT_STORAGE_PLAN_DIFFERS'
                    else:
                        valid, reason = verify_completed(case, previous, plan['inventory_database']['sha256'],
                            output, plan['analyzer_sha256'])
                    if valid:
                        results[case_id] = previous
                        skipped.append(case_id)
                        journal_append(journal, {'event': 'RESUME_VERIFIED', 'case_id': case_id, 'attempt': attempt})
                        continue
                    journal_append(journal, {'event': 'RESUME_REJECTED', 'case_id': case_id, 'reason': reason, 'attempt': attempt})
                target = output / case_id
                if target.exists():
                    target = output / 'retries' / (case_id + '-' + attempt)
                pending.append((case, target))

            def accept(case, target, future=None):
                try:
                    receipt = worker(case, target, plan['inventory_database']['path'], plan['inventory_database']['sha256']) if future is None else future.result()
                    results[case['case_id']] = receipt
                    journal_append(journal, {'event': 'RESULT', 'attempt': attempt, 'case_id': case['case_id'], 'receipt': receipt})
                except Exception as error:
                    failure = {'case_id': case['case_id'], 'output': str(target),
                        'error': type(error).__name__ + ':' + str(error), 'attempt': attempt}
                    failures[case['case_id']] = failure
                    journal_append(journal, {'event': 'FAILED', **failure})

            if workers == 1:
                for case, target in pending:
                    journal_append(journal, {'event': 'START', 'case_id': case['case_id'], 'output': str(target), 'attempt': attempt})
                    if settings is None:
                        accept(case, target)
                    else:
                        from concurrent.futures import Future
                        result = Future()
                        try:
                            result.set_result(analyze_archived_case(case, target, plan['inventory_database']['path'],
                                plan['inventory_database']['sha256'], settings, worker))
                        except Exception as error:
                            result.set_exception(error)
                        accept(case, target, result)
            else:
                with ProcessPoolExecutor(max_workers=workers) as pool:
                    futures = {}
                    for case, target in pending:
                        journal_append(journal, {'event': 'SUBMITTED', 'case_id': case['case_id'], 'output': str(target), 'attempt': attempt})
                        if settings is None:
                            future = pool.submit(worker, case, target, plan['inventory_database']['path'], plan['inventory_database']['sha256'])
                        else:
                            future = pool.submit(analyze_archived_case, case, target, plan['inventory_database']['path'],
                                plan['inventory_database']['sha256'], settings, worker)
                        futures[future] = (case, target)
                    for future in as_completed(futures):
                        case, target = futures[future]
                        accept(case, target, future)
            receipt = {'schema_version': 1, 'attempt': attempt, 'workers': workers,
                'batch_elapsed_seconds': time.monotonic() - started,
                'elapsed_scope': 'SELECTED_CASES_PLUS_POOL_STARTUP_OUTPUT_HASHES_AND_RESUME_VERIFICATION; PLAN_PREPARATION_SEPARATE',
                'status': 'COMPLETE_FOR_SELECTED_CASES' if not failures and len(results) == len(plan['cases'])
                    and all(row['analysis_status'] == 'COMPLETE_FOR_SELECTED_HOOKS' for row in results.values()) else 'INCOMPLETE',
                'selected_cases': len(plan['cases']), 'available_full_detail_cases': plan['available_full_detail_cases'],
                'selected_prefix_limit': plan['selected_prefix_limit'], 'resume_verified_cases': skipped,
                'results': results, 'failures': failures,
                'scope': 'OFFLINE_SELECTED_CASE_CONVERSION; NOT_A_NEW_WORKLOAD_EXPERIMENT_OR_AUTHENTICATED_VERDICT'}
            if settings is not None:
                receipt.update(schema_version=2, artifact_storage=settings)
            ANALYZER.write_json(output / ('attempt-' + attempt + '.json'), receipt)
            journal_append(journal, {'event': 'ATTEMPT_FINISHED', 'attempt': attempt, 'status': receipt['status']})
            return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', type=Path, required=True)
    parser.add_argument('--inventory-database', type=Path, required=True)
    parser.add_argument('--expected-inventory-sha256', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--limit', type=int, help='Analyze a prefix for worker-count calibration; explicitly marked as a subset')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--archive-codec', choices=('gzip',), help='Explicit lossless archive mode; default remains plain schema 1')
    parser.add_argument('--scratch-root', type=Path, help='Existing private owned 0700 per-campaign temporary directory')
    parser.add_argument('--scratch-per-case-bytes', type=int, default=8 * 1024 ** 3,
                        help='Admission reservation, measured per-case footprint and per-file RLIMIT; not a filesystem quota')
    parser.add_argument('--min-output-free-bytes', type=int, default=8 * 1024 ** 3)
    args = parser.parse_args()
    if bool(args.archive_codec) != bool(args.scratch_root):
        parser.error('--archive-codec and --scratch-root must be selected together')
    settings = None if args.archive_codec is None else {'codec': args.archive_codec,
        'scratch_root': str(args.scratch_root.absolute()), 'scratch_per_case_bytes': args.scratch_per_case_bytes,
        'min_output_free_bytes': args.min_output_free_bytes}
    plan = plan_batch(args.matrix, args.inventory_database, args.expected_inventory_sha256, args.limit, settings)
    receipt = run_batch(plan, args.output_dir, args.workers, args.resume)
    print(json.dumps({'status': receipt['status'], 'cases': receipt['selected_cases'], 'failures': receipt['failures'],
        'attempt': receipt['attempt'], 'output': str(args.output_dir)}))


if __name__ == '__main__':
    main()
