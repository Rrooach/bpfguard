#!/usr/bin/env python3
"""Owned-Guest fixed-work 2/4/6/8 searches, paired file-access observation.

The existing run.py lifecycle is reused unchanged. Each access collector binds
an otherwise empty parent cgroup before run_trial creates stopped workers in a
child. All raw events are preserved; offline analysis must select release/end.
"""
import argparse
import gc
import itertools
import json
import os
from pathlib import Path
import random
import select
import signal
import subprocess
import time
import uuid

import cache_probe
import large_search
import run as runner


MODES = ('sampler', 'access')


def update_owned_json(path, value):
    """Atomically replace only a file in this freshly created campaign."""
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.tmp')
    runner.dump(temporary, value)
    os.replace(str(temporary), str(path))


def schedule(repetitions, seed, concurrencies=(2, 4, 6, 8),
             caches=('warm', 'guest-cold'), layouts=('shared', 'independent'), modes=MODES):
    """A complete independent randomized block, not old/new campaign pooling."""
    rng, rows = random.Random(seed), []
    for block in range(repetitions):
        current = [dict(cache=c, workspace_layout=w, concurrency=n,
                        file_access_mode=m, block=block, warmup=False, intervention='none')
                   for c, w, n, m in itertools.product(caches, layouts, concurrencies, modes)]
        rng.shuffle(current)
        rows.extend(current)
    return rows


def bounded_list(value, allowed, name):
    values = value.split(',')
    if not values or len(values) != len(set(values)) or not set(values) <= set(allowed):
        raise ValueError('unique supported ' + name + ' required')
    return values


def participating_roots(corpus, independent_roots, layouts):
    """Hash only input roots actually read by this campaign, once each."""
    roots = ([corpus] if 'shared' in layouts else [])
    if 'independent' in layouts:
        roots.extend(independent_roots)
    return list(dict.fromkeys(roots))


def valid_ring_bytes(value):
    return type(value) is int and 16 * 1024 ** 2 <= value <= 512 * 1024 ** 2 and not value & (value - 1)


def read_ready(process, timeout=45):
    deadline, data = time.monotonic() + timeout, bytearray()
    while b'\n' not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or len(data) > 65536:
            raise RuntimeError('file-access READY timed out or exceeded bound')
        readable, _, _ = select.select([process.stdout], [], [], min(remaining, .2))
        if readable:
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError('file-access exited before READY')
            data.extend(chunk)
        elif process.poll() is not None:
            raise RuntimeError('file-access exited before READY')
    first, _, trailing = bytes(data).partition(b'\n')
    if trailing.strip():
        raise RuntimeError('unexpected data after file-access READY')
    row = json.loads(first)
    if not isinstance(row, dict) or row.get('type') != 'READY':
        raise RuntimeError('file-access did not acknowledge READY')
    return row


def validate_ready(row, run_id, boot_id, object_sha256, group, backend='fentry', ring_bytes=64 * 1024 ** 2):
    if (row.get('run_id') != run_id or row.get('boot_id') != boot_id
            or row.get('bpf_sha256') != object_sha256 or row.get('backend') != backend
            or row.get('ring_bytes') != ring_bytes
            or type(row.get('start_monotonic_ns')) is not int or row['start_monotonic_ns'] <= 0):
        raise RuntimeError('file-access READY run/boot/object/time binding differs')
    domains = row.get('domains')
    if not isinstance(domains, list) or len(domains) != 1 or not isinstance(domains[0], dict):
        raise RuntimeError('file-access READY lacks the single registered cgroup')
    actual = domains[0]
    if any(actual.get(key) != group[key] for key in ('path', 'inode', 'device')):
        raise RuntimeError('file-access READY cgroup identity differs')


class Collector:
    def __init__(self, args, output, cgroup, run_id, boot_id):
        self.args, self.output, self.cgroup = args, Path(output), cgroup
        self.run_id, self.boot_id = run_id, boot_id
        self.process, self.stderr, self.receipt = None, None, {
            'schema_version': 1, 'status': 'NOT_STARTED', 'run_id': run_id,
            'collector_run_id': run_id, 'boot_id': boot_id, 'cgroup': cgroup,
            'collector_cgroup': cgroup,
            'binary_sha256': args.file_access_sha256,
            'bpf_sha256': args.file_access_object_sha256,
            'file_access_backend': args.file_access_backend,
            'collector_ring_bytes': args.collector_ring_bytes,
            'capture_budget': {'ring_bytes': args.collector_ring_bytes,
                'max_bytes': args.collector_max_bytes, 'max_seconds': args.collector_timeout_seconds},
            'scope': 'REGISTERED_PARENT_AND_DESCENDANTS; OFFLINE_RELEASE_END_CROP_REQUIRED',
            'cpu_affinity': sorted(os.sched_getaffinity(0)), 'issues': []}

    def start(self):
        self.stderr = self.output.with_name(self.output.name + '.stderr').open('xb')
        command = [str(self.args.file_access), '--cgroup', self.cgroup['path'],
            '--output-dir', str(self.output), '--bpf-object', str(self.args.file_access_object),
            '--bpf-sha256', self.args.file_access_object_sha256, '--run-id', self.run_id,
            '--backend', self.args.file_access_backend,
            '--ring-bytes', str(self.args.collector_ring_bytes),
            '--mode', 'events', '--max-seconds', str(self.args.collector_timeout_seconds),
            '--max-bytes', str(self.args.collector_max_bytes)]
        self.receipt.update(command=command, started_monotonic_ns=time.monotonic_ns())
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=self.stderr,
            start_new_session=True)
        row = read_ready(self.process)
        validate_ready(row, self.run_id, self.boot_id, self.args.file_access_object_sha256,
                       self.cgroup, self.args.file_access_backend, self.args.collector_ring_bytes)
        self.receipt.update(status='RECORDING', ready=row, ready_received_monotonic_ns=time.monotonic_ns(),
                            hash_scope=row.get('hash_scope', 'UNDECLARED_BY_COLLECTOR'))
        return self.receipt

    def finish(self):
        if self.receipt.get('finalized'):
            return self.receipt
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    self.process.send_signal(signal.SIGTERM)
                try:
                    trailing, _ = self.process.communicate(timeout=90)
                except subprocess.TimeoutExpired:
                    # Only our unreaped child/session, never a PID from evidence.
                    os.killpg(self.process.pid, signal.SIGKILL)
                    trailing, _ = self.process.communicate(timeout=10)
                    self.receipt['issues'].append('COLLECTOR_FINALIZATION_TIMEOUT')
                self.receipt['returncode'] = self.process.returncode
                if trailing:
                    self.output.with_name(self.output.name + '.stdout-tail').write_bytes(trailing)
                final_path = self.output / 'final.json'
                if final_path.exists():
                    final = json.loads(final_path.read_bytes())
                    self.receipt.update(final=final, final_sha256=runner.sha_file(final_path),
                        hash_scope=final.get('hash_scope', self.receipt.get('hash_scope', 'UNDECLARED_BY_COLLECTOR')))
                    self.receipt['status'] = ('COMPLETE_FOR_SELECTED_HOOKS'
                        if self.process.returncode == 0 and not self.receipt['issues']
                        and final.get('observation_health') == 'COMPLETE_FOR_SELECTED_HOOKS'
                        else 'INCOMPLETE')
                else:
                    self.receipt.update(status='INCOMPLETE')
                    self.receipt['issues'].append('COLLECTOR_FINAL_MISSING')
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            self.receipt.update(status='INCOMPLETE')
            self.receipt['issues'].append(type(error).__name__ + ':' + str(error))
        finally:
            if self.stderr:
                self.stderr.close()
            self.receipt.update(finalized=True, finalized_monotonic_ns=time.monotonic_ns())
        return self.receipt


def trial_with_collector(args, common, target, condition, inventory, queries, base_group, boot_id):
    """Unchanged inner lifecycle; parent observation includes explicit setup."""
    parent = base_group / ('capture-' + uuid.uuid4().hex)
    runner.ensure_cgroup_parent(parent)
    identity = runner.cgroup_identity(parent)
    common.cgroup_parent = parent
    collector = None
    capture = {'schema_version': 1, 'status': 'NOT_ENABLED', 'mode': condition['file_access_mode'],
               'file_access_backend': args.file_access_backend,
               'collector_ring_bytes': args.collector_ring_bytes, 'boot_id': boot_id, 'cgroup': identity}
    try:
        if condition['file_access_mode'] == 'access':
            collector = Collector(args, target / 'file-access', identity, target.name, boot_id)
            collector.start()
        row = runner.run_trial(common, target, condition, inventory, queries, 0)
        trial_path = target / row['path']
        profile = json.loads((trial_path / 'profile-run.json').read_bytes())
        if collector and collector.process.poll() is not None:
            raise RuntimeError('file-access collector stopped before task finalization')
        if collector:
            capture = collector.finish()
        capture.update(mode=condition['file_access_mode'], profile_path=row['path'] + '/profile-run.json',
            profile_sha256=runner.sha_file(trial_path / 'profile-run.json'),
            profile_run_sha256=runner.sha_file(trial_path / 'profile-run.json'), profile_run_id=profile['run_id'],
            release_ns=profile['release_ns'], end_ns=profile['end_ns'], makespan_ns=profile['makespan_ns'],
            inner_root_cgroup=profile['root_cgroup'],
            event_window='RETAIN_ALL_RAW; OFFLINE_SELECT_START_END_WITHIN_RELEASE_END; CROSSING_EVENTS_EXPLICIT')
        if capture['status'] == 'INCOMPLETE':
            # Counter loss is not erased, nor does it invalidate real wall time.
            row['file_access_health'] = 'INCOMPLETE'
        else:
            row['file_access_health'] = capture['status']
        return row
    finally:
        if collector and not collector.receipt.get('finalized'):
            capture = collector.finish()
        runner.dump(target / 'capture.json', capture)
        cleanup_errors = []
        runner.cleanup_owned_cgroup(parent, identity, cleanup_errors, kill_remaining=False)
        if cleanup_errors:
            runner.dump(target / 'capture-cleanup-errors.json', {'errors': cleanup_errors})
            raise RuntimeError('capture parent cgroup cleanup incomplete: ' + str(cleanup_errors))


def execute(args):
    args.output.mkdir(mode=0o700)
    preparation = json.loads((args.prepared / 'preparation.json').read_bytes())
    source = json.loads(args.source_manifest.read_bytes())
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if preparation['source'] != source or preparation['boot_id'] != boot_id:
        raise ValueError('new boot-bound preparation and identical immutable source required')
    inventory_path = args.prepared / 'corpus-inventory.json'
    if runner.sha_file(inventory_path) != preparation['inventory_sha256']:
        raise ValueError('prepared source inventory changed')
    inventory = json.loads(inventory_path.read_bytes())
    roots = list(map(Path, preparation['independent_roots']))
    if str(args.corpus) != preparation['corpus'] or len(roots) != 8:
        raise ValueError('fixed-eight prepared roots differ')
    queries = json.loads(args.queries.read_bytes())
    if (not isinstance(queries, list) or not 1 <= len(queries) <= 8
            or any(not isinstance(q, str) or not q or '\n' in q or '\0' in q for q in queries)):
        raise ValueError('bounded fixed literal queries required')
    common = large_search.arguments(args, inventory, roots)
    common.io_prime_devices = args.io_prime_devices
    available = os.sched_getaffinity(0)
    if not common.cpus <= available or not available - common.cpus:
        raise ValueError('separate fixed workload and measurement CPUs required')
    auxiliary = available - common.cpus
    os.sched_setaffinity(0, auxiliary)
    plans = schedule(args.repetitions, args.seed, args.concurrencies, args.caches_list,
                     args.layouts_list, args.modes_list)
    binaries = {'sampler_sha256': runner.sha_file(common.sampler), 'grep_sha256': common.grep_sha256,
        'runner_sha256': runner.sha_file(runner.__file__), 'matrix_sha256': runner.sha_file(__file__),
        'large_search_sha256': runner.sha_file(large_search.__file__),
        'cache_probe_sha256': runner.sha_file(cache_probe.__file__),
        'file_access_sha256': args.file_access_sha256,
        'file_access_object_sha256': args.file_access_object_sha256,
        'file_access_backend': args.file_access_backend}
    manifest = {'schema_version': 1, 'status': 'RUNNING', 'campaigns': [], 'schedule': plans,
        'purpose': 'FIXED_WORK_CONCURRENT_FILE_SEARCH_WITH_PAIRED_FILE_ACCESS_PROBE_COST',
        'primary_metric': 'WALL_SECONDS_FROM_COMMON_RELEASE_TO_ALL_WORKER_EXITS',
        'source': source, 'source_inventory_sha256': preparation['inventory_sha256'],
        'jobs': 8, 'passes': args.passes, 'queries': queries, 'cpus': sorted(common.cpus),
        'measurement_coordinator_sampler_collector_cpus': sorted(auxiliary),
        'boot_id': boot_id, 'seed': args.seed, 'measurement_modes': args.modes_list,
        'file_access_backend': args.file_access_backend,
        'collector_budget': {'ring_bytes': args.collector_ring_bytes,
            'max_bytes': args.collector_max_bytes, 'max_seconds': args.collector_timeout_seconds},
        'binaries': binaries, 'GPU': 'EXCLUDED',
        'participating_source_roots': list(map(str, participating_roots(args.corpus, roots, args.layouts_list))),
        'limits': ['File-access events are async and bounded; loss/caps remain INCOMPLETE.',
            'Only per-trial release/end events count; collector also retains worker preparation.',
            'No full-state audit, SQLite conversion or per-file report generation in timed windows; collector hash scope is reported by its actual READY/final metadata, not assumed.',
            'Cold is Guest data-cold/metadata-probed, not Host/physical disk cold.',
            'Sampler/full-detail modes are separate; full-detail timings are not probe-free performance.']}
    runner.dump(args.output / 'matrix.json', manifest)
    base = Path('/sys/fs/cgroup') / ('search-access-' + uuid.uuid4().hex)
    runner.ensure_cgroup_parent(base)
    base_identity = runner.cgroup_identity(base)
    expected, pins = {}, {}
    try:
        for layout in sorted(set(args.layouts_list)):
            selected = [args.corpus] if layout == 'shared' else roots
            print(json.dumps({'pinning': layout, 'roots': len(selected)}), flush=True)
            pins[layout] = cache_probe.pin_roots(selected, inventory['files'], independent=layout == 'independent')
            if pins[layout]['status'] != 'PINNED':
                raise ValueError('prepared exact source identities could not be pinned')
        for index, plan in enumerate(plans):
            common.cache, common.workspace_layout = plan['cache'], plan['workspace_layout']
            common.workspaces = [args.corpus] * 8 if plan['workspace_layout'] == 'shared' else roots
            common.cache_pins = pins[plan['workspace_layout']]
            target = args.output / ('%03d-r%d' % (index, plan['block']))
            target.mkdir()
            (target / 'trials').mkdir()
            condition = {key: value for key, value in plan.items() if key != 'block'}
            condition.update(mode='sampler', repetition=0, file_access_backend=args.file_access_backend,
                             collector_ring_bytes=args.collector_ring_bytes)
            campaign = {'schema_version': 1, 'status': 'RUNNING', 'trials': [], 'jobs': 8,
                'passes': args.passes, 'queries': queries, 'cache': common.cache,
                'workspace_layout': common.workspace_layout, 'intervention': 'none',
                'repository_version': common.repository_version, 'grep_options': runner.GREP_OPTIONS,
                'cgroup_layout': common.cgroup_layout, 'memory_max_mb': 0, 'memory_high_mb': 0,
                'sample_threads': False, 'calibration_kind': None,
                'corpus_sha256': inventory['sha256'], 'permission_scope_sha256': inventory['permission_scope_sha256'],
                'binaries': binaries}
            print(json.dumps({'trial_index': index, 'total': len(plans), **plan}), flush=True)
            sync_start = time.monotonic_ns()
            os.sync()
            campaign['pre_trial_writeback_drain'] = {'kind': 'OWNED_GUEST_SYNC_BEFORE_COLLECTOR_WORKER_AND_CACHE_PREPARATION',
                'start_monotonic_ns': sync_start, 'end_monotonic_ns': time.monotonic_ns()}
            try:
                row = trial_with_collector(args, common, target, condition, inventory, queries, base, boot_id)
                for result in row['results']:
                    identity = result['query_index']
                    signature = (result['exit_code'], result['output_sha256'], result['output_bytes'])
                    if identity in expected and expected[identity] != signature:
                        raise ValueError('raw output differs across equivalent search conditions')
                    expected[identity] = signature
                campaign.update(status='COMPLETE', trials=[row])
            finally:
                runner.dump(target / 'campaign.json', campaign)
            manifest['campaigns'].append({'path': target.name, 'block': plan['block'],
                'stage': 'performance', 'condition': condition})
            update_owned_json(args.output / 'matrix.json', manifest)
            with (args.output / 'progress.jsonl').open('a') as stream:
                stream.write(json.dumps({'index': index, 'condition': plan,
                    'makespan_seconds': row['makespan_ns'] / 1e9,
                    'file_access_health': row['file_access_health']}) + '\n')
            print(json.dumps({'completed': index, 'wall_seconds': row['makespan_ns'] / 1e9,
                'file_access_health': row['file_access_health']}), flush=True)
            gc.collect()
        for root in participating_roots(args.corpus, roots, args.layouts_list):
            if large_search.fingerprint(runner.corpus_inventory(root)) != large_search.fingerprint(inventory):
                raise ValueError('post-campaign immutable input integrity differs')
        manifest.update(status='COMPLETE', output_equivalence='PASS',
                        source_integrity='PARTICIPATING_ROOTS_POST_CAMPAIGN_REHASHED_IDENTICAL')
    except BaseException as error:
        manifest.update(status='FAILED', error=type(error).__name__ + ':' + str(error))
        raise
    finally:
        errors = []
        runner.cleanup_owned_cgroup(base, base_identity, errors, kill_remaining=False)
        if errors:
            manifest.update(status='FAILED', cleanup_errors=errors)
        update_owned_json(args.output / 'matrix.json', manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('corpus', 'source-manifest', 'prepared', 'output', 'queries', 'sampler',
                 'file-access', 'file-access-object'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--passes', type=int, default=1)
    parser.add_argument('--repetitions', type=int, default=5)
    parser.add_argument('--seed', type=int, default=101646)
    parser.add_argument('--cpus', default='0,1,2,3')
    parser.add_argument('--concurrency', default='2,4,6,8')
    parser.add_argument('--caches', default='warm,guest-cold')
    parser.add_argument('--layouts', default='shared,independent')
    parser.add_argument('--modes', default='sampler,access')
    parser.add_argument('--file-access-backend', choices=('fentry', 'kprobe-tracefs'), default='fentry',
                        help='explicit hook backend; no automatic fallback')
    parser.add_argument('--io-prime-device', action='append', dest='io_prime_devices',
                        default=None, help='repeat explicit workload-device baseline priming before cache preparation')
    parser.add_argument('--collector-max-bytes', type=int, default=2147483648)
    parser.add_argument('--collector-ring-bytes', type=int, default=64 * 1024 ** 2,
                        help='explicit power-of-two BPF ring budget, 16..512 MiB')
    parser.add_argument('--collector-timeout-seconds', type=int, default=1200)
    args = parser.parse_args()
    cache_probe._ensure_guest()
    if os.geteuid() != 0 or args.jobs != 8 or not 1 <= args.passes <= 8 or not 1 <= args.repetitions <= 20:
        parser.error('owned root QEMU Guest, fixed eight jobs and bounded passes/repetitions required')
    try:
        args.concurrencies = tuple(map(int, bounded_list(args.concurrency, ('2', '4', '6', '8'), 'concurrency')))
        args.caches_list = bounded_list(args.caches, ('warm', 'guest-cold'), 'caches')
        args.layouts_list = bounded_list(args.layouts, ('shared', 'independent'), 'layouts')
        args.modes_list = bounded_list(args.modes, MODES, 'modes')
    except ValueError as error:
        parser.error(str(error))
    if not 1024 * 1024 <= args.collector_max_bytes <= 8 * 1024 ** 3 or not 60 <= args.collector_timeout_seconds <= 3600:
        parser.error('bounded collector bytes and timeout required')
    if not valid_ring_bytes(args.collector_ring_bytes):
        parser.error('collector ring bytes must be a power of two between 16 and 512 MiB')
    for key in ('corpus', 'source_manifest', 'prepared', 'queries', 'sampler', 'file_access', 'file_access_object'):
        setattr(args, key, getattr(args, key).resolve(strict=True))
    args.output = args.output.absolute()
    if args.output.exists() or args.output == args.corpus or args.corpus in args.output.parents:
        parser.error('fresh output outside corpus required')
    args.io_prime_devices = args.io_prime_devices or ['/dev/vda', '/dev/sda']
    args.file_access_sha256 = runner.sha_file(args.file_access)
    args.file_access_object_sha256 = runner.sha_file(args.file_access_object)
    execute(args)


if __name__ == '__main__':
    main()
