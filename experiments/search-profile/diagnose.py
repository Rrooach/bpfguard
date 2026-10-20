#!/usr/bin/env python3
"""Separate cgroup-scoped search diagnosis; never a timing/overhead campaign.

Runs only in an owned disposable QEMU Guest. CPU-clock samples are on-CPU
candidate evidence; optional D-state switch-out traces are separate raw stacks,
not wait durations. Neither proves disk waiting or exact per-Agent accounting.
Unknown symbols and missing/reset counters stay unknown. No model/API is used.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
MAX_TEXT = 128 * 1024 * 1024
SAMPLE = re.compile(r'^\s*(\d+)\s*/\s*(\d+)\s+([UKGgH]+)\s+(\d+)\.(\d{1,9}):\s+'
                    r'(\d+)\s+((?:0x)?[0-9a-fA-F]+)\s+(.+?)\s+\((.+)\)\s*$')
MATCHERS = ('Fexecute', 'EGexecute', 'Pexecute', 'dfaexec', 'kwsexec', 'bmexec', 'kws_exec')
METADATA = ('iterate_dir', 'iterate_shared', 'getdents', 'ksys_getdents', '__x64_sys_getdents',
    'filldir', 'ext4_readdir', 'btrfs_real_readdir', 'lookup_fast', 'lookup_slow', '__lookup_slow',
    'link_path_walk', 'path_lookupat', 'filename_lookup', 'walk_component', 'd_lookup', '__d_lookup',
    'inode_permission', 'security_inode_permission', 'security_inode_getattr', 'vfs_getattr',
    'vfs_statx', '__x64_sys_statx', 'ext4_lookup', 'btrfs_lookup')
READ_PATH = ('vfs_read', 'new_sync_read', 'generic_file_read_iter', 'filemap_read',
    'filemap_get_pages', 'ext4_file_read_iter', 'btrfs_file_read_iter', 'do_sys_read', 'ksys_read')
RECLAIM = ('try_to_free_pages', 'shrink_node', 'shrink_lruvec', 'shrink_folio_list', 'shrink_page_list',
    'reclaim_pages', 'balance_pgdat', 'do_try_to_free_pages', 'try_to_free_mem_cgroup_pages',
    'mem_cgroup_handle_over_high', 'shrink_slab', 'do_shrink_slab', 'lru_gen_shrink')


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read(path, lines=False):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_TEXT:
        raise ValueError('bounded regular evidence required: ' + str(path))
    raw = path.read_text()
    return [json.loads(line) for line in raw.splitlines()] if lines else json.loads(raw)


def save(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def within(path, root):
    try:
        Path(path).relative_to(Path(root))
        return True
    except ValueError:
        return False


def cache_flags(verify_residency=False, io_prime_device=None):
    """Forward optional proofs; runner retains pre-cache/probe/release ordering."""
    result = ['--verify-cache-residency'] if verify_residency else []
    devices = io_prime_device if isinstance(io_prime_device, (list, tuple)) else ([] if io_prime_device is None else [io_prime_device])
    for device in devices:
        result += ['--io-prime-device', str(device)]
    return result


def freeze(module, group, identity, frozen):
    if module._identity(group) != identity:
        raise RuntimeError('diagnostic cgroup identity changed')
    (group / 'cgroup.freeze').write_text(str(int(frozen)))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        events = dict(line.split() for line in (group / 'cgroup.events').read_text().splitlines())
        if events.get('frozen') == str(int(frozen)):
            return
        time.sleep(.01)
    raise TimeoutError('diagnostic cgroup freezer barrier')


def classify_symbol(mode, symbol, dso, grep):
    # Classification is deliberately narrow. Generic libc memchr/memcpy may
    # execute for many reasons and are not proof of grep string matching.
    symbol = re.sub(r'\+0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?$', '', symbol).strip()
    if symbol in ('[unknown]', 'unknown', '??') or re.fullmatch(r'(?:0x)?[0-9a-fA-F]+', symbol):
        return 'UNKNOWN_SYMBOL'
    if mode == 'K':
        for category, prefixes in (('KERNEL_DIRECTORY_METADATA_CANDIDATE', METADATA),
                ('KERNEL_FILE_READ_PATH_CANDIDATE_NOT_STORAGE_WAIT', READ_PATH),
                ('KERNEL_RECLAIM_CANDIDATE', RECLAIM)):
            if symbol.startswith(prefixes):
                return category
        return 'KERNEL_OTHER'
    if mode == 'U':
        if dso in (str(grep), Path(grep).name):
            return 'GREP_MATCHER_CANDIDATE' if symbol.startswith(MATCHERS) else 'GREP_USER_OTHER'
        return 'USER_OTHER_NOT_ESTABLISHED_AS_MATCHING'
    return 'UNKNOWN_CPU_MODE'


def parse_samples(lines, windows, grep):
    counts, periods, symbols, issues = Counter(), Counter(), Counter(), []
    outside, parsed = 0, 0
    for line_number, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = SAMPLE.fullmatch(line.rstrip('\n'))
        if not match:
            issues.append({'line': line_number, 'code': 'UNPARSED_OR_LOST_PERF_RECORD'})
            continue
        pid, tid, mode, sec, nsec, period, ip, symbol, dso = match.groups()
        stamp = int(sec) * 1_000_000_000 + int(nsec.ljust(9, '0'))
        if not any(start <= stamp <= end for start, end in windows):
            outside += 1
            continue
        weight = int(period)
        if weight <= 0:
            issues.append({'line': line_number, 'code': 'INVALID_SAMPLE_PERIOD'})
            continue
        category = classify_symbol(mode, symbol, dso, grep)
        counts[category] += 1
        periods[category] += weight
        symbols[(category, dso, symbol)] += weight
        parsed += 1
    total = sum(periods.values())
    return {'status': 'INCOMPLETE' if issues else ('OBSERVED' if parsed else 'NO_SAMPLES_IN_SEARCH_WINDOWS'),
        'sample_count': parsed, 'outside_search_windows': outside, 'issues': issues,
        'categories': {key: {'samples': counts[key], 'period_weight': periods[key],
            'fraction_of_observed_period': periods[key] / total if total else None} for key in sorted(counts)},
        'top_symbols': [{'category': key[0], 'dso': key[1], 'symbol': key[2], 'period_weight': value}
                        for key, value in symbols.most_common(30)],
        'interpretation': 'LEAF_ONCPU_SOFTWARE_CPU_CLOCK_SAMPLES_NOT_WALL_TIME_OR_OFFCPU_WAIT; UNKNOWN_STAYS_IN_DENOMINATOR'}


def counter(values, name, issues):
    if not values or any(type(value) is not int or value < 0 for value in values):
        issues.append('MISSING_COUNTER:' + name)
        return None
    if any(right < left for left, right in zip(values, values[1:])):
        issues.append('COUNTER_RESET:' + name)
        return None
    return values[-1] - values[0]


def at(value, keys):
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def resource_envelope(directory, profile, parent):
    load = directory / 'load'
    meta, stats = read(load / 'load-meta.json'), read(load / 'load-sampler-stats.json')
    rows = read(load / 'load-samples.jsonl', lines=True)
    begin, end = profile['release_ns'], profile['end_ns']
    before = [row for row in rows if type(row.get('collection_end_ns')) is int and row['collection_end_ns'] <= begin]
    after = [row for row in rows if row['monotonic_ns'] >= end]
    groups = meta.get('cgroups', [])
    expected_path = str(parent / profile['run_id'])
    expected_identity = profile.get('root_cgroup')
    if (not groups or groups[0].get('path') != expected_path or meta.get('boot_id') != profile.get('boot_id')
            or not isinstance(expected_identity, dict)
            or any(groups[0].get(key) != expected_identity.get(key) for key in ('path', 'inode', 'device'))
            or meta.get('label') != profile['run_id'] or not before or not after):
        return {'status': 'INCOMPLETE', 'issues': ['SAMPLER_SCOPE_IDENTITY_OR_BRACKET_MISSING']}
    first, last = before[-1], after[0]
    chosen = [row for row in rows if first['monotonic_ns'] <= row['monotonic_ns'] <= last['monotonic_ns']]
    values = [row['cgroups'][0] if row.get('cgroups') else {} for row in chosen]
    issues, derived = [], {}
    if (any(row.get('seq') != index for index, row in enumerate(rows))
            or any(right['monotonic_ns'] <= left['monotonic_ns'] for left, right in zip(rows, rows[1:]))
            or any(row.get('errors') for row in chosen) or any(value.get('present') is not True for value in values)):
        issues.append('SAMPLER_SEQUENCE_OR_COLLECTION_HEALTH_INCOMPLETE')
    for section, names in (('cpu_stat', ('usage_usec', 'user_usec', 'system_usec', 'throttled_usec')),
            ('memory_stat', ('pgmajfault', 'workingset_refault_file', 'pgscan', 'pgsteal')),
            ('memory_events', ('high', 'max', 'oom', 'oom_kill'))):
        derived[section] = {name: counter([at(value, (section, name)) for value in values], section + '.' + name, issues)
                            for name in names}
    derived['psi'] = {resource: {kind: counter([at(value, ('psi', resource, kind + '_total_us')) for value in values],
        'psi.' + resource + '.' + kind, issues) for kind in ('some', 'full')} for resource in ('cpu', 'memory', 'io')}
    maps = [value.get('io_stat_by_device') for value in values]
    if any(not isinstance(value, dict) for value in maps):
        derived['io_by_device'] = None
        issues.append('MISSING_DEVICE_IO')
    else:
        devices = sorted(set().union(*(value.keys() for value in maps)))
        derived['io_by_device'] = {device: {name: counter([at(value, (device, name)) for value in maps],
            'io.' + device + '.' + name, issues) for name in ('rbytes', 'wbytes', 'rios', 'wios')} for device in devices}
    for name in ('read_errors', 'missed_ticks', 'truncated_process_sets', 'truncated_cgroup_traversals', 'cgroup_traversal_read_errors'):
        if type(stats.get(name)) is not int or stats[name] != 0:
            issues.append('SAMPLER_HEALTH:' + name)
    if stats.get('samples') != len(rows):
        issues.append('SAMPLER_FINAL_SAMPLE_COUNT_MISMATCH')
    return {'status': 'OBSERVED_WITHIN_SCOPE' if not issues else 'INCOMPLETE', 'issues': sorted(set(issues)),
        'run_id': profile['run_id'], 'release_ns': begin, 'end_ns': end, 'cgroup': expected_identity,
        'counter_deltas': derived, 'before_uncertainty_ns': begin - first['monotonic_ns'],
        'after_uncertainty_ns': last['monotonic_ns'] - end,
        'scope': 'EXECUTION_CGROUP_ROOT_INCLUSIVE_TOTAL_NOT_PER_AGENT_COST; PSI_RESOURCES_NOT_ADDITIVE'}


def validate_cache_receipt(directory, profile, mode, corpus):
    """After execution only: recheck the non-atomic proof, never reread corpus."""
    receipt = profile.get('cache_residency')
    result = {'status': 'INCOMPLETE', 'issues': [], 'thresholds': {'warm_min': .999, 'guest_cold_max': .001},
        'scope': 'PER_FILE_NON_ATOMIC_DATA_PAGES; METADATA_PROBED; NOT_RELEASE_INSTANT_OR_HOST_CACHE_PROOF'}
    try:
        if not isinstance(receipt, dict) or receipt.get('path') != 'cache-residency.json':
            raise ValueError('CACHE_PROOF_RECEIPT_MISSING_OR_UNEXPECTED_PATH')
        path = directory / receipt['path']
        proof = read(path)
        if sha(path) != receipt.get('sha256'):
            raise ValueError('CACHE_PROOF_SHA256_MISMATCH')
        roots = proof.get('roots')
        if proof.get('status') != 'OBSERVED_NON_ATOMIC' or not isinstance(roots, list) or len(roots) != 1:
            raise ValueError('CACHE_PROOF_NOT_COMPLETE_SHARED_ROOT')
        row = roots[0]
        integers = ('declared_file_count', 'observed_file_count', 'unknown_file_count', 'total_pages', 'observed_total_pages',
            'start_monotonic_ns', 'end_monotonic_ns')
        if (row.get('status') != 'OBSERVED_NON_ATOMIC' or row.get('errors') != []
                or row.get('root') != str(corpus) or row.get('inventory_sha256') != profile['config']['corpus_sha256']
                or any(type(row.get(key)) is not int or row[key] < 0 for key in integers)
                or row['declared_file_count'] <= 0 or row['observed_file_count'] != row['declared_file_count']
                or row['unknown_file_count'] != 0 or row['total_pages'] <= 0
                or row['observed_total_pages'] != row['total_pages']
                or not row['start_monotonic_ns'] <= row['end_monotonic_ns'] <= profile['release_ns']):
            raise ValueError('CACHE_PROOF_SCOPE_COUNT_OR_TIME_INCOMPLETE')
        fraction = row.get('resident_fraction')
        if (type(fraction) not in (int, float) or not 0 <= fraction <= 1
                or mode == 'warm' and fraction < .999 or mode == 'guest-cold' and fraction > .001):
            raise ValueError('CACHE_RESIDENCY_OUTSIDE_DECLARED_CONDITION')
        details = proof.get('file_details')
        if not isinstance(details, dict) or details.get('path') != 'cache-residency-files.json.gz':
            raise ValueError('CACHE_FILE_DETAILS_MISSING_OR_UNEXPECTED_PATH')
        details_path = directory / details['path']
        if details_path.is_symlink() or not details_path.is_file() or sha(details_path) != details.get('sha256'):
            raise ValueError('CACHE_FILE_DETAILS_SHA256_MISMATCH')
        result.update(status='OBSERVED_WITHIN_DECLARED_NON_ATOMIC_CONDITION', resident_fraction=fraction,
            proof_sha256=receipt['sha256'], proof_end_to_release_ns=profile['release_ns'] - row['end_monotonic_ns'])
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['issues'].append(str(error))
    return result


def output_signature(root):
    manifest = read(root / 'campaign.json')
    if (manifest.get('schema_version') != 1 or manifest.get('status') != 'COMPLETE'
            or manifest.get('intervention') != 'none' or manifest.get('calibration_kind') is not None):
        raise ValueError('completed real-search no-reuse campaign required')
    signatures, profiles = {}, []
    for item in manifest['trials']:
        directory = (root / item['path']).resolve(strict=True)
        if not within(directory, root):
            raise ValueError('trial path escapes reference campaign')
        profile = read(directory / 'profile-run.json')
        results, tasks = profile.get('results'), profile.get('tasks')
        if (profile.get('status') != 'COMPLETE' or profile.get('cleanup_errors')
                or profile.get('run_id') != item.get('run_id') or not isinstance(results, list) or not isinstance(tasks, list)
                or len(results) != manifest.get('jobs') or len(tasks) != manifest.get('jobs')
                or len({row.get('task_id') for row in results}) != manifest.get('jobs')
                or {row.get('task_id') for row in results} != {row.get('task_id') for row in tasks}):
            raise ValueError('trial execution/cleanup incomplete')
        if (type(profile.get('release_ns')) is not int or type(profile.get('end_ns')) is not int
                or profile['end_ns'] <= profile['release_ns']
                or profile.get('makespan_ns') != profile['end_ns'] - profile['release_ns']):
            raise ValueError('invalid raw search timing window')
        profiles.append((directory, profile))
        for result in profile['results']:
            task = result['task_id']
            if not re.fullmatch(r'task-[0-9]{4}', task):
                raise ValueError('unsafe task identity')
            source = directory / (task + '.stdout')
            if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_TEXT:
                raise ValueError('bounded non-symlink raw search output required')
            raw = source.read_bytes()
            parts = raw.split(b'\0')
            digest = hashlib.sha256(b'\0'.join(sorted(parts[:-1])) + b'\0').hexdigest()
            if parts[-1] != b'' or digest != result['output_sha256'] or len(raw) != result['output_bytes'] or result['exit_code'] not in (0, 1):
                raise ValueError('raw search output mismatch')
            key = result['query_index']
            value = (digest, len(raw), result['exit_code'])
            if key in signatures and signatures[key] != value:
                raise ValueError('unequal fixed query outputs')
            signatures[key] = value
    if not profiles or not signatures:
        raise ValueError('empty reference campaign')
    return manifest, signatures, profiles


def compare_work(reference, actual):
    fields = ('corpus_sha256', 'permission_scope_sha256', 'repository_version', 'grep_options', 'queries', 'jobs', 'passes',
              'cache', 'workspace_layout', 'cgroup_layout', 'memory_max_mb', 'memory_high_mb')
    if any(reference.get(key) != actual.get(key) for key in fields) or reference['binaries']['grep_sha256'] != actual['binaries']['grep_sha256']:
        raise ValueError('diagnosis changed source/query/grep/options/fixed work/cache contract')


def candidate_summary(perf, resources):
    categories = perf.get('categories', {})
    result = {name: {'status': 'SYMBOL_CANDIDATE_OBSERVED' if category in categories else 'UNKNOWN_NO_IDENTIFIED_SAMPLE_NOT_PROOF_OF_ABSENCE',
                    'category': category, 'measurement': categories.get(category)}
              for name, category in (('matching_cpu', 'GREP_MATCHER_CANDIDATE'),
                  ('directory_metadata_cpu', 'KERNEL_DIRECTORY_METADATA_CANDIDATE'),
                  ('read_path_cpu_not_storage_wait', 'KERNEL_FILE_READ_PATH_CANDIDATE_NOT_STORAGE_WAIT'),
                  ('reclaim_cpu', 'KERNEL_RECLAIM_CANDIDATE'))}
    for label, resource, counter_paths in (('storage_read_and_wait', 'io', [('memory_stat', 'pgmajfault')]),
            ('memory_pressure', 'memory', [('memory_stat', 'pgscan'), ('memory_stat', 'workingset_refault_file'), ('memory_events', 'high')])):
        measurements = []
        for envelope in resources:
            deltas = envelope.get('counter_deltas', {})
            measurements.append({'psi_some_us': at(deltas, ('psi', resource, 'some')),
                'counters': {'.'.join(path): at(deltas, path) for path in counter_paths},
                'io_by_device': deltas.get('io_by_device') if resource == 'io' else None,
                'resource_status': envelope.get('status', 'INCOMPLETE')})
        result[label] = {'status': 'REVIEW_SEPARATE_COUNTERS_AND_TEST_CONTROLLED_INTERVENTION', 'measurements': measurements,
            'not_claimed': 'On-CPU samples or successful reads do not measure disk blocking; PSI/counters alone are not causal attribution.'}
    return result


def helper(path):
    specification = importlib.util.spec_from_file_location('separate_search_diagnostics', path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def perf_event_flags(event, frequency, call_graph):
    """Mutually exclusive on-CPU sampling or D-state switch-out raw traces."""
    if call_graph not in ('fp', 'dwarf'):
        raise ValueError('unsupported perf call graph mode')
    if event == 'sched-switch':
        if call_graph != 'fp':
            raise ValueError('sched-switch requires fp; per-switch DWARF stack copies are deliberately disabled')
        # sched_switch prev_state uses the report-state bit mask. Bit 2 is D;
        # filtering only nonzero would also include runnable preemption (R+).
        return ['-e', 'sched:sched_switch', '-c', '1', '--filter', 'prev_state & 2', '--call-graph', 'fp']
    if event != 'cpu-clock':
        raise ValueError('unsupported diagnostic perf event')
    return ['-e', 'cpu-clock', '-F', str(frequency), '--call-graph', 'dwarf,16384' if call_graph == 'dwarf' else 'fp']


def kernel_symbol_receipt(kallsyms=Path('/proc/kallsyms'), sysctl=Path('/proc/sys/kernel')):
    """Bounded readiness clue; never expose kernel addresses or claim full symbols."""
    result = {'status': 'UNKNOWN', 'lines_checked': 0, 'nonzero_address_lines': 0,
        'interpretation': 'READABILITY_CLUE_ONLY; perf export still determines actual symbol resolution'}
    try:
        with kallsyms.open() as stream:
            for _, line in zip(range(4096), stream):
                fields = line.split()
                result['lines_checked'] += 1
                if fields and re.fullmatch(r'[0-9a-fA-F]+', fields[0]) and int(fields[0], 16):
                    result['nonzero_address_lines'] += 1
        result['status'] = 'NONZERO_ADDRESSES_OBSERVED' if result['nonzero_address_lines'] else 'NO_NONZERO_ADDRESSES_OBSERVED'
    except OSError as error:
        result['reason'] = type(error).__name__ + ': ' + str(error)
    result['sysctls'] = {}
    for name in ('kptr_restrict', 'perf_event_paranoid'):
        try:
            result['sysctls'][name] = (sysctl / name).read_text().strip()
        except OSError:
            result['sysctls'][name] = None
    return result


def collector_class(module):
    class Collector(module.Diagnostics):
        def _start_perf(self):
            binary = module._pinned(self.config, 'perf_binary', 'perf_sha256')
            event = self.config.get('perf_event', 'cpu-clock')
            call_graph = self.config.get('call_graph', 'fp')
            flags = perf_event_flags(event, self.config['frequency_hz'], call_graph)
            control_read, self.control_write = os.pipe()
            self.ack_read, ack_write = os.pipe()
            relative = str(self.cgroup.relative_to(module.CGROUP_ROOT))
            # perf parses -G immediately and rejects an empty event list.
            # Keep -e (and its trace filter) before the cgroup option.
            command = [binary, 'record', '--no-buildid-cache'] + flags + ['-a', '-G', relative, '--clockid', 'mono', '--delay=-1',
                '--control', 'fd:%d,%d' % (control_read, ack_write), '-o', str(self.output / 'perf.data')]
            try:
                self._spawn(command, pass_fds=(control_read, ack_write), cwd=str(self.output))
            finally:
                os.close(control_read)
                os.close(ack_write)
            self._perf_control('enable')
            self.report['perf_scope'] = {'event': 'software cpu-clock' if event == 'cpu-clock' else 'sched:sched_switch', 'clock': 'CLOCK_MONOTONIC',
                'cgroup_relative_path': relative, 'enable_ack_received': True,
                'frequency_hz': self.config['frequency_hz'] if event == 'cpu-clock' else None,
                'period': 1 if event == 'sched-switch' else None,
                'trace_filter': 'prev_state & 2' if event == 'sched-switch' else None,
                'call_graph': call_graph, 'dwarf_stack_bytes': 16384 if call_graph == 'dwarf' else None,
                'classification': ('Leaf samples only; unusable symbols/frames remain unknown; callchains are separate raw evidence.'
                    if event == 'cpu-clock' else 'D_STATE_SWITCH_OUT_RAW_STACKS_ONLY; counts are not wait durations, CPU samples or proof of disk blocking.'),
                'record_buildid_cache': 'DISABLED; perf.data/buildid metadata remain in separate diagnosis output',
                'attribution': 'REGISTERED_PARENT_AND_DESCENDANTS_AGGREGATE_NOT_EXCLUSIVE_AGENT_COST'}
    return Collector


def perf_script_command(perf, data, callchains=False):
    """Only the leaf export feeds counts; callchain frames must not be samples."""
    command = [str(perf), 'script', '--ns']
    if not callchains:
        command.append('-G')
    return command + ['--show-lost-events', '-F', 'pid,tid,misc,time,period,ip,sym,dso', '-i', str(data)]


def sched_switch_script_command(perf, data):
    return [str(perf), 'script', '--ns', '--show-lost-events', '-F',
        'pid,tid,misc,time,event,trace,ip,sym,dso', '-i', str(data)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-campaign', type=Path,
                        help='optional completed timing campaign for independent fixed-output comparison; never altered')
    parser.add_argument('--runner', type=Path, default=HERE / 'run.py')
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--queries', '--queries-file', dest='queries_file', type=Path, required=True)
    parser.add_argument('--sampler', type=Path, required=True)
    parser.add_argument('--grep', type=Path, default=Path('/usr/bin/grep'))
    parser.add_argument('--perf', type=Path, default=Path('/usr/bin/perf'))
    parser.add_argument('--perf-event', choices=['cpu-clock', 'sched-switch'], default='cpu-clock',
                        help='separate cpu-clock samples or D-state switch-out raw stacks; never combined into CPU percentages')
    parser.add_argument('--collector', choices=['perf', 'files'], default='perf')
    parser.add_argument('--file-profiler', type=Path)
    parser.add_argument('--file-object', type=Path)
    parser.add_argument('--file-object-sha256')
    parser.add_argument('--diagnostics-helper', type=Path, default=HERE.parent / 'agent-benchmarks/diagnostics.py')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int)
    parser.add_argument('--passes', type=int)
    parser.add_argument('--cache', choices=['warm', 'guest-cold', 'uncontrolled'])
    parser.add_argument('--repository-version')
    parser.add_argument('--memory-max-mb', type=int)
    parser.add_argument('--memory-high-mb', type=int)
    parser.add_argument('--concurrency', default='8')
    parser.add_argument('--repetitions', type=int, default=1)
    parser.add_argument('--cpus', default='0,1')
    parser.add_argument('--frequency-hz', type=int, default=99)
    parser.add_argument('--call-graph', choices=['fp', 'dwarf'], default='fp',
                        help='perf stack capture; dwarf uses a bounded 16384-byte user stack; neither guarantees complete unwinding')
    parser.add_argument('--allow-guest-drop-caches', action='store_true')
    parser.add_argument('--verify-cache-residency', action='store_true',
                        help='forward full file-data mincore proof; metadata is traversed before release')
    parser.add_argument('--io-prime-device', type=Path, action='append', dest='io_prime_devices', default=[],
                        help='forward explicit Guest block device for observed pre-cache I/O baseline priming')
    parser.add_argument('--timeout-seconds', type=int, default=300,
                        help='per-worker diagnosis timeout; separate from formal task times')
    parser.add_argument('--process-interval-ms', type=int, default=0,
                        help='optional extra process polling; zero matches cgroup-only formal search sampling')
    args = parser.parse_args()
    if args.perf_event == 'sched-switch' and (args.call_graph != 'fp' or args.collector != 'perf'):
        parser.error('sched-switch requires --collector perf --call-graph fp; no per-switch DWARF stack copies')
    if not 1 <= args.timeout_seconds <= 3600:
        parser.error('timeout-seconds must be within 1..3600')
    if args.process_interval_ms != 0 and not 100 <= args.process_interval_ms <= 60000:
        parser.error('process-interval-ms must be zero or within 100..60000')
    vendor = ' '.join(path.read_text() for path in (Path('/sys/class/dmi/id/product_name'), Path('/sys/class/dmi/id/sys_vendor'))).lower()
    if os.geteuid() != 0 or not any(value in vendor for value in ('qemu', 'kvm')):
        parser.error('owned privileged QEMU Guest only; never run a workload on the physical server')
    reference_root = args.reference_campaign.resolve(strict=True) if args.reference_campaign else None
    corpus = args.corpus.resolve(strict=True)
    output = args.output.resolve()
    if within(output, corpus) or reference_root and within(output, reference_root):
        parser.error('fresh diagnosis output must be outside source and reference evidence')
    reference, expected = None, None
    if reference_root:
        reference, expected, _ = output_signature(reference_root)
        if (reference.get('workspace_layout') != 'shared' or reference.get('cgroup_layout') != 'shared-leaf'
                or reference.get('queries') != read(args.queries_file) or sha(args.grep) != reference['binaries']['grep_sha256']):
            parser.error('shared-leaf fixed-work reference and identical queries/grep required')
    configuration = {'jobs': 8, 'passes': 8, 'cache': 'warm', 'repository_version': 'content-addressed',
                     'memory_max_mb': 0, 'memory_high_mb': 0}
    if reference:
        configuration.update({key: reference.get(key, configuration[key]) for key in configuration})
    for name in configuration:
        value = getattr(args, name)
        if value is not None:
            if reference and value != configuration[name]:
                parser.error('explicit parameter differs from reference: ' + name)
            configuration[name] = value
    try:
        concurrency = list(map(int, args.concurrency.split(',')))
    except ValueError:
        parser.error('comma-separated integer concurrency required')
    if (not concurrency or len(set(concurrency)) != len(concurrency) or min(concurrency) < 1
            or max(concurrency) > configuration['jobs'] or not 1 <= configuration['jobs'] <= 128
            or not 1 <= configuration['passes'] <= 1000 or not 1 <= args.repetitions <= 2
            or not 1 <= args.frequency_hz <= 1000 or not 0 <= configuration['memory_max_mb'] <= 16384
            or not 0 <= configuration['memory_high_mb'] <= 16384 or configuration['memory_max_mb']
            and configuration['memory_high_mb'] > configuration['memory_max_mb']):
        parser.error('bounded jobs/passes/frequency and 1..2 diagnostic repetitions required')
    if configuration['cache'] == 'guest-cold' and not args.allow_guest_drop_caches:
        parser.error('guest-cold requires explicit --allow-guest-drop-caches in owned VM')
    args.runner = args.runner.resolve(strict=True)
    output.mkdir(mode=0o700)
    module = helper(args.diagnostics_helper.resolve(strict=True))
    group = Path('/sys/fs/cgroup') / ('search-diagnose-' + uuid.uuid4().hex[:16])
    group.mkdir()
    expected_group = module._identity(group)
    (group / 'cgroup.subtree_control').write_text('+cpu +memory +io')
    collector = None
    config = {'mode': args.collector, 'frequency_hz': args.frequency_hz, 'call_graph': args.call_graph, 'perf_event': args.perf_event}
    capture = {'status': 'NOT_STARTED'}
    report = {'schema_version': 1, 'status': 'INCOMPLETE', 'diagnosis_only': True,
        'not_formal_timing_or_overhead': True, 'GPU': 'EXCLUDED',
        'reference_campaign_sha256': sha(reference_root / 'campaign.json') if reference_root else None,
        'diagnostics_helper_sha256': sha(args.diagnostics_helper), 'diagnose_source_sha256': sha(__file__),
        'runner_sha256': sha(args.runner), 'grep_sha256': sha(args.grep), 'sampler_sha256': sha(args.sampler),
        'perf_event': args.perf_event if args.collector == 'perf' else None,
        'kernel_symbol_readiness': kernel_symbol_receipt(),
        'sampling_configuration': {'interval_ms': 100, 'process_interval_ms': args.process_interval_ms,
            'timing': 'Sampler writes and live perf collection overlap search; script/report/hash finalization is after runner completion.',
            'overhead': 'DIAGNOSTIC_ONLY_NOT_FORMAL_MAKESPAN_OR_OVERHEAD; collector CPU affinity is inherited, workers use --cpus.'},
        'cache_proof_requests': {'verify_cache_residency': args.verify_cache_residency,
            'io_prime_devices': list(map(str, args.io_prime_devices)),
            'scope': 'FILE_DATA_PAGE_RESIDENCY_WITH_METADATA_PROBING_NOT_DENTRY_INODE_COLD_PROOF'},
        'cgroup': expected_group, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'issues': []}
    command = [sys.executable, '-B', str(args.runner), '--corpus', str(corpus), '--queries-file', str(args.queries_file.resolve()),
        '--sampler', str(args.sampler.resolve()), '--grep', str(args.grep.resolve()), '--output-dir', str(output / 'runner'),
        '--cgroup-parent', str(group), '--concurrency', args.concurrency, '--jobs', str(configuration['jobs']),
        '--passes', str(configuration['passes']), '--repository-version', configuration['repository_version'],
        '--repetitions', str(args.repetitions), '--warmups', '0', '--modes', 'sampler', '--workspace-layout', 'shared',
        '--cgroup-layout', 'shared-leaf', '--cache', configuration['cache'], '--cpus', args.cpus,
        '--memory-max-mb', str(configuration['memory_max_mb']), '--memory-high-mb', str(configuration['memory_high_mb']),
        '--interval-ms', '100', '--process-interval-ms', str(args.process_interval_ms), '--timeout-seconds', str(args.timeout_seconds)]
    if args.allow_guest_drop_caches:
        command.append('--allow-guest-drop-caches')
    command += cache_flags(args.verify_cache_residency, args.io_prime_devices)
    report['command'] = command
    process = None
    try:
        try:
            if args.collector == 'perf':
                config.update(perf_binary=str(args.perf.resolve(strict=True)), perf_sha256=sha(args.perf))
            else:
                if not args.file_profiler or not args.file_object or sha(args.file_object) != args.file_object_sha256:
                    raise ValueError('explicit pinned file collector and object required')
                config.update(file_profiler_binary=str(args.file_profiler.resolve(strict=True)), file_profiler_sha256=sha(args.file_profiler),
                    file_profiler_object=str(args.file_object.resolve(strict=True)), file_profiler_object_sha256=args.file_object_sha256,
                    max_file_records=65536, max_seconds=3600)
            freeze(module, group, expected_group, True)
            collector = collector_class(module)(config, output / 'collector', group, output.name)
            collector.start()
            capture = {'status': 'RECORDING', 'configuration': config}
        except (OSError, RuntimeError, ValueError, TimeoutError) as error:
            capture = {'status': 'MISSING_OR_UNAVAILABLE', 'reason': type(error).__name__ + ': ' + str(error)}
            if args.collector == 'perf':
                report['sched_switch' if args.perf_event == 'sched-switch' else 'perf_samples'] = {
                    'status': 'MISSING_OR_UNAVAILABLE', 'reason': capture['reason']}
            collector = None
        freeze(module, group, expected_group, False)
        with (output / 'runner.stdout').open('xb') as out, (output / 'runner.stderr').open('xb') as err:
            process = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True)
            try:
                code = process.wait(timeout=3600)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=15)
                raise RuntimeError('bounded diagnosis runner timed out')
        report['runner_returncode'] = code
        if code:
            raise RuntimeError('fixed diagnosis search failed; preserve all raw output')
        if collector:
            freeze(module, group, expected_group, True)
            try:
                capture = collector.finish()
            except (OSError, RuntimeError, ValueError, TimeoutError, subprocess.TimeoutExpired) as error:
                capture = dict(collector.report)
                report['issues'].append('COLLECTOR_FINALIZATION:' + type(error).__name__ + ': ' + str(error))
        actual, signatures, profiles = output_signature(output / 'runner')
        if (any(actual.get(key) != value for key, value in configuration.items()) or actual.get('queries') != read(args.queries_file)
                or actual.get('binaries', {}).get('grep_sha256') != report['grep_sha256']):
            raise ValueError('actual runner did not honor declared fixed-work inputs')
        if reference:
            compare_work(reference, actual)
            if signatures != expected:
                raise ValueError('diagnosis output differs from fixed reference queries')
        report['output_equivalence'] = ('RAW_NUL_FILENAME_RESULTS_RECHECKED_EQUAL_TO_REFERENCE' if reference else
            'RAW_NUL_FILENAME_RESULTS_RECHECKED_EQUAL_WITHIN_DIAGNOSIS_ONLY_NO_FORMAL_REFERENCE')
        report['resources'] = [resource_envelope(directory, profile, group) for directory, profile in profiles]
        report['cache_proof_receipts'] = [{'trial': str(directory.relative_to(output)),
            'cache_residency': profile.get('cache_residency'), 'io_baseline_priming': profile.get('io_baseline_priming')}
            for directory, profile in profiles]
        if args.verify_cache_residency:
            for receipt, (directory, profile) in zip(report['cache_proof_receipts'], profiles):
                receipt['validation'] = validate_cache_receipt(directory, profile, configuration['cache'], corpus)
                if receipt['validation']['status'] == 'INCOMPLETE':
                    report['issues'].extend('CACHE_PROOF:' + issue for issue in receipt['validation']['issues'])
        if args.collector == 'perf' and collector and args.perf_event == 'sched-switch':
            path = output / 'sched-switch-callchains.txt'
            script = sched_switch_script_command(args.perf, output / 'collector/perf.data')
            with path.open('xb') as out, (output / 'sched-switch-script.stderr').open('xb') as err:
                code = subprocess.run(script, stdout=out, stderr=err, timeout=120).returncode
            report['sched_switch'] = {'status': 'RAW_TRACE_EXPORTED_NOT_CLASSIFIED' if code == 0 else 'INCOMPLETE',
                'command': script, 'returncode': code, 'path': path.name, 'bytes': path.stat().st_size, 'sha256': sha(path),
                'event': 'sched:sched_switch', 'filter': 'prev_state & 2', 'call_graph': 'fp',
                'loss_assessment': 'NOT_VALIDATED_BY_RAW_EXPORT; inspect lost records/stderr before interpreting counts',
                'scope': 'UNCROPPED_REGISTERED_CGROUP_LIFETIME; use resources release_ns/end_ns to inspect search windows',
                'not_claimed': ['No CPU percentages, elapsed wait durations, wakeup pairing or exhaustive off-CPU history.',
                    'D-state includes page-cache/page-lock and other kernel waits; it is not proof of disk bandwidth saturation.',
                    'Interruptible waits and runnable preemption are excluded; unresolved kernel symbols remain unknown.']}
            if code:
                report['issues'].append('SCHED_SWITCH_SCRIPT_FAILED_RAW_PERF_DATA_PRESERVED')
        elif args.collector == 'perf' and collector:
            script = perf_script_command(args.perf, output / 'collector/perf.data')
            with (output / 'perf-samples.txt').open('xb') as out, (output / 'perf-script.stderr').open('xb') as err:
                code = subprocess.run(script, stdout=out, stderr=err, timeout=120).returncode
            if code:
                raise RuntimeError('perf script failed; raw perf.data preserved')
            path = output / 'perf-samples.txt'
            if path.stat().st_size > MAX_TEXT:
                raise ValueError('perf script exceeds bounded parsing budget; raw evidence retained')
            report['perf_samples'] = parse_samples(path.read_text().splitlines(),
                [(profile['release_ns'], profile['end_ns']) for _, profile in profiles], args.grep)
            # Keep the uncropped raw stacks for offline review. Do not parse or
            # feed frames into leaf counts: that would multiply sample counts.
            chains = output / 'perf-callchains.txt'
            chain_command = perf_script_command(args.perf, output / 'collector/perf.data', callchains=True)
            with chains.open('xb') as out, (output / 'perf-callchains.stderr').open('xb') as err:
                chain_code = subprocess.run(chain_command, stdout=out, stderr=err, timeout=120).returncode
            report['perf_callchains'] = {'status': 'EXPORTED_RAW_NOT_CLASSIFIED' if chain_code == 0 else 'INCOMPLETE',
                'command': chain_command, 'returncode': chain_code, 'path': chains.name,
                'bytes': chains.stat().st_size, 'sha256': sha(chains),
                'scope': 'UNCROPPED_REGISTERED_CGROUP_LIFETIME; use release_ns/end_ns from resources for search windows',
                'call_graph': args.call_graph, 'not_claimed': 'Complete unwinding or symbol resolution; no frames are added to leaf sample counts.'}
            if chain_code:
                report['issues'].append('PERF_CALLCHAIN_EXPORT_FAILED_RAW_PERF_DATA_PRESERVED')
        elif args.collector == 'files' and collector:
            profile = read(output / 'collector/files/file-profile.json')
            totals = defaultdict(lambda: Counter())
            for row in profile['records']:
                for name in ('calls', 'returned_bytes', 'duration_ns'):
                    if type(row.get(name)) is not int or row[name] < 0:
                        raise ValueError('invalid file aggregate counter: ' + name)
                    totals[row['operation']][name] += row[name]
            report['file_operations'] = dict(totals)
            report['file_scope'] = 'SELECTED_VFS_READ_AND_DIRECTORY_AGGREGATES_NOT_PHYSICAL_IO_OR_EXCLUSIVE_WALL_TIME; MMAP_ACCESS_BYTES_UNKNOWN'
        report['status'] = 'DIAGNOSTIC_EVIDENCE_RECORDED_WITH_DECLARED_LIMITS' if (
            collector and capture.get('status') == 'COMPLETE_FOR_DECLARED_DIAGNOSTIC_MODE'
            and all(value['status'] == 'OBSERVED_WITHIN_SCOPE' for value in report['resources'])
            and report.get('perf_samples', {}).get('status', 'OBSERVED') == 'OBSERVED') else 'INCOMPLETE'
        if args.collector == 'perf' and args.perf_event == 'sched-switch' and report['status'] != 'INCOMPLETE':
            report['status'] = 'RAW_SCHED_TRACE_RECORDED_LOSS_NOT_ESTABLISHED'
        if args.perf_event == 'cpu-clock' or args.collector != 'perf':
            report['candidate_summary'] = candidate_summary(report.get('perf_samples', {}), report['resources'])
        report['interpretation'] = ['Matcher/metadata/read/reclaim symbols are candidate locations, not automatic root-cause labels.',
            'Use resource deltas and independent cold/warm or memory.high interventions to test a candidate.',
            ('D-state switch-out records are only raw blocked-stack candidates; counts are not elapsed wait time, and D is not proof of disk I/O.'
                if args.collector == 'perf' and args.perf_event == 'sched-switch' else
                'CPU-clock samples only on-CPU execution; disk waiting needs IO/PSI/block evidence, not read() count.'),
            'No perf sample or unresolved stripped symbol cannot establish absence or matching cost.',
            'The collector covers the registered parent and descendant cgroups, not the coordinator or whole VM.',
            'Diagnostic task times are not formal baseline, overhead or optimization measurements.']
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        report['issues'].append(type(error).__name__ + ': ' + str(error))
    finally:
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        if collector and not collector.finished:
            try:
                freeze(module, group, expected_group, True)
                capture = collector.finish()
            except BaseException as error:
                report['issues'].append('collector_cleanup:' + str(error))
        report['collector'] = dict(collector.report) if collector else capture
        if module._identity(group) != expected_group:
            report['issues'].append('CGROUP_IDENTITY_CHANGED_REFUSE_CLEANUP')
        else:
            if 'populated 1' in (group / 'cgroup.events').read_text():
                (group / 'cgroup.kill').write_text('1')
                report['issues'].append('RESIDUAL_WORKLOAD_KILLED_IN_EXACT_OWNED_CGROUP')
            try:
                group.rmdir()
            except OSError as error:
                report['issues'].append('CGROUP_RETAINED:' + str(error))
        if report['issues']:
            report['status'] = 'INCOMPLETE'
        save(output / 'diagnosis.json', report)
    print(json.dumps({'status': report['status'], 'report': str(output / 'diagnosis.json')}))


if __name__ == '__main__':
    main()
