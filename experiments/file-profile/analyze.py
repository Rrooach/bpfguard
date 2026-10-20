#!/usr/bin/env python3
"""Offline file costs. Never divide ambiguous shared-thread counters by guesswork."""
import argparse
from collections import defaultdict
import json
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024
HEALTH_V1 = {'context_full', 'pending_full', 'object_read_failed', 'aggregate_full',
    'nested_hooks_skipped', 'unpaired_exit', 'syscall_exit_pending', 'unresolved_mmap'}
HEALTH_V2 = HEALTH_V1 | {'unsupported_syscall_abi'}
HOOKS = {'fp_sys_enter', 'fp_sys_exit', 'fp_read_enter', 'fp_read_exit',
    'fp_readv_enter', 'fp_readv_exit', 'fp_dir_enter', 'fp_dir_exit', 'fp_mmap_file'}
STATUSES = {'INCOMPLETE', 'COMPLETE_FOR_SELECTED_HOOKS'}
U64_MAX = (1 << 64) - 1


def unsigned(value, positive=False):
    return type(value) is int and (1 if positive else 0) <= value <= U64_MAX


def domains(value):
    """Validate saved registration declarations without opening dead Guest paths."""
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise ValueError('one to sixteen registered domains required')
    ids, paths = set(), []
    for domain in value:
        if not isinstance(domain, dict) or not unsigned(domain.get('inode'), True) or not unsigned(domain.get('device'), True):
            raise ValueError('invalid registered cgroup identity')
        path, level = domain.get('path'), domain.get('level')
        if (not isinstance(path, str) or not path.startswith('/sys/fs/cgroup/') or
                path != str(Path(path)) or any(part in ('.', '..') for part in path.split('/')) or
                type(level) is not int or not 1 <= level <= 31 or len(Path(path).parts) - 4 != level):
            raise ValueError('invalid registered cgroup path/level')
        if domain['inode'] in ids or any(path == other or path.startswith(other + '/') or
                other.startswith(path + '/') for other in paths):
            raise ValueError('duplicate/overlapping registered domains')
        ids.add(domain['inode'])
        paths.append(path)
    return ids


def object_key(obj):
    # A read/getattr query bit is not a version change. Keep it in raw rows
    # and aggregate raw_storage_variants, not in the semantic version key.
    return json.dumps({key: value for key, value in obj.items()
        if key not in ('raw_ctime_nsec', 'ctime_queried_flag')}, sort_keys=True)


def read(path, lines=False):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError('bounded regular input file required')
    with path.open() as stream:
        return [json.loads(line) for line in stream] if lines else json.load(stream)


def intervals(events):
    tasks, result = {}, []
    for event in events:
        task = event.get('task_id')
        if event.get('event') == 'START':
            if task in tasks:
                raise ValueError('duplicate task START')
            tasks[task] = event
        elif event.get('event') in ('COMPLETE', 'FAILED', 'CANCELLED'):
            start = tasks.pop(task, None)
            if not start:
                raise ValueError('orphan task terminal')
            for key in ('run_id', 'boot_id', 'task_id', 'attempt', 'epoch', 'process', 'cgroup'):
                if start.get(key) != event.get(key):
                    raise ValueError('task identity changed: ' + key)
            if event['monotonic_ns'] < start['monotonic_ns']:
                raise ValueError('task time reversed')
            result.append({'task_id': task, 'agent_id': start.get('agent_id'),
                'tool_call_id': start.get('tool_call_id'), 'phase': start.get('phase'),
                'boot_id': start.get('boot_id'), 'process': start.get('process'),
                'domain_id': start.get('cgroup', {}).get('inode'),
                'start_ns': start['monotonic_ns'], 'end_ns': event['monotonic_ns']})
    if tasks:
        raise ValueError('incomplete task interval')
    return result


def associate(row, tasks):
    """A unique registered execution domain covering ALL calls establishes a
    cooperative runtime association, not a security/causal proof. Two requests
    using one thread cannot be disaggregated after kernel aggregation.
    """
    candidates = [task for task in tasks if task['boot_id'] == row['boot_id']
        and task['domain_id'] == row['domain_id']
        and task['start_ns'] <= row['first_start_ns']
        and row['last_end_ns'] <= task['end_ns']]
    if len(candidates) == 1:
        return {'quality': 'DECLARED_DOMAIN_INTERVAL',
                **{key: candidates[0].get(key) for key in
                   ('task_id', 'agent_id', 'tool_call_id', 'phase')}}
    return {'quality': 'UNRESOLVED',
            'reason': 'NO_COMPLETE_INTERVAL' if not candidates else 'OVERLAPPING_SHARED_DOMAIN'}


def validate_profile(profile, meta=None, events=()):
    """Check raw aggregate consistency, not an audit/kernel trust proof."""
    version = profile.get('schema_version')
    if type(version) is not int or version not in (1, 2) or not isinstance(profile.get('boot_id'), str) or not profile['boot_id']:
        raise ValueError('profile schema and boot identity required')
    start, end = profile.get('start_monotonic_ns'), profile.get('end_monotonic_ns')
    if not unsigned(start) or not unsigned(end) or start > end:
        raise ValueError('invalid collector observation window')
    if profile.get('observation_health') not in STATUSES:
        raise ValueError('unknown observation health status')
    if type(profile.get('timed_out')) is not bool:
        raise ValueError('collector timeout state required')
    if not isinstance(profile.get('records'), list) or len(profile['records']) > 131072:
        raise ValueError('bounded aggregate records required')
    expected_health = HEALTH_V1 if version == 1 else HEALTH_V2
    if not isinstance(profile.get('health'), dict) or set(profile['health']) != expected_health:
        raise ValueError('required versioned health counters missing/unknown')
    programs = profile.get('programs')
    if not isinstance(programs, list) or len(programs) != len(HOOKS) or any(not isinstance(program, dict) for program in programs):
        raise ValueError('complete selected-hook health table required')
    names = [program.get('name') for program in programs]
    if any(not isinstance(name, str) for name in names) or set(names) != HOOKS or len(set(names)) != len(names):
        raise ValueError('selected hook names missing/duplicate/unknown')
    program_ids = []
    for program in programs:
        if version == 2 or 'id' in program:
            if not unsigned(program.get('id'), True):
                raise ValueError('loaded program identity missing/invalid')
            program_ids.append(program['id'])
    if len(set(program_ids)) != len(program_ids):
        raise ValueError('loaded program identities duplicated')
    registered = domains(profile.get('registered_domains')) if version == 2 else None
    binding = 'NOT_PROVIDED'
    if meta is not None:
        if not isinstance(meta, dict) or type(meta.get('schema_version')) is not int or meta.get('schema_version') != version:
            raise ValueError('meta/profile schema mismatch')
        if meta.get('boot_id') != profile['boot_id'] or not unsigned(meta.get('start_monotonic_ns')) or meta['start_monotonic_ns'] != start:
            raise ValueError('meta/profile boot/start mismatch')
        declared = domains(meta.get('domains'))
        if version == 2 and profile['registered_domains'] != meta['domains']:
            raise ValueError('meta/profile domain registration mismatch')
        registered = declared
        if type(meta.get('entry_limit')) is not int or not 1024 <= meta['entry_limit'] <= 131072:
            raise ValueError('bounded file-record budget missing/invalid')
        if len(profile['records']) > meta['entry_limit']:
            raise ValueError('file-record count exceeds registered budget')
        label = meta.get('label')
        if label is not None and (not isinstance(label, str) or not label):
            raise ValueError('collector label must be null or nonempty string')
        if events and (label is None or any(event.get('run_id') != label for event in events)):
            raise ValueError('collector label/task run identity mismatch')
        binding = 'BOUND_DECLARATIONS_NOT_AUTHENTICATION'
    incomplete = profile['timed_out']
    for field in ('pending_syscalls', 'pending_vfs_calls'):
        value = profile.get(field)
        if not unsigned(value):
            raise ValueError('invalid pending counters')
        incomplete |= value != 0
    for name, value in profile['health'].items():
        if not unsigned(value):
            raise ValueError('invalid health counter')
        # Selected coverage is the outermost user-visible VFS operation;
        # deliberately nested hooks are not an additional promised operation.
        incomplete |= value != 0 and name != 'nested_hooks_skipped'
    for program in programs:
        value = program.get('recursion_misses')
        if not unsigned(value):
            raise ValueError('program recursion counter missing or invalid')
        incomplete |= value != 0
    if incomplete and profile.get('observation_health') == 'COMPLETE_FOR_SELECTED_HOOKS':
        raise ValueError('declared complete profile contradicts raw health counters')
    for event in events:
        if (event.get('boot_id') != profile['boot_id'] or not unsigned(event.get('monotonic_ns')) or
                not start <= event['monotonic_ns'] <= end):
            raise ValueError('task event boot/window differs from collector')
    for row in profile['records']:
        if row.get('boot_id') != profile['boot_id']:
            raise ValueError('row boot differs from collector')
        first, last = row.get('first_start_ns'), row.get('last_end_ns')
        if not unsigned(first) or not unsigned(last) or not start <= first <= last <= end:
            raise ValueError('row outside collector observation window')
        for identity, id_field in (('process', 'pid'), ('thread', 'tid')):
            value = row.get(identity, {})
            if not unsigned(value.get(id_field), True) or not unsigned(value.get('start_boottime_ns'), True):
                raise ValueError('process/thread instance identity required')
        for field in ('domain_id',):
            if not unsigned(row.get(field), True):
                raise ValueError('registered domain identity required')
        if registered is not None and row['domain_id'] not in registered:
            raise ValueError('record domain is not registered')
        if row.get('operation') not in ('read_or_pread', 'readv_or_preadv', 'directory_iteration', 'file_mmap'):
            raise ValueError('unknown file operation')
        for field in ('calls', 'success_calls', 'errors', 'returned_bytes', 'duration_ns', 'max_duration_ns'):
            if not unsigned(row.get(field)):
                raise ValueError('bounded nonnegative aggregate counters required')
        if row['calls'] != row['success_calls'] + row['errors'] or row['calls'] == 0:
            raise ValueError('aggregate call totals inconsistent')
        if row['max_duration_ns'] > row['duration_ns']:
            raise ValueError('maximum duration exceeds aggregate duration')
        if row['operation'] in ('directory_iteration', 'file_mmap') and row['returned_bytes'] != 0:
            raise ValueError('directory status/mapping result is not access bytes')
    return {'profile_schema_version': version, 'metadata_binding': binding,
            'registered_domain_validation': 'CHECKED_DECLARATIONS' if registered is not None else 'UNKNOWN_LEGACY_WITHOUT_META',
            'syscall_abi_guard': 'DECLARED_NATIVE_ABI_GUARD_V2' if version == 2 else 'NOT_ESTABLISHED_LEGACY_V1',
            'authority': 'PERFORMANCE_SIDE_CHANNEL_NOT_AUTHENTICATED_AUDIT_VERIFIER'}


def analyze(profile, events=(), inventory=None, meta=None):
    validation = validate_profile(profile, meta, events)
    tasks = intervals(events)
    object_paths = defaultdict(list)
    if inventory is not None:
        if inventory.get('boot_id') != profile['boot_id'] or inventory.get('pre_post_identical') is not True:
            raise ValueError('inventory must bind same boot and verified unchanged before/after scope')
        for item in inventory['objects']:
            key = tuple(item[name] for name in ('kernel_device', 'inode', 'size', 'mtime_sec',
                'mtime_nsec', 'ctime_sec', 'ctime_nsec'))
            object_paths[key].append({'path': item['path'], 'content_sha256': item.get('sha256'),
                'quality': 'DECLARED_QUIESCENT_READ_ONLY_INVENTORY_MATCH_NOT_KERNEL_PATH_SNAPSHOT'})
    output = defaultdict(lambda: {'calls': 0, 'success_calls': 0, 'errors': 0,
        'returned_bytes': 0, 'duration_ns': 0, 'thread_instances': set(),
        'process_instances': set(), 'raw_ctime_storage_variants': set()})
    unresolved = 0
    for row in profile['records']:
        obj = row['object']
        if row['calls'] != row['success_calls'] + row['errors']:
            raise ValueError('invalid call counters')
        if row['first_start_ns'] > row['last_end_ns']:
            raise ValueError('invalid observation interval')
        if row['operation'] == 'file_mmap' and row['returned_bytes']:
            raise ValueError('mmap access bytes must remain unknown')
        association = associate(row, tasks)
        if association['quality'] == 'UNRESOLVED':
            unresolved += row['calls']
        # Preserve all fields of the metadata-version hint and mount identity.
        key = (row['boot_id'], row['domain_id'], object_key(obj),
               json.dumps(association, sort_keys=True), row['operation'])
        value = output[key]
        value['object'] = obj
        if 'raw_ctime_nsec' in obj:
            value['raw_ctime_storage_variants'].add(obj['raw_ctime_nsec'])
        path_key = tuple(obj.get(name) for name in ('kernel_device', 'inode', 'size', 'mtime_sec',
            'mtime_nsec', 'ctime_sec', 'ctime_nsec'))
        value['inventory_paths'] = object_paths.get(path_key, [])
        value['association'] = association
        value['operation'] = row['operation']
        value['domain_id'] = row['domain_id']
        for field in ('calls', 'success_calls', 'errors', 'returned_bytes', 'duration_ns'):
            if type(row[field]) is not int or row[field] < 0:
                raise ValueError('invalid nonnegative counters')
            value[field] += row[field]
        value['thread_instances'].add((row['thread']['tid'], row['thread']['start_boottime_ns']))
        value['process_instances'].add((row['process']['pid'], row['process']['start_boottime_ns']))
    rows = []
    for value in output.values():
        for field in ('thread_instances', 'process_instances', 'raw_ctime_storage_variants'):
            value[field] = sorted(value[field])
        size = value['object']['size']
        # A lower bound on byte-volume repetition, NOT repeated ranges or
        # proved wasted work. Without offsets, two calls may read disjoint data.
        value['byte_volume_over_object_size'] = (value['returned_bytes'] / size
            if size > 0 and value['operation'] != 'file_mmap' else None)
        rows.append(value)
    rows.sort(key=lambda value: value['duration_ns'], reverse=True)
    shared = {}
    for value in rows:
        if value['operation'] == 'file_mmap':
            continue
        key = object_key(value['object'])
        item = shared.setdefault(key, {'object': value['object'], 'domain_ids': set(),
            'task_ids': set(), 'returned_bytes': 0, 'calls': 0, 'aggregate_vfs_ns': 0,
            'inventory_paths': value['inventory_paths'], 'raw_ctime_storage_variants': set()})
        item['raw_ctime_storage_variants'].update(value['raw_ctime_storage_variants'])
        item['domain_ids'].add(value['domain_id'])
        if value['association'].get('task_id'):
            item['task_ids'].add(value['association']['task_id'])
        item['returned_bytes'] += value['returned_bytes']
        item['calls'] += value['calls']
        item['aggregate_vfs_ns'] += value['duration_ns']
    shared_rows = []
    for item in shared.values():
        item['domain_ids'] = sorted(item['domain_ids'])
        item['task_ids'] = sorted(item['task_ids'])
        item['raw_ctime_storage_variants'] = sorted(item['raw_ctime_storage_variants'])
        size = item['object']['size']
        item['byte_volume_over_object_size'] = item['returned_bytes'] / size if size > 0 else None
        shared_rows.append(item)
    shared_rows.sort(key=lambda item: item['returned_bytes'], reverse=True)
    return {'schema_version': 1, 'observation_health': profile['observation_health'],
        'validation': validation,
        'health': profile['health'], 'unresolved_association_calls': unresolved,
        'objects_by_cost': rows, 'shared_file_access': shared_rows, 'limits': profile['limits'] + [
            'duration_ns across threads is aggregate work, not critical-path wall time',
            'byte_volume_over_object_size is not proof of duplicate ranges or avoidable work',
            'task association uses cooperative runtime declarations, not an audit-verifier verdict',
            'metadata version hint cannot authorize cross-user cache reuse; reuse separately binds content/permissions']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', required=True)
    parser.add_argument('--task-events')
    parser.add_argument('--inventory')
    parser.add_argument('--meta', help='Optional saved collector metadata binding (not authentication)')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = analyze(read(args.profile), read(args.task_events, True) if args.task_events else [],
                     read(args.inventory) if args.inventory else None, read(args.meta) if args.meta else None)
    with Path(args.output).open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
