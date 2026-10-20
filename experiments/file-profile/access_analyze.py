#!/usr/bin/env python3
"""Offline selected file hooks: raw events on disk, not a whole-trace JSON list.

This is a cooperative performance diagnostic, not an authenticated audit
verifier. An inode is not a path, a mapping is not an access, and a filemap
fault attempt (which can return RETRY) is not a process-wide page-fault count.
"""
import argparse
from collections import Counter
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import struct
import sys


MAX_METADATA = 512 * 1024 * 1024
MAX_TRACE_BYTES = 16 * 1024 ** 3
MAX_CPU = 16384
SQL_MAX = (1 << 63) - 1
U64_MAX = (1 << 64) - 1
EVENT = struct.Struct('<IHHII11QqqQqqQQ8I')
MAGIC = 0x46414343
EVENT_FIELDS = ('magic', 'version', 'kind', 'size', 'flags', 'sequence',
    'domain_id', 'caller_cgroup_id', 'process_birth_ns', 'thread_birth_ns',
    'start_ns', 'end_ns', 'sys_start_ns', 'sys_end_ns', 'mount_id', 'inode',
    'file_size', 'offset_before', 'requested_bytes', 'result', 'syscall_result',
    'fault_address', 'fault_pgoff', 'device', 'generation', 'tgid', 'tid',
    'cpu', 'syscall_nr', 'fault_input_flags', 'vm_fault_result')
OPERATIONS = {1: 'read', 2: 'readv', 3: 'directory', 4: 'open', 5: 'fault', 6: 'mm_fault'}
OBJECT_VALID, REQUESTED_VALID, OFFSET_VALID = 1, 2, 4
SYSCALL_VALID, FAULT_FLAGS_VALID, FAULT_RETURN_VALID = 8, 32, 64
REGULAR_FILE, DIRECTORY, NO_FILE_VMA = 128, 256, 512
KNOWN_FLAGS = OBJECT_VALID | REQUESTED_VALID | OFFSET_VALID | SYSCALL_VALID | FAULT_FLAGS_VALID | FAULT_RETURN_VALID | REGULAR_FILE | DIRECTORY | NO_FILE_VMA
HEALTH = {'context_full', 'pending_full', 'object_read_failed', 'nested_hooks',
    'unpaired_exit', 'syscall_exit_pending', 'unsupported_syscall_abi', 'ring_drops',
    'fault_pending_full', 'fault_unpaired', 'fault_exit_pending', 'syscall_mismatch',
    'multiple_vfs', 'offset_read_failed', 'mm_fault_pending_full',
    'mm_fault_unpaired', 'mm_fault_exit_pending'}
PROGRAMS = {'fa_sys_enter', 'fa_sys_exit', 'fa_read_enter', 'fa_read_exit',
    'fa_readv_enter', 'fa_readv_exit', 'fa_dir_enter', 'fa_dir_exit',
    'fa_open_file', 'fa_fault_enter', 'fa_fault_exit', 'fa_task_exit',
    'fa_mm_fault_enter', 'fa_mm_fault_exit'}
FAULT_FLAGS_CONTRACT = {'major': 4, 'retry': 1024, 'error_mask': 2163}
INVENTORY_SCHEMA = '''CREATE TABLE inventory (
    device TEXT, inode TEXT, size INTEGER, mtime_sec INTEGER,
    mtime_nsec INTEGER, ctime_sec INTEGER, ctime_nsec INTEGER, path TEXT,
    mount_id TEXT, generation TEXT, scope_kind TEXT);
    CREATE INDEX inventory_identity ON inventory(device,inode,size);'''
INDEX_DIGEST_CACHE = {}
TRACE_ANCHORS = {
    'fa_read_enter': ('vfs_read', False), 'fa_read_exit': ('vfs_read', True),
    'fa_readv_enter': ('vfs_readv', False), 'fa_readv_exit': ('vfs_readv', True),
    'fa_dir_enter': ('iterate_dir', False), 'fa_dir_exit': ('iterate_dir', True),
    'fa_open_file': ('security_file_open', False),
    'fa_fault_enter': ('filemap_fault', False), 'fa_fault_exit': ('filemap_fault', True),
    'fa_mm_fault_enter': ('handle_mm_fault', False), 'fa_mm_fault_exit': ('handle_mm_fault', True)}


def integer(value, positive=False, maximum=U64_MAX):
    return type(value) is int and int(positive) <= value <= maximum


def regular(path, limit):
    path = Path(path)
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > limit:
        raise ValueError('bounded regular, non-symlink input required: ' + str(path))
    return path


def json_input(path):
    path = regular(path, MAX_METADATA)
    raw = path.read_bytes()
    return json.loads(raw), {'path': str(path), 'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest()}


def cgroup_identity(value):
    if (not isinstance(value, dict) or not isinstance(value.get('path'), str)
            or not value['path'].startswith('/sys/fs/cgroup/')
            or str(Path(value['path'])) != value['path']
            or '..' in Path(value['path']).parts
            or any(not integer(value.get(key), True) for key in ('inode', 'device'))):
        raise ValueError('cgroup path/inode/device identity required')
    return {key: value[key] for key in ('path', 'inode', 'device')}


def profile_window(profile):
    if (not isinstance(profile, dict) or profile.get('status') != 'COMPLETE'
            or not isinstance(profile.get('boot_id'), str) or not profile['boot_id']
            or not isinstance(profile.get('run_id'), str) or not profile['run_id']
            or not integer(profile.get('release_ns')) or not integer(profile.get('end_ns'))
            or profile['release_ns'] >= profile['end_ns']
            or not integer(profile.get('makespan_ns'), True)
            or profile.get('makespan_ns') != profile['end_ns'] - profile['release_ns']):
        raise ValueError('complete run with exact release/end monotonic interval required')
    root = cgroup_identity(profile.get('root_cgroup'))
    groups = {}
    tasks = profile.get('tasks')
    if not isinstance(tasks, list) or not tasks:
        raise ValueError('explicit worker and cgroup declarations required')
    task_ids = set()
    for task in tasks:
        task_id = task.get('task_id')
        process = task.get('process', {})
        group = cgroup_identity(task.get('cgroup'))
        if (not isinstance(task_id, str) or not task_id or task_id in task_ids
                or not integer(process.get('pid'), True) or not integer(process.get('start_ticks'), True)
                or not (group['path'] == root['path'] or group['path'].startswith(root['path'] + '/'))
                or group['device'] != root['device']):
            raise ValueError('unique worker identities and descendant cgroup declarations required')
        task_ids.add(task_id)
        groups.setdefault(group['inode'], []).append(task_id)
    # A unique, declared task cgroup supplies membership attribution. Time
    # overlap or a matching PID alone is deliberately never used as a join.
    associations = {key: values[0] for key, values in groups.items() if len(values) == 1}
    return {'boot_id': profile['boot_id'], 'run_id': profile['run_id'],
        'release_ns': profile['release_ns'], 'end_ns': profile['end_ns'],
        'root_cgroup': root, 'associations': associations,
        'shared_cgroups': [key for key, values in groups.items() if len(values) != 1]}


def temporal_scope(start, end, release, finish):
    if end < release:
        return 'BEFORE'
    if start > finish:
        return 'AFTER'
    if release <= start <= end <= finish:
        return 'IN_WINDOW'
    return 'CROSSES_WINDOW_BOUNDARY'


def log2_bin(value):
    return 0 if value == 0 else value.bit_length()


def histogram(counter, unit):
    total = sum(counter.values())
    bins = [{'lower_inclusive': 0 if key == 0 else 1 << (key - 1),
             'upper_inclusive': 0 if key == 0 else (1 << key) - 1,
             'count': count} for key, count in sorted(counter.items())]
    quantiles = {}
    for label, percentile in (('p50', 50), ('p95', 95), ('p99', 99)):
        rank, seen = max(1, (total * percentile + 99) // 100), 0
        quantiles[label] = None
        for row in bins:
            seen += row['count']
            if seen >= rank:
                quantiles[label] = {key: row[key] for key in ('lower_inclusive', 'upper_inclusive')}
                break
    return {'unit': unit, 'observations': total, 'bins': bins,
        'quantiles': quantiles, 'quantile_quality': 'LOG2_BIN_BOUNDS_NOT_EXACT_RAW_PERCENTILES'}


def fault_classification(flags):
    # Linux include/linux/mm_types.h VM_FAULT_* return bits. RETRY and errors
    # are attempts, not resolved faults. This does not cover anonymous faults.
    names = {0x1: 'OOM', 0x2: 'SIGBUS', 0x4: 'MAJOR',
        0x10: 'HWPOISON', 0x20: 'HWPOISON_LARGE', 0x40: 'SIGSEGV',
        0x100: 'NOPAGE', 0x200: 'LOCKED', 0x400: 'RETRY',
        0x800: 'FALLBACK', 0x1000: 'DONE_COW', 0x2000: 'NEEDDSYNC',
        0x4000: 'COMPLETED'}
    selected = [name for bit, name in names.items() if flags & bit]
    # HINDEX occupies the upper four bits and is data, not a new verdict.
    known = sum(names) | 0xF0000
    if flags & ~known:
        selected.append('UNKNOWN_RETURN_BITS')
    if flags & ~known:
        outcome = 'UNRESOLVED_UNKNOWN_RETURN_BITS'
    elif flags & (0x1 | 0x2 | 0x10 | 0x20 | 0x40 | 0x800):
        outcome = 'ERROR_OR_FALLBACK_ATTEMPT'
    elif flags & 0x400:
        outcome = 'RETRY_ATTEMPT'
    else:
        outcome = 'NON_RETRY_NON_ERROR_RETURN_NOT_PROCESS_FAULT_TOTAL'
    return outcome, selected


def inventory_rows(inventory, boot):
    if inventory is None:
        return []
    if (not isinstance(inventory, dict) or inventory.get('boot_id') != boot
            or inventory.get('pre_post_identical') is not True or inventory.get('read_only') is not True
            or not isinstance(inventory.get('objects'), list)):
        raise ValueError('same-boot read-only pre/post-checked inventory required')
    result = []
    for row in inventory['objects']:
        path = row.get('path')
        if (not isinstance(path, str) or not path or '\x00' in path
                or not integer(row.get('kernel_device')) or not integer(row.get('inode'), True)
                or not integer(row.get('size'))
                or any(type(row.get(key)) is not int for key in ('mtime_sec', 'ctime_sec'))
                or any(not integer(row.get(key), maximum=999999999) for key in ('mtime_nsec', 'ctime_nsec'))):
            raise ValueError('inventory must include an exact stat identity and metadata version hint')
        result.append((str(row['kernel_device']), str(row['inode']), row['size'], row['mtime_sec'],
            row['mtime_nsec'], row['ctime_sec'], row['ctime_nsec'], path,
            str(row['mount_id']) if integer(row.get('mount_id'), True) else None,
            str(row['generation']) if integer(row.get('generation')) else None,
            row.get('scope_kind', inventory.get('scope_kind', 'UNCLASSIFIED_DECLARED_REGULAR_FILE_SCOPE'))))
    return result


def initialize_database(path, inventory=(), inventory_database=None):
    with Path(path).open('xb'):
        pass
    connection = sqlite3.connect(str(path), uri=True)
    connection.executescript('''
        PRAGMA journal_mode=DELETE;
        PRAGMA synchronous=FULL;
        PRAGMA temp_store=FILE;
        PRAGMA cache_size=-16384;
        CREATE TABLE events (
            record_number INTEGER PRIMARY KEY, raw_offset INTEGER NOT NULL, raw BLOB NOT NULL,
            operation TEXT, temporal_scope TEXT, valid INTEGER, object_key TEXT,
            object_quality TEXT, regular_file INTEGER, device TEXT, inode TEXT,
            generation TEXT, mount_id TEXT, size INTEGER, mtime_sec INTEGER,
            mtime_nsec INTEGER, ctime_sec INTEGER, ctime_nsec INTEGER,
            start_ns INTEGER, end_ns INTEGER, duration_ns INTEGER, interval_scope TEXT,
            sys_start_ns INTEGER, sys_end_ns INTEGER, syscall_nr INTEGER, syscall_result INTEGER,
            domain_id TEXT, caller_cgroup_id TEXT, task_id TEXT,
            tgid INTEGER, tid INTEGER, process_birth_ns TEXT, thread_birth_ns TEXT,
            cpu INTEGER, sequence TEXT, requested_bytes INTEGER, result INTEGER,
            returned_bytes INTEGER, offset_before INTEGER, fault_address TEXT,
            fault_pgoff TEXT, fault_input_flags TEXT, fault_return_flags INTEGER, fault_context TEXT, fault_outcome TEXT,
            fault_return_names TEXT, flags INTEGER);
        CREATE TABLE malformed (record_number INTEGER, reason TEXT);
        CREATE TABLE cpu_sequences (cpu INTEGER, sequence TEXT, record_number INTEGER,
            PRIMARY KEY(cpu,sequence)) WITHOUT ROWID;
    ''')
    if inventory_database is None:
        connection.executescript(INVENTORY_SCHEMA)
        connection.executemany('INSERT INTO inventory VALUES(?,?,?,?,?,?,?,?,?,?,?)', inventory)
    else:
        connection.execute('ATTACH DATABASE ? AS inventory_index',
            (Path(inventory_database).resolve().as_uri() + '?mode=ro',))
        connection.execute('CREATE TEMP VIEW inventory AS SELECT * FROM inventory_index.inventory')
    connection.commit()
    return connection


def file_digest(path):
    path = regular(path, 64 * 1024 ** 3)
    before = path.stat()
    identity = tuple(getattr(before, name) for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    cached = INDEX_DIGEST_CACHE.get((str(path.resolve()), identity))
    if cached is not None:
        return cached
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while True:
            chunk = stream.read(1024 ** 2)
            if not chunk:
                break
            digest.update(chunk)
    after = path.stat()
    if identity != tuple(getattr(after, name) for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
        raise ValueError('file changed while hashing')
    result = {'path': str(path), 'bytes': after.st_size, 'sha256': digest.hexdigest()}
    if len(INDEX_DIGEST_CACHE) >= 8:
        INDEX_DIGEST_CACHE.clear()
    INDEX_DIGEST_CACHE[(str(path.resolve()), identity)] = result
    return result


def build_inventory_index(paths, output, boot_id):
    with Path(output).open('xb'):
        pass
    connection = sqlite3.connect(str(output))
    sources, count = [], 0
    try:
        connection.executescript(INVENTORY_SCHEMA + '''
            CREATE TABLE index_metadata(key TEXT PRIMARY KEY,value TEXT);
        ''')
        for path in paths:
            inventory, source = json_input(path)
            rows = inventory_rows(inventory, boot_id)
            connection.executemany('INSERT INTO inventory VALUES(?,?,?,?,?,?,?,?,?,?,?)', rows)
            connection.commit()
            count += len(rows)
            sources.append(source)
        manifest = {'schema_version': 1, 'boot_id': boot_id, 'pre_post_identical': True,
            'read_only': True, 'regular_file_stat_rows': count, 'sources': sources,
            'quality': 'DECLARED_QUIESCENT_READ_ONLY_STAT_INVENTORY; NOT_AUTHENTICATED_KERNEL_PATHS'}
        connection.execute('INSERT INTO index_metadata VALUES(?,?)', ('manifest', json.dumps(manifest, sort_keys=True)))
        connection.commit()
    finally:
        connection.close()
    return {**manifest, 'artifact': file_digest(output)}


def inventory_index_manifest(path, boot_id):
    source = file_digest(path)
    connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        row = connection.execute("SELECT value FROM index_metadata WHERE key='manifest'").fetchone()
        if row is None or len(row[0]) > 4 * 1024 ** 2:
            raise ValueError('bounded inventory-index manifest missing')
        manifest = json.loads(row[0])
        if (manifest.get('schema_version') != 1 or manifest.get('boot_id') != boot_id
                or manifest.get('pre_post_identical') is not True or manifest.get('read_only') is not True
                or not integer(manifest.get('regular_file_stat_rows'))
                or not isinstance(manifest.get('sources'), list)):
            raise ValueError('same-boot verified read-only inventory-index binding required')
        columns = [row[1] for row in connection.execute('PRAGMA table_info(inventory)')]
        if columns != ['device', 'inode', 'size', 'mtime_sec', 'mtime_nsec', 'ctime_sec', 'ctime_nsec', 'path', 'mount_id', 'generation', 'scope_kind']:
            raise ValueError('inventory index schema mismatch')
    finally:
        connection.close()
    return source, manifest


class RegularInventoryLookup:
    """Only unknown inode types need a lookup; kernel REGULAR/DIR bits bypass it."""
    def __init__(self, connection):
        self.connection = connection
        self.cache = {}

    def __contains__(self, key):
        if key not in self.cache:
            device, inode, size = key
            found = self.connection.execute('SELECT 1 FROM inventory WHERE device=? AND inode=? AND size=? LIMIT 1',
                (str(device), str(inode), size)).fetchone() is not None
            if len(self.cache) >= 131072:
                self.cache.pop(next(iter(self.cache)))
            self.cache[key] = found
        return self.cache[key]


def export_file_rows(connection, output):
    """SQL aggregation spills to disk; paths never participate in object identity."""
    connection.executescript('''
        CREATE INDEX event_identity ON events(object_key);
        CREATE INDEX event_file_details ON events(device,inode,record_number);
        CREATE INDEX event_operation ON events(operation,valid,temporal_scope);
        CREATE VIEW selected AS SELECT * FROM events
          WHERE valid=1 AND temporal_scope='IN_WINDOW';
        CREATE TABLE objects AS SELECT object_key, MAX(object_quality) AS object_quality,
          MAX(regular_file) AS regular_file, device,inode,generation,mount_id,
          COUNT(*) AS selected_events,
          SUM(operation='open' AND result>=0) AS open_success_calls,
          SUM(operation IN ('read','readv')) AS read_calls,
          SUM(operation IN ('read','readv') AND result<0) AS read_errors,
          SUM(operation IN ('read','readv') AND requested_bytes IS NULL) AS read_requested_unknown_calls,
          SUM(CASE WHEN operation IN ('read','readv') THEN requested_bytes ELSE 0 END) AS read_requested_bytes,
          SUM(CASE WHEN operation IN ('read','readv') THEN returned_bytes ELSE 0 END) AS read_returned_bytes,
          SUM(CASE WHEN operation IN ('read','readv') THEN duration_ns ELSE 0 END) AS read_duration_ns,
          MAX(CASE WHEN operation IN ('read','readv') THEN duration_ns ELSE NULL END) AS max_read_duration_ns,
          NULL AS mmap_success_calls,
          SUM(operation='fault') AS filemap_fault_attempts,
          SUM(operation='fault' AND fault_outcome='RETRY_ATTEMPT') AS filemap_fault_retry_attempts,
          SUM(operation='fault' AND fault_outcome='ERROR_OR_FALLBACK_ATTEMPT') AS filemap_fault_error_or_fallback_attempts,
          SUM(operation='mm_fault') AS mm_fault_attempts,
          SUM(operation='mm_fault' AND fault_outcome='RETRY_ATTEMPT') AS mm_fault_retry_attempts,
          SUM(operation='mm_fault' AND fault_outcome='ERROR_OR_FALLBACK_ATTEMPT') AS mm_fault_error_or_fallback_attempts,
          MIN(start_ns) AS first_start_ns, MAX(end_ns) AS last_end_ns
        FROM selected WHERE object_key IS NOT NULL GROUP BY object_key;
        CREATE TABLE object_hints AS SELECT DISTINCT object_key,device,inode,size,
          mount_id,generation,mtime_sec,mtime_nsec,ctime_sec,ctime_nsec
          FROM selected WHERE object_key IS NOT NULL;
        CREATE TABLE object_paths AS SELECT DISTINCT e.object_key,i.path,i.scope_kind,
          CASE WHEN i.mount_id IS NOT NULL AND i.generation IS NOT NULL
            THEN 'DECLARED_READ_ONLY_DEVICE_INODE_SIZE_MOUNT_GENERATION; NO_RUNTIME_MTIME_CTIME_VERIFICATION'
            ELSE 'DECLARED_READ_ONLY_DEVICE_INODE_SIZE; NO_RUNTIME_MOUNT_GENERATION_MTIME_CTIME_VERIFICATION' END AS quality
        FROM object_hints e JOIN inventory i
          ON e.device=i.device AND e.inode=i.inode AND e.size=i.size
          AND (e.mtime_sec IS NULL OR (e.mtime_sec=i.mtime_sec AND e.mtime_nsec=i.mtime_nsec))
          AND (e.ctime_sec IS NULL OR (e.ctime_sec=i.ctime_sec AND e.ctime_nsec=i.ctime_nsec))
          AND (i.mount_id IS NULL OR i.mount_id=e.mount_id)
          AND (i.generation IS NULL OR i.generation=e.generation)
        WHERE e.object_key IS NOT NULL;
        CREATE INDEX object_paths_identity ON object_paths(object_key);
    ''')
    connection.commit()
    columns = [row[1] for row in connection.execute('PRAGMA table_info(objects)')]
    columns += ['mean_read_duration_ns', 'inventory_paths_json', 'inventory_scope_kinds_json', 'path_quality']
    rows = connection.execute('SELECT * FROM objects ORDER BY read_duration_ns DESC,object_key')
    top = []
    with Path(output).open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for raw in rows:
            value = dict(zip(columns, raw))
            count = value['read_calls']
            value['mean_read_duration_ns'] = value['read_duration_ns'] / count if count else None
            paths = list(connection.execute('SELECT path,quality FROM object_paths WHERE object_key=? ORDER BY path',
                (value['object_key'],)))
            value['inventory_paths_json'] = json.dumps([row[0] for row in paths], ensure_ascii=True)
            value['inventory_scope_kinds_json'] = json.dumps([row[0] for row in connection.execute(
                'SELECT DISTINCT scope_kind FROM object_paths WHERE object_key=? ORDER BY scope_kind', (value['object_key'],))])
            value['path_quality'] = paths[0][1] if paths else 'UNRESOLVED_NO_STATIC_INVENTORY_MATCH'
            writer.writerow(value)
            if len(top) < 20:
                top.append({**value, 'inventory_paths': [row[0] for row in paths]})
    return top


def export_detail(database, output, object_key=None, device=None, inode=None,
        tid=None, thread_birth_ns=None, start_ns=None, end_ns=None):
    """One row per original event, including failures and boundary crossings."""
    database = regular(database, 64 * 1024 ** 3)
    if object_key is not None and (device is not None or inode is not None):
        raise ValueError('choose either exact object key or device+inode')
    if object_key is None and (device is None) != (inode is None):
        raise ValueError('device and inode must be selected together')
    if object_key is None and device is None and tid is None and start_ns is None and end_ns is None:
        raise ValueError('at least one exact object, TID or time filter required')
    if thread_birth_ns is not None and tid is None:
        raise ValueError('thread birth filter requires a TID')
    if start_ns is not None and end_ns is not None and start_ns > end_ns:
        raise ValueError('time filter reversed')
    connection = sqlite3.connect('file:' + str(database.resolve()) + '?mode=ro', uri=True)
    try:
        clauses, args = [], []
        if object_key is not None:
            clauses.append('object_key=?')
            args.append(object_key)
        elif device is not None:
            clauses.append('device=? AND inode=?')
            args.extend([str(device), str(inode)])
        for column, value, operator in (('tid', tid, '='), ('thread_birth_ns', str(thread_birth_ns) if thread_birth_ns is not None else None, '='),
                ('start_ns', start_ns, '>='), ('end_ns', end_ns, '<=')):
            if value is not None:
                clauses.append(column + operator + '?')
                args.append(value)
        rows = connection.execute('SELECT * FROM events WHERE ' + ' AND '.join(clauses) + ' ORDER BY record_number', args)
        columns = [row[0] for row in rows.description]
        count = 0
        with Path(output).open('x', encoding='utf-8') as stream:
            for row in rows:
                value = dict(zip(columns, row))
                value['raw_hex'] = value.pop('raw').hex()
                try:
                    value['raw_fields'] = decode_event(bytes.fromhex(value['raw_hex']))
                except ValueError as error:
                    value['raw_decode_error'] = str(error)
                stream.write(json.dumps(value, ensure_ascii=True, separators=(',', ':')) + '\n')
                count += 1
        return count
    finally:
        connection.close()


def export_read_samples(connection, output, source_only=False, limit=100):
    """Small human-readable examples; never presented as the complete trace."""
    if not integer(limit, True, maximum=10000):
        raise ValueError('bounded read example limit required')
    columns = ['record_number', 'start_ns', 'end_ns', 'sys_start_ns', 'sys_end_ns',
        'syscall_nr', 'tgid', 'tid', 'thread_birth_ns', 'device', 'inode', 'mount_id',
        'offset_before', 'requested_bytes', 'returned_bytes', 'result', 'duration_ns',
        'interval_scope', 'object_key']
    query = 'SELECT ' + ','.join(columns) + " FROM selected WHERE operation IN ('read','readv')"
    if source_only:
        query += " AND object_key IN (SELECT object_key FROM object_paths WHERE scope_kind='SOURCE_CORPUS')"
    query += ' ORDER BY record_number LIMIT ?'
    with Path(output).open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns + ['syscall_duration_ns',
            'selected_interval_microseconds', 'syscall_microseconds', 'inventory_paths_json'])
        writer.writeheader()
        count = 0
        for raw in connection.execute(query, (limit,)):
            value = dict(zip(columns, raw))
            value['syscall_duration_ns'] = value['sys_end_ns'] - value['sys_start_ns']
            value['selected_interval_microseconds'] = value['duration_ns'] / 1000
            value['syscall_microseconds'] = value['syscall_duration_ns'] / 1000
            value['inventory_paths_json'] = json.dumps([row[0] for row in connection.execute(
                'SELECT path FROM object_paths WHERE object_key=? ORDER BY path', (value['object_key'],))], ensure_ascii=True)
            writer.writerow(value)
            count += 1
    return {'path': str(output), 'records': count, 'limit': limit,
        'selection': 'FIRST_SELECTED_SOURCE_READS' if source_only else 'FIRST_SELECTED_READS',
        'coverage': 'BOUNDED_EXAMPLES_NOT_THE_FULL_RAW_TRACE'}


def database_summary(connection):
    scalar = lambda query: connection.execute(query).fetchone()[0] or 0
    read = "operation IN ('read','readv')"
    totals = connection.execute('''SELECT COUNT(*),
        COALESCE(SUM(requested_bytes),0),COALESCE(SUM(returned_bytes),0),
        COALESCE(SUM(CASE WHEN interval_scope='OUTERMOST_VFS_OPERATION' THEN duration_ns ELSE 0 END),0),
        MAX(CASE WHEN interval_scope='OUTERMOST_VFS_OPERATION' THEN duration_ns ELSE NULL END),
        SUM(result<0),SUM(result=0),SUM(interval_scope='OUTERMOST_VFS_OPERATION'),
        COALESCE(SUM(sys_end_ns-sys_start_ns),0),MAX(sys_end_ns-sys_start_ns)
        FROM selected WHERE ''' + read).fetchone()
    size_hist, returned_hist, duration_hist = Counter(), Counter(), Counter()
    for requested, returned, duration, interval in connection.execute(
            'SELECT requested_bytes,returned_bytes,duration_ns,interval_scope FROM selected WHERE ' + read):
        if requested is not None:
            size_hist[log2_bin(requested)] += 1
        returned_hist[log2_bin(returned)] += 1
        if interval == 'OUTERMOST_VFS_OPERATION':
            duration_hist[log2_bin(duration)] += 1
    fault_outcomes = dict(connection.execute("SELECT fault_outcome,COUNT(*) FROM selected WHERE operation='fault' GROUP BY fault_outcome"))
    fault_flags = Counter()
    for raw, count in connection.execute("SELECT fault_return_names,COUNT(*) FROM selected WHERE operation='fault' GROUP BY fault_return_names"):
        for name in json.loads(raw):
            fault_flags[name] += count
    summary = {
        'selected_events': scalar('SELECT COUNT(*) FROM selected'),
        'unique_regular_files': scalar('SELECT COUNT(*) FROM objects WHERE regular_file=1 AND (read_calls>0 OR filemap_fault_attempts>0 OR mm_fault_attempts>0)'),
        'unique_regular_files_definition': 'BOOT_MOUNT_DEVICE_INODE_GENERATION_OBJECTS_WITH_READ_OR_FILE_FAULT_ATTEMPT; NOT_INPUT_FILE_COUNT; NOT_ALL_INTERFACE_COVERAGE',
        'unique_regular_objects_including_open_and_mapping': scalar('SELECT COUNT(*) FROM objects WHERE regular_file=1'),
        'unique_regular_files_opened_successfully': scalar('SELECT COUNT(*) FROM objects WHERE regular_file=1 AND open_success_calls>0'),
        'unique_regular_files_read_attempted': scalar('SELECT COUNT(*) FROM objects WHERE regular_file=1 AND read_calls>0'),
        'unique_regular_files_read_positive_bytes': scalar("SELECT COUNT(DISTINCT object_key) FROM selected WHERE regular_file=1 AND returned_bytes>0 AND " + read),
        'unique_regular_files_mapped_successfully': None,
        'unique_regular_files_with_filemap_fault_attempt': scalar('SELECT COUNT(*) FROM objects WHERE regular_file=1 AND filemap_fault_attempts>0'),
        'unique_regular_files_with_mm_fault_attempt': scalar('SELECT COUNT(*) FROM objects WHERE regular_file=1 AND mm_fault_attempts>0'),
        'unique_objects_by_operation': dict(connection.execute('SELECT operation,COUNT(DISTINCT object_key) FROM selected GROUP BY operation')),
        'selected_events_by_operation': dict(connection.execute('SELECT operation,COUNT(*) FROM selected GROUP BY operation')),
        'unresolved_object_events': scalar("SELECT COUNT(*) FROM selected WHERE object_key IS NULL AND (fault_context IS NULL OR fault_context!='NO_FILE_VMA')"),
        'unresolved_task_events': scalar('SELECT COUNT(*) FROM selected WHERE task_id IS NULL'),
        'read_calls': totals[0], 'read_requested_bytes': totals[1], 'read_returned_bytes': totals[2],
        'read_requested_unknown_calls': scalar('SELECT COUNT(*) FROM selected WHERE requested_bytes IS NULL AND ' + read),
        'read_vfs_calls': totals[7] or 0,
        'read_duration_unresolved_or_pre_vfs_calls': totals[0] - (totals[7] or 0),
        'read_duration_ns': totals[3], 'read_mean_duration_ns': totals[3] / totals[7] if totals[7] else None,
        'read_max_duration_ns': totals[4], 'read_error_calls': totals[5] or 0,
        'read_zero_result_calls': totals[6] or 0,
        'read_syscall_duration_ns': totals[8],
        'read_mean_syscall_duration_ns': totals[8] / totals[0] if totals[0] else None,
        'read_max_syscall_duration_ns': totals[9],
        'read_duration_scope': 'SUM_OF_SELECTED_OUTERMOST_VFS_OPERATION_ELAPSED_NS; OVERLAPPING_THREADS; NOT_ADDITIVE_WALLCLOCK_COMPONENT_OR_DISK_SERVICE_TIME',
        'read_requested_size_histogram': histogram(size_hist, 'bytes'),
        'read_returned_size_histogram': histogram(returned_hist, 'bytes'),
        'read_duration_histogram': histogram(duration_hist, 'nanoseconds'),
        'filemap_fault_attempts': sum(fault_outcomes.values()),
        'filemap_fault_outcomes': fault_outcomes,
        'filemap_fault_return_flags': dict(fault_flags),
        'fault_scope': 'HANDLE_MM_FAULT_AND_FILEMAP_FAULT_ATTEMPTS_REPORTED_SEPARATELY; NESTED_NOT_ADDITIVE; RETRY_MAY_REPEAT_ONE_FAULT; NOT_PROCESS_MAJOR_MINOR_FAULT_COUNTS',
        'fault_mapping_quality': 'VM_FILE_OBJECT_AT_HOOK_ENTRY; NO_ANONYMOUS_FAULT_PATH_INVENTED',
        'mapping_scope': 'MMAP_CALLS_NOT_OBSERVED_BY_THIS_ABI; FILEMAP_FAULT_ATTEMPTS_SEPARATE; NO_MAPPING_BYTES_INFERRED',
        'inventory_paths_quality': 'DECLARED_QUIESCENT_READ_ONLY_DEVICE_INODE_SIZE_MATCH; NO_RUNTIME_MTIME_CTIME_VERIFICATION; NOT_KERNEL_RUNTIME_PATH_RESOLUTION',
        'path_resolved_objects': scalar('SELECT COUNT(DISTINCT object_key) FROM object_paths'),
        'object_identity_quality_counts': dict(connection.execute('SELECT object_quality,COUNT(*) FROM selected GROUP BY object_quality'))}
    for prefix, scope in (('source', 'SOURCE_CORPUS'), ('system_runtime', 'SYSTEM_RUNTIME')):
        predicate = 'object_key IN (SELECT object_key FROM object_paths WHERE scope_kind=?)'
        count = lambda condition: connection.execute('SELECT COUNT(*) FROM objects WHERE regular_file=1 AND ' + condition + ' AND ' + predicate,
            (scope,)).fetchone()[0]
        summary[prefix + '_unique_regular_files_opened_successfully'] = count('open_success_calls>0')
        summary[prefix + '_unique_regular_files_read_attempted'] = count('read_calls>0')
        summary[prefix + '_unique_regular_files_with_filemap_fault_attempt'] = count('filemap_fault_attempts>0')
        summary[prefix + '_unique_regular_files_with_mm_fault_attempt'] = count('mm_fault_attempts>0')
        summary[prefix + '_unique_regular_objects'] = count('1=1')
        source_read = connection.execute('SELECT COUNT(*),COALESCE(SUM(returned_bytes),0) FROM selected WHERE ' + read + ' AND ' + predicate,
            (scope,)).fetchone()
        summary[prefix + '_read_calls'] = source_read[0]
        summary[prefix + '_read_returned_bytes'] = source_read[1]
    summary['inventory_scope_mapping_quality'] = 'EXPLICIT_SOURCE_CORPUS_OR_SYSTEM_RUNTIME_INVENTORY_DECLARATIONS; UNMAPPED_OBJECTS_NOT_ASSIGNED_BY_PATH_GUESS'
    summary['mm_fault_attempts'] = scalar("SELECT COUNT(*) FROM selected WHERE operation='mm_fault'")
    summary['mm_file_backed_fault_attempts'] = scalar("SELECT COUNT(*) FROM selected WHERE operation='mm_fault' AND fault_context='FILE_BACKED_VMA'")
    summary['mm_no_file_vma_fault_attempts'] = scalar("SELECT COUNT(*) FROM selected WHERE operation='mm_fault' AND fault_context='NO_FILE_VMA'")
    summary['mm_unresolved_fault_attempts'] = scalar("SELECT COUNT(*) FROM selected WHERE operation='mm_fault' AND fault_context='UNRESOLVED_VMA_BACKING'")
    summary['mm_fault_outcomes'] = dict(connection.execute("SELECT fault_outcome,COUNT(*) FROM selected WHERE operation='mm_fault' GROUP BY fault_outcome"))
    summary['mm_fault_contexts'] = {}
    for context in ('FILE_BACKED_VMA', 'NO_FILE_VMA', 'UNRESOLVED_VMA_BACKING'):
        flag_counts = Counter()
        rows = connection.execute("SELECT fault_return_names,COUNT(*) FROM selected WHERE operation='mm_fault' AND fault_context=? GROUP BY fault_return_names", (context,))
        for raw, count in rows:
            for name in json.loads(raw):
                flag_counts[name] += count
        summary['mm_fault_contexts'][context] = {'return_flags': dict(flag_counts),
            'outcomes': dict(connection.execute("SELECT fault_outcome,COUNT(*) FROM selected WHERE operation='mm_fault' AND fault_context=? GROUP BY fault_outcome", (context,)))}
    summary['no_file_vma_quality'] = 'VMA_VM_FILE_READ_SUCCESSFULLY_AS_NULL; NOT_VMA_IS_ANONYMOUS_PROOF; SPECIAL_NO_FILE_MAPPINGS_MAY_BE_INCLUDED'
    return summary


def decode_event(raw):
    if len(raw) != EVENT.size:
        raise ValueError('TRUNCATED_EVENT')
    event = dict(zip(EVENT_FIELDS, EVENT.unpack(raw)))
    if event['magic'] != MAGIC or event['version'] != 1 or event['size'] != EVENT.size:
        raise ValueError('EVENT_MAGIC_VERSION_SIZE')
    if event['kind'] not in OPERATIONS:
        raise ValueError('UNKNOWN_OPERATION')
    if event['flags'] & ~KNOWN_FLAGS:
        raise ValueError('UNKNOWN_EVENT_FLAGS')
    if event['flags'] & REGULAR_FILE and event['flags'] & DIRECTORY:
        raise ValueError('CONTRADICTORY_INODE_TYPE_FLAGS')
    if event['flags'] & (REGULAR_FILE | DIRECTORY) and not event['flags'] & OBJECT_VALID:
        raise ValueError('INODE_TYPE_WITHOUT_OBJECT_IDENTITY')
    if event['flags'] & NO_FILE_VMA and (event['kind'] != 6 or event['flags'] & OBJECT_VALID):
        raise ValueError('CONTRADICTORY_NO_FILE_VMA_FLAG')
    if (event['start_ns'] == 0 or event['end_ns'] < event['start_ns'] or event['end_ns'] > SQL_MAX
            or any(event[key] == 0 for key in ('tgid', 'tid', 'process_birth_ns', 'thread_birth_ns', 'domain_id', 'caller_cgroup_id'))
            or event['cpu'] >= MAX_CPU or event['sequence'] == 0):
        raise ValueError('INVALID_TIME_OR_CALLER_IDENTITY')
    if event['flags'] & OBJECT_VALID and (event['inode'] == 0 or event['mount_id'] == 0 or event['file_size'] < 0):
        raise ValueError('INVALID_OBJECT_IDENTITY')
    if event['flags'] & SYSCALL_VALID and not (0 < event['sys_start_ns'] <= event['start_ns'] <= event['end_ns'] <= event['sys_end_ns'] <= SQL_MAX):
        raise ValueError('INVALID_SYSCALL_CORRELATION_INTERVAL')
    if event['flags'] & SYSCALL_VALID and event['syscall_nr'] not in {
            1: {0, 17}, 2: {19, 295, 327}, 3: {78, 217}, 4: {2, 85, 257, 437}, 5: set(), 6: set()}[event['kind']]:
        raise ValueError('SYSCALL_KIND_MISMATCH')
    if event['kind'] not in (5, 6) and not event['flags'] & SYSCALL_VALID:
        raise ValueError('MISSING_NATIVE_SYSCALL_CORRELATION')
    if event['kind'] in (5, 6) and (not event['flags'] & FAULT_RETURN_VALID or
            event['flags'] & SYSCALL_VALID or event['syscall_nr'] != 0xffffffff):
        raise ValueError('INVALID_FAULT_RETURN_OR_SYSCALL_CONTRACT')
    if event['kind'] in (1, 2) and event['result'] >= 0 and event['flags'] & REQUESTED_VALID and event['result'] > event['requested_bytes']:
        raise ValueError('RETURNED_BYTES_EXCEED_REQUESTED')
    return event


def event_row(event, raw, number, window, regular_objects):
    flags, operation = event['flags'], OPERATIONS[event['kind']]
    available = bool(flags & OBJECT_VALID)
    mount, dev, inode, generation = [event[key] for key in ('mount_id', 'device', 'inode', 'generation')]
    object_key = '/'.join(str(value) for value in (window['boot_id'], mount, dev, inode, generation)) if available else None
    object_quality = ('BOOT_MOUNT_DEVICE_INODE_GENERATION_NO_GLOBAL_LIFETIME_PROOF'
        if available and mount else 'BOOT_DEVICE_INODE_GENERATION_MOUNT_UNRESOLVED' if available else
        'NO_FILE_VMA_NOT_A_FILE_OBJECT' if flags & NO_FILE_VMA else 'UNRESOLVED_OBJECT')
    requested = event['requested_bytes'] if flags & REQUESTED_VALID and event['requested_bytes'] <= SQL_MAX else None
    result = event['result']
    returned = max(0, result) if operation in ('read', 'readv') else 0
    fault_outcome, fault_flags = (None, [])
    if operation in ('fault', 'mm_fault'):
        fault_outcome, fault_flags = fault_classification(event['vm_fault_result']) if flags & FAULT_RETURN_VALID else ('UNRESOLVED_RETURN_FLAGS', [])
    return {'record_number': number, 'raw_offset': (number - 1) * EVENT.size, 'raw': raw,
        'operation': operation, 'temporal_scope': temporal_scope(event['start_ns'], event['end_ns'], window['release_ns'], window['end_ns']),
        'valid': 1, 'object_key': object_key, 'object_quality': object_quality,
        'regular_file': (1 if flags & REGULAR_FILE else 0 if flags & DIRECTORY else
            1 if (dev, inode, event['file_size']) in regular_objects else
            0 if operation == 'directory' else None) if available else None,
        'device': str(dev) if available else None, 'inode': str(inode) if available else None,
        'generation': str(generation) if available else None, 'mount_id': str(mount) if available else None,
        'size': event['file_size'] if available else None,
        'start_ns': event['start_ns'], 'end_ns': event['end_ns'], 'duration_ns': event['end_ns'] - event['start_ns'],
        'interval_scope': 'FILEMAP_FAULT_ATTEMPT' if operation == 'fault' else 'HANDLE_MM_FAULT_ATTEMPT' if operation == 'mm_fault' else 'SYSCALL' if operation == 'open' else
            'OUTERMOST_VFS_OPERATION' if available else 'UNRESOLVED_VFS_OR_PRE_VFS_SYSCALL',
        'sys_start_ns': event['sys_start_ns'] if flags & SYSCALL_VALID else None,
        'sys_end_ns': event['sys_end_ns'] if flags & SYSCALL_VALID else None,
        'syscall_nr': event['syscall_nr'] if flags & SYSCALL_VALID else None,
        'syscall_result': event['syscall_result'] if flags & SYSCALL_VALID else None,
        'domain_id': str(event['domain_id']), 'caller_cgroup_id': str(event['caller_cgroup_id']),
        'task_id': window['associations'].get(event['caller_cgroup_id']),
        'tgid': event['tgid'], 'tid': event['tid'], 'process_birth_ns': str(event['process_birth_ns']),
        'thread_birth_ns': str(event['thread_birth_ns']), 'cpu': event['cpu'], 'sequence': str(event['sequence']),
        'requested_bytes': requested, 'result': result, 'returned_bytes': returned,
        'offset_before': event['offset_before'] if flags & OFFSET_VALID else None,
        'fault_address': str(event['fault_address']) if operation in ('fault', 'mm_fault') else None,
        'fault_pgoff': str(event['fault_pgoff']) if operation in ('fault', 'mm_fault') else None,
        'fault_input_flags': str(event['fault_input_flags']) if flags & FAULT_FLAGS_VALID else None,
        'fault_return_flags': event['vm_fault_result'] if flags & FAULT_RETURN_VALID else None,
        'fault_context': ('FILEMAP_REFILL_SUBSET' if operation == 'fault' else
            'FILE_BACKED_VMA' if available else 'NO_FILE_VMA' if flags & NO_FILE_VMA else 'UNRESOLVED_VMA_BACKING') if operation in ('fault', 'mm_fault') else None,
        'fault_outcome': fault_outcome, 'fault_return_names': json.dumps(fault_flags), 'flags': flags}


def ingest_events(path, connection, window, registered_domains, regular_objects=(), maximum_bytes=MAX_TRACE_BYTES):
    path = regular(path, maximum_bytes)
    columns = [row[1] for row in connection.execute('PRAGMA table_info(events)')]
    insert = 'INSERT INTO events VALUES(' + ','.join('?' for _ in columns) + ')'
    digest, counters, issues, cpu_last, cpu_counts = hashlib.sha256(), Counter(), Counter(), {}, Counter()
    cpu_previous, cpu_min, cpu_reordered = {}, {}, Counter()
    rows, malformed, sequence_rows, examples = [], [], [], []

    def issue(reason, number):
        issues[reason] += 1
        if len(examples) < 20:
            examples.append({'record_number': number, 'reason': reason})

    def flush():
        connection.executemany(insert, rows)
        connection.executemany('INSERT INTO malformed VALUES(?,?)', malformed)
        connection.executemany('INSERT OR IGNORE INTO cpu_sequences VALUES(?,?,?)', sequence_rows)
        del rows[:]
        del malformed[:]
        del sequence_rows[:]

    # Keep decoding/SQL batches bounded, but import the new derived tables in
    # one transaction instead of syncing a rollback journal every 4096 rows.
    # DELETE journaling and FULL synchronization remain unchanged. A runtime
    # or SQL failure rolls back every ingested row and cannot yield a summary.
    try:
        with path.open('rb') as stream:
            before = os.fstat(stream.fileno())
            while True:
                raw = stream.read(EVENT.size)
                if not raw:
                    break
                digest.update(raw)
                counters['bytes'] += len(raw)
                counters['records'] += 1
                number = counters['records']
                try:
                    event = decode_event(raw)
                    if event['domain_id'] not in registered_domains:
                        raise ValueError('UNREGISTERED_DOMAIN')
                    if ('collector_start_ns' in window and not
                            window['collector_start_ns'] <= event['start_ns'] <= event['end_ns'] <= window['collector_end_ns']):
                        raise ValueError('RAW_EVENT_OUTSIDE_COLLECTOR_WINDOW')
                    row = event_row(event, raw, number, window, regular_objects)
                    cpu, sequence = event['cpu'], event['sequence']
                    previous = cpu_previous.get(cpu, 0)
                    if sequence < previous:
                        cpu_reordered[cpu] += 1
                    cpu_previous[cpu] = sequence
                    cpu_last[cpu] = max(sequence, cpu_last.get(cpu, 0))
                    cpu_min[cpu] = min(sequence, cpu_min.get(cpu, sequence))
                    sequence_rows.append((cpu, str(sequence), number))
                    cpu_counts[event['cpu']] += 1
                    counters[row['temporal_scope']] += 1
                    if row['temporal_scope'] == 'CROSSES_WINDOW_BOUNDARY':
                        issue('OPERATION_CROSSES_TIMING_WINDOW', number)
                except ValueError as error:
                    reason = str(error)
                    issue(reason, number)
                    malformed.append((number, reason))
                    row = {'record_number': number, 'raw_offset': (number - 1) * EVENT.size,
                        'raw': raw, 'valid': 0, 'temporal_scope': 'MALFORMED_RETAINED'}
                rows.append(tuple(row.get(name) for name in columns))
                if len(rows) >= 4096:
                    flush()
            after = os.fstat(stream.fileno())
        if rows:
            flush()
        cpu_unique = dict(connection.execute('SELECT cpu,COUNT(*) FROM cpu_sequences GROUP BY cpu'))
        for cpu, count in cpu_counts.items():
            if cpu_unique[cpu] != count:
                issue('DUPLICATE_CPU_SEQUENCE', 0)
            if cpu_min[cpu] != 1 or cpu_last[cpu] != cpu_unique[cpu]:
                issue('CPU_SEQUENCE_RANGE_GAP', 0)
        if any(getattr(before, name) != getattr(after, name) for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            issue('RAW_FILE_CHANGED_DURING_READ', 0)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return {'path': str(path), 'sha256': digest.hexdigest(), **counters,
        'issues': dict(issues), 'issue_examples': examples,
        'cpu_last_sequence': cpu_last, 'cpu_min_sequence': cpu_min,
        'cpu_observed_records': dict(cpu_counts), 'cpu_unique_sequences': cpu_unique,
        'cpu_reordered_observations': dict(cpu_reordered),
        'sequence_order_scope': 'PER_CPU_UNIQUENESS_RANGE_COUNTS; RING_RESERVATION_ORDER_CAN_DIFFER_FROM_ASSIGNMENT_ORDER; REORDER_ALONE_NOT_LOSS'}


def bind_collector(meta, final, profile, profile_source, capture=None):
    """Check declarations against raw inputs, not against a copied summary."""
    window = profile_window(profile)
    if any(type(value.get('schema_version')) is not int or value['schema_version'] != 1 for value in (meta, final)):
        raise ValueError('collector metadata schema version 1 required')
    if (meta.get('mode') != 'events' or meta.get('record_bytes') != EVENT.size
            or meta.get('vm_fault_flags_contract') != FAULT_FLAGS_CONTRACT
            or meta.get('page_size') != 4096
            or meta.get('event_magic') != MAGIC or meta.get('event_abi_version') != 1
            or meta.get('endian') != 'little'
            or meta.get('native_syscall_abi') != 'X86_64_EXCLUDING_TS_COMPAT_AND_X32'
            or meta.get('cpu_seq_contract') != 'ONE_BASED_ATTEMPT_BEFORE_RESERVATION_PER_CPU'
            or not integer(meta.get('possible_cpus'), True, maximum=MAX_CPU)
            or not integer(meta.get('max_bytes'), True)
            or not integer(meta.get('ring_bytes'), True)
            or not 16 * 1024 ** 2 <= meta['ring_bytes'] <= 512 * 1024 ** 2
            or meta['ring_bytes'] & (meta['ring_bytes'] - 1) != 0
            or not isinstance(meta.get('required_programs'), list)
            or any(not isinstance(name, str) for name in meta['required_programs'])
            or set(meta['required_programs']) != PROGRAMS or len(meta['required_programs']) != len(PROGRAMS)
            or meta.get('boot_id') != window['boot_id'] or final.get('boot_id') != window['boot_id']
            or not isinstance(meta.get('run_id'), str) or not meta['run_id']
            or final.get('run_id') != meta['run_id']
            or not integer(meta.get('start_monotonic_ns'))
            or final.get('start_monotonic_ns') != meta['start_monotonic_ns']
            or not integer(final.get('end_monotonic_ns'))
            or not meta['start_monotonic_ns'] <= window['release_ns'] < window['end_ns'] <= final['end_monotonic_ns']):
        raise ValueError('collector ABI, boot, run or enclosing observation interval mismatch')
    if any(final.get(key) != value for key, value in meta.items()):
        raise ValueError('READY/final immutable metadata differs')
    for field in ('bpf_sha256', 'binary_sha256', 'bpf_source_sha256', 'header_sha256'):
        value = meta.get(field)
        if not isinstance(value, str) or len(value) != 64 or any(char not in '0123456789abcdef' for char in value):
            raise ValueError('collector source/binary digest binding missing')
    registered = meta.get('domains')
    if not isinstance(registered, list) or not 1 <= len(registered) <= 16 or final.get('domains') != registered:
        raise ValueError('matching complete registered cgroup declarations required')
    roots = [cgroup_identity(value) for value in registered]
    if len({value['inode'] for value in roots}) != len(roots):
        raise ValueError('duplicate registered cgroup identities')
    if any(left['path'].startswith(right['path'] + '/') or right['path'].startswith(left['path'] + '/')
            for index, left in enumerate(roots) for right in roots[index + 1:]):
        raise ValueError('registered cgroup roots overlap')
    if any(type(value.get('level')) is not int or value['level'] != len(Path(value['path']).parts) - 4
            for value in registered):
        raise ValueError('registered cgroup ancestor levels invalid')
    root = window['root_cgroup']
    parents = [value for value in roots if value['device'] == root['device'] and
        (root['path'] == value['path'] or root['path'].startswith(value['path'] + '/'))]
    if len(parents) != 1:
        raise ValueError('exactly one registered root must contain the execution cgroup')
    if meta['run_id'] != window['run_id'] and capture is None:
        raise ValueError('different collector/run labels require an explicit capture binding')
    if capture is not None:
        if (capture.get('collector_run_id') != meta['run_id'] or capture.get('profile_run_id') != window['run_id']
                or capture.get('file_access_backend') != meta.get('backend')
                or capture.get('profile_run_sha256') != profile_source['sha256']
                or capture.get('boot_id') != window['boot_id']
                or capture.get('release_ns') != window['release_ns'] or capture.get('end_ns') != window['end_ns']
                or capture.get('makespan_ns') != window['end_ns'] - window['release_ns']
                or cgroup_identity(capture.get('collector_cgroup')) != parents[0]
                or cgroup_identity(capture.get('inner_root_cgroup')) != root):
            raise ValueError('capture does not bind exact collector, profile, boot, cgroups and timing')
        configured_backend = profile.get('config', {}).get('file_access_backend')
        if configured_backend is not None and configured_backend != meta.get('backend'):
            raise ValueError('execution configuration declares another probe backend')
        expected_ready = {**meta, 'type': 'READY'}
        if (capture.get('ready') != expected_ready
                or not integer(capture.get('ready_received_monotonic_ns'))
                or not meta['start_monotonic_ns'] <= capture['ready_received_monotonic_ns'] <= window['release_ns']
                or not integer(capture.get('finalized_monotonic_ns'))
                or capture['finalized_monotonic_ns'] < final['end_monotonic_ns']):
            raise ValueError('READY gate or collector finalization receipt invalid')
    return {**window, 'collector_start_ns': meta['start_monotonic_ns'],
        'collector_end_ns': final['end_monotonic_ns']}, {value['inode'] for value in roots}


def health_issues(meta, final, raw):
    issues = Counter(raw['issues'])
    if (not integer(final.get('persisted_records')) or final['persisted_records'] != raw.get('records', 0)
            or not integer(final.get('bytes')) or final['bytes'] != raw.get('bytes', 0)
            or final.get('events_sha256') != raw['sha256']):
        issues['RAW_COUNT_BYTES_OR_SHA256_MISMATCH'] += 1
    health = final.get('health')
    if not isinstance(health, dict) or set(health) != HEALTH or any(not integer(value) for value in health.values()):
        issues['MISSING_OR_INVALID_HEALTH_COUNTERS'] += 1
    else:
        for name, value in health.items():
            if value and name != 'nested_hooks':
                issues['COLLECTOR_HEALTH_' + name] += value
    for field in ('pending_syscalls', 'pending_vfs_calls', 'pending_fault_calls', 'pending_mm_fault_calls'):
        value = final.get(field)
        if not integer(value) or value:
            issues['PENDING_OR_MISSING_' + field] += 1
    if type(final.get('timed_out')) is not bool or final['timed_out']:
        issues['COLLECTOR_TIMEOUT_OR_UNKNOWN'] += 1
    for field in ('parser_errors', 'sequence_errors', 'cap_discarded', 'write_errors'):
        if not integer(final.get(field)) or final[field]:
            issues['COLLECTOR_ERROR_OR_MISSING_' + field] += 1
    for field in ('write_error', 'flush_error'):
        if field not in final or final[field] is not None:
            issues['COLLECTOR_ERROR_OR_MISSING_' + field] += 1
    if 'event_hashing' in meta and ('hash_error' not in final or final['hash_error'] is not None):
        issues['COLLECTOR_ERROR_OR_MISSING_hash_error'] += 1
    if final.get('observation_health') != 'COMPLETE_FOR_SELECTED_HOOKS':
        issues['COLLECTOR_DECLARED_INCOMPLETE_OR_UNKNOWN'] += 1
    programs = final.get('programs')
    if not isinstance(programs, list) or not programs:
        issues['MISSING_PROGRAM_HEALTH'] += 1
    else:
        names, ids = set(), set()
        for program in programs:
            if (not isinstance(program.get('name'), str) or not program['name'] or program['name'] in names
                    or not integer(program.get('id'), True) or program['id'] in ids
                    or not integer(program.get('recursion_misses'))):
                issues['INVALID_PROGRAM_HEALTH'] += 1
            else:
                names.add(program['name'])
                ids.add(program['id'])
                if program['recursion_misses']:
                    issues['PROGRAM_RECURSION_MISSES'] += program['recursion_misses']
        if names != PROGRAMS:
            issues['MISSING_OR_UNKNOWN_SELECTED_PROGRAMS'] += 1
    cpus = final.get('cpus')
    seen, emitted, attempted, dropped = set(), 0, 0, 0
    if not isinstance(cpus, list) or not cpus:
        issues['MISSING_PER_CPU_COUNTERS'] += 1
    else:
        for cpu in cpus:
            number = cpu.get('cpu')
            if (not integer(number, maximum=MAX_CPU - 1) or number in seen
                    or any(not integer(cpu.get(key)) for key in ('attempted', 'emitted', 'ring_drops'))):
                issues['INVALID_PER_CPU_COUNTERS'] += 1
                continue
            seen.add(number)
            emitted += cpu['emitted']
            attempted += cpu['attempted']
            dropped += cpu['ring_drops']
            if (cpu['attempted'] != raw['cpu_last_sequence'].get(number, 0)
                    or cpu['emitted'] != raw['cpu_observed_records'].get(number, 0)
                    or cpu['attempted'] != cpu['emitted'] + cpu['ring_drops']):
                issues['CPU_SEQUENCE_ENDPOINT_OR_COUNT_MISMATCH'] += 1
            if cpu['ring_drops']:
                issues['RING_DROPS'] += cpu['ring_drops']
        if not set(raw['cpu_observed_records']).issubset(seen) or emitted != raw.get('records', 0):
            issues['CPU_EMITTED_RAW_COUNT_MISMATCH'] += 1
        if integer(meta.get('possible_cpus'), True, maximum=MAX_CPU) and seen != set(range(meta['possible_cpus'])):
            issues['MISSING_POSSIBLE_CPU_ENDPOINTS'] += 1
    return dict(issues)


def tracefs_issues(meta, final):
    """Validate saved owned-probe identities and counters; never read Host tracefs."""
    issues = Counter()
    backend = meta.get('backend')
    if backend not in ('fentry', 'kprobe-tracefs'):
        return {'MISSING_OR_UNSUPPORTED_HOOK_BACKEND': 1}
    online = final.get('online_cpu_identity', {})
    if (not isinstance(meta.get('online_cpus'), str)
            or not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', meta['online_cpus'])
            or online.get('status') != 'STABLE' or online.get('initial') != meta['online_cpus']
            or online.get('current') != meta['online_cpus']):
        issues['CPU_ONLINE_IDENTITY_CHANGED_OR_UNKNOWN'] += 1
    cleanup = final.get('tracefs_cleanup', {})
    expected_count = len(TRACE_ANCHORS) if backend == 'kprobe-tracefs' else 0
    if (cleanup.get('status') != 'COMPLETE' or cleanup.get('owned_events') != expected_count
            or cleanup.get('remaining_owned_events') != 0 or cleanup.get('errors') != []):
        issues['OWNED_TRACEFS_CLEANUP_INCOMPLETE_OR_UNKNOWN'] += 1
    if backend == 'fentry':
        if (meta.get('hook_abi', {}).get('status') != 'FENTRY_BTF_PROTOTYPE_VERIFIED_BY_KERNEL_LOADER'
                or meta.get('kprobe_events') != [] or final.get('kprobe_event_health') != []):
            issues['FENTRY_BACKEND_ABI_OR_TRACEFS_RECEIPT_MISMATCH'] += 1
        return dict(issues)
    abi = meta.get('hook_abi', {})
    expected_abi = {'vfs_read': (4, 8, 'file'), 'vfs_readv': (5, 8, 'file'),
        'iterate_dir': (2, 4, 'file'), 'security_file_open': (1, 4, 'file'),
        'filemap_fault': (1, 4, 'vm_fault'), 'handle_mm_fault': (4, 4, 'vm_area_struct')}
    anchors = abi.get('anchors', [])
    if (abi.get('status') != 'VALIDATED' or abi.get('architecture') != 'x86_64'
            or abi.get('registers') != ['di', 'si', 'dx', 'cx', 'ax']
            or meta.get('kretprobe_maxactive') != 4096 or abi.get('kretprobe_maxactive') != 4096
            or not isinstance(anchors, list) or len(anchors) != len(expected_abi)):
        issues['KPROBE_ABI_GATE_NOT_ESTABLISHED'] += 1
    elif len({row.get('name') for row in anchors}) != len(expected_abi):
        issues['KPROBE_ABI_GATE_NOT_ESTABLISHED'] += 1
    else:
        for row in anchors:
            wanted = expected_abi.get(row.get('name'))
            if (wanted is None or not integer(row.get('btf_function_id'), True)
                    or (row.get('parameter_count'), row.get('return_bytes'), row.get('first_argument_struct')) != wanted):
                issues['KPROBE_ABI_GATE_NOT_ESTABLISHED'] += 1
    initial, terminal = meta.get('kprobe_events'), final.get('kprobe_event_health')
    if any(not isinstance(rows, list) or len(rows) != len(TRACE_ANCHORS) for rows in (initial, terminal)):
        issues['KPROBE_EVENT_TABLE_MISSING_OR_TRUNCATED'] += 1
        return dict(issues)
    by_program = {row.get('program_name'): row for row in initial}
    if set(by_program) != set(TRACE_ANCHORS) or len({row.get('program_name') for row in terminal}) != len(TRACE_ANCHORS):
        issues['KPROBE_EVENT_NAMES_MISSING_DUPLICATE_OR_UNKNOWN'] += 1
        return dict(issues)
    identities = set()
    immutable = ('program_name', 'name', 'group', 'anchor', 'is_return', 'maxactive',
        'tracefs_root', 'definition', 'device', 'directory_inode', 'event_id', 'initial_hits', 'initial_misses')
    for end in terminal:
        program = end.get('program_name')
        start = by_program.get(program)
        if start is None:
            issues['KPROBE_EVENT_NAMES_MISSING_DUPLICATE_OR_UNKNOWN'] += 1
            continue
        anchor, is_return = TRACE_ANCHORS[program]
        name = end.get('name', '')
        definition = end.get('definition')
        prefix = 'r4096' if is_return else 'p'
        expected_definition = prefix + ':allox_file_access/' + name + ' ' + anchor
        if (any(start.get(key) != end.get(key) for key in immutable)
                or not re.fullmatch(r'alloxfa_[0-9a-f]{32}_' + re.escape(program), name)
                or end.get('group') != 'allox_file_access' or end.get('anchor') != anchor
                or type(end.get('is_return')) is not bool or end['is_return'] != is_return
                or end.get('maxactive') != (4096 if is_return else None)
                or end.get('tracefs_root') not in ('/sys/kernel/tracing', '/sys/kernel/debug/tracing')
                or definition not in (expected_definition, expected_definition + '+0')
                or any(not integer(end.get(key), True) for key in ('device', 'directory_inode', 'event_id'))):
            issues['KPROBE_OWNED_IDENTITY_OR_DEFINITION_CHANGED'] += 1
        identity = (end.get('device'), end.get('directory_inode'), end.get('event_id'))
        if identity in identities:
            issues['KPROBE_DUPLICATE_EVENT_IDENTITY'] += 1
        identities.add(identity)
        for row in (start, end):
            if (row.get('profile_status') != 'OBSERVED' or row.get('identity_status') != 'MATCH'
                    or row.get('error') is not None
                    or any(not integer(row.get(key)) for key in ('initial_hits', 'initial_misses', 'hits', 'misses', 'misses_delta'))
                    or not integer(row.get('collection_start_ns')) or not integer(row.get('collection_end_ns'))
                    or row['collection_start_ns'] > row['collection_end_ns']):
                issues['KPROBE_PROFILE_UNKNOWN_OR_MALFORMED'] += 1
                continue
            if row['hits'] < row['initial_hits'] or row['misses'] < row['initial_misses'] or row['misses_delta'] != row['misses'] - row['initial_misses']:
                issues['KPROBE_COUNTER_ROLLBACK_OR_DELTA_MISMATCH'] += 1
            if row['misses_delta'] != 0:
                issues['KPROBE_MISSED_PROBES'] += row['misses_delta']
        if (integer(start.get('collection_end_ns')) and integer(end.get('collection_start_ns'))
                and (start['collection_end_ns'] > end['collection_start_ns'] or end['collection_start_ns'] < final['end_monotonic_ns'])):
            issues['KPROBE_PROFILE_BOUNDARIES_REVERSED'] += 1
        if (all(integer(row.get(key)) for row in (start, end) for key in ('hits', 'misses'))
                and (end['hits'] < start['hits'] or end['misses'] < start['misses'])):
            issues['KPROBE_COUNTER_ROLLBACK_OR_DELTA_MISMATCH'] += 1
    return dict(issues)


def write_json(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=True)
        stream.write('\n')


def analyze(collector_dir, profile_run, output_dir, inventory_paths=(), capture_path=None,
        inventory_database=None, expected_inventory_sha256=None):
    root, profile_path, output = Path(collector_dir), Path(profile_run), Path(output_dir)
    if profile_path.is_dir():
        profile_path /= 'profile-run.json'
    meta, meta_source = json_input(root / 'meta.json')
    final, final_source = json_input(root / 'final.json')
    profile, profile_source = json_input(profile_path)
    sources = {'collector_meta': meta_source, 'collector_final': final_source, 'profile_run': profile_source}
    if capture_path is None and (root.parent / 'capture.json').is_file():
        capture_path = root.parent / 'capture.json'
    capture = None
    if capture_path is not None:
        capture, sources['capture'] = json_input(capture_path)
        if capture.get('final_sha256') != final_source['sha256']:
            raise ValueError('capture final receipt digest mismatch')
    window, registered = bind_collector(meta, final, profile, profile_source, capture)
    if inventory_database is not None and inventory_paths:
        raise ValueError('choose raw inventories or one verified read-only inventory index')
    inventory, regular_objects = [], set()
    sources['inventories'] = []
    for path in inventory_paths:
        value, source = json_input(path)
        rows = inventory_rows(value, window['boot_id'])
        inventory.extend(rows)
        regular_objects.update((int(row[0]), int(row[1]), row[2]) for row in rows)
        sources['inventories'].append(source)
    if inventory_database is not None:
        source, manifest = inventory_index_manifest(inventory_database, window['boot_id'])
        if expected_inventory_sha256 is not None and source['sha256'] != expected_inventory_sha256:
            raise ValueError('inventory-index external digest mismatch')
        sources['inventory_database'] = {**source, 'manifest': manifest}
    output.mkdir(parents=True)
    database = output / 'events.sqlite'
    connection = initialize_database(database, inventory, inventory_database)
    try:
        if inventory_database is not None:
            regular_objects = RegularInventoryLookup(connection)
        raw = ingest_events(root / 'events.bin', connection, window, registered, regular_objects)
        top = export_file_rows(connection, output / 'per-file.csv')
        examples = export_read_samples(connection, output / 'read-samples.csv')
        source_examples = export_read_samples(connection, output / 'source-read-samples.csv', source_only=True)
        metrics = database_summary(connection)
        issues = health_issues(meta, final, raw)
        issues.update(tracefs_issues(meta, final))
        if capture is None:
            issues['READY_GATE_NOT_ESTABLISHED'] = 1
        summary = {'schema_version': 1, 'status': 'INCOMPLETE' if issues else 'COMPLETE_FOR_SELECTED_HOOKS',
            'authority': 'COOPERATIVE_PERFORMANCE_DIAGNOSTIC; BINDINGS_AND_RECOMPUTATION_NOT_AUTHENTICATION',
            'run_id': window['run_id'], 'collector_run_id': meta['run_id'], 'boot_id': window['boot_id'],
            'file_access_backend': meta.get('backend'),
            'analyzer': {'path': str(Path(__file__).resolve()),
                'sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'python_version': sys.version, 'sqlite_version': sqlite3.sqlite_version},
            'window': {key: window[key] for key in ('release_ns', 'end_ns', 'root_cgroup')},
            'sources': sources, 'raw_events': raw, 'issues': issues,
            'timing_scope_counts': {key: raw.get(key, 0) for key in ('IN_WINDOW', 'BEFORE', 'AFTER', 'CROSSES_WINDOW_BOUNDARY')},
            'metrics': metrics, 'top_objects_by_read_elapsed': top,
            'collector_health': {key: final.get(key) for key in ('observation_health', 'health',
                'programs', 'cpus', 'pending_syscalls', 'pending_vfs_calls', 'pending_fault_calls',
                'pending_mm_fault_calls', 'parser_errors', 'sequence_errors', 'cap_discarded',
                'write_errors', 'write_error', 'flush_error', 'kprobe_event_health',
                'tracefs_cleanup', 'online_cpu_identity', 'hash_error')},
            'artifacts': {'database': 'events.sqlite', 'per_file': 'per-file.csv',
                'read_examples': examples, 'source_read_examples': source_examples},
            'association_quality': 'UNIQUE_DECLARED_TASK_CGROUP_MEMBERSHIP_ONLY; SHARED_CGROUP_THREADS_NOT_GUESSED',
            'object_regular_file_classification': 'KERNEL_INODE_TYPE_FLAGS_OR_MATCH_TO_DECLARED_READ_ONLY_REGULAR_FILE_INVENTORY; OTHERWISE_UNKNOWN',
            'scope': 'SELECTED_NATIVE_SYSCALL_CORRELATED_OUTERMOST_VFS_READ_READV_DIRECTORY_OPEN_AND_HANDLE_MM_FAULT_FILEMAP_FAULT; NOT_ALL_FILE_INTERFACES',
            'limitations': ['No anonymous page-fault-to-file mapping is invented; NO_FILE_VMA is not proof of vma_is_anonymous.',
                'handle_mm_fault and nested filemap_fault are separate attempts, not additive completed process major/minor fault counts.',
                'A successful open or mmap does not establish that file contents were accessed.',
                'Cumulative overlapping VFS elapsed time is not a decomposition of wall-clock time.',
                'No mmap bytes or physical disk service time is inferred from VFS duration.',
                'Static inventory paths are not kernel-resolved runtime paths or content versions.']}
    finally:
        connection.close()
    write_json(output / 'summary.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collector-dir', type=Path)
    parser.add_argument('--profile-run', type=Path)
    parser.add_argument('--inventory', type=Path, action='append', default=[])
    parser.add_argument('--inventory-database', type=Path)
    parser.add_argument('--expected-inventory-sha256')
    parser.add_argument('--build-inventory-index', type=Path)
    parser.add_argument('--boot-id')
    parser.add_argument('--capture', type=Path)
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--database', type=Path, help='Export existing database rows instead of analyzing')
    parser.add_argument('--detail-output', type=Path)
    parser.add_argument('--object-key')
    parser.add_argument('--device', type=int)
    parser.add_argument('--inode', type=int)
    parser.add_argument('--tid', type=int)
    parser.add_argument('--thread-birth-ns', type=int)
    parser.add_argument('--start-ns', type=int)
    parser.add_argument('--end-ns', type=int)
    args = parser.parse_args()
    if args.build_inventory_index is not None:
        if not args.inventory or not args.boot_id:
            parser.error('--inventory (repeatable) and --boot-id required to build inventory index')
        print(json.dumps(build_inventory_index(args.inventory, args.build_inventory_index, args.boot_id)))
    elif args.database is not None:
        if args.detail_output is None:
            parser.error('--detail-output required with --database')
        count = export_detail(args.database, args.detail_output, args.object_key, args.device, args.inode,
            args.tid, args.thread_birth_ns, args.start_ns, args.end_ns)
        print(json.dumps({'exported_records': count, 'path': str(args.detail_output)}))
    else:
        if any(value is None for value in (args.collector_dir, args.profile_run, args.output_dir)):
            parser.error('--collector-dir, --profile-run and --output-dir required')
        summary = analyze(args.collector_dir, args.profile_run, args.output_dir, args.inventory, args.capture,
            args.inventory_database, args.expected_inventory_sha256)
        print(json.dumps({'status': summary['status'], 'summary': str(args.output_dir / 'summary.json'), 'metrics': summary['metrics']}))


if __name__ == '__main__':
    main()
