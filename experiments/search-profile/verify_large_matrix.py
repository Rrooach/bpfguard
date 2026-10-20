#!/usr/bin/env python3
"""Read-only fixed-work/pause-lineage verification, not a resource/cache oracle."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import stat


PLAN_FIELDS = {'cache', 'workspace_layout', 'concurrency', 'intervention', 'block', 'warmup'}
VARIABLE_CONFIG = {'cache', 'workspace_layout', 'concurrency', 'warmup'}
BINARY_FIELDS = {'matrix_sha256', 'runner_sha256', 'cache_probe_sha256', 'sampler_sha256', 'grep_sha256'}
BOUND_MANIFEST_FIELDS = ('source', 'source_inventory_sha256', 'jobs', 'passes', 'queries', 'cpus',
    'measurement_coordinator_and_sampler_cpus', 'boot_id', 'seed', 'binaries', 'measurement_mode')
GREP_OPTIONS = ['-r', '-l', '-Z', '-F', '--binary-files=without-match', '--exclude-dir=.git']
REQUIRED_CONFIG = {'jobs', 'passes', 'calibration_kind', 'calibration_seconds', 'timing_scope',
    'query_measurement_version', 'cpu_time_scope', 'corpus_sha256', 'queries_sha256',
    'permission_scope_sha256', 'repository_version', 'intervention', 'cgroup_layout', 'memory_max_mb',
    'memory_high_mb', 'memory_limit_start', 'sample_threads', 'cpus', 'interval_ms', 'process_interval_ms',
    'cache', 'workspace_layout', 'concurrency', 'repetition', 'warmup', 'mode'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def digest(value):
    return isinstance(value, str) and len(value) == 64 and all(ch in '0123456789abcdef' for ch in value)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def equal(left, right):
    return canonical(left) == canonical(right)


def child(root, relative):
    require(isinstance(relative, str) and relative and '\0' not in relative
            and not Path(relative).is_absolute() and '..' not in Path(relative).parts
            and str(Path(relative)) == relative and relative != '.', 'unsafe evidence path')
    result = (root / relative).resolve(strict=True)
    result.relative_to(root.resolve(strict=True))
    return result


class Evidence:
    def __init__(self):
        self.receipts = {}
        self.cache = {}

    def bytes(self, path, limit=32 * 1024 * 1024):
        path = Path(path).resolve(strict=True)
        if path in self.cache:
            return self.cache[path]
        metadata = path.stat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= limit, 'nonregular/oversized evidence: ' + str(path))
        raw = path.read_bytes()
        require(len(raw) == metadata.st_size, 'evidence changed while reading: ' + str(path))
        self.cache[path] = raw
        self.receipts[str(path)] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        return raw

    def json(self, path):
        value = json.loads(self.bytes(path))
        require(isinstance(value, dict), 'expected JSON object: ' + str(path))
        return value

    def sha(self, path):
        self.bytes(path)
        return self.receipts[str(Path(path).resolve())]['sha256']


def validate_plan(plan):
    require(isinstance(plan, dict) and set(plan) == PLAN_FIELDS, 'invalid original schedule shape')
    require(plan['cache'] in ('warm', 'guest-cold') and plan['workspace_layout'] in ('shared', 'independent')
            and integer(plan['concurrency'], 1) and plan['concurrency'] in (1, 2, 4, 8)
            and plan['intervention'] == 'none' and integer(plan['block']) and plan['warmup'] is False,
            'invalid original schedule condition/type')


def cgroup(value):
    return (isinstance(value, dict) and isinstance(value.get('path'), str) and value['path'].startswith('/')
            and '..' not in Path(value['path']).parts and integer(value.get('inode'), 1) and integer(value.get('device')))


def process(value):
    return isinstance(value, dict) and integer(value.get('pid'), 1) and integer(value.get('start_ticks'), 1)


def verify_campaign(reader, directory, binding, plan, expected, seen):
    """Reconstruct fixed work from raw jobs, query spans, lifecycle and stdout."""
    start_receipts = set(reader.receipts)
    campaign_path = directory / 'campaign.json'
    campaign = reader.json(campaign_path)
    require(campaign.get('status') == 'COMPLETE' and isinstance(campaign.get('trials'), list)
            and len(campaign['trials']) == 1, 'campaign is not one COMPLETE trial')
    for field in ('jobs', 'passes', 'queries', 'binaries'):
        require(equal(campaign.get(field), binding[field]), 'campaign binding differs: ' + field)
    require(equal(campaign.get('grep_options'), GREP_OPTIONS), 'grep options differ')
    item = campaign['trials'][0]
    trial = child(directory, item.get('path'))
    profile_path = trial / 'profile-run.json'
    profile = reader.json(profile_path)
    run_id = profile.get('run_id')
    require(isinstance(run_id, str) and run_id and run_id not in seen, 'duplicate/missing raw run identity')
    seen.add(run_id)
    require(profile.get('schema_version') == 1 and type(profile['schema_version']) is int
            and profile.get('status') == 'COMPLETE' and profile.get('cleanup_errors') == []
            and profile.get('boot_id') == binding['boot_id'] and run_id == item.get('run_id'),
            'raw run identity/status/cleanup differs')
    begin, end, span = (profile.get(key) for key in ('release_ns', 'end_ns', 'makespan_ns'))
    require(all(integer(value, 1) for value in (begin, end, span)) and end - begin == span
            and type(item.get('makespan_ns')) is int and item['makespan_ns'] == span, 'invalid raw execution interval')
    config = profile.get('config')
    require(isinstance(config, dict) and REQUIRED_CONFIG <= set(config), 'raw fixed configuration missing')
    require(all(integer(config.get(key)) for key in ('interval_ms', 'process_interval_ms', 'memory_max_mb', 'memory_high_mb'))
            and 10 <= config['interval_ms'] <= 60000 and type(config.get('sample_threads')) is bool
            and type(config.get('query_measurement_version')) is int and config['query_measurement_version'] == 1
            and type(config.get('calibration_seconds')) in (int, float) and math.isfinite(config['calibration_seconds'])
            and config['calibration_seconds'] > 0, 'raw fixed configuration field type invalid')
    for field in ('cache', 'workspace_layout', 'concurrency', 'warmup'):
        require(equal(config.get(field), plan[field]), 'raw scheduled condition differs: ' + field)
    require(config.get('intervention') == plan['intervention'] and type(config.get('repetition')) is int
            and config['repetition'] == 0, 'raw intervention/inner repetition differs')
    for field, value in (('jobs', binding['jobs']), ('passes', binding['passes']), ('cpus', binding['cpus']),
                         ('mode', binding['measurement_mode']), ('repository_version', binding['source']['commit'])):
        require(equal(config.get(field), value), 'raw manifest binding differs: ' + field)
    require(digest(config.get('corpus_sha256')) and digest(config.get('permission_scope_sha256'))
            and config.get('queries_sha256') == hashlib.sha256(canonical(binding['queries']).encode()).hexdigest(),
            'raw content/permissions/queries digest binding invalid')
    fixed = {key: value for key, value in config.items() if key not in VARIABLE_CONFIG}
    if 'fixed' not in expected:
        expected['fixed'] = fixed
    require(equal(fixed, expected['fixed']), 'raw full fixed configuration differs')
    for field in ('corpus_sha256', 'permission_scope_sha256', 'repository_version', 'cgroup_layout',
                  'memory_max_mb', 'memory_high_mb', 'sample_threads', 'calibration_kind'):
        require(equal(campaign.get(field), config.get(field)), 'campaign/raw fixed configuration differs: ' + field)
    for field in ('mode', 'concurrency', 'repetition', 'warmup'):
        require(equal(item.get(field), config.get(field)), 'campaign trial index differs: ' + field)
    tasks, results = profile.get('tasks'), profile.get('results')
    require(isinstance(tasks, list) and isinstance(results, list) and len(tasks) == binding['jobs'] == len(results),
            'raw task/result count differs')
    names = ['task-%04d' % index for index in range(binding['jobs'])]
    require([task.get('task_id') for task in tasks] == names and {row.get('task_id') for row in results} == set(names),
            'raw task/result identity missing/duplicate/reordered')
    result_map = {row['task_id']: row for row in results}
    require(cgroup(profile.get('root_cgroup')), 'root cgroup identity invalid')
    event_path = trial / 'task-events.jsonl'
    events = [json.loads(line) for line in reader.bytes(event_path).splitlines()]
    require(len(events) == 2 * binding['jobs'], 'raw task lifecycle count differs')
    event_map = {}
    previous = -1
    for seq, event in enumerate(events):
        require(type(event.get('seq')) is int and event['seq'] == seq and integer(event.get('monotonic_ns'))
                and event['monotonic_ns'] >= previous, 'invalid lifecycle sequence/window')
        previous = event['monotonic_ns']
        key = event.get('task_id'), event.get('event')
        require(key not in event_map, 'duplicate lifecycle event')
        event_map[key] = event
    workspaces, critical = [], ['campaign.json']
    for index, task in enumerate(tasks):
        task_id, row = task['task_id'], result_map[task['task_id']]
        query_index = index % len(binding['queries'])
        require(process(task.get('process')) and equal(task.get('cgroup'), profile['root_cgroup']),
                'task process/cgroup differs from declared shared leaf')
        require(type(row.get('query_index')) is int and row['query_index'] == query_index
                and type(row.get('exit_code')) is int and row['exit_code'] == 0, 'raw query assignment/result differs')
        for field in ('queue_ns', 'wall_ns', 'completion_latency_ns', 'user_usec', 'system_usec', 'output_bytes'):
            require(integer(row.get(field)), 'invalid raw task counter: ' + field)
        require(row['queue_ns'] + row['wall_ns'] == row['completion_latency_ns'], 'task time does not reconstruct')
        low, high = begin + row['queue_ns'], begin + row['completion_latency_ns']
        require(begin <= low <= high <= end, 'task interval outside execution')
        job_name, stats_name, stdout_name = task_id + '-job.json', task_id + '-statistics.json', task_id + '.stdout'
        job, stats = reader.json(child(trial, job_name)), reader.json(child(trial, stats_name))
        require(job.get('query') == binding['queries'][query_index] and type(job.get('query_index')) is int
                and job['query_index'] == query_index and equal(job.get('passes'), binding['passes']) and job.get('reuse') is None,
                'raw job query/work differs')
        identity = job.get('query_identity')
        require(isinstance(identity, dict) and type(identity.get('attempt')) is int and identity['attempt'] == 1
                and type(identity.get('epoch')) is int and identity['epoch'] == 1, 'raw job identity missing')
        for field, value in (('run_id', run_id), ('task_id', task_id), ('agent_id', task.get('agent_id')),
                ('tool_call_id', task.get('tool_call_id')), ('cgroup', task['cgroup']),
                ('corpus_sha256', config['corpus_sha256']), ('grep_sha256', binding['binaries']['grep_sha256']),
                ('repository_version', config['repository_version']), ('cache_state', plan['cache']),
                ('workspace_layout', plan['workspace_layout'])):
            require(equal(identity.get(field), value), 'raw job identity differs: ' + field)
        workspace = job.get('corpus')
        require(isinstance(workspace, str) and workspace.startswith('/') and '..' not in Path(workspace).parts,
                'invalid raw workspace')
        workspace_key = plan['workspace_layout'], index
        expected.setdefault('workspaces', {}).setdefault(workspace_key, workspace)
        require(expected['workspaces'][workspace_key] == workspace, 'workspace changed across pause/conditions')
        workspaces.append(workspace)
        grep = job.get('grep')
        require(isinstance(grep, str) and grep.startswith('/') and '..' not in Path(grep).parts, 'raw grep executable path invalid')
        expected.setdefault('grep_path', grep)
        require(expected['grep_path'] == grep, 'raw grep executable path changed')
        for event_name, clock in (('START', low), ('COMPLETE', high)):
            event = event_map.get((task_id, event_name))
            require(isinstance(event, dict) and event.get('monotonic_ns') == clock, 'lifecycle/task time differs')
            for field, value in (('run_id', run_id), ('boot_id', binding['boot_id']), ('process', task['process']),
                                 ('cgroup', task['cgroup']), ('agent_id', task.get('agent_id')), ('tool_call_id', task.get('tool_call_id'))):
                require(equal(event.get(field), value), 'lifecycle identity differs: ' + field)
            if event_name == 'COMPLETE':
                for field in ('exit_code', 'output_sha256', 'output_bytes', 'user_usec', 'system_usec'):
                    require(equal(event.get(field), row[field]), 'lifecycle/result differs: ' + field)
        require(stats.get('schema_version') == 2 and type(stats['schema_version']) is int
                and equal(stats.get('logical_queries'), binding['passes'])
                and equal(stats.get('physical_grep_executions'), binding['passes'])
                and type(stats.get('cache_hits')) is int and stats['cache_hits'] == 0 and stats.get('intervention') == 'none'
                and stats.get('query_timing_contract') == 'WORKER_MONOTONIC_PER_LOGICAL_QUERY_V1',
                'raw query statistics work differs')
        spans = stats.get('query_spans')
        require(isinstance(spans, list) and len(spans) == binding['passes'], 'raw query span count differs')
        previous_query_end = low
        for ordinal, query in enumerate(spans):
            for field, value in identity.items():
                require(equal(query.get(field), value), 'raw query identity differs: ' + field)
            qbegin, qend = query.get('begin_ns'), query.get('end_ns')
            require(integer(qbegin) and integer(qend) and previous_query_end <= qbegin <= qend <= high
                    and type(query.get('duration_ns')) is int and query['duration_ns'] == qend - qbegin
                    and type(query.get('query_ordinal')) is int and query['query_ordinal'] == ordinal
                    and query.get('query_index') == query_index and type(query['query_index']) is int
                    and query.get('query_sha256') == hashlib.sha256(job['query'].encode()).hexdigest()
                    and equal(query.get('process'), task['process']) and query.get('boot_id') == binding['boot_id']
                    and query.get('execution_kind') == 'SCAN' and query.get('status') == 'COMPLETE'
                    and type(query.get('schema_version')) is int and query['schema_version'] == 1
                    and query.get('mode') == 'none' and type(query.get('lock_wait_ns')) is int and query['lock_wait_ns'] == 0
                    and query.get('query_id') == task['tool_call_id'] + ':query-%06d' % ordinal
                    and type(query.get('returncode')) is int and query['returncode'] in (0, 1), 'raw query span invalid')
            previous_query_end = qend
        raw = reader.bytes(child(trial, stdout_name), 64 * 1024 * 1024)
        fields = raw.split(b'\0')
        require(fields[-1] == b'' and all(fields[:-1]), 'invalid raw NUL output')
        value = (0, hashlib.sha256(b'\0'.join(sorted(fields[:-1])) + b'\0').hexdigest(), len(raw))
        require(all(query['returncode'] == (0 if raw else 1) for query in spans), 'grep return code contradicts raw output')
        require(equal(list(value), [row['exit_code'], row['output_sha256'], row['output_bytes']]), 'raw stdout digest/bytes differs')
        expected.setdefault('outputs', {}).setdefault(query_index, value)
        require(expected['outputs'][query_index] == value, 'query output changed across conditions/pause')
        critical += [str((trial / name).relative_to(directory)) for name in (job_name, stats_name, stdout_name)]
    require((len(set(workspaces)) == 1 if plan['workspace_layout'] == 'shared' else len(set(workspaces)) == binding['jobs']),
            'workspace layout does not match actual jobs')
    require(max(row['completion_latency_ns'] for row in results) == span, 'makespan does not reconstruct from task results')
    report_path = trial / 'report.json'
    analyzer = reader.json(report_path).get('analysis', {}).get('source_sha256')
    require(digest(analyzer), 'producer analyzer digest missing')
    expected.setdefault('analyzer', analyzer)
    require(analyzer == expected['analyzer'], 'producer analyzer changed')
    meta_path = trial / 'load/load-meta.json'
    meta = reader.json(meta_path)
    require(meta.get('label') == run_id and meta.get('boot_id') == binding['boot_id']
            and isinstance(meta.get('cgroups'), list) and len(meta['cgroups']) == 1
            and equal({key: meta['cgroups'][0].get(key) for key in ('path', 'inode', 'device')}, profile['root_cgroup']),
            'sampler registry/run binding differs')
    reader.json(trial / 'load/load-sampler-stats.json')
    cache_reference = profile.get('cache_residency')
    require(isinstance(cache_reference, dict) and digest(cache_reference.get('sha256')), 'cache summary reference missing')
    cache_path = child(trial, cache_reference.get('path'))
    compact = reader.json(cache_path)
    require(reader.sha(cache_path) == cache_reference['sha256'], 'cache compact digest differs')
    gz = compact.get('file_details', {})
    require(digest(gz.get('sha256')), 'gzip digest reference missing')
    gz_path = child(trial, gz.get('path'))
    require(stat.S_ISREG(gz_path.stat().st_mode), 'gzip artifact missing/nonregular')
    critical += [str(path.relative_to(directory)) for path in
        (profile_path, event_path, report_path, meta_path, trial / 'load/load-sampler-stats.json', cache_path)]
    return {'run_id': run_id, 'release_ns': begin, 'end_ns': end, 'directory': str(directory),
            'critical_artifacts': {name: reader.sha(child(directory, name)) for name in critical},
            'gzip': {'path': str(gz_path), 'declared_sha256': gz['sha256'], 'bytes': gz_path.stat().st_size,
                     'validation': 'NOT_READ_OR_DECOMPRESSED; REFERENCE_ONLY'},
            'newly_read_artifacts': len(set(reader.receipts) - start_receipts)}


def verify(combined_path, original_prefix_dir, expected_original_sha256):
    reader, runs = Evidence(), []
    result = {'schema_version': 1, 'verified': False, 'status': 'FAILED', 'issues': [],
        'inputs': {'combined': str(combined_path), 'original_prefix_dir': str(original_prefix_dir),
                   'expected_original_sha256': expected_original_sha256},
        'scope': {'verified': 'SCHEDULE_LINEAGE_UNIQUE_RUNS_FULL_FIXED_CONFIG_RAW_JOBS_QUERY_SPANS_LIFECYCLE_STDOUT',
            'binary_validation': 'PRODUCER_DECLARATIONS_AND_RESUME_PROVENANCE_BINDING; NO_BINARY_REEXECUTION',
            'gzip': 'NOT_READ_OR_DECOMPRESSED; COMPACT_REFERENCES_ONLY',
            'cache_and_resources': 'NOT_REPLAYED; USE_WALLCLOCK_REPORT_SEPARATELY',
            'source_contents': 'INDEPENDENT_NINE_ROOT_CONTENT_PERMISSION_REHASH_NOT_PERFORMED'},
        'trust_boundary': 'Original matrix SHA anchors its manifest; supplied original-prefix bytes are not an independently externally sealed sensor.',
        'runs': runs}
    try:
        require(digest(expected_original_sha256), 'expected original SHA256 invalid')
        combined_path, original_prefix_dir = Path(combined_path).resolve(strict=True), Path(original_prefix_dir).resolve(strict=True)
        old_path = original_prefix_dir / 'matrix.json'
        original = reader.json(old_path)
        require(reader.sha(old_path) == expected_original_sha256, 'original FAILED matrix does not match expected SHA256')
        combined = reader.json(combined_path)
        require(type(original.get('schema_version')) is int and original['schema_version'] == 1
                and original.get('status') == 'FAILED' and type(combined.get('schema_version')) is int
                and combined['schema_version'] == 1 and combined.get('status') == 'COMPLETE', 'matrix schema/raw statuses invalid')
        plans, prefix = original.get('schedule'), original.get('campaigns')
        require(isinstance(plans, list) and isinstance(prefix, list) and 0 < len(prefix) < len(plans) <= 4096,
                'invalid original interrupted schedule/prefix')
        for plan in plans:
            validate_plan(plan)
        keys = [(p['block'], p['cache'], p['workspace_layout'], p['concurrency'], p['intervention']) for p in plans]
        require(len(set(keys)) == len(keys), 'original schedule duplicates a condition/block')
        require(integer(original.get('jobs'), 1) and original['jobs'] <= 128 and integer(original.get('passes'), 1)
                and original['passes'] <= 1000 and isinstance(original.get('queries'), list) and original['queries']
                and len(original['queries']) <= original['jobs']
                and all(isinstance(q, str) and q and len(q) <= 4096 and '\0' not in q and '\n' not in q for q in original['queries']),
                'invalid fixed-work dimensions')
        require(isinstance(original.get('binaries'), dict) and set(original['binaries']) == BINARY_FIELDS
                and all(digest(value) for value in original['binaries'].values()), 'frozen binary declarations invalid')
        for field in BOUND_MANIFEST_FIELDS:
            require(equal(original.get(field), combined.get(field)), 'combined fixed binding differs: ' + field)
        require(equal(combined.get('schedule'), plans) and isinstance(combined.get('campaigns'), list)
                and len(combined['campaigns']) == len(plans), 'combined schedule/count differs')
        provenance = combined.get('resume_provenance')
        require(isinstance(provenance, dict) and provenance.get('original_matrix_sha256') == expected_original_sha256
                and digest(provenance.get('adapter_sha256')) and digest(provenance.get('resumed_matrix_sha256'))
                and equal(provenance.get('completed_prefix'), len(prefix))
                and equal(provenance.get('remaining_cases'), len(plans) - len(prefix)), 'resume lineage anchor differs')
        old_records, expected, old_seen = [], {}, set()
        for index, entry in enumerate(prefix):
            require(equal(entry.get('condition'), plans[index]) and equal(entry.get('block'), plans[index]['block'])
                    and entry.get('stage') == 'performance' and entry.get('path') == '%03d-r%d' % (index, plans[index]['block']),
                    'original entries not exact schedule prefix')
            old_records.append(verify_campaign(reader, child(original_prefix_dir, entry['path']), original, plans[index], expected, old_seen))
        entries, root = combined['campaigns'], combined_path.parent
        suffix_parents = {child(root, entry['path']).parent for entry in entries[len(prefix):]}
        require(len(suffix_parents) == 1, 'resumed campaigns do not have one source matrix directory')
        suffix_dir = next(iter(suffix_parents))
        resumed_path = suffix_dir / 'matrix.json'
        resumed = reader.json(resumed_path)
        require(reader.sha(resumed_path) == provenance['resumed_matrix_sha256']
                and resumed.get('status') == 'COMPLETE' and resumed.get('output_equivalence') == 'PASS'
                and equal(resumed.get('schedule'), plans[len(prefix):])
                and isinstance(resumed.get('campaigns'), list) and len(resumed['campaigns']) == len(plans) - len(prefix),
                'resumed completion/schedule/source digest differs')
        for field in BOUND_MANIFEST_FIELDS:
            require(equal(resumed.get(field), original.get(field)), 'resumed fixed binding differs: ' + field)
        require(provenance.get('frozen_analyzer_sha256') == expected['analyzer']
                and provenance.get('timing_implementation') == 'ORIGINAL_FROZEN_EXECUTE_AND_RUN_TRIAL; ONLY_SCHEDULE_PROVIDER_REPLACED_IN_MEMORY'
                and provenance.get('integrity') == 'Frozen execute rechecked all source/copy contents and permissions after the remaining trials.',
                'frozen-execute completion provenance missing/different')
        require(integer(provenance.get('begin_monotonic_ns'), 1) and integer(provenance.get('end_monotonic_ns'), 1)
                and provenance['end_monotonic_ns'] >= provenance['begin_monotonic_ns'], 'invalid resume control interval')
        seen, directories = set(), set()
        for index, entry in enumerate(entries):
            require(type(entry.get('original_schedule_index')) is int and entry['original_schedule_index'] == index
                    and equal(entry.get('condition'), plans[index]) and equal(entry.get('block'), plans[index]['block'])
                    and entry.get('stage') == 'performance', 'combined original index/block/condition/stage differs')
            directory = child(root, entry.get('path'))
            require(directory not in directories, 'combined reuses an evidence directory')
            directories.add(directory)
            record = verify_campaign(reader, directory, original, plans[index], expected, seen)
            require(not runs or record['release_ns'] >= runs[-1]['end_ns'], 'formal execution windows overlap or are reordered')
            if index < len(prefix):
                require(Path(entry['path']).name == prefix[index]['path'], 'combined prefix path mapping differs')
                require(equal(record['critical_artifacts'], old_records[index]['critical_artifacts'])
                        and record['run_id'] == old_records[index]['run_id']
                        and record['gzip']['declared_sha256'] == old_records[index]['gzip']['declared_sha256']
                        and record['gzip']['bytes'] == old_records[index]['gzip']['bytes'], 'original prefix critical evidence was changed')
            else:
                local = index - len(prefix)
                source_entry = resumed['campaigns'][local]
                require(child(suffix_dir, source_entry.get('path')) == directory
                        and equal(source_entry.get('condition'), plans[index])
                        and equal(source_entry.get('block'), plans[index]['block'])
                        and source_entry.get('stage') == 'performance', 'combined/resumed campaign mapping differs')
                require(provenance['begin_monotonic_ns'] <= record['release_ns'] <= record['end_ns'] <= provenance['end_monotonic_ns'],
                        'resumed trial outside control interval')
            record.update(original_schedule_index=index, block=entry['block'], segment='prefix' if index < len(prefix) else 'resumed')
            runs.append(record)
        interrupted_index = len(prefix)
        interrupted_dir = child(original_prefix_dir, '%03d-r%d' % (interrupted_index, plans[interrupted_index]['block']))
        interrupted_campaign = reader.json(interrupted_dir / 'campaign.json')
        canceled_paths = list((interrupted_dir / 'trials').glob('*/profile-run.json'))
        require(interrupted_campaign.get('status') == 'RUNNING' and interrupted_campaign.get('trials') == []
                and len(canceled_paths) == 1, 'original interrupted attempt is not separately preserved')
        canceled = reader.json(canceled_paths[0])
        require(canceled.get('status') == 'FAILED' and canceled.get('boot_id') == original['boot_id']
                and canceled.get('run_id') not in seen and all(key not in canceled for key in ('release_ns', 'end_ns', 'makespan_ns')),
                'interrupted attempt has a release/result or was counted')
        result.update(verified=True, status='VERIFIED_WITH_DECLARED_SCOPE', total_trials=len(runs),
            unique_runs=len(seen), original_prefix_trials=len(prefix), resumed_trials=len(plans) - len(prefix),
            original_matrix_sha256=expected_original_sha256, combined_matrix_sha256=reader.sha(combined_path),
            full_fixed_config=expected['fixed'], producer_analyzer_sha256=expected['analyzer'],
            query_outputs={str(key): list(value) for key, value in sorted(expected['outputs'].items())},
            canceled_attempt={'run_id': canceled['run_id'], 'profile': str(canceled_paths[0]),
                'profile_sha256': reader.sha(canceled_paths[0]), 'original_schedule_index': interrupted_index,
                'included_in_performance_trials': False, 'release_present': False},
            source_post_validation={'status': 'PRODUCER_FROZEN_EXECUTE_COMPLETION_CLAIM_BOUND',
                'claimed_roots': original['jobs'] + 1, 'resumed_manifest_sha256': reader.sha(resumed_path),
                'independent_content_permission_rehash': 'NOT_PERFORMED'},
            split_pause_block=plans[len(prefix) - 1]['block'] if plans[len(prefix) - 1]['block'] == plans[len(prefix)]['block'] else None)
    except (ValueError, OSError, TypeError, KeyError, StopIteration, AttributeError, OverflowError) as error:
        result['issues'].append({'code': 'MATRIX_VERIFICATION_FAILED', 'detail': str(error)})
    result['read_artifacts'] = reader.receipts
    result['verifier_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--combined', type=Path, required=True)
    parser.add_argument('--original-prefix-dir', type=Path, required=True)
    parser.add_argument('--expected-original-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    require(not output.exists(), 'output must be fresh')
    result = verify(args.combined, args.original_prefix_dir, args.expected_original_sha256)
    protected = [args.original_prefix_dir.resolve()]
    protected += [Path(row['directory']) for row in result['runs']]
    try:
        index = json.loads(args.combined.read_bytes())
        protected += [child(args.combined.resolve().parent, row['path']) for row in index['campaigns']]
    except (ValueError, OSError, TypeError, KeyError):
        # Failed verification still gets a receipt; never relax the already
        # known protected directories because the source index is malformed.
        pass
    for directory in protected:
        require(directory not in output.resolve().parents, 'receipt must be outside raw evidence directories')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    print(json.dumps({'verified': result['verified'], 'status': result['status'], 'output': str(output)}))
    return 0 if result['verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
