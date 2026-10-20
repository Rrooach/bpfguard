"""Offline cross-check of the owned tracefs VFS hook receipt.

This verifies bound collector statements, not an independent trusted sensor.
Global nmissed is deliberately not attributed away to unrelated processes.
"""
import re

BACKEND = 'OWNED_TRACEFS_KPROBE_KRETPROBE'
HOOKS = {'et_read_begin': ('vfs_read', False), 'et_read_end': ('vfs_read', True),
         'et_readv_begin': ('vfs_readv', False), 'et_readv_end': ('vfs_readv', True)}


def require(value, message):
    if not value:
        raise ValueError('owned kprobe evidence: ' + message)


def unsigned(value, positive=False):
    return type(value) is int and value >= int(positive)


def validate_receipt(receipt, meta, health):
    require(isinstance(receipt, dict) and receipt.get('schema_version') == 1, 'schema')
    require(receipt.get('backend') == meta.get('read_hook_backend') == health.get('read_hook_backend') == BACKEND,
            'backend differs')
    require(receipt.get('boot_id') == meta.get('boot_id') and bool(meta.get('boot_id')), 'boot differs')
    require(unsigned(meta.get('root_cgroup_id'), True)
            and receipt.get('root_cgroup_id') == meta['root_cgroup_id'], 'cgroup differs')
    begin, end = health.get('start_ns'), health.get('end_ns')
    require(unsigned(begin, True) and unsigned(end, True) and begin <= end
            and receipt.get('capture_start_ns') == begin and receipt.get('capture_end_ns') == end,
            'capture window differs')
    enabled = meta.get('enabled_monotonic_ns')
    require(unsigned(enabled, True) and begin <= enabled <= end, 'enable window differs')
    require(receipt.get('kretprobe_maxactive') == meta.get('kretprobe_maxactive') == 4096, 'return capacity')
    abi = receipt.get('btf_abi', {})
    require(abi.get('status') == 'VALIDATED_NATIVE_X86_64'
            and abi.get('registers') == ['di', 'si', 'dx', 'cx', 'ax']
            and all(unsigned(abi.get(key), True) for key in
                    ('vfs_read_function_id', 'vfs_readv_function_id', 'pt_regs_struct_id')), 'BTF ABI')
    for left, right in (('errors', 'kprobe_profile_errors'), ('cleanup_errors', 'kprobe_cleanup_errors'),
                        ('misses_delta', 'kprobe_misses')):
        require(unsigned(receipt.get(left)) and receipt[left] == health.get(right), 'health counter differs: ' + left)
    hooks = receipt.get('hooks')
    require(isinstance(hooks, list) and len(hooks) == 4
            and {hook.get('program') for hook in hooks} == set(HOOKS), 'four distinct required hooks')
    names, event_ids, directories = set(), set(), set()
    misses, profile_bad, cleanup_bad = 0, 0, 0
    require(len({hook.get('tracefs_root') for hook in hooks}) == 1
            and len({hook.get('device') for hook in hooks}) == 1, 'mixed tracefs identity')
    programs = {entry.get('program'): entry for entry in health.get('programs', [])}
    for hook in hooks:
        program = hook['program']
        anchor, returned = HOOKS[program]
        name = hook.get('name')
        require(isinstance(name, str) and re.fullmatch(r'alloxet_[a-f0-9]{32}_' + program, name)
                and name not in names, 'owned unique name')
        names.add(name)
        require(hook.get('tracefs_root') in ('/sys/kernel/tracing', '/sys/kernel/debug/tracing'), 'tracefs root')
        require(all(unsigned(hook.get(field), True) for field in ('device', 'directory_inode', 'event_id'))
                and hook['event_id'] not in event_ids, 'hook identity')
        event_ids.add(hook['event_id'])
        directory = hook['device'], hook['directory_inode']
        require(directory not in directories, 'duplicate live hook directory identity')
        directories.add(directory)
        require(hook.get('maxactive') == (4096 if returned else 0), 'per-hook return capacity')
        definition = ('r4096' if returned else 'p') + ':allox_execution_timeline/' + name + ' ' + anchor
        require(hook.get('definition') in (definition, definition + '+0'), 'definition/anchor')
        section = ('kretprobe/' if returned else 'kprobe/') + anchor
        require(program in programs and programs[program].get('section') == section, 'program section differs')
        for field in ('initial_hits', 'initial_misses', 'hits', 'misses', 'initial_begin_ns',
                      'initial_end_ns', 'final_begin_ns', 'final_end_ns'):
            require(unsigned(hook.get(field)), 'unknown profile field: ' + field)
        valid = (hook.get('initial_valid') is True and hook.get('final_valid') is True
                 and begin <= hook['initial_begin_ns'] <= hook['initial_end_ns'] <= enabled
                 and end <= hook['final_begin_ns'] <= hook['final_end_ns']
                 and hook['hits'] >= hook['initial_hits'] and hook['misses'] >= hook['initial_misses'])
        if valid:
            misses += hook['misses'] - hook['initial_misses']
        else:
            profile_bad += 1
        if hook.get('removed') is not True or hook.get('cleanup_error') is not False:
            cleanup_bad += 1
    require(misses == receipt['misses_delta'], 'miss delta sum differs')
    require(not profile_bad or receipt['errors'] >= profile_bad, 'unreported unknown/rollback profile')
    require(not cleanup_bad or receipt['cleanup_errors'] >= cleanup_bad, 'unreported cleanup failure')
    failures = receipt['errors'] + receipt['cleanup_errors'] + misses + profile_bad + cleanup_bad
    require(not failures or health.get('status') == 'INCOMPLETE', 'failed hook evidence claimed complete')
    return {'status': 'VALIDATED_BOUND_RECEIPT' if not failures else 'INCOMPLETE_HOOK_EVIDENCE_RETAINED',
            'misses': misses, 'profile_bad': profile_bad, 'cleanup_bad': cleanup_bad,
            'trust_scope': 'CROSS_CHECK_OF_BOUND_COLLECTOR_RECEIPT_NOT_INDEPENDENT_KERNEL_TRUST'}
