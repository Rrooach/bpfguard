import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('file_profile_run', Path(__file__).with_name('run.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProfileTests(unittest.TestCase):
    def profile(self):
        records = []
        for domain in (1, 2):
            records.append(dict(domain_id=domain, object={'inode': 456}, operation='directory_iteration',
                calls=1, returned_bytes=0, thread={'tid': 10}))
            for tid, size in ((10, 288), (11, 256), (12, 256)):
                records.append({'domain_id': domain, 'object': {'inode': 123},
                    'operation': 'read_or_pread', 'calls': 2, 'returned_bytes': size,
                    'thread': {'tid': tid}})
            records += [dict(domain_id=domain, object={'inode': 123},
                operation='readv_or_preadv', calls=3, returned_bytes=0, thread={'tid': 10}),
                dict(domain_id=domain, object={'inode': 123}, operation='file_mmap',
                     calls=1, returned_bytes=0, thread={'tid': 10})]
        return {'observation_health': 'COMPLETE_FOR_SELECTED_HOOKS', 'health': {}, 'records': records}

    def test_complete(self):
        result = module.check(self.profile(), {'returned_file_bytes': 800}, 123, [1, 2])
        self.assertEqual(result['actual_file_bytes'], 1600)

    def test_missing_bytes(self):
        p = self.profile()
        p['records'][0]['returned_bytes'] -= 1
        with self.assertRaises(ValueError):
            module.check(p, {'returned_file_bytes': 800}, 123, [1, 2])

    def test_incomplete_is_not_pass(self):
        p = self.profile()
        p['observation_health'] = 'INCOMPLETE'
        with self.assertRaises(ValueError):
            module.check(p, {'returned_file_bytes': 800}, 123, [1, 2])

    def test_fabricated_mmap_bytes_rejected(self):
        p = self.profile()
        next(r for r in p['records'] if r['operation'] == 'file_mmap')['returned_bytes'] = 9
        with self.assertRaises(ValueError):
            module.check(p, {'returned_file_bytes': 809}, 123, [1, 2])

    def test_missing_directory_hook_rejected(self):
        p = self.profile()
        p['records'] = [r for r in p['records'] if r['operation'] != 'directory_iteration']
        with self.assertRaises(ValueError):
            module.check(p, {'returned_file_bytes': 800}, 123, [1, 2])

    def test_mmap_failure_classification_required(self):
        p = self.profile()
        for row in p['records']:
            if row['operation'] == 'file_mmap':
                row.update(calls=2, success_calls=1, errors=1)
        expected = {'returned_file_bytes': 800, 'mmap_calls': 2, 'mmap_success': 1, 'mmap_errors': 1}
        module.check(p, expected, 123, [1, 2])
        next(r for r in p['records'] if r['operation'] == 'file_mmap')['errors'] = 0
        with self.assertRaises(ValueError):
            module.check(p, expected, 123, [1, 2])
