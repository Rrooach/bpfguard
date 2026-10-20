from copy import deepcopy
import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path

from native_replay_profile import build_replay_view,render_replay_page,export_replay_view
from test_native_agent_profile import fixture


class NativeReplayProfileTests(unittest.TestCase):
    def values(self):
        report,app,results,corr=fixture();app['budget_label']='native-trace-replay'
        scope={'kind':'ARGV_AND_CORE_EXEC_LIFETIME_CORRELATION','core_syscall_count_increment':0,
            'correlated_syscall_references':2,'calls':[{'call_id':'call-1',
            'status':'KERNEL_ARGV_AND_CORE_EXEC_IDENTITY_CORRELATED','syscall_count':2,
            'thread_ranges':[{'thread_key':'10:birth','thread_ref':'report#/threads/0',
                'scope_begin_ns':report['run']['begin_ns'],'scope_end_ns':report['run']['end_ns'],
                'call_indices':[0,1]}]}]}
        return report,app,scope,results

    def test_scope_has_one_owner_and_conserves_global_events(self):
        values=self.values();saved=deepcopy(values);view=build_replay_view(*values)
        self.assertEqual(values,saved)
        self.assertEqual((view['total_syscalls'],view['correlated_syscalls'],view['unassigned_syscalls']),(3,2,1))
        self.assertEqual(view['tools'][0]['output']['text'],'needle\n')
        views={item['name']:item for item in view['profile']['views']}
        self.assertEqual(views['syscall_count']['total'],3)
        self.assertEqual(views['file_read_bytes']['total'],3)
        self.assertEqual(views['oncpu_ms']['total'],2)
        self.assertEqual(views['runnable_ms']['total'],1)
        self.assertFalse(any(frame['kind']=='tool' for operation in view['profile']['operations']
            if 'oncpu_ms' in operation['measures'] for frame in operation['stack']))
        self.assertNotIn('memory_peak_bytes',views)
        self.assertFalse(view['slowdown_claim_allowed'])
        owned=[item for item in view['profile']['operations'] if item['kind']=='core_replay_call' and any(frame['kind']=='tool' for frame in item['stack'])]
        self.assertEqual(len(owned),2)

    def test_bad_reference_bounds_grade_total_and_fake_paid_rejected(self):
        mutators=[lambda r,a,s,o:s['calls'][0]['thread_ranges'][0].update(thread_key='bad'),
            lambda r,a,s,o:s['calls'][0]['thread_ranges'][0].update(scope_begin_ns=r['run']['end_ns']),
            lambda r,a,s,o:s['calls'][0].update(status='CAUSAL'),
            lambda r,a,s,o:s.update(correlated_syscall_references=3),
            lambda r,a,s,o:a.update(paid_request_count=1),
            lambda r,a,s,o:s.update(core_syscall_count_increment=1)]
        for mutate in mutators:
            values=self.values();mutate(*values)
            with self.assertRaises(ValueError):build_replay_view(*values)
        values=self.values();duplicate=deepcopy(values[2]['calls'][0]);values[2]['calls'].append(duplicate)
        with self.assertRaises(ValueError):build_replay_view(*values)

    def test_html_escapes_real_tool_strings_and_no_full_rows_embedded(self):
        values=self.values();values[1]['tool_calls'][0]['arguments']['command']='</script><img src=x onerror=evil()>'
        view=build_replay_view(*values);page=render_replay_page(view,{'all':['pages/all-00000.json'],'by_tool':{}})
        self.assertNotIn('<img src=x',page)
        self.assertIn('&lt;img src=x',page)
        self.assertIn('0 次付费 API',page)
        self.assertNotIn('"rows":',page)

    def test_export_recomputes_scope_instead_of_believing_supplied_json(self):
        from common import write_new
        report,app,scope,results=self.values()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);run=root/'run';(run/'app').mkdir(parents=True)
            write_new(run/'report.json',report);write_new(run/'app/steps.json',app);write_new(root/'scope.json',scope)
            forged=deepcopy(scope);forged['correlated_syscall_references']=999
            with patch('verify_exec_args_run.verify_native_exec_scopes',return_value=forged) as verify:
                with self.assertRaisesRegex(ValueError,'independently recomputed'):
                    export_replay_view(run,root/'scope.json',root/'public')
                verify.assert_called_once_with(run.resolve(),snapshot_projection=False)
            self.assertFalse((root/'public').exists())
            wrong_provenance={**scope,'provider_provenance':'NEW_MODEL_INFERENCE'}
            write_new(root/'not-replay.json',wrong_provenance)
            with patch('verify_exec_args_run.verify_native_exec_scopes',return_value=wrong_provenance):
                with self.assertRaisesRegex(ValueError,'manifest must declare replayed'):
                    export_replay_view(run,root/'not-replay.json',root/'public')


if __name__=='__main__':unittest.main()
