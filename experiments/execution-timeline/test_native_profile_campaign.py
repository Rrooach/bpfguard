from copy import deepcopy
import unittest
import tempfile
from pathlib import Path
import os

from native_profile_campaign import (acceptance_public_summary, compare_native_runs, render_comparison,
    publish_frozen_live_view,render_campaign_index)
from native_profile_campaign import freeze_public_campaign


class NativeCampaignTests(unittest.TestCase):
    def fixture(self):
        from semantic_annotations import _digest
        taxonomy={'task':'修复请求头','inspect':'检查实现','repair':'实现修复','unassigned':'未分配阶段'}
        marks={'taxonomy':taxonomy,'taxonomy_version':'header-v1','trajectory_digest':'bound','method':'OFFLINE_REVIEW',
            'taxonomy_digest':_digest(taxonomy)}
        def story(status,stage,tokens):
            path=['修复请求头',taxonomy[stage]]
            return {'run_id':status,'status':status,'agent_wall_ms':10,'wall_scope':'FULL_CAPTURE',
                'tools':[{'call_id':'a','semantic_path':path}],
                'semantic_annotations':{key:marks[key] for key in ('trajectory_digest','taxonomy_version','taxonomy_digest','method')},
                'native_model_tools':[{'call_id':'outer','semantic_path':path,'provider_request_ids':['r']}],
                'model_requests':[{'request_id':'r','semantic_path':path,'usage':tokens,'native_output_tool_call_ids':['outer']}],
                'wall_partition':{'segments':[{'duration_ns':10_000_000,'semantic_path':path,'active_ids':['r']}]}}
        result=[]
        for name,status,stage,tokens in (('002','failed','inspect',None),('004','completed','repair',{'total_tokens':100})):
            annotations={**deepcopy(marks),'call_paths':{'a':['task',stage]},'request_paths':{'r':['task',stage]}}
            result.append((name,story(status,stage,tokens),annotations))
        return result

    def test_failed_and_completed_are_not_a_speedup_claim(self):
        value=compare_native_runs(self.fixture())
        self.assertFalse(value['speedup_claim_allowed'])
        self.assertEqual([r['outcome'] for r in value['runs']],['failed','completed'])
        self.assertEqual(sum(r['wall_ms'] for r in value['runs']),20)
        self.assertEqual(next(v['total'] for v in value['profile']['views'] if v['name']=='wall_ms'),20)
        self.assertIsNone(value['runs'][0]['known_provider_tokens'])
        self.assertEqual(value['runs'][1]['known_provider_tokens'],100)
        self.assertIn('不提供“提速百分比”',render_comparison(value))

    def test_mismatched_taxonomy_or_unconserved_wall_rejected(self):
        cases=self.fixture();cases[1][2]['taxonomy_version']='header-v2'
        with self.assertRaises(ValueError):compare_native_runs(cases)
        cases=self.fixture();cases[0][2]['trajectory_digest']='swapped-review'
        with self.assertRaisesRegex(ValueError,'binding differs'):compare_native_runs(cases)
        cases=self.fixture();cases[0][1]['tools'][0]['semantic_path']=['修复请求头','实现修复']
        with self.assertRaisesRegex(ValueError,'reviewed exact IDs'):compare_native_runs(cases)
        cases=self.fixture();cases[1][1]['agent_wall_ms']=100
        with self.assertRaises(ValueError):compare_native_runs(cases)

    def test_acceptance_summary_omits_private_or_arbitrary_fields(self):
        value=acceptance_public_summary({'status':'PASSED','private_budget':'DO_NOT_PUBLISH',
            'native_configuration':{'secret':'DO_NOT_PUBLISH'},'model_receipts':[{'body':'DO_NOT_PUBLISH'}],
            'kernel_health':{'status':'COMPLETE','counters':{'ring_drops':0,'unrelated_secret':'DO_NOT_PUBLISH'}}})
        self.assertNotIn('DO_NOT_PUBLISH',str(value))
        self.assertEqual(value['kernel_health']['ring_drops'],0)

    def test_publication_reuses_only_named_immutable_artifacts(self):
        from common import write_new,digest
        from test_native_agent_profile import fixture
        from native_agent_profile import export_native_profile
        report,app,results,corr=fixture()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);frozen=root/'frozen';frozen.mkdir();source=frozen/'source';(source/'app').mkdir(parents=True)
            for name,value in (('report.json',report),('app/steps.json',app),('verification.json',{'status':'REPLAY_PASSED'})):
                write_new(source/name,value)
            write_new(source/'app/native-tool-results.jsonl',b''.join((__import__('json').dumps(row)+'\n').encode() for row in results))
            export_native_profile(source,frozen/'index.html',frozen/'semantic-profile.json')
            write_new(frozen/'.private-budget',b'PRIVATE_NOT_PUBLIC')
            write_new(source/'app/token.json',b'PRIVATE_NOT_PUBLIC')
            identity=digest(source/'report.json');public=root/'public'
            result=publish_frozen_live_view(frozen,public)
            self.assertEqual(result['status'],'IMMUTABLE_ALLOWLIST_HARDLINK_PUBLICATION')
            self.assertEqual(os.stat(public/'source/report.json').st_ino,os.stat(source/'report.json').st_ino)
            self.assertEqual(identity,digest(source/'report.json'))
            self.assertFalse((public/'.private-budget').exists())
            self.assertFalse((public/'source/app/token.json').exists())
            self.assertIn('预算代理会缓冲 provider SSE',(public/'index.html').read_text())
            with self.assertRaises(ValueError):publish_frozen_live_view(frozen,public)

    def test_tabs_distinguish_live_failed_comparison_and_trace_replay(self):
        page=render_campaign_index()
        for marker in ('live/index.html','compare/index.html','replay/index.html','不是事后补造','不能当成提速实验'):
            self.assertIn(marker,page)
        with self.assertRaises(ValueError):render_campaign_index(live_url='javascript:alert(1)')

    def test_final_receipt_rejects_unknown_files_and_symlinks(self):
        from common import write_new,digest
        def prepare(root):
            for name in ('index.html','live/index.html','compare/index.html','replay/index.html',
                         'acceptance-summary.json','replay/scope-export-verification.json'):
                path=root/name;path.parent.mkdir(exist_ok=True);write_new(path,b'public')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);prepare(root);result=freeze_public_campaign(root)
            self.assertEqual(result['files']['live/index.html'],digest(root/'live/index.html'))
            with self.assertRaises(ValueError):freeze_public_campaign(root)
        for kind in ('private','symlink'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);prepare(root)
                if kind=='private':write_new(root/'private-budget.json',b'PRIVATE')
                else:(root/'README.md').symlink_to(root/'index.html')
                with self.assertRaises(ValueError):freeze_public_campaign(root)
                self.assertFalse((root/'publication.json').exists())


if __name__=='__main__':unittest.main()
