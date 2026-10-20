#!/usr/bin/env python3
"""Offline configuration/credential tests; never call a provider or cgroup."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from codex_run import codex_command, finalize_replay, proxy_token


class ConfigTests(unittest.TestCase):
    def args(self,**changes):
        return SimpleNamespace(codex=Path('/synthetic/codex'),broker_base_url='http://127.0.0.1:10091/v1',
            budget_label='codex-smoke-001',model='deepseek-flash',**changes)

    def test_official_binary_responses_and_no_builtin_shell_or_retry(self):
        command,config=codex_command(self.args(),Path('/synthetic/catalog.json'))
        self.assertEqual(command[:2],['/synthetic/codex','app-server'])
        for name in ('shell_tool','unified_exec','code_mode','code_mode_host','hooks'):
            self.assertIs(config['features.'+name],False)
        self.assertEqual(config['model_providers.observer_proxy.wire_api'],'responses')
        self.assertEqual(config['model_providers.observer_proxy.env_key'],'OBSERVER_BROKER_TOKEN')
        self.assertEqual(config['model_providers.observer_proxy.request_max_retries'],0)
        self.assertEqual(config['model_providers.observer_proxy.stream_max_retries'],0)
        self.assertIn('X-Benchmark-Task',' '.join(command))
        self.assertNotIn('DEEPSEEK_API_KEY',' '.join(command))

    def test_nonlocal_proxy_wrong_label_or_model_rejected(self):
        for key,value in [('broker_base_url','https://api.deepseek.com/v1'),('broker_base_url','http://localhost:10091/v1'),
            ('broker_base_url','http://127.0.0.1:10091/v1?secret=x'),('broker_base_url','http://token@127.0.0.1:10091/v1'),
            ('budget_label','other'),('model','other')]:
            args=self.args();setattr(args,key,value)
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):codex_command(args,Path('/synthetic/catalog'))

    def test_only_owned_small0600_proxy_credential_admitted(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'token';path.write_text('LOCAL_PROXY_ONLY\n');path.chmod(0o600)
            self.assertEqual(proxy_token(path),'LOCAL_PROXY_ONLY')
            path.chmod(0o644)
            with self.assertRaises(ValueError):proxy_token(path)
            path.chmod(0o600);path.write_text('bad token')
            with self.assertRaises(ValueError):proxy_token(path)
            link=root/'link';link.symlink_to(path)
            with self.assertRaises(ValueError):proxy_token(link)

    def test_display_failure_cannot_turn_raw_replay_pass_into_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'manifest.json').write_text('{"synthetic":true}')
            with mock.patch('replay.verify_run',return_value={'fixture_only':True}),mock.patch('render.render_report',side_effect=RuntimeError('synthetic display failure')):
                result=finalize_replay(root)
            self.assertEqual(result['status'],'REPLAY_PASSED')
            self.assertEqual(result['render_status'],'FAILED_SEPARATE_FROM_RAW_REPLAY')

    def test_raw_replay_failure_is_not_rendered_or_promoted(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'manifest.json').write_text('{"synthetic":true}')
            with mock.patch('replay.verify_run',side_effect=ValueError('synthetic evidence gap')),mock.patch('render.render_report') as render:
                result=finalize_replay(root)
            self.assertEqual(result['status'],'REPLAY_FAILED_OR_INCOMPLETE');render.assert_not_called()

if __name__=='__main__':unittest.main()
