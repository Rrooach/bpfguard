#!/usr/bin/env python3
"""Offline arithmetic plus harmless real local command replay; no BPF/API."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from native_profile_overhead import (output_identity,paired_statistics,percentile,
    recorded_plan,restore_new_workspace,tree_digest)
from native_profile_replay_worker import execute_plan


def application():
    return {"mode":"OFFICIAL_CODEX_NATIVE_TOOLS_NO_REPLACEMENT","status":"completed",
        "agent_id":"real-source-agent","task_id":"source-task","unmapped_items":[],
        "tool_calls":[{"call_id":"native-1","tool_name":"commandExecution",
            "arguments":{"command":"printf 'hello\\n'; printf x > result","cwd":"/original/work"}}],
        "native_tool_results":[{"call_id":"native-1","exit_code":0,
            "output":{"text":"hello\n","truncated":False,"size_bytes":6}}]}


class RecordedPlanTests(unittest.TestCase):
    def test_exact_native_command_and_output_are_preserved_no_original_path_rewrite(self):
        source=application()
        plan=recorded_plan(source,Path("/original/work"))
        self.assertEqual(plan["commands"][0]["command"],source["tool_calls"][0]["arguments"]["command"])
        self.assertEqual(plan["commands"][0]["relative_cwd"],".")
        self.assertEqual(plan["commands"][0]["source_output_digest"],
            {"sha256":hashlib.sha256(b"hello\n").hexdigest(),"size_bytes":6})
        self.assertIn("NOT_WHOLE_AGENT",plan["scope"])

    def test_apply_patch_mcp_unknown_or_truncated_work_is_not_silently_omitted(self):
        for kind in ("fileChange","mcpToolCall","sleep","collabAgentToolCall"):
            source=application();source["tool_calls"].append({"call_id":"other","tool_name":kind})
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,"NOT_REPLAYABLE"):
                recorded_plan(source,Path("/original/work"))
        for field,value in (("unmapped_items",[{"item_type":"codeModeUnknown"}]),("status","failed"),
                ("mode","LOCAL_DETERMINISTIC_FIXTURE_NO_MODEL_NO_PAID_API")):
            source=application();source[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):recorded_plan(source,Path("/original/work"))
        source=application();source["native_tool_results"][0]["output"]["truncated"]=True
        with self.assertRaisesRegex(ValueError,"truncated"):recorded_plan(source,Path("/original/work"))

    def test_external_cwd_or_absolute_original_workspace_command_rejected(self):
        for key,value in (("cwd","/outside"),("command","cat /original/work/secret"),("cwd","/original/work/../outside")):
            source=application();source["tool_calls"][0]["arguments"][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):recorded_plan(source,Path("/original/work"))


class PairedStatisticsTests(unittest.TestCase):
    def test_reports_exact_paired_ratio_and_interval(self):
        pairs=[{"off_ms":10+i,"full_ms":(10+i)*1.1} for i in range(5)]
        result=paired_statistics(pairs,seed=7,bootstrap=100)
        self.assertAlmostEqual(result["paired_slowdown"]["median_percent"],10)
        self.assertAlmostEqual(result["paired_slowdown"]["bootstrap_95_percent"][0],10)
        self.assertAlmostEqual(result["paired_slowdown"]["bootstrap_95_percent"][1],10)
        self.assertEqual(result["off_wall_ms"]["median"],12)
        self.assertAlmostEqual(result["off_wall_ms"]["p95"],13.8)

    def test_less_than_five_invalid_or_zero_samples_not_promoted(self):
        with self.assertRaises(ValueError):paired_statistics([{"off_ms":1,"full_ms":2}]*4)
        for value in (0,-1,float("nan"),float("inf")):
            with self.subTest(value=value),self.assertRaises(ValueError):
                paired_statistics([{"off_ms":value,"full_ms":2}]*5)


class RealLocalCommandReplayTests(unittest.TestCase):
    def test_pyc_normalization_is_opt_in_and_changes_only_source_mtime_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);cache=root/"__pycache__";cache.mkdir();path=cache/"a.cpython-313.pyc"
            content=b"\xf3\x0d\r\n"+b"\0"*4+b"aaaa"+b"size"+b"unchanged-bytecode"
            path.write_bytes(content);raw=tree_digest(root);logical=tree_digest(root,normalize_pyc_timestamp=True)
            path.write_bytes(content[:8]+b"bbbb"+content[12:])
            self.assertNotEqual(tree_digest(root),raw)
            self.assertEqual(tree_digest(root,normalize_pyc_timestamp=True),logical)
            path.write_bytes(content[:16]+b"changed-bytecode")
            self.assertNotEqual(tree_digest(root,normalize_pyc_timestamp=True),logical)

    def test_real_exact_work_output_and_final_digest_match_after_restore(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);baseline=root/"baseline";baseline.mkdir()
            (baseline/"input").write_text("fixed input\n")
            campaign=root/"campaign";campaign.mkdir();archives=campaign/"retained-workspaces";archives.mkdir()
            workspace=campaign/"workspace";plan=recorded_plan(application(),Path("/original/work"))
            outputs=[];trees=[]
            before=tree_digest(baseline)
            for index in range(2):
                restore_new_workspace(baseline,workspace,archives/("before-%d"%index))
                self.assertEqual(tree_digest(workspace),before)
                destination=campaign/("result-%d"%index);destination.mkdir()
                result=execute_plan(plan,workspace,destination)
                self.assertTrue(result["complete"])
                outputs.append(output_identity(result));trees.append(tree_digest(workspace))
                self.assertEqual(result["commands"][0]["output"],plan["commands"][0]["source_output_digest"])
                self.assertEqual((workspace/"result").read_bytes(),b"x")
            self.assertEqual(outputs[0],outputs[1]);self.assertEqual(trees[0],trees[1])
            self.assertEqual(tree_digest(baseline),before)
            self.assertTrue((archives/"before-1/result").is_file())

    def test_baseline_hardlinks_and_symlinks_retained_without_linking_baseline_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);baseline=root/"baseline";baseline.mkdir()
            (baseline/"a").write_bytes(b"a");os.link(baseline/"a",baseline/"b");(baseline/"link").symlink_to("a")
            campaign=root/"campaign";campaign.mkdir();archive=campaign/"retained-workspaces";archive.mkdir()
            workspace=campaign/"workspace"
            restore_new_workspace(baseline,workspace,archive/"first")
            self.assertEqual(tree_digest(workspace),tree_digest(baseline))
            self.assertEqual((workspace/"a").stat().st_ino,(workspace/"b").stat().st_ino)
            self.assertNotEqual((workspace/"a").stat().st_ino,(baseline/"a").stat().st_ino)
            with self.assertRaises(ValueError):restore_new_workspace(baseline,baseline,archive/"unsafe")


if __name__=="__main__":unittest.main()
