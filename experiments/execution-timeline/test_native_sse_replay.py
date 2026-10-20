#!/usr/bin/env python3
"""Real loopback replay HTTP; no upstream network or model inference."""
import http.client
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

from common import write_new
from codex_native_run import collect_native
from native_sse_replay import NativeSSEReplayServer,load_trace
from native_agent_replay_overhead import archive_verified_arm,business_identity,evidence_sink_preflight,fresh_native_worker,native_worker_command,normalize_native_output,normalize_outer_output,restore_fixed_workspace,workload_identity


class ReplayHTTPTests(unittest.TestCase):
    def trace(self,root):
        tools=[{"type":"custom","name":"exec","format":{"type":"text"}}]
        body=b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"recorded","status":"completed","output":[]}}\n\n'
        write_new(root/"source-step-1-native-request.json",{"model":"deepseek-flash","tools":tools})
        write_new(root/"source-step-1-delivered.sse",body)
        return load_trace(root,"source"),tools,body

    def request(self,server,tools,*,token="LOCAL-REPLAY"):
        connection=http.client.HTTPConnection("127.0.0.1",server.server.server_address[1],timeout=5)
        connection.request("POST","/v1/responses",body=json.dumps({"model":"deepseek-flash","tools":tools,"input":[]}),
            headers={"Authorization":"Bearer "+token,"X-Benchmark-Task":"native-trace-replay","Content-Type":"application/json"})
        response=connection.getresponse();status=response.status;body=response.read();connection.close()
        return status,body

    def test_exact_saved_sse_and_request_bound_no_external_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            entries,tools,body=self.trace(Path(temporary));server=NativeSSEReplayServer(entries,"LOCAL-REPLAY").start()
            try:
                self.assertEqual(self.request(server,tools),(200,body))
                receipt=server.receipt();self.assertTrue(receipt["complete"]);self.assertEqual(receipt["paid_api_calls"],0)
                self.assertEqual(self.request(server,tools)[0],409)
                self.assertFalse(server.receipt()["complete"])
                server.reset();self.assertEqual(self.request(server,tools),(200,body))
            finally:server.stop()

    def test_wrong_schema_or_credentials_never_consumes_recording(self):
        with tempfile.TemporaryDirectory() as temporary:
            entries,tools,_=self.trace(Path(temporary));server=NativeSSEReplayServer(entries,"LOCAL-REPLAY").start()
            try:
                self.assertEqual(self.request(server,tools,token="wrong")[0],401)
                self.assertEqual(server.cursor,0)
                self.assertEqual(self.request(server,[{"type":"function","name":"observer_bash"}])[0],409)
                self.assertEqual(server.cursor,0)
            finally:server.stop()


class AgentReplayCorrectnessTests(unittest.TestCase):
    def worker_args(self,root):
        paths=("collector","object","codex","catalog","workspace","prompt","output","broker_token_file","cgroup_parent")
        return SimpleNamespace(**{name:root/name for name in paths},broker_base_url="http://127.0.0.1:1234/v1",
            budget_label="replay",model="same-model",agent_id="agent",task_id="task",run_id="run",timeout=1,
            ring_bytes=64*1024**2,max_records=1000,max_bytes=1000000,process_sample_ms=20,capture_mode="off",
            provider_provenance="REPLAYED_PROVIDER_RESPONSES_NOT_NEW_INFERENCE",exec_args_collector=None,exec_args_object=None)

    def test_fresh_worker_execs_python_and_preserves_cli_evidence(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);script=root/"worker.py"
            script.write_text('import json,os,sys; print(json.dumps({"verification":"TEST_ONLY", "pid":os.getpid(),"argv":sys.argv[1:]}))')
            args=self.worker_args(root)
            outcome,receipt=fresh_native_worker(args,root/"logs","pair-00-off",script=script)
            self.assertNotEqual(outcome["pid"],os.getpid());self.assertEqual(receipt["pid"],outcome["pid"])
            self.assertEqual(receipt["return_code"],0)
            self.assertIn("--capture-mode",outcome["argv"])
            self.assertEqual(receipt["argv"],native_worker_command(args,script))
            self.assertTrue(Path(receipt["stdout_artifact"]).is_file())
            self.assertTrue((root/"logs/pair-00-off-worker.json").is_file())

    def test_fresh_worker_rejects_oversize_json_but_retains_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);script=root/"worker.py";script.write_text('print("x"*1000)')
            with self.assertRaises(ValueError):fresh_native_worker(self.worker_args(root),root/"logs","pair-00-off",script=script,max_output_bytes=128)
            self.assertEqual((root/"logs/pair-00-off.stdout").stat().st_size,1001)

    def test_unittest_footer_only_duration_changes_not_business_or_test_count(self):
        text="business time 0.1s\n----------------------------------------------------------------------\nRan 4 tests in 0.003s\n\nOK\n"
        value={"text":text,"truncated":False,"size_bytes":len(text)}
        normalized=normalize_native_output(value,"python -m unittest -v tests")
        self.assertIn("business time 0.1s",normalized["text"])
        self.assertIn("Ran 4 tests",normalized["text"])
        self.assertIn("OK",normalized["text"])
        self.assertEqual(normalize_native_output(value,"printf x"),value)
        changed={**value,"text":text.replace("4 tests","5 tests")}
        self.assertNotEqual(normalize_native_output(changed,"python -m unittest tests"),normalized)

    def test_ls_normalization_preserves_real_files_and_other_metadata(self):
        text="drwx------. 6 root root 4096 Oct 20 15:29 .\ndrwxr-xr-x. 7 root root 4096 Oct 20 15:29 ..\n-rw-rw-r-- 1 root root 12 Oct 20 15:29 code.py\n"
        value={"text":text,"truncated":False,"size_bytes":len(text)}
        normalized=normalize_native_output(value,"ls -la | head","/fixed/workspace")
        self.assertEqual(normalized["text"].count("DIRECTORY_MTIME"),2)
        self.assertIn("DIRECTORY_MTIME:/fixed/workspace",normalized["text"])
        self.assertIn("Oct 20 15:29 code.py",normalized["text"])
        self.assertIn("6 root root 4096",normalized["text"])
        self.assertEqual(normalize_native_output(value,"ls -la /unbound/path","/fixed/workspace"),value)

    def test_only_known_metadata_only_outer_block_is_normalized(self):
        block=lambda duration:{"text":json.dumps([{"type":"input_text","text":"Script completed\nWall time "+duration+" seconds\nOutput:\n"},
            {"type":"input_text","text":"business output\nWall time 3 seconds\n"}]),"truncated":False,"size_bytes":1}
        self.assertEqual(normalize_outer_output(block("0.1")),normalize_outer_output(block("3.8")))
        self.assertIn("Wall time 3 seconds",normalize_outer_output(block("0.1"))[1]["text"])
        unsafe={"text":json.dumps([{"type":"input_text","text":"Script completed\nWall time 0.1 seconds\nOutput:\nactual output"}]),"truncated":False}
        self.assertEqual(normalize_outer_output(unsafe),unsafe)

    def test_inner_command_actual_output_and_exit_change_correctness_identity(self):
        base={"tool_calls":[{"tool_name":"commandExecution","arguments":{"command":"printf x","cwd":"/same/path"},"status":"SUCCEEDED","exit_code":0}],
            "native_tool_results":[{"tool_name":"commandExecution","exit_code":0,"producer_status":"completed",
                "output":{"text":"x","truncated":False,"size_bytes":1}}]}
        before=workload_identity(base)
        base["native_tool_results"][0]["output"]["text"]="y"
        self.assertNotEqual(workload_identity(base),before)
        base["native_tool_results"][0]["output"]["truncated"]=True
        with self.assertRaises(ValueError):workload_identity(base)

    def test_remote_tool_is_not_replayed_as_local_work(self):
        with self.assertRaises(ValueError):workload_identity({"tool_calls":[{"tool_name":"mcpToolCall"}]})

    def test_internal_aggregate_coverage_separate_from_model_delivered_business(self):
        from copy import deepcopy
        workload={"native_tools":[{"command":"fixed","exit":0}],"native_outputs":[{"partial":"prefix"}],
            "native_model_tool_calls":[{"status":"MATCHED_TOOL_OUTPUT_OBSERVED","request":{"text":"fixed JS","truncated":False},
                "output":{"text":"complete actual model result","truncated":False}}]}
        changed=deepcopy(workload);changed["native_outputs"][0]["partial"]="suffix"
        self.assertNotEqual(workload,changed)
        self.assertEqual(business_identity(workload),business_identity(changed))
        changed["native_model_tool_calls"][0]["output"]["text"]="different business result"
        self.assertNotEqual(business_identity(workload),business_identity(changed))
        changed["native_model_tool_calls"][0]["output"]["truncated"]=True
        with self.assertRaises(ValueError):business_identity(changed)

    def test_fixed_absolute_workspace_restored_and_original_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);baseline=root/"baseline";baseline.mkdir();(baseline/"original").write_text("base")
            workspace=root/"source-work";workspace.mkdir();(workspace/"previous-result").write_text("keep")
            campaign=root/"campaign";campaign.mkdir()
            restore_fixed_workspace(baseline,workspace,campaign,"first",root)
            self.assertTrue((workspace/"original").exists())
            self.assertEqual((campaign/"retained-workspaces/first/previous-result").read_text(),"keep")
            with self.assertRaises(ValueError):restore_fixed_workspace(baseline,workspace,campaign,"bad",Path("/tmp"))

    def test_off_dispatch_loads_no_collector_or_sampler(self):
        with mock.patch("codex_native_off.collect_native_off",return_value={"mode":"off"}) as execute:
            args=SimpleNamespace(capture_mode="off")
            self.assertEqual(collect_native(args),{"mode":"off"})
            execute.assert_called_once_with(args)

    def test_off_has_no_active_os_pid_query_tracker(self):
        import ast
        import inspect
        from codex_native_off import collect_native_off
        tree=ast.parse(inspect.getsource(collect_native_off))
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)]
        self.assertFalse(any(isinstance(call.func,ast.Name) and call.func.id=="NativeOsPidTracker" for call in calls))
        execute=next(call for call in calls if isinstance(call.func,ast.Name) and call.func.id=="run_native_agent")
        option=next(option for option in execute.keywords if option.arg=="os_pid_tracker")
        self.assertIsInstance(option.value,ast.Constant);self.assertIsNone(option.value.value)

    def test_archive_content_verified_before_exact_arm_reclaimed(self):
        import tarfile
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);scratch=root/"scratch";scratch.mkdir();archives=root/"archives";archives.mkdir()
            run=scratch/"pair-00-full";run.mkdir();(run/"events.bin").write_bytes(b"raw-proof\0")
            sibling=scratch/"pair-00-off";sibling.mkdir();(sibling/"keep").write_text("keep")
            receipt=archive_verified_arm(run,scratch,archives)
            self.assertEqual(receipt["content_comparison"],"TAR_COMPARE_PASSED")
            self.assertFalse(run.exists());self.assertTrue((sibling/"keep").is_file())
            with tarfile.open(receipt["archive"],"r:gz") as archive:
                self.assertEqual(archive.extractfile("pair-00-full/events.bin").read(),b"raw-proof\0")

    def test_archive_failure_never_reclaims_raw_and_rejects_non_arm(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);scratch=root/"scratch";scratch.mkdir();archives=root/"archives";archives.mkdir()
            run=scratch/"pair-01-full";run.mkdir();(run/"events.bin").write_text("proof")
            with mock.patch("native_agent_replay_overhead.subprocess.run",side_effect=subprocess.CalledProcessError(2,"tar")):
                with self.assertRaises(subprocess.CalledProcessError):archive_verified_arm(run,scratch,archives)
            self.assertTrue((run/"events.bin").is_file())
            with self.assertRaises(ValueError):archive_verified_arm(scratch,scratch,archives)

    def test_preflight_refuses_broad_or_non_tmpfs_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):evidence_sink_preflight(Path(temporary),Path(temporary))


if __name__=="__main__":unittest.main()
