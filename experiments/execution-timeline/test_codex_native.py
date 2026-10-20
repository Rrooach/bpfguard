#!/usr/bin/env python3
"""Offline native protocol/config tests; no provider, VM, BPF, or paid calls."""
import json
import os
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest

from codex_native_events import NativeEvents, run_native_agent
from codex_native_run import capture_window, native_command
from codex_run import start_runtime
from common import proc_identity
from native_process_samples import NativeProcessSampler, correlate_native_commands, process_snapshot
from replay import check_tool_ledger
from codex_tool_adapter import verify_codex_tool_sources
from test_codex_client import ScriptedRPC, builtin_item, complete


def message(kind, phase, call_id=None):
    item=builtin_item(kind,"inProgress" if phase=="started" else "completed")
    if call_id:item["id"]=call_id
    return {"method":"item/"+phase,"params":{"threadId":"thread-1","turnId":"turn-1","item":item}}


class NativeConfigTests(unittest.TestCase):
    def args(self,**changes):
        return SimpleNamespace(codex=Path("/native/codex"),broker_base_url="http://127.0.0.1:18001/v1",
            budget_label="codex-native-001",model="deepseek-flash",**changes)

    def test_native_tools_enabled_not_replaced_or_secret_in_argv(self):
        command,config=native_command(self.args(),Path("/catalog.json"))
        for name in ("shell_tool","unified_exec","code_mode","code_mode_host"):
            self.assertIs(config["features."+name],True)
        self.assertEqual(config["web_search"],"disabled")
        self.assertNotIn("observer_bash"," ".join(command))
        self.assertNotIn("dynamicTools"," ".join(command))
        self.assertEqual(config["model_providers.observer_proxy.request_max_retries"],0)
        self.assertEqual(config["model_providers.observer_proxy.env_key"],"OBSERVER_BROKER_TOKEN")

    def test_remote_or_credential_endpoint_and_malformed_label_rejected(self):
        for key,value in (("broker_base_url","https://api.deepseek.com/v1"),
                ("broker_base_url","http://secret@127.0.0.1:10001/v1"),
                ("broker_base_url","http://127.0.0.1:10001/v1?token=secret"),
                ("budget_label","bad label"),("model","bad\nmodel")):
            args=self.args();setattr(args,key,value)
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                native_command(args,Path("/catalog"))

    def test_transport_endpoint_changes_only_provider_url(self):
        _,before=native_command(self.args(),Path("/catalog"))
        _,after=native_command(self.args(),Path("/catalog"),base_url="http://127.0.0.1:18009/v1")
        self.assertEqual([key for key in before if before[key]!=after[key]],
            ["model_providers.observer_proxy.base_url"])


class NativeProtocolTests(unittest.TestCase):
    def test_real_native_notifications_retained_without_dynamic_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            rpc=ScriptedRPC([message("commandExecution","started"),message("commandExecution","completed"),complete()])
            result=run_native_agent(rpc,"public task",Path(temporary),Path(temporary),budget_label="codex-native-001")
            params=next(params for method,params in rpc.requests if method=="thread/start")
            self.assertNotIn("dynamicTools",params)
            self.assertIs(params["experimentalRawEvents"],True)
            self.assertEqual(result["function_bindings"],[])
            self.assertEqual(result["native_tool_results"][0]["output"]["text"],"hello")
            self.assertEqual(result["tool_calls"][0]["tool_name"],"commandExecution")
            self.assertEqual(result["native_tool_results"][0]["application_process_handle"],"pty-1")
            self.assertIn("UNBOUND",result["steps"][0]["linux_process_binding"])
            self.assertNotIn("root_pid",result["steps"][0])
            self.assertEqual(rpc.answers,[])

    def test_numeric_process_handle_still_never_pid(self):
        with tempfile.TemporaryDirectory() as temporary:
            events=NativeEvents(temporary,agent_id="a",task_id="t",thread_id="thread-1",turn_id="turn-1")
            for phase,ts in (("started",1),("completed",2)):
                value=message("commandExecution",phase)
                value["params"]["item"]["processId"]="1234"
                events.accept(value,ts)
            call=events.projection(require_complete=True)
            self.assertEqual(call["native_tool_results"][0]["application_process_handle"],"1234")
            self.assertEqual(call["function_bindings"],[])
            self.assertEqual(call["tool_calls"][0]["execution_binding"],"NOT_ESTABLISHED")

    def test_parallel_tools_and_original_rpc_source_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            events=NativeEvents(temporary,agent_id="a",task_id="t",thread_id="thread-1",turn_id="turn-1")
            incoming=[message("commandExecution","started"),message("mcpToolCall","started"),
                message("commandExecution","completed"),message("mcpToolCall","completed")]
            raw=[]
            for index,value in enumerate(incoming):
                raw.append({"direction":"CODEX_TO_CLIENT","receipt_ns":index+1,"message":value})
                events.accept(value,index+1)
            self.assertEqual(len(events.projection(require_complete=True)["tool_calls"]),2)
            receipt=verify_codex_tool_sources(raw,events.rows)
            self.assertEqual(receipt["status"],"RAW_RPC_TOOL_EVENTS_REPLAYED")

    def test_unexposed_native_items_preserved_and_not_fake_v8_timing(self):
        with tempfile.TemporaryDirectory() as temporary:
            events=NativeEvents(temporary,agent_id="a",task_id="t",thread_id="thread-1",turn_id="turn-1")
            value={"method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1",
                "item":{"id":"v8","type":"futureCodeModeItem"}}}
            events.accept(value,1)
            self.assertEqual(events.projection()["unmapped_items"][0]["item_type"],"futureCodeModeItem")
            self.assertEqual(events.projection()["tool_calls"],[])
            self.assertIn("NOT_EXPOSED",events.projection()["native_code_mode"])

    def test_unexpected_dynamic_tool_not_serviced(self):
        with tempfile.TemporaryDirectory() as temporary:
            rpc=ScriptedRPC([{"id":7,"method":"item/tool/call","params":{}}])
            with self.assertRaisesRegex(ValueError,"no tool replacement"):
                run_native_agent(rpc,"public task",Path(temporary),Path(temporary))
            self.assertEqual(rpc.answers,[])

    def test_mismatched_turn_or_missing_tool_end_rejected(self):
        for messages in ([message("commandExecution","started"),complete()],
                [{"method":"turn/completed","params":{"threadId":"other","turn":{"id":"turn-1","status":"completed"}}}]):
            with tempfile.TemporaryDirectory() as temporary,self.assertRaises(ValueError):
                run_native_agent(ScriptedRPC(messages),"public",Path(temporary),Path(temporary))


class NativeCandidateTests(unittest.TestCase):
    def fixture(self):
        report={"run":{"boot_id":"boot"},"tools":[{"tool_call_id":"codex-native-runtime","root_key":"root",
            "association":"RUNTIME_GATE_AND_KERNEL_LIFETIME"}],
            "threads":[{"key":"root","tid":10,"tgid":10,"birth_ns":1000000000,"parent_key":None},
                {"key":"shell","tid":11,"tgid":11,"birth_ns":2000000000,"parent_key":"root"}]}
        app={"tool_calls":[{"call_id":"call","tool_name":"commandExecution","requested_ns":3000000000,
            "result_delivered_ns":5000000000,"arguments":{"command":"printf hello","cwd":"/workspace"}}]}
        sample={"pid":11,"start_ticks":200,"clock_ticks":100,"boot_id":"boot",
            "argv":["/bin/bash","-lc","printf hello"],"cwd":"/workspace","end_ns":4000000000}
        return app,report,sample

    def test_unique_exact_candidate_is_not_causal_and_does_not_mutate_ownership(self):
        app,report,sample=self.fixture()
        result=correlate_native_commands(app,report,[sample])
        self.assertEqual(result["links"][0]["status"],"CORRELATED_NOT_CAUSAL")
        self.assertEqual(result["links"][0]["candidates"][0]["pid"],11)
        self.assertNotIn("function_bindings",app)

    def test_wrong_command_cwd_lifetime_boot_window_or_ancestry_not_matched(self):
        changes=[{"argv":["/bin/bash","-lc","printf  hello"]},{"cwd":"/other"},{"start_ticks":201},
            {"boot_id":"other"},{"end_ns":6000000000}]
        for change in changes:
            app,report,sample=self.fixture()
            with self.subTest(change=change):
                self.assertEqual(correlate_native_commands(app,report,[{**sample,**change}])["links"][0]["status"],"UNBOUND")
        app,report,sample=self.fixture();report["threads"][1]["parent_key"]=None
        self.assertEqual(correlate_native_commands(app,report,[sample])["links"][0]["status"],"UNBOUND")

    def test_multiple_candidates_remain_ambiguous(self):
        app,report,sample=self.fixture()
        report["threads"].append({"key":"shell-2","tid":12,"tgid":12,"birth_ns":2000000000,"parent_key":"root"})
        result=correlate_native_commands(app,report,[sample,{**sample,"pid":12}])
        self.assertEqual(result["links"][0]["status"],"AMBIGUOUS")
        self.assertEqual(len(result["links"][0]["candidates"]),2)


class NativeLocalLifecycleTests(unittest.TestCase):
    def test_capture_begin_is_not_overwritten_by_sigcont_release(self):
        from replay import build_report
        tool={"agent_id":"a","tool_call_id":"codex-native-runtime","invocation_ns":20,"begin_ns":30,
            "end_ns":40,"root":{"tid":1,"start_ticks":1,"clock_ticks":100}}
        manifest={"schema_version":1,"boot_id":"boot","tools":[tool],**capture_window(10,50,tool)}
        result=build_report([],manifest,{"status":"COMPLETE","counters":{}})
        self.assertEqual(result["run"]["begin_ns"],10)
        with self.assertRaisesRegex(ValueError,"capture start"):
            capture_window(tool["begin_ns"],50,tool)
        with self.assertRaisesRegex(ValueError,"invocation must precede"):
            build_report([],{**manifest,"begin_ns":tool["begin_ns"]},{"status":"COMPLETE","counters":{}})

    def test_actual_stopped_launch_enrolls_same_root_before_exec(self):
        # A regular file substitutes for cgroup.procs solely in this local
        # lifecycle test. It makes no cgroup or provider mutation.
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);group=root/"group";target=root/"runtime"
            group.mkdir();target.mkdir()
            (group/"cgroup.procs").write_text("")
            pid,read_fd,write_fd=start_runtime(["/bin/sh","-c","printf native-actual-exec"],group,target,root,{"PATH":"/usr/bin:/bin"})
            try:
                self.assertEqual((group/"cgroup.procs").read_text(),str(pid))
                identity=proc_identity(pid)
                self.assertEqual(identity["tid"],pid)
                os.kill(pid,signal.SIGCONT)
                os.close(write_fd);write_fd=None
                self.assertEqual(os.read(read_fd,1024),b"native-actual-exec")
                _,status=os.waitpid(pid,0);pid=None
                self.assertTrue(os.WIFEXITED(status))
                self.assertEqual(os.WEXITSTATUS(status),0)
            finally:
                if write_fd is not None:os.close(write_fd)
                os.close(read_fd)
                if pid is not None:
                    os.kill(pid,signal.SIGKILL)
                    os.waitpid(pid,0)

    def test_process_samples_are_explicitly_bounded_and_not_lifetime_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);group=root/"group";out=root/"out"
            group.mkdir();out.mkdir();(group/"cgroup.procs").write_text(str(os.getpid()))
            actual=process_snapshot(os.getpid())
            self.assertEqual(actual["pid"],os.getpid())
            self.assertTrue(actual["argv"])
            sampler=NativeProcessSampler(group,out,max_records=1)
            sampler.sample();rows=sampler.stop()
            self.assertEqual(len(rows),1)
            summary=json.loads((out/"native-process-sampling-summary.json").read_text())
            self.assertEqual(summary["status"],"SAMPLED_NOT_EXHAUSTIVE")
            self.assertTrue(summary["sample_limit_reached"])

    def test_collector_requires_pre_release_enrollment(self):
        from codex_client import append_record
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            tool={"agent_id":"a","task_id":"t","tool_call_id":"codex-native-runtime","root":{"tid":1,"start_ticks":1},
                "cgroup_id":5,"command":["codex"],"invocation_ns":10,"begin_ns":None,"end_ns":None}
            append_record(root/"tool-spans.jsonl",{"event":"TOOL_ENROLLED",**tool})
            tool["begin_ns"]=20
            append_record(root/"tool-spans.jsonl",{"event":"TOOL_START",**tool})
            tool["end_ns"]=30
            append_record(root/"tool-spans.jsonl",{"event":"TOOL_END",**tool})
            check_tool_ledger(root,{"tools":[tool]})


if __name__=="__main__":
    unittest.main()
