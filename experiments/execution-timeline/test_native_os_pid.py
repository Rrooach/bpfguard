#!/usr/bin/env python3
"""Offline itemId/osPid source replay, PID reuse, and native coverage tests."""
from copy import deepcopy
import os
from pathlib import Path
import tempfile
import unittest

from native_os_pid import NativeOsPidTracker,value_digest,verify_native_pid_links


class NativePidVerificationTests(unittest.TestCase):
    def fixture(self):
        app={"tool_calls":[{"call_id":"call","thread_id":"t","tool_name":"commandExecution"}]}
        report={"run":{"boot_id":"boot"},"tools":[{"tool_call_id":"codex-native-runtime",
            "association":"RUNTIME_GATE_AND_KERNEL_LIFETIME","root_key":"root"}],"threads":[
                {"key":"root","tid":10,"tgid":10,"birth_ns":1000000000,"end_ns":9000000000},
                {"key":"child","tid":11,"tgid":11,"birth_ns":2000000000,"exit_ns":5000000000,"parent_key":"root"}]}
        terminal={"itemId":"call","processId":"opaque-not-pid","osPid":11,"command":"printf x","cwd":"/workspace"}
        result={"data":[terminal],"nextCursor":None}
        observed={"event":"NATIVE_OS_PID_QUERY","boot_id":"boot","thread_id":"t","rpc_request_id":9,
            "query_begin_ns":3000000000,"response_received_ns":3100000000,"result_sha256":value_digest(result),
            "observations":[{**terminal,"status":"APP_OS_PID_AND_LIVE_PROC_IDENTITY_OBSERVED",
                "snapshot_begin_ns":3200000000,"snapshot_end_ns":3300000000,
                "process_snapshot":{"pid":11,"start_ticks":200,"clock_ticks":100}}]}
        raw=[{"direction":"CLIENT_TO_CODEX","message":{"id":9,"method":"thread/backgroundTerminals/list",
            "params":{"threadId":"t","limit":128}}},
            {"direction":"CODEX_TO_CLIENT","message":{"id":9,"result":result}}]
        return app,report,observed,raw

    def test_explicit_ospid_and_source_rpc_kernel_lifetime_match(self):
        app,report,row,raw=self.fixture()
        result=verify_native_pid_links(app,report,[row],raw)
        self.assertEqual(result["links"][0]["status"],"APP_REPORTED_OS_PID_KERNEL_LIFETIME_VERIFIED")
        self.assertEqual(result["links"][0]["processes"][0]["pid"],11)
        self.assertEqual(result["links"][0]["processes"][0]["application_process_handle"],"opaque-not-pid")

    def test_source_os_pid_tampering_is_not_a_process_match(self):
        app,report,row,raw=self.fixture();row["observations"][0]["osPid"]=12
        with self.assertRaisesRegex(ValueError,"original terminal item"):
            verify_native_pid_links(app,report,[row],raw)
        app,report,row,raw=self.fixture();row["result_sha256"]="wrong"
        with self.assertRaisesRegex(ValueError,"raw RPC"):verify_native_pid_links(app,report,[row],raw)

    def test_pid_reuse_other_boot_no_ancestry_or_exit_before_snapshot_stay_unbound(self):
        for kind in ("reuse","boot","parent","exit","newborn"):
            app,report,row,raw=self.fixture()
            if kind=="reuse":row["observations"][0]["process_snapshot"]["start_ticks"]=201
            if kind=="boot":row["boot_id"]="other"
            if kind=="parent":report["threads"][1]["parent_key"]=None
            if kind=="exit":report["threads"][1]["exit_ns"]=3250000000
            if kind=="newborn":
                report["threads"][1]["birth_ns"]=3050000000
                row["observations"][0]["process_snapshot"]["start_ticks"]=305
            with self.subTest(kind=kind):
                self.assertEqual(verify_native_pid_links(app,report,[row],raw)["links"][0]["status"],"UNBOUND")

    def test_null_os_pid_or_missing_live_identity_does_not_coerce_handle(self):
        app,report,row,raw=self.fixture();row["observations"][0]["status"]="OS_PID_NOT_EXPOSED"
        self.assertEqual(verify_native_pid_links(app,report,[row],raw)["links"][0]["status"],"UNBOUND")


class TrackerCollectionTests(unittest.TestCase):
    def test_query_records_actual_local_pid_identity_only_from_explicit_ospid(self):
        class RPC:
            next_id=7
            def request(self,method,params,timeout):
                self.method,self.params=method,params
                return {"data":[{"itemId":"call","processId":"opaque","osPid":os.getpid(),"command":"test","cwd":os.getcwd()}]}
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);group=root/"group";out=root/"out";group.mkdir();out.mkdir()
            (group/"cgroup.procs").write_text(str(os.getpid()))
            tracker=NativeOsPidTracker(out,group);rpc=RPC();tracker.query(rpc,"t",force=True);tracker.finish()
            self.assertEqual(rpc.method,"thread/backgroundTerminals/list")
            self.assertEqual(tracker.rows[0]["observations"][0]["process_snapshot"]["pid"],os.getpid())
            self.assertEqual(tracker.rows[0]["observations"][0]["status"],"APP_OS_PID_AND_LIVE_PROC_IDENTITY_OBSERVED")


if __name__=="__main__":unittest.main()
