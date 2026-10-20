import unittest

from execution_metrics import model_requests, model_collection, partition_wall, memory_data


class MetricsTests(unittest.TestCase):
    def test_missing_model_finish_and_collection_failure_are_not_silently_complete(self):
        rows=[{"event":"MODEL_REQUEST_ACCEPTED","request_id":"lost","task_label":"t"}]
        state=model_collection(rows,[],None,"t","b")
        self.assertEqual(state["status"],"PARTIAL")
        self.assertEqual(state["unfinished_request_ids"],["lost"])
        receipt={"task_label":"t","boot_id":"b","status":"STOPPED","collection_errors":0,
            "requests_started":1,"requests_finished":1}
        finished=[{"request_id":"lost"}]
        self.assertEqual(model_collection(rows,finished,receipt,"t","b")["status"],
            "COMPLETE_AT_DECLARED_HTTP_BOUNDARY")
        receipt["collection_errors"]=1
        self.assertEqual(model_collection(rows,finished,receipt,"t","b")["status"],"PARTIAL")
        receipt["task_label"]="other"
        with self.assertRaisesRegex(ValueError,"summary identity"):
            model_collection(rows,finished,receipt,"t","b")

    def test_remote_monotonic_is_duration_only_and_links_by_call_id(self):
        row={"event":"MODEL_REQUEST_FINISHED","request_id":"m1","task_label":"task",
            "clock":"CLOCK_MONOTONIC","boot_id":"host","timestamps_ns":{"accepted":100,
                "request_end":300},"durations_ns":{"request_total":200},"output_tool_call_ids":["c1"]}
        model=model_requests([row],[{"call_id":"c1","tool_call_id":"t1","semantic_path":["search"]}],"guest","task")
        self.assertEqual(model[0]["bound_tool_call_ids"],["t1"])
        self.assertEqual(model[0]["clock_alignment"],"DIFFERENT_BOOT_DURATION_ONLY")
        wall=partition_wall(0,1000,[],model,None,"guest")
        self.assertEqual(wall["totals_ns"],{"UNRESOLVED_RUNTIME":1000})

    def test_wall_overlap_is_counted_once_and_unresolved_retained(self):
        tools=[{"call_id":"t1","requested_ns":20,"execution_begin_ns":30,"execution_end_ns":70,"delivered_ns":80}]
        model=[{"request_id":"m1","clock_alignment":"SAME_BOOT","begin_ns":0,"end_ns":40,
            "timestamps_ns":{"upstream_dispatch":5,"upstream_first_byte":15,"upstream_end":35}}]
        wall=partition_wall(0,100,tools,model,None,"guest")
        self.assertEqual(sum(wall["totals_ns"].values()),100)
        self.assertEqual(wall["totals_ns"]["CONCURRENT"],20)
        self.assertEqual(wall["totals_ns"]["UNRESOLVED_RUNTIME"],20)

    def test_resource_boot_change_is_rejected(self):
        with self.assertRaisesRegex(ValueError,"boot differs"):
            memory_data({"boot_id":"host"},[],"guest",0,100)

    def test_unrelated_model_request_without_registration_is_not_assigned(self):
        row={"event":"MODEL_REQUEST_FINISHED","request_id":"unrelated","task_label":"another",
            "clock":"CLOCK_MONOTONIC","boot_id":"guest","timestamps_ns":{"accepted":1,
                "request_end":10},"durations_ns":{"request_total":9},"output_tool_call_ids":[]}
        self.assertEqual(model_requests([row],[],"guest"),[])

    def test_stream_delivery_can_overlap_upstream_but_false_duration_is_rejected(self):
        row={"event":"MODEL_REQUEST_FINISHED","request_id":"m","task_label":"t",
            "clock":"CLOCK_MONOTONIC","boot_id":"g","timestamps_ns":{"accepted":0,
                "upstream_dispatch":1,"upstream_headers":2,"response_delivery_start":3,
                "upstream_first_byte":4,"upstream_end":8,"response_delivery_end":9,"request_end":10},
            "durations_ns":{"request_total":10,"time_to_first_byte":3,"first_byte_to_end":4,"delivery":6}}
        self.assertEqual(model_requests([row],[],"g","t")[0]["request_ms"],10/1e6)
        row["durations_ns"]["time_to_first_byte"]=999
        with self.assertRaisesRegex(ValueError,"duration differs"):
            model_requests([row],[],"g","t")

    def test_two_simultaneous_tools_and_unrelated_parent_wait_remain_parallel(self):
        tools=[{"call_id":"a","requested_ns":0,"execution_begin_ns":0,"execution_end_ns":10,"delivered_ns":10},
               {"call_id":"b","requested_ns":0,"execution_begin_ns":0,"execution_end_ns":10,"delivered_ns":10}]
        self.assertEqual(partition_wall(0,10,tools,[],None,"g")["totals_ns"],{"CONCURRENT":10})
        mode={"invocations":[{"call_id":"parent","boot_id":"g","segments":[
            {"kind":"AWAIT","begin_ns":0,"end_ns":10,"child_call_ids":["other"]}]}]}
        self.assertEqual(partition_wall(0,10,tools[:1],[],mode,"g")["totals_ns"],{"CONCURRENT":10})
        mode["invocations"][0]["segments"][0]["child_call_ids"]=["a"]
        self.assertEqual(partition_wall(0,10,tools[:1],[],mode,"g")["totals_ns"],{"TOOL_EXECUTION":10})

    def test_resource_pid_identity_cannot_be_reused_under_same_target_name(self):
        target={"name":"agent","pid":1,"start_ticks":2,"role":"AGENT_RUNTIME","agent_id":"a"}
        summary={"boot_id":"g","agent_id":"a","targets":[{"target":target}]}
        sample={"event":"RESOURCE_SAMPLE","boot_id":"g","begin_ns":1,"end_ns":2,
            "target":dict(target),"process":{"start_ticks":3,"values":{"rss_bytes":100}}}
        with self.assertRaisesRegex(ValueError,"PID lifetime"):
            memory_data(summary,[sample],"g",0,10,"a")

    def test_memory_replay_recovers_existing_pid_fields_but_not_missing_cgroup(self):
        target={"name":"agent","pid":1,"start_ticks":2,"role":"AGENT_RUNTIME","agent_id":"a",
                "cgroup":None,"cgroup_identity":None}
        summary={"boot_id":"g","agent_id":"a","interval_ms":100,"targets":[{"target":target,
                  "sampled_rss_peak_bytes":999999}]}
        sample={"event":"RESOURCE_SAMPLE","boot_id":"g","begin_ns":1,"end_ns":2,
            "target":target,"process":{"status":"OBSERVED","start_ticks":2,"values":{
                "rss_bytes":100,"rss_anon_bytes":60,"rss_file_bytes":40}}}
        data=memory_data(summary,[sample],"g",0,10,"a")
        self.assertEqual(data["targets"][0]["sampled_rss_peak_bytes"],100)
        self.assertEqual(data["targets"][0]["sampled_process_rss_anon_peak_bytes"],60)
        self.assertEqual(data["targets"][0]["sampled_process_rss_file_peak_bytes"],40)
        self.assertEqual(data["targets"][0]["memory_metrics"]["cgroup_file"]["reason"],
                         "CGROUP_NOT_REGISTERED_FOR_TARGET")
        self.assertEqual(data["lifecycle_markers"],[])
        self.assertEqual(data["targets"][0]["lifecycle"]["status"],"END_NOT_RECORDED")

    def test_memory_retains_cleanup_window_and_confirmed_exit_marker_without_fake_zero(self):
        target={"name":"agent","pid":1,"start_ticks":2,"role":"AGENT_RUNTIME","agent_id":"a"}
        rows=[]
        for stamp in (5,15,25):
            rows.append({"event":"RESOURCE_SAMPLE","boot_id":"g","begin_ns":stamp,"end_ns":stamp+1,
                "target":target,"process":{"status":"OBSERVED","start_ticks":2,
                                              "values":{"rss_bytes":100}}})
        rows.append({"event":"RESOURCE_TARGET_FINISHED","boot_id":"g","monotonic_ns":30,
            "target":target,"lifecycle":{"status":"EXIT_CONFIRMED","confirmed_exit":True,
                                           "end_ns":30,"exit_returncode":0,"reason":"WAIT_RETURNED"}})
        summary={"boot_id":"g","agent_id":"a","targets":[{"target":target}]}
        data=memory_data(summary,rows,"g",10,20,"a")
        self.assertEqual(len(data["series"]),1)
        self.assertEqual(len(data["capture_series"]),3)
        self.assertEqual(data["capture_begin_ms"],-5/1e6)
        self.assertEqual(data["capture_end_ms"],20/1e6)
        self.assertFalse(data["lifecycle_markers"][0]["within_agent_window"])
        self.assertTrue(all(row["rss_bytes"]==100 for row in data["capture_series"]))

    def test_resource_lifecycle_wrong_boot_and_cgroup_identity_are_rejected(self):
        identity={"path":"/cg","inode":1,"device":2}
        target={"name":"agent","pid":1,"start_ticks":2,"role":"AGENT_RUNTIME","agent_id":"a",
                "cgroup_identity":identity,"cgroup":"/cg"}
        summary={"boot_id":"g","agent_id":"a","targets":[{"target":target}]}
        finished={"event":"RESOURCE_TARGET_FINISHED","boot_id":"other","monotonic_ns":30,
            "target":target,"lifecycle":{"status":"EXIT_CONFIRMED","confirmed_exit":True,"end_ns":30}}
        with self.assertRaisesRegex(ValueError,"boot differs"):
            memory_data(summary,[finished],"g",10,20,"a")
        row={"event":"RESOURCE_SAMPLE","boot_id":"g","begin_ns":15,"end_ns":16,"target":target,
            "cgroup":{"identity":{**identity,"inode":3},"values":{"memory.current":100}}}
        with self.assertRaisesRegex(ValueError,"registered identity differs"):
            memory_data(summary,[row],"g",10,20,"a")

    def test_code_mode_refines_same_call_not_fake_parallel_work(self):
        tools=[{"call_id":"code","requested_ns":0,"execution_begin_ns":0,
            "execution_end_ns":30,"delivered_ns":30,"semantic_path":["prepare"]}]
        mode={"invocations":[{"call_id":"code","boot_id":"g","segments":[
            {"kind":"JS","begin_ns":0,"end_ns":10},
            {"kind":"AWAIT","begin_ns":10,"end_ns":20,"child_call_ids":["child"]},
            {"kind":"OTHER","begin_ns":20,"end_ns":30}]}]}
        wall=partition_wall(0,30,tools,[],mode,"g")
        self.assertEqual(wall["totals_ns"],{"CODE_MODE_JS":10,"CODE_MODE_AWAIT":10,"CODE_MODE_OTHER":10})
        self.assertEqual(wall["segments"][0]["semantic_path"],["prepare"])
        child={"call_id":"child","requested_ns":10,"execution_begin_ns":10,
            "execution_end_ns":20,"delivered_ns":20}
        self.assertEqual(partition_wall(0,30,tools+[child],[],mode,"g")["totals_ns"],
            {"CODE_MODE_JS":10,"TOOL_EXECUTION":10,"CODE_MODE_OTHER":10})
        child["call_id"]="unrelated"
        self.assertEqual(partition_wall(0,30,tools+[child],[],mode,"g")["totals_ns"],
            {"CODE_MODE_JS":10,"CONCURRENT":10,"CODE_MODE_OTHER":10})


if __name__=="__main__":unittest.main()
