import unittest
from runtime_rpc_phases import runtime_rpc_phases
from execution_metrics import partition_wall


class RuntimeRPCTests(unittest.TestCase):
    def rows(self):
        return [{"direction":"CLIENT_TO_CODEX","clock":"CLOCK_MONOTONIC","boot_id":"b","receipt_ns":1,
            "message":{"id":1,"method":"initialize"}},
            {"direction":"CODEX_TO_CLIENT","clock":"CLOCK_MONOTONIC","boot_id":"b","receipt_ns":9,
             "message":{"id":1,"result":{}}}]

    def test_explicit_initialization_refines_gap_not_cpu(self):
        phases=runtime_rpc_phases(self.rows(),"b",0,10)
        self.assertEqual(phases[0]["begin_ns"],1)
        wall=partition_wall(0,10,[],[],None,"b",runtime_phases=phases)
        self.assertEqual(wall["totals_ns"],{"UNRESOLVED_RUNTIME":2,"RUNTIME_INITIALIZE":8})
        tool={"call_id":"t","requested_ns":2,"execution_begin_ns":2,"execution_end_ns":8,"delivered_ns":8}
        self.assertEqual(partition_wall(0,10,[tool],[],None,"b",runtime_phases=phases)["totals_ns"],
            {"UNRESOLVED_RUNTIME":2,"RUNTIME_INITIALIZE":2,"TOOL_EXECUTION":6})

    def test_missing_ack_does_not_invent_phase(self):
        self.assertEqual(runtime_rpc_phases(self.rows()[:1],"b",0,10),[])

    def test_foreign_clock_duplicate_request_and_reversed_receipt_rejected(self):
        rows=self.rows();rows[1]["boot_id"]="foreign"
        with self.assertRaisesRegex(ValueError,"boot/clock"):runtime_rpc_phases(rows,"b",0,10)
        rows=self.rows();rows.insert(1,rows[0])
        with self.assertRaisesRegex(ValueError,"duplicate"):runtime_rpc_phases(rows,"b",0,10)
        rows=self.rows();rows[1]["receipt_ns"]=0
        with self.assertRaisesRegex(ValueError,"reversed"):runtime_rpc_phases(rows,"b",0,10)
