"""Runtime cgroup ownership/cleanup checks; no shared kernel groups modified."""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import codex_harbor_agent as runtime


class RuntimeCgroupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cg = self.root / "cgroup"
        self.cg.mkdir()
        self.path = self.cg / ("observer-runtime-fixture-" + "a" * 32) / "runtime"
        self.path.mkdir(parents=True)
        (self.path / "cgroup.events").write_text("populated 0\n")
        (self.path / "cgroup.procs").write_text("")
        (self.path / "cgroup.kill").write_text("0")
        self.app = self.root / "app"
        self.app.mkdir()
        self.patch_root = mock.patch.object(runtime, "CGROUP_ROOT", self.cg)
        self.patch_root.start()
        self.addCleanup(self.patch_root.stop)
        self.patch_capture = mock.patch.object(runtime, "capture_cgroup", side_effect=self.capture)
        self.patch_capture.start()
        self.addCleanup(self.patch_capture.stop)

    @staticmethod
    def capture(path):
        # These are explicitly synthetic filesystem counters, not cgroup data.
        return {"identity":runtime._runtime_cgroup_identity(Path(path)),"status":"COMPLETE",
                "values":{"memory.current":123,"memory.stat":{"anon":100,"file":20}},"errors":{}}

    def plan(self, owned=True):
        return runtime._prepare_runtime_cgroup(SimpleNamespace(runtime_cgroup=self.path,
                                                               runtime_cgroup_owned=owned))

    def test_only_explicit_owned_flag_marks_fresh_scope(self):
        plan = self.plan()
        self.assertTrue(plan["owned"])
        self.assertIn("FRESH_EXCLUSIVE", plan["scope"])
        settings = SimpleNamespace(runtime_cgroup=self.path)
        shared = runtime._prepare_runtime_cgroup(settings)
        self.assertFalse(shared["owned"])
        self.assertNotIn("FRESH_EXCLUSIVE", shared["scope"])
        with self.assertRaisesRegex(runtime.ObserverBindingError,"non-owned"):
            runtime._kill_owned_runtime_cgroup(shared)
        self.assertEqual((self.path / "cgroup.kill").read_text(),"0")

    def test_owned_group_requires_empty_fresh_leaf_and_no_nested_cgroup(self):
        (self.path / "cgroup.procs").write_text("123\n")
        with self.assertRaisesRegex(runtime.ObserverBindingError,"start empty"):
            self.plan()
        (self.path / "cgroup.procs").write_text("")
        nested = self.path / "nested"
        nested.mkdir()
        with self.assertRaisesRegex(runtime.ObserverBindingError,"no nested"):
            self.plan()
        nested.rmdir()
        other = self.cg / "shared"
        other.mkdir()
        with self.assertRaisesRegex(ValueError,"fresh UUID"):
            runtime._prepare_runtime_cgroup(SimpleNamespace(runtime_cgroup=other,runtime_cgroup_owned=True))

    def test_already_empty_group_records_no_kill_and_retains_charged_memory(self):
        plan = self.plan()
        with mock.patch.object(runtime,"_kill_owned_runtime_cgroup") as kill:
            receipt = runtime._close_runtime_cgroup(plan,self.app,123,0,100)
        kill.assert_not_called()
        self.assertFalse(receipt["forced_cleanup"])
        self.assertEqual(receipt["status"],"OWNED_CGROUP_ALREADY_EMPTY_NO_KILL")
        self.assertEqual(receipt["after"]["accounting"]["values"]["memory.current"],123)
        self.assertEqual(json.loads((self.app/"runtime-cgroup-cleanup.json").read_text()),receipt)

    def test_root_exit_with_remaining_descendant_records_before_and_forced_cleanup(self):
        plan = self.plan()
        before = {**plan["initial_state"],"populated":True,"pids":[os.getpid()]}
        after = {**plan["initial_state"],"populated":False,"pids":[]}
        with mock.patch.object(runtime,"_runtime_group_state",side_effect=[before,after]), \
                mock.patch.object(runtime,"_kill_owned_runtime_cgroup") as kill:
            receipt = runtime._close_runtime_cgroup(plan,self.app,123,0,100)
        kill.assert_called_once_with(plan)
        self.assertTrue(receipt["had_residual_processes_after_root_exit"])
        self.assertTrue(receipt["forced_cleanup"])
        self.assertFalse(receipt["after"]["populated"])
        fact = receipt["residual_processes_before_cleanup"][0]
        self.assertEqual(fact["pid"],os.getpid())
        self.assertIn("start_ticks",fact)
        self.assertIn("comm",fact)
        self.assertIn("exe",fact)
        self.assertNotIn("argv",fact)
        self.assertNotIn("environ",fact)

    def test_nonowned_cgroup_remains_readonly_even_when_populated(self):
        plan = self.plan(owned=False)
        (self.path/"cgroup.events").write_text("populated 1\n")
        (self.path/"cgroup.procs").write_text(str(os.getpid()))
        with mock.patch.object(runtime,"_kill_owned_runtime_cgroup") as kill:
            receipt = runtime._close_runtime_cgroup(plan,self.app,123,0,100)
        kill.assert_not_called()
        self.assertEqual(receipt["status"],"NOT_CLEANED_NONOWNED_SCOPE")
        self.assertTrue(receipt["after"]["populated"])
        self.assertFalse(receipt["forced_cleanup"])
        self.assertEqual((self.path/"cgroup.kill").read_text(),"0")

    def test_identity_change_blocks_kill_and_preserves_error_receipt(self):
        plan = self.plan()
        with mock.patch.object(runtime,"_runtime_cgroup_identity",return_value={**plan["identity"],"inode":-1}), \
                mock.patch.object(runtime,"_kill_owned_runtime_cgroup") as kill:
            with self.assertRaisesRegex(runtime.ObserverBindingError,"identity changed"):
                runtime._close_runtime_cgroup(plan,self.app,123,0,100)
        kill.assert_not_called()
        receipt=json.loads((self.app/"runtime-cgroup-cleanup.json").read_text())
        self.assertEqual(receipt["status"],"CLEANUP_FAILED_OR_IDENTITY_UNCONFIRMED")

    def test_kill_uses_bound_directory_and_rejects_missing_initial_proof(self):
        plan=self.plan()
        runtime._kill_owned_runtime_cgroup(plan)
        self.assertEqual((self.path/"cgroup.kill").read_text(),"1")
        del plan["initial_state"]
        with self.assertRaisesRegex(runtime.ObserverBindingError,"ownership evidence"):
            runtime._kill_owned_runtime_cgroup(plan)


if __name__=="__main__":
    unittest.main()
