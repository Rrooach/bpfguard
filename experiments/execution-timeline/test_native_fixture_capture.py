"""Offline bounds tests; these tests never load eBPF or invent a kernel report."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from native_fixture_capture import NativeFixtureCapture
from validate_runtime_metrics import input_read_proof


class NativeFixtureTests(unittest.TestCase):
    def test_unowned_scope_is_rejected_before_binary_copy_or_bpf_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError,"newly owned tool"):
                NativeFixtureCapture(temporary,"/missing","/missing",temporary,"run")

    def test_tool_ledger_keeps_independent_prerelease_and_final_bindings(self):
        capture=object.__new__(NativeFixtureCapture)
        capture.ledger=mock.Mock()
        capture.ledger.fileno.return_value=0
        capture.tool=None
        row={"tool_call_id":"tool","root":{"tid":10},"begin_ns":None,"end_ns":None}
        with mock.patch("native_fixture_capture.os.fsync"):
            capture.event("TOOL_ENROLLED",row)
            row["begin_ns"]=1
            capture.event("TOOL_START",row)
            row["end_ns"]=2
            capture.event("TOOL_END",row)
        emitted=[json.loads(call.args[0]) for call in capture.ledger.write.call_args_list]
        self.assertIsNone(emitted[0]["begin_ns"])
        self.assertIsNone(emitted[1]["end_ns"])
        row["root"]["tid"]=999
        self.assertEqual(capture.tool["root"]["tid"],10)
        self.assertEqual(emitted[2]["event"],"TOOL_END")

    def test_no_completed_tool_cannot_produce_manifest_or_report(self):
        capture=object.__new__(NativeFixtureCapture)
        capture.tool=None
        with self.assertRaisesRegex(ValueError,"completed gated tool"):
            capture.finish({})

    def test_input_read_proof_requires_actual_vfs_content_not_size_or_pipe(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"input.bin"
            path.write_bytes(b"test")
            stat=path.stat()
            file={"path":str(path),"inode":stat.st_ino,"device_major":os.major(stat.st_dev),
                "device_minor":os.minor(stat.st_dev),"mount_id_unique":1,"size":4,
                "read":{"start_ns":2,"end_ns":3,"requested_bytes":4,"returned_bytes":4}}
            pipe={"path":"pipe:[123]","inode":123,"mount_id_unique":2,
                "read":{"start_ns":4,"end_ns":5,"requested_bytes":100,"returned_bytes":99}}
            report={"threads":[{"tid":1,"birth_ns":1,"calls":[
                {"call_id":1,"name":"read","files":[file,file]},
                {"call_id":2,"name":"read","files":[pipe]}]}]}
            proof=input_read_proof(report,path,4)
            self.assertEqual(proof["input_file_actual_read_bytes"],4)
            self.assertEqual(proof["input_file_vfs_read_calls"],1)
            self.assertEqual(proof["pipe_vfs_read_returned_bytes"],99)
            del file["read"]
            with self.assertRaisesRegex(RuntimeError,"actual input VFS reads 0"):
                input_read_proof(report,path,4)


if __name__=="__main__":unittest.main()
