import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

from prepare_native_requests import prepare


class RequestsPreparationTests(unittest.TestCase):
    def archive(self, root):
        path = root / "task.tar"
        with tarfile.open(path, "w") as stream:
            content = b"unpatched baseline\n"
            member = tarfile.TarInfo("source.py")
            member.size = len(content)
            stream.addfile(member, io.BytesIO(content))
        return path

    def test_compatibility_inputs_recorded_and_task_not_patched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.archive(root)
            cgi = root / "historical-cgi.py"
            cgi.write_text("# explicit test stdlib stand-in\n")
            workspace = prepare(root, archive, sys.executable, cgi)
            self.assertEqual((workspace / "source.py").read_bytes(), b"unpatched baseline\n")
            self.assertEqual((workspace / ".observer-python-compat/cgi.py").read_bytes(), cgi.read_bytes())
            import json
            provenance = json.loads((root / "task-provenance.json").read_text())
            self.assertIsNotNone(provenance["cgi_compat_identity"])
            self.assertFalse(provenance["reference_patch_exposed"])
            self.assertEqual(len(provenance["environment_adaptation"]), 2)

    def test_no_implicit_cgi_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.archive(root)
            workspace = prepare(root, archive, sys.executable)
            self.assertFalse((workspace / ".observer-python-compat/cgi.py").exists())
            (workspace / "source.py").write_text("preserved user change\n")
            with self.assertRaisesRegex(ValueError, "no previous task is overwritten"):
                prepare(root, archive, sys.executable)
            self.assertEqual((workspace / "source.py").read_text(), "preserved user change\n")


if __name__ == "__main__":
    unittest.main()
