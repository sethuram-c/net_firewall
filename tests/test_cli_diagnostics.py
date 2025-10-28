"""Phase 28: local read-only diagnostics and JSON CLI."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "userspace"))
import netfw_client as client
import netfw_protocol as protocol

class CliDiagnosticsTests(unittest.TestCase):
    def test_module_detected_exactly(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"modules"; p.write_text("netfw_hello 100 0 - Live 0\n")
            self.assertTrue(client.read_local_diagnostics(p,Path(d))["module_loaded"])
    def test_no_substring_false_positive(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"modules"; p.write_text("not_netfw_hello 100 0 - Live 0\n")
            self.assertFalse(client.read_local_diagnostics(p,Path(d))["module_loaded"])
    def test_empty_modules(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"modules"; p.write_text("")
            self.assertFalse(client.read_local_diagnostics(p,Path(d))["module_loaded"])
    def test_unreadable_modules(self):
        with self.assertRaises(OSError): client.read_local_diagnostics("/missing/netfw/modules")
    def test_sysfs_presence(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"modules"; p.write_text("")
            self.assertTrue(client.read_local_diagnostics(p,Path(d))["sysfs_module_present"])
    def test_diagnose_does_not_call_netlink(self):
        with patch.object(client,"read_local_diagnostics",return_value={"module_loaded":False}), patch.object(client,"request",side_effect=AssertionError("no socket")):
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(client.main(["diagnose"]),0)
    def test_diagnose_json(self):
        out=io.StringIO()
        with patch.object(client,"read_local_diagnostics",return_value={"module_loaded":True}),contextlib.redirect_stdout(out):
            self.assertEqual(client.main(["diagnose","--json"]),0)
        self.assertTrue(json.loads(out.getvalue())["module_loaded"])
    def test_status_json(self):
        out=io.StringIO()
        with patch.object(client,"request",return_value=protocol.Response(1,2,7,0)),contextlib.redirect_stdout(out):
            self.assertEqual(client.main(["status","--json","--request-id","7"]),0)
        self.assertEqual(json.loads(out.getvalue())["request_id"],7)
    def test_failure_returns_nonzero(self):
        with patch.object(client,"request",side_effect=OSError(111,"refused")),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(client.main(["ping"]),1)

if __name__ == "__main__": unittest.main()
