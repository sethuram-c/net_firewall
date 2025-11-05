"""Phase 35: release audit contracts and portfolio integrity."""
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("final_audit", ROOT / "scripts/final_audit.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)

class FinalReleaseTests(unittest.TestCase):
    def test_read_only_audit_does_not_load_module(self):
        source = (ROOT / "scripts/final_audit.py").read_text()
        self.assertNotIn('sudo ', source)
        self.assertNotIn('subprocess.run(["insmod"', source)

    def test_audit_detects_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = AUDIT.audit(tmp, run_tests=False)
        self.assertFalse(result["complete"])
        self.assertIn("README.md", result["missing_files"])

    def test_audit_packaged_files(self):
        self.assertTrue(AUDIT.audit(ROOT, run_tests=False)["complete"])

    def test_module_is_optional_but_can_be_required(self):
        result = AUDIT.audit(ROOT, run_tests=False, require_module=True)
        self.assertEqual(result["complete"], result["module_present"])

    def test_cli_json_mode(self):
        done = subprocess.run([sys.executable, str(ROOT / "scripts/final_audit.py"), "--json", "--skip-tests"], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(json.loads(done.stdout)["complete"])

    def test_demo_has_all_privileged_regressions(self):
        demo = (ROOT / "docs/DEMO_RUNBOOK.md").read_text()
        for name in ("test_failure_paths.sh", "test_verdict_regression.sh", "test_staged_lab_rules.sh", "test_lab_hardening.sh"):
            self.assertIn(name, demo)

    def test_architecture_discloses_not_live_stateful(self):
        arch = (ROOT / "docs/ARCHITECTURE.md").read_text()
        self.assertIn("NOT wired into live verdicts", arch)
        self.assertIn("Fragmented", arch)

    def test_portfolio_discloses_scope(self):
        portfolio = (ROOT / "docs/PORTFOLIO.md").read_text()
        self.assertIn("not integrated", portfolio)
        self.assertIn("NETLINK_USERSOCK", portfolio)

    def test_release_checklist_and_make_integration(self):
        self.assertIn("final_audit.py", (ROOT / "README.md").read_text())
        self.assertIn("Phase 35", (ROOT / "progress.md").read_text())
        self.assertIn("final-audit", (ROOT / "Makefile").read_text())
        self.assertIn("- [ ]", (ROOT / "docs/RELEASE_CHECKLIST.md").read_text())

if __name__ == "__main__":
    unittest.main()
