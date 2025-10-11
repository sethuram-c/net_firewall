"""Phase 11 unprivileged regression checks, plus Fedora root-required runtime tests."""
from pathlib import Path
import subprocess
import unittest
ROOT = Path(__file__).resolve().parents[1]
LAB = (ROOT / "scripts/test_lab_drop.sh").read_text()
REG = (ROOT / "scripts/test_verdict_regression.sh").read_text()
MAKE = (ROOT / "Makefile").read_text()

class VerdictRegressionTests(unittest.TestCase):
    def test_shell_syntax(self):
        subprocess.run(["bash", "-n", str(ROOT / "scripts/test_lab_drop.sh"),
                        str(ROOT / "scripts/test_verdict_regression.sh")], check=True)
    def test_mode_validation(self):
        self.assertIn('case "$LAB_DROP_MODE" in 0|1)', LAB)
    def test_default_opt_in_behavior(self):
        self.assertIn('LAB_DROP_MODE="${LAB_DROP_MODE:-1}"', LAB)
        self.assertIn('lab_drop=0', LAB)
        self.assertIn('lab_drop=1', LAB)
    def test_runtime_expected_verdict_switch(self):
        self.assertIn('not drop_enabled', LAB)
        self.assertIn('54322, True', LAB)
    def test_sysfs_presence_check(self):
        self.assertIn('/sys/module/netfw_hello', LAB)
        self.assertNotIn("lsmod | grep -q '^netfw_hello '", LAB)
    def test_cleanup_trap_and_resources(self):
        self.assertIn('trap cleanup EXIT', LAB)
        self.assertIn('ip netns del', LAB)
        self.assertIn('ip link del', LAB)
        self.assertIn('rmmod netfw_hello', LAB)
    def test_regression_runs_both_modes(self):
        self.assertIn('LAB_DROP_MODE=0', REG)
        self.assertIn('LAB_DROP_MODE=1', REG)
    def test_regression_asserts_teardown(self):
        self.assertGreaterEqual(REG.count('check_clean'), 4)
        self.assertIn('/sys/module/netfw_hello', REG)
        self.assertIn('ip netns list', REG)
    def test_make_checks_new_script(self):
        self.assertIn('scripts/test_verdict_regression.sh', MAKE)
