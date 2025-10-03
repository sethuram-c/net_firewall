"""Phase 3 no-root checks for build and read-only diagnostics."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BuildWorkflowTests(unittest.TestCase):
    def test_make_help(self):
        result = subprocess.run(["make", "help"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("make verify-build", result.stdout)

    def test_makefile_has_safe_targets(self):
        text = (ROOT / "Makefile").read_text()
        self.assertIn("verify-build:", text)
        self.assertIn("info:", text)
        self.assertIn("check:", text)
        self.assertNotIn("sudo insmod", text)

    def test_diagnostics_does_not_modify_kernel(self):
        text = (ROOT / "scripts/inspect_module.sh").read_text()
        self.assertNotIn("\ninsmod ", text)
        self.assertNotIn("\nrmmod ", text)
        self.assertIn("journalctl -k -b", text)
        self.assertIn("modinfo", text)

    def test_scripts_shell_syntax(self):
        result = subprocess.run(
            ["bash", "-n", "scripts/check_env.sh", "scripts/test_module.sh", "scripts/inspect_module.sh"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
