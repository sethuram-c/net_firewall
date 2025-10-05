"""Phase 5 structural checks (runtime failure injection is tested on Fedora)."""
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "kernel/netfw_hello.c").read_text()
SCRIPT = (Path(__file__).resolve().parents[1] / "scripts/test_failure_paths.sh").read_text()

class LifecycleFailureTests(unittest.TestCase):
    def test_injection_parameter_is_read_only(self):
        self.assertIn("module_param(fail_step, int, 0444)", SOURCE)
    def test_allocations_are_independent(self):
        self.assertIn("kmalloc(NETFW_MESSAGE_SIZE, GFP_KERNEL)", SOURCE)
        self.assertIn("kmalloc(NETFW_LABEL_SIZE, GFP_KERNEL)", SOURCE)
    def test_unwind_label_frees_first_resource(self):
        self.assertIn("goto err_free_message;", SOURCE)
        self.assertIn("err_free_message:", SOURCE)
        self.assertIn("kfree(netfw_message);", SOURCE)
    def test_exit_frees_resources_in_reverse_order(self):
        exit_source = SOURCE.split("static void __exit")[1].split("module_init")[0]
        self.assertLess(exit_source.index("kfree(netfw_label)"), exit_source.index("kfree(netfw_message)"))
    def test_failure_script_probes_both_cases(self):
        self.assertIn("for scenario in 1 2", SCRIPT)
        self.assertIn("fail_step=$scenario", SCRIPT)
    def test_no_netfilter_yet(self):
        self.assertNotIn("nf_register_net_hook", SOURCE)

if __name__ == "__main__":
    unittest.main()
