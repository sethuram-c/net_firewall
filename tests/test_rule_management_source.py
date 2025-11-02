import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = (ROOT / "kernel/netfw_manage.h").read_text()
MOD = (ROOT / "kernel/netfw_hello.c").read_text()

class RuleManagementTests(unittest.TestCase):
    def test_guard(self): self.assertIn("#ifndef NETFW_MANAGE_H", SRC)
    def test_api(self): self.assertIn("netfw_manage_replace(", SRC)
    def test_authorization(self):
        self.assertIn("if (!authorized)", SRC)
        self.assertIn("return -EPERM", SRC)
    def test_capacity(self): self.assertIn("count > NETFW_MAX_RULES", SRC)
    def test_null_input(self): self.assertIn("count && !candidate", SRC)
    def test_action_validation(self): self.assertIn("default_action != NETFW_RULE_DROP", SRC)
    def test_reject_interface(self): self.assertIn("NETFW_MATCH_IN_IFACE", SRC)
    def test_atomic_publish(self):
        self.assertLess(SRC.index("for (i = 0; i < count"), SRC.index("spin_lock_bh"))
        self.assertLess(SRC.index("table->count = count"), SRC.index("spin_unlock_bh"))
    def test_init_only_and_live_unchanged(self):
        self.assertIn('#include "netfw_manage.h"', MOD)
        self.assertIn("manage_demo", MOD)
        self.assertIn("netfw_manage_replace(manage_demo", MOD)
        self.assertIn("return NF_DROP;", MOD)
        self.assertIn("netfw_manage_replace(&netfw_export_table", MOD)
        hook = MOD.split("static unsigned int netfw_observe", 1)[1].split("static int __init", 1)[0]
        self.assertNotIn("netfw_export_table", hook)

if __name__ == "__main__": unittest.main()
