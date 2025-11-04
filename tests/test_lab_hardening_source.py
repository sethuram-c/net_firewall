"""Phase 34: fail-safe fragment handling and extended isolated regression."""
import unittest
from pathlib import Path
R=Path(__file__).resolve().parents[1]
K=(R/'kernel/netfw_hello.c').read_text()
S=(R/'scripts/test_lab_hardening.sh').read_text()
M=(R/'Makefile').read_text()
class LabHardeningTests(unittest.TestCase):
    def test_fragmented_staging_denied(self):
        self.assertIn('!(ntohs(iph->frag_off) & (IP_MF | IP_OFFSET))',K)
    def test_fails_open_without_opt_in(self):
        self.assertIn('lab_rules=0 lab_drop=0',S)
        self.assertIn('probe 54321 yes',S)
    def test_enforcement_explicit(self):
        self.assertIn('lab_rules=1 lab_drop=0',S)
        self.assertIn('probe 54321 no',S)
    def test_nonmatching_udp_allowed(self):
        self.assertIn('probe 54322 yes',S)
    def test_invalid_replacement_not_committed(self):
        self.assertIn('dst_port\":70000',S)
        self.assertIn('if python3 userspace/netfw_client.py apply --file "$BAD_FILE"',S)
    def test_empty_replacement_restores_accept(self):
        self.assertIn('"rules":[]',S)
        self.assertGreaterEqual(S.count('probe 54321 yes'),3)
    def test_module_reload_resets_table(self):
        self.assertIn('rmmod netfw_hello',S)
        self.assertIn('x["rule_count"]==0',S)
    def test_teardown_and_safety_preflight(self):
        self.assertIn('trap cleanup EXIT',S)
        self.assertIn('ip netns del',S)
        self.assertIn('Refusing: the module or lab interface already exists',S)
    def test_shell_lint_and_netlink_framing(self):
        self.assertIn('scripts/test_lab_hardening.sh',M)
        self.assertIn('NLMSG_ALIGN(nlh->nlmsg_len) != skb->len',K)
if __name__=='__main__': unittest.main()
