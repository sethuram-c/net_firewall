"""Phase 29: offline validation and kernel snapshot source contracts."""
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
import netfw_rules as rules

BASE = {"version": 1, "default_action": "ACCEPT", "rules": [{"action": "DROP", "protocol": "UDP", "dst_port": 54321}]}

class RuleSnapshotTests(unittest.TestCase):
    def test_valid_ordered_rules(self):
        doc = rules.validate_snapshot(BASE)
        self.assertEqual(doc["rule_count"], 1)
        self.assertEqual(doc["rules"][0]["dst_port"], 54321)
    def test_empty_snapshot(self):
        self.assertEqual(rules.validate_snapshot({"version":1, "default_action":"DROP", "rules":[]})["rule_count"],0)
    def test_reject_version_and_extra_fields(self):
        for value in ({**BASE,"version":2}, {**BASE,"unexpected":True}):
            with self.assertRaises(ValueError): rules.validate_snapshot(value)
    def test_bounded_rules(self):
        with self.assertRaises(ValueError): rules.validate_snapshot({**BASE,"rules":BASE["rules"]*17})
    def test_protocol_is_required_for_port(self):
        with self.assertRaises(ValueError): rules.validate_snapshot({**BASE,"rules":[{"action":"DROP","dst_port":80}]})
    def test_reject_bad_types_and_actions(self):
        for row in ({"action":"REJECT"},{"action":"DROP","protocol":"SCTP"},{"action":"DROP","protocol":"UDP","dst_port":True}):
            with self.assertRaises(ValueError): rules.validate_snapshot({**BASE,"rules":[row]})
    def test_cidr_validation(self):
        doc=rules.validate_snapshot({**BASE,"rules":[{"action":"DROP","src_ip":"192.0.2.9/24"}]})
        self.assertEqual(doc["rules"][0]["src_ip"],"192.0.2.0/24")
        with self.assertRaises(ValueError): rules.validate_snapshot({**BASE,"rules":[{"action":"DROP","src_ip":"not-ip"}]})
    def test_cli_offline_json(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"snapshot.json";path.write_text(json.dumps(BASE))
            out=io.StringIO()
            with patch.object(client,"request",side_effect=AssertionError("must not contact Netlink")),contextlib.redirect_stdout(out):
                self.assertEqual(client.main(["rules","--file",str(path),"--json"]),0)
            self.assertEqual(json.loads(out.getvalue())["source"],"offline-file")
    def test_kernel_lock_copy_and_init_only(self):
        hdr=(ROOT/"kernel/netfw_snapshot.h").read_text();mod=(ROOT/"kernel/netfw_hello.c").read_text()
        self.assertIn("spin_lock_bh(&table->lock)",hdr)
        self.assertIn("memcpy(out->rules",hdr)
        self.assertIn("count > NETFW_MAX_RULES",hdr)
        self.assertIn("netfw_table_snapshot(demo_table, snapshot)",mod)
        self.assertNotIn("netfw_table_snapshot(",mod[mod.index("static unsigned int netfw_observe"):mod.index("static struct nf_hook_ops")])

if __name__ == "__main__": unittest.main()
