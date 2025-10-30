"""Phase 30: read-only, bounded live rule-export protocol tests."""
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'userspace'))
import netfw_protocol as proto
import netfw_client as cli


def payload(count=0, rules=b'', request_id=17, policy=0):
    return struct.pack('!BBHIiBBH', 1, 3, 0, request_id, 0, count, policy, 0) + rules


class LiveRuleExportTests(unittest.TestCase):
    def test_new_command_and_request_roundtrip(self):
        self.assertEqual(proto.decode_request(proto.encode_request(proto.CMD_RULES, 17)).command, 3)

    def test_empty_live_snapshot(self):
        self.assertEqual(proto.decode_rules_response(payload())['rule_count'], 0)
        self.assertEqual(proto.decode_rules_response(payload())['source'], 'kernel-netlink')

    def test_nonempty_rule_decode(self):
        rule = struct.pack(proto.RULE_WIRE_FORMAT, 0x18, 0, 0, 0, 0, 0, 54321, 17, 1, bytes(16), 0)
        decoded = proto.decode_rules_response(payload(1, rule))
        self.assertEqual(decoded['rules'], [{'action':'DROP', 'protocol':'UDP', 'dst_port':54321}])

    def test_bounded_count_and_exact_length(self):
        for bad in (payload(17), payload(1), payload() + b'\0'):
            with self.assertRaises(ValueError): proto.decode_rules_response(bad)

    def test_reserved_and_policy_guards(self):
        for bad in (payload(policy=2), payload()[:14] + b'\x00\x01'):
            with self.assertRaises(ValueError): proto.decode_rules_response(bad)

    def test_reject_unexported_interface(self):
        iface_rule = struct.pack(proto.RULE_WIRE_FORMAT, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, bytes(16), 0)
        with self.assertRaises(ValueError): proto.decode_rules_response(payload(1, iface_rule))

    def test_client_netlink_envelope(self):
        data = payload()
        header = cli.HEADER.pack(cli.HEADER.size + len(data), 3, 0, 9, 0)
        self.assertEqual(cli.parse_reply(header+data, 3, 17, 9)['rule_count'], 0)

    def test_cli_live_and_offline(self):
        value = proto.decode_rules_response(payload())
        with patch.object(cli, 'request', return_value=value) as request:
            self.assertEqual(cli.main(['rules', '--json']), 0)
            request.assert_called_once_with(proto.CMD_RULES, request_id=1)
        self.assertEqual(cli.main(['rules', '--file', str(ROOT/'examples/rules_snapshot.json'), '--json']), 0)

    def test_kernel_integration_read_only(self):
        k = (ROOT/'kernel/netfw_hello.c').read_text()
        h = (ROOT/'kernel/netfw_netlink.h').read_text()
        self.assertIn('NETFW_NL_CMD_RULES 3', h)
        self.assertIn('netfw_table_snapshot(&netfw_export_table, &snapshot)', k)
        self.assertIn('netfw_table_init(&netfw_export_table, NETFW_RULE_ACCEPT)', k)
        self.assertEqual(k.count('return NF_DROP;'), 1)
        self.assertNotIn('netfw_table_add(&netfw_export_table', k)


if __name__ == '__main__':
    unittest.main()
