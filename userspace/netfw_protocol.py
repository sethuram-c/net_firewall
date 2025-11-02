"""Portable versioned Netlink payload codec, including bounded rules snapshots."""
from dataclasses import dataclass
import struct

VERSION = 1
CMD_PING = 1
CMD_STATUS = 2
CMD_RULES = 3
CMD_REPLACE = 4
PAYLOAD_FORMAT = "!BBHI"  # network byte order: u8, u8, u16, u32
PAYLOAD_SIZE = struct.calcsize(PAYLOAD_FORMAT)
COMMANDS = frozenset((CMD_PING, CMD_STATUS, CMD_RULES, CMD_REPLACE))


@dataclass(frozen=True)
class Request:
    version: int
    command: int
    request_id: int


def encode_request(command: int, request_id: int) -> bytes:
    if type(command) is not int or command not in COMMANDS:
        raise ValueError("unknown Netlink command")
    if type(request_id) is not int or not 0 <= request_id <= 0xFFFFFFFF:
        raise ValueError("request_id must be an unsigned 32-bit integer")
    return struct.pack(PAYLOAD_FORMAT, VERSION, command, 0, request_id)


def decode_request(data: bytes) -> Request:
    if not isinstance(data, bytes) or len(data) != PAYLOAD_SIZE:
        raise ValueError("invalid Netlink payload length")
    version, command, reserved, request_id = struct.unpack(PAYLOAD_FORMAT, data)
    if version != VERSION or command not in COMMANDS or reserved != 0:
        raise ValueError("unsupported Netlink request")
    return Request(version, command, request_id)


RESPONSE_FORMAT = "!BBHIi"  # request fields + signed 32-bit errno status
RESPONSE_SIZE = struct.calcsize(RESPONSE_FORMAT)


@dataclass(frozen=True)
class Response:
    version: int
    command: int
    request_id: int
    status: int


def decode_response(data: bytes) -> Response:
    if not isinstance(data, bytes) or len(data) != RESPONSE_SIZE:
        raise ValueError("invalid Netlink response payload length")
    version, command, reserved, request_id, status = struct.unpack(
        RESPONSE_FORMAT, data)
    if reserved != 0:
        raise ValueError("invalid Netlink response reserved field")
    return Response(version, command, request_id, status)

# RULES success reply: 12-byte status header + 4-byte snapshot header,
# followed by up to 16 x 44-byte wire entries, no padding or pointers.
RULES_HEADER_FORMAT = "!BBHIiBBH"
RULES_HEADER_SIZE = struct.calcsize(RULES_HEADER_FORMAT)
RULE_WIRE_FORMAT = "!IIIIIHHBB16sH"
RULE_WIRE_SIZE = struct.calcsize(RULE_WIRE_FORMAT)
RULES_MAX = 16


def decode_rules_response(payload: bytes) -> dict:
    import ipaddress
    if not isinstance(payload, bytes) or len(payload) < RULES_HEADER_SIZE:
        raise ValueError("truncated rules response")
    version, command, reserved, request_id, status, count, default, reserved2 = struct.unpack_from(
        RULES_HEADER_FORMAT, payload)
    if (version != VERSION or command != CMD_RULES or reserved != 0 or
            status != 0 or reserved2 != 0 or count > RULES_MAX or default not in (0, 1)):
        raise ValueError("invalid rules response header")
    if len(payload) != RULES_HEADER_SIZE + count * RULE_WIRE_SIZE:
        raise ValueError("invalid rules response size")
    rules = []
    for i in range(count):
        fields = struct.unpack_from(RULE_WIRE_FORMAT, payload,
                                    RULES_HEADER_SIZE + i * RULE_WIRE_SIZE)
        flags, sip, smask, dip, dmask, sport, dport, proto, action, iface, zero = fields
        if (flags & ~0x1f or action not in (0, 1) or zero != 0 or
                iface != bytes(16) or (flags & 0x10 and proto not in (1, 6, 17)) or
                (flags & 0x0c and (not flags & 0x10 or proto not in (6,17)))):
            raise ValueError("invalid exported rule")
        rule = {"action": "ACCEPT" if action == 0 else "DROP"}
        if flags & 1:
            rule["src_ip"] = str(ipaddress.IPv4Network((sip, str(ipaddress.IPv4Address(smask))), strict=False))
        if flags & 2:
            rule["dst_ip"] = str(ipaddress.IPv4Network((dip, str(ipaddress.IPv4Address(dmask))), strict=False))
        if flags & 16:
            rule["protocol"] = {1:"ICMP", 6:"TCP", 17:"UDP"}[proto]
        if flags & 4: rule["src_port"] = sport
        if flags & 8: rule["dst_port"] = dport
        rules.append(rule)
    return {"version": version, "default_action": "ACCEPT" if default == 0 else "DROP",
            "rule_count": count, "rules": rules, "source": "kernel-netlink", "request_id": request_id}


def encode_replace_request(snapshot: dict, request_id: int = 1) -> bytes:
    """Validate a full offline JSON snapshot and encode an atomic replacement."""
    import ipaddress
    from netfw_rules import validate_snapshot
    validated = validate_snapshot(snapshot)
    rules = validated["rules"]
    if any("in_iface" in rule for rule in rules):
        raise ValueError("interface matching is not supported by the staging wire protocol")
    if len(rules) > RULES_MAX:
        raise ValueError("too many rules")
    header = (encode_request(CMD_REPLACE, request_id) +
              struct.pack("!iBBH", 0, len(rules),
                          0 if validated["default_action"] == "ACCEPT" else 1, 0))
    encoded = []
    for rule in rules:
        flags = 0
        sip = smask = dip = dmask = sport = dport = proto = 0
        if "src_ip" in rule:
            ip = ipaddress.IPv4Network(rule["src_ip"], strict=False)
            flags |= 1; sip = int(ip.network_address); smask = int(ip.netmask)
        if "dst_ip" in rule:
            ip = ipaddress.IPv4Network(rule["dst_ip"], strict=False)
            flags |= 2; dip = int(ip.network_address); dmask = int(ip.netmask)
        if "src_port" in rule: flags |= 4; sport = rule["src_port"]
        if "dst_port" in rule: flags |= 8; dport = rule["dst_port"]
        if "protocol" in rule:
            flags |= 16; proto = {"ICMP": 1, "TCP": 6, "UDP": 17}[rule["protocol"]]
        encoded.append(struct.pack(RULE_WIRE_FORMAT, flags, sip, smask, dip,
                                   dmask, sport, dport, proto,
                                   0 if rule["action"] == "ACCEPT" else 1,
                                   bytes(16), 0))
    return header + b"".join(encoded)
