"""Read-only rule snapshot validation and display (offline or live)."""
import ipaddress
import json
from pathlib import Path

MAX_RULES = 16
ALLOWED_ACTIONS = {"ACCEPT", "DROP"}
ALLOWED_KEYS = {"action", "protocol", "src_ip", "dst_ip", "src_port", "dst_port", "in_iface"}
ALLOWED_PROTOCOLS = {"TCP", "UDP", "ICMP"}


def _port(value):
    if type(value) is not int or not (0 <= value <= 65535):
        raise ValueError("ports must be integers from 0 to 65535")
    return value


def validate_snapshot(document):
    if not isinstance(document, dict) or set(document) != {"version", "default_action", "rules"}:
        raise ValueError("snapshot requires version, default_action and rules")
    if type(document["version"]) is not int or document["version"] != 1:
        raise ValueError("unsupported snapshot version")
    if document["default_action"] not in ALLOWED_ACTIONS:
        raise ValueError("invalid default action")
    rules = document["rules"]
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ValueError("rule list exceeds 16 entries or is not a list")
    clean = []
    for rule in rules:
        if not isinstance(rule, dict) or not set(rule) <= ALLOWED_KEYS or "action" not in rule:
            raise ValueError("invalid rule fields")
        if rule["action"] not in ALLOWED_ACTIONS:
            raise ValueError("invalid rule action")
        item = dict(rule)
        if "protocol" in item and item["protocol"] not in ALLOWED_PROTOCOLS:
            raise ValueError("invalid protocol")
        for field in ("src_ip", "dst_ip"):
            if field in item:
                if not isinstance(item[field], str):
                    raise ValueError("IP/CIDR must be a string")
                item[field] = str(ipaddress.IPv4Network(item[field], strict=False))
        for field in ("src_port", "dst_port"):
            if field in item:
                _port(item[field])
                if item.get("protocol") not in ("TCP", "UDP"):
                    raise ValueError("ports require TCP or UDP protocol")
        if "in_iface" in item and (not isinstance(item["in_iface"], str) or
                                     not 1 <= len(item["in_iface"].encode("utf-8")) < 16 or
                                     "\x00" in item["in_iface"]):
            raise ValueError("invalid interface name")
        clean.append(item)
    return {"version": 1, "default_action": document["default_action"],
            "rule_count": len(clean), "rules": clean, "source": "offline-file"}


def read_snapshot(path):
    file = Path(path)
    if file.stat().st_size > 65536:
        raise ValueError("snapshot file exceeds 64 KiB")
    return validate_snapshot(json.loads(file.read_text(encoding="utf-8")))


def format_snapshot(snapshot):
    lines = [f"NETFW {snapshot.get('source', 'offline-file')} snapshot: {snapshot['rule_count']} rule(s)",
             f"Default policy: {snapshot['default_action']}"]
    for i, rule in enumerate(snapshot["rules"], 1):
        fields = ", ".join(f"{key}={val}" for key, val in rule.items() if key != "action")
        lines.append(f"{i}. {rule['action']}" + (f" [{fields}]" if fields else ""))
    return "\n".join(lines)
