"""Phase 26: minimal Netlink PING/STATUS client for a loaded lab module.

Usage: python3 userspace/netfw_client.py ping | status
NETLINK_USERSOCK is shared, so kernel socket creation can fail if occupied.
"""
import socket
import struct
import sys
import argparse
import errno
import json
from pathlib import Path

from netfw_protocol import (CMD_PING, CMD_STATUS, RESPONSE_SIZE,
                            decode_request, decode_response, encode_request)

NETLINK_USERSOCK = 2
NLMSG_DONE = 3
NLMSG_REQUEST_TYPE = 0x10  # NLMSG_MIN_TYPE
NLM_F_REQUEST = 1
HEADER = struct.Struct("=IHHII")  # Native Netlink header (16 bytes)


def make_message(command: int, request_id: int, sequence: int) -> bytes:
    payload = encode_request(command, request_id)
    if type(sequence) is not int or not 0 <= sequence <= 0xFFFFFFFF:
        raise ValueError("sequence must be an unsigned 32-bit integer")
    return HEADER.pack(HEADER.size + len(payload), NLMSG_REQUEST_TYPE,
                       NLM_F_REQUEST, sequence, 0) + payload


def parse_reply(data: bytes, expected_command: int, expected_id: int,
                expected_sequence: int):
    # Retain Phase 26 fixture compatibility for its old 8-byte acknowledgments.
    if len(data) not in (HEADER.size + 8, HEADER.size + RESPONSE_SIZE):
        raise ValueError("invalid Netlink response size")
    length, kind, flags, seq, pid = HEADER.unpack_from(data)
    if (length != len(data) or kind != NLMSG_DONE or
            seq != expected_sequence or pid != 0):
        raise ValueError("invalid Netlink response header")
    payload = data[HEADER.size:]
    response = (decode_request(payload) if len(payload) == 8 else
                decode_response(payload))
    if response.command != expected_command or response.request_id != expected_id:
        raise ValueError("Netlink response does not match request")
    if hasattr(response, "status") and response.status:
        code = -response.status
        if code <= 0 or code > 4095:
            raise ValueError("invalid kernel Netlink status")
        raise OSError(code, errno.errorcode.get(code, "Netlink request failed"))
    return response


def request(command: int, request_id: int = 1, sequence: int = 1):
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                       NETLINK_USERSOCK) as sock:
        sock.settimeout(2.0)
        sock.bind((0, 0))
        sock.sendto(make_message(command, request_id, sequence), (0, 0))
        data, address = sock.recvfrom(4096)
        if address[0] != 0:
            raise ValueError("response was not sent by kernel")
        return parse_reply(data, command, request_id, sequence)


def read_local_diagnostics(proc_modules="/proc/modules", sys_module="/sys/module/netfw_hello"):
    """Read only; no subprocess, root privileges, or kernel writes required."""
    try:
        modules = Path(proc_modules).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise OSError(f"cannot read {proc_modules}: {exc}") from exc
    loaded = any(line.split() and line.split()[0] == "netfw_hello"
                 for line in modules.splitlines())
    return {
        "module_loaded": loaded,
        "sysfs_module_present": Path(sys_module).is_dir(),
        "transport": "NETLINK_USERSOCK",
        "interface": "read-only",
        "policy": "isolated lab mode only; no dynamic rules",
    }


def print_diagnostics(diagnostics, json_output=False):
    if json_output:
        print(json.dumps(diagnostics, sort_keys=True))
        return
    print("NETFW local diagnostics (read-only)")
    for key, value in diagnostics.items():
        print(f"  {key.replace('_', ' ')}: {value}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only NETFW Netlink client")
    parser.add_argument("command", choices=("ping", "status", "diagnose"))
    parser.add_argument("--request-id", type=int, default=1)
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    args = parser.parse_args(argv)
    if args.command == "diagnose":
        try:
            data = read_local_diagnostics()
        except OSError as exc:
            print(f"netfw: {exc}", file=sys.stderr)
            return 1
        print_diagnostics(data, args.json)
        return 0
    cmd = CMD_PING if args.command == "ping" else CMD_STATUS
    try:
        response = request(cmd, request_id=args.request_id)
    except (OSError, ValueError) as exc:
        print(f"netfw: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"command": args.command,
                          "request_id": response.request_id,
                          "status": getattr(response, "status", 0),
                          "note": ("endpoint reachable; no live counters" if
                                   args.command == "status" else "acknowledged")},
                         sort_keys=True))
    else:
        print(f"NETFW {args.command.upper()} OK (request_id={response.request_id})")
        if args.command == "status":
            print("STATUS: endpoint reachable; live firewall counters unavailable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
