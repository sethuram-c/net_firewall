"""Phase 26: minimal Netlink PING/STATUS client for a loaded lab module.

Usage: python3 userspace/netfw_client.py ping | status
NETLINK_USERSOCK is shared, so kernel socket creation can fail if occupied.
"""
import socket
import struct
import sys

from netfw_protocol import CMD_PING, CMD_STATUS, decode_request, encode_request

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
    if len(data) != HEADER.size + 8:
        raise ValueError("invalid Netlink response size")
    length, kind, flags, seq, pid = HEADER.unpack_from(data)
    if length != len(data) or kind != NLMSG_DONE or seq != expected_sequence:
        raise ValueError("invalid Netlink response header")
    response = decode_request(data[HEADER.size:])
    if response.command != expected_command or response.request_id != expected_id:
        raise ValueError("Netlink response does not match request")
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


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0] not in ("ping", "status"):
        raise SystemExit("usage: python3 userspace/netfw_client.py ping|status")
    cmd = CMD_PING if argv[0] == "ping" else CMD_STATUS
    print(request(cmd))


if __name__ == "__main__":
    main()
