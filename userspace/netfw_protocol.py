"""Phase 25: portable Netlink application-payload codec (no socket yet).

The 8-byte application message is separate from Linux's 16-byte nlmsghdr.
The kernel endpoint and socket I/O are introduced in later phases.
"""
from dataclasses import dataclass
import struct

VERSION = 1
CMD_PING = 1
CMD_STATUS = 2
PAYLOAD_FORMAT = "!BBHI"  # network byte order: u8, u8, u16, u32
PAYLOAD_SIZE = struct.calcsize(PAYLOAD_FORMAT)
COMMANDS = frozenset((CMD_PING, CMD_STATUS))


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
