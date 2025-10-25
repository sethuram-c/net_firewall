/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_NETLINK_H
#define NETFW_NETLINK_H

#include <linux/types.h>
#include <linux/build_bug.h>

/* Versioned application payload, carried inside an nlmsghdr (not yet sent). */
#define NETFW_NL_VERSION 1
#define NETFW_NL_CMD_PING 1
#define NETFW_NL_CMD_STATUS 2
#define NETFW_NL_PAYLOAD_BYTES 8

/* Fields whose names end in _be use network (big-endian) byte order. */
struct netfw_nl_request {
    u8 version;
    u8 command;
    __be16 reserved_be;
    __be32 request_id_be;
} __packed;

static inline bool netfw_nl_valid_request(const struct netfw_nl_request *req)
{
    if (!req || req->version != NETFW_NL_VERSION || req->reserved_be)
        return false;
    return req->command == NETFW_NL_CMD_PING ||
           req->command == NETFW_NL_CMD_STATUS;
}

static_assert(sizeof(struct netfw_nl_request) == NETFW_NL_PAYLOAD_BYTES);
#endif
