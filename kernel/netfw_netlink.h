/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_NETLINK_H
#define NETFW_NETLINK_H

#include <linux/types.h>
#include <linux/build_bug.h>

/* Versioned application payload, carried inside an nlmsghdr (not yet sent). */
#define NETFW_NL_VERSION 1
#define NETFW_NL_CMD_PING 1
#define NETFW_NL_CMD_STATUS 2
#define NETFW_NL_CMD_RULES 3
#define NETFW_NL_CMD_REPLACE 4
#define NETFW_NL_RULES_HEADER_BYTES 16
#define NETFW_NL_RULE_WIRE_BYTES 44
#define NETFW_NL_PAYLOAD_BYTES 8
#define NETFW_NL_RESPONSE_BYTES 12

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
           req->command == NETFW_NL_CMD_STATUS ||
           req->command == NETFW_NL_CMD_RULES ||
           req->command == NETFW_NL_CMD_REPLACE;
}

/* Replies preserve the request header and append a signed errno-style status. */
struct netfw_nl_response {
    struct netfw_nl_request request;
    __be32 status_be;
} __packed;

/* Canonical, padding-free snapshot encoding. Counts and flags are BE. */
struct netfw_nl_rule_wire {
    __be32 flags_be;
    __be32 src_ip_be;
    __be32 src_mask_be;
    __be32 dst_ip_be;
    __be32 dst_mask_be;
    __be16 src_port_be;
    __be16 dst_port_be;
    u8 protocol;
    u8 action;
    u8 iface[16];
    __be16 reserved_be;
} __packed;

struct netfw_nl_rules_header {
    struct netfw_nl_response response;
    u8 count;
    u8 default_action;
    __be16 reserved_be;
} __packed;

static_assert(sizeof(struct netfw_nl_rule_wire) == NETFW_NL_RULE_WIRE_BYTES);
static_assert(sizeof(struct netfw_nl_rules_header) == NETFW_NL_RULES_HEADER_BYTES);
static_assert(sizeof(struct netfw_nl_request) == NETFW_NL_PAYLOAD_BYTES);
static_assert(sizeof(struct netfw_nl_response) == NETFW_NL_RESPONSE_BYTES);
#endif
