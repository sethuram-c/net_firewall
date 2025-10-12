/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NETFW_RULE_H
#define NETFW_RULE_H

#include <linux/types.h>
#include <linux/if.h>

/* Rule representation only: evaluation and mutation arrive in later phases.
 * Addresses and masks are stored as IPv4 network-order __be32 values.
 * Ports are stored in host order (u16). Zero masks/ports mean "any" only
 * when the corresponding match flag is unset; never overload zero fields.
 */
enum netfw_rule_action {
    NETFW_RULE_ACCEPT = 0,
    NETFW_RULE_DROP = 1,
};

enum netfw_rule_match_flag {
    NETFW_MATCH_SRC_IP   = 1U << 0,
    NETFW_MATCH_DST_IP   = 1U << 1,
    NETFW_MATCH_SRC_PORT = 1U << 2,
    NETFW_MATCH_DST_PORT = 1U << 3,
    NETFW_MATCH_PROTOCOL = 1U << 4,
    NETFW_MATCH_IN_IFACE = 1U << 5,
};

struct netfw_rule {
    u32 match_flags;
    __be32 src_ip;
    __be32 src_mask;
    __be32 dst_ip;
    __be32 dst_mask;
    u16 src_port;
    u16 dst_port;
    u8 protocol;               /* IPPROTO_TCP / UDP / ICMP, when enabled */
    enum netfw_rule_action action;
    char in_iface[IFNAMSIZ];    /* bounded; valid NUL terminator required */
};

#endif /* NETFW_RULE_H */
