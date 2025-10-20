// SPDX-License-Identifier: GPL-2.0
/* Phase 10: bounded packet inspection; optional isolated-interface UDP drop. */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include "netfw_rule.h"
#include "netfw_match.h"
#include "netfw_policy.h"
#include "netfw_table.h"
#include "netfw_flow.h"
#include "netfw_conn.h"

#define NETFW_MESSAGE_SIZE 128
#define NETFW_LABEL_SIZE 32
#define NETFW_LAB_IFACE "nfwt10h"
#define NETFW_LAB_IPV4 0xC6120002U /* 198.18.0.2 in host integer order */
#define NETFW_LAB_UDP_PORT 54321

static char *netfw_message;
static char *netfw_label;
/* Explicit opt-in; immutable while loaded. Default behavior remains accept. */
static bool lab_drop;
module_param(lab_drop, bool, 0444);
MODULE_PARM_DESC(lab_drop, "Drop only UDP/54321 to 198.18.0.2 on nfwt10h");
/* 0: normal, 1: fail before first allocation, 2: fail after first. */
/* skb data may be fragmented/non-linear: copy header bytes, never dereference
 * skb->data as an unverified struct iphdr. Malformed traffic is accepted.
 */
static unsigned int netfw_observe(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr iph_buf;
    const struct iphdr *iph;
    int offset;
    unsigned int header_len;
    unsigned int wire_len;
    unsigned int transport_offset;
    unsigned int transport_len;
    unsigned int frag_offset;
    struct tcphdr tcp_buf;
    struct udphdr udp_buf;
    struct icmphdr icmp_buf;
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    const struct icmphdr *icmp;

    if (!skb)
        return NF_ACCEPT;

    offset = skb_network_offset(skb);
    if (offset < 0 || offset > skb->len ||
        skb->len - offset < sizeof(iph_buf))
        return NF_ACCEPT;

    iph = skb_header_pointer(skb, offset, sizeof(iph_buf), &iph_buf);
    if (!iph || iph->version != 4 || iph->ihl < 5)
        return NF_ACCEPT;

    header_len = (unsigned int)iph->ihl * 4;
    wire_len = ntohs(iph->tot_len);
    /* At least the entire declared IPv4 header must be available. */
    if (header_len > skb->len - offset || wire_len < header_len ||
        wire_len > skb->len - offset)
        return NF_ACCEPT;

    /* Non-first IPv4 fragments have no transport header at this offset. */
    frag_offset = ntohs(iph->frag_off) & 0x1FFF;
    if (frag_offset) {
        pr_info_ratelimited("netfw_hello: IPv4 fragment %pI4 -> %pI4 proto=%u (no ports)\n",
                            &iph->saddr, &iph->daddr, iph->protocol);
        return NF_ACCEPT;
    }

    transport_offset = offset + header_len;
    transport_len = wire_len - header_len;
    if (iph->protocol == IPPROTO_TCP && transport_len >= sizeof(tcp_buf)) {
        tcp = skb_header_pointer(skb, transport_offset, sizeof(tcp_buf), &tcp_buf);
        if (tcp && tcp->doff >= 5 &&
            (unsigned int)tcp->doff * 4 <= transport_len)
            pr_info_ratelimited("netfw_hello: TCP %pI4:%u -> %pI4:%u\n",
                                &iph->saddr, ntohs(tcp->source),
                                &iph->daddr, ntohs(tcp->dest));
    } else if (iph->protocol == IPPROTO_UDP && transport_len >= sizeof(udp_buf)) {
        udp = skb_header_pointer(skb, transport_offset, sizeof(udp_buf), &udp_buf);
        if (udp && ntohs(udp->len) >= sizeof(udp_buf) &&
            ntohs(udp->len) <= transport_len) {
            /* Match all fields before dropping: immutable opt-in + dedicated
             * lab ingress interface + destination IP + UDP port.
             * No packet modification and no dynamic allocation in hook.
             */
            if (lab_drop && state && state->in &&
                !strncmp(state->in->name, NETFW_LAB_IFACE, IFNAMSIZ) &&
                ntohl(iph->daddr) == NETFW_LAB_IPV4 &&
                ntohs(udp->dest) == NETFW_LAB_UDP_PORT) {
                pr_info_ratelimited("netfw_hello: LAB_DROP UDP %pI4:%u -> %pI4:%u\n",
                                    &iph->saddr, ntohs(udp->source),
                                    &iph->daddr, ntohs(udp->dest));
                return NF_DROP;
            }
            pr_info_ratelimited("netfw_hello: UDP %pI4:%u -> %pI4:%u\n",
                                &iph->saddr, ntohs(udp->source),
                                &iph->daddr, ntohs(udp->dest));
        }
    } else if (iph->protocol == IPPROTO_ICMP &&
               transport_len >= sizeof(icmp_buf)) {
        icmp = skb_header_pointer(skb, transport_offset,
                                  sizeof(icmp_buf), &icmp_buf);
        if (icmp)
            pr_info_ratelimited("netfw_hello: ICMP %pI4 -> %pI4 type=%u code=%u\n",
                                &iph->saddr, &iph->daddr,
                                icmp->type, icmp->code);
    } else {
        pr_info_ratelimited("netfw_hello: IPv4 %pI4 -> %pI4 proto=%u len=%u\n",
                            &iph->saddr, &iph->daddr, iph->protocol, wire_len);
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops netfw_hook = {
    .hook = netfw_observe,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FILTER,
};

static int fail_step;
module_param(fail_step, int, 0444);
MODULE_PARM_DESC(fail_step, "Demo only: force init failure at step 1 or 2");

static int __init netfw_hello_init(void)
{
    int err = -ENOMEM;

    /* All startup paths begin with empty ownership. */
    netfw_message = NULL;
    netfw_label = NULL;

    if (fail_step == 1) {
        pr_warn("netfw_hello: injected failure before first allocation\n");
        return -ENOMEM;
    }

    netfw_message = kmalloc(NETFW_MESSAGE_SIZE, GFP_KERNEL);
    if (!netfw_message) {
        pr_err("netfw_hello: kmalloc failed for message\n");
        return -ENOMEM;
    }
    strscpy(netfw_message, "allocated kernel memory safely", NETFW_MESSAGE_SIZE);

    if (fail_step == 2) {
        pr_warn("netfw_hello: injected failure after first allocation\n");
        goto err_free_message;
    }

    netfw_label = kmalloc(NETFW_LABEL_SIZE, GFP_KERNEL);
    if (!netfw_label) {
        pr_err("netfw_hello: kmalloc failed for label\n");
        goto err_free_message;
    }
    strscpy(netfw_label, "phase12", NETFW_LABEL_SIZE);
    /* Phase 19: validate 5-tuple directionality before hook registration.
     * No connection table exists and no packet verdict is changed.
     */
    {
        const struct netfw_flow_key outgoing = {
            .src_ip = htonl(0x0a000001), .dst_ip = htonl(0x0a000002),
            .src_port = htons(41000), .dst_port = htons(443),
            .protocol = IPPROTO_TCP,
        };
        const struct netfw_flow_key incoming = {
            .src_ip = htonl(0x0a000002), .dst_ip = htonl(0x0a000001),
            .src_port = htons(443), .dst_port = htons(41000),
            .protocol = IPPROTO_TCP,
        };
        if (!netfw_flow_is_transport(&outgoing) ||
            !netfw_flow_equal(&outgoing, &outgoing) ||
            netfw_flow_equal(&outgoing, &incoming) ||
            !netfw_flow_reverse_equal(&outgoing, &incoming)) {
            err = -EINVAL;
            goto err_free_label;
        }
    }

    /* Phase 12 declares the rule model only; packet policy is unchanged. */
    /* Phase 13 example: exercise the reusable matcher without changing
     * packet verdicts. Real rule evaluation is introduced later.
     */
    {
        const struct netfw_rule demo = {
            .match_flags = NETFW_MATCH_SRC_IP,
            .src_ip = 0,
            .src_mask = 0,
        };
        if (!netfw_match_src_ipv4(&demo, 0)) {
            err = -EINVAL;
            goto err_free_label;
        }
    }
    /* Phase 14: type-check destination matching on a harmless demo rule.
     * No packet verdict evaluates these rule helpers yet.
     */
    {
        const struct netfw_rule demo_dst = {
            .match_flags = NETFW_MATCH_DST_IP,
            .dst_ip = 0,
            .dst_mask = 0,
        };
        if (!netfw_match_dst_ipv4(&demo_dst, 0)) {
            err = -EINVAL;
            goto err_free_label;
        }
    }
    /* Phase 15: exercise port wildcard/match semantics during init only.
     * This is NOT consulted by the packet hook; lab verdicts are unchanged.
     */
    {
        const struct netfw_rule demo_ports = {
            .match_flags = NETFW_MATCH_SRC_PORT | NETFW_MATCH_DST_PORT,
            .src_port = 12345,
            .dst_port = 443,
        };
        if (!netfw_match_ports(&demo_ports, IPPROTO_TCP,
                               htons(12345), htons(443)) ||
            netfw_match_ports(&demo_ports, IPPROTO_UDP,
                              htons(12345), htons(444)) ||
            netfw_match_ports(&demo_ports, IPPROTO_ICMP,
                              htons(12345), htons(443))) {
            err = -EINVAL;
            goto err_free_label;
        }
    }
    /* Phase 16: combined predicate smoke checks; never used in hook. */
    {
        const struct netfw_rule demo_rule = {
            .match_flags = NETFW_MATCH_PROTOCOL | NETFW_MATCH_DST_PORT,
            .protocol = IPPROTO_TCP,
            .dst_port = 443,
        };
        if (!netfw_match_packet(&demo_rule, 0, 0, IPPROTO_TCP,
                                0, htons(443)) ||
            netfw_match_packet(&demo_rule, 0, 0, IPPROTO_UDP,
                               0, htons(443)) ||
            netfw_match_packet(&demo_rule, 0, 0, IPPROTO_TCP,
                               0, htons(80))) {
            err = -EINVAL;
            goto err_free_label;
        }
    }
/* Phase 17: self-test ordered first-match and no-match fallback.
 * This stack-only demo is deliberately NOT consulted by the hook. */
{
    const struct netfw_rule demo_rules[] = {
        { .match_flags = NETFW_MATCH_PROTOCOL | NETFW_MATCH_DST_PORT,
          .protocol = IPPROTO_UDP, .dst_port = 54321,
          .action = NETFW_RULE_DROP },
        { .match_flags = NETFW_MATCH_PROTOCOL,
          .protocol = IPPROTO_UDP, .action = NETFW_RULE_ACCEPT },
    };

    if (netfw_evaluate_rules(demo_rules, ARRAY_SIZE(demo_rules),
                             NETFW_RULE_ACCEPT, 0, 0, IPPROTO_UDP,
                             0, htons(54321)) != NETFW_RULE_DROP ||
        netfw_evaluate_rules(demo_rules, ARRAY_SIZE(demo_rules),
                             NETFW_RULE_DROP, 0, 0, IPPROTO_UDP,
                             0, htons(54322)) != NETFW_RULE_ACCEPT ||
        netfw_evaluate_rules(demo_rules, ARRAY_SIZE(demo_rules),
                             NETFW_RULE_ACCEPT, 0, 0, IPPROTO_TCP,
                             0, htons(54321)) != NETFW_RULE_ACCEPT ||
        netfw_evaluate_rules(NULL, 0, NETFW_RULE_DROP,
                             0, 0, IPPROTO_TCP, 0, 0) != NETFW_RULE_DROP) {
        err = -EINVAL;
        goto err_free_label;
    }
}
    /* Phase 18: table stays local to init: no live rule mutation yet. */
    {
        struct netfw_table *demo_table;
        const struct netfw_rule drop = {
            .match_flags = NETFW_MATCH_PROTOCOL | NETFW_MATCH_DST_PORT,
            .protocol = IPPROTO_UDP, .dst_port = 54321,
            .action = NETFW_RULE_DROP,
        };

        demo_table = kmalloc(sizeof(*demo_table), GFP_KERNEL);
        if (!demo_table) {
            err = -ENOMEM;
            goto err_free_label;
        }
        netfw_table_init(demo_table, NETFW_RULE_ACCEPT);
        err = netfw_table_add(demo_table, &drop);
        if (!err && (netfw_table_evaluate(demo_table, 0, 0,
                                          IPPROTO_UDP, 0, htons(54321)) != NETFW_RULE_DROP ||
                     netfw_table_evaluate(demo_table, 0, 0,
                                          IPPROTO_UDP, 0, htons(54322)) != NETFW_RULE_ACCEPT))
            err = -EINVAL;
        netfw_table_clear(demo_table);
        kfree(demo_table);
        if (err)
            goto err_free_label;
    }
    /* Phase 20: bounded connection lookup self-test, never used in hook. */
    {
        struct netfw_conn_table *demo_conn;
        const struct netfw_flow_key outgoing = {
            .src_ip = htonl(0x0a000001), .dst_ip = htonl(0x0a000002),
            .src_port = htons(41000), .dst_port = htons(443),
            .protocol = IPPROTO_TCP,
        };
        const struct netfw_flow_key incoming = {
            .src_ip = htonl(0x0a000002), .dst_ip = htonl(0x0a000001),
            .src_port = htons(443), .dst_port = htons(41000),
            .protocol = IPPROTO_TCP,
        };
        bool reverse = false;

        demo_conn = kmalloc(sizeof(*demo_conn), GFP_KERNEL);
        if (!demo_conn) {
            err = -ENOMEM;
            goto err_free_label;
        }
        netfw_conn_init(demo_conn);
        if (netfw_conn_lookup(demo_conn, &outgoing, NULL) ||
            netfw_conn_add(demo_conn, &outgoing) ||
            !netfw_conn_lookup(demo_conn, &outgoing, NULL) ||
            !netfw_conn_lookup(demo_conn, &incoming, &reverse) ||
            !reverse || demo_conn->count != 1 ||
            netfw_conn_add(demo_conn, &incoming) != -EEXIST) {
            err = -EINVAL;
        }
        kfree(demo_conn);
        if (err)
            goto err_free_label;
    }
    pr_info("netfw_hello: rule descriptor ready (%zu bytes; inactive)\n",
            sizeof(struct netfw_rule));
    err = nf_register_net_hook(&init_net, &netfw_hook);
    if (err) {
        pr_err("netfw_hello: hook registration failed (%d)\n", err);
        goto err_free_label;
    }
    pr_info("netfw_hello: %s; label=%s; IPv4 hook active (lab_drop=%u)\n",
            netfw_message, netfw_label, lab_drop);
    return 0;

err_free_label:
    kfree(netfw_label);
    netfw_label = NULL;
err_free_message:
    kfree(netfw_message);
    netfw_message = NULL;
    return err;
}

static void __exit netfw_hello_exit(void)
{
    nf_unregister_net_hook(&init_net, &netfw_hook);
    kfree(netfw_label);
    netfw_label = NULL;
    kfree(netfw_message);
    netfw_message = NULL;
    pr_info("netfw_hello: memory released; module unloaded\n");
}

module_init(netfw_hello_init);
module_exit(netfw_hello_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("NETFW learning project");
MODULE_DESCRIPTION("Phase 12 rule descriptor; isolated UDP verdict lab retained");
MODULE_VERSION("0.12");
