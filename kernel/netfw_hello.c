// SPDX-License-Identifier: GPL-2.0
/* Phase 9: bounded IPv4/TCP/UDP/ICMP header inspection; accept-only. */
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
#include <net/net_namespace.h>
#include <net/ip.h>

#define NETFW_MESSAGE_SIZE 128
#define NETFW_LABEL_SIZE 32

static char *netfw_message;
static char *netfw_label;
/* 0: normal, 1: fail before first allocation, 2: fail after first. */
/* skb data may be fragmented/non-linear: copy header bytes, never dereference
 * skb->data as an unverified struct iphdr. The hook is read-only/fail-open.
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
            ntohs(udp->len) <= transport_len)
            pr_info_ratelimited("netfw_hello: UDP %pI4:%u -> %pI4:%u\n",
                                &iph->saddr, ntohs(udp->source),
                                &iph->daddr, ntohs(udp->dest));
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
    strscpy(netfw_label, "phase9", NETFW_LABEL_SIZE);
    err = nf_register_net_hook(&init_net, &netfw_hook);
    if (err) {
        pr_err("netfw_hello: hook registration failed (%d)\n", err);
        goto err_free_label;
    }
    pr_info("netfw_hello: %s; label=%s; IPv4 observe-only hook active\n",
            netfw_message, netfw_label);
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
MODULE_DESCRIPTION("Phase 9 IPv4 TCP UDP ICMP observer");
MODULE_VERSION("0.9");
