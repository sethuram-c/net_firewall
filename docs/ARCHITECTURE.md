# How NETFW fits together

There are two paths in the module: packets enter through Netfilter, while the CLI talks to the module over Netlink. They meet at the bounded rule table, but only when the opt-in lab gate is enabled.

```text
Python CLI -- Netlink request --> netfw_nl_receive()
                                        |
                              validate / CAP_NET_ADMIN
                                        |
                             16-rule staging table
                                        |
IPv4 PRE_ROUTING --> parse header --> lab UDP gate --> first-match verdict
                         |
                  other traffic: ACCEPT
```

## Packet path

`kernel/netfw_hello.c` registers an IPv4 `NF_INET_PRE_ROUTING` hook in `init_net`. Header access uses `skb_header_pointer()` and checks IP and transport lengths before reading ports. Staged rules are considered only when `lab_rules=1`, ingress is `nfwt10h`, the destination is `198.18.0.2`, and the packet is valid, unfragmented UDP. Rules are checked in order, with a configured fallback action. The original `lab_drop` parameter is independent of the staged rule table.

Everything else returns `NF_ACCEPT`. Fragmented datagrams are not safely inspected by these port rules. This is an intentional constraint of the lab, not a fragment-handling implementation.

## Control path

`userspace/netfw_client.py` exchanges versioned binary messages with the module using `NETLINK_USERSOCK`. The kernel rejects unsupported framing and validates message fields and lengths. `REPLACE` requires the sender to have `CAP_NET_ADMIN`. It validates every incoming rule before swapping the table under `spin_lock_bh()`. `RULES` copies a bounded snapshot; it does not expose kernel pointers. Python checks response lengths, identifiers and reserved fields before using the payload.

The staging table holds at most 16 rules. The live packet hook does not allocate memory while evaluating them. `STATUS` currently checks that the endpoint is reachable; it is not a counter API.

## Connection tracking is separate

`netfw_conn.h` implements an 8-bucket, four-slots-per-bucket table keyed by a TCP/UDP five-tuple. It supports original/reply lookup, small TCP state transitions, a UDP replied state, explicit jiffies-based expiry and removal. It is exercised in the module's initialization tests and is NOT wired into live verdicts: the packet hook never queries it. Calling the current module a *stateful enforcing firewall* would be inaccurate.

## Things I would change next

A dedicated Generic Netlink family would avoid depending on the shared `NETLINK_USERSOCK` number. A production implementation would also need coherent fragmentation/reassembly policy, packet-path flow integration, TCP sequence tracking, periodic expiry, counters, network namespace scoping, and substantially more adversarial testing. For now, the isolated lab boundary keeps mistakes from applying to normal traffic.
