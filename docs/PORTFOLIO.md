# Project notes for a portfolio

**NETFW — Linux Netfilter firewall lab**  
C / Linux kernel / Netfilter / Netlink / Python / Bash

I wrote NETFW to get hands-on with packet processing in the Linux kernel and the interface between kernel configuration and a userspace tool. The module inspects incoming IPv4 packets, stores ordered firewall rules in a bounded table, and lets a Python CLI stage and inspect those rules over Netlink. The filtering demonstration is deliberately limited to UDP packets on an isolated test interface.

The harder engineering details were bounds checking around packet headers and Netlink messages, ownership and cleanup during failed module initialization, locking around shared rule data, and designing network-namespace tests that leave the host unchanged after they exit.

## Resume version

- Developed an out-of-tree C kernel module using IPv4 Netfilter hooks, bounded packet-header parsing and ordered lab-only UDP rules.
- Built a 16-entry spinlock-protected rule table and a Netlink/Python CLI for validated snapshots and capability-gated atomic rule updates.
- Implemented a separate 5-tuple connection-tracking prototype with bidirectional lookup, simplified TCP/UDP states and explicit timeouts; tested the module with Python checks and isolated veth/netns regressions.

## What to show in an interview

Start with `kernel/netfw_hello.c`: explain the `PRE_ROUTING` hook and why header access isn't a direct pointer dereference. Then show `kernel/netfw_manage.h` for validate-before-publish and `userspace/netfw_protocol.py` for the wire contract. Finish with the staged UDP test, including teardown. Be clear that tracking state and *enforcing* state are different milestones here.

## Current limitations

This is a learning project, not a deployable security appliance. Connection state is not integrated into the live verdict path. Only unfragmented UDP on `nfwt10h` to `198.18.0.2` is eligible for staged filtering, and the Netlink endpoint is built on the shared `NETLINK_USERSOCK` protocol number. There is no persistent policy database or real packet telemetry.
