# NETFW — Linux Netfilter learning firewall

**Portfolio-ready overview:** Built an out-of-tree Linux kernel module in C with IPv4 Netfilter pre-routing inspection, strict UDP lab-only policy evaluation and a Python CLI communicating over Netlink. Implemented bounded rule storage, ordered match predicates, authenticated CAP_NET_ADMIN staging updates, read-only rule snapshots and multiple network-namespace regression scripts. Added a separate 5-tuple connection-table learning implementation with simplified TCP/UDP state metadata and expiration utilities.

**Tech stack:** C (Linux kernel/Kbuild, Netfilter, spinlocks, Netlink), Python (CLI, protocol validation, unittest), Bash (fault-injection, veth/netns regression), Fedora 44.

**Resume bullets (accurate scope):**
- Designed and validated an out-of-tree IPv4 Netfilter module with opt-in, interface/address-scoped UDP rule enforcement for isolated lab traffic.
- Implemented a bounded (16-entry) synchronized rule table, versioned Netlink messaging and privilege-gated atomic rule updates with a Python inspection/apply CLI.
- Built a separate bounded 5-tuple connection data structure with bidirectional lookup, simplified TCP/UDP metadata and explicit expiration, without claiming live stateful enforcement.
- Created repeatable Python structural checks and privileged network-namespace regression scripts to test malformed inputs, fault injection, and cleanup.

**Demo sequence:** Follow `docs/DEMO_RUNBOOK.md` exactly. Show the negative and positive lab UDP test, non-root write rejection, privileged staging, live RULES snapshot, and clean module/namespace teardown. Attach command output only after actually running it.

**Limitations to disclose:** educational prototype; live stateful connection tracking not integrated; no general ingress firewall policy; staged filtering only on `nfwt10h` to `198.18.0.2`; fragmented packets bypass staged policy; Netlink uses shared NETLINK_USERSOCK.

**Suggested README portfolio subtitle:** “Educational, fail-safe IPv4 Netfilter + Netlink firewall lab; not a production security appliance.”
