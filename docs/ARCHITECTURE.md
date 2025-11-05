# Architecture and threat boundaries

```
Python CLI (userspace/netfw_client.py)
   | AF_NETLINK / NETLINK_USERSOCK: PING, STATUS, RULES, REPLACE
   v
Kernel module (kernel/netfw_hello.c)
   | validates Netlink framing, size, version, command and request ID
   | REPLACE requires netlink_capable(..., CAP_NET_ADMIN)
   v
Bounded rule table (16 ordered entries, spin_lock_bh)
   | snapshot / atomic replacement, default policy
   +----> opt-in IPv4 PRE_ROUTING evaluation
            ONLY lab_rules=1; nfwt10h; 198.18.0.2; valid unfragmented UDP
            separate legacy lab_drop still supported

Separate educational 5-tuple connection hash table (8 buckets x 4 entries)
  -> bidirectional lookup, TCP simplified states, UDP pseudo-state,
     explicit timeout expiration/cleanup; NOT wired into live verdicts.
```

**Important limitations:** Not a production or general-purpose stateful firewall. Connection metadata does not protect active packets. Staged rules operate only on tightly scoped lab UDP; other traffic is unaffected. Fragmented traffic deliberately bypasses staged filtering and is ACCEPTed. There is no packet reassembly, TCP sequence validation, background connection expiration, namespaced Generic Netlink family, persistent configuration, true firewall telemetry or workload hardening. NETLINK_USERSOCK can conflict with another user. CAP_NET_ADMIN grants privileged staging rights; it is not per-rule sandbox isolation. Module parameters default to safe lab opt-out. No guarantees of protection against malicious traffic.

**Memory and concurrency:** packet hook is allocation-free; rule and connection tables are bounded; table operations are protected by spin_lock_bh. Kernel teardown unregisters hook and releases socket/resources. Run user-owned namespace/veth cleanup separately.

**Verifying claims:** source tests prove source/API contracts, not functional safety. Fedora Kbuild confirms kernel compatibility for its exact running kernel. Only privileged test scripts provide runtime lab evidence; release claims must identify which tests were actually executed.
