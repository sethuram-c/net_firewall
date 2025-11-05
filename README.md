# NETFW - Linux Stateful Firewall (learning project)

**Phase 3 / 35** - C loadable module and reproducible Kbuild + diagnostics. **No traffic filtering yet.**

Platform: Fedora Linux. Future architecture: C in kernel, Python CLI/tests, Bash tooling.

## Setup

Use a disposable Fedora VM for privileged kernel work.

```bash
sudo dnf install gcc make git python3 bash mokutil "kernel-devel-$(uname -r)"
./scripts/check_env.sh
```

If Fedora cannot find matching `kernel-devel`, update your Fedora kernel/devel pair and reboot into the new kernel first. Secure Boot may reject unsigned modules; do not disable Secure Boot merely for this project.

## Phase 3 commands

```bash
make help                         # targets
make info                         # check current kernel's build tree
make                              # build .ko with kernel Kbuild
make verify-build                 # examine vermagic/license/metadata
make check                        # Python and Bash checks; no root
./scripts/inspect_module.sh       # READ-ONLY build/load/log snapshot
sudo ./scripts/test_module.sh --load   # only in a VM; load/unload smoke test
sudo ./scripts/inspect_module.sh  # include restricted journal entries
make clean                        # remove generated outputs
```

`make` and `make check` do not require root. `test_module.sh --load` is intentionally the *only* included action that modifies loaded kernel modules. It refuses to touch a preloaded module and attempts cleanup on errors.

## Troubleshooting quick map

- `No such file or directory: .../build`: kernel-devel version does not match `uname -r`.
- `Required key not available` on insmod: module-signing policy, often Secure Boot.
- `invalid module format`: inspect `modinfo ... | grep vermagic`, compare `uname -r` and kernel log.
- No `journalctl -k` output: try `sudo ./scripts/inspect_module.sh`.
- `insmod: File exists`: module already loaded; use `lsmod | grep netfw_hello`.

## Repository

- `kernel/netfw_hello.c`: module lifecycle code (unchanged from Phase 2)
- `Makefile`: build, check, metadata, help, and cleanup targets
- `scripts/check_env.sh`: Fedora setup check
- `scripts/test_module.sh`: explicit privileged lifecycle test
- `scripts/inspect_module.sh`: safe read-only diagnostics
- `tests/`: no-root Python checks
- `progress.md`: phase-by-phase acceptance checklist

The detailed personal-learning PDF is distributed separately and is not part of the Git repository.


## Phase 4: kernel heap memory and errors
The minimal module now allocates a 128-byte buffer with `kmalloc(..., GFP_KERNEL)` during initialization, checks the result, safely copies a short message, and releases it with `kfree()` on unload. If allocation fails, initialization returns `-ENOMEM` and the module does **not** become loaded. No firewall hooks exist yet.

Fedora VM smoke test (only if module loading is allowed):

```bash
make clean && make && make verify-build && make check
sudo ./scripts/test_module.sh --load
sudo journalctl -k -b --no-pager | grep netfw_hello
lsmod | grep '^netfw_hello' || echo 'module is unloaded (expected)'
```

`make check` consists of static/source tests, **not** live kernel fault injection or proof of memory safety. The script loads then unloads the module. See the personal Phase 4 PDF for the concepts and exercises.

## Phase 5 - multi-resource init and error unwinding

Module initialization acquires two independent allocations. If either allocation fails,
initialization returns `-ENOMEM` and frees everything already acquired. Kernel will
**not** call `module_exit` after failed `module_init`, so cleanup must happen in the
init failure path. The read-only `fail_step` module parameter injects errors for learning.

On a disposable Fedora VM (from repository root):

```bash
make clean && make && make verify-build && make check
sudo ./scripts/test_failure_paths.sh
sudo ./scripts/test_module.sh --load
sudo journalctl -k -b --no-pager | grep netfw_hello
```

`test_failure_paths.sh` expects `insmod` to fail (normal for `fail_step=1` and `2`).
It checks that the module is not loaded afterward; only log inspection plus more
advanced runtime tooling can provide stronger assurance against memory leaks.
Never use these tests on an important system; kernel modules have full kernel privileges.

## Phase 6 — Observe-only IPv4 Netfilter hook

`kernel/netfw_hello.c` now registers an IPv4 `NF_INET_PRE_ROUTING` hook in the **initial network namespace** (`init_net`). Every callback returns `NF_ACCEPT`: no packet inspection, dropping, or logging occurs on the packet path. This is a registration/lifecycle learning milestone, **not a functioning firewall yet**.

On Fedora (preferably a VM):

```bash
make clean && make && make verify-build
make check
sudo ./scripts/test_failure_paths.sh
sudo ./scripts/test_netfilter_observe.sh
sudo journalctl -k -b --no-pager | grep netfw_hello
```

`PRE_ROUTING` covers incoming IPv4 packets, not locally generated `LOCAL_OUT` traffic. The script deliberately tests registration and cleanup rather than claiming packet observation counts. Module insertion requires a compatible Fedora kernel, kernel-devel and any applicable Secure Boot signing/trust. The personal learning PDF is kept outside Git.


## Phase 7: safe IPv4 metadata observation

The PRE_ROUTING hook now uses `skb_network_offset` and `skb_header_pointer` to
copy a safe IPv4 header view, checks version, IHL, total length, and buffer
bounds, then uses **rate-limited** kernel logging of IPv4 source/destination,
protocol and packet length. The hook still returns `NF_ACCEPT` on **every**
path. This is learning/diagnostic code, **not** packet validation or a firewall
policy. Nonlinear packet buffers are permitted; no TCP/UDP parsing yet.

On a Fedora VM run `make clean && make && make verify-build && make check`,
then `sudo ./scripts/test_ipv4_observe.sh`. Inspect with
`sudo journalctl -k -b --no-pager | grep netfw_hello`. A localhost ping may
not pass through IPv4 PRE_ROUTING in the way a packet entering an interface
does; use a second namespace / veth setup in a later integration phase.
If module signature enforcement prevents loading, do not disable Secure Boot
on your main system; use a signed module or test VM.

## Phase 8 — TCP and UDP header observation
After verifying on Fedora: `make clean && make && make verify-build && make check`; then `sudo ./scripts/test_transport_observe.sh` and inspect `sudo journalctl -k -b --no-pager | grep netfw_hello`.

TCP and UDP ports are logged from valid, non-later IPv4 fragments. Header reads use `skb_header_pointer`, bounds are checked against IPv4 total length, and ports are converted from network byte order. The callback **always returns NF_ACCEPT**. Source-level tests cannot prove runtime packet parsing is correct.


## Phase 9 — ICMP inspection & malformed IPv4 safety

The IPv4 PRE_ROUTING observer now parses ICMP `type` and `code` using `skb_header_pointer` after verifying the declared IPv4 payload has enough bytes. Non-initial fragments are skipped. TCP/UDP support is unchanged. Every path still returns `NF_ACCEPT`. This module is NOT a traffic blocker.

Fedora: `make clean && make && make verify-build && make check`; then `sudo ./scripts/test_failure_paths.sh` and `sudo ./scripts/test_icmp_observe.sh`. View events using `sudo journalctl -k -b --no-pager | grep netfw_hello`. Run kernel modules in a VM or disposable testing environment.

`make check` is a *source-regression* suite: it does not compile the module. Kernel compilation is a separate mandatory acceptance check.


## Phase 10 — Controlled ACCEPT/DROP lab
Default is `lab_drop=0`; the hook still accepts all packets. The opt-in `lab_drop=1` mode drops **only** valid initial IPv4 UDP packets arriving on `nfwt10h`, targeting `198.18.0.2:54321`. Other packets are accepted. This is intentionally not a configurable firewall rule engine.

Fedora VM prerequisites: `sudo dnf install iproute python3 iputils` (plus existing kernel-devel/toolchain). Run `make clean && make check-build`, then `sudo ./scripts/test_lab_drop.sh` in a disposable VM with console access. The script creates a temporary network namespace and veth, confirms UDP/54322 ACCEPT and UDP/54321 DROP using a real receiving socket, unloads the module, and removes the test network resources. `ip netns` requires root and kernel support. Avoid using this on a remote host.

Never enable lab mode against a production or remote host. Existing network/firewalld rules may independently block the probe and invalidate the ACCEPT assertion. The source-level `make check` does not compile a `.ko`; `make check-build` is the combined build check.

## Phase 11 - verdict and teardown regression (Fedora VM only)

Phase 10's user-reported lab delivered the correct packets but left the module
loaded. Phase 11 replaces an `lsmod | grep -q` check in a `pipefail` script
with a direct `/sys/module/netfw_hello` membership check. In a long pipeline
`grep -q` may close its input early and cause an upstream SIGPIPE; with
`set -o pipefail`, a true match can therefore appear as a failed pipeline.

`test_lab_drop.sh` now accepts `LAB_DROP_MODE=0` (no packets dropped) and
`LAB_DROP_MODE=1` (only the isolated UDP/54321 case dropped); default is 1.
`test_verdict_regression.sh` runs both modes, checks delivery, and asserts
that module, temporary veth and namespace are absent **after** each run.

```bash
make clean && make check-build
sudo rmmod netfw_hello  # only if OUR test module is currently loaded
sudo ./scripts/test_failure_paths.sh
sudo ./scripts/test_verdict_regression.sh
lsmod | grep '^netfw_hello' || echo 'Module unloaded'
ip link show nfwt10h  # should report non-existent device
sudo ip netns list
```

These tests have root privileges and modify network namespaces; run only in
a disposable Fedora VM with console access. `make check` is not a replacement
for the Fedora runtime regression.


## Phase 12 — rule data model (not yet active)

`kernel/netfw_rule.h` defines `struct netfw_rule`, explicit matching flags, and ACCEPT/DROP actions. IPv4 addresses and masks use `__be32` (network byte order); port fields are host-order integers. Interface names are limited to `IFNAMSIZ`. The packet hook still uses the Phase 10 lab-only policy: declaring a rule does **not** enforce it. Rule evaluation begins in later phases.

Fedora validation: `make clean && make check-build`, followed in a disposable VM by `sudo ./scripts/test_failure_paths.sh` and `sudo ./scripts/test_verdict_regression.sh`. Check cleanup using `test ! -d /sys/module/netfw_hello`, `ip link show nfwt10h`, and `sudo ip netns list`.


## Phase 13 — Source IPv4 matching (reusable helper)

`kernel/netfw_match.h` introduces `netfw_match_src_ipv4(rule, packet_src)` for optional source IPv4 matching. With `NETFW_MATCH_SRC_IP` clear it returns true (wildcard). When enabled, both network-order addresses are ANDed with the network-order mask and compared: `(packet_src & mask) == (rule_src & mask)`. A `/32` mask means exact host; `/24` matches a subnet; `/0` matches all addresses. Set the flag deliberately: a zero field must not be confused with a disabled flag.

The module executes a harmless zero-mask example during initialization solely to compile/type-check use of the helper; **no packet verdict consumes a rule yet**. The existing opt-in UDP lab DROP remains the only active drop case. Later phases will wire helpers to the Netfilter callback.

On Fedora, run `make clean && make check-build`, `sudo ./scripts/test_failure_paths.sh`, and `sudo ./scripts/test_verdict_regression.sh`. After the regression verify the module/interface/namespace were removed. Source-level Python tests do not prove the module builds: use `make check-build`.


## Phase 14 — Destination IPv4 CIDR matcher

`kernel/netfw_match.h` now includes `netfw_match_dst_ipv4(rule, packet_dst)`. The helper returns true when `NETFW_MATCH_DST_IP` is unset (destination wildcard). When set, it compares `(packet_dst & dst_mask) == (dst_ip & dst_mask)` in network byte order; `/32` matches one address, `/24` a subnet, `/0` any destination. Source matching remains unchanged. `kernel/netfw_hello.c` type-checks the new helper with an inert example during initialization. The hook does **not** yet evaluate dynamic rules; only the isolated opt-in lab rule can DROP packets.

On Fedora run `make clean && make check-build` (96 expected Python tests), then `sudo ./scripts/test_failure_paths.sh`, `sudo ./scripts/test_verdict_regression.sh` and confirm the test resources are removed. The learning PDF is personal and intentionally not in the repository.


## Phase 15 - TCP/UDP source and destination port matching

`kernel/netfw_match.h` now implements `netfw_match_ports()`. Rule ports are
**host order** (`u16`), packet ports **network order** (`__be16`), so comparisons
convert with `ntohs()`. Match flags determine wildcards: port zero is a valid
port, not an implicit wildcard. When either port match is enabled, only TCP
and UDP can match. Both enabled conditions must be satisfied (AND semantics).

This helper is tested by an **initialization-only smoke check**, not yet
called in the packet hook. The opt-in lab UDP DROP is unchanged.

Fedora acceptance:

```bash
make clean && make check-build   # 105 source checks plus kernel compilation
sudo ./scripts/test_failure_paths.sh
sudo ./scripts/test_verdict_regression.sh
lsmod | grep '^netfw_hello' || echo 'Module unloaded'
ip link show nfwt10h             # expected: does not exist
sudo ip netns list               # expected: empty for test namespace
```

Use a disposable VM for root-required tests. The phase PDF is personal study
material and should not be committed.


## Phase 16 — Protocol and combined rule predicates

`netfw_match_protocol(rule, protocol)` honors `NETFW_MATCH_PROTOCOL`: with the
flag clear it matches any protocol; with the flag set it requires exact equality.
`netfw_match_packet()` combines source CIDR, destination CIDR, protocol, and
TCP/UDP ports using logical AND. A null rule pointer is rejected. Ports remain
network-order on the packet side and host-order in rule data. Only call the
helper with fields already validated and extracted safely from packet headers.
**Interface matching is deliberately deferred** to a later step because the
`NETFW_MATCH_IN_IFACE` field is not part of this predicate yet.

The combined matcher runs only as a harmless initialization smoke check; it
is not called by the Netfilter hook, and the opt-in lab verdicts are unchanged.

Fedora validation: `make clean && make check-build` (114 Python tests), then
`sudo bash scripts/test_failure_paths.sh` and
`sudo bash scripts/test_verdict_regression.sh` in a disposable VM.

## Phase 17 - ordered rule evaluation and default policy

`kernel/netfw_policy.h` introduces a pure `netfw_evaluate_rules()` helper.
Rules are checked from index 0 upward, and the first complete match supplies
its ACCEPT/DROP action; no match returns the explicitly provided default.
A null/empty table is safe. Unsupported ingress-interface flags are skipped,
not silently ignored. Invalid rule actions are skipped; an invalid default
falls back to ACCEPT for safety. Configuration validation will be improved
before rules become active. The example two-rule table runs only during module
initialization and is never consulted by the live Netfilter hook. The existing
`lab_drop` opt-in behavior remains unchanged.

Fedora: `make clean && make check-build`, then
`sudo bash scripts/test_failure_paths.sh` and
`sudo bash scripts/test_verdict_regression.sh` in a disposable VM.

### Phase 18: bounded rule storage (inactive demonstration)
`kernel/netfw_table.h` defines a fixed-capacity (16) table of rule descriptors.
Validated additions preserve insertion order, reject overflow with `-ENOSPC`,
and use a bottom-half-safe spinlock shared with reads. A temporary table is
allocated and exercised **only at module initialization**, then freed before
Netfilter registration. The table does **not** change live packet policy yet.
Run `make check-build` on Fedora followed by the existing failure-path and
verdict-regression scripts. See the separate Phase 18 PDF for concepts.


## Phase 19 - TCP/UDP flow identity (concept foundation)
`kernel/netfw_flow.h` introduces an immutable five-tuple of source/destination
IPv4, source/destination transport ports, and L4 protocol. Comparisons work
in both forward and reverse directions. All endpoint fields use **network byte
order**, matching packet headers. No state table, timeouts, or acceptance
policy based on connections exists yet. The module only smoke-tests the helper
during initialization. ICMP cannot be represented as TCP/UDP ports.

Fedora: `make clean && make check-build`, then
`sudo bash scripts/test_failure_paths.sh` and
`sudo bash scripts/test_verdict_regression.sh` in a disposable VM.

### Phase 20: bounded connection hash table (inactive demo)
`kernel/netfw_conn.h` implements a fixed 8-bucket / four-slots-per-bucket lookup table keyed on the TCP/UDP five-tuple. A symmetric XOR hash puts both directions in the same bucket; full-key equality prevents collisions from becoming false matches. Under `spin_lock_bh()`, insertion rejects duplicates and bucket overflow; lookup returns a boolean and an optional reverse-direction flag. This table is currently instantiated **only during module initialization** for self-tests; no packets are tracked by the hook and live lab decisions are unchanged. Run `make check-build` on Fedora and the existing namespace regression test.


### Phase 21 — Flow direction and state metadata
`kernel/netfw_conn.h` adds a copy-out `netfw_conn_lookup_info()` API carrying the stored state and whether a key matched in the original or reply direction. Entries start in `NETFW_CONN_NEW`; detecting reverse direction does **not** mark a flow established. No live tracking or transitions yet. The old lookup API is retained. Run `make check-build` and isolated regression tests as before.


## Phase 22 — Simplified TCP state transitions

`netfw_conn_tcp_step()` in `kernel/netfw_conn.h` models a tiny TCP handshake: NEW (initial SYN observed), REPLIED (reverse SYN+ACK), ESTABLISHED (original ACK), then CLOSING (FIN/RST). Missing or out-of-order handshake steps do not advance the state. A reverse lookup by itself never advances a connection. Updates are protected by `spin_lock_bh`; API returns a snapshot, not an internal pointer.

This is intentionally **not** full TCP tracking: no sequence/ACK-number validation, retransmission handling, teardown handshake, timeouts, or live packet state changes. Init-only smoke tests exercise transitions. Real lab ACCEPT/DROP behavior is preserved.

Fedora: `make clean && make check-build`; `sudo bash scripts/test_failure_paths.sh`; `sudo bash scripts/test_verdict_regression.sh`.


### Phase 23: UDP pseudo-state and inactivity
`kernel/netfw_conn.h` now provides `netfw_conn_udp_step()` and `netfw_conn_expire()` for the bounded educational flow table. Original traffic remains NEW; a reverse-direction datagram changes state to REPLIED. Inactivity is measured in kernel jiffies: unreplied UDP 30s, replied UDP 120s, TCP 300s. The expiration scan is explicit (no timer/workqueue), lock-protected, and removes expired entries. It runs only in deterministic initialization-time checks; it does not yet track live packets or affect filtering.

On Fedora: `make clean && make check-build`, then `sudo bash scripts/test_failure_paths.sh` and `sudo bash scripts/test_verdict_regression.sh`. Nested tests are invoked via `bash` to tolerate ZIP extraction permissions.


### Phase 24 — synchronized connection cleanup
The educational connection table now exposes `netfw_conn_count()` (snapshot),
`netfw_conn_remove()` (either direction), and `netfw_conn_clear()` (idempotent
reset). Each uses `spin_lock_bh()` to serialize access to the fixed slots.
The explicit expiration scan from Phase 23 is retained; no worker or live
connection tracking is activated. A table owner must stop all concurrent
readers/writers before freeing its memory; clearing does not make freeing
concurrently safe. Initialization exercises removal and clearing.

Fedora: `make clean && make check-build`, then `sudo bash scripts/test_failure_paths.sh`
and `sudo bash scripts/test_verdict_regression.sh`. Verify module, veth and
namespace removal. The separate learning PDF must not be committed.


## Phase 25 — Netlink message contract (codec only)

`kernel/netfw_netlink.h` and `userspace/netfw_protocol.py` define a shared,
versioned 8-byte application payload: version (u8), command (u8), reserved
(u16, zero), request ID (u32, network order). Commands 1 and 2 denote PING
and STATUS. Unknown versions, commands, reserved bits or lengths are rejected.

**No AF_NETLINK socket is registered yet.** PING and STATUS are protocol
identifiers only. There is no kernel listener, no live replies, and no
userspace CLI yet. In particular, this phase does not modify Netfilter verdicts.

Run `python3 -m unittest tests/test_netlink_protocol.py -v` or `make check`.


## Phase 26 — Kernel Netlink PING / STATUS endpoint

The module now registers one `NETLINK_USERSOCK` endpoint in the initial network
namespace after successfully registering its existing IPv4 Netfilter hook.
Both PING and STATUS acknowledge the validated 8-byte Phase 25 payload without
modifying rules or providing statistics. The kernel strictly checks the Netlink
header, fixed payload length, message type, flags, application version and
reserved bytes. It copies potentially unaligned payload bytes before checking
fields, allocates replies with `GFP_ATOMIC`, and derives sender port ID from
`NETLINK_CB(skb).portid`, not the untrusted header. The socket is released
before the hook and module allocations on exit. Registration failure unwinds
the hook and allocations. No extra `NF_DROP` path is added.

**Experimental caveats:** protocol number `NETLINK_USERSOCK` (2) is shared,
so another kernel endpoint can prevent module insertion. Netlink replies are
not authenticated to applications and this is not a privileged firewall control
interface. STATUS currently echoes the request: no live state statistics. Do
not build mutation commands on this endpoint without proper access control.

With the module loaded, run:

```bash
sudo insmod kernel/netfw_hello.ko
python3 userspace/netfw_client.py ping
python3 userspace/netfw_client.py status
sudo rmmod netfw_hello
```

The Python transport validates response length, type, sequence, command and ID.
Run `make check-build`, then previously existing failure-path and verdict
regression scripts. Test socket exchanges only on a disposable Fedora VM.


## Phase 27 — Netlink error statuses and read-only CLI

Netlink replies now contain a 12-byte application payload: an
8-byte version/command/reserved/request-ID header (reserved zero in replies) and a signed big-endian 32-bit
status. Zero means success; a negative Linux errno reports a rejected request.
For an otherwise valid 8-byte request envelope: unsupported versions yield
`-EPROTONOSUPPORT`, nonzero reserved bytes `-EINVAL`, and unknown commands
`-EOPNOTSUPP`. Malformed Netlink envelopes are silently rejected because their
framing or sender information cannot be trusted. No rules are changed.

After `sudo insmod kernel/netfw_hello.ko`:

```bash
python3 userspace/netfw_client.py ping --request-id 42
python3 userspace/netfw_client.py status
sudo rmmod netfw_hello
```

The Python CLI checks response sequence, identity and status, reports Linux
errors, and uses nonzero exit codes on failure. STATUS is reachability-only,
not true counters. `NETLINK_USERSOCK` is shared; this is not authenticated
firewall administration. Phase 26 8-byte response parsing remains for existing
unit-test fixture compatibility, although the Phase 27 kernel emits 12 bytes.


## Phase 28 — read-only CLI diagnostics

`python3 userspace/netfw_client.py diagnose` reads `/proc/modules` and
`/sys/module/netfw_hello` without root or Netlink activity. Use `--json`
for scripting. Existing `ping` and `status` also accept `--json`, but require
a loaded Netlink endpoint. `status` confirms reachability only: it does not
report live rule, packet or connection counts. Diagnostics do not mutate kernel
state; no rule management is implemented yet.

```bash
python3 userspace/netfw_client.py diagnose
python3 userspace/netfw_client.py diagnose --json
sudo insmod kernel/netfw_hello.ko
python3 userspace/netfw_client.py ping --json
python3 userspace/netfw_client.py status --json
sudo rmmod netfw_hello
```


## Phase 29 — validated, read-only rule-table snapshots

`kernel/netfw_snapshot.h` safely copies the bounded, ordered rule table under
`spin_lock_bh`, with count and default action in one consistent snapshot.
No table pointer escapes the lock. The demo snapshot is tested during module
initialization; it is **not** exposed through Netlink and does not affect
packet filtering. The snapshot API writes to caller-owned storage.

The CLI can validate and display a trusted **offline** JSON example:

```bash
python3 userspace/netfw_client.py rules --file examples/rules_snapshot.json
python3 userspace/netfw_client.py rules --file examples/rules_snapshot.json --json
```

Version=1; default action ACCEPT or DROP; at most 16 ordered rules; strict
protocol, IPv4 CIDR, port, and interface validation. The CLI rejects unknown
fields. **No live rule export, Netlink rules command, rule mutation, or runtime
policy activation** exists in this phase. Do not confuse the example with
the currently loaded firewall configuration.

## Phase 30 — live, bounded, read-only Netlink rules export

The **read-only** command `python3 userspace/netfw_client.py rules --json` now asks
our kernel Netlink endpoint for a rule-table snapshot, rather than relying on
an offline JSON fixture. `rules --file examples/rules_snapshot.json --json` still
uses the independent Phase 29 offline sample. Each output includes `source`,
which distinguishes `kernel-netlink` from `offline-file`.

**Crucial:** The kernel-export table is initialized empty, default ACCEPT,
and never mutated in Phase 30. Therefore the live response is normally
`{"default_action":"ACCEPT","rule_count":0,"rules":[],"source":"kernel-netlink", ...}`.
This does *not* report the module's separately implemented opt-in `lab_drop`
condition, and it does *not* mean the sample offline DROP rule is installed.
No runtime rule policy is activated. Live packet filtering remains unchanged.

Protocol command `3` uses the same 8-byte versioned request. Successful replies
are 16 bytes (the 12-byte status response + one byte count, one byte default
action, two zero reserved bytes) plus at most 16 packed 44-byte rule descriptors.
Rules contain numeric flags, 4 network-order IPv4 address/mask values, two
network-order ports, protocol, action, a zeroed 16-byte placeholder for a
future interface field, and a zero 2-byte reserved field. No pointers, native
struct padding, or kernel memory addresses cross the boundary. The worst-case
application response is 720 bytes. Unexpected interface-match flags are
rejected rather than misrepresented; Python checks exact lengths, limits,
reserved fields, and protocol consistency.

Run on Fedora after compiling:

```bash
make clean && make check-build && make verify-build
sudo bash scripts/test_failure_paths.sh
sudo bash scripts/test_verdict_regression.sh
sudo insmod kernel/netfw_hello.ko
python3 userspace/netfw_client.py rules --json
python3 userspace/netfw_client.py rules --file examples/rules_snapshot.json --json
python3 userspace/netfw_client.py ping --json
python3 userspace/netfw_client.py status --json
sudo rmmod netfw_hello
lsmod | grep '^netfw_hello' || echo 'Module unloaded'
ip link show nfwt10h
sudo ip netns list
```

Source-level and Python tests do not substitute for Fedora compilation or
privileged exchange testing. The Netlink endpoint still uses shared protocol
number NETLINK_USERSOCK and may conflict with another owner.


## Phase 31/35 — Controlled rule-management staging

`kernel/netfw_manage.h` adds `netfw_manage_replace()` for a bounded (0–16)
whole-table replacement. Authorization is an explicit **trusted kernel caller**
precondition; the API returns `-EPERM` when it is false, `-EINVAL` for an
invalid candidate/default policy, and publishes the full validated candidate
under `spin_lock_bh`. Unsupported incoming-interface predicates are rejected.
An empty authorized replacement clears all rules and sets a new default.

**Security boundary:** Phase 31 does **not** accept Netlink write requests.
No userspace field may supply authorization. A future Netlink write handler
must verify the sending client's `CAP_NET_ADMIN` in the correct namespace before
calling the kernel helper. The live exported table is still empty, read-only,
and distinct from the existing `lab_drop` verdict.

Validation: `make check-build`, `make verify-build`,
`sudo bash scripts/test_failure_paths.sh`,
`sudo bash scripts/test_verdict_regression.sh`, and live
`python3 userspace/netfw_client.py rules --json` after loading the module.


## Phase 32 — Authenticated Netlink staging updates (NOT live enforcement)

The new `apply --file` command atomically replaces the **staging/export** rule table.
Linux checks the sending socket's `CAP_NET_ADMIN` with `netlink_capable(skb, CAP_NET_ADMIN)` before accepting it. `rules --json` displays the staging snapshot.

```bash
sudo insmod kernel/netfw_hello.ko
sudo python3 userspace/netfw_client.py apply --file examples/rules_snapshot.json --json
python3 userspace/netfw_client.py rules --json
sudo rmmod netfw_hello
```

The `lab_drop` lab policy is **unaffected**, and the staging rules are **not** used in the Netfilter packet hook. Do not assume `DROP` staged via Netlink drops live packets.
An unprivileged apply should return `EPERM`; an invalid candidate must not partially update the table. Maximum 16 rules, no interface predicates, no background writer, and no root-free bypass. The Netlink socket is shared `NETLINK_USERSOCK` and should be used only in the isolated lab.


## Phase 33 — opt-in, isolated staged rule enforcement

New immutable-at-load `lab_rules=1` parameter permits the staged rule table to decide **UDP** verdicts **only** for packets arriving on `nfwt10h` with destination `198.18.0.2` and a validated UDP header. It is disabled by default; `lab_drop` retains its existing independent UDP/54321 demonstration. The table's first-match policy applies within the lab boundary, and its default action is used if no rules match. No packets on other interfaces or to other destination IPs consult staged rules. TCP, ICMP, fragmented non-initial packets, and malformed UDP remain unaffected.

**Safety:** Run only on a disposable VM you administer. The staging table is populated by an authenticated `CAP_NET_ADMIN` Netlink `apply`. Test with `sudo bash scripts/test_staged_lab_rules.sh` after `make check-build`; the test creates a temporary network namespace, applies a UDP DROP rule, verifies UDP 54322 is accepted and 54321 is dropped, then unloads the module and deletes interfaces/namespace via a cleanup trap. Never activate `lab_rules=1` on general production network interfaces. The script explicitly refuses preexisting lab interfaces and loaded modules. Existing `sudo bash scripts/test_verdict_regression.sh` still tests legacy behavior.

This is deliberately restricted demonstration enforcement, **not a full dynamic stateful firewall**. The connection table remains disconnected from packet decisions.

## Phase 34/35 — Hardening and extended isolated regression

- The **staged** rule path now declines IPv4 packets with MF or any fragment offset: no port-based assertion is made for incomplete datagrams. Like earlier malformed/unsupported traffic, these are **accepted**, not safely filtered; production firewalls require a documented fragment policy and defragmentation strategy. The original `lab_drop` laboratory rule is unchanged.
- Netlink handles exactly one application envelope per skb and rejects trailing/batched framing.
- `sudo bash scripts/test_lab_hardening.sh` exercises disabled enforcement, module reload (no persistent staging state), staged positive/negative UDP cases, invalid input and atomicity, empty-table reset, and cleanup in an isolated veth/netns lab. Script refuses an existing module or interface; **run only in a disposable VM**.
- This phase does not promise full hardening: UDP spoofing, TCP stateful enforcement, fragments, network namespace isolation and a dedicated Generic Netlink family are future concerns.
- Verification: `make clean && make check-build && make verify-build`; then privileged `sudo bash scripts/test_failure_paths.sh`, `sudo bash scripts/test_verdict_regression.sh`, `sudo bash scripts/test_staged_lab_rules.sh`, `sudo bash scripts/test_lab_hardening.sh`. Kernel build and privileged tests must run on Fedora.

## Phase 35/35 — Final project audit, demonstration and portfolio release

Run `python3 scripts/final_audit.py --json` or `make final-audit` for an
unprivileged, read-only release audit. The audit checks required project files
and runs Python/source and Bash-syntax tests; it does not load modules, alter
rules, create interfaces or execute privileged tests. Run
`python3 scripts/final_audit.py --json --require-module` only after successfully
compiling the kernel module on your Fedora machine.

The final resources are `docs/DEMO_RUNBOOK.md` (privileged Fedora walkthrough),
`docs/ARCHITECTURE.md` (design and limitations), `docs/PORTFOLIO.md` (accurate
project descriptions), and `docs/RELEASE_CHECKLIST.md` (release checklist).
Complete the privileged regressions on a disposable Fedora VM before claiming
a fully verified release:

```bash
make clean && make check-build && make verify-build
python3 scripts/final_audit.py --json --require-module
sudo bash scripts/test_failure_paths.sh
sudo bash scripts/test_verdict_regression.sh
sudo bash scripts/test_staged_lab_rules.sh
sudo bash scripts/test_lab_hardening.sh
```

**Scope:** Live rule enforcement is limited to the opt-in isolated UDP lab.
Connection-tracking helpers are demonstrational and do not drive live packet
verdicts. The project is not a production-ready stateful firewall.
