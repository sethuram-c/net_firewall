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
