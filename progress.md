# NETFW progress tracker

**Plan:** 35 small phases (~1–1.5 focused hours each); Fedora; C kernel + Python CLI/tests + Bash.

## Phase 1 — Kernel foundations & Fedora setup
**Status:** Files delivered; Fedora verification on your machine still required.
- [ ] Environment checker passes on your Fedora system
- [ ] Explain user space vs kernel space, matching kernel-devel, and Secure Boot

## Phase 2 — First C loadable kernel module
**Status:** Implemented and statically tested; actual Fedora build and privileged load/unload await your machine.

**What changed:** `kernel/netfw_hello.c`, root `Makefile`, `scripts/test_module.sh`, `tests/test_module_source.py`, improved `.gitignore`, updated `README.md` and this file.

**Learn:** `module_init`/`module_exit`, `__init`/`__exit`, `pr_info`, GPL metadata, Kbuild's `obj-m`, `.ko` artifact, module-loading permissions, log inspection.

**Acceptance checklist:**
- [ ] Read the separate Phase 2 learning PDF
- [ ] Run `./scripts/check_env.sh` with zero failures
- [ ] `make` builds `kernel/netfw_hello.ko` on Fedora
- [ ] `make check` succeeds
- [ ] `modinfo kernel/netfw_hello.ko` displays license and description
- [ ] In a Fedora VM, `sudo ./scripts/test_module.sh --load` succeeds
- [ ] Verify both load and unload lines with `sudo journalctl -k -b --no-pager | grep netfw_hello`
- [ ] `make clean` removes generated build files
- [ ] Commit just the Phase 2 changes, with recorded metadata dates clearly distinguished from actual work date

**Not yet included:** firewall rules, packet handling, Netfilter hooks, connection tracking, Netlink.

## Phase 3 - Kbuild workflow and kernel diagnostics
**Status:** Fedora build, `make verify-build`, `make check` (8 tests), and diagnostics were reported successful by the learner; load/unload logs observed.

**Changed:** `Makefile`, `scripts/inspect_module.sh`, `tests/test_build_workflow.py`, `.gitignore`, `README.md`, `progress.md`.

**Concepts:** running kernel vs installed development headers, out-of-tree Kbuild, module `vermagic`, safe read-only inspection, kernel journal vs userspace log, diagnosing signing/load failures.

**Acceptance checklist:**
- [ ] Read Phase 3 learning PDF separately (not committed)
- [ ] `make info` shows a valid Kbuild tree on Fedora
- [ ] `make && make verify-build` pass
- [ ] `make check` passes
- [ ] `./scripts/inspect_module.sh` runs without modifying system state
- [ ] In a disposable Fedora VM: `sudo ./scripts/test_module.sh --load` succeeds
- [ ] `sudo ./scripts/inspect_module.sh` shows load/unload log entries
- [ ] `make clean` removes build artifacts
- [ ] Explain Kbuild, `vermagic`, journal permissions, and module-signing implications

## Phase 4 - Kernel memory and error handling
**Status:** Implemented; source tests run locally. Fedora build/load must be verified by the learner.

**Changed:** `kernel/netfw_hello.c`, `tests/test_kernel_memory_source.py`, `README.md`, `progress.md`.

**Learn:** kernel heap vs stack, `kmalloc` / `kfree`, `GFP_KERNEL`, allocation failure, `-ENOMEM`, bounded copying with `strscpy`, ownership, leak prevention, and why partial initialization needs cleanup.

**Acceptance checklist:**
- [ ] Read the separate personal Phase 4 PDF
- [ ] Explain when `GFP_KERNEL` is allowed and why allocation can fail
- [ ] `make clean && make && make verify-build` works on Fedora
- [ ] `make check` passes all 14 tests
- [ ] In a disposable Fedora VM, load then unload with `sudo ./scripts/test_module.sh --load`
- [ ] Kernel journal shows allocation message and memory released message
- [ ] Explain the `-ENOMEM` failure path (not exercised by routine smoke test)
- [ ] Commit changed files with planned Phase 4 Git metadata

## Phase 5 - Initialization ordering and safe rollback
**Status:** Source implementation and no-root tests complete; Fedora module runtime testing pending.

**Modified:** `kernel/netfw_hello.c`, `Makefile`, `README.md`, `progress.md`.
**Added:** `scripts/test_failure_paths.sh`, `tests/test_lifecycle_failures_source.py`.
**Learn:** multiple owned allocations; partial failure rollback; `goto` cleanup; return `-ENOMEM`; module parameters; why `module_exit` does not run when `module_init` fails.

**Acceptance checklist:**
- [ ] Read personal Phase 5 learning PDF (not part of repository)
- [ ] `make clean && make && make verify-build` on Fedora
- [ ] `make check` passes 20 tests
- [ ] `sudo ./scripts/test_failure_paths.sh` verifies expected failures
- [ ] `sudo ./scripts/test_module.sh --load` succeeds with default parameters
- [ ] Inspect kernel journal for injected failure and successful cleanup messages
- [ ] Explain reverse-order teardown and ownership after failed initialization
- [ ] Commit Phase 5 source and documentation

## Phase 6 — Netfilter architecture and observe-only hook
**Status:** Source complete; no-root tests passed; Fedora runtime verification pending.

**Modified:** `kernel/netfw_hello.c`, `Makefile`, `README.md`, `progress.md`, three earlier source tests that assumed no hook existed.
**Added:** `tests/test_netfilter_hook_source.py`, `scripts/test_netfilter_observe.sh`.

**Concepts:** packet journey; PRE_ROUTING vs LOCAL_IN/FORWARD/LOCAL_OUT/POST_ROUTING; `nf_hook_ops`; `NF_ACCEPT`; initial network namespace; hook registration/unregistration and error unwinding.

**Acceptance checklist:**
- [ ] Review personal Phase 6 learning PDF (not committed)
- [ ] `make clean && make && make verify-build` on Fedora
- [ ] `make check` passes 26 tests
- [ ] `sudo ./scripts/test_failure_paths.sh` verifies injected failures
- [ ] `sudo ./scripts/test_netfilter_observe.sh` loads/unloads safely
- [ ] Explain why locally generated IPv4 does not enter PRE_ROUTING
- [ ] Commit Phase 6 changes

## Phase 7 — Safe sk_buff and IPv4 header inspection
**Status:** Source implemented; no-root tests passed; Fedora kernel compilation and runtime verification pending.

**Modified:** `kernel/netfw_hello.c`, `Makefile`, `README.md`, `progress.md`.
**Added:** `tests/test_ipv4_header_source.py`, `scripts/test_ipv4_observe.sh`.

**Concepts:** non-linear sk_buff; network-header offsets; `skb_header_pointer()`;
IPv4 version/IHL/total length; network byte order; `%pI4`; rate-limited logging;
fail-open observation with no per-packet memory allocation.

**Acceptance checklist:**
- [ ] Read personal Phase 7 learning PDF (not committed)
- [ ] `make clean && make && make verify-build` on Fedora
- [ ] `make check` passes all 33 source-level tests
- [ ] `sudo ./scripts/test_failure_paths.sh` continues to pass
- [ ] `sudo ./scripts/test_ipv4_observe.sh` load/unload succeeds
- [ ] Inspect journal for IPv4 header metadata when ingress traffic is seen
- [ ] Explain why skb data cannot always be directly cast to an IP header
- [ ] Commit Phase 7 files

## Phase 8 — Safe TCP and UDP port parsing
**Status:** Completed on Fedora: user confirmed successful build, 42/42 tests, both runtime scripts, and commit `7eb0c2d`.

**Modified:** `kernel/netfw_hello.c`, `Makefile`, `README.md`, `progress.md`.
**Added:** `tests/test_transport_header_source.py`, `scripts/test_transport_observe.sh`.

**Concepts:** layer-4 headers; TCP data offset; UDP datagram length; IPv4 fragments;
network-order ports; non-linear skb bounded reads; observe-only behavior.

**Acceptance checklist:**
- [ ] Review personal Phase 8 PDF (not included in Git)
- [ ] Fedora: `make clean && make && make verify-build`
- [ ] Run `make check` (expect 42 source tests)
  - Phase 8 fix: the fragment-offset test accepts `0x1FFF` or `IP_OFFSET`; Fedora compilation and runtime passed in the reported run.
- [ ] Run earlier failure injection script
- [ ] Run `sudo ./scripts/test_transport_observe.sh`
- [ ] Read kernel log for TCP/UDP ports (may require namespace ingress)
- [ ] Explain why later fragments have no ports
- [ ] Commit Phase 8 changes

## Up next
Phase 9: handle ICMP and malformed packets safely.


## Commit convention
Phase N planned calendar day is November N, 2026 (N <= 30), then December N-30. Each has a distinct selected after-21:00 IST metadata timestamp. These can be set explicitly with Git environment variables; they do not prove when work actually occurred.

Phase 1: `chore: initialize Fedora kernel development workspace`
Phase 2: `feat: add minimal Linux kernel module and lifecycle smoke tests`

Phase 3: `build: add Kbuild verification and kernel diagnostics` (2026-11-03 21:18 IST metadata target)

Phase 4: `feat: demonstrate safe kernel heap allocation and cleanup` (2026-11-04 21:36 IST metadata target)

Phase 5: `feat: add fault-injected module initialization rollback` (2026-11-05 21:52 IST metadata target)

Phase 6: `feat: register accept-only IPv4 Netfilter pre-routing hook` (2026-11-06 21:27 IST metadata target)

Phase 7: `feat: safely inspect IPv4 headers in Netfilter observer` (2026-11-07 21:44 IST metadata target)

Phase 8: `feat: inspect TCP and UDP ports in IPv4 observer` (2026-11-08 21:33 IST metadata target)


## Phase 9 — ICMP and malformed IPv4 safety
**Status:** Implemented. Local source-level checks passed; Fedora kernel compilation and runtime pending.

**Modified:** `kernel/netfw_hello.c`, `Makefile`, `README.md`, `progress.md`.
**Added:** `tests/test_icmp_safety_source.py`, `scripts/test_icmp_observe.sh`.

**Concepts:** ICMP type/code; safe `skb_header_pointer` access; IPv4 IHL/total-length checks; packet fragmentation; safe fail-open observer.

**Acceptance:**
- [ ] Read Phase 9 personal learning PDF (excluded from repository)
- [ ] `make clean && make && make verify-build` on Fedora
- [ ] `make check` (51 Python source tests)
- [ ] `sudo ./scripts/test_failure_paths.sh`
- [ ] `sudo ./scripts/test_icmp_observe.sh`
- [ ] Inspect ICMP type/code logs if packet traverses PRE_ROUTING
- [ ] Explain why a passing source test is not proof of kernel compilation
- [ ] Commit Phase 9

**Phase 9 commit:** `feat: observe ICMP metadata with bounded packet-header reads` (2026-11-09 21:49 IST metadata target).

**Next:** Phase 10 — safe ACCEPT/DROP verdict demonstration in a controlled namespace, without affecting host traffic.


## Phase 10 — Controlled Netfilter ACCEPT/DROP
**Status:** Implemented; source tests passed. Fedora build and namespace runtime require local verification.

**Modified:** `kernel/netfw_hello.c`, `Makefile`, `README.md`, `progress.md`, and five legacy assertion tests.
**Added:** `scripts/test_lab_drop.sh`, `tests/test_lab_drop_source.py`.

**Concepts:** `NF_ACCEPT` vs `NF_DROP`; default-deny vs opt-in lab mode; Netfilter PRE_ROUTING and ingress interface; exact IPv4 destination/UDP port check; IPv4 fragments; namespace/veth isolation; test negative and positive controls.

**Acceptance:**
- [ ] `make clean && make check-build` on Fedora
- [ ] `make check` (all previous plus Phase 10 tests)
- [ ] `sudo ./scripts/test_failure_paths.sh`
- [ ] `sudo ./scripts/test_lab_drop.sh` inside a disposable Fedora VM
- [ ] Verify UDP/54322 arrives and UDP/54321 is dropped
- [ ] Verify module unloaded and `nfwt10h` removed
- [ ] Read the private Phase 10 learning PDF
- [ ] Commit Phase 10, November 10, 2026 at 21:38 IST metadata timestamp

**Next:** Phase 11 — deterministic packet verdict tests and traffic policy regression.


## Phase 11 - deterministic verdict and teardown regression
**Status:** Verified by user on Fedora: 69/69 Python checks, successful kernel build, both packet verdict modes, clean teardown; commit `1e74075`.

**Phase 10 user results:** 60/60 tests, Fedora build, UDP/54322 ACCEPT, UDP/54321 DROP, and clean veth/namespace. Module remained loaded unexpectedly; Phase 11 addresses cleanup reliability. Phase 10 commit: `8e1048e`.

**Files:** modified `scripts/test_lab_drop.sh`, `Makefile`, `README.md`, `progress.md`; added `scripts/test_verdict_regression.sh`, `tests/test_verdict_regression_source.py`.

**Concepts:** Linux shell `pipefail` and `grep -q`/SIGPIPE, kernel module presence through sysfs, fail-closed test harness checks, positive/negative test controls, idempotent cleanup, opt-in rule regression.

**Acceptance:**
- [ ] `make clean && make check-build` on Fedora
- [ ] `sudo rmmod netfw_hello` if already loaded; verify absent
- [ ] `sudo ./scripts/test_failure_paths.sh`
- [ ] `sudo ./scripts/test_verdict_regression.sh` (both rule modes)
- [ ] Confirm no module (`lsmod`), no veth (`ip link show nfwt10h`), and no `nfwt10-*` namespace (`ip netns list`)
- [ ] Read Phase 11 private learning PDF
- [ ] Commit Phase 11 (planned Git metadata November 11, 2026, 21:46 IST)

**Next:** Phase 12 - C firewall rule data structure.


## Phase 12 — Firewall rule representation in C
**Status:** Implemented and source tests passed; Fedora Kbuild/runtime verification pending.

**Changes:** `kernel/netfw_rule.h` added; `kernel/netfw_hello.c` includes it and logs descriptor size; `tests/test_rule_structure_source.py` added; README updated.

**Concepts:** typed `struct` layouts, enums, per-field match flags, `__be32` network order, host-order ports, interface string bounds, separation of rule data from packet decisions.

**Safety:** No rule evaluation added; existing opt-in lab drop remains unchanged.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (expected 78 Python checks)
- [ ] `sudo ./scripts/test_failure_paths.sh`
- [ ] `sudo ./scripts/test_verdict_regression.sh` (both modes)
- [ ] Verify no module/interface/test namespace left
- [ ] Read personal PDF outside repository
- [ ] Commit Phase 12 with November 12, 2026 at 21:29 IST metadata

**Next:** Phase 13 — source IPv4 address matching.


## Phase 13 — Source IPv4 address matcher
**Status:** Implemented; local source tests passed. Fedora kernel build and live verdict regression pending.

**Changes:** Added `kernel/netfw_match.h` with a reusable inline source IP/mask matcher; integrated a harmless initialization-time compiler smoke example into `kernel/netfw_hello.c`; added `tests/test_source_ipv4_match.py`; updated README.

**Concepts:** CIDR prefix and mask; network byte order; match-flags versus zero-valued fields; wildcard semantics; side-effect-free inline helpers; matching independent from firewall verdict.

**Safety:** Current Netfilter verdicts unchanged. Phase 13 helper is not yet used for per-packet filtering.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (expected 87 tests)
- [ ] `sudo ./scripts/test_failure_paths.sh`
- [ ] `sudo ./scripts/test_verdict_regression.sh` (both lab modes)
- [ ] Verify no module, veth, or test namespace remains
- [ ] Review separate learning PDF (not tracked in repository)
- [ ] Commit Phase 13 with requested November 13, 2026, 21:42 IST metadata

**Next:** Phase 14 — destination IPv4 address and CIDR matching.


## Phase 14 — Destination IPv4 and CIDR matcher
**Status:** Implemented; local source-level tests and shell syntax passed. Fedora compilation and live regression pending.

**Changes:** Added `netfw_match_dst_ipv4()` to `kernel/netfw_match.h`; added an initialization-only compiler smoke call; added `tests/test_destination_ipv4_match.py`; updated README. No packet verdict changes.

**Concepts:** Destination subnet matching, CIDR prefixes, network byte order, field match flags and wildcard semantics, separation between matching and enforcement.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (expected 96 Python checks)
- [ ] `sudo ./scripts/test_failure_paths.sh`
- [ ] `sudo ./scripts/test_verdict_regression.sh` (ACCEPT and opt-in DROP)
- [ ] Verify module, interface and namespace absent after tests
- [ ] Review personal learning PDF outside repository
- [ ] Commit with November 14, 2026 at 21:37 IST Git metadata

**Next:** Phase 15 — TCP/UDP source and destination port matching.


## Phase 15 — TCP/UDP port matching
**Status:** Implemented; source-level checks passed locally. Fedora Kbuild and live regression pending.

**Changes:** Added `netfw_match_ports()` with optional source/destination port conditions, TCP/UDP protocol guard and byte-order conversion; added harmless module-init smoke exercise; created nine source tests; updated README.

**Concepts:** Host versus network byte order; source/destination ports; TCP/UDP-only semantics; wildcard flags; combined conditions; separation of matching from verdict enforcement.

**Safety:** The helper is not in the Netfilter packet callback. Existing opt-in UDP lab drop is unchanged.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (105 checks expected)
- [ ] `sudo ./scripts/test_failure_paths.sh`
- [ ] `sudo ./scripts/test_verdict_regression.sh` (ACCEPT and DROP modes)
- [ ] Confirm module unloaded, veth absent, test namespace removed
- [ ] Review separate personal PDF
- [ ] Commit with November 15, 2026 21:54 IST metadata

**Next:** Phase 16 — protocol matching and combined rule predicates.


## Phase 16 — Protocol and combined predicate
**Status:** Implemented; local source tests passed, Fedora build and runtime verification pending.

**Changes:** Added optional protocol matching and a conjunctive IPv4/source/destination/port predicate in `kernel/netfw_match.h`; an init-only positive/negative smoke check; nine new Python source tests; README guidance. No packet-hook policy change.

**Concepts:** Protocol wildcard flags, short-circuit AND evaluation, prevalidated packet fields, host/network byte order, and separation of match from action. Incoming interface matching and actual configurable rule evaluation are NOT included yet.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (114 tests expected)
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Verify `netfw_hello` unloaded, `nfwt10h` absent and no test namespace
- [ ] Review separate personal Phase 16 PDF (not committed)
- [ ] Commit Phase 16 using November 16, 2026, 21:32 IST metadata

**Next:** Phase 17 — ordered rule evaluation and default policy.

## Phase 17 - Ordered rule evaluation and default policy
**Status:** Implemented; local Python/source tests complete; Fedora build and
runtime regression pending.

**Changes:** Added `kernel/netfw_policy.h` with ordered, first-match rule
selection and configurable default; preserved safety for empty/null rules,
invalid actions and unsupported interface filters. Added init-only smoke
cases and nine Python tests. Live Netfilter behavior is unchanged.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (123 tests expected)
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh` (ACCEPT and DROP)
- [ ] Confirm `netfw_hello` unloaded, `nfwt10h` absent and no test namespace
- [ ] Study separate personal Phase 17 learning PDF (not committed)
- [ ] Commit November 17, 2026, 21:43 IST metadata

**Next:** Phase 18 - bounded rule storage and synchronization.

## Phase 18 - Bounded rule storage and synchronization
**Status:** Implemented; 132 source tests targeted; Fedora compilation and privileged tests pending.

**Changes:** Added `kernel/netfw_table.h`, a fixed 16-entry rule table with
`spin_lock_bh()` protecting ordered insertion, count, clearing and evaluation.
Rejects invalid rule actions, unknown match flags, bad protocol/port combinations,
and non-terminated interface names. Exceeding capacity returns `-ENOSPC`.
The module performs an init-only storage/evaluation check; the live Netfilter
hook still uses the isolated Phase 10 lab DROP only.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (132 Python tests expected)
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Verify module unloaded; interface and namespace removed
- [ ] Review personal Phase 18 learning PDF (not tracked)
- [ ] Commit with November 18, 2026, 21:51 IST metadata

**Next:** Phase 19 - stateful connection-tracking concepts.

## Phase 19 - Stateful vs stateless and 5-tuple flow identity
**Status:** Implemented; 141 source tests targeted; Fedora build/runtime checks pending.

**Changes:** Added `kernel/netfw_flow.h` with TCP/UDP 5-tuple identity,
forward-direction equality, and reverse-direction equality; init-only smoke
checks and nine Python tests. No per-packet tracking, mutable state,
timeouts, or altered hook verdicts in this phase.

**Concepts:** Stateless vs stateful decisions, bidirectional flow identity,
network byte order, why IP/ports/protocol together identify a flow, and why
ICMP needs different handling.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (141 Python tests expected)
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Verify module unloaded, lab interface absent, namespace removed
- [ ] Read personal Phase 19 learning PDF (not committed)
- [ ] Commit with November 19, 2026, 21:26 IST metadata

**Next:** Phase 20 - hashable 5-tuple keys and connection lookup.

## Phase 20 - Bounded connection hash table and flow lookup
**Status:** Implemented; 150 Python tests targeted; Fedora build and privileged runtime regression pending.

**Changes:** Added `kernel/netfw_conn.h` with 8 hash buckets and 4 fixed slots per bucket (maximum 32 flows). The symmetric bucket hash maps a flow and its reverse to the same bucket. Added duplicate rejection (`-EEXIST`), invalid key rejection (`-EINVAL`), bucket overflow (`-ENOSPC`), and short `spin_lock_bh()` critical sections. Lookup returns a bool and optional reverse-direction flag; never an unlocked entry pointer. Added init-only smoke checks and 9 tests.

**Scope:** Hash table is *not* connected to the packet hook. No timeout, state transitions, or stateful filtering yet. Lab ACCEPT/DROP behavior remains unchanged. Capacity is a theoretical maximum: a bucket may fill before the whole table does.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (150 tests expected)
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Verify module unloaded, `nfwt10h` absent and no namespace left
- [ ] Read personal Phase 20 learning PDF (not in repo)
- [ ] Commit with November 20, 2026, 21:47 IST metadata

**Next:** Phase 21 - forward/reverse flow recognition and state metadata.


## Phase 21 - Forward/reverse flow recognition and connection metadata
**Status:** Implemented; 159 Python tests targeted, Fedora compilation/runtime pending.

**Changes:** Added direction and conceptual state enums, stored NEW state in each hash-table entry, and a lock-protected copy-out `netfw_conn_lookup_info()` API. Preserved Phase 20 lookup signature and the isolated live ACCEPT/DROP lab. Added 9 source tests and initialization-only verification for original/reply direction. Reverse traffic does not advance state.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (159 tests expected)
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Confirm module unloaded, veth removed, and namespace gone
- [ ] Read separate Phase 21 personal learning PDF (not committed)
- [ ] Commit with November 21, 2026, 21:34 IST metadata

**Next:** Phase 22 - simplified TCP connection state transitions.


## Phase 22 — Simplified TCP state transitions
**Status:** Implemented; 168 Python tests targeted; Fedora compilation and privileged regression pending.

**Changes:** Extend connection metadata with ESTABLISHED/CLOSING and `syn_seen`. Add locked `netfw_conn_tcp_step()` to recognize original SYN, reply SYN+ACK, original ACK and FIN/RST; return safe snapshots and reject non-TCP flow keys. Preserve original Phase 21 lookup API and real lab verdicts. Add 9 source tests and init-only positive/negative smoke checks.

**Limitations:** Not complete RFC TCP state tracking. No sequence validation, retransmission model, timeout, or live Netfilter connection-state enforcement.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (168 tests expected)
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Verify module unloaded and temporary veth/namespace removed
- [ ] Read separate personal learning PDF (not committed)
- [ ] Commit with November 22, 2026, 21:57 IST metadata

**Next:** Phase 23 — UDP pseudo-state and timeouts.


## Phase 23 — UDP pseudo-state and inactivity timeouts
**Status:** Implemented; 177 source tests targeted. Fedora build/runtime pending.

**Changes:** A UDP flow stays NEW on original-direction traffic and becomes REPLIED after a reverse packet. Track last activity in jiffies, use 30s (unreplied UDP), 120s (replied UDP), and 300s (simplified TCP) inactivity windows. Add explicit bounded expiry scanning without timers or allocations. Run deterministic init-only smoke tests. Fix nested Bash test execution regardless of ZIP executable permissions. The live Netfilter policy remains unchanged.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (177 tests expected)
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Verify module unloaded and temporary interfaces/namespaces removed
- [ ] Read personal Phase 23 PDF (not committed)
- [ ] Commit using November 23, 2026, 21:39 IST metadata

**Next:** Phase 24 — Connection synchronization, expiration and cleanup integration.


## Phase 24 — synchronized connection expiration and cleanup
**Status:** Implemented; 186 Python tests expected. Fedora compilation/runtime pending.

**Changes:** Add lock-protected connection count snapshots, explicit removal
by original/reverse key, and idempotent table clearing. Preserve Phase 23
expiration scanning and original live ACCEPT/DROP lab. Add init-only positive
and negative removal checks, and 9 source tests. No live tracking yet.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (186 tests expected)
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Verify module unloaded, `nfwt10h` absent, no namespace remaining
- [ ] Read Phase 24 personal PDF (exclude from repository)
- [ ] Commit using November 24, 2026 at 21:48 IST metadata

**Next:** Phase 25 — Netlink socket fundamentals and message protocol.


## Phase 25 — Netlink fundamentals and versioned message protocol
**Status:** Implemented; 195 Python tests targeted; Fedora build/runtime pending.

**Changes:** Define a small network-order 8-byte kernel/userspace payload
contract with version, command, reserved, request ID and strict validation.
Add Python encode/decode codec and nine tests. No socket opened and no packet
policy changed. Prior Phase 24 Fedora run: 186 tests, build, failure paths,
verdict regression and teardown passed; commit `eeab856`.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (195 tests expected)
- [ ] `python3 -m unittest discover -s tests -p 'test_netlink_protocol.py' -v`
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Verify module unloaded, veth absent and namespace absent
- [ ] Keep Phase 25 Learning PDF outside Git
- [ ] Commit November 25, 2026, 21:36 IST

**Next:** Phase 26 — kernel-side Netlink socket registration and safe handler.


## Phase 26 — Kernel Netlink socket and safe read-only handler
**Status:** Implemented, 204 Python tests targeted; Fedora build and runtime pending.

**Changes:** Register an initial-netns `NETLINK_USERSOCK` listener, safely
validate versioned PING/STATUS requests, echo nonmutating acknowledgments,
release socket on unload and unwind the hook if socket setup fails. Add a
minimal userspace transport client and nine tests. This does not expose live
rule editing or change any existing Netfilter verdict.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (204 tests expected)
- [ ] `make verify-build`
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Manual `sudo insmod kernel/netfw_hello.ko`, Python PING/STATUS, `sudo rmmod netfw_hello`
- [ ] Check module unloaded, `nfwt10h` absent, namespace list empty
- [ ] Read separate Phase 26 learning PDF (not committed)
- [ ] Commit with November 26, 2026, 21:44 IST metadata

**Next:** Phase 27 — Netlink request/response error reporting and CLI integration.


## Phase 27 — Netlink error replies and CLI
**Status:** Implemented; 213 source tests targeted; Fedora kernel build and
privileged live Netlink/regression tests pending.

**Changes:** Add 12-byte reply with signed errno, specific protocol validation
errors and CLI `ping` / `status` / `--request-id` with failure exit codes.
Malformed outer Netlink envelopes remain ignored. Read-only operations only.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (213 Python tests expected)
- [ ] `make verify-build`
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] `sudo insmod kernel/netfw_hello.ko` and Python ping/status
- [ ] `sudo rmmod netfw_hello`; verify no module/veth/netns leftover
- [ ] Commit November 27, 2026, 21:42 IST (planned Git metadata)

**Next:** Phase 28 — Python CLI subcommands and read-only diagnostics.


## Phase 28 — Python CLI subcommands and read-only diagnostics
**Status:** Implemented; 222 Python tests targeted; Fedora kernel/runtime pending.

- `diagnose` reads procfs/sysfs without a socket or elevated privileges.
- `--json` supports automation for `diagnose`, `ping`, and `status`.
- Missing procfs gracefully reports an error; Netlink requests still report nonzero failures.
- No kernel changes and no policy changes; STATUS provides endpoint reachability only.

**Fedora acceptance:**
- [ ] `make clean && make check-build` (222 tests expected)
- [ ] `make verify-build`
- [ ] `python3 userspace/netfw_client.py diagnose --json` without sudo
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] With module loaded, run CLI `ping --json` and `status --json`, then unload
- [ ] Confirm no leftover module, veth or namespace
- [ ] Commit with November 28, 2026, 21:53 IST metadata

**Next:** Phase 29 — validated read-only rule-table snapshots (design milestone).


## Phase 28 — Fedora validation reported by user
- [x] All 222 Python tests passed; module build and `verify-build` successful on Fedora kernel 7.2.9-201.fc44.x86_64
- [x] Read-only local diagnostics, PING and STATUS JSON verified
- [x] Failure-path and ACCEPT/DROP regressions passed; module and lab resources cleaned
- [x] Commit `96fc63b`; 28 commits confirmed

## Phase 29 — bounded rule snapshots and offline inspector
**Status:** Implemented; 231 Python tests targeted, Fedora build/runtime pending.

- A new lock-protected, caller-owned snapshot captures all ordered rules, count and default policy consistently.
- Initialization-only self-check covers snapshot contents and frees buffers on all paths.
- Offline JSON schema and CLI `rules --file` (including `--json`), with tight validation and no kernel requests.
- This is NOT a live rule-table API. No rule mutations or live filtering changes.

**Fedora acceptance:**
- [ ] `make clean && make check-build && make verify-build` (231 tests)
- [ ] `python3 userspace/netfw_client.py rules --file examples/rules_snapshot.json --json`
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Manual Netlink PING/STATUS then unload; confirm no remaining resources
- [ ] Commit November 29, 2026, 21:46 IST (planned metadata)

**Next:** Phase 30 — bounded read-only Netlink rule snapshot transport.

## Phase 30 — bounded live rule snapshot over Netlink
**Status:** Implemented; 240 Python tests and Bash syntax passed locally. Fedora kernel build, privileged regression and live Netlink exchange pending.

- Version-1 read-only `RULES` command 3; no rule mutations or new verdicts.
- Kernel copies a bounded snapshot under table lock, then encodes a 16-byte header plus 0–16 wire rule descriptors outside the lock.
- Live export table has zero rules and default ACCEPT; it is intentionally distinct from the existing `lab_drop` condition and offline sample.
- Python validates exact wire lengths, limit, flags, reserved fields and replies, and labels the source `kernel-netlink`.
- `rules --file` remains a distinct offline-only path.
- Phase 29 source test updated: runtime read-only snapshot is now permitted, while the packet hook still may not evaluate the rule table.

**Fedora acceptance:**
- [ ] `make clean && make check-build && make verify-build` (240 tests)
- [ ] `sudo bash scripts/test_failure_paths.sh` and `sudo bash scripts/test_verdict_regression.sh`
- [ ] Load module; `python3 userspace/netfw_client.py rules --json` returns zero rules, default ACCEPT, source kernel-netlink
- [ ] Compare `rules --file examples/rules_snapshot.json --json` (offline sample)
- [ ] Verify PING/STATUS and unload with no remaining module or lab interface/network namespace
- [ ] Commit with November 30, 2026, 21:52 IST planned metadata

**Next:** Phase 31 — controlled rule-management protocol design, validation and permissions.


## Phase 30 — Fedora validation reported by user
- [x] Fedora 44 kernel 7.2.9-201.fc44.x86_64: `make check-build` and `make verify-build` successful.
- [x] All 240 Python tests and Bash checks passed.
- [x] Both expected fault-injection failures and opt-in ACCEPT/DROP regression passed.
- [x] Live Netlink RULES returned zero entries and default ACCEPT; PING and STATUS worked.
- [x] Module, lab interface and network namespace cleanup verified.
- [x] Git commit `121bed8`, 30 commits confirmed.

## Phase 31 — Staged bounded rule replacement and authorization contract
**Status:** Implemented; local tests complete, Fedora kernel and privileged tests pending.

- Validates complete replacement candidate (0–16 rules) and default policy.
- Rejects missing caller authorization with `-EPERM` and bad rules with `-EINVAL`.
- Atomically publishes all rules, count and default policy under `spin_lock_bh`.
- Rejects interface predicates until packet matching supports them.
- Initialization-only smoke covers unauthorized, invalid, successful and clear operations.
- No Netlink rule writes and no active rule enforcement.

**Fedora checklist:**
- [ ] `make clean && make check-build && make verify-build` (249 tests expected)
- [ ] `sudo bash scripts/test_failure_paths.sh`
- [ ] `sudo bash scripts/test_verdict_regression.sh`
- [ ] Live RULES remains empty/ACCEPT, PING and STATUS unchanged
- [ ] Unload and confirm no module, interface or network namespace remains
- [ ] Git commit with November 1, 2026 + 30 days = December 1, 2026, 21:38 IST planned metadata

**Next:** Phase 32 — sender-authenticated Netlink rule updates in an isolated lab.
