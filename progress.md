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
