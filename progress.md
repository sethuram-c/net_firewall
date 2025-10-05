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

## Up next
Phase 6: Netfilter architecture and hook concepts (packet inspection starts after that).

## Commit convention
Phase N planned calendar day is November N, 2026 (N <= 30), then December N-30. Each has a distinct selected after-21:00 IST metadata timestamp. These can be set explicitly with Git environment variables; they do not prove when work actually occurred.

Phase 1: `chore: initialize Fedora kernel development workspace`
Phase 2: `feat: add minimal Linux kernel module and lifecycle smoke tests`

Phase 3: `build: add Kbuild verification and kernel diagnostics` (2026-11-03 21:18 IST metadata target)

Phase 4: `feat: demonstrate safe kernel heap allocation and cleanup` (2026-11-04 21:36 IST metadata target)

Phase 5: `feat: add fault-injected module initialization rollback` (2026-11-05 21:52 IST metadata target)
