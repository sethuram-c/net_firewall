# NETFW progress tracker

**Plan:** 35 phases, approximately 1-1.5 focused hours each. Fedora + C (kernel) + Python (CLI/tests) + Bash (automation).

## Phase 1 - Linux kernel architecture and Fedora setup

**Status:** Files delivered; local Fedora verification pending (not run by the author on your machine).

**Learning goals:** kernel space vs user space, system calls, modules, kernel versions, external-module development prerequisites, privilege boundaries, Secure Boot.

**Files added:** `README.md`, `progress.md`, `.gitignore`, `scripts/check_env.sh`.

**Acceptance checklist:**
- [ ] Read Phase 1 personal learning PDF (outside repository)
- [ ] Install Fedora build prerequisites
- [ ] Run `uname -r` and explain what the version means
- [ ] Run `./scripts/check_env.sh` with zero failures
- [ ] Confirm `/lib/modules/$(uname -r)/build/Makefile` exists
- [ ] Inspect `lsmod` and `journalctl -k` output (do not change kernel state)
- [ ] Commit Phase 1 on or after 2026-11-01 using a truthful timestamp

**What is not implemented:** C module, packet hooks, rule engine, Netlink, tests. These are scheduled for later phases.

## Upcoming phases

- **2:** Hello-world loadable kernel module in C
- **3:** Kbuild, insmod/rmmod and kernel log inspection
- **4:** Kernel memory and defensive error handling
- **5:** Module lifetime and safe cleanup
- **6-35:** Netfilter, packet inspection, rules, conntrack, Netlink, testing and resume polish

## Commit plan

Phase 1 suggested commit message: `chore: initialize Fedora kernel development workspace`

Commit day mapping: Phase N -> 2026-11-(N) for N <= 30; subsequent phases continue into December (Phase 31 -> 2026-12-01). Use a different late-evening IST time after 21:00 for each phase **when the commit genuinely occurs**. Do not backdate or future-date actual work to fabricate a contribution timeline.
