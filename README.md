# NETFW - Linux Stateful Firewall

A learning-first, resume-oriented Linux IPv4 stateful firewall project.

**Target:** Fedora Linux. **Stack:** C kernel module, Python CLI/tests, Bash automation.

## Status

Phase 1 of 35 - development environment and kernel architecture. **No kernel module or firewall functionality yet.** See [progress.md](progress.md).

## Fedora setup

```bash
sudo dnf install gcc make git python3 bash mokutil "kernel-devel-$(uname -r)"
./scripts/check_env.sh
```

If `kernel-devel-$(uname -r)` is unavailable, the repositories may no longer carry your running kernel's version. Update your system, reboot into the newly installed kernel, and then install its matching `kernel-devel`. Do not assume generic `kernel-headers` is a substitute for the matching `kernel-devel` package.

Secure Boot may prevent loading unsigned local modules later. Prefer module signing with a trusted key or a disposable development VM; don't turn off host security simply to follow this guide.

## Planned structure

- `kernel/` - C Netfilter module (starts Phase 2)
- `userspace/` - Python control CLI (later phases)
- `tests/` - integration tests (later phases)
- `scripts/` - environment and test automation
- `progress.md` - phase progress and acceptance criteria

The separate personal learning PDFs are distributed outside this repository.
