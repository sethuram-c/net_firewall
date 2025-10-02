# NETFW — Linux Stateful Firewall (learning project)

**Phase 2 / 35** — minimal C loadable kernel module. **No packet filtering is implemented yet.**

Fedora Linux; C in kernel, Python for future CLI/tests, Bash for automation.

## Fedora prerequisites

```bash
sudo dnf install gcc make git python3 bash mokutil "kernel-devel-$(uname -r)"
./scripts/check_env.sh
```

If the installed `kernel-devel` does not match `uname -r`, update/reboot into a supported kernel before building. Run experiments in a disposable VM where possible. Secure Boot may require enrolling a module-signing key; do not disable protections just for this exercise.

## Phase 2 workflow

```bash
make                # creates kernel/netfw_hello.ko using running kernel's Kbuild
make check          # Bash syntax + Python static checks (no root required)
modinfo kernel/netfw_hello.ko
sudo ./scripts/test_module.sh --load   # privileged load/unload; recommend a VM
sudo journalctl -k -b --no-pager | grep netfw_hello
make clean
```

Manual equivalent of the lifecycle test:

```bash
sudo insmod kernel/netfw_hello.ko
lsmod | grep '^netfw_hello'
sudo rmmod netfw_hello
sudo journalctl -k -b --no-pager | grep netfw_hello
```

**Security:** Loadable modules execute in kernel space. Broken code can crash the OS. Never run arbitrary module binaries. The included module logs only on load/unload, has no Netfilter hook, and doesn't inspect traffic.

## Layout

- `kernel/netfw_hello.c`: first kernel module
- `Makefile`: Kbuild entry point and validation targets
- `scripts/check_env.sh`: prerequisites
- `scripts/test_module.sh`: guarded privileged lifecycle smoke test
- `tests/test_module_source.py`: simple no-root static checks
- `progress.md`: learning and acceptance tracking

Personal learning PDFs are distributed separately, not committed to the repository.
