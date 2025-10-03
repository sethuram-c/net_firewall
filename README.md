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
