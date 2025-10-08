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
