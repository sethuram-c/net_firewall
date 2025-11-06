# NETFW

An out-of-tree IPv4 firewall module for Linux, with a small Python command-line client. I built it to work through Netfilter packet handling, kernel synchronization, and the problems involved in sending configuration data across a Netlink socket.

The useful part is the end-to-end lab: load the module, stage rules from Python, send UDP packets through a network namespace, and check which packets make it through. This is **not** a general-purpose stateful firewall. The connection tracker is implemented as a separate exercise and does not feed decisions back into the Netfilter hook.

## What works

- IPv4 `PRE_ROUTING` hook with bounded IPv4/TCP/UDP/ICMP header reads (`skb_header_pointer`).
- Ordered rules matching IPv4 source/destination, protocol and TCP/UDP ports; a 16-entry table guarded by `spin_lock_bh()`.
- A Netlink endpoint (`NETLINK_USERSOCK`) for `ping`, `status`, reading rule snapshots, and replacing staged rules. The write path checks `CAP_NET_ADMIN` and validates the complete replacement before publishing it.
- Opt-in rule evaluation for **unfragmented UDP only**, arriving on `nfwt10h` and addressed to `198.18.0.2`. `lab_rules` defaults to off. The older `lab_drop` experiment is separate.
- A bounded 5-tuple connection table with reverse-flow lookup, basic TCP handshake states, UDP reply state, and explicit expiration/cleanup. This table is exercised during initialization, **not on live packets**.
- Python checks and disposable veth/network-namespace tests for rule updates, packet verdicts, failure paths, and teardown.

## Build

I used Fedora 44 with matching `kernel-devel` for the running kernel. You need `gcc`, `make`, `python3`, `iproute`, and the kernel development tree. Run privileged tests only in a disposable VM: these load code into the host kernel.

```bash
bash scripts/check_env.sh
make clean
make check-build
make verify-build
python3 scripts/final_audit.py --json
```

`make check` runs the Python/source checks and Bash syntax validation without loading the module. `make check-build` also invokes Kbuild. Neither replaces packet-level testing.

## Try the CLI

From the repository root, after building:

```bash
sudo insmod kernel/netfw_hello.ko
python3 userspace/netfw_client.py diagnose --json
python3 userspace/netfw_client.py ping --json
python3 userspace/netfw_client.py status --json
python3 userspace/netfw_client.py rules --json
sudo python3 userspace/netfw_client.py apply --file examples/rules_snapshot.json --json
python3 userspace/netfw_client.py rules --json
sudo rmmod netfw_hello
```

An unprivileged `apply` should be denied unless the caller already has `CAP_NET_ADMIN`. By default, updating staged rules **does not** cause them to filter packets; you must explicitly load with `lab_rules=1` for the isolated UDP test path.

For the actual packet tests, let the scripts create and clean up their own interfaces and namespaces:

```bash
sudo bash scripts/test_failure_paths.sh
sudo bash scripts/test_verdict_regression.sh
sudo bash scripts/test_staged_lab_rules.sh
sudo bash scripts/test_lab_hardening.sh
```

The expected deliberately failed `insmod` calls in the failure-path test are part of the test, not unexpected build failures.

## Where things live

| Path | Purpose |
| --- | --- |
| `kernel/netfw_hello.c` | Module lifecycle, Netfilter hook and Netlink receiver |
| `kernel/netfw_rule.h`, `netfw_match.h`, `netfw_policy.h` | Rule format, predicates and first-match evaluation |
| `kernel/netfw_table.h`, `netfw_manage.h`, `netfw_snapshot.h` | Bounded rule storage, atomic replacement and snapshots |
| `kernel/netfw_flow.h`, `netfw_conn.h` | Educational flow tracking and timeouts |
| `kernel/netfw_netlink.h` | Shared wire format |
| `userspace/` | Python Netlink codec, CLI and offline rule validation |
| `scripts/` | Fedora checks and disposable-network regression tests |
| `tests/` | Python contract and regression tests |
| `docs/` | Architecture notes, demo commands, release checks |
| `progress.md` | Original phase-by-phase development notes |

## Known gaps

Live flow-state enforcement is not implemented. Fragmented packets bypass the staged policy; malformed packets generally fail open. The lab hook does not protect other interfaces or destinations. The endpoint uses the shared `NETLINK_USERSOCK` protocol number, and `status` confirms reachability rather than reporting packet counters. This code is for learning and controlled demonstrations, not for protecting a production host.

See [architecture notes](docs/ARCHITECTURE.md), the [demo runbook](docs/DEMO_RUNBOOK.md), and the [release checklist](docs/RELEASE_CHECKLIST.md) for the exact boundaries and test procedure.
