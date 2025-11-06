# Demo runbook

These commands were written for a disposable Fedora VM. Check `uname -r` against the installed kernel development headers before building. The tests insert a kernel module and create a network namespace; don't run them on a host you depend on remotely.

## 1. Build and inspect

```bash
uname -r
bash scripts/check_env.sh
make clean
make check-build
make verify-build
python3 scripts/final_audit.py --json --require-module
```

The audit is read-only and covers project layout and source checks. A passing audit is not evidence that packets have been filtered.

## 2. Run isolated regressions

```bash
sudo bash scripts/test_failure_paths.sh
sudo bash scripts/test_verdict_regression.sh
sudo bash scripts/test_staged_lab_rules.sh
sudo bash scripts/test_lab_hardening.sh
```

The first script deliberately makes `insmod` fail twice. The other scripts create their own lab veth/network namespace and check delivery for allowed and dropped UDP packets. Do not preload the module before running them. If one fails, inspect the kernel journal and verify cleanup before trying again.

## 3. Try Netlink without enforcement

```bash
sudo insmod kernel/netfw_hello.ko
python3 userspace/netfw_client.py diagnose --json
python3 userspace/netfw_client.py ping --json
python3 userspace/netfw_client.py status --json
python3 userspace/netfw_client.py rules --json
python3 userspace/netfw_client.py apply --file examples/rules_snapshot.json --json
sudo python3 userspace/netfw_client.py apply --file examples/rules_snapshot.json --json
python3 userspace/netfw_client.py rules --json
sudo rmmod netfw_hello
```

The first `apply` normally fails with `EPERM`; the privileged request should succeed. A subsequent `rules` query shows the staged values. They are not enforced because this loading sequence leaves `lab_rules` disabled. If your unprivileged user already has `CAP_NET_ADMIN`, the negative authorization example is not a valid test.

## 4. Check teardown

```bash
lsmod | grep '^netfw_hello' || echo 'Module unloaded'
ip link show nfwt10h   # expected: device not found
sudo ip netns list     # no leftover test namespace
```

For troubleshooting, run `sudo journalctl -k -b --no-pager | grep netfw_hello`. If a test has left a module or interface behind, inspect what it owns rather than deleting unrelated networking resources.

The demo is successful only when the Fedora build, the applicable isolated tests and cleanup all succeed. Keep actual console output alongside the release, not fabricated sample results.
