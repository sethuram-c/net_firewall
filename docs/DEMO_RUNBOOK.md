# NETFW final demonstration runbook (Phase 35)

**Target:** disposable Fedora 44 VM, matching kernel headers (previously verified on `7.2.9-201.fc44.x86_64`). Work in the repository root. **Never run the packet tests on a production host.** The lab uses an isolated veth and namespace, but a kernel module still executes in the host kernel.

## A. Preflight, build and local audit

```bash
uname -r
bash scripts/check_env.sh
python3 scripts/final_audit.py --json
make clean
make check-build
make verify-build
python3 scripts/final_audit.py --json --require-module
```

The audit executes `make check` (not root-required) and checks expected files. It **does not** verify privileged tests or claim a build has succeeded. `--require-module` insists that a build artifact exists; it does not load the module.

## B. Fault injection and legacy behavior

```bash
sudo bash scripts/test_failure_paths.sh
sudo bash scripts/test_verdict_regression.sh
```

Expected: two deliberately failed `insmod` operations with `Cannot allocate memory`, followed by PASS reports; legacy lab default ACCEPT and opt-in UDP/54321 DROP. `insmod` failure is expected in the fault-injection tests only.

## C. Authenticated staging and isolated enforcement

```bash
sudo bash scripts/test_staged_lab_rules.sh
sudo bash scripts/test_lab_hardening.sh
```

These scripts must start with the module and lab interface absent. They manage their own temporary namespace, veth and module lifecycle. The Phase 34 script verifies opt-out, opt-in, reload, invalid replacement and clear. If either fails, inspect `sudo journalctl -k -b --no-pager | grep netfw_hello` and cleanup checks, and do not publish a PASS claim.

## D. Netlink demonstration (separate from lab tests)

```bash
sudo insmod kernel/netfw_hello.ko
python3 userspace/netfw_client.py diagnose --json
python3 userspace/netfw_client.py ping --json
python3 userspace/netfw_client.py status --json
python3 userspace/netfw_client.py rules --json
python3 userspace/netfw_client.py apply --file examples/rules_snapshot.json --json  # expect EPERM
sudo python3 userspace/netfw_client.py apply --file examples/rules_snapshot.json --json
python3 userspace/netfw_client.py rules --json
sudo rmmod netfw_hello
```

The `apply` command without sudo should fail unless this user already has `CAP_NET_ADMIN`. The privileged write updates the staging table. **With `lab_rules=0` (default), staged DROP rules do not affect live packet verdicts.** The sample contains illustrative rules; read-only RULES is a snapshot, not evidence of packet matching.

## E. Teardown and evidence

```bash
lsmod | grep '^netfw_hello' || echo 'Module unloaded'
ip link show nfwt10h
sudo ip netns list
git status --short
git rev-list --count HEAD
```

Expected: module absent, interface absent, test namespace absent. Save the terminal output showing test summaries, commit hash and any honest limitations. Do not include `*.ko`, build objects, logs or PDF study guide in the repository commit.
