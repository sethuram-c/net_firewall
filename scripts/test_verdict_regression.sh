#!/usr/bin/env bash
# Phase 11: test both module configurations and assert teardown.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID -eq 0 ]] || { echo "Run with sudo" >&2; exit 1; }
[[ ! -d /sys/module/netfw_hello ]] || { echo "Unload existing netfw_hello first" >&2; exit 1; }
check_clean() {
  if [[ -d /sys/module/netfw_hello ]] || ip link show nfwt10h >/dev/null 2>&1 ||
     ip netns list | grep -qE '^nfwt10-[0-9]+([[:space:]]|$)'; then
    echo "FAIL: leaked module, veth, or namespace" >&2
    exit 1
  fi
}
check_clean
LAB_DROP_MODE=0 ./scripts/test_lab_drop.sh
check_clean
LAB_DROP_MODE=1 ./scripts/test_lab_drop.sh
check_clean
printf 'PASS: Phase 11 default ACCEPT, opt-in DROP, and teardown regression\n'
