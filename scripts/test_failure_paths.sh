#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mod=kernel/netfw_hello.ko
[[ $EUID -eq 0 ]] || { echo 'Run with sudo (after make)' >&2; exit 1; }
[[ -f "$mod" ]] || { echo 'Build first: make' >&2; exit 1; }
if lsmod | awk 'NR > 1 {print $1}' | grep -qx netfw_hello; then
  echo 'ERROR: netfw_hello already loaded; unload first' >&2
  exit 1
fi
for scenario in 1 2; do
  echo "Testing expected init failure: fail_step=$scenario"
  if insmod "$mod" "fail_step=$scenario"; then
    echo 'ERROR: module unexpectedly loaded' >&2
    rmmod netfw_hello || true
    exit 1
  fi
  if lsmod | awk 'NR > 1 {print $1}' | grep -qx netfw_hello; then
    echo 'ERROR: module remains loaded after failed init' >&2
    exit 1
  fi
  echo "PASS: failed insertion $scenario left no loaded module"
done
echo 'Inspect messages: sudo journalctl -k -b --no-pager | grep netfw_hello'
