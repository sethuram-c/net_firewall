#!/usr/bin/env bash
# Intentionally explicit and interactive: don't accidentally load into your host.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
name=netfw_hello
module=kernel/netfw_hello.ko

if [[ "${1:-}" != "--load" ]]; then
  printf 'Usage: sudo ./scripts/test_module.sh --load\n'
  printf 'Build first: make; preferably use a disposable Fedora VM.\n'
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo 'Run with sudo to insert a kernel module.' >&2
  exit 1
fi
if [[ ! -f "$module" ]]; then
  echo "Not built: $module (run make first)" >&2
  exit 1
fi
if lsmod | awk '{print $1}' | grep -qx "$name"; then
  echo "$name is already loaded; refusing to modify it" >&2
  exit 1
fi
loaded=0
cleanup() {
  if (( loaded )); then
    rmmod "$name" || echo 'WARNING: rmmod failed; check lsmod manually' >&2
  fi
}
trap cleanup EXIT
insmod "$module"
loaded=1
lsmod | awk -v n="$name" 'NR == 1 || $1 == n'
modinfo "$module" | head -n 12
rmmod "$name"
loaded=0
printf '\nModule lifecycle succeeded. Inspect recent logs with:\n'
printf 'sudo journalctl -k -b --no-pager | grep netfw_hello\n'
