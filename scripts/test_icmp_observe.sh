#!/usr/bin/env bash
# Phase 9: expect safe ICMP observer lifecycle; ICMP logs depend on ingress route.
set -euo pipefail
cd "$(dirname "$0")/.."
module=kernel/netfw_hello.ko
[[ -f "$module" ]] || { echo 'Build first: make' >&2; exit 1; }
if lsmod | grep -q '^netfw_hello '; then
  echo 'netfw_hello already loaded; unload before running' >&2; exit 1
fi
cleanup() {
  if lsmod | grep -q '^netfw_hello '; then rmmod netfw_hello; fi
}
trap cleanup EXIT
insmod "$module"
ping -c 1 -W 2 127.0.0.1
cleanup
trap - EXIT
! lsmod | grep -q '^netfw_hello '
echo 'PASS: Phase 9 ICMP observer loaded and unloaded safely'
echo "Inspect: journalctl -k -b --no-pager | grep 'netfw_hello: ICMP'"
echo 'Note: localhost ping may or may not traverse PRE_ROUTING on your setup.'
