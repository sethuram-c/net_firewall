#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
MODULE=kernel/netfw_hello.ko
if [[ $EUID -ne 0 ]]; then echo "Run with sudo" >&2; exit 1; fi
if [[ ! -f $MODULE ]]; then echo "Build first: make" >&2; exit 1; fi
if lsmod | grep -q '^netfw_hello '; then echo "Module already loaded; unload before running" >&2; exit 1; fi
cleanup() { if lsmod | grep -q '^netfw_hello '; then rmmod netfw_hello; fi; }
trap cleanup EXIT
insmod "$MODULE"
lsmod | grep '^netfw_hello '
# Local outgoing loopback traffic may not traverse PRE_ROUTING; use incoming IPv4 traffic for that hook.
# This smoke test establishes registration + clean teardown; no packet counters are implemented yet.
echo 'IPv4 PRE_ROUTING observation hook registered. All packets accepted.'
rmmod netfw_hello
trap - EXIT
! lsmod | grep -q '^netfw_hello '
echo 'Hook unloaded successfully.'
