#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if (( EUID != 0 )); then echo "Run as root: sudo ./scripts/test_ipv4_observe.sh" >&2; exit 1; fi
if [[ ! -f kernel/netfw_hello.ko ]]; then echo "Build first with make" >&2; exit 1; fi
if lsmod | grep -q '^netfw_hello '; then echo "Module already loaded, unload before testing" >&2; exit 1; fi
cleanup() { if lsmod | grep -q '^netfw_hello '; then rmmod netfw_hello; fi; }
trap cleanup EXIT
insmod kernel/netfw_hello.ko
# Loopback ping is a convenience probe. PRE_ROUTING observability varies by path.
if command -v ping >/dev/null; then ping -4 -c 1 -W 2 127.0.0.1 || true; fi
rmmod netfw_hello
trap - EXIT
if lsmod | grep -q '^netfw_hello '; then echo "Module still loaded" >&2; exit 1; fi
echo "Phase 7 module lifecycle passed. Check: journalctl -k -b | grep netfw_hello"
echo "Note: a loopback ping may not produce PRE_ROUTING observations; use separate namespace ingress if needed."
