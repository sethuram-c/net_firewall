#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if (( EUID != 0 )); then echo "Run: sudo ./scripts/test_transport_observe.sh" >&2; exit 1; fi
if [[ ! -f kernel/netfw_hello.ko ]]; then echo "Build with make first" >&2; exit 1; fi
if lsmod | grep -q '^netfw_hello '; then echo "Module already loaded" >&2; exit 1; fi
cleanup() { if lsmod | grep -q '^netfw_hello '; then rmmod netfw_hello; fi; }
trap cleanup EXIT
insmod kernel/netfw_hello.ko
# Loopback is suitable for basic smoke-testing on the observed Fedora machine.
# These probes may not produce PRE_ROUTING records on every configuration.
if command -v python3 >/dev/null; then
python3 - <<'PYNET'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.sendto(b'netfw-phase8', ('127.0.0.1', 39081))
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.settimeout(1)
        s.connect(('127.0.0.1', 39082))
    except (ConnectionRefusedError, TimeoutError, OSError):
        pass  # A TCP SYN without a listener is enough for the smoke probe.
PYNET
fi
rmmod netfw_hello
trap - EXIT
if lsmod | grep -q '^netfw_hello '; then echo "FAIL: module still loaded" >&2; exit 1; fi
echo "PASS: Phase 8 transport observer loaded/unloaded safely"
echo "Inspect: sudo journalctl -k -b --no-pager | grep 'netfw_hello: TCP\|netfw_hello: UDP'"
echo "No transport log? Generate ingress from a separate network namespace."
