#!/usr/bin/env bash
# Phase 33: opt-in, isolated veth + netns test. Run in disposable Fedora VM.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ ${EUID} -eq 0 ]] || { echo "Run with sudo" >&2; exit 1; }
for cmd in ip python3 insmod rmmod; do command -v "$cmd" >/dev/null || exit 1; done
[[ -f kernel/netfw_hello.ko ]] || { echo 'Build module first' >&2; exit 1; }
NS="nfwt33-$$"; HOST_IF=nfwt10h; PEER_IF=nfwt10n
if [[ -d /sys/module/netfw_hello ]] || ip link show "$HOST_IF" >/dev/null 2>&1; then
  echo 'Refusing: module or lab interface already exists' >&2; exit 1
fi
cleanup() {
  if [[ -d /sys/module/netfw_hello ]]; then rmmod netfw_hello || true; fi
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$HOST_IF" 2>/dev/null || true
}
trap cleanup EXIT
ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name "$PEER_IF"
ip link set "$PEER_IF" netns "$NS"
ip addr add 198.18.0.2/30 dev "$HOST_IF"
ip link set "$HOST_IF" up
ip -n "$NS" addr add 198.18.0.1/30 dev "$PEER_IF"
ip -n "$NS" link set lo up
ip -n "$NS" link set "$PEER_IF" up
insmod kernel/netfw_hello.ko lab_rules=1 lab_drop=0
# Stage a single rule with default ACCEPT (do not confuse sample's TCP rule).
RULE_FILE=$(mktemp)
trap 'rm -f "$RULE_FILE"; cleanup' EXIT
cat > "$RULE_FILE" <<'JSON'
{"version":1,"default_action":"ACCEPT","rules":[{"action":"DROP","protocol":"UDP","dst_port":54321}]}
JSON
python3 userspace/netfw_client.py apply --file "$RULE_FILE" --json
python3 userspace/netfw_client.py rules --json
LAB_NS="$NS" python3 - <<'PYTEST'
import os, socket, subprocess
ns=os.environ['LAB_NS']
for port, expected in [(54322,True),(54321,False)]:
    receiver=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    receiver.bind(('198.18.0.2',port)); receiver.settimeout(1.5)
    try:
        subprocess.run(['ip','netns','exec',ns,'python3','-c',
            'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"phase33",("198.18.0.2",'+str(port)+'))'],check=True)
        try: got=receiver.recvfrom(256)[0]==b'phase33'
        except socket.timeout: got=False
        assert got==expected, f'UDP {port}: expected arrival {expected}, got {got}'
        print(f'PASS UDP {port}: {"ACCEPT" if got else "DROP"}')
    finally: receiver.close()
PYTEST
printf 'PASS: Phase 33 opt-in isolated staged UDP rule enforcement and cleanup\n'
