#!/usr/bin/env bash
# Isolated veth / netns lab. Only run on a disposable VM you control.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ ${EUID} -eq 0 ]] || { echo "Run with sudo" >&2; exit 1; }
for cmd in ip python3 insmod rmmod; do command -v "$cmd" >/dev/null || { echo "Missing: $cmd" >&2; exit 1; }; done
[[ -f kernel/netfw_hello.ko ]] || { echo "Run make first" >&2; exit 1; }
NS="nfwt10-$$"
HOST_IF=nfwt10h
PEER_IF=nfwt10n
if ip link show "$HOST_IF" >/dev/null 2>&1 || lsmod | grep -q '^netfw_hello '; then
  echo "Refusing: module loaded or lab interface already exists" >&2; exit 1
fi
cleanup() {
  if lsmod | grep -q '^netfw_hello '; then rmmod netfw_hello || true; fi
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
# install hook only AFTER dedicated test interface exists
insmod kernel/netfw_hello.ko lab_drop=1
# A real UDP receiver on the host checks packets, not just source text.
# Sender is executed inside the namespace, guaranteeing ingress at nfwt10h.
LAB_NS="$NS" python3 - <<'PYTEST'
import os, socket, subprocess
ns=os.environ['LAB_NS']
for port, must_arrive in ((54322, True), (54321, False)):
    receiver=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    receiver.bind(('198.18.0.2',port)); receiver.settimeout(1.5)
    try:
        subprocess.run(['ip','netns','exec',ns,'python3','-c',
            'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"netfw10",("198.18.0.2",'+str(port)+'))'],check=True)
        try:
            data,_=receiver.recvfrom(256)
            arrived=(data==b'netfw10')
        except socket.timeout:
            arrived=False
        assert arrived==must_arrive, f'UDP {port}: expected arrival={must_arrive}, actual={arrived}'
        print(f'PASS UDP {port}: {"ACCEPT" if arrived else "DROP"}')
    finally:
        receiver.close()
PYTEST
printf 'PASS: isolated Netfilter ACCEPT/DROP lab; resources cleaned on exit\n'
