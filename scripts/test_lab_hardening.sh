#!/usr/bin/env bash
# Phase 34: extra fail-safe cases, isolated to a disposable veth/netns lab.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ ${EUID} -eq 0 ]] || { echo 'Run with sudo' >&2; exit 1; }
for cmd in ip python3 insmod rmmod mktemp; do command -v "$cmd" >/dev/null || exit 1; done
[[ -f kernel/netfw_hello.ko ]] || { echo 'Build the module first' >&2; exit 1; }
NS="nfwt34-$$"; HOST_IF=nfwt10h; PEER_IF=nfwt10n
if [[ -d /sys/module/netfw_hello ]] || ip link show "$HOST_IF" >/dev/null 2>&1; then
  echo 'Refusing: the module or lab interface already exists' >&2; exit 1
fi
RULE_FILE=$(mktemp); BAD_FILE=$(mktemp)
cleanup() {
  if [[ -d /sys/module/netfw_hello ]]; then rmmod netfw_hello || true; fi
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$HOST_IF" 2>/dev/null || true
  rm -f "$RULE_FILE" "$BAD_FILE"
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
cat > "$RULE_FILE" <<'JSON'
{"version":1,"default_action":"ACCEPT","rules":[{"action":"DROP","protocol":"UDP","dst_port":54321}]}
JSON
cat > "$BAD_FILE" <<'JSON'
{"version":1,"default_action":"ACCEPT","rules":[{"action":"DROP","protocol":"UDP","dst_port":70000}]}
JSON
probe() {
    LAB_NS="$NS" EXPECT_PORT="$1" EXPECT_ARRIVAL="$2" python3 - <<'PYTEST'
import os, socket, subprocess
port=int(os.environ['EXPECT_PORT'])
expected=os.environ['EXPECT_ARRIVAL']=='yes'
receiver=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
receiver.bind(('198.18.0.2',port)); receiver.settimeout(1.5)
try:
    subprocess.run(['ip','netns','exec',os.environ['LAB_NS'],'python3','-c',
        'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"p34",("198.18.0.2",'+str(port)+'))'],check=True)
    try: received=receiver.recvfrom(128)[0]==b'p34'
    except socket.timeout: received=False
    assert received==expected, f'UDP {port}: expected arrival={expected}, got={received}'
    print(f'PASS UDP {port}: {"ACCEPT" if received else "DROP"}')
finally: receiver.close()
PYTEST
}
# Stage a DROP rule while enforcement is OFF; no staged rule may affect traffic.
insmod kernel/netfw_hello.ko lab_rules=0 lab_drop=0
python3 userspace/netfw_client.py apply --file "$RULE_FILE" --json
probe 54321 yes
rmmod netfw_hello
# Load again, explicitly opt in. No rules should survive module unload/reload.
insmod kernel/netfw_hello.ko lab_rules=1 lab_drop=0
python3 userspace/netfw_client.py rules --json | python3 -c   'import json,sys; x=json.load(sys.stdin); assert x["rule_count"]==0'
probe 54321 yes
python3 userspace/netfw_client.py apply --file "$RULE_FILE" --json
probe 54322 yes
probe 54321 no
# Rejected replacement must not partially publish or erase the good rule.
if python3 userspace/netfw_client.py apply --file "$BAD_FILE" --json; then
  echo 'FAIL: invalid rules accepted' >&2; exit 1
fi
python3 userspace/netfw_client.py rules --json | python3 -c   'import json,sys; x=json.load(sys.stdin); assert x["rule_count"]==1 and x["rules"][0]["dst_port"]==54321'
probe 54321 no
# Remove every staged rule via an authorized empty-table replacement.
cat > "$RULE_FILE" <<'JSON'
{"version":1,"default_action":"ACCEPT","rules":[]}
JSON
python3 userspace/netfw_client.py apply --file "$RULE_FILE" --json
probe 54321 yes
printf 'PASS: Phase 34 opt-in isolation, invalid replacement, reload and teardown
'
