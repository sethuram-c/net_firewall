#!/usr/bin/env bash
# Read-only diagnostic helper. Does not insert/remove modules.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
name=netfw_hello
printf '== Running kernel ==\n'
uname -r
printf '\n== Kbuild tree ==\n'
if [[ -d "/lib/modules/$(uname -r)/build" ]]; then
  readlink -f "/lib/modules/$(uname -r)/build"
else
  echo 'Missing matching build tree; check kernel-devel installation'
fi
printf '\n== Built module ==\n'
if [[ -f kernel/netfw_hello.ko ]]; then
  modinfo kernel/netfw_hello.ko | grep -E '^(filename|license|description|vermagic):' || true
else
  echo 'Not built (run make)'
fi
printf '\n== Loaded module ==\n'
if lsmod 2>/dev/null | awk -v n="$name" 'NR > 1 && $1 == n { found=1; print; } END { exit !found }'; then
  :
else
  echo 'Not loaded'
fi
printf '\n== Recent kernel journal lines ==\n'
if journalctl -k -b --no-pager -n 200 2>/dev/null | grep -F "$name"; then
  :
else
  echo 'No accessible NETFW log entries (sudo may be required)'
fi
