#!/usr/bin/env bash
set -u

pass=0
fail=0
warn=0
ok() { printf '[PASS] %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '[FAIL] %s\n' "$1"; fail=$((fail+1)); }
notice() { printf '[WARN] %s\n' "$1"; warn=$((warn+1)); }

printf 'NETFW Phase 1 - Fedora environment check\n\n'
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  printf 'OS: %s\n' "${PRETTY_NAME:-unknown}"
  [[ "${ID:-}" == fedora ]] && ok 'Fedora detected' || notice 'Not Fedora; commands may differ'
else
  notice '/etc/os-release is unavailable'
fi

kernel="$(uname -r)"
printf 'Running kernel: %s\n' "$kernel"
for command in gcc make git python3 bash rpm; do
  if command -v "$command" >/dev/null 2>&1; then
    ok "$command available"
  else
    bad "$command missing"
  fi
done

build="/lib/modules/$kernel/build"
if [[ -e "$build/Makefile" ]]; then
  ok "Matching kernel build directory exists: $build"
else
  bad "No matching kernel-devel build tree at $build"
fi
if command -v rpm >/dev/null 2>&1; then
  if rpm -q "kernel-devel-$kernel" >/dev/null 2>&1; then
    ok "kernel-devel-$kernel installed"
  else
    bad "Matching kernel-devel-$kernel package not installed"
  fi
fi
if command -v mokutil >/dev/null 2>&1; then
  sb="$(mokutil --sb-state 2>&1 || true)"
  case "$sb" in
    *'SecureBoot enabled'*|*'Secure Boot enabled'*) notice 'Secure Boot enabled: unsigned modules may be rejected; plan trusted signing' ;;
    *'SecureBoot disabled'*|*'Secure Boot disabled'*) ok 'Secure Boot disabled' ;;
    *) notice "Secure Boot status inconclusive: $sb" ;;
  esac
else
  notice 'mokutil not installed; Secure Boot status not checked'
fi
printf '\nSummary: %d pass, %d fail, %d warning(s)\n' "$pass" "$fail" "$warn"
if (( fail > 0 )); then
  printf 'Suggested setup: sudo dnf install gcc make git python3 bash mokutil "kernel-devel-$(uname -r)"\n'
  exit 1
fi
printf 'Phase 1 environment prerequisites look ready.\n'
