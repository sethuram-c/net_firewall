#!/usr/bin/env python3
"""Read-only release readiness audit. Never loads modules or changes firewall policy."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "Makefile", "README.md", "progress.md", "kernel/netfw_hello.c",
    "kernel/netfw_netlink.h", "kernel/netfw_conn.h", "kernel/netfw_table.h",
    "userspace/netfw_client.py", "userspace/netfw_protocol.py",
    "examples/rules_snapshot.json", "scripts/test_lab_hardening.sh",
    "docs/DEMO_RUNBOOK.md", "docs/ARCHITECTURE.md",
    "docs/PORTFOLIO.md", "docs/RELEASE_CHECKLIST.md",
)

def audit(root=ROOT, *, run_tests=True, require_module=False):
    """Return structured results; never invoke sudo, insmod, ip or rmmod."""
    root = Path(root)
    missing = [name for name in REQUIRED if not (root / name).is_file()]
    result = {"phase": 35, "complete": False, "missing_files": missing,
              "source_tests": "not-run", "module_present": (root / "kernel/netfw_hello.ko").is_file(),
              "fedora_privileged_tests": "not-run-by-this-tool"}
    if missing:
        return result
    if run_tests:
        try:
            completed = subprocess.run(["make", "check"], cwd=root, capture_output=True,
                                       text=True, check=False, timeout=90)
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["source_tests"] = "error: " + str(exc)
            return result
        result["source_tests"] = "passed" if completed.returncode == 0 else "failed"
        if completed.returncode != 0:
            result["test_tail"] = (completed.stderr or completed.stdout)[-800:]
    result["complete"] = (not missing and (not run_tests or result["source_tests"] == "passed")
                          and (not require_module or result["module_present"]))
    return result

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable summary")
    parser.add_argument("--skip-tests", action="store_true", help="only check packaged files")
    parser.add_argument("--require-module", action="store_true", help="require locally built .ko")
    args = parser.parse_args(argv)
    result = audit(run_tests=not args.skip_tests, require_module=args.require_module)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("NETFW Phase 35 audit:", "PASS" if result["complete"] else "FAIL")
        print("Source checks:", result["source_tests"])
        print("Local module:", "present" if result["module_present"] else "not built")
        print("Privileged Fedora checks: NOT RUN (see docs/DEMO_RUNBOOK.md)")
        if result["missing_files"]:
            print("Missing:", ", ".join(result["missing_files"]))
        if "test_tail" in result:
            print(result["test_tail"], file=sys.stderr)
    return 0 if result["complete"] else 1

if __name__ == "__main__":
    sys.exit(main())
