# Phase 35 release acceptance checklist

- [ ] Review `docs/ARCHITECTURE.md` and do not claim production-grade statefulness.
- [ ] Run `python3 scripts/final_audit.py --json` and confirm source tests passed.
- [ ] Run `make clean && make check-build && make verify-build` on the Fedora VM.
- [ ] Run `sudo bash scripts/test_failure_paths.sh`.
- [ ] Run `sudo bash scripts/test_verdict_regression.sh`.
- [ ] Run `sudo bash scripts/test_staged_lab_rules.sh`.
- [ ] Run `sudo bash scripts/test_lab_hardening.sh`.
- [ ] Demonstrate CLI `ping`, `status`, `rules`, non-root denied `apply`, and sudo authorized `apply`.
- [ ] Confirm module/interface/namespace teardown.
- [ ] Confirm `git status --short` is intentional and no generated artifacts staged.
- [ ] Commit only source/documentation; record terminal proof separately.
- [ ] Mark unrun Fedora tests as pending; never substitute source tests for runtime tests.
