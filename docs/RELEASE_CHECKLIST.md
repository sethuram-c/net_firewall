# Release checks

This list is for a local Fedora VM run. Check boxes only after executing the corresponding command. Python source checks and a successful build are useful, but neither proves the isolated UDP path works.

- [ ] `bash scripts/check_env.sh` reports a usable build environment.
- [ ] `make clean && make check-build && make verify-build` completes against the running Fedora kernel.
- [ ] `python3 scripts/final_audit.py --json --require-module` passes.
- [ ] `sudo bash scripts/test_failure_paths.sh` reports both intentional failures and no loaded module.
- [ ] `sudo bash scripts/test_verdict_regression.sh` passes both legacy modes.
- [ ] `sudo bash scripts/test_staged_lab_rules.sh` passes its isolated UDP delivery checks.
- [ ] `sudo bash scripts/test_lab_hardening.sh` passes the opt-out, replace, reset and cleanup scenarios.
- [ ] With the module loaded, CLI `ping`, `status`, `rules` work; an unauthorized `apply` is rejected and an authorized one is accepted.
- [ ] After tests, `netfw_hello` is unloaded, `nfwt10h` is absent, and no test namespace remains.
- [ ] `git diff --check` is clean and generated kernel files are not staged.
- [ ] `README.md` and `docs/ARCHITECTURE.md` clearly distinguish staged UDP filtering from the inactive connection-tracking prototype.

Keep test output if you want reproducible evidence for the portfolio. Avoid describing a test as passed if it hasn't run on the target system.
