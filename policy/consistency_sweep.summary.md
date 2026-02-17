## Consistency sweep
- total: **47**  passed: **45**  failed: **2**

### Failures
#### CS-EV-006
- message: Index policy.consistency_sweep in every Tier>=1 PASS EvidenceManifest (fixtures) with hash=9b9d61cb93158e378ce070e89c8867f8cdd55a7bcf118a5e3325988ec57d0a7b, then rerun the sweep. (Tip: run python -m tools.sweep consistency --repo . --fix-fixtures)
- remediation: CS-EV-006 bootstrap: update fixture expected hash to the printed 'fixtures should declare' value (or run `python -m tools.sweep consistency --repo . --fix-fixtures`) and add/update the EvidenceManifest.artifacts[] entry for policy.consistency_sweep.
- details: violations=1 examples=r_pass_tier1
#### CS-PACK-IDENTITY-001
- message: Builtin protocol pack manifest invalid: manifest.files do not match scanned pack contents. Fix manifest/tree binding, then rerun sweep.
- remediation: Open policy/consistency_sweep.json and fix the reported check; re-run tools.sweep consistency.
