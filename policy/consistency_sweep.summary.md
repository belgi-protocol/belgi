## Consistency sweep
- total: **49**  passed: **48**  failed: **1**

### Failures
#### CS-CAN-005
- message: Canonical package mirror drift detected. Run `python -m tools.build_builtin_pack` and rerun sweep. Drift: belgi/canonicals/docs/operations/running-belgi.md != docs/operations/running-belgi.md.
- remediation: Open policy/consistency_sweep.json and fix the reported check; re-run tools.sweep consistency.
