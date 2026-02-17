## Consistency sweep
- total: **47**  passed: **46**  failed: **1**

### Failures
#### CS-PACK-IDENTITY-001
- message: Run `python -m tools.belgi fixtures sync-pack-identity --repo . --pack-dir belgi/_protocol_packs/v1`, then rerun the sweep.
- remediation: Open policy/consistency_sweep.json and fix the reported check; re-run tools.sweep consistency.
