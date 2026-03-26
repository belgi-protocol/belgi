Directory lanes under `tests/` are suite authority and state boundaries, not cosmetic folders.

Current repo truth is in transition: heavyweight top-level `tests/test_*.py` modules still exist, but each one is assigned to exactly one lane by `tests/meta/test_lane_contracts.py` until the later split commits move them under their owner directories.

Lane owners:

- `tests/meta/`: suite governance, duplicate-guard prevention, serial discipline, sweep registry/helper semantics, and bounded xdist-determinism guards
- `tests/docs_authority/`: owner-doc claims, mirror parity, and thin-entrypoint structural checks only
- `tests/run_cli/`: black-box shipped CLI contracts and generated workspace/run guidance
- `tests/run_orchestrator/`: in-process orchestration and staging contracts
- `tests/gates/`: Q/R/S, objectref, tier, and trust-anchor gate contracts
- `tests/schemas/`: schema and loader authority checks
- `tests/shipped_surface/`: packaged bytes, wheel/install, and shipped-surface integrity
- `tests/tools/`: non-run BELGI tool surfaces
- `tests/serial/`: explicit justified exceptions only

This root README is the single lane-owner summary for `tests/`.
The only per-lane README that remains intentional is `tests/serial/README.md`, because serial is an exception protocol with its own marker, budget, and justification rules.
