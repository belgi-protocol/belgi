Directory lanes under `tests/` are suite authority and state boundaries, not cosmetic folders.

Current repo truth is physically lane-owned: tracked `test_*.py` modules live under their owner directories, and `tests/meta/test_lane_contracts.py` is the executable owner for lane topology, cross-lane import boundaries, and the no-wrong-lane discipline.

Lane owners:

- `tests/meta/`: suite governance only
- `tests/meta/` owns lane classification, cross-lane guardrails, duplicate-guard prevention, serial discipline, shared helper seam contracts, sweep implementation/helper semantics, and bounded xdist-determinism guards
- `tests/meta/` does not own repo-live static parity, mirror/generated/rendered parity, or runtime owner behavior
- `tests/docs_authority/`: owner-doc claims and thin-entrypoint structural checks only
- `tests/run_cli/`: subprocess black-box shipped CLI contracts and runtime-owned generated workspace/run guidance
- `tests/run_orchestrator/`: in-process orchestration and staging contracts
- `tests/gates/`: Q/R/S, objectref, tier, and trust-anchor gate contracts
- `tests/schemas/`: schema and loader authority checks
- `tests/shipped_surface/`: packaged bytes, wheel/install, and shipped-surface integrity
- `tests/tools/`: non-run BELGI tool surfaces
- `tests/serial/`: explicit justified exceptions only

Repo-wide static/generated/mirror/rendered parity is sweep-owned:
- executable owner: `tools/sweep.py`
- law/spec owner: `docs/operations/consistency-sweep.md`
- `tests/meta/test_sweep_semantics.py` exists only to prove sweep helper and implementation semantics on synthetic inputs, not to re-own live repo parity
- only `tests/tools/` and `tests/meta/test_sweep_semantics.py` may target packaged parity roots as part of tool-surface or sweep-helper semantics
- `tests/docs_authority/` may prove owner-doc claim shape and public entrypoint structure, but it must not own or read packaged parity roots / mirror roots

This root README is the single lane-owner summary for `tests/`.
The only per-lane README that remains intentional is `tests/serial/README.md`, because serial is an exception protocol with its own marker, budget, and justification rules.

Custom pytest markers are suite control-plane state, not topic labels.
Current registered custom vocabulary is only:

- `repo_local`: repo-local import/reset handling
- `serial`: explicit serial-lane exclusion

Lane identity comes from path and lane classification, not from a second marker taxonomy.
Generated `.belgi/README.md` and run-local `RUN.md` stay under `run_cli/`; they are product surfaces tied to runtime behavior, not public-doc owner claims.
Repo-local BELGI imports for `tests/run_orchestrator/` must come from per-test fresh-import fixture/factory discipline, not module-global cached handles.
Empty lane directories are intentionally tracked with placeholders only where the lane remains part of the suite contract even without a current owner module.
