# Changelog
This changelog is a factual record of protocol mechanics, documentation, and enforcement changes in this repository.
It does not contain experimental results or performance claims.

## 1.6.10 — 2026-03-30

### Summary
Removed duplicate C3 staging authority from `belgi/core/run_orchestrator.py` and moved staged-source proof onto the compiler-owned C3 path.

### Changed
- `belgi/core/run_orchestrator.py` no longer carries its own C3 canonical binding tables or the dead `ensure_chain_c3_canonicals(...)` helper.
- `chain/compiler_c3_docs.py` now exposes `materialize_protocol_bound_c3_source_root(...)` as the reusable protocol-bound materialization seam used by staged-source resolution and staged-cache rebuild paths.
- `tests/run_orchestrator/test_run_orchestrator_hydration_contracts.py` now stays on template hydration only, while shipped-surface C3 tests prove staged-source materialization on the compiler-owned seam.

### Notes
- This patch does not change which C3 canonical files exist; it removes a second source-binding authority for the same staged tree.

## 1.6.9 — 2026-03-30

### Summary
Patch release converging public CLI exit-code authority on the shared CLI normalization owner and adding a direct canonical-doc/runtime parity contract for that surface.

### Changed
- Removed the shadow public exit-code constants from `belgi/cli_app/commands/run.py`, so the shipped `belgi run` path now returns the shared `belgi.cli_app.render` owner constants instead of carrying a second RC authority copy.
- Tightened `docs/operations/exit-codes.md` so the canonical public contract now documents the two real normalization surfaces separately: the default public CLI boundary and the public `belgi stage ...` forwarder boundary.
- Added direct docs/runtime parity coverage in `tests/tools/test_exit_code_contracts.py`, which parses the canonical exit-code tables and checks them against `belgi.cli_app.render` constants and `_normalize_cli_exit_code(...)`.

### Notes
- This patch converges an existing public CLI contract only; it does not widen the CLI surface or change the public exit-code model `{0,10,20,30}`.

## 1.6.8 — 2026-03-29

### Summary
Patch release resetting the repo-wide test versus sweep boundary, tightening suite owner-lane governance, and hardening two shipped run-path regressions uncovered during that cleanup.

### Changed
- Centralized owner-derived semantic fixtures and retired stale docs-authority, meta, and static-parity tests so repo-live mirror/parity policing stays on sweep or `check_drift`, while runtime/helper semantics stay in their owner lanes.
- Narrowed run-cli, gate, schema, shipped-surface, and tools contract tests to published owner behavior and published tool/output surfaces, replacing brittle prose freezes, regex/source policing, and wrong-surface helper coupling with owner-path or tool-surface proofs.
- Added shared seam shape contracts for tier fixtures, direct `tools.check_drift` and emitted sweep-report coverage, and repo-wide suite governance that locks parity-root targeting to sweep/tools lanes while keeping `tests/meta/` on suite-governance duties only.
- Hardened precomputed seal-signature replay on the shared `belgi run --seal-signature-ref` path so replay signatures are generated from the exact failed-at-seal payload that the retry verifies.
- Removed install/package metadata from `belgi run` key derivation so repeated runs on the same logical run identity keep a stable `run_key` while `attempt_id` continues to advance.

### Notes
- This patch primarily resets test and sweep ownership boundaries and their supporting proofs; public CLI surface and locked-object schema remain unchanged.

## 1.6.7 — 2026-03-28

### Summary
Patch release converging shipped tier admission and HOTL authority on canonical tier policy, and making PromptBundle block selection follow tier-policy owner fields instead of broad tier-literal branching.

### Changed
- Added a shared runtime tier authority surface in `chain/logic/tier_packs.py` for supported-tier admission and HOTL requirement reads from the active protocol-pack `tiers/tier-packs.json`, and rewired shipped `belgi run`, the run parser, Gate Q Q7, and `q_hotl_001.py` to consume that owner instead of duplicated fixed tier tuples.
- Moved Gate Q tier-support admission ahead of tier-derived validations so unsupported tiers fail deterministically as Q7 / `FQ-TIER-UNKNOWN` before evidence, waiver, HOTL, or envelope checks try to read policy for an invalid tier.
- Corrected Tier-1 HOTL policy to match the shipped tier owner surface, then propagated that alignment through `tiers/tier-packs.json`, generated `tiers/tier-packs.md`, `gates/GATE_Q.md`, `schemas/README.md`, `docs/operations/waivers.md`, built-in protocol-pack mirrors, and the consistency-sweep contract.
- Reworked PromptBundle block selection so PB-009, PB-010, and PB-011 derive from the actual tier-policy fields (`command_log_mode`, `test_policy.required`, and `envelope_policy.requires_attestation`) instead of a blanket `tier-1`/`tier-2`/`tier-3` branch.
- Updated owner-lane and sweep-semantic tests so they prove the surviving owner surfaces directly, including tier-policy override coverage, HOTL contract coverage, PromptBundle selection contracts, and stale-surface consistency checks.

### Notes
- This patch converges existing tier and prompt authority surfaces only; no new CLI flags or locked-object schema changes are introduced.

## 1.6.6 — 2026-03-28

### Summary
Patch release aligning the README quickstart with the shipped operator spine and hardening the shared run-orchestrator execution spine without widening BELGI's public CLI contract.

### Changed
- Reworked `README.md` into the repo overview/entrypoint, pointed exact shipped CLI syntax, operator quickstart, and `NO-GO` triage to `docs/operations/cli.md`, and replaced the old `pip install belgi` assumption with source-checkout install guidance until publication.
- Narrowed the README quickstart onto the canonical `belgi about` / `belgi init` / `belgi run` / `belgi verify` operator path, and documented the generated `.belgi/README.md`, run-local `RUN.md`, command-surface tiers, and repo-local `./scripts/dev_sync.ps1` repair entrypoint instead of the older broad command catalog.
- Routed `tools.belgi_tools` helper execution from `belgi/core/run_orchestrator.py` through child-process `python -m tools.belgi_tools` invocation while preserving orchestrator-facing rc handling.
- Replaced parent-process `CI` mutation around `chain.compiler_c1_intent` with explicit child-process env handling, so the C1 path no longer depends on ambient parent-env rewrites.
- Updated run-orchestrator owner tests so ToolchainSet, Tolerances, and CLI failure-path proofs intercept the explicit subprocess seam rather than the retired in-process helper shape.
- Added a dedicated execution-spine guard owner test surface for the helper/C1 seam family and aligned the run-orchestrator owner proofs to that boundary.

### Notes
- This patch updates public README/operator guidance and hardens run-orchestrator execution and proof surfaces only; shipped CLI contract, tier semantics, and locked-object schema remain unchanged.

## 1.6.5 — 2026-03-27

### Summary
Patch release completing the physical test-suite lane modularization and removing the last root-level lane fallback.

### Changed
- Moved the remaining root `tests/test_*.py` modules into their owner lanes under `tests/meta/`, `tests/run_cli/`, `tests/run_orchestrator/`, `tests/gates/`, `tests/schemas/`, `tests/shipped_surface/`, and `tests/tools`, so tracked test ownership is now expressed directly by path.
- Split the old run, gate, shipped-surface, and non-run tooling hotspots into narrower owner files and aligned suite lane assertions to those live paths.
- Removed the legacy root-lane fallback from `tests/meta/test_lane_contracts.py`; unclassified test modules now fail closed instead of inheriting a root-path mapping.
- Updated `tests/README.md` and `pytest.ini` to describe and discover the physically lane-owned suite layout while keeping custom marker vocabulary limited to execution-control exceptions.
- Preserved import hygiene, shared script-loader handling, and serial-only exceptions on the new lane-owned surfaces.
- Updated repository verification to install `pytest-xdist`, run the full tracked test suite under xdist, and keep wheel-smoke packaging checks aligned with the lane-owned packaging smoke test surface.

### Notes
- This patch restructures test ownership and discovery surfaces only; application runtime behavior is unchanged.

## 1.6.4 — 2026-03-25

### Summary
Patch release resetting shipped operator-doc ownership so one owner-of-record carries each run/operator truth family while README and non-owner Tier-3 surfaces become pointer-led.

### Changed
- Made `docs/operations/cli.md` the sole tracked owner of shipped `belgi run` flags, accepted path examples, and operator quickstart for the shared run spine.
- Reduced `docs/operations/running-belgi.md` to manual `python -m chain.*` reference, stage order, and replay/evidence notes while keeping only the bounded shipped-vs-manual execution truths it still needs.
- Reduced `docs/operations/operator-anchors.md` to anchor classes, handling, and workspace/file-boundary guidance, removing the repeated full Tier-2/Tier-3 `belgi run` command examples and exact flag catalog posture.
- Slimmed `README.md` into a pointer-led entrypoint for hosted workflow governance, wheel-boundary truth, and repo-maintenance tooling, with those families now owned by `docs/operations/workflows.md`, `CANONICALS.md`, and `tools/README.md`.
- Narrowed the remaining Tier-3 reminders in `docs/operations/running-belgi.md` and `docs/operations/operator-anchors.md` to owner pointers back to `docs/operations/evidence-bundles.md` and `CANONICALS.md` instead of long-form co-owner authority prose.
- Realigned consistency-sweep and contract guards so owner docs keep exact-claim protection while non-owner docs are checked for required pointers, useful boundary notes, and absence of contradictory or owner-competing wording.

### Notes
- This patch changes documentation authority and guard scope only; runtime, schema, tier, and gate semantics are unchanged.

## 1.6.3 — 2026-03-25

### Summary
Patch release repairing the shipped ToolchainSet/Tolerances run-local operator contract on the shared `belgi run` spine, including tighter-but-not-wider explicit tolerances under the selected tier.

### Changed
- Repaired shipped `belgi run` ingress so explicit `--toolchain-set-ref` and `--tolerances-ref` accept only the current run's canonical run-local operator inputs under `.belgi/runs/<run_id>/inputs/environment/`, while leaving shorthand `--toolchain-ref` on evaluated-revision declaration surfaces.
- Repaired the orchestrator/C1 handoff so accepted run-local ToolchainSet/Tolerances inputs are staged into `out/inputs/environment/` before lock, and later stages consume the locked/store copy rather than ambient workspace bytes.
- Repaired explicit current-run Tolerances semantics so `scope_budgets.max_touched_files` and `scope_budgets.max_loc_delta` may equal or tighten the selected tier ceilings, but fail closed when either value widens the selected tier; `Tolerances.tier_id` must still match the selected tier.
- Removed the stale C1 tolerances precheck that rejected explicit run-local Tolerances before Gate Q, keeping selected-tier `Tolerances` enforcement on the repaired Gate Q path and aligning the high-level C1 compiler doc with the current manual-versus-shipped surface split.
- Narrowed shipped operator docs and generated run guidance so `docs/operations/cli.md` owns the exact shipped CLI contract, `docs/operations/running-belgi.md` keeps execution-truth/manual-reference wording, and the explicit ingress story no longer contradicts runtime.
- Added regression coverage for accepted run-local ToolchainSet/Tolerances ingress, fail-closed foreign-run and wrong-leaf rejection, malformed/missing/invalid run-local refs, and the staged-orchestrator binding path that feeds R7/C1.

### Notes
- This patch repairs shipped ingress truth only; `LockedSpec` schema, Tier-2/Tier-3 anchor semantics, and broader docs-authority convergence remain unchanged.

## 1.6.2 — 2026-03-24

### Summary
Patch release closing two bounded test-governance debts, tightening repo-local helper/import hygiene, and keeping the heavyweight isolation debt open without changing shipped BELGI semantics.

### Changed
- Replaced the Tier-0 R7 run-test dependence on literal `allowed_dirs` template-text replacement with a more robust helper-based rewrite that survives harmless template formatting changes.
- Centralized fresh BELGI import hygiene for the heavyweight CLI/gate/SSOT test modules in `tests/helpers/repo_imports.py`, removing ad hoc per-module `sys.modules` / `sys.path` surgery and materially narrowing the remaining parallel-safe isolation debt surface without claiming the broader isolation debt is fully closed.
- Moved the repo-local synthetic helpers under `tests/helpers/`, narrowed the public `tests/helpers/builders.py` export surface to explicit builder entrypoints only, restored that builder to current LockedSpec / ToolchainSet / Tolerances / EvidenceManifest truth after the move, aligned synthetic `LockedSpec.belgi_version` to the same version authority source used by live C1, and kept the direct meta-test guards on determinism, invalid-path preservation, current synthetic object shapes, and clean-HEAD synthetic Gate R fidelity.
- Tightened the moved test-local helper surface further by replacing the synthetic diff closure in `tests/helpers/builders.py` with an explicit helper and by keeping repo-root resolution anchored to the real BELGI repo root.

### Notes
- This patch is maintenance and trust-surface tightening only; shipped CLI, gate, schema, tier, and runtime semantics are unchanged.

## 1.6.1 — 2026-03-23

### Summary
Patch release finalizing BELGI main-repo fixture-zero closure and tightening the repo-local synthetic builder trust surface without changing shipped gate or runtime semantics.

### Changed
- BELGI main repo no longer maintains in-repo Q/R/S/Seal fixtures; the scoped regression coverage for this surface is programmatic and pytest-based.
- Removed the remaining scoped fixture-path dependencies from BELGI main-repo tests and filled the programmatic Q/R coverage gaps for `Q3`, `Q5`, `Q7`, `Q-PROMPT-001`, `Q-DOC-002`, and `R-DOC-001`.
- Removed BELGI main-repo fixture sweep and regen burden, kept only the vault-only placeholders under `policy/fixtures/internal/`, and removed the retired fixture-maintenance command surfaces from `tools.sweep`, `tools.rehash`, and `tools.belgi`.
- Removed the last embedded fixture sweep and self-referential fixture-hash logic from `tools.sweep`, aligned `dev_sync` to the current main-repo sweep path only, and cleaned the consistency/tool docs to remove stale retired-surface wording.
- Removed retired fixture references from repository-verification and CODEOWNERS so proof surfaces no longer target deleted BELGI main-repo fixture files.
- Removed the retired fixture-only consistency invariants from the sweep spec and code so BELGI main repo no longer carries dead legacy fixture checks.
- Moved the repo-local synthetic payload builder out of `tests/` into top-level `builders.py` and added explicit builder meta-tests guarding determinism, invalid-path preservation, and absence of hidden authority-bearing defaults.
- Removed the stale tests that still targeted deleted fixture-hash repair helpers, and dropped the last dead `ZERO_SHA256` carryover from `tools.sweep`.
- Repaired the synthetic Q/R/S test helper path so builder/meta-tests reach their intended ownership points, synthetic R repos bind `upstream_state.commit_sha` to the initialized commit, and synthetic S repos emit a real `SealManifest.json` instead of depending on a broken helper call shape.
- Removed the dead unified-diff parser helpers from `chain.logic.r_checks.git_ops` once Ruff cleanup proved the R checks no longer consume that fallback path.
- Repaired synthetic Gate R repo setup so positive-path tests now evaluate a clean committed base-to-HEAD git diff from tracked bytes, instead of relying on stale-head or dirty-tree synthetic setup.
- Narrowed public docs so BELGI main repo makes no run or completeness claim about any separate maintainer-private fixture workspace.

### Notes
- This patch is maintenance and trust-surface tightening only; shipped gate semantics, `chain/` behavior, and TierPacks behavior are unchanged (except legacy fixture behavior that was removed from the gate semantics).

## 1.6.0 — 2026-03-22

### Summary
Release closing the object-surface and runtime-truth gaps around ToolchainSet, Tolerances, R7, R8, and shipped `belgi run` budget authority on the primary run spine.

### Changed
- Promoted ToolchainSet into a real first-class locked object with schema-backed runtime validation, explicit `LockedSpec.environment_envelope.toolchain_set_ref`, shipped `belgi run --toolchain-set-ref <object_id>=<repo-relative-path>`, and repeatable `--toolchain-ref <object_id>=<repo-relative-path>` retained only as shorthand that normalizes into ToolchainSet authority before lock.
- Promoted Tolerances into a real first-class locked object with schema-backed runtime validation, explicit `--tolerances-ref <object_id>=<repo-relative-path>`, generated default Tolerances objects from tier packs when omitted, and direct runtime consumption through `LockedSpec.tier.tolerances_ref`.
- Retired numeric scope-budget authority from shipped `IntentSpec`; legacy `IntentSpec.scope.max_touched_files` and `IntentSpec.scope.max_loc_delta` are now rejected by both schema and runtime with migration guidance to move numeric budgets into Tolerances.
- Reworked Gate Q and Gate R to enforce the new authority map: Q validates locked ToolchainSet and locked Tolerances objects, Q rejects legacy numeric intent budgets, R2 reads the locked Tolerances object as the sole runtime budget source after lock, and tier packs remain canonical templates and ceilings rather than post-lock runtime authority.
- Reworked `belgi supplychain-scan` and shipped run/orchestrator wiring so R7 uses the actual `base_revision -> evaluated_revision` diff plus ToolchainSet-derived accounting refs on the existing run spine, without a second control family and with fail-closed evaluated-revision binding plus reserved `toolchain.main`.
- Reworked `belgi adversarial-scan` so R8 gates only on findings on changed Python lines from the actual diff; historical repo findings outside the change no longer drive `FR-ADVERSARIAL-DIFF-SUSPECT`.
- Moved the operator-facing run workspace truth to `.belgi/runs/<run_id>/inputs/environment/`, taught ToolchainSet and Tolerances as real shared run objects, and removed the old misleading root-level `toolchain.json` / `tolerances.json` placeholder affordances.
- Repaired the manual `chain.compiler_c1_intent` example to the actual `1.6.0` object contract: explicit `--toolchain-set`, explicit `--tolerances`, and built-in `toolchain.main` binding without obsolete shorthand mixing.
- Updated schemas, LockedSpec, operator docs, gate docs, tier-pack truth, canonical mirrors, and protocol-pack mirrors so the shipped authority map is consistent across runtime, docs, and locked pack surfaces.
- Refreshed the public Gate Q / Gate R / Gate S fixtures to the locked ToolchainSet and Tolerances object shape so canonical pass fixtures remain valid under `1.6.0` and negative fixtures continue to fail at their intended checks instead of stale legacy schema drift.
- Expanded consistency-sweep authority coverage to lock the shipped run object-ref CLI contract, `run new` environment-input guidance, legacy numeric-budget retirement parity, and ToolchainSet/Tolerances schema-catalog loader claims.
- Added regression coverage for explicit/generated ToolchainSet binding, explicit/generated Tolerances locking, legacy intent-budget rejection, locked Tolerances consumption in R2, R7 unaccounted/accounted diff controls, R8 inside-diff/outside-diff controls, and the revised orchestrator run inputs.

### Notes
- This release sharpens shipped runtime truth and object authority; it does not widen R7 into SBOM/provenance/vulnerability claims or turn R8 into a repo-wide scan.

## 1.5.4 — 2026-03-21

### Summary
Patch release refactoring the shipped BELGI CLI into a thin membrane layout while preserving the existing public run, verify, stage, bundle, exit-code, machine-JSON, and remediation-rendering behavior.

### Changed
- Repaired the shipped CLI into the locked `belgi/cli_app/` tree, with a thin `belgi/cli.py` compatibility shim over `main`, `registry`, `render`, root parser assembly, per-surface parser modules, and per-surface command modules.
- Added `python -m belgi` support through a thin `belgi/__main__.py` entry that stays on the same shipped CLI spine as the console entrypoint.
- Kept static command wiring explicit across `run`, `verify`, `stage`, `bundle`, `pack`, `policy`, `manifest`, `waiver`, `about`, `supplychain-scan`, and `adversarial-scan` without introducing dynamic handler resolution or a second orchestration family.
- Preserved the public CLI exit-code model `{0,10,20,30}`, current machine first-line JSON contract, `belgi run` remediation precedence shipped in `1.5.3`, bounded `belgi verify` authority, and thin `belgi stage ...` forwarder behavior.
- Kept the module entrypoint, compatibility shim, and legacy monkeypatch surfaces aligned with the repaired `cli_app` tree so existing public entry behavior and test touchpoints remain stable.
- Restored the stage forwarder's centralized rc normalization so raw stage rc `1` continues to surface as public internal error `30`, while `2` and `3` still map to public `10` and `20`.
- Added `pytest-xdist` to `requirements-dev.txt` for local development and test tooling.

### Notes
- This patch is an internal maintainability refactor only; it does not change protocol semantics, gate authority, or shipped CLI behavior.

## 1.5.3 — 2026-03-21

### Summary
Patch release hardening shipped `belgi run` remediation surfacing so the public `NO-GO (10)` path lifts authoritative next-step text from current structured artifacts without overclaiming across the separate public `USER_ERROR (20)` path.

### Changed
- For public `NO-GO (10)` run failures, `belgi run` renders human `next:` text in strict precedence order:
  - `GateVerdict.<Q|R|S>.json remediation.next_instruction` from a produced `NO-GO` gate verdict
  - current-run `C1IntentParseError.json next_instruction` when no gate verdict remediation is available
  - generic CLI fallback only when neither authoritative source exists
- Separate public `USER_ERROR (20)` failures continue to use direct CLI guidance for input, argument, or repo-state problems.
- Kept the machine JSON first line, public CLI exit-code model `{0,10,20,30}`, run workspace/store boundary, and default open-helper ordering unchanged.
- Updated shipped operator docs and generated init guidance to separate those public classes while keeping evidence/verdict pointers unchanged.

### Notes
- This patch hardens operator remediation surfacing only; it does not change gate schemas, gate ordering, or verification authority.

## 1.5.2 — 2026-03-20

### Summary
Patch release landing the first `ruff` cleanup wave and activating the chosen `ruff` rule surface for repo maintenance.

### Changed
- Applied safe repo-wide `ruff` autofixes across the current target set, covering import sorting, unused imports, and other mechanical hygiene cleanup without changing operator or protocol semantics.
- Removed the repeated `tools/sweep.py` `root` import/name collision that produced a large `F811` cluster.
- Closed the remaining patch-safe `ruff` findings in the current rule set with small deterministic fixes such as direct attribute access in tests, explicit exception chaining, unused-variable cleanup, and `zip(..., strict=True)` where length equality is already asserted.
- Activated `ruff` enforcement for the existing chosen `F`, `I`, and `B` surface on both `Repository Verification` and local `dev_sync`.

### Notes
- `ruff` is active as repo-maintenance enforcement only; Pyright remains non-gating.

## 1.5.1 — 2026-03-20

### Summary
Patch release hardening tier-pack markdown parsing and landing tracked, dormant `ruff` preparation without switching lint enforcement on as a required proof gate.

### Changed
- Replaced the markdown tier-pack `envelope_policy` nested multi-line regex scan with deterministic sub-block parsing in `chain/logic/tier_packs.py`.
- Added regression coverage for long sibling-line parsing, preserved optional envelope-policy defaults, and locked out the old regex shape.
- Added tracked `ruff` configuration as the planned lint authority surface while keeping both local and hosted `ruff` execution dormant by default in this iteration.
- Kept public docs and workflow descriptions aligned to shipped truth: `ruff` is prepared but not yet part of the required proof path, and Pyright remains non-gating.

### Notes
- This patch does not claim active lint-gate enforcement or typing-closure completion.

## 1.5.0 — 2026-03-20

### Summary
Release focused on shared operator-path closure across Tier-2/Tier-3, Operator Anchors convergence, and tier-pack truth reconciliation.

### Added
- Shipped Tier-2 and Tier-3 operator paths on the shared `belgi run` family:
  - explicit local-only operator controls for HOTL, public-key pins, attestation signing, and seal entry
  - explicit Tier-3 `--genesis-seal-ref` handling on the same run backbone
  - shipped-path `belgi verify` coverage for Tier-2 and Tier-3 runs
- Canonical `Operator Anchors` surface:
  - normative `Operator Anchors` term in `CANONICALS.md` with pointer-only terminology entries
  - recommended operator workspace family `inputs/anchors/{approvals,keys,signing}`
  - dedicated operator guidance for shared control materials and their replay boundaries

### Changed
- Shared run-path architecture:
  - Tier-2 and Tier-3 converge on one operator-control model without introducing a second orchestration family
  - local signing material is consumed without persisting raw secret bytes on authoritative run outputs
  - both local-signing and precomputed seal-signature entry paths are supported on the shipped run surface
- Tier-3 boundary enforcement:
  - `genesis_seal` remains Tier-3 evidence, not an Operator Anchor
  - `TrustAnchor.json` remains the Tier-3 authority artifact, not an Operator Anchor
  - Tier-3 remediation text now separates missing shared Operator Anchors from missing Tier-3 evidence input
- Tier-pack and operator-truth propagation:
  - HOTL remains a separate control artifact from waivers
  - Tier-2 remains bounded to one active waiver and Tier-3 remains zero-waiver
  - generated tier views, operator docs, and run scaffolding now teach the shared anchors workspace and preserve bounded verify/bundle-check guidance

### Notes
- Public entry records shipped operator surfaces and canonical boundaries only.
- This release does not claim outer trust-chain completion, hosted-governance expansion, or release-provenance / trusted-builder closure.

## 1.4.18 — 2026-03-19

### Summary
Patch release retiring the current non-blocking debt items around CRLF result parsing assertions, markdown tier-pack strictness, and `CS-CAN-001` terminology detection before the Tier-2/3 adopter-path push.

### Changed
- Strengthened the CRLF BELGI result parser test so it now asserts `ok == True` and `verdict == "GO"` in addition to `run_key` and `attempt_id`.
- Removed the markdown tier-pack parser fallback from `command_log_mode` to `adversarial_policy.findings_mode`; markdown tier params now fail closed if `findings_mode` is missing.
- Added regression coverage that current markdown tier-pack surfaces still load with explicit `findings_mode` values and that missing `findings_mode` is rejected deterministically.
- Tightened `CS-CAN-001` definitional-sentence detection by deriving canonical-term subjects from BELGI's live `terminology.md` Term Map pointers instead of a hard-coded style subset, without reopening the old broad prose matcher.
- `CS-CAN-001` now rejects glossary-like definitional sentences for live canonical term subjects using `is a`, `is an`, or `is the` after deterministic normalization of optional outer backticks, whitespace, and case.
- Added regression coverage for the live canonical subject families used by BELGI, including the missing `is an` article form for parenthesized and hyphenated terms, plus the benign prose non-match `This is a test.`; consistency-sweep docs were re-aligned to the enforced rule.

### Notes
- Protocol/gate semantics are unchanged in this release.

## 1.4.17 — 2026-03-19

### Summary
Patch release refreshing tracked external GitHub Action pins to Node.js 24-capable releases so hosted runs stop warning on Node.js 20 deprecation, without changing BELGI workflow topology or proof semantics.

### Changed
- Repinned tracked `actions/checkout` refs from the prior SHA to `v6.0.1` commit `8e8c483db84b4bee98b60c0593521ed34d9990e8`.
- Repinned tracked `actions/setup-python` refs from the prior SHA to `v6.2.0` commit `a309ff8b426b58ec0e2a45f0f869d46889d02405`.
- Repinned tracked `actions/upload-artifact` refs from the prior SHA to `v6.0.0` commit `b7c566a772e6b6bfb58ed0dc250532a479d7789f`.
- Repinned tracked `actions/download-artifact` refs to `v5.0.0` commit `634f93cb2916e3fdff6788551b99b062d0335ce0` so the repository-verification wheel artifact handoff no longer relies on the older runtime family.
- Kept the workflow graph, gate names, proof surfaces, package-boundary checks, pinned-install semantics, and hosted governance contract unchanged.
- Updated release/version references in workflow docs, README, and workflow contract tests where `v1.4.16` would otherwise become stale after this patch release.

### Notes
- Protocol/gate semantics are unchanged in this release.

## 1.4.16 — 2026-03-19

### Summary
Patch release stabilizing hosted required-check governance, tightening repository-verification package proof topology, and removing the ambient-backend pinned-install shortcut without changing BELGI protocol semantics.

### Changed
- Added stable hosted gate jobs `repository-verification-gate` and `pull-request-proof-gate` so rulesets/branch protection can bind to explicit gate contexts instead of volatile matrix/job surfaces.
- Refactored `Repository Verification` package proof topology to:
  - build one canonical wheel
  - verify the wheel boundary on that canonical artifact
  - upload the built wheel once
  - install and smoke-test that same exact wheel artifact across the supported Python matrix
- Preserved `Repository Verification` ownership for repo/package verification and kept repo health, sweeps, boundary verification, and installed-wheel runtime proof intact.
- Preserved `Pull Request Proof` as the exact PR-head review surface and added stable gate aggregation so the required context resolves truthfully instead of remaining expected/pending.
- Kept `Pull Request Proof` label-gated by `proof:full`; without that label the gate now remains explicitly unsatisfied instead of silently relying on skipped proof jobs.
- Removed `--no-build-isolation` from `Pinned Install Proof` so pinned `pip install git+repo@sha` follows the package’s declared build-system requirements across hosted runners.
- Kept `Pinned Install Proof` manual/reusable, preserved BELGI ref keyed artifact naming, and added a final workflow-local readability gate without making it a PR-required context.
- Updated workflow operations docs, README wording, and workflow contract tests so proof surfaces and hosted required gate contexts are defined separately and truthfully.

### Notes
- Protocol/gate semantics are unchanged in this release.

## 1.4.15 — 2026-03-19

### Summary
Patch release closing remaining hosted workflow truth gaps, hardening tracked GitHub Action pinning, and fixing the reusable pinned-install bootstrap path without changing BELGI protocol semantics.

### Changed
- Renamed the three hosted workflow surfaces to purpose-first public names and file paths:
  - `Repository Verification` at `.github/workflows/repository-verification.yml`
  - `Pull Request Proof` at `.github/workflows/pull-request-proof.yml`
  - `Pinned Install Proof` at `.github/workflows/pinned-install-proof.yml`
- Preserved the three distinct hosted proof obligations:
  - repo/package verification ownership remains with `Repository Verification`
  - exact PR-head review proof remains with `Pull Request Proof`
  - reusable/manual pinned-install proof remains with `Pinned Install Proof`
- Replaced floating tracked external GitHub Action refs with full commit SHAs for `actions/checkout`, `actions/setup-python`, and `actions/upload-artifact`.
- Added `.github/scripts/check_external_action_pins.py` and wired it into `Repository Verification` so tracked workflow/action surfaces fail closed on floating external `uses:` refs.
- Fixed the reusable pinned-install bootstrap bug by moving BELGI ref / repo URL resolution into checked-in helper `.github/scripts/resolve_belgi_workflow_inputs.py`; the workflow no longer relies on inline temporary-script imports of `tools.github_vars_sanitize`.
- Updated pinned-install artifact naming so hosted artifacts now carry the resolved BELGI ref short prefix (`pinned-install-<belgi_ref_short>-<os>-<tier>`) instead of only `${{ github.sha }}`.
- Updated workflow docs, README references, CODEOWNERS, sweep authority inputs, and template comments to the renamed workflow surfaces and explicit three-surface ownership model.
- Documented the current hosted release boundary factually:
  - BELGI signs/verifies protocol evidence
  - release/publish remains manual/operator-owned
  - stronger release artifact provenance is future work, not a present claim

### Notes
- Protocol/gate semantics are unchanged in this release.

## 1.4.14 — 2026-03-10

### Summary
Patch release introducing the first canonical Tier-3 trust-anchor artifact and converging Tier-3 authority verification onto that single authority path.

### Changed
- Added `belgi/anchor/v1/TrustAnchor.json` as the first canonical Tier-3 trust-anchor artifact.
- Added `schemas/TrustAnchor.schema.json` and a shared `belgi.trust_anchor` helper that loads canonical trust-anchor bytes, validates the tracked artifact structure/signature, and enforces one pinned `sha256(bytes)` digest before Tier-3 authority fields are consumed.
- Updated Gate R `R4` so Tier-3 `genesis_seal` verification now uses canonical `TrustAnchor.anchor_payload` + `TrustAnchor.public_key_hex` instead of split hardcoded architect/philosophy/dedication/public-key constants.
- Updated the report tool to consume the same canonical Tier-3 authority helper as Gate R; Tier-3 report frontmatter is now emitted only after `genesis_seal` evidence validates under canonical `TrustAnchor.json` authority.
- Preserved `belgi/genesis/GenesisSealPayload.json` as a historical repo-local genesis reference surface and added `belgi/genesis/README.md` to make the historical-vs-canonical boundary explicit.
- Added `cryptography>=41` as a runtime package dependency because packaged Tier-3 trust-anchor loading and verification is now part of the shipped wheel surface.
- Added deterministic coverage for trust-anchor validation, digest mismatch, signature/key drift, field drift, verifier/report shared authority logic, Tier-3 evidence validation, and Tier-2 non-regression.
- Updated public docs, canonical mirrors, and sweep coverage so Tier-3 authority wording now consistently states:
  - canonical Tier-3 authority is rooted in `belgi/anchor/v1/TrustAnchor.json`
  - `genesis_seal` remains the Tier-3 evidence kind
  - internet publication is secondary only; the repo artifact is the primary authority surface

### Notes
- Tier-2 is unchanged and remains out of scope for this trust-anchor change.

## 1.4.13 — 2026-03-09

### Summary
Patch release aligning the public R8 contract to the already-implemented runtime semantics.

### Changed
- Updated Gate R and operations docs to state that `belgi adversarial-scan` command success is satisfied by `exit_code == 0` only; legacy alternative success-code wording is no longer part of the public contract.
- Documented that R8 semantic verdicting is driven by `adversarial_policy.findings_mode` after `R4` structurally accepts the required `policy.adversarial_scan` report for the current run.
- Documented the current bounded R8 verdict split:
  - `warn` mode does not fail on findings by itself when command/report/waiver structure is otherwise valid
  - `fail` mode emits `FR-ADVERSARIAL-DIFF-SUSPECT` only for unwaived findings
  - R8 can PASS when findings are present but all findings are covered by applicable active waivers allowed by the selected tier
- Updated failure taxonomy wording so `FR-ADVERSARIAL-DIFF-SUSPECT` no longer overstates `summary.failed != 0` as an unconditional fail condition.
- Added deterministic doc-contract guards for rc=`0` only, `adversarial_policy.findings_mode`, `warn` vs `fail`, and waiver-to-PASS wording across root and mirrored R8 contract surfaces.

### Notes
- Runtime behavior is unchanged; this release closes a public-truth gap only.

## 1.4.12 — 2026-03-07

### Summary
Patch release binding required policy/test report payloads to the current `LockedSpec.run_id`.

### Changed
- Gate R now rejects required `policy_report` payloads whose `payload.run_id` does not match the current `LockedSpec.run_id`, even when artifact hash and payload schema are otherwise valid.
- Gate R now rejects required `test_report` payloads whose `payload.run_id` does not match the current `LockedSpec.run_id`, closing cross-run evidence acceptance on required reports.
- Foreign-run required report payloads fail closed under `R4` with `FR-SCHEMA-ARTIFACT-INVALID`; semantic owners (`R1`, `R5`, `R7`, `R8`) only evaluate required reports after that structural current-run acceptance.
- Updated Gate R and operations docs to state the structural R4 ownership model for required-report current-run binding.
- Added regression coverage for foreign-run `policy.invariant_eval`, `policy.supplychain`, `policy.adversarial_scan`, and required `test_report` rejection, plus current-run positive controls.

### Notes
- This release closes a replay-integrity / cross-run evidence acceptance gap without expanding features.

## 1.4.11 — 2026-03-07

### Summary
Patch release locking Gate R to fail-fast / minimal-mutation doctrine on fatal early paths.

### Changed
- Gate R now stops immediately after `PROTOCOL-IDENTITY-001` failure and does not continue into mutation-producing snapshot work or later Gate R checks.
- Gate R now treats R-snapshot index/persistence failure as terminal: if the snapshot index invariant fails or the R-snapshot manifest cannot be written, later checks do not execute.
- `verify_report.results[]` now remains strictly execution-truthful on fatal early paths and contains executed checks only.
- Updated Gate R and operations docs to state the fail-fast / minimal-mutation doctrine and the terminal chain-of-custody rule for snapshot manifest/index write failure.
- Added regression coverage for protocol-identity short-circuiting, terminal snapshot write failure, normal PASS-path snapshot persistence, and doctrine wording drift.

### Notes
- Fatal early paths may now produce fewer side-effect artifacts by design.

## 1.4.10 — 2026-03-06

### Summary
Patch release tightening R7 claim boundaries and clarifying waiver control boundaries without changing runtime behavior.

### Changed
- Bounded R7 public meaning to a repo-state / change-surface signal based on workspace/revision state and declared evidence.
- Added explicit R7 non-claims: no SBOM generation/verification, provenance attestation, dependency vulnerability scanning, or full dependency/toolchain inventory claim in v1.
- Corrected tier-parameter ownership so `envelope_policy.pinned_toolchain_refs_required` remains documented under Q5 and is no longer attributed to R7.
- Clarified waiver boundary language to distinguish repo-mechanical enforcement from operational controls outside in-repo proof.
- Added deterministic doc/contract guards for R7 non-claims, Q5/R7 tier-param ownership, and waiver mechanical-vs-operational wording.

### Notes
- Runtime behavior is unchanged; this release is contract truthfulness hardening.

## 1.4.9 — 2026-03-04

### Summary
Patch release removing hidden C3 pipeline prerequisites and finalizing C3 prompt-hash/cache contracts.

### Changed
- C3 canonical source resolution no longer requires pre-staged `.belgi/engine/c3_canonicals`; when staged canonicals are absent, C3 deterministically materializes canonicals from BELGI bundled canonicals plus the active protocol pack content.
- Staged C3 canonicals are now cache-safe: `.belgi/engine/c3_canonicals` is used only when cache metadata matches the active protocol-pack identity (`pack_id`, `manifest_sha256`, `pack_name`); mismatched/missing metadata is ignored and cache is rebuilt deterministically.
- `belgi run` no longer auto-stages C3 canonicals as a correctness requirement; manual stage execution and orchestrated execution now use the same C3 acceptance contract.
- C3 prompt hash validation now requires hashes for selected prompt blocks only (by `LockedSpec.tier.tier_id`), where each selected hash must equal `sha256(C1_rendered_block_bytes)`, and rejects missing/mismatched selected hashes deterministically.
- Added regression coverage for:
  - C3 execution without staged canonicals
  - selected-only prompt hash completeness and mismatch fail-closed behavior
  - manual C1→C3 handoff parity with orchestrated run semantics

### Notes
- Extra prompt hash keys for non-selected blocks are allowed and ignored by contract.
- This release may tighten failure behavior for users who previously depended on implicit staging or hash-map auto-completion.

## 1.4.8 — 2026-03-04

### Summary
Patch release aligning template/doc claims with enforced behavior for C1/C3 evidence contracts.

### Changed
- Updated `belgi/templates/PromptBundle.blocks.md` to remove the incorrect `tiers/tier-packs.json` input claim for C1 determinism (both byte-identity and repo-file-input claims).
- Updated `belgi/templates/DocsCompiler.template.md` to state that per-file normalized output hashes are surfaced via `bundle/docs_bundle_manifest.json` (`files[]`), not as required direct fields in `docs_compilation_log` payload.
- Updated `docs/operations/running-belgi.md` to document the strict C3 out-log contract: `--out-log` MUST be `docs/docs_compilation_log.json` for deterministic discovery/indexability.
- Added deterministic template/doc drift guards for the three claim classes above.

### Notes
- Runtime behavior is unchanged; this release is contract truthfulness hardening.

## 1.4.7 — 2026-03-04

### Summary
Patch release aligning the DocsCompiler bundle-hash template contract with the implemented C3 algorithm.

### Changed
- Updated `belgi/templates/DocsCompiler.template.md` B3.5 to match the engine’s non-circular bundle hash semantics:
  - `bundle_sha256` excludes `docs_bundle_manifest.json`,
  - hash payload format is `<path>\\n<sha256>\\n` in sorted path order,
  - `bundle_root_sha256` is explicitly derived from `docs_bundle_manifest_sha256` and `bundle_sha256`.
- Added deterministic regression shields for C3 hash semantics and template drift.

### Notes
- This is SSOT alignment only; compiler behavior is unchanged.

## 1.4.6 — 2026-03-04

### Summary
Patch release removing a non-operative tier policy surface from declared contracts.

### Changed
- Removed non-operative tier parameter `test_policy.flaky_handling` from tier pack definitions, rendered tier pack docs, and tier→gate parameter map declarations.
- Relaxed TierPacks schema requirement so `test_policy.flaky_handling` is no longer required.
- Added regression guards to prevent reintroduction of `test_policy.flaky_handling` in tier packs and gate parameter map declarations.

### Notes
- No change to gate outcomes except removing an unenforced declared parameter.
- Compatibility posture remains non-tightening: schema was relaxed, not tightened.

## 1.4.5 — 2026-03-04

### Summary
Patch release aligning adversarial scan command-success semantics with Gate R command enforcement.

### Changed
- `belgi adversarial-scan` now returns exit code `0` on successful execution even when findings exist; findings remain encoded only in `policy.adversarial_scan` payload (`summary.failed`, `findings`).
- Gate R R8 command validation now treats only `exit_code == 0` as command success in structured command logs (no alternate success code).
- Added regression coverage for:
  - non-zero adversarial command record => `FR-COMMAND-FAILED`
  - `exit_code == 0` + valid report with `summary.failed != 0` => `FR-ADVERSARIAL-DIFF-SUSPECT`

### Notes
- Any downstream usage that interpreted non-zero adversarial scan exit codes as a findings signal was never part of the stable contract; findings are policy-report data.
- No tier enablement or schema changes.

## 1.4.4 — 2026-03-04

### Summary
Patch release repairing Gate R category ownership boundaries and waiver-scope wording alignment.

### Changed
- R4 no longer pre-validates `policy.supplychain` and `policy.adversarial_scan`, so required report ownership for missing/duplicate/invalid cases is now deterministically handled by R7/R8.
- Gate R and waiver operations docs now state R3 waiver scope matching as normalized repo-relative prefix semantics, not substring semantics.
- Added regression locks for R7/R8 ownership and for substring-vs-prefix waiver scope behavior.
- Added a minimal wording guard test to prevent reintroduction of substring semantics in normative matching text.

### Notes
- This is a contract-repair patch that may change primary-cause category observed by consumers previously relying on R4 preemption.
- No tier enablement changes, no schema changes, and no producer exit-code behavior changes.

## 1.4.3 — 2026-03-04

### Summary
Patch release hardening Gate R ordered-results serialization so report ordering and primary-cause selection cannot diverge.

### Changed
- Gate R now serializes `PROTOCOL-IDENTITY-001` into `verify_report.results[]` on every run (PASS/FAIL), with fixed first position.
- Gate R now serializes `R-SNAPSHOT-INDEX-001` on every run and keeps it in fixed second position.
- Gate R now serializes `R-OVERLAY-001` in fixed third position when `--overlay` is supplied, and omits it when overlay is not supplied.
- Gate R verdict primary-cause selection now uses the same ordered result sequence that is serialized into `verify_report.results[]`.
- Gate R documentation now states the ordered-results contract including preflight conditionality.

### Notes
- This tightens consumer-visible `results[]` ordering semantics for Gate R; downstream tooling must treat `results[]` as the canonical primary-cause source.
- No tier enablement changes, no new evidence kinds, and no producer exit-code behavior changes.

## 1.4.2 — 2026-03-03

### Summary
Patch release hardening waiver safety and deterministic expiry replay.

### Changed
- `belgi waiver new` now emits fail-closed drafts with `status: "revoked"` until explicitly activated.
- Gate Q Q6 rejects placeholder/template content in critical waiver fields and requires explicit active status for applied waivers.
- Waiver expiry is evaluated against `EvidenceManifest.anchored_time_utc`; replay verification uses the same anchor and fails closed when the anchor is missing/invalid.

### Notes
- Replay determinism: waiver expiry outcomes are anchored to evidence (`anchored_time_utc`), not ambient wall-clock time.
- No gate ordering changes, no tier expansion, and no new evidence kinds.

## 1.4.1 — 2026-03-03

### Summary
Bookkeeping patch release aligning public-facing text with already-landed enforcement behavior.

### Changed
- Protocol pack identity SSOT clarified and enforced as identity tuple only (`pack_id`, `manifest_sha256`, `pack_name`); `source` is operational context and not an identity field.
- C3 protocol-pack identity enforcement is fail-closed, removing bypass behavior.
- CODEOWNERS dead-path guard is added and enforced fail-closed.
- Wheel publish boundary SSOT for v1.4.x is mechanically enforced by CI via the wheel boundary checker.

### Notes
- No canonical chain/stage ordering changes.
- Public summary remains adopter-agnostic.

## 1.4.0 — 2026-03-02

### Summary
Release focused on operator-facing run ergonomics, deterministic evidence navigation, and verification-path hardening.

### Added
- Operator-oriented CLI output refinements for clearer GO/NO-GO status reading:
  - compact status blocks with deterministic evidence pointers
  - bounded open-helper guidance with optional link-capable rendering where supported
- Deterministic run workspace guidance and pointer-bridge behavior for operator-facing paths under `.belgi/runs/`.
- Waiver helper ergonomics for deterministic draft/apply flows with strict matching posture and explicit human approval control.

### Changed
- `belgi verify` selection flow hardening:
  - deterministic selection precedence (`explicit`, `pointer`, `latest`)
  - stale/invalid pointer candidates are skipped deterministically
  - fail-closed user error when no valid pointer/store candidate exists
- Machine first-line JSON contract for CLI result output remains stable.
- Operator documentation consolidation and CLI usage/triage flow clarity in operations docs.

### Notes
- No protocol semantics changes.
- No gate ordering changes.
- No schema contract expansion.
- Public summary remains adopter-agnostic and verification-first.

## 1.3.0 — 2026-02-28

### Summary
Capability-focused release for run revision authority, stage discoverability parity, workflow drift controls, and operator guidance hardening.

### Added
- Authoritative revision-binding evidence for `belgi run`:
  - schema-valid `policy.revision_binding` artifact indexed in `EvidenceManifest`
  - explicit binding fields for `base_revision` and `evaluated_revision` (stable SHA40 values)
- Repo-local stage forwarders on primary CLI:
  - `belgi stage c1|q|r|c3|s seal|s verify`
  - thin-wrapper forwarding to canonical `chain.*` entrypoints
- Private workflow safety helper for repository variables:
  - `tools/github_vars_sanitize.py` with allowlist filtering and secret-like key rejection

### Changed
- Run correctness hardening:
  - base/evaluated revision discovery is fail-closed and SHA40-only
  - `LockedSpec.upstream_state.commit_sha` and Gate R revision wiring are aligned to authoritative base/evaluated inputs
  - supplychain scan revision labeling now binds to the evaluated revision
- CLI stage forwarder reliability:
  - normalized exit-code mapping under CLI SSOT `{0,10,20,30}`
  - canonical stage module rc mapping preserved (`2 -> 10`, `3 -> 20`)
  - missing repo-local stage modules return actionable USER_ERROR
- Workflow drift controls:
  - ACT-context upload suppression hardened with explicit override (`BELGI_FORCE_ACT`)
  - repository variable consumption restricted to allowlisted keys with fail-closed secret-like detection
  - run-smoke call-sites aligned to explicit `--base-revision` usage
- Operations/docs clarity:
  - updated repo-local vs wheel-only boundaries for stage usage
  - evaluated revision examples now use stable SHA40 guidance (no moving refs for canonical examples)

### Notes
- Public entry intentionally records shipped capability surfaces only; private qualification/proof packets remain under private `temp/` operations paths.

## 1.2.0 — 2026-02-27

### Summary
Artifact-backed release in capability buckets: infra orchestration/verify, tier+waiver realism, CI proof surfaces, sweep hardening, operator ergonomics, and exit-code SSOT stabilization.

### Added
- Deterministic run workspace orchestration and verification surfaces:
  - run-keyed attempt layout under `.belgi/runs/<run_key>/<attempt_id>/`
  - `belgi verify` integrity checks over run summary/manifests
- Tier-1 CI/template proof surfaces:
  - reusable workflow and template wiring for BELGI checks
  - immutable BELGI ref pin validator (`BELGI_REF` must be 40-hex SHA)
  - cross-platform smoke helper used by workflows
  - PR label-gated proof workflow (`proof-tier1.yml`) with downloadable audit artifacts
- Sweep managed-surface hardening:
  - expanded authoritative sweep input coverage for managed docs/workflows/scripts/templates
  - `CS-SWEEP-002` invariant + regression lock to fail on unlisted managed surfaces
- Operator ergonomics helpers:
  - `scripts/belgi_latest_run.py`
  - `scripts/belgi_latest_run.ps1`
  - `scripts/belgi_latest_run.sh`
  - `scripts/belgi_wip_commit_run_reset.ps1`
  - `docs/operations/cli.md`

### Changed
- Run/verify contract hardening:
  - stabilized machine-readable first-line result and classed exit-code model for infra usage
  - tier obligations sourced from tier packs (SSOT) and enforced across gate/orchestrator paths
  - legacy `rc=3` normalization aligned to `USER_ERROR (20)` and exit-code SSOT centralized under `docs/operations/exit-codes.md`
- Tier policy and waiver realism:
  - Tier-0 findings signal surfaced in machine/run-summary outputs
  - tier-driven adversarial findings policy (`warn` tier-0, `fail` tier-1+)
  - Tier-1 applied waiver ingestion wired into `LockedSpec.waivers_applied` with seal binding and deterministic reporting
- Pack/mirror and drift protections:
  - protocol-pack mirrors updated for tier/waiver policy surfaces
  - consistency/render guardrails strengthened for deterministic drift detection
- Engine smoke and packaging reliability:
  - CI smoke/pin flows hardened for reproducible install/runner behavior
  - template/canonical hydration fixes to prevent repo-layout coupling in run execution
- Portability follow-up:
  - `scripts/belgi_latest_run.sh` now prefers `python3`, then `python`, else fail-closed with exit code `2`

### Fixed
- Tier-1 test evidence production no longer depends on adopter-specific test path assumptions.
- Tier-1 adopter-pytest existing-target runtime path corrected with regression coverage.
- Template hydration ordering corrected to preserve scan-first execution contract.

### Notes
- Public entry intentionally omits private pack paths; authoritative proof artifacts remain in private evidence packs.

## 1.1.1 — 2026-02-17

### Summary
Terminology hardening for verification-first protocol language and deterministic drift enforcement.

### Changed
- Clarified the bounded claim in canonicals to: `Deterministic verification of probabilistic proposals within a declared Environment Envelope.`
- Added canonical terminology boundaries for Verification vs Validation vs Auditability and usage rules for `audited` language.
- Propagated terminology updates across key docs (runbook, tiers, schemas, and mirrored protocol-pack docs), including Stage Q heading normalization (`Lock & Verify`) and schema-specific wording (`schema-validate`) where appropriate.
- Integrated `CS-TERM-001` (Terminology Drift Guard) into the existing consistency sweep path (no separate CI job), with fail-closed sorted `file:line` remediation.

## 1.1.0 — 2026-02-13

### Summary
Local CI reproducibility + adopter integration surfaces.

### Added
- Adopter bootstrap and overlay surfaces in BELGI CLI:
  - `belgi init` (repo-local adopter defaults, protocol-pack pin awareness)
  - `belgi policy stub` (deterministic schema-valid `PolicyReportPayload`)
  - `belgi policy check-overlay` (optional additive fail-closed overlay preflight)
  - `belgi run new` and `belgi manifest add` (deterministic run workspace + evidence mutation helpers)
- Deterministic adopter demo proof contract:
  - overlay check fails when required policy check is missing
  - overlay check passes only after schema-valid policy report is produced and indexed in `EvidenceManifest`
  - deterministic run artifact output for replay (`overlay_check_report.json`)

### Changed
- Overlay policy-report scanning hardened: non-`PolicyReportPayload` `policy_report` artifacts are ignored during overlay check-id collection, while required check IDs remain fail-closed.
- Local CI reproducibility posture hardened around pinned BELGI checkout and deterministic compatibility helpers in adopter demo scripts.
- Maintainer/operator docs updated for local `act` verification path (full runner image + local token requirement for cross-repo checkout).
- Deterministic sweep/fixture outputs recalibrated through canonical converge (`dev_sync`) after 1.1.0 surface changes.

### Notes
- Canonical semantics were preserved in 1.1.0 (`schemas/`, `gates/`, `tiers/` meaning unchanged).
- No new `EvidenceManifest.artifacts[].kind` values were introduced for adopter needs.
- Optional integrations remain opt-in via env flags; integration tests skip by default unless explicitly enabled.

## 1.0.1 — 2026-02-09

### Documentation
- Refresh example identifiers used in docs.

### Tooling
- Add maintainer marker comments (non-functional).

### Policy
- Sync sweep fixtures (calibration) .

## 1.0.0 — 2026-01-20

### Release
- Declared the verification kernel and public artifact contracts stable under SemVer 1.0.0.
- Published surface focuses on deterministic verification (schemas, gate contracts, and the builtin protocol pack `v1`).
- Repo-local governance and operator tooling remains intentionally separated from the shipped pack/wheel surface.
