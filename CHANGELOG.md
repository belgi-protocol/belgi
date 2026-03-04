# Changelog
This changelog is a factual record of protocol mechanics, documentation, and enforcement changes in this repository.
It does not contain experimental results or performance claims.

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
