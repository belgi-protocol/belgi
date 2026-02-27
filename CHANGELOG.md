# Changelog
This changelog is a factual record of protocol mechanics, documentation, and enforcement changes in this repository.
It does not contain experimental results or performance claims.

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
  - `docs/operations/triage.md`

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
