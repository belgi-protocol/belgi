# Changelog
This changelog is a factual record of protocol mechanics, documentation, and enforcement changes in this repository.
It does not contain experimental results or performance claims.

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
