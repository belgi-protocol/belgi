# BELGI

<p align="center">
  <img alt="BELGI" src="assets/brand/logo-primary.svg#gh-light-mode-only" width="420" />
  <img alt="BELGI" src="assets/brand/logo-reverse.svg#gh-dark-mode-only" width="420" />
</p>

<div align="center">
  <a href="https://github.com/belgi-protocol/belgi/actions/workflows/ci.yml">
  <img src="https://img.shields.io/github/actions/workflow/status/belgi-protocol/belgi/ci.yml?branch=main&label=Gate%20R%20Verifier&style=flat-square&logo=github" alt="CI" />
</a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square&logo=apache" alt="License" />
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Python-3.10_%7C_3.11_%7C_3.12_%7C_3.13-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python Versions" />
  </a>
  <a href="TRADEMARK.md">
    <img src="https://img.shields.io/badge/Trademark-Policy-0A2A66.svg?style=flat-square" alt="Branding" />
  </a>
</div>

<br />

A control protocol for shipping software under probabilistic cognition (LLMs, tired humans, distributed teams).

BELGI does not promise deterministic thinking. It promises deterministic *verification* and a reproducible audit trail: you can point at bytes, hashes, and a declared environment envelope and say: “this is what happened.”

Read the whitepaper: [WHITEPAPER.md](WHITEPAPER.md)

Branding and trademark policy: [TRADEMARK.md](TRADEMARK.md)

## The Mechanical Truth

If your process can’t be checked deterministically, you don’t have a process — you have a story.

BELGI is the boring part done correctly: strict schemas, deterministic gates, byte-level hashes, and evidence you can seal.
No vibes. No “trust me.” Just artifacts.

## Features

- **Deterministic gates**: fail-closed checks for intent, evidence, and verifier obligations.
- **Evidence by bytes**: artifacts are indexed by `sha256(bytes)` — newline drift is a real failure mode, treated as such.
- **Schema-first contracts**: `LockedSpec`, `GateVerdict`, `EvidenceManifest`, `SealManifest`, `Waiver` are strict JSON schema artifacts.
- **Two-phase validation posture**: Gate Q (lock & verify) and Gate R (verify bundle) separate “spec correctness” from “execution correctness.”
- **Tier packs**: parameterized tolerances and required evidence sets (no hidden bypasses).
- **Repro + audit trail**: deterministic reports and a stable failure taxonomy to prevent expectation-gaming.

Example run stamp used in docs: `bk_ycanary_7f3a9c2d`

## Quick Start

BELGI requires full verification coverage for public release. See [CANONICALS.md](CANONICALS.md), [gates/GATE_Q.md](gates/GATE_Q.md), and [gates/GATE_R.md](gates/GATE_R.md) for the verification architecture and contracts.

For current progress, see gate verification test results in CI/CD.

### Installation

```bash
pip install belgi
```

### CLI Commands

```bash
# Package info
belgi about

# Initialize adopter-local BELGI workspace defaults (idempotent)
belgi init --repo .

# Verify builtin protocol pack (installed package)
belgi pack verify --builtin

# Verify a pack directory (repo checkout)
python -m belgi.cli pack verify --in belgi/_protocol_packs/v1

# Check an evidence bundle (demo-grade checker, --demo required)
belgi bundle check --in path/to/bundle --demo
```

### Publish Surface (Wheel vs Repo-local)

Canonical definitions:
- [CANONICALS.md#wheel-vs-repo-local](CANONICALS.md#wheel-vs-repo-local)
- [CANONICALS.md#publication-posture](CANONICALS.md#publication-posture)

Published wheel (`pip install belgi`) includes:
- `belgi/_protocol_packs/v1/**` (builtin protocol pack mirror + `ProtocolPackManifest.json`)
- `belgi/templates/**` (publish-safe templates)
- `belgi` CLI entrypoint (`belgi about`, `belgi pack verify`, `belgi bundle check --demo`)

Repo-local only (not shipped in the wheel by design):
- `chain/` (reference deterministic gate implementations)
- `tools/` (developer/operator fixers and sweeps; may mutate tracked artifacts when invoked in fixer mode)
- `wrapper/` (optional forwarders)

SSOT/mirror rule:
- Canonical specs live at repo root: `gates/`, `schemas/`, `tiers/`.
- The wheel ships a mirror at `belgi/_protocol_packs/v1/`; pack mirror drift is forbidden and must be detected before publishing (repo-local: `python -m tools.check_drift`).

### Repo-local Development

#### Verifier vs. fixer flow (important)

BELGI’s determinism guarantee is about **verification**: the same inputs must verify to the same outputs. CI is **verifier‑only** and must not mutate tracked artifacts.

Local development is allowed to **repair** fixtures and governed reports after you make changes. This is expected and required for keeping the repo invariant surface consistent.

- **Local fixer (calibration)**: updates tracked artifacts (fixtures, report hashes, seals) to restore repo invariants after edits. This is expected, transparent, and must be committed.
- **CI verifier**: validates the repo state; it must never auto‑fix or “paper over” drift.

When you change repo inputs during development (schemas, tier rules, fixtures, compilers), some **tracked** outputs become stale (hashes, derived summaries, fixture seals). CI will fail because it refuses to rewrite those files for you.

Example (what this looks like in practice):
- You change a tier rule or a schema (e.g. add a required field).
- Now the previously committed fixtures/reports no longer match the new invariants.
- CI runs the verifier sweeps and reports deterministic drift (hash mismatch / missing required fields / fixture exit-code mismatch).
- Locally, you run the fixer (`./scripts/dev_sync.ps1`) which regenerates the affected tracked artifacts (and rehashes references).
- You commit those updates; CI then passes because it is validating the same committed state.

If CI fails on sweep/fixtures, run the local fixer and commit the resulting changes. CI only verifies what’s in the repo; it must not mutate artifacts during verification.

Canonical chain runbook (exact `chain/*` commands + when-to-run-what): [docs/operations/running-belgi.md](docs/operations/running-belgi.md)

Adopter dev-tier runbook (`belgi init`, run-local workspace, Gate R overlay mode): [docs/operations/runbook_dev_tier.md](docs/operations/runbook_dev_tier.md)

From the repo workspace:

```bash
# Local fixer (single command; may modify tracked artifacts)
./scripts/dev_sync.ps1

# CI verifier equivalents (must not modify files)
python -m tools.sweep consistency --repo .
python -m tools.sweep fixtures-qr --repo .
python -m tools.sweep fixtures-s --repo .
python -m tools.sweep fixtures-seal --repo .
```

See [tools/README.md](tools/README.md) for dev tool documentation.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

## Trademark Notice

BELGI™ is a trademark of the BELGI Protocol Founding Maintainer.
The BELGI code is available under the Apache 2.0 License. However, this license does not grant permission to use the 'BELGI' trade name, trademarks, service marks, or product names, except as required for reasonable and customary use in describing the origin of the Work.
