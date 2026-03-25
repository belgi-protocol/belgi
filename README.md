# BELGI

<p align="center">
  <img alt="BELGI" src="assets/brand/logo-primary.svg#gh-light-mode-only" width="420" />
  <img alt="BELGI" src="assets/brand/logo-reverse.svg#gh-dark-mode-only" width="420" />
</p>

<div align="center">
  <a href="https://github.com/belgi-protocol/belgi/actions/workflows/repository-verification.yml">
  <img src="https://img.shields.io/github/actions/workflow/status/belgi-protocol/belgi/repository-verification.yml?branch=main&label=Repository%20Verification&style=flat-square&logo=github" alt="Repository Verification" />
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
- **Two-gate verification posture**: Gate Q (lock & verify) and Gate R (verify bundle) separate “spec correctness” from “execution correctness.”
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

# Create a deterministic run workspace
belgi run new --repo . --run-id run-demo-001

# Generate deterministic PolicyReportPayload stub (adopter overlay checks)
belgi policy stub --out .belgi/runs/run-demo-001/artifacts/policy.overlay.json --run-id run-demo-001 --check-id OVERLAY-REQ-001

# Add/update artifact in EvidenceManifest deterministically
belgi manifest add --repo . --manifest .belgi/runs/run-demo-001/EvidenceManifest.json --artifact .belgi/runs/run-demo-001/artifacts/policy.overlay.json --kind policy_report --id policy.overlay --media-type application/json --produced-by R

# Evaluate overlay requirements only (installed BELGI, no repo-local chain modules)
belgi policy check-overlay --repo . --evidence-manifest .belgi/runs/run-demo-001/EvidenceManifest.json --overlay belgi_pack

# Verify builtin protocol pack (installed package)
belgi pack verify --builtin

# Verify a pack directory (repo checkout)
python -m belgi.cli pack verify --in belgi/_protocol_packs/v1

# Check an evidence bundle (demo-grade checker, --demo required)
belgi bundle check --in path/to/bundle --demo
```

### Publish Surface (Wheel vs Repo-local)

Wheel boundary, publication posture, and builtin protocol-pack drift rules are owned by:
- [CANONICALS.md#wheel-vs-repo-local](CANONICALS.md#wheel-vs-repo-local)
- [CANONICALS.md#publication-posture](CANONICALS.md#publication-posture)
- [tools/README.md](tools/README.md)

Use those owner docs for exact wheel contents, repo-only authoring boundaries, and pack-verification or drift-check commands.

### Repo-local Development

#### Verifier vs. fixer flow (important)

BELGI’s determinism guarantee is about **verification**: the same inputs must verify to the same outputs. CI is **verifier-only** and must not mutate tracked artifacts.

Local development is allowed to **repair** governed reports and protocol-pack mirrors after you make changes.

- **Local fixer (calibration)**: updates tracked artifacts that still belong to BELGI main repo, such as governed reports and pack mirrors. Those changes are expected, transparent, and must be committed.
- **CI verifier**: validates the repo state; it must never auto-fix or paper over drift.

When you change repo inputs during development (schemas, tier rules, compilers, pack mirrors), some **tracked** outputs become stale. CI will fail because it refuses to rewrite those files for you.

Example (what this looks like in practice):
- You change a tier rule or a schema (e.g. add a required field).
- Now previously committed governed reports or pack mirrors no longer match the new invariants.
- CI runs the verifier surfaces and reports deterministic drift.
- Locally, you run the fixer (`./scripts/dev_sync.ps1`) which refreshes the affected tracked artifacts.
- You commit those updates; CI then passes because it is validating the same committed state.

If CI fails on consistency or pack drift, run the local fixer and commit the resulting changes. CI only verifies what’s in the repo; it must not mutate artifacts during verification.

Operator CLI quickstart and NO-GO triage SSOT: [docs/operations/cli.md](docs/operations/cli.md)

Operator Anchors prep and boundary guide: [docs/operations/operator-anchors.md](docs/operations/operator-anchors.md)

Chain-module reference commands (`python -m chain.*`): [docs/operations/running-belgi.md](docs/operations/running-belgi.md)

Hosted proof surfaces, required gate contexts, local workflow rehearsal, and branch-governance details: [docs/operations/workflows.md](docs/operations/workflows.md)

Repo-local maintenance commands and tool contracts: [tools/README.md](tools/README.md)

Common repo-local repair entrypoint from the workspace:

```bash
./scripts/dev_sync.ps1
```

### Commit Metadata Privacy

If you do not want your personal email in public commit metadata, use your GitHub noreply address and update git config:

```bash
git config --global user.email "123456+username@users.noreply.github.com"
git config --global user.name "Your Name"
```

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

## Trademark Notice

BELGI™ is a trademark of the BELGI Protocol Founding Maintainer.
The BELGI code is available under the Apache 2.0 License. However, this license does not grant permission to use the 'BELGI' trade name, trademarks, service marks, or product names, except as required for reasonable and customary use in describing the origin of the Work.
