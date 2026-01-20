# Policy Fixtures

This directory contains deterministic test fixtures for Gate Q, Gate R, and Seal (stage S) tooling.

## Public / Internal split (vault posture)

This repo **ships one runnable fixture root**:

- `public/` — safe-to-publish fixtures (default; minimal “basics”)

It also contains:

- `public/seal/` — Seal producer fixtures (run via the seal fixture sweep; exercises `chain/seal_bundle.py`)
- `public/gate_s/` — Gate S verifier fixtures (run via the Gate S fixture sweep; exercises `chain/gate_s_verify.py`)
- `internal/` — **placeholder only** (this repo tracks only `.gitignore` + `HALLOFFAME.md`)

Internal vault note (public-safe):
- The full internal fixture suite is maintained in a separate access-controlled repository.
- This repo intentionally does not ship those fixtures to reduce bypass surface and eliminate accidental publication risk.

The fixture sweep tool accepts `--fixtures-root` to select a fixture tree. In this repo, the supported/sane value is `policy/fixtures/public` (the default). `policy/fixtures/internal` is not a runnable suite in this repository.

## Structure

```
fixtures/
├── public/          # Public fixtures root
│   ├── gate_q/
│   │   └── cases.json
│   ├── gate_r/
│   │   └── cases.json
│   ├── seal/         # Stage S producer fixtures (seal tool)
│   │   └── cases.json
│   ├── gate_s/       # Stage S verifier fixtures (Gate S)
│   │   └── cases.json
├── internal/         # Private vault placeholder (not a runnable suite in  this repo)
│   ├── .gitignore
│   └── HALLOFFAME.md
└── README.md         # This file
```

## Running Fixtures

```bash
# Run PUBLIC fixture sweep (default)
python -m tools.sweep fixtures-qr --out-dir temp/fixture_sweep

# Explicitly select the published fixture root
python -m tools.sweep fixtures-qr --fixtures-root policy/fixtures/public --out-dir temp/fixture_sweep

# Run Gate S verifier fixture sweep (validates stage S verifier)
python -m tools.sweep fixtures-s --out-dir temp/gate_s_fixture_sweep

# Run seal fixture sweep (validates stage S seal tool)
python -m tools.sweep fixtures-seal --out-dir temp/seal_fixture_sweep
```

Notes:
- The fixture sweep may emit non-fatal `WARN:` lines about fixture “physical reality” (for example, a fixture that intentionally omits an input file to validate deterministic failure behavior).
- For `fixtures-qr`, the PASS/FAIL expectation is `expected_exit_code` and `expected_primary`.
- For `fixtures-s` and `fixtures-seal`, the PASS/FAIL expectation is `expected_exit_code`.

## Stage S: Gate vs Seal (read this once)

Stage S has **two separate roles**, with separate fixture suites:

- **Seal (producer)**: `chain/seal_bundle.py` creates a `SealManifest.json`.
	- Swept via: `python -m tools.sweep fixtures-seal`
	- Fixtures live in: `policy/fixtures/public/seal/`
	- A “bad signature” here means: the producer is given an invalid/incorrect `--seal-signature-file` and must fail-closed (NO-GO) **without emitting an invalid manifest**.

Fixture signing keys (anti-footgun, fail-closed):
- Fixture-only signing keys MUST live under `policy/fixtures/`.
- If `--seal-private-key` is under `policy/fixtures/`, the operator MUST pass `--fixture-mode` or the tool fails closed.
- If `--fixture-mode` is set, `--seal-private-key` MUST be under `policy/fixtures/` or the tool fails closed.
- Real/private production keys MUST NOT be stored under `policy/fixtures/`.

- **Gate S (verifier)**: `chain/gate_s_verify.py` verifies an existing `SealManifest.json`.
	- Swept via: `python -m tools.sweep fixtures-s`
	- Fixtures live in: `policy/fixtures/public/gate_s/`
	- A “bad signature” here means: a `SealManifest.json` exists but its signature fields are invalid or non-verifying, so Gate S must return NO-GO.

## Fixture Naming Convention

- `q<N>_*` / `r<N>_*` — Targets check Q<N> or R<N>
- `*_pass*` — Expected to PASS (exit code 0)
- All others — Expected to NO-GO (exit code 2)

## cases.json Format

Each gate's `cases.json` contains:
- `case_id`: Directory name
- `expected_exit_code`: 0 (GO), 2 (NO-GO), or 3 (error)
- `expected_primary`: The check ID expected as primary failure cause
- `paths`: Relative paths to fixture artifacts

## Defense-in-Depth Checks (Not Fixture-Testable)

Some Gate Q checks exist as second-layer guardrails but cannot be reached through normal execution flow. They guard against bugs in earlier checks.

### Unreachable Checks

| Check ID | Purpose | Shadowed By |
|----------|---------|-------------|
| Q4 | Constraints presence (allowed_paths non-empty + forbidden_paths present) | Q-INTENT-003 |
| Q-CONSTRAINT-001 | LockedSpec.constraints path normalization | Q-INTENT-003 |
| Q-DOC-001 | LockedSpec.doc_impact path normalization | Q-INTENT-003 |
| Q-DOC-002 | doc_impact tier enforcement (presence + note_on_empty) | LockedSpec schema (tier allOf) + schema note_on_empty rule |

**Why unreachable:** Q-INTENT-003 validates IntentSpec↔LockedSpec mapping
consistency. If IntentSpec has valid (normalized) paths but LockedSpec has
non-normalized paths, Q-INTENT-003 catches the mismatch before Q-CONSTRAINT-001
or Q-DOC-001 can run.

**Why kept:** Defense-in-depth. If Q-INTENT-003 has a bug and incorrectly
passes, these checks provide a second layer of protection.

**Coverage:** The coverage report correctly shows these as "uncovered" — this
is expected and documented behavior.

### Gate R command obligation subchecks

Gate R includes defense-in-depth subchecks like:
- `R1.command_required.invariant-eval`
- `R5.command_required.run-tests`
- `R6.command_required.verify-attestation`
- `R7.command_required.supplychain-scan`
- `R8.command_required.adversarial-scan`

These are evaluated after the main R1–R8 checks and are not expected to become
the **primary** failure in normal operation, because the corresponding primary
checks (R1/R5/R6/R7/R8) already enforce the same command obligations.

## Adding New Fixtures

Fixture generation is handled by maintainers. Pre-generated fixtures are
committed to this directory and validated via `tools/sweep.py fixtures-qr`.
