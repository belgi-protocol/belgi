# Evidence ownership (engine-owned, deterministic)

This note defines which BELGI step is the canonical **owner** of each runtime artifact, and which artifacts must exist for Gate Q/R/S.

## Canonical chain ownership

- **C1** (`chain.compiler_c1_intent`)
  - Writes (repo-relative paths are caller-defined):
    - `LockedSpec.json`
    - `bundle/prompt_bundle.bin`
    - `bundle/policy.prompt_bundle.json`
    - `prompt_block_hashes.json`

- **Q seed (engine primitive; new)** (`python -m tools.belgi manifest-init`)
  - Writes:
    - `EvidenceManifest.Q.seed.json` (schema-valid, deterministic)
  - Purpose:
    - binds *governed repo bytes* (sha256 over files under `--repo`) into `EvidenceManifest.artifacts[]` so Gate Q can evaluate evidence sufficiency without any wrapper-generated JSON.

- **Gate Q** (`chain.gate_q_verify`)
  - Reads:
    - `IntentSpec.core.md`
    - `LockedSpec.json`
    - `EvidenceManifest.Q.seed.json`
  - Writes:
    - `GateVerdict.Q.json`

- **R helpers (engine primitives)**
  - `python -m tools.belgi command-record` updates `EvidenceManifest.commands_executed` deterministically (fixed timestamps when `--deterministic`).
  - `python -m tools.belgi manifest-update` adds/replaces one `EvidenceManifest.artifacts[]` entry deterministically.
  - `python -m tools.rehash evidence-manifest` recomputes hashes from governed bytes (defense-in-depth).

- **Gate R** (`chain.gate_r_verify`)
  - Reads:
    - `LockedSpec.json`, `GateVerdict.Q.json`, `EvidenceManifest.R.json`
  - Writes:
    - `GateVerdict.R.json` (+ verify report, and optional R snapshot manifest)

- **C3** (`chain.compiler_c3_docs`)
  - Writes:
    - docs outputs (including `docs_compilation_log` evidence artifacts)
    - `EvidenceManifest.final.json` (append-only extension)

- **SEAL** (`chain.seal_bundle`)
  - Writes:
    - `SealManifest.json`

- **Gate S** (`chain.gate_s_verify`)
  - Reads:
    - `LockedSpec.json`, `SealManifest.json`, `EvidenceManifest.final.json`
  - Writes:
    - `GateVerdict.S.json`

## Runtime-mandatory inputs

- **Gate Q requires** a schema-valid EvidenceManifest and enforces required evidence kinds per tier (`required_evidence_kinds_q`).
  - Required kinds are **tier/policy-defined** (protocol pack); public fixtures commonly exercise `command_log`, `policy_report`, and `schema_validation`.

- **Gate R requires** evidence sufficiency kinds per tier (`required_evidence_kinds`) plus the required command log shape (`command_log_mode`).

- **Gate S requires** a final EvidenceManifest plus the SealManifest.

Important: **schema-valid != gate-sufficient**.
- `manifest-init` guarantees repo-root confinement, deterministic hashing, and schema validity.
- Gates still enforce tier/policy sufficiency and will return **NO-GO** if required evidence kinds/semantics are missing.

## Wrapper/adopter command example: run Gate Q with zero wrapper JSON generation

Assume the governed repo root is passed as an absolute path in `--repo` and a run directory exists under that root.

1) After C1 produced `LockedSpec.json` (and any other initial evidence files), initialize the Q seed manifest:

```powershell
python -m tools.belgi manifest-init `
  --repo C:\ABS\GOVERNED_REPO `
  --out _out/run_0001/EvidenceManifest.Q.seed.json `
  --locked-spec _out/run_0001/LockedSpec.json `
  --command-executed "C1 seed" `
  --add command_log:command_log.c1:_out/run_0001/LockedSpec.json:application/json:C1 `
  --add policy_report:policy_report.c1:_out/run_0001/LockedSpec.json:application/json:C1 `
  --add schema_validation:schema_validation.c1:_out/run_0001/LockedSpec.json:application/json:C1
```
Note: `--command` is an alias for `--command-executed`.


2) Run Gate Q using that manifest:

```powershell
python -m chain.gate_q_verify `
  --repo C:\ABS\GOVERNED_REPO `
  --intent-spec IntentSpec.core.md `
  --locked-spec _out/run_0001/LockedSpec.json `
  --evidence-manifest _out/run_0001/EvidenceManifest.Q.seed.json `
  --out _out/run_0001/GateVerdict.Q.json
```

Note: `manifest-init` can bind the *same* governed file under multiple required evidence kinds (as the public fixtures do). When you have real `command_log` / `policy_report` / `schema_validation` artifacts, point each `--add` to its true file.

## Why this is deterministic & safe

- Repo-root confinement: every authoritative path is resolved under `--repo` and symlinks are rejected.
- Deterministic hashing: each artifact hash is `sha256(file_bytes)` from governed repo bytes.
- Canonical JSON: keys are sorted and output ends with a trailing newline.
- Fail-closed validation: output is validated against the pinned `schemas/EvidenceManifest.schema.json` before returning success.
