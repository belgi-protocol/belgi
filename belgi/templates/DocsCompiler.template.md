# Docs Compiler Template (C3) — Deterministic Docs Bundle

DEFAULT: **NO-GO** unless the docs bundle can be reproduced byte-for-byte (or with explicitly declared, bounded variance) from declared inputs within the declared Environment Envelope.

This template specifies the **deterministic compilation contract** for C3 (Docs Compiler) as defined canonically in `../../CANONICALS.md#c3-docs-compiler`.

---

## B1) Purpose
C3 compiles canonical docs plus selected repo documentation into a **stable documentation bundle** that:
- is deterministic with respect to declared inputs,
- is public-safe (no bypass-oriented details added), and
- supports replay/audit by producing explicit evidence artifacts and hashes.

C3 is post-verification (after Gate R). It must not change verification outcomes; it must only **document and package** what was verified.

---

## B2) Inputs

### B2.1 Schema inputs (locked run contract)
The compiler consumes the following schema artifacts as inputs (all must be schema-valid):
- `LockedSpec.json` (see `../../schemas/LockedSpec.schema.json`)
  - Key fields used: `run_id`, `belgi_version`, `tier.tier_id`, `environment_envelope.*`, `upstream_state.commit_sha`, optional `waivers_applied[]`.
- Gate verdicts:
  - Gate Q verdict JSON (see `../../schemas/GateVerdict.schema.json`, must have `gate_id == "Q"`)
  - Gate R verdict JSON (see `../../schemas/GateVerdict.schema.json`, must have `gate_id == "R"`)
- R-Snapshot EvidenceManifest JSON (see `../../schemas/EvidenceManifest.schema.json`)
  - The exact EvidenceManifest referenced by `GateVerdict (R).evidence_manifest_ref`.

### B2.2 Repository documentation inputs (public-safe categories)
C3 compiles from repo files in these categories (paths are repo-relative):

**Required roots (always included):**
- `CANONICALS.md`
- `terminology.md`
- `trust-model.md`
- `gates/` (all `*.md` under `gates/`)
- `schemas/` (all `*.schema.json` and `schemas/README.md`)
- `tiers/` (all `*.md` under `tiers/`)
- `docs/operations/` (all `*.md` under `docs/operations/`)

**Optional roots (explicit inclusion rule):**
- `docs/research/` is **excluded** from the default docs bundle.
  - Inclusion rule (deterministic): include `docs/research/**` only when the compiler is invoked with `--profile internal`.
  - The chosen profile value is a required declared input (recorded in the docs compilation log; see B4).

### B2.3 File allowlist
Only these file types are eligible for inclusion:
- Markdown: `*.md`
- JSON schemas and schema docs: `*.json`

Any other file types are ignored by default.

---

## B3) Deterministic compilation rules

### B3.1 Full inputs (must be complete to claim determinism)
C3 output is deterministic **iff** it is a pure function of:
1) The exact bytes of all included source files (B2.2/B2.3) at the evaluated repo revision.
2) The exact bytes of `LockedSpec.json`, both gate verdict JSON files, and the R-Snapshot EvidenceManifest.
3) Compiler identity string:
   - `compiler_id` and `compiler_version` (C3 implementation-defined), recorded in the docs compilation log.
4) Compiler invocation profile:
   - `profile ∈ {"public", "internal"}`.

Determinism scope (explicit):
- The determinism claim applies to the **docs bundle outputs** (`bundle/**` including `TOC.md` and `docs_bundle_manifest.json`) and to the `docs_compilation_log` payload.
- Evidence wrapper fields that are inherently runtime-dependent (e.g., `EvidenceManifest.commands_executed[*].started_at` / `finished_at` in structured mode) are **not** part of the docs bundle output claim and MUST NOT be used as inputs that alter bundle bytes.

Prohibited non-determinism:
- timestamps injected into docs bundle outputs (`bundle/**`)
- random IDs
- environment-dependent path normalization
- locale-dependent sorting

If any nondeterminism exists, C3 must fail and the run is **NO-GO** for deterministic docs claims.

### B3.2 File discovery and ordering
1) Enumerate candidate files from the required/optional roots.
2) Convert each candidate path to a **normalized relative path**:
   - Use `/` as separator.
   - No `./` prefixes.
3) Sort included files by normalized relative path in **lexicographic (codepoint) order**.

Collision rule (determinism on case-insensitive filesystems):
- If two different files would normalize to the same path under case-insensitive comparison, compilation MUST fail with a deterministic error (ambiguity).

### B3.3 Content normalization (output bytes)
For each included file, write a normalized copy into the output bundle:
- Encoding: UTF-8.
- Newlines: convert CRLF (`\r\n`) to LF (`\n`).
- Ensure exactly one trailing newline at EOF (append if missing; do not add extra blank lines).
- Do not otherwise rewrite content (no reflow, no heading renumbering).

### B3.4 Deterministic TOC rules (if generated)
If a TOC is generated, it MUST be deterministic and derived only from included source file headings.

This template defines a minimal deterministic TOC:
- Create `bundle/TOC.md` listing all included files as links in the same order as the file ordering (B3.2).
- Do not infer document structure beyond the file list.

### B3.5 Deterministic bundle manifest
C3 MUST write a machine-readable manifest file:

- Output path: `bundle/docs_bundle_manifest.json`
- Content (JSON object):
  - `schema_version`: string (implementation-defined; not governed by `schemas/*.schema.json`)
  - `profile`: `"public"|"internal"`
  - `inputs`: ordered list of normalized source file paths
  - `files`: ordered list of objects `{ "path": <normalized>, "sha256": <hex> }`
  - `bundle_sha256`: overall bundle hash (see below)

Per-file hash:
- `sha256` is computed over the normalized output bytes of each file.

Overall bundle hash:
- Compute `bundle_sha256` as SHA-256 over the UTF-8 bytes of the exact concatenation:
  - for each file in order: `<sha256>  <path>\n`
  - followed by `"MANIFEST\n" + sha256(manifest_bytes) + "\n"`

The manifest file itself is part of the bundle and must be included in the file list and hash computation.

---

## B4) Outputs

### B4.1 Bundle directory tree (example)
Example output layout (names are normative, content depends on inputs):

- `bundle/`
  - `CANONICALS.md`
  - `terminology.md`
  - `trust-model.md`
  - `gates/…`
  - `schemas/…`
  - `tiers/…`
  - `docs/operations/…`
  - `docs/research/…` (only if `--profile internal`)
  - `TOC.md`
  - `docs_bundle_manifest.json`

### B4.2 Required evidence artifact: docs_compilation_log
C3 MUST produce a `docs_compilation_log` evidence artifact and index it in `EvidenceManifest.artifacts[]` (no new schema fields).

Required fields in the **log artifact payload** (recommended JSON):
- `run_id` (from LockedSpec)
- `profile` ("public"|"internal")
- `compiler_id`, `compiler_version`
- `inputs`:
  - normalized list of included source file paths
  - for each file: source hash (SHA-256 of *source bytes*)
  - for each file: normalized output hash (SHA-256 of normalized bytes)
- `outputs`:
  - `bundle_sha256`
  - `docs_bundle_manifest_sha256`

EvidenceManifest indexing requirements (schema-defined fields only):
- `kind`: `"docs_compilation_log"`
- `id`: recommended `"log.docs_compiler"`
- `hash`: SHA-256 of the log artifact bytes
- `media_type`: recommended `"application/json"`
- `storage_ref`: opaque location string
- `produced_by`: `"C3"`

---

## B5) Verification expectations (Gate R + replay)

Important boundary:
- Gate R is evaluated **before** C3 and tier packs explicitly note `docs_compilation_log` must not be required by Gate R.

What Gate R verifies deterministically (relevant to docs compilation claims):
- Gate R verdict references an **R-Snapshot EvidenceManifest** by hash; that R-Snapshot must remain immutable.
- Post-R evidence (including docs compilation evidence) must be recorded as an **append-only extension** of the R-Snapshot EvidenceManifest (see `docs/operations/evidence-bundles.md`).

Evidence obligation for replay/audit (post-R):
- The final sealed EvidenceManifest MUST include:
  - the `docs_compilation_log` artifact reference (produced_by `C3`), and
  - the command log entries for docs compilation under `EvidenceManifest.commands_executed` (shape per tier’s `command_log_mode`).

EXAMPLE COMMAND (non-normative):
- Implementation-defined (this repo specifies the contract, not a required CLI name).

---

## B6) Failure modes + remediation

### Missing required inputs
NO-GO if any required schema input is missing or schema-invalid:
- Missing `LockedSpec.json`, gate verdicts, or the R-Snapshot EvidenceManifest.
- Remediation: regenerate the missing artifacts and re-run C3.

### Missing required source files
NO-GO if any required root file is missing:
- `CANONICALS.md`, `terminology.md`, `trust-model.md`, required roots listed in B2.2.
- Remediation: restore required docs or adjust the repo revision (do not silently skip).

### Nondeterministic generation detected
NO-GO if output differs when re-run with identical inputs/profile/envelope, or if prohibited nondeterminism is present.
- Prohibited examples: embedding timestamps into docs outputs, generating random IDs, or environment-dependent ordering.
- Remediation: remove nondeterministic fields, pin deterministic ordering, and re-run.

### Case-collision / path ambiguity
NO-GO if normalized paths collide under case-insensitive comparison.
- Remediation: rename files to remove ambiguity.

---

## Consistency Sweep Checklist (Mandatory)
- [ ] “compiler deterministic” claim is supported by explicit full-input and ordering rules.
- [ ] No bypass-friendly or secret heuristics are published in this template.
- [ ] Evidence kinds referenced (`docs_compilation_log`, `schema_validation`, `policy_report`, etc.) exist in `../../schemas/EvidenceManifest.schema.json`.
- [ ] References to tier/gates align with existing check IDs and the Gate R evidence sufficiency rule.
- [ ] Prompt block registry publishes only metadata + redaction/hashes policy (no sensitive contents). 
