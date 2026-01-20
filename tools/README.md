# Tools (Operator Utilities)

This folder contains deterministic operator utilities used by BELGI workflows.

These tools are **fail-closed** and enforce **repo-root confinement** (rejects absolute paths, `..`, NUL bytes, and symlink scopes).

## Which command proves what?

| Goal | Command | Result (strict) |
|---|---|---|
| No CRLF drift in tracked files | `python -m tools.normalize --repo . --check --tracked-only` | Exit `0` = PASS; exit `2/4` = NO-GO |
| Canonical sweep report is current | `python -m tools.sweep consistency --repo .` | Writes `policy/consistency_sweep.json`; exit `0` = all PASS; exit `1` = invariant FAIL; exit `2` = spec-sync NO-GO |
| Builtin protocol pack matches canonicals | `python -m tools.check_drift` | Exit `0` = pack shape OK + no drift; exit `1` = NO-GO |
| Builtin pack manifest is self-consistent | `belgi pack verify --in belgi/_protocol_packs/v1` | Exit `0` = PASS; exit `1/3` = NO-GO |
| Installed pack (wheel) is self-consistent | `belgi pack verify --builtin` | Exit `0` = PASS; exit `1/3` = NO-GO |
| Create a schema-valid EvidenceManifest | `python -m tools.belgi manifest-init --repo <ABS> --out <rel> --run-id <id> --add <spec> [--command-executed <cmd> | --command <cmd>]` | Writes manifest atomically; exit `0` = PASS; exit `3` = NO-GO |
| EvidenceManifest hashes match bytes | `python -m tools.rehash evidence-manifest --repo . --manifest EvidenceManifest.json` | Prints `No changes needed` when hashes already match current bytes |

Note: `manifest-init` creates a schema-valid manifest binding current governed bytes; Gate Q/R/S may still NO-GO if policy-required evidence kinds/semantics are missing. `--command` is an alias for `--command-executed`.

See docs/operations/evidence-ownership.md for the canonical chain ownership story and Gate Q wrapper commands.

### Why CS-EV-006 often fails right after a commit

`CS-EV-006` binds governed **public Gate R fixtures** to the exact SHA-256 of `policy/consistency_sweep.json`.

That creates an intentional “bootstrap / fixed-point” loop:
- If you change anything that changes the sweep report bytes, fixtures are now pinned to the *previous* report hash and `CS-EV-006` will FAIL.
- The sweep prints `SHA-256 (fixtures should declare)` which is the PASS-target hash (what fixtures must be updated to pin).

Use:
- `python -m tools.sweep consistency --repo . --fix-fixtures` to deterministically patch governed fixtures and converge in one pass.

If the sweep reports `REGEN-SEALS NO-GO` after `--fix-fixtures`, regenerate only the touched seal-related fixtures (and immediately re-verify via Gate S):
- `python -m tools.sweep consistency --repo . --fix-fixtures --regen-seals`

## rehash.py

Purpose: recompute `sha256(bytes)` bindings in manifest-style artifacts after legitimate byte changes (e.g., after LF normalization or regenerated reports).

### sha256-txt

Rehash or verify a `sha256sum`-style manifest file.

- Format: `<64hex>␠␠<path>` (two spaces)
- Paths are interpreted as repo-relative (and confined under the repo root).

Verify (no rewrite):

```bash
python -m tools.rehash sha256-txt --repo . --manifest AuditReport.sha256.txt --check
```

Rewrite (atomic replace):

```bash
python -m tools.rehash sha256-txt --repo . --manifest AuditReport.sha256.txt
```

Empty manifests are treated as **NO-GO** unless you pass `--allow-empty`.

### evidence-manifest

Recompute hashes inside an `EvidenceManifest.json` (updates `artifacts[].hash` and `envelope_attestation.hash` based on their `storage_ref` bytes).

```bash
python -m tools.rehash evidence-manifest --repo . --manifest EvidenceManifest.json
```

If the manifest contains zero hash targets, this is **NO-GO** unless you pass `--allow-empty`.

### required-reports

Rehash required report ObjectRefs inside fixture `EvidenceManifest.json` files referenced by a fixture `cases.json`.

- Supported `cases.json` shapes:
  - `cases[].paths.evidence_manifest` (current)
  - `cases[].evidence_manifest` (legacy)

```bash
python -m tools.rehash required-reports --repo . --cases policy/fixtures/public/gate_r/cases.json
```

If any required report ObjectRef is missing/invalid, this subcommand is **NO-GO**.

By default it enforces this strictly only for cases with `expected_exit_code: 0` (fixtures expected to PASS). Failing fixtures may intentionally omit required artifacts and will be reported as notes without forcing a NO-GO.

## sweep.py

Purpose: produce the canonical **Consistency Sweep Report** at `policy/consistency_sweep.json`.

Guarantees:
- Deterministic, fail-closed, repo-root confined.
- Spec is authoritative: the sweep refuses to run if the invariant catalog in `docs/operations/consistency-sweep.md` does not match the code registry 1:1.

### consistency

Run the consistency sweep (writes the canonical report path atomically):

```bash
python -m tools.sweep consistency --repo .
```

Exit codes:
- `0`: all invariants PASS.
- `1`: one or more invariants FAIL (report still written).
- `2`: **spec-sync NO-GO** (missing/extra invariant IDs between spec and code).

Notes:
- `--out` is fixed by contract and MUST remain `policy/consistency_sweep.json`.

CS-EV-006 tip (fixture manifests):
- If the sweep prints both `SHA-256 (report)` and `SHA-256 (fixtures should declare)`, fixture `EvidenceManifest.json` files MUST copy the `fixtures should declare` value into the `policy.consistency_sweep` artifact entry.

## report.py

Purpose: generate a deterministic human-readable audit report (`AuditReport.md`) from a run’s artifacts, with a companion sha256 manifest so manual edits are detectable.

```bash
python -m tools.report \
  --repo . \
  --locked-spec LockedSpec.json \
  --evidence-manifest EvidenceManifest.json \
  --verify-report policy/verify_report.json \
  --gate-q-verdict GateVerdict.Q.json \
  --gate-r-verdict GateVerdict.R.json \
  --seal-manifest SealManifest.json
```

Verify the report bytes haven’t been edited:

```bash
python -m tools.rehash sha256-txt --repo . --manifest AuditReport.sha256.txt --check
```

Compatibility note:
- `tools/generate_audit_report.py` remains as a thin wrapper that forwards to `tools/report.py`.
- `--inputs` can add extra repo-relative inputs; canonical core inputs are always included.

### Safe invariant-add workflow (no drift)

1) Add the new `- invariant_id:` entry to `docs/operations/consistency-sweep.md` (this is the registry).
2) Implement the corresponding check in `tools/sweep.py` and register it in the consistency registry.
3) Run `python -m tools.sweep consistency --repo .` and confirm exit `0` (or expected FAIL if you are mid-migration).

If you add code without updating the spec (or vice versa), the sweep returns exit `2` and lists the missing/extra IDs.

## normalize.py

Purpose: Project Byte Guard for CRLF normalization to protect `sha256(bytes)` integrity across OSes.

### --check

Detect CRLF drift (fail-closed) without modifying files:

```bash
python -m tools.normalize --repo . --check --tracked-only
```

Exit codes:
- `0`: PASS (no drift)
- `2`: NO-GO (drift detected)
- `4`: NO-GO (empty scan surface, unless `--allow-empty`)

### --fix

Normalize CRLF→LF atomically and then rehash affected manifests/reports:

```bash
python -m tools.normalize --repo . --fix --tracked-only
```

Notes:
- `--no-rehash` disables the subordinate `tools/rehash.py` step (default: rehash).
- `--report-out <path>` writes a deterministic JSON report (repo-relative path only).

## belgi CLI (installed entrypoint)

The `belgi` command is installed as a console script when you install the package.

```bash
pip install belgi
belgi --help
```

### belgi about

Print package identity info:

```bash
belgi about
```

### belgi pack build

Build/update protocol pack manifest deterministically from a pack directory:

```bash
belgi pack build --in belgi/_protocol_packs/v1 --pack-name belgi-protocol-pack-v1
```

- Scans `--in` directory for protocol content (`schemas/`, `gates/`, `tiers/`).
- Excludes scaffolding (`__init__.py`, `__pycache__`, `.py` files).
- Generates `ProtocolPackManifest.json` with deterministic `pack_id`.
- Validates immediately after writing (fail-closed).

### belgi pack verify

Verify protocol pack manifest matches the file tree:

```bash
# Verify a directory pack
belgi pack verify --in belgi/_protocol_packs/v1

# Verify the builtin pack from installed package
belgi pack verify --builtin
```

Exit codes:
- `0`: PASS (manifest verified)
- `1`: FAIL (mismatch/tamper detected)
- `3`: usage error (directory not found, etc.)

Verification checks:
- All files in manifest exist with matching SHA-256 and size.
- No extra files in pack that aren't in manifest.
- `pack_id` recomputes correctly.
- Manifest JSON is canonical (sorted keys, compact separators, trailing LF).
- No symlinks anywhere under pack root.

### belgi bundle check

Check an evidence bundle (demo-grade checker):

```bash
belgi bundle check --in path/to/bundle --demo
```

**Important:** The `--demo` flag is **required**. This prevents false security assumptions—the command name and flag make it explicit this is a demo-grade checker, not a full gate replay.

This is a publish-safe checker that only depends on `belgi*` modules.
It checks:
- Required bundle files exist (LockedSpec.json, EvidenceManifest.json, SealManifest.json, GateVerdict_Q/R/S.json)
- No symlinks in bundle
- Protocol identity binding (LockedSpec.protocol_pack must match the active pack on pack_id, pack_name, manifest_sha256; source is metadata)
- Run ID consistency across all artifacts
- All gate verdicts are GO
- All ObjectRefs in SealManifest exist in bundle and hash-match (fail-closed)
- seal_hash recomputes correctly (normative algorithm; see docs/operations/evidence-bundles.md)

Note on `seal_hash`: this README is not a source of truth for the algorithm. Treat it as a pointer to the normative specification in docs/operations/evidence-bundles.md.

Exit codes:
- `0`: PASS (bundle integrity verified)
- `1`: FAIL (check failed)
- `3`: usage error (missing --demo, directory not found, etc.)

Note: This is a demo-grade checker. It does **not** replay Gate Q/R/S logic. Full verification requires repo-local gate execution.

## tools/belgi_tools.py (dev helper)

For development workflows that run from the repo, `tools/belgi_tools.py` provides additional
subcommands used by fixtures and Gate R integration tests.

Compatibility: `tools/belgi.py` is kept as a thin wrapper that dispatches to
`tools/belgi_tools.py` to avoid Python import-shadowing issues.
evidence generation commands. These are used by Gate R workflows:

```bash
python -m tools.belgi run-tests --run-id <id>
python -m tools.belgi invariant-eval --locked-spec LockedSpec.json
python -m tools.belgi verify-attestation --run-id <id> --command-log <path>
```

Note: The pack commands have been moved to `belgi.cli` (the installed entrypoint).
Use `belgi pack verify` (installed) or `python -m belgi.cli pack verify` (repo/module form) instead of `python -m tools.belgi pack verify`.

### Protocol Pack Identity Semantics

Identity fields (bound into LockedSpec/SealManifest):
- `pack_id`: SHA-256 of protocol content (deterministic)
- `manifest_sha256`: SHA-256 of manifest bytes
- `pack_name`: human-readable identifier

Metadata (not part of cryptographic identity):
- `source`: `builtin|override|dev-override` (operational context)

Dev-override policy:
- `source=dev-override` requires `BELGI_DEV=1` environment variable.
- Dev-override is forbidden in CI (`CI` env var set).
- These guards are enforced fail-closed in `belgi/protocol/pack.py`.
