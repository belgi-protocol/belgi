# C3 Docs Compiler — Verified inputs → docs + Final EvidenceManifest

This document describes the **C3 compiler** implemented in the chain layout.

Canonical implementation:
- Compiler: [../chain/compiler_c3_docs.py](../chain/compiler_c3_docs.py)
- Wrapper forwarder: [../wrapper/comp_C3.py](../wrapper/comp_C3.py)

Normative posture references:
- Evidence mutability + append-only rule: [../docs/operations/evidence-bundles.md](../docs/operations/evidence-bundles.md)
- C3 determinism requirement: [../CANONICALS.md#c3-docs-compiler](../CANONICALS.md#c3-docs-compiler)
- Template contract: [../belgi/templates/DocsCompiler.template.md](../belgi/templates/DocsCompiler.template.md)

## Role in the chain

C3 runs **post-R** and must be treated as an evidence-append step:
- It MUST NOT mutate the R-snapshot EvidenceManifest referenced by `GateVerdict (R).evidence_manifest_ref`.
- It MUST produce a **Final EvidenceManifest** that is an **append-only extension** of the R-snapshot manifest.
- It MUST be deterministic with respect to its declared inputs.

## Inputs

C3 consumes the verified state:
- `LockedSpec.json`
- `GateVerdict.Q.json`
- `GateVerdict.R.json` (must be `verdict == "GO"`)
- R-snapshot `EvidenceManifest.json` (the exact manifest referenced by `GateVerdict (R).evidence_manifest_ref`)
- Prompt-block hash disclosure mapping (JSON `{block_id: sha256_hex}`)
- Docs compiler template markdown (default: `belgi/templates/DocsCompiler.template.md`)

Additional declared inputs:
- Profile binding: `LockedSpec.publication_intent.profile` is the authoritative profile for C3.
	- If `--profile` is provided, it MUST match `LockedSpec.publication_intent.profile` (hard error on mismatch).
	- If `LockedSpec.publication_intent.profile` is absent, `--profile` is required.

## Integrity checks (fail-closed)

C3 enforces a post-R integrity boundary:
- Validates all JSON inputs against their schemas:
	- `schemas/LockedSpec.schema.json`
	- `schemas/GateVerdict.schema.json`
	- `schemas/EvidenceManifest.schema.json`
	- `schemas/DocsCompilationLogPayload.schema.json`
- Verifies `GateVerdict(R).evidence_manifest_ref.storage_ref` matches `--r-snapshot-manifest` and that the manifest bytes hash matches `evidence_manifest_ref.hash`.

R-snapshot indexing requirements (post-R binding):
- The R-snapshot EvidenceManifest MUST index (at minimum):
	- `LockedSpec.json`
	- `GateVerdict.Q.json`
- Before compiling docs, C3 verifies that the `--locked-spec` and `--gate-q-verdict` files match the R-snapshot manifest by **exact** `(storage_ref, sha256)`.

Note: the R-snapshot EvidenceManifest is referenced by hash from Gate R, so it cannot also index `GateVerdict.R.json` without creating an impossible circular dependency. C3 therefore binds the R-snapshot manifest by hash but does not require that verdict/spec JSON files be indexed inside it.

Any mismatch is a hard failure (exit code 3). This is required to prevent post-R evidence substitution.

## Outputs

C3 produces:
- `docs_compilation_log` JSON (public-safe: prompt bytes are not embedded; hashes only)
- Deterministic docs markdown (stable summary + canonical pointers + bundle hashes)
- A deterministic docs bundle directory (`bundle/**`): normalized copies of required documentation roots
- `bundle/TOC.md`
- `bundle/docs_bundle_manifest.json`
- A bundle root hash file (repo-relative) containing `bundle_root_sha256`
- Final `EvidenceManifest.json` as an append-only extension of the R-snapshot manifest

The docs compilation log records output bindings inside `outputs`:
- bundle hash anchors (`bundle_sha256`, `docs_bundle_manifest_sha256`, `bundle_root_sha256`)
- output path+hash records for the emitted docs markdown, TOC, bundle manifest, and bundle root hash file

The Final EvidenceManifest appends exactly one new artifact (and MUST NOT index bundle files as separate artifacts):
- `kind: "docs_compilation_log"`
- `id: "docs.compilation_log"`
- `produced_by: "C3"`
- `storage_ref: "docs/docs_compilation_log.json"`
- `hash: sha256(file bytes)`

It also appends a C3 command record to `commands_executed` while preserving the R-snapshot command list as an exact prefix (for both string and structured command log modes).

## Determinism rules

- Default evidence timestamp is fixed: `generated_at = 1970-01-01T00:00:00Z`.
- All JSON outputs are serialized deterministically: `sort_keys=True`, `ensure_ascii=False`, trailing `\n`.
- All writes are atomic: temp file + `fsync()` + `os.replace()`.
- All paths are repo-root jailed; absolute paths, `..`, NUL bytes, and symlinks are rejected.

Docs bundle determinism (per template):
- Included source files are enumerated from the required roots and sorted by normalized repo-relative POSIX path.
- Output bytes are normalized to LF newlines with exactly one trailing newline.
- `bundle_sha256` is computed over bundle files excluding `bundle/docs_bundle_manifest.json` (non-circular model).
- `docs_bundle_manifest_sha256` is the SHA-256 of the manifest bytes.
- `bundle_root_sha256 = sha256("manifest\n" + docs_bundle_manifest_sha256 + "\n" + "bundle\n" + bundle_sha256 + "\n")`.

## CLI

Canonical invocation (chain entrypoint):

```bash
python chain/compiler_c3_docs.py \
	--repo . \
	--locked-spec temp/LockedSpec.json \
	--gate-q-verdict temp/GateVerdict.Q.json \
	--gate-r-verdict temp/GateVerdict.R.json \
	--r-snapshot-manifest temp/EvidenceManifest.R.json \
	--out-final-manifest temp/EvidenceManifest.final.json \
	--out-log docs/docs_compilation_log.json \
	--out-docs temp/docs.md \
	--out-bundle-dir temp/bundle \
	--out-bundle-root-sha temp/bundle_root.sha256 \
	--profile public \
	--prompt-block-hashes temp/prompt_block_hashes.json
```

Wrapper compatibility: `wrapper/comp_C3.py` is a strict forwarder to the chain entrypoint.

Notes:
- `--out-final-manifest` MUST NOT equal `--r-snapshot-manifest`.
- For deterministic runs, keep the default `--generated-at` or supply a fixed value.