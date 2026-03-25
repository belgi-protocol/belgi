# C1 Prompt Compiler — IntentSpec.core.md → LockedSpec.json

This document describes the **C1 compiler entry gate** implemented in the chain layout.

Canonical implementation:
- Compiler: [../chain/compiler_c1_intent.py](../chain/compiler_c1_intent.py)
- Wrapper forwarder: [../wrapper/comp_C1.py](../wrapper/comp_C1.py)

Note: This repository does not contain a separate `compilers/comp_c1_intent.py` code file. The executable compiler lives under `chain/` and is documented here.

## Inputs

C1 compiles a LockedSpec from:
- `IntentSpec.core.md` (single fenced YAML block)

- Prompt bundle input (one of):
	- **Assemble mode (canonical):** C1 deterministically assembles PromptBundle bytes and sets `LockedSpec.prompt_bundle_ref` from the produced bytes.
	- **Reference mode (legacy):** operator provides an already-assembled PromptBundle object reference.

- Operator-provided object references required by the LockedSpec schema:
	- `tier.tolerances_ref` (repo-relative object bytes supplied to C1)
	- `environment_envelope` fields + `pinned_toolchain_refs[]` (repo-relative inputs supplied to C1)
	- For tier-2/3: `environment_envelope.attestation_pubkey_ref` and `seal_pubkey_ref` (bytes stored in-repo)
- Git upstream state:
	- `--repo-ref`
	- `--upstream-commit-sha` if supplied; otherwise C1 falls back to `git rev-parse HEAD`
	- in CI, the repo must be clean before C1 emits `dirty_flag=false`
- Protocol version from `VERSION`

## Deterministic parsing (IntentSpec)

Parsing is strict and aligned with Gate Q:
- The compiler extracts **exactly one** fenced YAML block delimited by exact lines ` ```yaml ` and ` ``` `.
- The YAML is parsed using the same deterministic subset parser used by Gate Q (`chain/logic/q_checks/yaml_subset.py`).
- The parsed object is validated against [../schemas/IntentSpec.schema.json](../schemas/IntentSpec.schema.json).

Any missing/extra YAML blocks, YAML subset violations (tabs, flow style, duplicate keys, etc.), or schema violations are **hard failures** (non-zero exit).

## Compilation rules (Intent → LockedSpec)

The compiler emits a LockedSpec that is validated against [../schemas/LockedSpec.schema.json](../schemas/LockedSpec.schema.json) before writing.

Intent field mapping is **exactly** the deterministic mapping Gate Q recomputes (see Gate Q `Q-INTENT-003` in [../gates/GATE_Q.md](../gates/GATE_Q.md)). In particular:
- `LockedSpec.intent.*` is derived directly from `IntentSpec.*`.
- `LockedSpec.constraints.*` maps from `IntentSpec.scope.*`.
- `LockedSpec.tier.tier_id` maps from `IntentSpec.tier.tier_pack_id`.
- `LockedSpec.doc_impact` is emitted from `IntentSpec.doc_impact` (always present).
- `LockedSpec.publication_intent` is emitted iff present in the IntentSpec (and is required by schema for tier-2/3).

Additional required LockedSpec fields are populated as follows:
- `LockedSpec.belgi_version` is read from `VERSION`.
- `LockedSpec.upstream_state.repo_ref` is copied from `--repo-ref`; `commit_sha` comes from `--upstream-commit-sha` when supplied, otherwise from `git rev-parse HEAD`; `dirty_flag` is emitted as `false`.
- `LockedSpec.environment_envelope.*` and `tier.tolerances_ref` are built from repo-relative paths passed to C1; hashes are computed as SHA-256 over file bytes.
- C1 validates the referenced ToolchainSet/Tolerances objects against schema and binds their ObjectRefs into LockedSpec, but selected-tier tolerances semantics are enforced later by Gate Q. In particular, Gate Q verifies `Tolerances.tier_id` against `LockedSpec.tier.tier_id` and checks that numeric scope budgets do not widen the selected tier ceilings.
- `LockedSpec.prompt_bundle_ref` is either:
	- assembled by C1 (canonical), or
	- computed from the referenced PromptBundle bytes (legacy).

When assembling a PromptBundle, C1 also emits helper artifacts for downstream stages:
- `prompt_block_hashes.json` mapping `{block_id: sha256_hex}` (for C3 `--prompt-block-hashes`)
- `policy.prompt_bundle.json` as a schema-valid `PolicyReportPayload` containing `block_ids`, `block_hashes`, and prompt bundle integrity hashes.
- `LockedSpec.invariants[]` is deterministically derived from `IntentSpec.acceptance.success_criteria` (one invariant per criterion). This satisfies Q2/Q3 structural requirements and is stable across reruns.

## Invariants contract (C1-owned)

Invariants are a first-class C1 output in the canonical chain (P → C1 → Q → C2 → R → C3 → S):
- C1 MUST emit a non-empty `LockedSpec.invariants[]` so Gate Q can lock/verify that the intent is specific enough to enforce (see Gate Q `Q3` in [../gates/GATE_Q.md](../gates/GATE_Q.md)).
- Invariant `id` tokens are the stable rule identifiers that Gate R’s R1 evidence may reference. Gate R requires `belgi invariant-eval` plus a required `policy_report` artifact `id == "policy.invariant_eval"` (see Gate R `R1` in [../gates/GATE_R.md](../gates/GATE_R.md)).
- C1’s invariant compilation is deterministic: given the same IntentSpec, it emits the same invariant ids and descriptions. This prevents “silent drift” where the evidence report is evaluating a different set of invariants than the locked run contract.

## Hardening invariants (must-holds)

The compiler enforces the repo’s non-negotiables:
- **Fail-closed**: any parse/validation/IO/git error exits non-zero.
- **Repo-root confinement**: all file arguments are validated as repo-relative and resolved under `--repo`; attempts to escape are rejected.
- **Symlink rejection**: paths that traverse symlinks in scope are rejected.
- **Deterministic JSON**: serialized with `sort_keys=True`, `ensure_ascii=False`, and explicit trailing newline `\n`.
- **Atomic output**: writes via temp file + `fsync()` + `os.replace()`.
- **No silent dirty locking in CI**: refuses to emit a LockedSpec in CI when `git status --porcelain` is non-empty (schema requires `dirty_flag=false`).

## CLI

Canonical invocation (chain entrypoint):

```bash
python chain/compiler_c1_intent.py \
	--repo . \
	--intent-spec path/to/IntentSpec.core.md \
	--out temp/LockedSpec.json \
	--run-id my-run-001 \
	--repo-ref owner/repo \
	--prompt-bundle-out temp/prompt_bundle.bin \
	--tolerances tier.tolerances=path/to/tolerances.json \
	--envelope-id env-001 \
	--envelope-description "Pinned toolchain for run" \
	--expected-runner "windows-x64" \
	--toolchain-ref toolchain.main=temp/toolchain.json \
	--toolchain-ref deps.python=toolchains/python.lock.json
```

Wrapper compatibility: `wrapper/comp_C1.py` is a strict forwarder to the chain entrypoint.

This is the manual C1 surface. On the shipped `belgi run` path, explicit current-run ToolchainSet/Tolerances operator inputs are staged into the chain workspace before C1 is invoked with repo-relative `--toolchain-set` / `--tolerances` refs.

For tier-2/3, additionally provide:

```bash
	--attestation-pubkey att-pk-001=path/to/attestation_pubkey.pem \
	--seal-pubkey seal-pk-001=path/to/seal_pubkey.pem
```
