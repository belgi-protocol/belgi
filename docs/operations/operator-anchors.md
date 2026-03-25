# Operator Anchors

Canonical term:
- `Operator Anchors` is defined in `../../CANONICALS.md#operator-anchors`

This guide describes the shared operator-control surface used by shipped Tier-2/Tier-3 runs on the single `belgi run` backbone.

Owner boundaries:
- `docs/operations/cli.md` owns exact shipped Tier-2/Tier-3 `belgi run` flag syntax and end-to-end examples
- `docs/operations/running-belgi.md` owns manual `python -m chain.*` stage order and replay/evidence notes
- this guide owns anchor classes, handling, and workspace/file-boundary guidance

## 1) Classes

Recommended workspace family:
- `.belgi/runs/<run_id>/inputs/anchors/approvals/`
- `.belgi/runs/<run_id>/inputs/anchors/keys/`
- `.belgi/runs/<run_id>/inputs/anchors/signing/`

Class roles:
- `approvals/`: operator approval artifacts such as `hotl_approval.json`
- `keys/`: pinned public-key materials such as `attestation_pubkey.hex` and `seal_pubkey.hex`
- `signing/`: local signing refs or precomputed signatures such as `attestation_signing_key.hex`, `seal_private_key.hex`, and `seal_signature.b64`

Adjacent non-anchor Tier-3 evidence workspace:
- `.belgi/runs/<run_id>/inputs/evidence/genesis_seal.json`

## 2) Handling Model

| Anchor class | Typical files | Producer | Public/local-only | Staged/bundled behavior |
|---|---|---|---|---|
| approvals | `hotl_approval.json` | human operator / approval process | public artifact | staged into run outputs and indexed in `EvidenceManifest` |
| keys | `attestation_pubkey.hex`, `seal_pubkey.hex` | operator / key-management process | public key material | staged into run outputs and locked into `LockedSpec.environment_envelope` |
| signing | `attestation_signing_key.hex`, `seal_private_key.hex` | local operator-only key material | local-only secret | consumed locally at signing time; raw bytes are not persisted into run outputs, manifests, or bundles |
| signing | `seal_signature.b64` | external signer or earlier deterministic signing step | public signature artifact | staged only as the resulting signature input; the signature may appear in `SealManifest`, but no private key bytes are persisted |

Boundary:
- `genesis_seal` is not an Operator Anchor.
- Tier-3 authority semantics, including `TrustAnchor.json` and the historical genesis payload boundary, are owned by `docs/operations/evidence-bundles.md` and `../../CANONICALS.md`.

## 3) Format Expectations

- `hotl_approval.json`: schema-valid `HOTLApproval`
- `attestation_pubkey.hex`: UTF-8 text file containing the pinned Ed25519 public key hex
- `seal_pubkey.hex`: UTF-8 text file containing the pinned Ed25519 public key hex
- `attestation_signing_key.hex`: UTF-8 text file containing the Ed25519 seed hex used locally by `belgi verify-attestation`
- `seal_private_key.hex`: UTF-8 text file containing the Ed25519 seed hex used locally by `chain.seal_bundle`
- `seal_signature.b64`: UTF-8 text file containing the base64 Ed25519 seal signature verified by `chain.seal_bundle`

All refs are explicit repo-relative paths supplied on `belgi run`. No remote fetches or ambient discovery are allowed.

Tier-3 note:
- `--genesis-seal-ref` is a Tier-3 evidence input on the same shipped `belgi run` family.
- It is taught under `.belgi/runs/<run_id>/inputs/evidence/genesis_seal.json`.
- It is intentionally not part of the anchors family.

## 4) Shipped CLI Pointer

This section keeps only the class-to-file boundary:

| Surface | Shipped CLI family | Workspace boundary |
|---|---|---|
| approvals | approval-ref family (see `docs/operations/cli.md`) | `.belgi/runs/<run_id>/inputs/anchors/approvals/hotl_approval.json` |
| keys | public-key ref family (see `docs/operations/cli.md`) | `.belgi/runs/<run_id>/inputs/anchors/keys/*.hex` |
| signing | signing-key / seal-signature ref family (see `docs/operations/cli.md`) | `.belgi/runs/<run_id>/inputs/anchors/signing/*` |
| Tier-3 evidence (not an anchor) | Tier-3 evidence ref family (see `docs/operations/cli.md`) | `.belgi/runs/<run_id>/inputs/evidence/genesis_seal.json` |

## 5) Signing Models

Local signing key path:
- use `--attestation-signing-key-ref` for the env attestation signer
- use `--seal-private-key-ref` when `belgi run` should sign the seal during the run
- raw secret material stays at the operator-supplied local refs and is not copied into persisted run outputs

Precomputed signature path:
- use `--seal-signature-ref` when the seal signature is produced outside the run and supplied as a base64 file
- `belgi run` verifies that signature against the pinned `seal_pubkey_ref`
- `seal_signature.b64` must bind the exact `SealManifestAnchorUnsigned` bytes for the target run, as defined in `docs/operations/evidence-bundles.md`
- a prior run's seal signature is not portable unless the target run produces the same unsigned seal anchor bytes

Exactly one seal-signing input is allowed:
- `--seal-private-key-ref`
- `--seal-signature-ref`

## 6) Tier-3 Evidence Boundary

Recommended Tier-3 evidence path:
- `.belgi/runs/<run_id>/inputs/evidence/genesis_seal.json`

Use `docs/operations/cli.md` for the full Tier-3 `belgi run` examples that combine these files on the shipped spine.

## 7) Verify And Replay Boundaries

- `belgi verify` replays the stored run summaries, manifests, hashes, and gate outputs for the selected attempt.
- `belgi verify` does not create missing HOTL approvals, public-key refs, signing refs, Tier-3 evidence inputs, or signatures.
- `belgi verify` does not regenerate secret material.
- `belgi bundle check --demo` remains bounded and does not replace `belgi verify`.
