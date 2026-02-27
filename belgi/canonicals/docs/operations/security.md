# Security (public-safe posture)

This document is public-safe by design: it describes categories and interfaces only. It MUST NOT include exploit signatures, detection regexes, secret allowlists, or bypass-oriented thresholds.

Grounded sources:
- Trust model categories and boundaries: `../../trust-model.md`
- Canonical publication posture: `../../CANONICALS.md#publication-posture`
- Canonical bounded-trust / envelope concepts: `../../CANONICALS.md#bounded-trust` and `../../CANONICALS.md#environment-envelope`
- Gate R responsibility categories (R1–R8): `../../CANONICALS.md#r-verifier-responsibilities`

## 1) Threat model summary

BELGI’s trust model assumes:
- The proposer (C2) is untrusted by default.
- Repo text can be adversarial (prompt injection risk).
- Supply chain and toolchain drift can invalidate evidence.
- Nondeterministic execution (flaky tests) can undermine replay.

See the full threat category list and trust boundary diagram in `../../trust-model.md`.

## 2) What BELGI defends against (categories) and what it does not

### 2.1 Defends against (category-level)
Within the declared Environment Envelope and locked inputs, BELGI aims to defend against:
- Hallucination/drift by requiring deterministic gates (Q, R) and explicit evidence sufficiency.
- Prompt injection influence by locking the run contract in LockedSpec before proposing.
- Backdoor diffs by constraining blast radius and verifying with category-level policy checks (R2/R3) and an adversarial diff scan category (R8).
- Supply chain drift by requiring pinned toolchain refs in the envelope and supply-chain evidence obligations (R7).

### 2.2 Does not defend against
BELGI does NOT claim:
- Universal determinism outside the declared Environment Envelope.
- Formal correctness proofs of program semantics.
- Security guarantees if the envelope is underspecified, compromised, or unreplayable.
- Safety if required evidence is missing or unverifiable.

These limits are consistent with the bounded claim in `../../CANONICALS.md#bounded-claim`.

## 3) Publication posture

From `../../CANONICALS.md#publication-posture`:

### 3.1 Safe to publish
- Protocol stages and interfaces (P → C1 → Q → C2 → R → C3 → S).
- Schema contracts and evidence categories.
- Gate behaviors at the category level (what they check, not how to bypass).
- Failure category tokens and remediation interface format.

### 3.2 Must remain private in real deployments
- Exact detection signatures, patterns, thresholds, or rule details that enable bypass.
- Secret allowlists/denylists used by scanning or policy systems.
- Any operational secrets (tokens/keys) and proprietary supply-chain intelligence.

## 4) Hardening recommendations (process-level)

These recommendations align to the trust model and canonical bounded-trust principle.

- Sandbox the proposer (C2): isolate it from secrets, production networks, and privileged credentials.
- Minimize tool access: grant only the minimum needed to produce evidence; treat everything else as out-of-envelope.
- Pin toolchain: ensure `LockedSpec.environment_envelope.pinned_toolchain_refs[]` is complete and resolvable.
- Isolate secrets in CI: keep secrets out of the proposer environment; restrict who/what can trigger sealing.
- Preserve evidence: keep EvidenceManifest + referenced artifacts immutable after Gate R (tamper-evident via hashes).

## 5) Incident response basics (high-level)

If Gate R flags concerns (category-level):

- Supply chain concerns (R7-related):
  - Stop progression to sealing/publishing.
  - Escalate to a human security/ops owner.
  - Reconstruct the envelope and verify pinned toolchain refs; investigate dependency changes.

- Adversarial concerns (R8-related):
  - Treat as potentially hostile change.
  - Require human review under HOTL policy.
  - Consider narrowing blast radius or rejecting the proposal.

- Evidence insufficiency (R0/R4-related):
  - Treat as NO-GO regardless of apparent correctness.
  - Regenerate required evidence within the declared envelope and rerun Gate R.

This response is intentionally process-only and avoids bypass-oriented specifics.
