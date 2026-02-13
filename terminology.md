# BELGI Terminology

## 0. Rule of Use (Canonical Pointer)
This file MUST NOT define or redefine terms. The single source of truth is [CANONICALS.md](CANONICALS.md).

## 1. Term Map (Pointers Only)
| Term | Canonical definition |
|---|---|
| P Intent | [CANONICALS.md#p-intent](CANONICALS.md#p-intent) |
| C1 Prompt Compiler | [CANONICALS.md#c1-prompt-compiler](CANONICALS.md#c1-prompt-compiler) |
| Q Gate 1 Lock & Verify | [CANONICALS.md#q-gate-1-lock-verify](CANONICALS.md#q-gate-1-lock-verify) |
| C2 Propose | [CANONICALS.md#c2-propose](CANONICALS.md#c2-propose) |
| R Gate 2 Verify | [CANONICALS.md#r-gate-2-verify](CANONICALS.md#r-gate-2-verify) |
| C3 Docs Compiler | [CANONICALS.md#c3-docs-compiler](CANONICALS.md#c3-docs-compiler) |
| S Seal | [CANONICALS.md#s-seal](CANONICALS.md#s-seal) |
| Tier Packs | [CANONICALS.md#tier-packs](CANONICALS.md#tier-packs) |
| Waivers | [CANONICALS.md#waivers](CANONICALS.md#waivers) |
| Publication posture | [CANONICALS.md#publication-posture](CANONICALS.md#publication-posture) |
| Propagation/Consistency Sweep | [CANONICALS.md#propagation-consistency-sweep](CANONICALS.md#propagation-consistency-sweep) |
| Environment Envelope | [CANONICALS.md#environment-envelope](CANONICALS.md#environment-envelope) |
| Bounded Trust | [CANONICALS.md#bounded-trust](CANONICALS.md#bounded-trust) |
| Deterministic (BELGI sense) | [CANONICALS.md#deterministic-belgi](CANONICALS.md#deterministic-belgi) |
| Evidence Bundle | [CANONICALS.md#evidence-bundle](CANONICALS.md#evidence-bundle) |
| Evidence Sufficiency | [CANONICALS.md#evidence-sufficiency](CANONICALS.md#evidence-sufficiency) |
| LockedSpec | [CANONICALS.md#lockedspec](CANONICALS.md#lockedspec) |
| Protocol Pack | [CANONICALS.md#protocol-pack](CANONICALS.md#protocol-pack) |
| Protocol Pack Identity | [CANONICALS.md#protocol-pack-identity](CANONICALS.md#protocol-pack-identity) |
| pack_id | [CANONICALS.md#protocol-pack-identity](CANONICALS.md#protocol-pack-identity) |
| manifest_sha256 | [CANONICALS.md#protocol-pack-identity](CANONICALS.md#protocol-pack-identity) |
| evaluated_revision | [CANONICALS.md#evaluated-revision](CANONICALS.md#evaluated-revision) |
| R-Snapshot | [CANONICALS.md#r-snapshot](CANONICALS.md#r-snapshot) |
| Replay Integrity | [CANONICALS.md#replay-integrity](CANONICALS.md#replay-integrity) |
| Wheel vs Repo-Local | [CANONICALS.md#wheel-vs-repo-local](CANONICALS.md#wheel-vs-repo-local) |
| Pack Mirror Drift | [CANONICALS.md#pack-mirror-drift](CANONICALS.md#pack-mirror-drift) |
| Blast Radius | [CANONICALS.md#blast-radius](CANONICALS.md#blast-radius) |
| HOTL | [CANONICALS.md#hotl](CANONICALS.md#hotl) |
| NO-GO | [CANONICALS.md#no-go](CANONICALS.md#no-go) |
| GO | [CANONICALS.md#go](CANONICALS.md#go) |

## 2. Symbols / Notation

### 2.1 Hoare-triple-inspired documentation notation
BELGI MAY use a Hoare-triple-inspired notation as a documentation device:

{Pre} Step {Post}

- This notation is for readable contracts and traceability only; BELGI is NOT claiming formal program correctness proofs.
- BELGI does not prove program semantic correctness; it proves protocol adherence given the declared evidence within the declared Environment Envelope.
