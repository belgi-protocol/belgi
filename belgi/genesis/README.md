# Historical Genesis Reference Surface

`GenesisSealPayload.json` is the historical repo-local genesis reference payload.

Boundary:
- it was used in repo-local and reporting-era surfaces before BELGI defined a canonical Tier-3 trust-anchor artifact
- it remains a historical reference surface inside the repository
- it is not authoritative for canonical Tier-3 trust-anchor verification

Canonical Tier-3 authority begins with [../anchor/v1/TrustAnchor.json](../anchor/v1/TrustAnchor.json).

Naming boundary:
- `genesis_seal` remains the Tier-3 evidence kind in `EvidenceManifest`
- `TrustAnchor.json` is the canonical authority object used to validate that evidence
