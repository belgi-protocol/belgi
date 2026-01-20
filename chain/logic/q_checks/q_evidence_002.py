from __future__ import annotations

from typing import Any

from chain.logic.base import CheckResult
from .context import QCheckContext


def _kinds(artifacts: Any) -> set[str]:
    if not isinstance(artifacts, list):
        return set()
    out: set[str] = set()
    for a in artifacts:
        if not isinstance(a, dict):
            continue
        k = a.get("kind")
        if isinstance(k, str) and k:
            out.add(k)
    return out


def run(ctx: QCheckContext) -> list[CheckResult]:
    required = ctx.tier_params.get("required_evidence_kinds_q")
    required_first = None
    if isinstance(required, list):
        for x in required:
            if isinstance(x, str) and x:
                required_first = x
                break

    if ctx.evidence_manifest is None or not isinstance(ctx.evidence_manifest, dict):
        return [
            CheckResult(
                check_id="Q-EVIDENCE-002",
                status="FAIL",
                message="EvidenceManifest missing/invalid; cannot enforce minimum evidence kinds.",
                pointers=[str(ctx.evidence_manifest_path)],
                category="FQ-EVIDENCE-MISSING",
                remediation_next_instruction=f"Do produce required evidence kind {required_first or 'missing_field'} under the declared envelope then re-run Q.",
            )
        ]

    artifacts = ctx.evidence_manifest.get("artifacts")
    present = _kinds(artifacts)

    if not isinstance(required, list) or not all(isinstance(x, str) and x for x in required):
        return [
            CheckResult(
                check_id="Q-EVIDENCE-002",
                status="FAIL",
                message="Tier required_evidence_kinds_q missing/invalid; cannot enforce minimum evidence kinds deterministically.",
                pointers=["tiers/tier-packs.md"],
                category="FQ-EVIDENCE-MISSING",
                remediation_next_instruction=f"Do produce required evidence kind {required_first or 'missing_field'} under the declared envelope then re-run Q.",
            )
        ]

    missing = [k for k in required if k not in present]
    if missing:
        missing_kind = missing[0]
        return [
            CheckResult(
                check_id="Q-EVIDENCE-002",
                status="FAIL",
                message=f"Required evidence kind missing from EvidenceManifest.artifacts: {missing_kind}",
                pointers=[str(ctx.evidence_manifest_path)],
                category="FQ-EVIDENCE-MISSING",
                remediation_next_instruction=f"Do produce required evidence kind {missing_kind} under the declared envelope then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q-EVIDENCE-002",
            status="PASS",
            message="Minimum required evidence kinds are present.",
            pointers=[str(ctx.evidence_manifest_path)],
        )
    ]
