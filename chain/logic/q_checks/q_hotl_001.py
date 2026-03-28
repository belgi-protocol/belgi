from __future__ import annotations

import json
import re
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import resolve_storage_ref
from belgi.core.schema import validate_schema
from chain.logic.base import CheckResult
from chain.logic.tier_packs import tier_requires_hotl

from .context import QCheckContext


def _find_hotl_artifact(evidence_manifest: dict[str, Any]) -> dict[str, Any] | None:
    arts = evidence_manifest.get("artifacts")
    if not isinstance(arts, list):
        return None
    for a in arts:
        if isinstance(a, dict) and a.get("kind") == "hotl_approval":
            return a
    return None


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q-HOTL-001 — Human-on-the-Loop approval artifact (role confusion prevention)."""

    if ctx.evidence_manifest is None:
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="FAIL",
                message="EvidenceManifest missing/invalid; cannot evaluate HOTL approval.",
                pointers=[str(ctx.evidence_manifest_path)],
                category="FQ-HOTL-MISSING",
                remediation_next_instruction="Do produce hotl_approval artifact with valid human approver then re-run Q.",
            )
        ]

    tier_id = ctx.tier_id
    try:
        hotl_required = tier_requires_hotl(ctx.tiers_md, str(tier_id or ""))
    except Exception as e:
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="FAIL",
                message=f"tier HOTL policy missing/invalid for tier_id={tier_id!r}: {e}",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-HOTL-MISSING",
                remediation_next_instruction="Do restore a valid tier HOTL policy then re-run Q.",
            )
        ]

    art = _find_hotl_artifact(ctx.evidence_manifest)
    if art is None:
        if hotl_required:
            return [
                CheckResult(
                    check_id="Q-HOTL-001",
                    status="FAIL",
                    message="HOTL approval artifact required for tier but not found in EvidenceManifest.artifacts.",
                    pointers=[str(ctx.evidence_manifest_path)],
                    category="FQ-HOTL-MISSING",
                    remediation_next_instruction="Do produce hotl_approval artifact with valid human approver then re-run Q.",
                )
            ]
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="PASS",
                message="Q-HOTL-001 satisfied: tier policy does not require HOTL approval.",
                pointers=[str(ctx.evidence_manifest_path)],
            )
        ]

    # When present, validate referenced payload.
    hotl_schema = ctx.schemas.get("HOTLApproval")
    if not isinstance(hotl_schema, dict):
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="FAIL",
                message="Missing HOTLApproval schema; cannot validate HOTL payload.",
                pointers=["schemas/HOTLApproval.schema.json"],
                category="FQ-HOTL-MISSING",
                remediation_next_instruction="Do produce hotl_approval artifact with valid human approver then re-run Q.",
            )
        ]

    storage_ref = art.get("storage_ref")
    declared_hash = art.get("hash")
    if not isinstance(storage_ref, str) or not storage_ref:
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="FAIL",
                message="hotl_approval artifact storage_ref missing/invalid.",
                pointers=[str(ctx.evidence_manifest_path)],
                category="FQ-HOTL-MISSING",
                remediation_next_instruction="Do produce hotl_approval artifact with valid human approver then re-run Q.",
            )
        ]
    if not isinstance(declared_hash, str) or not declared_hash:
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="FAIL",
                message="hotl_approval artifact hash missing/invalid.",
                pointers=[str(ctx.evidence_manifest_path)],
                category="FQ-HOTL-MISSING",
                remediation_next_instruction="Do produce hotl_approval artifact with valid human approver then re-run Q.",
            )
        ]

    try:
        p = resolve_storage_ref(ctx.repo_root, storage_ref)
        data = p.read_bytes()
    except Exception as e:
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="FAIL",
                message=f"Cannot read hotl_approval payload bytes: {e}",
                pointers=[storage_ref],
                category="FQ-HOTL-MISSING",
                remediation_next_instruction="Do produce hotl_approval artifact with valid human approver then re-run Q.",
            )
        ]

    if sha256_bytes(data) != declared_hash:
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="FAIL",
                message="hotl_approval sha256(bytes) mismatch.",
                pointers=[storage_ref],
                category="FQ-HOTL-MISSING",
                remediation_next_instruction="Do produce hotl_approval artifact with valid human approver then re-run Q.",
            )
        ]

    try:
        payload = json.loads(data.decode("utf-8", errors="strict"))
    except Exception as e:
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="FAIL",
                message=f"hotl_approval payload is not valid UTF-8 JSON: {e}",
                pointers=[storage_ref],
                category="FQ-HOTL-MISSING",
                remediation_next_instruction="Do produce hotl_approval artifact with valid human approver then re-run Q.",
            )
        ]

    if not isinstance(payload, dict):
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="FAIL",
                message="hotl_approval payload must be a JSON object.",
                pointers=[storage_ref],
                category="FQ-HOTL-MISSING",
                remediation_next_instruction="Do produce hotl_approval artifact with valid human approver then re-run Q.",
            )
        ]

    errs = validate_schema(payload, hotl_schema, root_schema=hotl_schema, path="HOTLApproval")
    if errs:
        first = errs[0]
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="FAIL",
                message=f"HOTLApproval schema invalid at {first.path}: {first.message}",
                pointers=[storage_ref],
                category="FQ-HOTL-MISSING",
                remediation_next_instruction="Do produce hotl_approval artifact with valid human approver then re-run Q.",
            )
        ]

    approver = payload.get("approver")
    if not isinstance(approver, str) or not re.match(r"^human:[A-Za-z0-9_.@+-]+$", approver):
        return [
            CheckResult(
                check_id="Q-HOTL-001",
                status="FAIL",
                message="HOTLApproval.approver must match ^human:[A-Za-z0-9_.@+-]+$.",
                pointers=[storage_ref],
                category="FQ-HOTL-MISSING",
                remediation_next_instruction="Do produce hotl_approval artifact with valid human approver then re-run Q.",
            )
        ]

    return [
        CheckResult(
            check_id="Q-HOTL-001",
            status="PASS",
            message="Q-HOTL-001 satisfied: hotl_approval artifact present and valid.",
            pointers=[storage_ref],
        )
    ]
