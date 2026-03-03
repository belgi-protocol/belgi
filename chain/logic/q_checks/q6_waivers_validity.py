from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from belgi.core.schema import parse_rfc3339, validate_schema
from belgi.core.jail import resolve_storage_ref
from chain.logic.base import CheckResult, load_json

from .context import QCheckContext

_DRAFT_OR_PLACEHOLDER_REMEDIATION = (
    "Do edit waiver waiver_id to be eligible "
    "(set status=\"active\", replace placeholder fields, and ensure expires_at is after "
    "EvidenceManifest.anchored_time_utc), or remove it, then re-run Q."
)
_MISSING_ANCHOR_REMEDIATION = (
    "Do re-run with BELGI >=1.4.2 so EvidenceManifest.anchored_time_utc is recorded, then re-run Q."
)
_PLACEHOLDER_MARKERS = frozenset({"TODO", "TBD", "REPLACE_ME"})
_PLACEHOLDER_LINE_RE = re.compile(r"^(?:TODO|TBD|REPLACE_ME)\s*[:\-].*$", re.IGNORECASE)
_ANGLE_TOKEN_RE = re.compile(r"^<[^>\n]+>$")


def _rfc3339_to_dt(dt: str) -> datetime:
    parse_rfc3339(dt)
    s = dt
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    parsed = datetime.fromisoformat(s)
    if parsed.tzinfo is None:
        raise ValueError("missing timezone offset")
    return parsed


def _contains_llm_or_agent(s: str) -> bool:
    t = s.lower()
    return "llm" in t or "agent" in t


def _is_placeholder_token(value: str) -> bool:
    token = value.strip()
    if not token:
        return False
    if token.upper() in _PLACEHOLDER_MARKERS:
        return True
    if _ANGLE_TOKEN_RE.fullmatch(token) is not None:
        return True
    return False


def _field_contains_placeholder(*, field_name: str, field_value: str) -> bool:
    value = field_value.strip()
    if not value:
        return False
    if _is_placeholder_token(value):
        return True
    if _PLACEHOLDER_LINE_RE.fullmatch(value) is not None:
        return True

    for raw_line in value.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if _is_placeholder_token(line):
            return True
        if _PLACEHOLDER_LINE_RE.fullmatch(line) is not None:
            return True

        if field_name in ("scope", "approver"):
            _, sep, suffix = line.partition(":")
            if sep and _is_placeholder_token(suffix):
                return True
    return False


def _waiver_anchor_result(ctx: QCheckContext) -> datetime | CheckResult:
    evidence_manifest = ctx.evidence_manifest
    if not isinstance(evidence_manifest, dict):
        return CheckResult(
            check_id="Q6",
            status="FAIL",
            message="EvidenceManifest missing/invalid; cannot evaluate waiver expiry deterministically.",
            pointers=[str(ctx.evidence_manifest_path)],
            category="FQ-WAIVER-INVALID",
            remediation_next_instruction=_MISSING_ANCHOR_REMEDIATION,
        )

    anchored_time_raw = evidence_manifest.get("anchored_time_utc")
    if not isinstance(anchored_time_raw, str) or not anchored_time_raw.strip():
        return CheckResult(
            check_id="Q6",
            status="FAIL",
            message="EvidenceManifest.anchored_time_utc missing; waiver expiry cannot be evaluated deterministically.",
            pointers=[str(ctx.evidence_manifest_path), "EvidenceManifest.anchored_time_utc"],
            category="FQ-WAIVER-INVALID",
            remediation_next_instruction=_MISSING_ANCHOR_REMEDIATION,
        )

    try:
        return _rfc3339_to_dt(anchored_time_raw.strip()).astimezone(timezone.utc)
    except Exception:
        return CheckResult(
            check_id="Q6",
            status="FAIL",
            message="EvidenceManifest.anchored_time_utc is invalid RFC3339; waiver expiry cannot be evaluated.",
            pointers=[str(ctx.evidence_manifest_path), "EvidenceManifest.anchored_time_utc"],
            category="FQ-WAIVER-INVALID",
            remediation_next_instruction=_MISSING_ANCHOR_REMEDIATION,
        )


def run(ctx: QCheckContext) -> list[CheckResult]:
    """Q6 — Waivers validity (if present)."""

    if ctx.locked_spec is None:
        return [
            CheckResult(
                check_id="Q6",
                status="FAIL",
                message="LockedSpec missing/invalid; cannot evaluate waivers.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-WAIVER-INVALID",
                remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
            )
        ]

    waivers = ctx.locked_spec.get("waivers_applied")
    if not isinstance(waivers, list) or len(waivers) == 0:
        return [
            CheckResult(
                check_id="Q6",
                status="PASS",
                message="Q6 satisfied: no waivers_applied.",
                pointers=[str(ctx.locked_spec_path)],
            )
        ]

    allowed = ctx.tier_params.get("waiver_policy.allowed")
    max_active = ctx.tier_params.get("waiver_policy.max_active_waivers")

    if allowed is None or max_active is None:
        return [
            CheckResult(
                check_id="Q6",
                status="FAIL",
                message="Tier waiver policy parameters missing; cannot evaluate Q6 deterministically.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-WAIVER-INVALID",
                remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
            )
        ]

    if allowed is False:
        return [
            CheckResult(
                check_id="Q6",
                status="FAIL",
                message="Waivers are not allowed for selected tier.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-WAIVER-INVALID",
                remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
            )
        ]

    if isinstance(max_active, int) and len(waivers) > max_active:
        return [
            CheckResult(
                check_id="Q6",
                status="FAIL",
                message=f"Too many active waivers: {len(waivers)} > max_active_waivers {max_active}.",
                pointers=[str(ctx.locked_spec_path)],
                category="FQ-WAIVER-INVALID",
                remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
            )
        ]

    waiver_schema = ctx.schemas.get("Waiver")
    if not isinstance(waiver_schema, dict):
        return [
            CheckResult(
                check_id="Q6",
                status="FAIL",
                message="Missing Waiver schema; cannot validate waiver documents.",
                pointers=["schemas/Waiver.schema.json"],
                category="FQ-WAIVER-INVALID",
                remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
            )
        ]

    evaluated_dt_or_fail = _waiver_anchor_result(ctx)
    if isinstance(evaluated_dt_or_fail, CheckResult):
        return [evaluated_dt_or_fail]
    evaluated_dt = evaluated_dt_or_fail

    for waiver_rel in waivers:
        if not isinstance(waiver_rel, str) or not waiver_rel.strip():
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message="waivers_applied contains a non-string/empty entry.",
                    pointers=[str(ctx.locked_spec_path)],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                )
            ]

        waiver_path = resolve_storage_ref(ctx.repo_root, waiver_rel.strip())
        try:
            waiver_doc = load_json(waiver_path)
        except Exception as e:
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message=f"Cannot read waiver document '{waiver_rel}': {e}",
                    pointers=[waiver_rel.strip()],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                )
            ]

        if not isinstance(waiver_doc, dict):
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message=f"Waiver document '{waiver_rel}' is not a JSON object.",
                    pointers=[waiver_rel.strip()],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                )
            ]

        errs = validate_schema(waiver_doc, waiver_schema, root_schema=waiver_schema, path="Waiver")
        if errs:
            first = errs[0]
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message=f"Waiver schema invalid at {first.path}: {first.message}",
                    pointers=[waiver_rel.strip()],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                )
            ]

        if waiver_doc.get("status") != "active":
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message=(
                        f"Waiver '{waiver_rel}' is not eligible: status must be 'active' "
                        "(draft templates default to revoked)."
                    ),
                    pointers=[waiver_rel.strip()],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction=_DRAFT_OR_PLACEHOLDER_REMEDIATION,
                )
            ]

        placeholder_fields: list[str] = []
        for field_name in ("scope", "justification", "mitigation", "approver"):
            raw_value = waiver_doc.get(field_name)
            if isinstance(raw_value, str) and _field_contains_placeholder(field_name=field_name, field_value=raw_value):
                placeholder_fields.append(field_name)
        if placeholder_fields:
            fields_str = ", ".join(sorted(set(placeholder_fields)))
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message=f"Waiver '{waiver_rel}' contains placeholder content in field(s): {fields_str}.",
                    pointers=[waiver_rel.strip()],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction=_DRAFT_OR_PLACEHOLDER_REMEDIATION,
                )
            ]

        waived_gate = waiver_doc.get("gate_id")
        waived_rule = waiver_doc.get("rule_id")
        if isinstance(waived_gate, str) and isinstance(waived_rule, str) and waived_rule:
            if waived_rule[0] in ("Q", "R") and waived_gate != waived_rule[0]:
                return [
                    CheckResult(
                        check_id="Q6",
                        status="FAIL",
                        message=f"gate_id '{waived_gate}' inconsistent with rule_id '{waived_rule}'.",
                        pointers=[waiver_rel.strip()],
                        category="FQ-WAIVER-INVALID",
                        remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                    )
                ]

        approver = waiver_doc.get("approver")
        if not isinstance(approver, str) or not approver.strip():
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message=f"Waiver '{waiver_rel}' approver missing/empty.",
                    pointers=[waiver_rel.strip()],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                )
            ]

        if _contains_llm_or_agent(approver):
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message=f"Waiver '{waiver_rel}' approver appears non-human.",
                    pointers=[waiver_rel.strip()],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                )
            ]

        # Enforce human: prefix for tiers 1-3 (audit-grade; per Waiver schema description).
        if ctx.tier_id in ("tier-1", "tier-2", "tier-3"):
            if not approver.startswith("human:"):
                return [
                    CheckResult(
                        check_id="Q6",
                        status="FAIL",
                        message=f"Waiver '{waiver_rel}' approver must use 'human:<identity>' format for tier-1..3.",
                        pointers=[waiver_rel.strip()],
                        category="FQ-WAIVER-INVALID",
                        remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                    )
                ]

        expires_at = waiver_doc.get("expires_at")
        if not isinstance(expires_at, str) or not expires_at.strip():
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message=f"Waiver '{waiver_rel}' expires_at missing/empty.",
                    pointers=[waiver_rel.strip()],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                )
            ]

        expires_dt = _rfc3339_to_dt(expires_at).astimezone(timezone.utc)
        if not (expires_dt > evaluated_dt):
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message=f"Waiver '{waiver_rel}' expires_at is not after EvidenceManifest.anchored_time_utc.",
                    pointers=[waiver_rel.strip()],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                )
            ]

        atr = waiver_doc.get("audit_trail_ref")
        if not isinstance(atr, dict) or not isinstance(atr.get("id"), str) or not str(atr.get("id")).strip():
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message=f"Waiver '{waiver_rel}' audit_trail_ref.id missing/empty.",
                    pointers=[waiver_rel.strip()],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                )
            ]
        if not isinstance(atr.get("storage_ref"), str) or not str(atr.get("storage_ref")).strip():
            return [
                CheckResult(
                    check_id="Q6",
                    status="FAIL",
                    message=f"Waiver '{waiver_rel}' audit_trail_ref.storage_ref missing/empty.",
                    pointers=[waiver_rel.strip()],
                    category="FQ-WAIVER-INVALID",
                    remediation_next_instruction="Do fix or remove waiver waiver_id then re-run Q.",
                )
            ]

    return [
        CheckResult(
            check_id="Q6",
            status="PASS",
            message="Q6 satisfied: waivers validated.",
            pointers=[str(ctx.locked_spec_path)],
        )
    ]
