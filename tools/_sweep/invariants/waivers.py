from __future__ import annotations

from tools._shared import common as _common
from tools._sweep.model import InvariantResult


def check_cs_wvr_001(root: _common.Path) -> InvariantResult:
    """CS-WVR-001 — Waivers are human-controlled (LLM-closed)."""

    can = _common.repo_path(root, "CANONICALS.md")
    ops = _common.repo_path(root, "docs/operations/waivers.md")
    ws = _common.repo_path(root, "schemas/Waiver.schema.json")
    for rel, p in [("CANONICALS.md", can), ("docs/operations/waivers.md", ops), ("schemas/Waiver.schema.json", ws)]:
        if not p.exists():
            return InvariantResult("CS-WVR-001", "FAIL", [], f"Missing {rel}.")

    if "MUST NOT" not in _common.read_text(can) or "LLM" not in _common.read_text(can):
        return InvariantResult(
            "CS-WVR-001",
            "FAIL",
            ["CANONICALS.md#waivers"],
            "Ensure CANONICALS waiver policy forbids LLM-created/edited/applied waivers.",
        )
    if "forbidden" not in _common.read_text(ops).lower() or "c2" not in _common.read_text(ops).lower():
        return InvariantResult(
            "CS-WVR-001",
            "FAIL",
            ["docs/operations/waivers.md#24-proposer-llm--forbidden"],
            "Ensure waivers.md explicitly forbids proposer/LLM (C2) from waiver actions.",
        )

    try:
        schema = _common.load_json(ws)
        req = set(schema.get("required", []))
        if "approver" not in req:
            return InvariantResult(
                "CS-WVR-001",
                "FAIL",
                ["schemas/Waiver.schema.json#/required"],
                "Ensure Waiver schema requires approver.",
            )
        approver = schema.get("properties", {}).get("approver", {})
        desc = approver.get("description") if isinstance(approver, dict) else None
        if not isinstance(desc, str) or "human" not in desc.lower():
            return InvariantResult(
                "CS-WVR-001",
                "FAIL",
                ["schemas/Waiver.schema.json#/properties/approver/description"],
                "Describe Waiver.approver as a human identity class in schema.",
            )
    except Exception as e:
        return InvariantResult("CS-WVR-001", "FAIL", ["schemas/Waiver.schema.json"], f"Fix Waiver schema error ({e}).")

    return InvariantResult(
        "CS-WVR-001",
        "PASS",
        ["CANONICALS.md#waivers", "docs/operations/waivers.md#24-proposer-llm--forbidden", "schemas/Waiver.schema.json#/properties/approver"],
        "",
    )

def check_cs_wvr_002(root: _common.Path) -> InvariantResult:
    """CS-WVR-002 — Waivers are time-bounded and auditable."""

    ws = _common.repo_path(root, "schemas/Waiver.schema.json")
    q = _common.repo_path(root, "gates/GATE_Q.md")
    ops = _common.repo_path(root, "docs/operations/waivers.md")
    for rel, p in [("schemas/Waiver.schema.json", ws), ("gates/GATE_Q.md", q), ("docs/operations/waivers.md", ops)]:
        if not p.exists():
            return InvariantResult("CS-WVR-002", "FAIL", [], f"Missing {rel}.")

    try:
        schema = _common.load_json(ws)
        req = set(schema.get("required", []))
        if not {"expires_at", "audit_trail_ref"}.issubset(req):
            return InvariantResult(
                "CS-WVR-002",
                "FAIL",
                ["schemas/Waiver.schema.json#/required"],
                "Ensure Waiver schema requires expires_at and audit_trail_ref.",
            )
    except Exception as e:
        return InvariantResult("CS-WVR-002", "FAIL", ["schemas/Waiver.schema.json"], f"Fix Waiver schema error ({e}).")

    q_txt = _common.read_text(q)
    missing_q = _common._missing_needles(q_txt, ["Q6", "status == \"active\"", "expires_at", "anchored_time_utc", "placeholder"])
    if missing_q:
        return InvariantResult(
            "CS-WVR-002",
            "FAIL",
            ["gates/GATE_Q.md#q6--waivers-validity-if-present"],
            "Ensure Gate Q Q6 enforces active status, placeholder rejection, and expires_at after EvidenceManifest.anchored_time_utc.",
        )
    ops_txt = _common.read_text(ops)
    if "expires_at" not in ops_txt or "audit_trail_ref" not in ops_txt:
        return InvariantResult(
            "CS-WVR-002",
            "FAIL",
            ["docs/operations/waivers.md#34-apply-to-a-run-lockedspecwaivers_applied"],
            "Ensure waivers.md documents expires_at and audit_trail_ref requirements and application point.",
        )
    missing_ops = _common._missing_needles(
        ops_txt,
        [
            "status: \"revoked\"",
            "placeholder",
            "anchored_time_utc",
            "belgi verify",
            "fails closed",
            "mitigation",
        ],
    )
    if missing_ops:
        return InvariantResult(
            "CS-WVR-002",
            "FAIL",
            ["docs/operations/waivers.md#31-create-request-human", "docs/operations/waivers.md#43-verify-replay-enforcement-post-run"],
            "Ensure waivers.md documents revoked-by-default draft posture, placeholder rejection, anchored replay via belgi verify, fail-closed behavior, and mitigation field requirements.",
        )

    return InvariantResult(
        "CS-WVR-002",
        "PASS",
        ["schemas/Waiver.schema.json#/required", "gates/GATE_Q.md#q6--waivers-validity-if-present", "docs/operations/waivers.md#34-apply-to-a-run-lockedspecwaivers_applied"],
        "",
    )

def check_cs_wvr_003(root: _common.Path) -> InvariantResult:
    """CS-WVR-003 — Tier waiver policy is consistent and enforced."""

    tiers_json = _common.repo_path(root, "tiers/tier-packs.json")
    tiers = _common.repo_path(root, "tiers/tier-packs.md")
    q = _common.repo_path(root, "gates/GATE_Q.md")
    ops = _common.repo_path(root, "docs/operations/waivers.md")
    ops_canon = _common.repo_path(root, "belgi/canonicals/docs/operations/waivers.md")
    schema_readme = _common.repo_path(root, "schemas/README.md")
    for rel, p in [
        ("tiers/tier-packs.json", tiers_json),
        ("tiers/tier-packs.md", tiers),
        ("gates/GATE_Q.md", q),
        ("docs/operations/waivers.md", ops),
        ("belgi/canonicals/docs/operations/waivers.md", ops_canon),
        ("schemas/README.md", schema_readme),
    ]:
        if not p.exists():
            return InvariantResult("CS-WVR-003", "FAIL", [], f"Missing {rel}.")

    t_txt = _common.read_text(tiers)
    missing_t = _common._missing_needles(t_txt, ["waiver_policy", "max_active_waivers", "requires_HOTL", "tier-3"])
    if missing_t:
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["tiers/tier-packs.md#24-waiver_policy"],
            "Ensure tier-packs defines waiver_policy.allowed, max_active_waivers, and requires_HOTL per tier.",
        )

    q_txt = _common.read_text(q)
    if (
        "max_active_waivers" not in q_txt
        or "Verify tier allows waivers" not in q_txt
        or "waiver_policy.requires_HOTL" not in q_txt
    ):
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            [
                "gates/GATE_Q.md#q6--waivers-validity-if-present",
                "gates/GATE_Q.md#q-hotl-001--human-on-the-loop-approval-artifact-role-confusion-prevention",
            ],
            "Ensure Gate Q Q6 references tier waiver_policy and Q-HOTL-001 reads waiver_policy.requires_HOTL from tier policy.",
        )

    def _parse_waiver_policy_lines(doc_path: _common.Path, doc_ref: str) -> tuple[dict[str, tuple[bool, int, bool, int]], str | None]:
        doc_txt = _common.read_text(doc_path)
        lowered = doc_txt.lower()
        if "limits per tier" not in lowered or ("tier 3" not in lowered and "tier-3" not in lowered):
            return {}, f"{doc_ref}: missing limits-per-tier section"

        observed: dict[str, tuple[bool, int, bool, int]] = {}
        tier_line_re = _common.re.compile(
            r"^\s*-\s*Tier\s+([0-3])\s*:\s*waivers\s+(allowed|not allowed)"
            r"(?:,\s*max\s+([0-9]+)\s+active)?(?:,\s*(.*))?\s*$",
            flags=_common.re.IGNORECASE,
        )
        for line_no, line in enumerate(doc_txt.splitlines(), start=1):
            m = tier_line_re.match(line)
            if m is None:
                continue
            tid = f"tier-{m.group(1)}"
            allowed = m.group(2).lower() == "allowed"
            max_active_raw = m.group(3)
            max_active = int(max_active_raw) if max_active_raw is not None else 0
            tail = (m.group(4) or "").lower()
            hotl_required = "hotl required" in tail
            observed[tid] = (allowed, max_active, hotl_required, line_no)
        return observed, None

    try:
        tiers_obj = _common.load_json(tiers_json)
    except Exception as e:
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["tiers/tier-packs.json"],
            f"Fix tier-packs.json parse error ({e}).",
        )

    tier_map = tiers_obj.get("tiers")
    if not isinstance(tier_map, dict):
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["tiers/tier-packs.json#/tiers"],
            "tiers/tier-packs.json must define an object at /tiers.",
        )

    expected_limits: dict[str, tuple[bool, int, bool]] = {}
    for tid in ("tier-0", "tier-1", "tier-2", "tier-3"):
        tier_entry = tier_map.get(tid)
        if not isinstance(tier_entry, dict):
            return InvariantResult(
                "CS-WVR-003",
                "FAIL",
                [f"tiers/tier-packs.json#/tiers/{tid}"],
                f"tiers/tier-packs.json missing {tid} tier entry.",
            )
        waiver_policy = tier_entry.get("waiver_policy")
        if not isinstance(waiver_policy, dict):
            return InvariantResult(
                "CS-WVR-003",
                "FAIL",
                [f"tiers/tier-packs.json#/tiers/{tid}/waiver_policy"],
                f"tiers/tier-packs.json missing waiver_policy for {tid}.",
            )
        allowed = waiver_policy.get("allowed")
        max_active = waiver_policy.get("max_active_waivers")
        requires_hotl = waiver_policy.get("requires_HOTL")
        if not isinstance(allowed, bool):
            return InvariantResult(
                "CS-WVR-003",
                "FAIL",
                [f"tiers/tier-packs.json#/tiers/{tid}/waiver_policy/allowed"],
                f"tiers/tier-packs.json waiver_policy.allowed must be boolean for {tid}.",
            )
        if not (isinstance(max_active, int) and not isinstance(max_active, bool) and max_active >= 0):
            return InvariantResult(
                "CS-WVR-003",
                "FAIL",
                [f"tiers/tier-packs.json#/tiers/{tid}/waiver_policy/max_active_waivers"],
                f"tiers/tier-packs.json waiver_policy.max_active_waivers must be a non-negative integer for {tid}.",
            )
        if not isinstance(requires_hotl, bool):
            return InvariantResult(
                "CS-WVR-003",
                "FAIL",
                [f"tiers/tier-packs.json#/tiers/{tid}/waiver_policy/requires_HOTL"],
                f"tiers/tier-packs.json waiver_policy.requires_HOTL must be boolean for {tid}.",
            )
        expected_limits[tid] = (allowed, max_active, requires_hotl)

    observed_limits, parse_error = _parse_waiver_policy_lines(ops, "docs/operations/waivers.md#51-limits-per-tier")
    if parse_error is not None:
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["docs/operations/waivers.md#51-limits-per-tier"],
            "Ensure waivers.md repeats the tier waiver limits and HOTL-required tiers.",
        )

    observed_canon_limits, canon_parse_error = _parse_waiver_policy_lines(
        ops_canon,
        "belgi/canonicals/docs/operations/waivers.md#51-limits-per-tier",
    )
    if canon_parse_error is not None:
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["belgi/canonicals/docs/operations/waivers.md#51-limits-per-tier"],
            "Ensure the packaged waivers doc repeats the tier waiver limits and HOTL-required tiers.",
        )

    schema_txt = _common.read_text(schema_readme)
    schema_missing = _common._missing_needles(
        schema_txt,
        [
            "waiver_policy.requires_HOTL == true",
            "FAIL if `requires_HOTL == true` and no `hotl_approval` artifact is found.",
        ],
    )
    if schema_missing or "Tier-1 runs trigger a warning if missing." in schema_txt:
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            ["schemas/README.md#hotlapproval-purpose"],
            "Ensure schemas/README.md describes HOTLApproval scope and enforcement from tier policy, not stale Tier-1 warning prose.",
        )

    drift: list[str] = []
    for tid in ("tier-0", "tier-1", "tier-2", "tier-3"):
        if tid not in observed_limits:
            drift.append(f"{tid}:missing in docs/operations/waivers.md#5.1")
            continue
        expected_allowed, expected_max, expected_hotl = expected_limits[tid]
        observed_allowed, observed_max, observed_hotl, observed_line = observed_limits[tid]
        if (expected_allowed, expected_max, expected_hotl) != (observed_allowed, observed_max, observed_hotl):
            drift.append(
                f"{tid}@docs/operations/waivers.md:{observed_line}:"
                f"expected allowed={expected_allowed},max_active_waivers={expected_max},requires_HOTL={expected_hotl};"
                f"found allowed={observed_allowed},max_active_waivers={observed_max},requires_HOTL={observed_hotl}"
            )
        if tid not in observed_canon_limits:
            drift.append(f"{tid}:missing in belgi/canonicals/docs/operations/waivers.md#5.1")
            continue
        canon_allowed, canon_max, canon_hotl, canon_line = observed_canon_limits[tid]
        if (expected_allowed, expected_max, expected_hotl) != (canon_allowed, canon_max, canon_hotl):
            drift.append(
                f"{tid}@belgi/canonicals/docs/operations/waivers.md:{canon_line}:"
                f"expected allowed={expected_allowed},max_active_waivers={expected_max},requires_HOTL={expected_hotl};"
                f"found allowed={canon_allowed},max_active_waivers={canon_max},requires_HOTL={canon_hotl}"
            )
    if drift:
        return InvariantResult(
            "CS-WVR-003",
            "FAIL",
            [
                "tiers/tier-packs.json#/tiers",
                "docs/operations/waivers.md#51-limits-per-tier",
                "belgi/canonicals/docs/operations/waivers.md#51-limits-per-tier",
            ],
            "Ensure waivers tier-policy docs exactly match tiers/tier-packs.json waiver_policy, including requires_HOTL. "
            + "; ".join(drift),
            {"drift": drift},
        )

    return InvariantResult(
        "CS-WVR-003",
        "PASS",
        [
            "tiers/tier-packs.json#/tiers",
            "tiers/tier-packs.md#24-waiver_policy",
            "gates/GATE_Q.md#q6--waivers-validity-if-present",
            "gates/GATE_Q.md#q-hotl-001--human-on-the-loop-approval-artifact-role-confusion-prevention",
            "docs/operations/waivers.md#51-limits-per-tier",
            "belgi/canonicals/docs/operations/waivers.md#51-limits-per-tier",
            "schemas/README.md#hotlapproval-purpose",
        ],
        "",
    )

def check_cs_wvr_004(root: _common.Path) -> InvariantResult:
    """CS-WVR-004 — Waivers are visible in sealing and replay bundles."""

    eb = _common.repo_path(root, "docs/operations/evidence-bundles.md")
    sm = _common.repo_path(root, "schemas/SealManifest.schema.json")
    ops = _common.repo_path(root, "docs/operations/waivers.md")
    for rel, p in [("docs/operations/evidence-bundles.md", eb), ("schemas/SealManifest.schema.json", sm), ("docs/operations/waivers.md", ops)]:
        if not p.exists():
            return InvariantResult("CS-WVR-004", "FAIL", [], f"Missing {rel}.")

    if "waivers" not in _common.read_text(eb).lower():
        return InvariantResult(
            "CS-WVR-004",
            "FAIL",
            ["docs/operations/evidence-bundles.md#11-mandatory-artifacts-minimum-replay-set"],
            "Ensure evidence-bundles mandates including waiver documents when LockedSpec.waivers_applied is non-empty.",
        )

    try:
        schema = _common.load_json(sm)
        if "waivers" not in (schema.get("properties") or {}):
            return InvariantResult(
                "CS-WVR-004",
                "FAIL",
                ["schemas/SealManifest.schema.json#/properties"],
                "Ensure SealManifest schema defines waivers[] ObjectRefs.",
            )
    except Exception as e:
        return InvariantResult("CS-WVR-004", "FAIL", ["schemas/SealManifest.schema.json"], f"Fix SealManifest schema error ({e}).")

    if "visible in sealing" not in _common.read_text(ops).lower():
        return InvariantResult(
            "CS-WVR-004",
            "FAIL",
            ["docs/operations/waivers.md#15-waivers-must-be-visible-in-sealing"],
            "Ensure waivers.md states waivers must be visible in sealing.",
        )

    return InvariantResult(
        "CS-WVR-004",
        "PASS",
        [
            "docs/operations/evidence-bundles.md#11-mandatory-artifacts-minimum-replay-set",
            "schemas/SealManifest.schema.json#/properties/waivers",
            "docs/operations/waivers.md#15-waivers-must-be-visible-in-sealing",
        ],
        "",
    )

def check_cs_wvr_005(root: _common.Path) -> InvariantResult:
    """CS-WVR-005 — doc_impact enforcement does not introduce a waiver bypass."""

    q = _common.repo_path(root, "gates/GATE_Q.md")
    r = _common.repo_path(root, "gates/GATE_R.md")
    tiers = _common.repo_path(root, "tiers/tier-packs.md")
    for rel, p in [("gates/GATE_Q.md", q), ("gates/GATE_R.md", r), ("tiers/tier-packs.md", tiers)]:
        if not p.exists():
            return InvariantResult("CS-WVR-005", "FAIL", [], f"Missing {rel}.")

    q_txt = _common.read_text(q)
    r_txt = _common.read_text(r)

    # Fail if doc_impact checks mention waivers (no bypass branches).
    if _common.re.search(r"(?im)^###\s+Q-DOC-001\b[\s\S]{0,1600}\bwaiver\b", q_txt) or _common.re.search(
        r"(?im)^###\s+Q-DOC-002\b[\s\S]{0,1600}\bwaiver\b", q_txt
    ):
        return InvariantResult(
            "CS-WVR-005",
            "FAIL",
            ["gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty"],
            "Remove waiver-based bypass logic from Q-DOC-001/Q-DOC-002 doc_impact enforcement.",
        )
    if _common.re.search(r"(?im)^###\s+R-DOC-001\b[\s\S]{0,1600}\bwaiver\b", r_txt):
        return InvariantResult(
            "CS-WVR-005",
            "FAIL",
            ["gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff"],
            "Remove waiver-based bypass logic from R-DOC-001 doc_impact enforcement.",
        )

    t_txt = _common.read_text(tiers)
    if "tier-3" not in t_txt or "waiver_policy" not in t_txt or "allowed" not in t_txt:
        return InvariantResult(
            "CS-WVR-005",
            "FAIL",
            ["tiers/tier-packs.md#24-waiver_policy"],
            "Ensure tier waiver policy remains unchanged and tier-3 disallows waivers.",
        )

    return InvariantResult(
        "CS-WVR-005",
        "PASS",
        [
            "gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty",
            "gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff",
            "tiers/tier-packs.md#24-waiver_policy",
        ],
        "",
    )
