from __future__ import annotations

import json
import re
from typing import Any


def _parse_tier_params_from_json(tier_packs_json: str, tier_id: str) -> dict[str, Any]:
    """Deterministic tier parameter extraction from tiers/tier-packs.json (canonical SSOT).

    Returns a dict with the keys used by chain verifiers/checks.
    On parse issues that must fail-closed, returns a dict containing _tier_parse_error.
    """

    try:
        obj = json.loads(tier_packs_json)
    except Exception as e:
        return {"_tier_parse_error": f"tier-packs.json is not valid JSON: {e}"}

    if not isinstance(obj, dict):
        return {"_tier_parse_error": "tier-packs.json must be a JSON object"}

    tiers = obj.get("tiers")
    if not isinstance(tiers, dict):
        return {"_tier_parse_error": "tier-packs.json missing/invalid top-level tiers map"}

    tier_obj = tiers.get(tier_id)
    if not isinstance(tier_obj, dict):
        return {"_tier_parse_error": f"Unknown tier_id: {tier_id}"}

    params: dict[str, Any] = {}

    # required_evidence_kinds
    req = tier_obj.get("required_evidence_kinds")
    if isinstance(req, list) and all(isinstance(x, str) and x for x in req):
        params["required_evidence_kinds"] = req
    else:
        params["_tier_parse_error"] = "required_evidence_kinds missing/invalid"
        return params

    # required_evidence_kinds_q
    req_q = tier_obj.get("required_evidence_kinds_q")
    if isinstance(req_q, list) and all(isinstance(x, str) and x for x in req_q):
        params["required_evidence_kinds_q"] = req_q
    else:
        params["_tier_parse_error"] = "required_evidence_kinds_q missing/invalid"
        return params

    # doc_impact_required
    doc_required = tier_obj.get("doc_impact_required")
    if isinstance(doc_required, bool):
        params["doc_impact_required"] = doc_required
    else:
        params["_tier_parse_error"] = "doc_impact_required missing/invalid"
        return params

    # command_log_mode
    clm = tier_obj.get("command_log_mode")
    if isinstance(clm, str) and clm in ("strings", "structured"):
        params["command_log_mode"] = clm
    else:
        params["_tier_parse_error"] = "command_log_mode missing/invalid"
        return params

    # scope_budgets
    sb = tier_obj.get("scope_budgets")
    if isinstance(sb, dict):
        mtf = sb.get("max_touched_files")
        mld = sb.get("max_loc_delta")
        fpe = sb.get("forbidden_paths_enforcement")
        if mtf is None or (isinstance(mtf, int) and not isinstance(mtf, bool) and mtf >= 0):
            params["scope_budgets.max_touched_files"] = mtf
        if mld is None or (isinstance(mld, int) and not isinstance(mld, bool) and mld >= 0):
            params["scope_budgets.max_loc_delta"] = mld
        if isinstance(fpe, str) and fpe in ("strict", "relaxed"):
            params["scope_budgets.forbidden_paths_enforcement"] = fpe

    # test_policy
    tp = tier_obj.get("test_policy")
    if isinstance(tp, dict):
        required = tp.get("required")
        allowed_skips = tp.get("allowed_skips")
        if isinstance(required, bool):
            params["test_policy.required"] = "yes" if required else "no"
        if isinstance(allowed_skips, bool):
            params["test_policy.allowed_skips"] = "yes" if allowed_skips else "no"

    # waiver_policy
    wp = tier_obj.get("waiver_policy")
    if isinstance(wp, dict):
        allowed = wp.get("allowed")
        max_active = wp.get("max_active_waivers")
        requires_hotl = wp.get("requires_HOTL")
        if isinstance(allowed, bool):
            params["waiver_policy.allowed"] = allowed
        if isinstance(max_active, int) and not isinstance(max_active, bool) and max_active >= 0:
            params["waiver_policy.max_active_waivers"] = max_active
        if isinstance(requires_hotl, bool):
            params["waiver_policy.requires_HOTL"] = "yes" if requires_hotl else "no"

    # envelope_policy
    ep = tier_obj.get("envelope_policy")
    if isinstance(ep, dict):
        requires_att = ep.get("requires_attestation")
        if isinstance(requires_att, bool):
            params["envelope_policy.requires_attestation"] = "yes" if requires_att else "no"
        else:
            params["_tier_parse_error"] = "Missing mandatory envelope_policy.requires_attestation"
            return params

        # Optional knobs (preserve previous defaults)
        sig_required = ep.get("attestation_signature_required")
        if isinstance(sig_required, bool):
            params["envelope_policy.attestation_signature_required"] = "yes" if sig_required else "no"
        else:
            params["envelope_policy.attestation_signature_required"] = "no"

        pinned_required = ep.get("pinned_toolchain_refs_required")
        if isinstance(pinned_required, bool):
            params["envelope_policy.pinned_toolchain_refs_required"] = "yes" if pinned_required else "no"
        else:
            params["envelope_policy.pinned_toolchain_refs_required"] = "yes"
    else:
        params["_tier_parse_error"] = "Missing envelope_policy block"
        return params

    return params


def _parse_tier_params_from_md(tiers_md: str, tier_id: str) -> dict[str, Any]:
    """Deterministic minimal parser aligned to tiers/tier-packs.md (legacy generated view).

    Returns a dict with the keys used by chain verifiers/checks.
    On parse issues that must fail-closed, returns a dict containing _tier_parse_error.
    """

    # Accept both:
    # - "### Tier 1 (tier-1)"
    # - "### 3.2 Tier 1 (tier-1)"
    header_re = re.compile(
        rf"^###\s+(?:\d+(?:\.\d+)*\s+)?Tier\s+\d+\s+\({re.escape(tier_id)}\)\s*$",
        re.MULTILINE,
    )
    m = header_re.search(tiers_md)
    if not m:
        return {"_tier_parse_error": f"Unknown tier_id: {tier_id}"}

    start = m.end()
    next_m = re.search(r"^###\s+(?:\d+(?:\.\d+)*\s+)?Tier\s+\d+\s+\(tier-\d\)\s*$", tiers_md[start:], re.MULTILINE)
    end = start + next_m.start() if next_m else len(tiers_md)
    block = tiers_md[start:end]

    params: dict[str, Any] = {}

    # required_evidence_kinds: `[...]`
    rem = re.search(r"-\s+required_evidence_kinds:\s+`([^`]+)`", block)
    if rem:
        try:
            parsed = json.loads(rem.group(1))
            if isinstance(parsed, list):
                params["required_evidence_kinds"] = parsed
            else:
                params["_tier_parse_error"] = "required_evidence_kinds is not a JSON list"
        except Exception:
            params["_tier_parse_error"] = "required_evidence_kinds is not valid JSON"

    # required_evidence_kinds_q: `[...]`
    req_q = re.search(r"-\s+required_evidence_kinds_q:\s+`([^`]+)`", block)
    if req_q:
        try:
            parsed = json.loads(req_q.group(1))
            if isinstance(parsed, list):
                params["required_evidence_kinds_q"] = parsed
            else:
                params["_tier_parse_error"] = "required_evidence_kinds_q is not a JSON list"
        except Exception:
            params["_tier_parse_error"] = "required_evidence_kinds_q is not valid JSON"

    # doc_impact_required: `true|false`
    dim = re.search(r"-\s+doc_impact_required:\s+`(true|false)`", block)
    if dim:
        params["doc_impact_required"] = dim.group(1) == "true"

    # scope_budgets:
    sb = re.search(r"^\s*-\s+scope_budgets:\s*$", block, re.MULTILINE)
    if sb:
        sub = block[sb.end() :]
        stop = re.search(r"^-\s+[a-zA-Z0-9_\-]+:\s*", sub, re.MULTILINE)
        if stop:
            sub = sub[: stop.start()]

        mtf = re.search(r"^\s*-\s+max_touched_files:\s+`(null|\d+)`\s*$", sub, re.MULTILINE)
        if mtf:
            params["scope_budgets.max_touched_files"] = None if mtf.group(1) == "null" else int(mtf.group(1))

        mld = re.search(r"^\s*-\s+max_loc_delta:\s+`(null|\d+)`\s*$", sub, re.MULTILINE)
        if mld:
            params["scope_budgets.max_loc_delta"] = None if mld.group(1) == "null" else int(mld.group(1))

        fpe = re.search(r"^\s*-\s+forbidden_paths_enforcement:\s+`(strict|relaxed)`\s*$", sub, re.MULTILINE)
        if fpe:
            params["scope_budgets.forbidden_paths_enforcement"] = fpe.group(1)

    # command_log_mode: `"strings"|"structured"`
    clm = re.search(r"-\s+command_log_mode:\s+`\"(strings|structured)\"`", block)
    if clm:
        params["command_log_mode"] = clm.group(1)

    # test_policy.required: `yes|no`
    tr = re.search(r"-\s+test_policy:\s*\n\s*-\s+required:\s+`(yes|no)`", block)
    if tr:
        params["test_policy.required"] = tr.group(1)

    ask = re.search(r"\s*-\s+allowed_skips:\s+`(yes|no)`", block)
    if ask:
        params["test_policy.allowed_skips"] = ask.group(1)

    # waiver_policy.allowed: `yes|no`
    wp = re.search(r"-\s+waiver_policy:\s*\n\s*-\s+allowed:\s+`(yes|no)`", block)
    if wp:
        params["waiver_policy.allowed"] = wp.group(1) == "yes"

    maw = re.search(r"\s*-\s+max_active_waivers:\s+`(\d+)`", block)
    if maw:
        params["waiver_policy.max_active_waivers"] = int(maw.group(1))

    rht = re.search(r"\s*-\s+requires_HOTL:\s+`(yes|no)`", block)
    if rht:
        params["waiver_policy.requires_HOTL"] = rht.group(1)

    # envelope_policy.requires_attestation: mandatory.
    ra = re.search(
        r"-\s+envelope_policy:\s*\n\s*-\s+requires_attestation:\s+`?([a-z]+)`?",
        block,
        flags=re.IGNORECASE,
    )
    if ra:
        raw = (ra.group(1) or "").strip().lower()
        if raw in ("yes", "no"):
            params["envelope_policy.requires_attestation"] = raw
        else:
            params["_tier_parse_error"] = "Invalid envelope_policy.requires_attestation (must be yes|no)"
    else:
        params["_tier_parse_error"] = "Missing mandatory envelope_policy.requires_attestation"

    # envelope_policy.attestation_signature_required: optional; default fail-closed is NOT required.
    asr = re.search(
        r"-\s+envelope_policy:\s*\n(?:\s*-\s+[^\n]+\n)*?\s*-\s+attestation_signature_required:\s+`?([a-z]+)`?",
        block,
        flags=re.IGNORECASE,
    )
    if asr:
        raw = (asr.group(1) or "").strip().lower()
        if raw in ("yes", "no"):
            params["envelope_policy.attestation_signature_required"] = raw
        else:
            params["_tier_parse_error"] = "Invalid envelope_policy.attestation_signature_required (must be yes|no)"
    else:
        params["envelope_policy.attestation_signature_required"] = "no"

    # envelope_policy.pinned_toolchain_refs_required: optional; used by Gate Q Q5.
    ptr = re.search(
        r"-\s+envelope_policy:\s*\n(?:\s*-\s+[^\n]+\n)*?\s*-\s+pinned_toolchain_refs_required:\s+`?([a-z]+)`?",
        block,
        flags=re.IGNORECASE,
    )
    if ptr:
        raw = (ptr.group(1) or "").strip().lower()
        if raw in ("yes", "no"):
            params["envelope_policy.pinned_toolchain_refs_required"] = raw
        else:
            params["_tier_parse_error"] = "Invalid envelope_policy.pinned_toolchain_refs_required (must be yes|no)"
    else:
        # Fail-closed: Gate Q uses this for semantic enforcement.
        params["envelope_policy.pinned_toolchain_refs_required"] = "yes"

    return params


def parse_tier_params(tiers_text: str, tier_id: str) -> dict[str, Any]:
    """Parse tier parameters from canonical JSON SSOT (preferred) or legacy MD view.

    Canonical: tiers/tier-packs.json
    Generated view: tiers/tier-packs.md
    """

    s = (tiers_text or "").lstrip()
    if s.startswith("{"):
        return _parse_tier_params_from_json(tiers_text, tier_id)
    return _parse_tier_params_from_md(tiers_text, tier_id)
