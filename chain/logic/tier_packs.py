from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TierParams:
    """Validated tier contract parameters consumed by Gate Q/R checks."""

    tier_id: str
    required_evidence_kinds: tuple[str, ...]
    required_evidence_kinds_q: tuple[str, ...]
    doc_impact_required: bool
    command_log_mode: str
    scope_budgets_max_touched_files: int | None
    scope_budgets_max_loc_delta: int | None
    scope_budgets_forbidden_paths_enforcement: str | None
    test_policy_required: str
    test_policy_allowed_skips: str
    waiver_policy_allowed: bool
    waiver_policy_max_active_waivers: int
    waiver_policy_requires_hotl: str
    envelope_policy_requires_attestation: str
    envelope_policy_attestation_signature_required: str
    envelope_policy_pinned_toolchain_refs_required: str

    def to_legacy_map(self) -> dict[str, Any]:
        # Compatibility map for existing checks while using a validated source object.
        return {
            "required_evidence_kinds": list(self.required_evidence_kinds),
            "required_evidence_kinds_q": list(self.required_evidence_kinds_q),
            "doc_impact_required": self.doc_impact_required,
            "command_log_mode": self.command_log_mode,
            "scope_budgets.max_touched_files": self.scope_budgets_max_touched_files,
            "scope_budgets.max_loc_delta": self.scope_budgets_max_loc_delta,
            "scope_budgets.forbidden_paths_enforcement": self.scope_budgets_forbidden_paths_enforcement,
            "test_policy.required": self.test_policy_required,
            "test_policy.allowed_skips": self.test_policy_allowed_skips,
            "waiver_policy.allowed": self.waiver_policy_allowed,
            "waiver_policy.max_active_waivers": self.waiver_policy_max_active_waivers,
            "waiver_policy.requires_HOTL": self.waiver_policy_requires_hotl,
            "envelope_policy.requires_attestation": self.envelope_policy_requires_attestation,
            "envelope_policy.attestation_signature_required": self.envelope_policy_attestation_signature_required,
            "envelope_policy.pinned_toolchain_refs_required": self.envelope_policy_pinned_toolchain_refs_required,
        }


@dataclass(frozen=True)
class TierParamsLoadResult:
    tier_id: str
    params: TierParams | None
    parse_error: str | None = None

    def to_legacy_map(self) -> dict[str, Any]:
        if self.params is None:
            return {"_tier_parse_error": self.parse_error or "tier parameter parse failed"}
        out = self.params.to_legacy_map()
        if self.parse_error:
            out["_tier_parse_error"] = self.parse_error
        return out


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


def _require_string_list(raw: dict[str, Any], key: str) -> tuple[str, ...]:
    v = raw.get(key)
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ValueError(f"{key} missing/invalid")
    return tuple(v)


def _require_bool(raw: dict[str, Any], key: str) -> bool:
    v = raw.get(key)
    if not isinstance(v, bool):
        raise ValueError(f"{key} missing/invalid")
    return v


def _require_int_nonneg(raw: dict[str, Any], key: str) -> int:
    v = raw.get(key)
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ValueError(f"{key} missing/invalid")
    return v


def _optional_int_nonneg(raw: dict[str, Any], key: str) -> int | None:
    v = raw.get(key)
    if v is None:
        return None
    if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
        return v
    raise ValueError(f"{key} missing/invalid")


def _optional_enum(raw: dict[str, Any], key: str, *, allowed: tuple[str, ...]) -> str | None:
    v = raw.get(key)
    if v is None:
        return None
    if isinstance(v, str) and v in allowed:
        return v
    raise ValueError(f"{key} missing/invalid")


def _require_enum(raw: dict[str, Any], key: str, *, allowed: tuple[str, ...]) -> str:
    v = raw.get(key)
    if isinstance(v, str) and v in allowed:
        return v
    raise ValueError(f"{key} missing/invalid")


def _build_validated_tier_params(raw: dict[str, Any], tier_id: str) -> TierParams:
    return TierParams(
        tier_id=tier_id,
        required_evidence_kinds=_require_string_list(raw, "required_evidence_kinds"),
        required_evidence_kinds_q=_require_string_list(raw, "required_evidence_kinds_q"),
        doc_impact_required=_require_bool(raw, "doc_impact_required"),
        command_log_mode=_require_enum(raw, "command_log_mode", allowed=("strings", "structured")),
        scope_budgets_max_touched_files=_optional_int_nonneg(raw, "scope_budgets.max_touched_files"),
        scope_budgets_max_loc_delta=_optional_int_nonneg(raw, "scope_budgets.max_loc_delta"),
        scope_budgets_forbidden_paths_enforcement=_optional_enum(
            raw,
            "scope_budgets.forbidden_paths_enforcement",
            allowed=("strict", "relaxed"),
        ),
        test_policy_required=_require_enum(raw, "test_policy.required", allowed=("yes", "no")),
        test_policy_allowed_skips=_require_enum(raw, "test_policy.allowed_skips", allowed=("yes", "no")),
        waiver_policy_allowed=_require_bool(raw, "waiver_policy.allowed"),
        waiver_policy_max_active_waivers=_require_int_nonneg(raw, "waiver_policy.max_active_waivers"),
        waiver_policy_requires_hotl=_require_enum(raw, "waiver_policy.requires_HOTL", allowed=("yes", "no")),
        envelope_policy_requires_attestation=_require_enum(
            raw,
            "envelope_policy.requires_attestation",
            allowed=("yes", "no"),
        ),
        envelope_policy_attestation_signature_required=_require_enum(
            raw,
            "envelope_policy.attestation_signature_required",
            allowed=("yes", "no"),
        ),
        envelope_policy_pinned_toolchain_refs_required=_require_enum(
            raw,
            "envelope_policy.pinned_toolchain_refs_required",
            allowed=("yes", "no"),
        ),
    )


def load_tier_params(tiers_text: str, tier_id: str) -> TierParamsLoadResult:
    """Load tier params from SSOT and return a validated object (fail-closed)."""

    s = (tiers_text or "").lstrip()
    raw = _parse_tier_params_from_json(tiers_text, tier_id) if s.startswith("{") else _parse_tier_params_from_md(tiers_text, tier_id)
    parse_err = raw.get("_tier_parse_error")
    if isinstance(parse_err, str) and parse_err:
        return TierParamsLoadResult(tier_id=tier_id, params=None, parse_error=parse_err)
    try:
        params = _build_validated_tier_params(raw, tier_id)
    except Exception as e:
        return TierParamsLoadResult(tier_id=tier_id, params=None, parse_error=str(e))
    return TierParamsLoadResult(tier_id=tier_id, params=params, parse_error=None)


def parse_tier_params(tiers_text: str, tier_id: str) -> dict[str, Any]:
    """Parse tier parameters from canonical JSON SSOT (preferred) or legacy MD view.

    Canonical: tiers/tier-packs.json
    Generated view: tiers/tier-packs.md
    """

    return load_tier_params(tiers_text, tier_id).to_legacy_map()
