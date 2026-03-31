from __future__ import annotations

from tools.consistency import common as _common
from tools.consistency.model import InvariantResult


def check_cs_ref_001(root: _common.Path) -> InvariantResult:
    """CS-REF-001 — ObjectRef storage_ref is constrained in every schema definition."""

    targets = [
        ("schemas/LockedSpec.schema.json", "#/$defs/ObjectRef/properties/storage_ref"),
        ("schemas/EvidenceManifest.schema.json", "#/$defs/ObjectRef/properties/storage_ref"),
        ("schemas/GateVerdict.schema.json", "#/$defs/ObjectRef/properties/storage_ref"),
        ("schemas/SealManifest.schema.json", "#/$defs/ObjectRef/properties/storage_ref"),
        ("schemas/Waiver.schema.json", "#/$defs/AuditTrailRef/properties/storage_ref"),
    ]

    bad: _common.List[str] = []
    for rel, ptr in targets:
        p = _common.repo_path(root, rel)
        if not p.exists():
            bad.append(f"{rel} (missing)")
            continue
        doc = _common.load_json(p)
        try:
            sr = _common.json_pointer(doc, ptr)
        except Exception:
            bad.append(f"{rel}{ptr} (missing)")
            continue
        if not isinstance(sr, dict) or "pattern" not in sr:
            bad.append(f"{rel}{ptr} (no pattern)")
            continue
        patt = sr.get("pattern")
        if not isinstance(patt, str) or not patt:
            bad.append(f"{rel}{ptr} (empty pattern)")
            continue
        required_fragments = ["(?!/)", "(?!.*\\\\)", "(?!.*://)", "(?!.*:)", "(?!.*//)", "(?!\\./)"]
        has_dotdot_forbid = (".." in patt) or ("\\.\\." in patt)
        if (not has_dotdot_forbid) or any(frag not in patt for frag in required_fragments):
            bad.append(f"{rel}{ptr} (pattern missing required constraints)")

    if bad:
        return InvariantResult(
            "CS-REF-001",
            "FAIL",
            bad[:8],
            "Constrain storage_ref with a safe local-only pattern in all schema ObjectRef-like definitions.",
        )

    return InvariantResult("CS-REF-001", "PASS", [f"{rel}{ptr}" for rel, ptr in targets], "")

def check_cs_verify_bundle_001(root: _common.Path) -> InvariantResult:
    """CS-VERIFY_BUNDLE-001 — Canonical verifier entrypoint exists."""

    p = _common.repo_path(root, "chain/gate_r_verify.py")
    if not p.exists():
        return InvariantResult(
            "CS-VERIFY_BUNDLE-001",
            "FAIL",
            [],
            "Add chain/gate_r_verify.py deterministic verifier entrypoint and rerun sweep.",
        )

    return InvariantResult("CS-VERIFY_BUNDLE-001", "PASS", ["chain/gate_r_verify.py"], "")

def check_cs_gate_r_mandates_verify_bundle_001(root: _common.Path) -> InvariantResult:
    """CS-GATE_R-MANDATES-VERIFY_BUNDLE-001 — Gate R explicitly requires verify_bundle."""

    p = _common.repo_path(root, "gates/GATE_R.md")
    if not p.exists():
        return InvariantResult("CS-GATE_R-MANDATES-VERIFY_BUNDLE-001", "FAIL", [], "Missing gates/GATE_R.md.")

    md = _common.read_text(p)
    try:
        verifier_section = _common.markdown_heading_section(md, "### 5.2.2 Canonical deterministic verifier (MUST)")
    except _common._UserInputError:
        verifier_section = ""
    must_have = [
        "chain/gate_r_verify.py",
        "MUST",
        "must match exactly one",
        "sha256(bytes)",
        "PolicyReportPayload.schema.json",
        "TestReportPayload.schema.json",
    ]
    missing = [s for s in must_have if s not in verifier_section]
    if missing:
        return InvariantResult(
            "CS-GATE_R-MANDATES-VERIFY_BUNDLE-001",
            "FAIL",
            ["gates/GATE_R.md#522-canonical-deterministic-verifier-must"],
            f"Gate R must explicitly mandate the canonical verifier and its enforced contracts; missing: {missing[:5]}",
        )

    return InvariantResult(
        "CS-GATE_R-MANDATES-VERIFY_BUNDLE-001",
        "PASS",
        ["gates/GATE_R.md#522-canonical-deterministic-verifier-must"],
        "",
    )

def check_cs_verify_bundle_gateverdict_binding_001(root: _common.Path) -> InvariantResult:
    """CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001 — Gate R mentions optional verdict→manifest binding."""

    p = _common.repo_path(root, "gates/GATE_R.md")
    if not p.exists():
        return InvariantResult("CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001", "FAIL", [], "Missing gates/GATE_R.md.")

    md = _common.read_text(p)
    try:
        verifier_section = _common.markdown_heading_section(md, "### 5.2.2 Canonical deterministic verifier (MUST)")
    except _common._UserInputError:
        verifier_section = ""
    must_phrases = [
        "GateVerdict.evidence_manifest_ref",
        "MUST",
        "resolve",
        "sha256",
        "gate_r_verify",
    ]
    if not all(s.lower() in verifier_section.lower() for s in must_phrases):
        return InvariantResult(
            "CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001",
            "FAIL",
            ["gates/GATE_R.md#522-canonical-deterministic-verifier-must"],
            "When GateVerdict is provided, Gate R must state the verdict's evidence_manifest_ref resolves under repo root and sha256(bytes) matches the declared hash.",
        )

    return InvariantResult(
        "CS-VERIFY_BUNDLE-GATEVERDICT-BINDING-001",
        "PASS",
        ["gates/GATE_R.md#522-canonical-deterministic-verifier-must"],
        "",
    )
