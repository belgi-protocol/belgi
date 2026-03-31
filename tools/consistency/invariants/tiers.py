from __future__ import annotations

from tools.consistency import common as _common
from tools.consistency.model import InvariantResult


def check_cs_tier_001(root: _common.Path) -> InvariantResult:
    """CS-TIER-001 — Tier IDs are consistent and bounded."""

    allowed = {"tier-0", "tier-1", "tier-2", "tier-3"}
    tiers = _common.repo_path(root, "tiers/tier-packs.md")
    q = _common.repo_path(root, "gates/GATE_Q.md")
    pb = _common.repo_path(root, "belgi/templates/PromptBundle.blocks.md")
    for rel, p in [("tiers/tier-packs.md", tiers), ("gates/GATE_Q.md", q), ("belgi/templates/PromptBundle.blocks.md", pb)]:
        if not p.exists():
            return InvariantResult("CS-TIER-001", "FAIL", [], f"Missing {rel}.")

    tier_txt = _common.read_text(tiers) + "\n" + _common.read_text(q) + "\n" + _common.read_text(pb)
    used = sorted(set(_common.re.findall(r"\btier-[0-9]+\b", tier_txt)))
    bad = [t for t in used if t not in allowed]
    if bad:
        return InvariantResult(
            "CS-TIER-001",
            "FAIL",
            ["tiers/tier-packs.md#1-tier-ids", "gates/GATE_Q.md#q7--tier-id-supported"],
            f"Remove or correct unsupported tier_id token(s): {bad}",
        )

    for t in sorted(allowed):
        if t not in tier_txt:
            return InvariantResult(
                "CS-TIER-001",
                "FAIL",
                ["tiers/tier-packs.md#1-tier-ids"],
                "Ensure all supported tier IDs tier-0..tier-3 are documented in tier-packs and referenced consistently.",
            )

    return InvariantResult(
        "CS-TIER-001",
        "PASS",
        ["tiers/tier-packs.md#1-tier-ids", "gates/GATE_Q.md#q7--tier-id-supported", "belgi/templates/PromptBundle.blocks.md#fm-pb-001--unknown-or-unsupported-tier_id"],
        "",
    )

def check_cs_tier_002(root: _common.Path) -> InvariantResult:
    """CS-TIER-002 — Tier required_evidence_kinds are consistent across docs."""

    tiers = _common.repo_path(root, "tiers/tier-packs.md")
    eb = _common.repo_path(root, "docs/operations/evidence-bundles.md")
    rb = _common.repo_path(root, "docs/operations/running-belgi.md")
    for rel, p in [("tiers/tier-packs.md", tiers), ("docs/operations/evidence-bundles.md", eb), ("docs/operations/running-belgi.md", rb)]:
        if not p.exists():
            return InvariantResult("CS-TIER-002", "FAIL", [], f"Missing {rel}.")

    t_txt = _common.read_text(tiers)
    eb_txt = _common.read_text(eb)
    rb_txt = _common.read_text(rb)

    tier0 = ["diff", "command_log", "schema_validation", "policy_report"]
    tier1 = ["diff", "command_log", "schema_validation", "policy_report", "test_report", "env_attestation"]

    def doc_mentions_all(doc: str, toks: list[str]) -> bool:
        return all(f"`{t}`" in doc or t in doc for t in toks)

    def extract_tier_block(doc: str, tier_id: str) -> str | None:
        header_re = _common.re.compile(
            rf"^###\s+(?:\d+(?:\.\d+)*\s+)?Tier\s+\d+\s+\({_common.re.escape(tier_id)}\)\s*$",
            _common.re.MULTILINE,
        )
        m = header_re.search(doc)
        if not m:
            return None
        start = m.end()
        next_m = _common.re.search(r"^###\s+(?:\d+(?:\.\d+)*\s+)?Tier\s+\d+\s+\(tier-\d\)\s*$", doc[start:], _common.re.MULTILINE)
        end = start + next_m.start() if next_m else len(doc)
        return doc[start:end]

    if not doc_mentions_all(t_txt, tier0) or not doc_mentions_all(t_txt, tier1):
        return InvariantResult(
            "CS-TIER-002",
            "FAIL",
            ["tiers/tier-packs.md#3-tier-parameter-sets"],
            "Ensure tier-packs.md lists required_evidence_kinds for tier-0 and tier-1..3 exactly as specified.",
        )

    tier0_block = extract_tier_block(t_txt, "tier-0")
    if tier0_block is None or "- adversarial_policy:" not in tier0_block or "findings_mode: `warn`" not in tier0_block:
        return InvariantResult(
            "CS-TIER-002",
            "FAIL",
            ["tiers/tier-packs.md#3-tier-parameter-sets"],
            "Ensure tier-0 documents adversarial_policy.findings_mode as warn.",
        )
    for tid in ("tier-1", "tier-2", "tier-3"):
        block = extract_tier_block(t_txt, tid)
        if block is None or "- adversarial_policy:" not in block or "findings_mode: `fail`" not in block:
            return InvariantResult(
                "CS-TIER-002",
                "FAIL",
                ["tiers/tier-packs.md#3-tier-parameter-sets"],
                "Ensure tier-1..tier-3 document adversarial_policy.findings_mode as fail.",
            )
    if "| R8 |" not in t_txt or "adversarial_policy.findings_mode" not in t_txt:
        return InvariantResult(
            "CS-TIER-002",
            "FAIL",
            ["tiers/tier-packs.md#4-tier--gate-parameter-map"],
            "Ensure R8 gate parameter map includes adversarial_policy.findings_mode.",
        )

    if not doc_mentions_all(eb_txt, tier0) or not doc_mentions_all(eb_txt, tier1):
        return InvariantResult(
            "CS-TIER-002",
            "FAIL",
            ["docs/operations/evidence-bundles.md#22-tier-driven-minimums-gate-r-evidence-sufficiency"],
            "Ensure evidence-bundles.md matches the tier required_evidence_kinds sets.",
        )
    if not doc_mentions_all(rb_txt, tier0) or not doc_mentions_all(rb_txt, tier1):
        return InvariantResult(
            "CS-TIER-002",
            "FAIL",
            ["docs/operations/running-belgi.md#step-4--run-gate-r-verify"],
            "Ensure running-belgi.md matches the tier required_evidence_kinds sets.",
        )

    return InvariantResult(
        "CS-TIER-002",
        "PASS",
        [
            "tiers/tier-packs.md#3-tier-parameter-sets",
            "docs/operations/evidence-bundles.md#22-tier-driven-minimums-gate-r-evidence-sufficiency",
            "docs/operations/running-belgi.md#step-4--run-gate-r-verify",
        ],
        "",
    )

def check_cs_tier_003(root: _common.Path) -> InvariantResult:
    """CS-TIER-003 — docs_compilation_log exists but is not a Gate R requirement."""

    em = _common.repo_path(root, "schemas/EvidenceManifest.schema.json")
    tiers = _common.repo_path(root, "tiers/tier-packs.md")
    eb = _common.repo_path(root, "docs/operations/evidence-bundles.md")
    if not em.exists() or not tiers.exists() or not eb.exists():
        return InvariantResult("CS-TIER-003", "FAIL", [], "Missing EvidenceManifest schema and/or required docs.")

    try:
        schema = _common.load_json(em)
        kinds = set(schema["properties"]["artifacts"]["items"]["properties"]["kind"]["enum"])
        if "docs_compilation_log" not in kinds:
            return InvariantResult(
                "CS-TIER-003",
                "FAIL",
                ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum"],
                "Add docs_compilation_log to EvidenceManifest kind enum.",
            )
    except Exception as e:
        return InvariantResult("CS-TIER-003", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix schema parse error ({e}).")

    if "MUST NOT require" not in _common.read_text(tiers) or "docs_compilation_log" not in _common.read_text(tiers):
        return InvariantResult(
            "CS-TIER-003",
            "FAIL",
            ["tiers/tier-packs.md#21-required_evidence_kinds"],
            "Ensure tier-packs.md states Gate R MUST NOT require docs_compilation_log.",
        )
    if "MUST NOT require" not in _common.read_text(eb) or "docs_compilation_log" not in _common.read_text(eb):
        return InvariantResult(
            "CS-TIER-003",
            "FAIL",
            ["docs/operations/evidence-bundles.md#23-evidence-kinds-used-by-specific-gate-checks"],
            "Ensure evidence-bundles.md reiterates docs_compilation_log is post-R and not required by Gate R.",
        )

    return InvariantResult(
        "CS-TIER-003",
        "PASS",
        [
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum",
            "tiers/tier-packs.md#21-required_evidence_kinds",
            "docs/operations/evidence-bundles.md#23-evidence-kinds-used-by-specific-gate-checks",
        ],
        "",
    )

def check_cs_tier_004(root: _common.Path) -> InvariantResult:
    """CS-TIER-004 — command_log_mode is enforceable with the current schema."""

    tiers = _common.repo_path(root, "tiers/tier-packs.md")
    r = _common.repo_path(root, "gates/GATE_R.md")
    em = _common.repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not tiers.exists() or not r.exists() or not em.exists():
        return InvariantResult("CS-TIER-004", "FAIL", [], "Missing tiers/tier-packs.md, gates/GATE_R.md, or schemas/EvidenceManifest.schema.json.")

    try:
        schema = _common.load_json(em)
        one_of = schema["properties"]["commands_executed"]["oneOf"]
        if not isinstance(one_of, list) or len(one_of) != 2:
            raise ValueError("commands_executed.oneOf unexpected")
    except Exception as e:
        return InvariantResult(
            "CS-TIER-004",
            "FAIL",
            ["schemas/EvidenceManifest.schema.json#/properties/commands_executed/oneOf"],
            f"Fix EvidenceManifest.commands_executed oneOf shape ({e}).",
        )

    if "command_log_mode" not in _common.read_text(tiers):
        return InvariantResult(
            "CS-TIER-004",
            "FAIL",
            ["tiers/tier-packs.md#25-command_log_mode"],
            "Document tier command_log_mode and its supported values in tier-packs.md.",
        )
    r_txt = _common.read_text(r)
    must = ["command_log_mode", "commands_executed", "matching rule"]
    missing_must = _common._missing_needles(r_txt, must)
    if missing_must:
        return InvariantResult(
            "CS-TIER-004",
            "FAIL",
            ["gates/GATE_R.md#51-command-matching-rule-used-by-r1r5r6r7r8"],
            "Define deterministic command matching rules for both commands_executed representations and tie them to tier command_log_mode.",
        )

    return InvariantResult(
        "CS-TIER-004",
        "PASS",
        [
            "schemas/EvidenceManifest.schema.json#/properties/commands_executed/oneOf",
            "tiers/tier-packs.md#25-command_log_mode",
            "gates/GATE_R.md#51-command-matching-rule-used-by-r1r5r6r7r8",
        ],
        "",
    )

def check_cs_tier_005(root: _common.Path) -> InvariantResult:
    """CS-TIER-005 — doc_impact_required parameter is consistent across docs."""

    tiers = _common.repo_path(root, "tiers/tier-packs.md")
    q = _common.repo_path(root, "gates/GATE_Q.md")
    r = _common.repo_path(root, "gates/GATE_R.md")
    rb = _common.repo_path(root, "docs/operations/running-belgi.md")
    for rel, p in [("tiers/tier-packs.md", tiers), ("gates/GATE_Q.md", q), ("gates/GATE_R.md", r), ("docs/operations/running-belgi.md", rb)]:
        if not p.exists():
            return InvariantResult("CS-TIER-005", "FAIL", [], f"Missing {rel}.")

    t_txt = _common.read_text(tiers)
    required_lines = ["doc_impact_required", "tier-0", "tier-1", "tier-2", "tier-3"]
    missing_required_lines = _common._missing_needles(t_txt, required_lines)
    if missing_required_lines:
        return InvariantResult(
            "CS-TIER-005",
            "FAIL",
            ["tiers/tier-packs.md#27-doc_impact_required"],
            "Ensure tier-packs.md defines doc_impact_required and the tier-0..tier-3 mapping.",
        )

    if "doc_impact_required" not in _common.read_text(q) or "doc_impact_required" not in _common.read_text(r):
        return InvariantResult(
            "CS-TIER-005",
            "FAIL",
            ["gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty", "gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff"],
            "Ensure Gate Q Q-DOC-002 and Gate R R-DOC-001 reference doc_impact_required parameter.",
        )

    rb_txt = _common.read_text(rb)
    if "Tier 2" not in rb_txt or "Tier 3" not in rb_txt or "doc_impact" not in rb_txt:
        return InvariantResult(
            "CS-TIER-005",
            "FAIL",
            ["docs/operations/running-belgi.md#23-doc_impact-operator-requirement-for-tier-23"],
            "Ensure running-belgi.md states Tier 2–3 require doc_impact and describes the empty required_paths + note_on_empty rule.",
        )

    return InvariantResult(
        "CS-TIER-005",
        "PASS",
        [
            "tiers/tier-packs.md#27-doc_impact_required",
            "gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty",
            "gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff",
            "docs/operations/running-belgi.md#23-doc_impact-operator-requirement-for-tier-23",
        ],
        "",
    )
