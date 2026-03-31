from __future__ import annotations

from tools._shared import common as _common
from tools._sweep.model import InvariantResult


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

    tiers_txt = _common.read_text(tiers)
    try:
        command_log_mode_section = _common.markdown_heading_section(tiers_txt, "### 2.5 command_log_mode")
    except _common._UserInputError:
        command_log_mode_section = ""
    if _common._missing_needles(command_log_mode_section, ["command_log_mode", "commands_executed", "`strings`", "`structured`"]):
        return InvariantResult(
            "CS-TIER-004",
            "FAIL",
            ["tiers/tier-packs.md#25-command_log_mode"],
            "Document tier command_log_mode and its supported values in tier-packs.md.",
        )
    r_txt = _common.read_text(r)
    try:
        command_log_mode_slice = _common.markdown_marker_slice(
            r_txt,
            start_marker="Additionally, Gate R MUST enforce the tier’s `command_log_mode` deterministically:",
            end_marker="## 5. Deterministic Checks (Executable Doc)",
        )
    except _common._UserInputError:
        command_log_mode_slice = ""
    if _common._missing_needles(
        command_log_mode_slice,
        ["command_log_mode", "EvidenceManifest.commands_executed", "structured command records", "R0.command_log_mode"],
    ):
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

    def _mentions_tier_23_scope(section: str) -> bool:
        return (
            "Tier 2–3" in section
            or "Tier 2-3" in section
            or ("Tier 2" in section and "Tier 3" in section)
        )

    tiers = _common.repo_path(root, "tiers/tier-packs.md")
    q = _common.repo_path(root, "gates/GATE_Q.md")
    r = _common.repo_path(root, "gates/GATE_R.md")
    rb = _common.repo_path(root, "docs/operations/running-belgi.md")
    for rel, p in [("tiers/tier-packs.md", tiers), ("gates/GATE_Q.md", q), ("gates/GATE_R.md", r), ("docs/operations/running-belgi.md", rb)]:
        if not p.exists():
            return InvariantResult("CS-TIER-005", "FAIL", [], f"Missing {rel}.")

    t_txt = _common.read_text(tiers)
    try:
        doc_impact_required_section = _common.markdown_heading_section(t_txt, "### 2.7 doc_impact_required")
    except _common._UserInputError:
        doc_impact_required_section = ""
    if _common._missing_needles(doc_impact_required_section, ["doc_impact_required", "tier-0", "tier-1", "tier-2", "tier-3"]):
        return InvariantResult(
            "CS-TIER-005",
            "FAIL",
            ["tiers/tier-packs.md#27-doc_impact_required"],
            "Ensure tier-packs.md defines doc_impact_required and the tier-0..tier-3 mapping.",
        )

    q_txt = _common.read_text(q)
    try:
        q_doc_section = _common.markdown_heading_section(
            q_txt,
            "### Q-DOC-002 — doc_impact tier enforcement (presence + note-on-empty)",
        )
    except _common._UserInputError:
        q_doc_section = ""
    if "doc_impact_required" not in q_doc_section:
        return InvariantResult(
            "CS-TIER-005",
            "FAIL",
            ["gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty"],
            "Ensure Gate Q Q-DOC-002 and Gate R R-DOC-001 reference doc_impact_required parameter.",
        )

    r_txt = _common.read_text(r)
    try:
        r_doc_section = _common.markdown_heading_section(
            r_txt,
            "### R-DOC-001 — doc_impact required docs touched (contract compliance)",
        )
    except _common._UserInputError:
        r_doc_section = ""
    if "doc_impact_required" not in r_doc_section:
        return InvariantResult(
            "CS-TIER-005",
            "FAIL",
            ["gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff"],
            "Ensure Gate Q Q-DOC-002 and Gate R R-DOC-001 reference doc_impact_required parameter.",
        )

    rb_txt = _common.read_text(rb)
    try:
        running_belgi_section = _common.markdown_heading_section(
            rb_txt,
            "### 2.3 doc_impact (operator requirement for Tier 2–3)",
        )
    except _common._UserInputError:
        running_belgi_section = ""
    running_belgi_missing = _common._missing_needles(
        running_belgi_section,
        ["doc_impact", "required_paths", "note_on_empty"],
    )
    has_empty_rule = "[]" in running_belgi_section or "empty" in running_belgi_section.lower()
    if running_belgi_missing or not _mentions_tier_23_scope(running_belgi_section) or not has_empty_rule:
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
