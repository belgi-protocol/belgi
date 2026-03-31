from __future__ import annotations

from tools._shared import common as _common
from tools._sweep.model import InvariantResult


def check_cs_tpl_001(root: _common.Path) -> InvariantResult:
    """CS-TPL-001 — PromptBundle policy_report payload includes required hashes and block identifiers."""

    pb = _common.repo_path(root, "belgi/templates/PromptBundle.blocks.md")
    em = _common.repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not pb.exists() or not em.exists():
        return InvariantResult("CS-TPL-001", "FAIL", [], "Missing PromptBundle template and/or EvidenceManifest schema.")

    pb_txt = _common.read_text(pb)
    try:
        policy_report_section = _common.markdown_heading_section(
            pb_txt,
            "### A5.1 Required evidence artifact (policy_report)",
        )
    except _common._UserInputError:
        policy_report_section = ""
    must = ["A5.1", "block_ids", "block_hashes", "prompt_bundle_manifest_hash", "prompt_bundle_bytes_hash"]
    missing_must = _common._missing_needles(policy_report_section, must)
    if missing_must:
        return InvariantResult(
            "CS-TPL-001",
            "FAIL",
            ["belgi/templates/PromptBundle.blocks.md#a51-required-evidence-artifact-policy_report"],
            "Ensure PromptBundle.blocks.md A5.1 lists required policy_report payload fields (block_ids/block_hashes and prompt_bundle hashes).",
        )

    try:
        schema = _common.load_json(em)
        req = set(schema["properties"]["artifacts"]["items"]["required"])
        need = {"kind", "id", "hash", "media_type", "storage_ref", "produced_by"}
        if not need.issubset(req):
            return InvariantResult(
                "CS-TPL-001",
                "FAIL",
                ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/required"],
                "Ensure EvidenceManifest.artifacts[] supports indexing via kind/id/hash/media_type/storage_ref/produced_by without schema extension.",
            )
    except Exception as e:
        return InvariantResult("CS-TPL-001", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix EvidenceManifest schema error ({e}).")

    return InvariantResult(
        "CS-TPL-001",
        "PASS",
        [
            "belgi/templates/PromptBundle.blocks.md#a51-required-evidence-artifact-policy_report",
            "belgi/templates/PromptBundle.blocks.md#a34-canonical-promptbundle-hash",
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/required",
        ],
        "",
    )

def check_cs_tpl_002(root: _common.Path) -> InvariantResult:
    """CS-TPL-002 — PromptBundle integrity binds LockedSpec.prompt_bundle_ref."""

    pb = _common.repo_path(root, "belgi/templates/PromptBundle.blocks.md")
    ls = _common.repo_path(root, "schemas/LockedSpec.schema.json")
    if not pb.exists() or not ls.exists():
        return InvariantResult("CS-TPL-002", "FAIL", [], "Missing PromptBundle template and/or LockedSpec schema.")

    if "LockedSpec.prompt_bundle_ref" not in _common.read_text(pb) and "prompt_bundle_ref" not in _common.read_text(pb):
        return InvariantResult(
            "CS-TPL-002",
            "FAIL",
            ["belgi/templates/PromptBundle.blocks.md#a52-relationship-to-lockedspecprompt_bundle_ref"],
            "Ensure PromptBundle.blocks.md defines the relationship to LockedSpec.prompt_bundle_ref and deterministic integrity checks.",
        )

    try:
        schema = _common.load_json(ls)
        if "prompt_bundle_ref" not in (schema.get("required") or []):
            return InvariantResult(
                "CS-TPL-002",
                "FAIL",
                ["schemas/LockedSpec.schema.json#/required"],
                "Ensure LockedSpec schema requires prompt_bundle_ref.",
            )
    except Exception as e:
        return InvariantResult("CS-TPL-002", "FAIL", ["schemas/LockedSpec.schema.json"], f"Fix LockedSpec schema error ({e}).")

    return InvariantResult(
        "CS-TPL-002",
        "PASS",
        [
            "belgi/templates/PromptBundle.blocks.md#a52-relationship-to-lockedspecprompt_bundle_ref",
            "belgi/templates/PromptBundle.blocks.md#fm-pb-004--hash-mismatch-between-declared-and-produced-artifacts",
            "schemas/LockedSpec.schema.json#/properties/prompt_bundle_ref",
        ],
        "",
    )

def check_cs_tpl_003(root: _common.Path) -> InvariantResult:
    """CS-TPL-003 — DocsCompiler emits docs_compilation_log via existing schema fields."""

    dc = _common.repo_path(root, "belgi/templates/DocsCompiler.template.md")
    em = _common.repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not dc.exists() or not em.exists():
        return InvariantResult("CS-TPL-003", "FAIL", [], "Missing DocsCompiler template and/or EvidenceManifest schema.")

    dc_txt = _common.read_text(dc)
    try:
        docs_log_section = _common.markdown_heading_section(
            dc_txt,
            "### B4.2 Required evidence artifact: docs_compilation_log",
        )
    except _common._UserInputError:
        docs_log_section = ""

    must = [
        "docs_compilation_log",
        "EvidenceManifest.artifacts[]",
        '`kind`: `"docs_compilation_log"`',
        '`produced_by`: `"C3"`',
    ]
    if _common._missing_needles(docs_log_section, must):
        return InvariantResult(
            "CS-TPL-003",
            "FAIL",
            ["belgi/templates/DocsCompiler.template.md#b42-required-evidence-artifact-docs_compilation_log"],
            "Ensure DocsCompiler.template.md requires a docs_compilation_log artifact and specifies EvidenceManifest indexing.",
        )

    try:
        schema = _common.load_json(em)
        kinds = set(schema["properties"]["artifacts"]["items"]["properties"]["kind"]["enum"])
        produced = set(schema["properties"]["artifacts"]["items"]["properties"]["produced_by"]["enum"])
        if "docs_compilation_log" not in kinds:
            return InvariantResult(
                "CS-TPL-003",
                "FAIL",
                ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum"],
                "Add docs_compilation_log to EvidenceManifest kind enum.",
            )
        if "C3" not in produced:
            return InvariantResult(
                "CS-TPL-003",
                "FAIL",
                ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/produced_by/enum"],
                "Add C3 to EvidenceManifest.produced_by enum.",
            )
    except Exception as e:
        return InvariantResult("CS-TPL-003", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix EvidenceManifest schema error ({e}).")

    return InvariantResult(
        "CS-TPL-003",
        "PASS",
        [
            "belgi/templates/DocsCompiler.template.md#b42-required-evidence-artifact-docs_compilation_log",
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum",
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/produced_by/enum",
        ],
        "",
    )

def check_cs_tpl_004(root: _common.Path) -> InvariantResult:
    """CS-TPL-004 — Gate R obligations rely on existing evidence artifact indexing (no new schema fields)."""

    r = _common.repo_path(root, "gates/GATE_R.md")
    em = _common.repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not r.exists() or not em.exists():
        return InvariantResult("CS-TPL-004", "FAIL", [], "Missing gates/GATE_R.md and/or schemas/EvidenceManifest.schema.json.")

    r_txt = _common.read_text(r)
    must = [
        "policy report",
        "commands_executed",
        "Resolve bytes via the artifact’s `storage_ref`",
        "Compute `sha256(bytes)`",
        "PolicyReportPayload.schema.json",
        "TestReportPayload.schema.json",
        "MUST match **exactly one**",
    ]
    if any(m.lower() not in r_txt.lower() for m in must):
        return InvariantResult(
            "CS-TPL-004",
            "FAIL",
            ["gates/GATE_R.md#521-required-report-artifact-integrity--payload-validation-required"],
            "Ensure Gate R specifies required policy_report obligations satisfied via EvidenceManifest indexing + storage_ref bytes->hash verification + payload schema validation.",
        )

    try:
        schema = _common.load_json(em)
        _ = schema["properties"]["artifacts"]["items"]["required"]
        _ = schema["properties"]["commands_executed"]["oneOf"]
    except Exception as e:
        return InvariantResult("CS-TPL-004", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix EvidenceManifest schema error ({e}).")

    return InvariantResult(
        "CS-TPL-004",
        "PASS",
        [
            "gates/GATE_R.md#52-policy-report-naming-convention-used-by-r1r7r8",
            "gates/GATE_R.md#51-command-matching-rule-used-by-r1r5r6r7r8",
            "gates/GATE_R.md#521-required-report-artifact-integrity--payload-validation-required",
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/required",
            "schemas/EvidenceManifest.schema.json#/properties/commands_executed/oneOf",
        ],
        "",
    )

def check_cs_tpl_005(root: _common.Path) -> InvariantResult:
    """CS-TPL-005 — Docs compilation does not change verification outcomes."""

    dc = _common.repo_path(root, "belgi/templates/DocsCompiler.template.md")
    can = _common.repo_path(root, "CANONICALS.md")
    tiers = _common.repo_path(root, "tiers/tier-packs.md")
    for rel, p in [("belgi/templates/DocsCompiler.template.md", dc), ("CANONICALS.md", can), ("tiers/tier-packs.md", tiers)]:
        if not p.exists():
            return InvariantResult("CS-TPL-005", "FAIL", [], f"Missing {rel}.")

    dc_txt = _common.read_text(dc)
    if "post-verification" not in dc_txt.lower() or "must not change verification outcomes" not in dc_txt.lower():
        return InvariantResult(
            "CS-TPL-005",
            "FAIL",
            ["belgi/templates/DocsCompiler.template.md#b1-purpose"],
            "Ensure DocsCompiler.template.md states C3 is post-verification and must not change Gate R outcomes.",
        )
    if "MUST NOT require" not in _common.read_text(tiers) or "docs_compilation_log" not in _common.read_text(tiers):
        return InvariantResult(
            "CS-TPL-005",
            "FAIL",
            ["tiers/tier-packs.md#21-required_evidence_kinds"],
            "Ensure tier-packs note states Gate R MUST NOT require docs_compilation_log.",
        )
    if "C3" not in _common.read_text(can) or "Docs Compiler" not in _common.read_text(can):
        return InvariantResult(
            "CS-TPL-005",
            "FAIL",
            ["CANONICALS.md#c3-docs-compiler"],
            "Ensure CANONICALS describes C3 as deterministic documentation from the verified state.",
        )

    return InvariantResult(
        "CS-TPL-005",
        "PASS",
        [
            "belgi/templates/DocsCompiler.template.md#b5-verification-expectations-gate-r--replay",
            "tiers/tier-packs.md#21-required_evidence_kinds",
            "CANONICALS.md#c3-docs-compiler",
        ],
        "",
    )
