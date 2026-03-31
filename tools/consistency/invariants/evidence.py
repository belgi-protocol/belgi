from __future__ import annotations

from tools.consistency import common as _common
from tools.consistency.model import InvariantResult


def check_cs_ev_001(root: _common.Path) -> InvariantResult:
    """CS-EV-001 — Evidence kind enum is the single allowed vocabulary."""

    em_path = _common.repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not em_path.exists():
        return InvariantResult("CS-EV-001", "FAIL", [], "Missing schemas/EvidenceManifest.schema.json.")

    docs = [
        "docs/operations/evidence-bundles.md",
        "tiers/tier-packs.md",
        "docs/operations/cli.md",
        "docs/operations/running-belgi.md",
        "belgi/templates/DocsCompiler.template.md",
    ]

    try:
        schema = _common.load_json(em_path)
        kinds = schema["properties"]["artifacts"]["items"]["properties"]["kind"]["enum"]
        if not isinstance(kinds, list) or not all(isinstance(k, str) for k in kinds):
            raise ValueError("kind enum missing")
        kind_set = set(kinds)
    except Exception as e:
        return InvariantResult("CS-EV-001", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix EvidenceManifest schema parse error ({e}).")

    observed: set[str] = set()
    for rel in docs:
        p = _common.repo_path(root, rel)
        if not p.exists():
            return InvariantResult("CS-EV-001", "FAIL", [], f"Missing {rel}.")
        txt = _common.read_text(p)
        for tok in _common.re.findall(r"`([a-z][a-z0-9_]+)`", txt):
            if tok in kind_set or tok.endswith("_log") or tok.endswith("_report") or tok.endswith("_validation") or tok.endswith("_approval"):
                observed.add(tok)

    unknown = sorted([k for k in observed if k not in kind_set])
    if unknown:
        return InvariantResult(
            "CS-EV-001",
            "FAIL",
            ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum"],
            f"Remove or define unknown evidence kind(s) (must be in schema enum): {unknown[:8]}",
        )

    return InvariantResult(
        "CS-EV-001",
        "PASS",
        [
            "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum",
            "docs/operations/evidence-bundles.md#21-allowed-evidence-kinds-schema-enum",
            "tiers/tier-packs.md#21-required_evidence_kinds",
        ],
        "",
    )

def check_cs_ev_002(root: _common.Path) -> InvariantResult:
    """CS-EV-002 — Gate Q minimum required evidence kinds are consistent."""

    q = _common.repo_path(root, "gates/GATE_Q.md")
    em = _common.repo_path(root, "schemas/EvidenceManifest.schema.json")
    if not q.exists() or not em.exists():
        return InvariantResult("CS-EV-002", "FAIL", [], "Missing gates/GATE_Q.md and/or schemas/EvidenceManifest.schema.json.")

    q_txt = _common.read_text(q)
    must = ["Minimum required evidence kinds at Q", "`command_log`", "`policy_report`", "`schema_validation`"]
    missing_must = _common._missing_needles(q_txt, must)
    if missing_must:
        return InvariantResult(
            "CS-EV-002",
            "FAIL",
            ["gates/GATE_Q.md#33-evidencemanifest-reference"],
            "Update Gate Q to explicitly require command_log, policy_report, and schema_validation at minimum.",
        )

    try:
        schema = _common.load_json(em)
        kinds = set(schema["properties"]["artifacts"]["items"]["properties"]["kind"]["enum"])
    except Exception as e:
        return InvariantResult("CS-EV-002", "FAIL", ["schemas/EvidenceManifest.schema.json"], f"Fix schema parse error ({e}).")

    required = {"command_log", "policy_report", "schema_validation"}
    if not required.issubset(kinds):
        return InvariantResult(
            "CS-EV-002",
            "FAIL",
            ["schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum"],
            "Ensure EvidenceManifest kind enum includes command_log, policy_report, and schema_validation.",
        )

    return InvariantResult(
        "CS-EV-002",
        "PASS",
        ["gates/GATE_Q.md#33-evidencemanifest-reference", "schemas/EvidenceManifest.schema.json#/properties/artifacts/items/properties/kind/enum"],
        "",
    )

def check_cs_ev_003(root: _common.Path) -> InvariantResult:
    """CS-EV-003 — Gate R evidence sufficiency rule is tier-driven."""

    r = _common.repo_path(root, "gates/GATE_R.md")
    tiers = _common.repo_path(root, "tiers/tier-packs.md")
    if not r.exists() or not tiers.exists():
        return InvariantResult("CS-EV-003", "FAIL", [], "Missing gates/GATE_R.md and/or tiers/tier-packs.md.")

    r_txt = _common.read_text(r).lower()
    t_txt = _common.read_text(tiers).lower()
    must_r = ["evidence sufficiency rule", "required_evidence_kinds", "evidencemanifest"]
    must_t = ["required_evidence_kinds", "tier 0", "tier 1", "tier 2", "tier 3"]
    missing_r = _common._missing_needles(r_txt, must_r)
    missing_t = _common._missing_needles(t_txt, must_t)
    if missing_r or missing_t:
        return InvariantResult(
            "CS-EV-003",
            "FAIL",
            ["gates/GATE_R.md#4-evidence-sufficiency-rule-deterministic", "tiers/tier-packs.md#21-required_evidence_kinds"],
            "Ensure Gate R derives evidence sufficiency from tier required_evidence_kinds and tier-packs defines the parameter set.",
        )

    return InvariantResult(
        "CS-EV-003",
        "PASS",
        ["gates/GATE_R.md#4-evidence-sufficiency-rule-deterministic", "tiers/tier-packs.md#21-required_evidence_kinds"],
        "",
    )

def check_cs_ev_004(root: _common.Path) -> InvariantResult:
    """CS-EV-004 — Post-R evidence must be append-only and preserve the R-snapshot."""

    eb = _common.repo_path(root, "docs/operations/evidence-bundles.md")
    rb = _common.repo_path(root, "docs/operations/running-belgi.md")
    dc = _common.repo_path(root, "belgi/templates/DocsCompiler.template.md")
    for rel, p in [
        ("docs/operations/evidence-bundles.md", eb),
        ("docs/operations/running-belgi.md", rb),
        ("belgi/templates/DocsCompiler.template.md", dc),
    ]:
        if not p.exists():
            return InvariantResult("CS-EV-004", "FAIL", [], f"Missing {rel}.")

    eb_txt = _common.read_text(eb)
    rb_txt = _common.read_text(rb)
    dc_txt = _common.read_text(dc)

    need = ["append-only", "R-Snapshot"]
    if (not all(s in eb_txt for s in need)) or ("append-only" not in rb_txt) or ("append-only" not in dc_txt):
        return InvariantResult(
            "CS-EV-004",
            "FAIL",
            [
                "docs/operations/evidence-bundles.md#evidence-mutability-r-snapshot-and-replay-integrity-normative",
                "docs/operations/running-belgi.md#step-5--run-c3-docs-compiler",
                "belgi/templates/DocsCompiler.template.md#b5-verification-expectations-gate-r--replay",
            ],
            "Align docs to state R-Snapshot immutability and append-only Final EvidenceManifest extension semantics.",
        )

    return InvariantResult(
        "CS-EV-004",
        "PASS",
        [
            "docs/operations/evidence-bundles.md#evidence-mutability-r-snapshot-and-replay-integrity-normative",
            "docs/operations/running-belgi.md#step-5--run-c3-docs-compiler",
            "belgi/templates/DocsCompiler.template.md#b5-verification-expectations-gate-r--replay",
        ],
        "",
    )

def check_cs_ev_005(root: _common.Path) -> InvariantResult:
    """CS-EV-005 — Seal binds the core replay set (including waivers)."""

    sm = _common.repo_path(root, "schemas/SealManifest.schema.json")
    eb = _common.repo_path(root, "docs/operations/evidence-bundles.md")
    can = _common.repo_path(root, "CANONICALS.md")
    if not sm.exists() or not eb.exists() or not can.exists():
        return InvariantResult("CS-EV-005", "FAIL", [], "Missing SealManifest schema and/or required docs.")

    try:
        schema = _common.load_json(sm)
        req = set(schema.get("required", []))
        must_req = {"locked_spec_ref", "gate_q_verdict_ref", "gate_r_verdict_ref", "evidence_manifest_ref", "waivers"}
        if not must_req.issubset(req):
            return InvariantResult(
                "CS-EV-005",
                "FAIL",
                ["schemas/SealManifest.schema.json#/required"],
                "SealManifest must require locked_spec_ref, gate_q_verdict_ref, gate_r_verdict_ref, evidence_manifest_ref, and waivers.",
            )
        waivers = schema.get("properties", {}).get("waivers", {})
        if not isinstance(waivers, dict) or waivers.get("type") != "array":
            return InvariantResult(
                "CS-EV-005",
                "FAIL",
                ["schemas/SealManifest.schema.json#/properties/waivers"],
                "SealManifest.waivers must be an array of ObjectRef items (may be empty).",
            )
    except Exception as e:
        return InvariantResult("CS-EV-005", "FAIL", ["schemas/SealManifest.schema.json"], f"Fix SealManifest schema error ({e}).")

    if ("mandatory artifacts" not in _common.read_text(eb).lower()) or ("waiver" not in _common.read_text(can).lower()):
        return InvariantResult(
            "CS-EV-005",
            "FAIL",
            ["docs/operations/evidence-bundles.md#11-mandatory-artifacts-minimum-replay-set", "CANONICALS.md#waivers"],
            "Ensure evidence-bundles and CANONICALS require seal binding of the core replay set and applied waivers.",
        )

    return InvariantResult(
        "CS-EV-005",
        "PASS",
        [
            "schemas/SealManifest.schema.json#/required",
            "schemas/SealManifest.schema.json#/properties/waivers",
            "docs/operations/evidence-bundles.md#11-mandatory-artifacts-minimum-replay-set",
            "CANONICALS.md#waivers",
        ],
        "",
    )
