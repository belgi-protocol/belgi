from __future__ import annotations

from tools._shared import common as _common
from tools._sweep.model import InvariantResult


def check_cs_gs_001(root: _common.Path) -> InvariantResult:
    """CS-GS-001 — GateVerdict GO/NO-GO semantics match schema and gate specs."""

    p = _common.repo_path(root, "schemas/GateVerdict.schema.json")
    if not p.exists():
        return InvariantResult("CS-GS-001", "FAIL", [], "Missing schemas/GateVerdict.schema.json.")

    try:
        schema = _common.load_json(p)
        all_of = schema.get("allOf", [])
        if not isinstance(all_of, list):
            raise ValueError("allOf not list")

        def has_go_rule() -> bool:
            for entry in all_of:
                if not isinstance(entry, dict):
                    continue
                if entry.get("if", {}).get("properties", {}).get("verdict", {}).get("const") != "GO":
                    continue
                then = entry.get("then", {})
                props = then.get("properties", {})
                if props.get("failure_category", {}).get("const") is not None:
                    continue
                failures = props.get("failures", {})
                if failures.get("maxItems") != 0:
                    continue
                if then.get("not", {}).get("required") != ["remediation"]:
                    continue
                return True
            return False

        def has_nogo_rule() -> bool:
            for entry in all_of:
                if not isinstance(entry, dict):
                    continue
                if entry.get("if", {}).get("properties", {}).get("verdict", {}).get("const") != "NO-GO":
                    continue
                then = entry.get("then", {})
                if "remediation" not in (then.get("required") or []):
                    continue
                props = then.get("properties", {})
                if props.get("failure_category", {}).get("type") != "string":
                    continue
                failures = props.get("failures", {})
                if failures.get("minItems") != 1:
                    continue
                return True
            return False

        if not has_go_rule() or not has_nogo_rule():
            return InvariantResult(
                "CS-GS-001",
                "FAIL",
                ["schemas/GateVerdict.schema.json#/allOf"],
                "Ensure GateVerdict.schema.json encodes GO/NO-GO constraints via allOf if/then rules (GO => failure_category null, failures empty, remediation absent; NO-GO => remediation required, failure_category string, failures non-empty).",
            )
    except Exception as e:
        return InvariantResult(
            "CS-GS-001",
            "FAIL",
            ["schemas/GateVerdict.schema.json"],
            f"Fix GateVerdict schema parse/shape error ({e}), then rerun sweep.",
        )

    q = _common.repo_path(root, "gates/GATE_Q.md")
    r = _common.repo_path(root, "gates/GATE_R.md")
    if not q.exists() or not r.exists():
        return InvariantResult("CS-GS-001", "FAIL", [], "Missing gates/GATE_Q.md and/or gates/GATE_R.md.")
    q_md = _common.read_text(q)
    r_md = _common.read_text(r)

    q_needles = ["GO semantics", "failure_category = null", "failures = []", "`remediation` MUST be absent"]
    r_needles = ["GO / NO-GO semantics", "failure_category = null", "failures = []", "`remediation` MUST be absent"]
    missing_q = _common._missing_needles(q_md, q_needles)
    missing_r = _common._missing_needles(r_md, r_needles)
    if missing_q or missing_r:
        return InvariantResult(
            "CS-GS-001",
            "FAIL",
            ["gates/GATE_Q.md#31-gateverdict-gate_id--q", "gates/GATE_R.md#31-go--no-go-semantics-schema-enforced"],
            "Update gate docs to restate GateVerdict GO/NO-GO semantics exactly as schema-enforced.",
        )

    return InvariantResult(
        "CS-GS-001",
        "PASS",
        ["schemas/GateVerdict.schema.json#/allOf", "gates/GATE_Q.md#31-gateverdict-gate_id--q", "gates/GATE_R.md#31-go--no-go-semantics-schema-enforced"],
        "",
    )

def check_cs_gs_002(root: _common.Path) -> InvariantResult:
    """CS-GS-002 — Remediation instruction format is consistent."""

    gv = _common.repo_path(root, "schemas/GateVerdict.schema.json")
    ft = _common.repo_path(root, "gates/failure-taxonomy.md")
    q = _common.repo_path(root, "gates/GATE_Q.md")
    r = _common.repo_path(root, "gates/GATE_R.md")
    for rel, p in [
        ("schemas/GateVerdict.schema.json", gv),
        ("gates/failure-taxonomy.md", ft),
        ("gates/GATE_Q.md", q),
        ("gates/GATE_R.md", r),
    ]:
        if not p.exists():
            return InvariantResult("CS-GS-002", "FAIL", [], f"Missing {rel}.")

    try:
        schema = _common.load_json(gv)
        patt = schema["properties"]["remediation"]["properties"]["next_instruction"]["pattern"]
        if patt != "^Do .+ then re-run (Q|R|S)\\.$":
            return InvariantResult(
                "CS-GS-002",
                "FAIL",
                ["schemas/GateVerdict.schema.json#/properties/remediation/properties/next_instruction/pattern"],
                "Align GateVerdict remediation.next_instruction pattern to '^Do .+ then re-run (Q|R|S)\\.$' and update docs accordingly.",
            )
    except Exception as e:
        return InvariantResult("CS-GS-002", "FAIL", ["schemas/GateVerdict.schema.json"], f"Fix schema parse error ({e}).")

    ft_txt = _common.read_text(ft).lower()
    if ("must start with `do" not in ft_txt and "must start with do" not in ft_txt) or ("then re-run" not in ft_txt):
        return InvariantResult(
            "CS-GS-002",
            "FAIL",
            ["gates/failure-taxonomy.md#11-remediation-string-constraints-schema-aligned"],
            "Update failure-taxonomy remediation format section to restate the machine-parseable remediation instruction constraints.",
        )

    if ("then re-run q." not in _common.read_text(q).lower()) or ("then re-run r." not in _common.read_text(r).lower()):
        return InvariantResult(
            "CS-GS-002",
            "FAIL",
            ["gates/GATE_Q.md#31-gateverdict-gate_id--q", "gates/GATE_R.md#31-go--no-go-semantics-schema-enforced"],
            "Ensure gate docs remediation templates end with 'then re-run Q.' and 'then re-run R.' as appropriate.",
        )

    return InvariantResult(
        "CS-GS-002",
        "PASS",
        [
            "schemas/GateVerdict.schema.json#/properties/remediation/properties/next_instruction/pattern",
            "gates/failure-taxonomy.md#11-remediation-string-constraints-schema-aligned",
            "gates/GATE_Q.md#31-gateverdict-gate_id--q",
            "gates/GATE_R.md#31-go--no-go-semantics-schema-enforced",
        ],
        "",
    )

def check_cs_gs_003(root: _common.Path) -> InvariantResult:
    """CS-GS-003 — Failure category tokens used by gates exist in failure taxonomy."""

    q = _common.repo_path(root, "gates/GATE_Q.md")
    r = _common.repo_path(root, "gates/GATE_R.md")
    ft = _common.repo_path(root, "gates/failure-taxonomy.md")
    if not q.exists() or not r.exists() or not ft.exists():
        return InvariantResult("CS-GS-003", "FAIL", [], "Missing gates/GATE_Q.md, gates/GATE_R.md, or gates/failure-taxonomy.md.")

    gate_txt = _common.read_text(q) + "\n" + _common.read_text(r)
    tokens = sorted(set(_common.re.findall(r"\bF[QR]-[A-Z0-9_.-]+\b", gate_txt)))
    tax_txt = _common.read_text(ft)
    defined = set(_common.re.findall(r"(?m)^\s*-\s*category_id:\s*`?(F[QR]-[A-Z0-9_.-]+)`?\s*$", tax_txt))

    missing = [t for t in tokens if t not in defined]
    if missing:
        return InvariantResult(
            "CS-GS-003",
            "FAIL",
            ["gates/failure-taxonomy.md#1-category-ids-stable"],
            f"Define missing failure category tokens in failure-taxonomy.md (category_id): {missing[:8]}",
        )

    return InvariantResult(
        "CS-GS-003",
        "PASS",
        ["gates/GATE_Q.md#deterministic-selection-rule-for-gateverdictfailure_category", "gates/GATE_R.md#deterministic-selection-rule-for-gateverdictfailure_category", "gates/failure-taxonomy.md#1-category-ids-stable"],
        "",
    )

def check_cs_gs_004(root: _common.Path) -> InvariantResult:
    """CS-GS-004 — doc_impact contract is schema- and gate-consistent."""

    p = _common.repo_path(root, "schemas/LockedSpec.schema.json")
    if not p.exists():
        return InvariantResult("CS-GS-004", "FAIL", [], "Missing schemas/LockedSpec.schema.json.")

    try:
        schema = _common.load_json(p)
        props = schema.get("properties", {})
        if "doc_impact" not in props:
            raise KeyError("properties.doc_impact")
        di = props["doc_impact"]
        if not isinstance(di, dict):
            raise ValueError("doc_impact not object")
        di_props = di.get("properties", {})
        if "required_paths" not in di_props or "note_on_empty" not in di_props:
            return InvariantResult(
                "CS-GS-004",
                "FAIL",
                ["schemas/LockedSpec.schema.json#/properties/doc_impact"],
                "doc_impact must define required_paths and note_on_empty.",
            )

        # Tier-2/3 requirement surface.
        all_of = schema.get("allOf", [])
        tier_requires_doc_impact = False
        if isinstance(all_of, list):
            for entry in all_of:
                if not isinstance(entry, dict):
                    continue
                cond = entry.get("if", {}).get("properties", {}).get("tier", {}).get("properties", {}).get("tier_id", {})
                if cond.get("enum") == ["tier-2", "tier-3"]:
                    req = entry.get("then", {}).get("required", [])
                    if isinstance(req, list) and ("doc_impact" in req):
                        tier_requires_doc_impact = True
                        break
        if not tier_requires_doc_impact:
            return InvariantResult(
                "CS-GS-004",
                "FAIL",
                ["schemas/LockedSpec.schema.json#/allOf"],
                "Ensure LockedSpec.schema.json requires doc_impact for tier-2 and tier-3 via an allOf if/then rule.",
            )
    except Exception as e:
        return InvariantResult("CS-GS-004", "FAIL", ["schemas/LockedSpec.schema.json"], f"Fix LockedSpec schema error ({e}).")

    q = _common.repo_path(root, "gates/GATE_Q.md")
    r = _common.repo_path(root, "gates/GATE_R.md")
    if not q.exists() or not r.exists():
        return InvariantResult("CS-GS-004", "FAIL", [], "Missing gates/GATE_Q.md and/or gates/GATE_R.md.")
    q_txt = _common.read_text(q)
    r_txt = _common.read_text(r)

    required_q = ["Q-DOC-001", "Q-DOC-002", "note_on_empty"]
    required_r = ["R-DOC-001", "note_on_empty", "required_paths"]
    missing_q = _common._missing_needles(q_txt, required_q)
    missing_r = _common._missing_needles(r_txt, required_r)
    if missing_q or missing_r:
        return InvariantResult(
            "CS-GS-004",
            "FAIL",
            ["gates/GATE_Q.md#q-doc-001--doc_impact-shape--path-normalization", "gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty", "gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff"],
            "Ensure gate docs define Q-DOC-001/Q-DOC-002 and R-DOC-001 with note-on-empty semantics aligned to LockedSpec.schema.json.",
        )

    return InvariantResult(
        "CS-GS-004",
        "PASS",
        [
            "schemas/LockedSpec.schema.json#/properties/doc_impact",
            "schemas/LockedSpec.schema.json#/allOf",
            "gates/GATE_Q.md#q-doc-002--doc_impact-tier-enforcement--note-on-empty",
            "gates/GATE_R.md#r-doc-001--doc_impact-enforced-with-diff",
        ],
        "",
    )

def check_cs_gs_005(root: _common.Path) -> InvariantResult:
    """CS-GS-005 — No spec fiction: doc_impact claimed implies schema field exists."""

    schema_path = _common.repo_path(root, "schemas/LockedSpec.schema.json")
    if not schema_path.exists():
        return InvariantResult("CS-GS-005", "FAIL", [], "Missing schemas/LockedSpec.schema.json.")

    q = _common.repo_path(root, "gates/GATE_Q.md")
    r = _common.repo_path(root, "gates/GATE_R.md")
    tiers = _common.repo_path(root, "tiers/tier-packs.md")
    for rel, p in [("gates/GATE_Q.md", q), ("gates/GATE_R.md", r), ("tiers/tier-packs.md", tiers)]:
        if not p.exists():
            return InvariantResult("CS-GS-005", "FAIL", [], f"Missing {rel}.")

    any_claim = any("doc_impact" in _common.read_text(p) for p in (q, r, tiers))
    if not any_claim:
        return InvariantResult(
            "CS-GS-005",
            "PASS",
            ["docs/operations/consistency-sweep.md#cs-gs-005--no-spec-fiction-doc_impact-claimed-implies-schema-field-exists"],
            "",
        )

    try:
        schema = _common.load_json(schema_path)
        if "doc_impact" not in (schema.get("properties") or {}):
            return InvariantResult(
                "CS-GS-005",
                "FAIL",
                ["schemas/LockedSpec.schema.json#/properties"],
                "Define LockedSpec.properties.doc_impact in schemas/LockedSpec.schema.json.",
            )
    except Exception as e:
        return InvariantResult("CS-GS-005", "FAIL", ["schemas/LockedSpec.schema.json"], f"Fix LockedSpec schema parse error ({e}).")

    return InvariantResult(
        "CS-GS-005",
        "PASS",
        ["schemas/LockedSpec.schema.json#/properties/doc_impact", "tiers/tier-packs.md#27-doc_impact_required"],
        "",
    )

def check_cs_gv_001(root: _common.Path) -> InvariantResult:
    """CS-GV-001 — GateVerdict schema requires run_id."""

    p = _common.repo_path(root, "schemas/GateVerdict.schema.json")
    if not p.exists():
        return InvariantResult("CS-GV-001", "FAIL", [], "Missing schemas/GateVerdict.schema.json.")

    schema = _common.load_json(p)
    req = set(schema.get("required", []))
    props = schema.get("properties", {})
    run_prop = props.get("run_id", {}) if isinstance(props, dict) else {}

    if "run_id" not in req:
        return InvariantResult(
            "CS-GV-001",
            "FAIL",
            ["schemas/GateVerdict.schema.json#/required"],
            "Add run_id to GateVerdict required list.",
        )
    if not isinstance(run_prop, dict) or run_prop.get("type") != "string" or int(run_prop.get("minLength", 0) or 0) < 1:
        return InvariantResult(
            "CS-GV-001",
            "FAIL",
            ["schemas/GateVerdict.schema.json#/properties/run_id"],
            "Define GateVerdict.run_id as non-empty string.",
        )

    return InvariantResult("CS-GV-001", "PASS", ["schemas/GateVerdict.schema.json#/properties/run_id"], "")

def check_cs_ls_001(root: _common.Path) -> InvariantResult:
    """CS-LS-001 — LockedSpec constraints items enforce RepoRelPathPrefix normalization."""

    p = _common.repo_path(root, "schemas/LockedSpec.schema.json")
    if not p.exists():
        return InvariantResult("CS-LS-001", "FAIL", [], "Missing schemas/LockedSpec.schema.json.")

    schema = _common.load_json(p)
    try:
        constraints_props = schema["properties"]["constraints"]["properties"]
        items_allowed = constraints_props["allowed_paths"]["items"]
        items_forbidden = constraints_props["forbidden_paths"]["items"]
    except Exception:
        return InvariantResult(
            "CS-LS-001",
            "FAIL",
            ["schemas/LockedSpec.schema.json#/properties/constraints"],
            "LockedSpec.constraints missing allowed_paths/forbidden_paths items.",
        )

    def get_pattern(item_schema: _common.Any) -> str | None:
        if isinstance(item_schema, dict) and "pattern" in item_schema:
            return item_schema.get("pattern")
        if isinstance(item_schema, dict) and "$ref" in item_schema:
            ref = item_schema["$ref"]
            if isinstance(ref, str) and ref.startswith("#/"):
                target = _common.json_pointer(schema, ref)
                if isinstance(target, dict) and "pattern" in target:
                    return target.get("pattern")
        return None

    patt_a = get_pattern(items_allowed)
    patt_f = get_pattern(items_forbidden)
    if not patt_a or not patt_f:
        return InvariantResult(
            "CS-LS-001",
            "FAIL",
            [
                "schemas/LockedSpec.schema.json#/properties/constraints/properties/allowed_paths/items",
                "schemas/LockedSpec.schema.json#/properties/constraints/properties/forbidden_paths/items",
            ],
            "Ensure constraints.allowed_paths[].items and forbidden_paths[].items enforce RepoRelPathPrefix via pattern (inline or $ref).",
        )

    def forbids_dotdot(patt: str) -> bool:
        return (".." in patt) or ("\\.\\." in patt)

    must_tokens = ["(?!/)", "(?!.*\\\\)", "(?!.*\\*)", "(?!.*\\?)", "(?!.*//)", "(?!\\./)"]
    if not forbids_dotdot(patt_a) or not forbids_dotdot(patt_f):
        return InvariantResult(
            "CS-LS-001",
            "FAIL",
            ["schemas/LockedSpec.schema.json#/$defs/RepoRelPathPrefix"],
            "RepoRelPathPrefix pattern must forbid '..' segments.",
        )
    for token in must_tokens:
        if token not in patt_a or token not in patt_f:
            return InvariantResult(
                "CS-LS-001",
                "FAIL",
                ["schemas/LockedSpec.schema.json#/$defs/RepoRelPathPrefix"],
                "RepoRelPathPrefix pattern must forbid '/', './', '//', '\\', '*' and '?' patterns.",
            )

    return InvariantResult(
        "CS-LS-001",
        "PASS",
        ["schemas/LockedSpec.schema.json#/properties/constraints", "schemas/LockedSpec.schema.json#/$defs/RepoRelPathPrefix"],
        "",
    )

def check_cs_ls_002(root: _common.Path) -> InvariantResult:
    """CS-LS-002 — ToolchainSet/Tolerances locked-object authority is explicit and wired."""

    locked_schema_path = _common.repo_path(root, "schemas/LockedSpec.schema.json")
    if not locked_schema_path.exists():
        return InvariantResult(
            "CS-LS-002",
            "FAIL",
            ["schemas/LockedSpec.schema.json"],
            "Add explicit ToolchainSet/Tolerances ObjectRef fields to LockedSpec schema, then rerun sweep.",
        )

    locked_schema = _common.load_json(locked_schema_path)
    pointer_expectations = [
        ("#/properties/environment_envelope/properties/toolchain_set_ref/$ref", "#/$defs/ObjectRef"),
        ("#/properties/environment_envelope/properties/pinned_toolchain_refs/items/$ref", "#/$defs/ObjectRef"),
        ("#/properties/tier/properties/tolerances_ref/$ref", "#/$defs/ObjectRef"),
    ]
    violations: list[str] = []
    for ptr, expected in pointer_expectations:
        try:
            actual = _common.json_pointer(locked_schema, ptr)
        except Exception:
            violations.append(f"schemas/LockedSpec.schema.json{ptr} missing")
            continue
        if actual != expected:
            violations.append(f"schemas/LockedSpec.schema.json{ptr} expected {expected!r}, got {actual!r}")

    required_files = [
        "schemas/ToolchainSet.schema.json",
        "schemas/Tolerances.schema.json",
        "chain/compiler_c1_intent.py",
        "chain/logic/locked_object_schema.py",
        "chain/logic/toolchain_set.py",
        "chain/logic/tolerances.py",
        "chain/logic/q_checks/q4_constraints_present.py",
        "chain/logic/q_checks/q5_environment_envelope.py",
        "chain/logic/r_checks/r2_scope_budgets.py",
        "docs/operations/running-belgi.md",
    ]
    for rel in required_files:
        if not _common.repo_path(root, rel).exists():
            violations.append(f"{rel} missing")

    string_expectations: list[tuple[str, list[str]]] = [
        (
            "chain/compiler_c1_intent.py",
            [
                "schemas/ToolchainSet.schema.json",
                "schemas/Tolerances.schema.json",
                '"toolchain_set_ref": toolchain_set_ref_obj',
                '"tolerances_ref": tolerances_ref',
            ],
        ),
        ("chain/logic/locked_object_schema.py", ["def load_locked_schema_object(", "resolve_storage_ref", "validate_schema("]),
        ("chain/logic/toolchain_set.py", ["load_locked_schema_object", "schemas/ToolchainSet.schema.json"]),
        (
            "chain/logic/tolerances.py",
            [
                "load_locked_schema_object",
                "schemas/Tolerances.schema.json",
                "find_scope_budget_widening_against_selected_tier",
            ],
        ),
        (
            "chain/logic/q_checks/q4_constraints_present.py",
            [
                "load_locked_tolerances",
                "find_scope_budget_widening_against_selected_tier",
                "widens selected tier ceilings",
            ],
        ),
        ("chain/logic/q_checks/q5_environment_envelope.py", ["load_locked_toolchain_set"]),
        ("chain/logic/r_checks/r2_scope_budgets.py", ["load_locked_tolerances", "locked Tolerances object only"]),
        (
            "docs/operations/cli.md",
            [
                "--toolchain-set-ref",
                "--tolerances-ref",
                "may equal or tighten the selected tier ceilings, but BELGI rejects wider values",
            ],
        ),
        (
            "docs/operations/running-belgi.md",
            [
                "current-run ToolchainSet/Tolerances inputs are staged into locked/store authority before C1",
                "manual C1 uses repo-relative `--toolchain-set` / `--tolerances` inputs instead of shipped `belgi run` refs",
            ],
        ),
    ]
    for rel, needles in string_expectations:
        path = _common.repo_path(root, rel)
        if not path.exists():
            continue
        text = _common.read_text(path)
        for needle in needles:
            if needle not in text:
                violations.append(f"{rel} missing {needle!r}")

    if violations:
        return InvariantResult(
            "CS-LS-002",
            "FAIL",
            [
                "schemas/LockedSpec.schema.json",
                "schemas/ToolchainSet.schema.json",
                "schemas/Tolerances.schema.json",
                "chain/compiler_c1_intent.py",
                "chain/logic/locked_object_schema.py",
                "chain/logic/toolchain_set.py",
                "chain/logic/tolerances.py",
                "chain/logic/q_checks/q4_constraints_present.py",
                "chain/logic/q_checks/q5_environment_envelope.py",
                "chain/logic/r_checks/r2_scope_budgets.py",
                "docs/operations/cli.md",
                "docs/operations/running-belgi.md",
            ],
            "Keep ToolchainSet/Tolerances as first-class LockedSpec object authority in schema, C1, loaders, Gate Q/R consumers, and run docs, then rerun sweep.",
            {"violations_sample": violations[:12], "violations_total": len(violations)},
        )

    return InvariantResult(
        "CS-LS-002",
        "PASS",
        [
            "schemas/LockedSpec.schema.json#/properties/environment_envelope/properties/toolchain_set_ref",
            "schemas/LockedSpec.schema.json#/properties/environment_envelope/properties/pinned_toolchain_refs/items",
            "schemas/LockedSpec.schema.json#/properties/tier/properties/tolerances_ref",
            "schemas/ToolchainSet.schema.json",
            "schemas/Tolerances.schema.json",
            "chain/compiler_c1_intent.py",
            "chain/logic/locked_object_schema.py",
            "chain/logic/toolchain_set.py",
            "chain/logic/tolerances.py",
            "chain/logic/q_checks/q4_constraints_present.py",
            "chain/logic/q_checks/q5_environment_envelope.py",
            "chain/logic/r_checks/r2_scope_budgets.py",
            "docs/operations/cli.md",
            "docs/operations/running-belgi.md",
        ],
        "",
    )
