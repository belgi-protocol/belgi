from __future__ import annotations

from tools._shared import common as _common
from tools._sweep.model import InvariantResult


def check_intentspec_yaml_single_block(root: _common.Path) -> InvariantResult:
    """CS-IS-001 — IntentSpec core template is machine-parseable and field-complete."""

    p = _common.repo_path(root, "belgi/templates/IntentSpec.core.template.md")
    if not p.exists():
        return InvariantResult("CS-IS-001", "FAIL", [], "Missing belgi/templates/IntentSpec.core.template.md.")

    md = _common.read_text(p)
    blocks = _common.find_fenced_blocks(md, fence_lang="yaml")
    if len(blocks) != 1:
        return InvariantResult(
            "CS-IS-001",
            "FAIL",
            ["belgi/templates/IntentSpec.core.template.md"],
            "IntentSpec.core.template.md must contain exactly one ```yaml fenced block.",
        )

    yaml_text = blocks[0]
    required_keys = ["intent_id", "title", "goal", "scope", "acceptance", "tier", "doc_impact"]
    missing = [k for k in required_keys if _common.re.search(rf"(?m)^\s*{_common.re.escape(k)}\s*:", yaml_text) is None]
    if missing:
        return InvariantResult(
            "CS-IS-001",
            "FAIL",
            ["belgi/templates/IntentSpec.core.template.md"],
            f"Missing key(s) in YAML block: {', '.join(missing)}.",
        )

    return InvariantResult("CS-IS-001", "PASS", ["belgi/templates/IntentSpec.core.template.md"], "")

def check_cs_is_002(root: _common.Path) -> InvariantResult:
    """CS-IS-002 — IntentSpec schema matches required fields and note-on-empty rule."""

    p = _common.repo_path(root, "schemas/IntentSpec.schema.json")
    if not p.exists():
        return InvariantResult("CS-IS-002", "FAIL", [], "Missing schemas/IntentSpec.schema.json.")

    try:
        schema = _common.load_json(p)
        req = set(schema.get("required", []))
        required_fields = {"intent_id", "title", "goal", "scope", "acceptance", "tier", "doc_impact"}
        if not required_fields.issubset(req):
            missing = sorted(required_fields - req)
            return InvariantResult(
                "CS-IS-002",
                "FAIL",
                ["schemas/IntentSpec.schema.json#/required"],
                f"Add required fields to IntentSpec schema: {missing}",
            )

        di = schema.get("properties", {}).get("doc_impact", {})
        if not isinstance(di, dict):
            raise ValueError("doc_impact not object")
        all_of = di.get("allOf", [])
        has_note_on_empty = False
        if isinstance(all_of, list):
            for entry in all_of:
                if not isinstance(entry, dict):
                    continue
                cond = entry.get("if", {}).get("properties", {}).get("required_paths", {})
                if cond.get("maxItems") == 0:
                    then_req = entry.get("then", {}).get("required", [])
                    if isinstance(then_req, list) and "note_on_empty" in then_req:
                        has_note_on_empty = True
                        break
        if not has_note_on_empty:
            return InvariantResult(
                "CS-IS-002",
                "FAIL",
                ["schemas/IntentSpec.schema.json#/properties/doc_impact/allOf"],
                "Add note-on-empty enforcement: when doc_impact.required_paths is empty [], require non-empty note_on_empty.",
            )

        # Wildcard/path safety: RepoRelPathPrefix must forbid '*' and '?'.
        rpp = schema.get("$defs", {}).get("RepoRelPathPrefix", {})
        patt = rpp.get("pattern") if isinstance(rpp, dict) else None
        if not isinstance(patt, str) or ("\\*" not in patt) or ("\\?" not in patt):
            return InvariantResult(
                "CS-IS-002",
                "FAIL",
                ["schemas/IntentSpec.schema.json#/$defs/RepoRelPathPrefix/pattern"],
                "Ensure RepoRelPathPrefix forbids '*' and '?' wildcards via pattern.",
            )
    except Exception as e:
        return InvariantResult("CS-IS-002", "FAIL", ["schemas/IntentSpec.schema.json"], f"Fix IntentSpec schema error ({e}).")

    return InvariantResult(
        "CS-IS-002",
        "PASS",
        [
            "schemas/IntentSpec.schema.json#/required",
            "schemas/IntentSpec.schema.json#/properties/doc_impact/allOf",
            "schemas/IntentSpec.schema.json#/$defs/RepoRelPathPrefix/pattern",
        ],
        "",
    )

def check_cs_is_003(root: _common.Path) -> InvariantResult:
    """CS-IS-003 — Gate Q enforces IntentSpec parse/validate/compile deterministically."""

    q = _common.repo_path(root, "gates/GATE_Q.md")
    if not q.exists():
        return InvariantResult("CS-IS-003", "FAIL", [], "Missing gates/GATE_Q.md.")
    txt = _common.read_text(q)

    section_cases = [
        (
            "gates/GATE_Q.md#q-intent-001--intentspec-file-present-and-yaml-block-parseable",
            "### Q-INTENT-001 — IntentSpec file present and YAML block parseable",
            ["IntentSpec.core.md", "```yaml"],
        ),
        (
            "gates/GATE_Q.md#q-intent-002--intentspec-validates-against-intentspecschemajson",
            "### Q-INTENT-002 — IntentSpec validates against IntentSpec.schema.json",
            ["schemas/IntentSpec.schema.json", "Validate the parsed YAML object against the IntentSpec schema."],
        ),
        (
            "gates/GATE_Q.md#q-intent-003--deterministic-mapping-rules-from-intentspec--lockedspec-inputs",
            "### Q-INTENT-003 — Deterministic mapping rules from IntentSpec → LockedSpec inputs",
            ["schemas/LockedSpec.schema.json", "LockedSpec.intent.intent_id", "LockedSpec.doc_impact", "LockedSpec.publication_intent"],
        ),
    ]
    for evidence, heading, needles in section_cases:
        try:
            section = _common.markdown_heading_section(txt, heading)
        except _common._UserInputError:
            section = ""
        if _common._missing_needles(section, needles):
            return InvariantResult(
                "CS-IS-003",
                "FAIL",
                [evidence],
                "Ensure Gate Q defines Q-INTENT-001/002/003 with deterministic parse, schema validate, and explicit mapping into LockedSpec fields.",
            )

    return InvariantResult(
        "CS-IS-003",
        "PASS",
        [
            "gates/GATE_Q.md#q-intent-001--intentspec-file-present-and-yaml-block-parseable",
            "gates/GATE_Q.md#q-intent-002--intentspec-validates-against-intentspecschemajson",
            "gates/GATE_Q.md#q-intent-003--deterministic-mapping-rules-from-intentspec--lockedspec-inputs",
        ],
        "",
    )

def check_cs_is_004(root: _common.Path) -> InvariantResult:
    """CS-IS-004 — IntentSpec is consistently referenced across docs."""

    targets = {
        "gates/GATE_Q.md": ["belgi/templates/IntentSpec.core.template.md", "schemas/IntentSpec.schema.json"],
        "docs/operations/running-belgi.md": ["belgi/templates/IntentSpec.core.template.md", "schemas/IntentSpec.schema.json", "IntentSpec.core.md"],
        "schemas/README.md": ["IntentSpec.schema.json", "IntentSpec.core.md"],
        "belgi/templates/IntentSpec.core.template.md": ["```yaml", "doc_impact"],
    }

    missing: list[str] = []
    for rel, needles in targets.items():
        p = _common.repo_path(root, rel)
        if not p.exists():
            missing.append(f"missing file: {rel}")
            continue
        txt = _common.read_text(p)
        for n in needles:
            if n not in txt:
                missing.append(f"{rel}: missing '{n}'")

    if missing:
        return InvariantResult(
            "CS-IS-004",
            "FAIL",
            ["docs/operations/consistency-sweep.md#cs-is-004--intentspec-is-consistently-referenced-across-gates-schemas-docs-runbook-and-templates-new"],
            "Align IntentSpec references across Gate Q, runbook, schemas docs, and template (canonical filenames and IntentSpec.core.md naming).",
        )

    return InvariantResult(
        "CS-IS-004",
        "PASS",
        [
            "gates/GATE_Q.md#1-inputs-and-outputs",
            "docs/operations/running-belgi.md#step-2--prepare-intentspeccoremd",
            "schemas/README.md#index",
            "belgi/templates/IntentSpec.core.template.md#intentspec-core--template-core-intent-contract-v1",
        ],
        "",
    )

def check_cs_is_005(root: _common.Path) -> InvariantResult:
    """CS-IS-005 — Legacy numeric-budget retirement is consistent across schema/runtime/docs."""

    schema_path = _common.repo_path(root, "schemas/IntentSpec.schema.json")
    if not schema_path.exists():
        return InvariantResult("CS-IS-005", "FAIL", ["schemas/IntentSpec.schema.json"], "Add schemas/IntentSpec.schema.json.")
    schema = _common.load_json(schema_path)
    violations: list[str] = []
    try:
        scope_props = _common.json_pointer(schema, "#/properties/scope/properties")
    except Exception:
        scope_props = {}
    if isinstance(scope_props, dict):
        for retired in ("max_touched_files", "max_loc_delta"):
            if retired in scope_props:
                violations.append(f"schemas/IntentSpec.schema.json still defines scope.{retired}")

    targets = {
        "chain/compiler_c1_intent.py": [
            "IntentSpec.scope numeric budgets are retired on the shipped run spine;",
            "move numeric budgets into a Tolerances object.",
        ],
        "chain/logic/q_checks/q_intent_003.py": [
            "IntentSpec.scope numeric budgets are retired on the shipped run spine;",
            "Do remove IntentSpec.scope.max_* and move numeric budgets into a Tolerances object ",
        ],
        "docs/operations/cli.md": [
            "numeric scope budgets no longer live in `IntentSpec`; move any legacy `IntentSpec.scope.max_*` values into the Tolerances object",
        ],
    }
    for rel, needles in targets.items():
        path = _common.repo_path(root, rel)
        if not path.exists():
            violations.append(f"missing file: {rel}")
            continue
        text = _common.read_text(path)
        for needle in needles:
            if needle not in text:
                violations.append(f"{rel} missing {needle!r}")

    if violations:
        return InvariantResult(
            "CS-IS-005",
            "FAIL",
            [
                "schemas/IntentSpec.schema.json",
                "chain/compiler_c1_intent.py",
                "chain/logic/q_checks/q_intent_003.py",
                "docs/operations/cli.md",
            ],
            "Keep legacy IntentSpec numeric-budget retirement aligned across schema, compiler, Gate Q, and operator docs.",
            {"violations_sample": violations[:12], "violations_total": len(violations)},
        )

    return InvariantResult(
        "CS-IS-005",
        "PASS",
        [
            "schemas/IntentSpec.schema.json",
            "chain/compiler_c1_intent.py",
            "chain/logic/q_checks/q_intent_003.py",
            "docs/operations/cli.md",
        ],
        "",
    )
