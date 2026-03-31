from __future__ import annotations

from tools.canonicals_report import CanonicalsReportError, derive_canonicals_report
from tools.consistency import common as _common
from tools.consistency.model import InvariantResult

_C3_CANONICAL_MIRROR_BINDINGS: tuple[tuple[str, str], ...] = (
    ("CANONICALS.md", "belgi/canonicals/CANONICALS.md"),
    ("terminology.md", "belgi/canonicals/terminology.md"),
    ("trust-model.md", "belgi/canonicals/trust-model.md"),
    ("docs/operations/consistency-sweep.md", "belgi/canonicals/docs/operations/consistency-sweep.md"),
    ("docs/operations/cli.md", "belgi/canonicals/docs/operations/cli.md"),
    ("docs/operations/evidence-bundles.md", "belgi/canonicals/docs/operations/evidence-bundles.md"),
    ("docs/operations/evidence-ownership.md", "belgi/canonicals/docs/operations/evidence-ownership.md"),
    ("docs/operations/operator-anchors.md", "belgi/canonicals/docs/operations/operator-anchors.md"),
    ("docs/operations/running-belgi.md", "belgi/canonicals/docs/operations/running-belgi.md"),
    ("docs/operations/security.md", "belgi/canonicals/docs/operations/security.md"),
    ("docs/operations/waivers.md", "belgi/canonicals/docs/operations/waivers.md"),
    ("docs/research/README.md", "belgi/canonicals/docs/research/README.md"),
    ("docs/research/experiment-design.md", "belgi/canonicals/docs/research/experiment-design.md"),
    ("docs/research/metrics.md", "belgi/canonicals/docs/research/metrics.md"),
)

_TERM_GUARD_FIXED_FILES: tuple[str, ...] = (
    "README.md",
    "CANONICALS.md",
    "WHITEPAPER.md",
    "terminology.md",
    "trust-model.md",
    "schemas/README.md",
    "belgi/_protocol_packs/v1/schemas/README.md",
)

_TERM_GUARD_PREFIXES: tuple[str, ...] = (
    "docs/",
    "gates/",
    "tiers/",
    "belgi/_protocol_packs/v1/gates/",
    "belgi/_protocol_packs/v1/tiers/",
)

_TERM_GUARD_ALLOWED_CONTEXTS: tuple[str, ...] = (
    "schema",
    "schema_validation",
    ".schema.json",
    "format validation",
    "parse validation",
    "input validation",
)


def _load_derived_canonicals_report(root: _common.Path) -> dict[str, object]:
    try:
        report = derive_canonicals_report(root)
    except (CanonicalsReportError, ValueError, OSError) as e:
        raise _common._UserInputError(str(e)) from e

    anchor_registry_ids = report.get("anchor_registry_ids")
    if not isinstance(anchor_registry_ids, list) or not all(isinstance(item, str) for item in anchor_registry_ids):
        raise _common._UserInputError("Derived canonicals report is missing string anchor_registry_ids.")

    canonical_chain = report.get("canonical_chain")
    if not isinstance(canonical_chain, dict):
        raise _common._UserInputError("Derived canonicals report is missing canonical_chain.")

    sequence = canonical_chain.get("sequence")
    if not isinstance(sequence, list) or not all(isinstance(item, str) and item for item in sequence):
        raise _common._UserInputError("Derived canonicals report canonical_chain.sequence is malformed.")

    return report


def _format_arrow_chain_sequence(sequence: _common.Sequence[str]) -> str:
    return " → ".join(str(item) for item in sequence)


def _extract_arrow_chain_sequence(text: str) -> list[str]:
    sequence = [part.strip(" `") for part in str(text or "").split("→")]
    if len(sequence) < 2 or any(not part for part in sequence):
        raise _common._UserInputError("Arrow chain is missing one or more stage labels.")
    return sequence


def _extract_labeled_arrow_chain_sequence(md: str, label: str) -> list[str]:
    pattern = _common.re.compile(rf"(?im)^\s*{_common.re.escape(label)}\s*:\s*`([^`]+)`")
    match = pattern.search(md)
    if match is None:
        raise _common._UserInputError(f"Missing `{label}:` line with a backticked arrow chain.")
    return _extract_arrow_chain_sequence(match.group(1))


def _strip_code_blocks_and_tables(md: str) -> _common.List[str]:
    lines = md.splitlines()
    out: _common.List[str] = []
    in_code = False
    for line in lines:
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        if line.lstrip().startswith("|"):
            continue
        out.append(line)
    return out

def check_cs_can_004(root: _common.Path) -> InvariantResult:
    """CS-CAN-004 — No duplicate non-canonical spec trees."""

    p_gates = root / "belgi" / "gates"
    p_schemas = root / "belgi" / "schemas"

    def has_any_file(p: _common.Path) -> bool:
        if not p.exists():
            return False
        for _, _, files in _common.os.walk(p):
            if files:
                return True
        return False

    if has_any_file(p_gates) or has_any_file(p_schemas):
        return InvariantResult(
            "CS-CAN-004",
            "FAIL",
            ["docs/operations/consistency-sweep.md#cs-can-004--no-duplicate-non-canonical-spec-trees"],
            "Remove non-canonical duplicates under belgi/gates/ and/or belgi/schemas/ and rerun sweep.",
        )

    return InvariantResult(
        "CS-CAN-004",
        "PASS",
        ["docs/operations/consistency-sweep.md#cs-can-004--no-duplicate-non-canonical-spec-trees"],
        "",
    )

def check_cs_can_002(root: _common.Path) -> InvariantResult:
    """CS-CAN-002 — Canonical chain matches everywhere."""

    evidence = [
        "CANONICALS.md#2-canonical-chain-canonical",
        "docs/operations/running-belgi.md#1-overview-what-happens-in-p--c1--q--c2--r--c3--s",
    ]
    runbook_rel = "docs/operations/running-belgi.md"
    runbook_path = _common.repo_path(root, runbook_rel)
    if not runbook_path.exists():
        return InvariantResult("CS-CAN-002", "FAIL", evidence, f"Missing required file: {runbook_rel}.")

    try:
        report = _load_derived_canonicals_report(root)
    except _common._UserInputError as e:
        return InvariantResult(
            "CS-CAN-002",
            "FAIL",
            evidence,
            f"Failed to derive canonical chain report from CANONICALS.md#2-canonical-chain-canonical ({e}).",
        )

    expected_sequence = list(report["canonical_chain"]["sequence"])
    expected_chain = _format_arrow_chain_sequence(expected_sequence)

    try:
        actual_sequence = _extract_labeled_arrow_chain_sequence(_common.read_text(runbook_path), "Canonical chain")
    except _common._UserInputError as e:
        return InvariantResult(
            "CS-CAN-002",
            "FAIL",
            evidence,
            f"docs/operations/running-belgi.md must keep a `Canonical chain:` line aligned to the derived canonical-chain report ({e}).",
        )

    if actual_sequence != expected_sequence:
        actual_chain = _format_arrow_chain_sequence(actual_sequence)
        return InvariantResult(
            "CS-CAN-002",
            "FAIL",
            evidence,
            "Canonical chain drift detected in docs/operations/running-belgi.md. "
            f"Expected `{expected_chain}` from CANONICALS.md#2-canonical-chain-canonical via the derived report, found `{actual_chain}`.",
        )

    return InvariantResult("CS-CAN-002", "PASS", evidence, "")

def check_cs_can_003(root: _common.Path) -> InvariantResult:
    """CS-CAN-003 — Publication posture is enforced in public-safe docs."""

    can = _common.repo_path(root, "CANONICALS.md")
    sec = _common.repo_path(root, "docs/operations/security.md")
    pb = _common.repo_path(root, "belgi/templates/PromptBundle.blocks.md")
    dc = _common.repo_path(root, "belgi/templates/DocsCompiler.template.md")

    missing_files = [
        rel
        for rel, p in [
            ("CANONICALS.md", can),
            ("docs/operations/security.md", sec),
            ("belgi/templates/PromptBundle.blocks.md", pb),
            ("belgi/templates/DocsCompiler.template.md", dc),
        ]
        if not p.exists()
    ]
    if missing_files:
        return InvariantResult(
            "CS-CAN-003",
            "FAIL",
            ["docs/operations/consistency-sweep.md#cs-can-003--publication-posture-is-enforced-in-public-safe-docs"],
            f"Missing required file(s): {', '.join(missing_files)}.",
        )

    can_txt = _common.read_text(can)
    sec_txt = _common.read_text(sec)
    pb_txt = _common.read_text(pb)
    dc_txt = _common.read_text(dc)

    can_needles = [
        "Publication Posture",
        "MUST NOT publish exploit signatures",
        "evasion thresholds",
        "only categories",
    ]
    sec_needles = [
        "public-safe",
        "MUST NOT include exploit signatures",
        "bypass",
    ]
    pb_needles = [
        "Public release redaction policy",
        "bypass-oriented rule details",
        "exploit signatures",
    ]
    dc_needles = [
        "public-safe",
        "Prohibited non-determinism",
        "No bypass-friendly",
    ]

    missing: list[str] = []
    missing.extend([f"CANONICALS.md: {m}" for m in _common._missing_needles(can_txt, can_needles)])
    missing.extend([f"security.md: {m}" for m in _common._missing_needles(sec_txt, sec_needles)])
    missing.extend([f"PromptBundle.blocks.md: {m}" for m in _common._missing_needles(pb_txt, pb_needles)])
    missing.extend([f"DocsCompiler.template.md: {m}" for m in _common._missing_needles(dc_txt, dc_needles)])

    if missing:
        return InvariantResult(
            "CS-CAN-003",
            "FAIL",
            [
                "CANONICALS.md#8-publication-posture-canonical",
                "docs/operations/security.md#security-public-safe-posture",
                "belgi/templates/PromptBundle.blocks.md#a4-public-release-redaction-policy",
                "belgi/templates/DocsCompiler.template.md#b22-repository-documentation-inputs-public-safe-categories",
            ],
            "Add/restore public-safe publication posture prohibitions across canonicals/ops/templates and rerun sweep.",
        )

    return InvariantResult(
        "CS-CAN-003",
        "PASS",
        [
            "CANONICALS.md#8-publication-posture-canonical",
            "docs/operations/security.md#security-public-safe-posture",
            "belgi/templates/PromptBundle.blocks.md#a4-public-release-redaction-policy",
            "belgi/templates/DocsCompiler.template.md#b22-repository-documentation-inputs-public-safe-categories",
        ],
        "",
    )

def check_cs_can_005(
    root: _common.Path,
    *,
    mirror_bindings: tuple[tuple[str, str], ...] = _C3_CANONICAL_MIRROR_BINDINGS,
) -> InvariantResult:
    """CS-CAN-005 — Package canonical mirror is byte-identical to source docs."""

    missing: list[str] = []
    drifted: list[str] = []
    evidence: list[str] = []

    for src_rel, dst_rel in mirror_bindings:
        try:
            src = _common._resolve_repo_path(root, src_rel, must_exist=True, must_be_file=True)
        except _common._UserInputError:
            missing.append(src_rel)
            continue
        try:
            dst = _common._resolve_repo_path(root, dst_rel, must_exist=True, must_be_file=True)
        except _common._UserInputError:
            missing.append(dst_rel)
            continue

        evidence.extend([src_rel, dst_rel])
        if src.read_bytes() != dst.read_bytes():
            drifted.append(f"{dst_rel} != {src_rel}")

    if missing:
        joined = ", ".join(sorted(set(missing)))
        return InvariantResult(
            "CS-CAN-005",
            "FAIL",
            [f"{_common.CONSISTENCY_SPEC_DOC}#cs-can-005--package-canonical-mirror-is-byte-identical-to-source-docs"],
            f"Missing canonical mirror source/target file(s): {joined}.",
        )

    if drifted:
        sample = ", ".join(sorted(drifted)[:8])
        extra = len(drifted) - 8
        suffix = "" if extra <= 0 else f" (+{extra} more)"
        return InvariantResult(
            "CS-CAN-005",
            "FAIL",
            [f"{_common.CONSISTENCY_SPEC_DOC}#cs-can-005--package-canonical-mirror-is-byte-identical-to-source-docs"],
            (
                "Canonical package mirror drift detected. "
                "Run `python -m tools.build_builtin_pack` and rerun sweep. Drift: "
                f"{sample}{suffix}."
            ),
        )

    return InvariantResult(
        "CS-CAN-005",
        "PASS",
        sorted(set(evidence)),
        "",
    )

def _term_guard_scan_files(root: _common.Path) -> list[str]:
    """Deterministically enumerate tracked doc surfaces for CS-TERM-001."""

    tracked = _common._run_git(root, ["ls-files"])
    files: set[str] = set()
    for raw in tracked.splitlines():
        rel = raw.strip()
        if not rel:
            continue
        rel = _common._validate_repo_rel(rel)
        # This spec file contains forbidden token examples by design.
        if rel == _common.CONSISTENCY_SPEC_DOC:
            continue
        if rel in _TERM_GUARD_FIXED_FILES:
            files.add(rel)
            continue
        if rel.endswith((".md", ".txt")) and any(rel.startswith(p) for p in _TERM_GUARD_PREFIXES):
            files.add(rel)
    return sorted(files)

def check_cs_term_001(root: _common.Path) -> InvariantResult:
    """CS-TERM-001 — Terminology Drift Guard (Verification vs Validation)."""

    try:
        targets = _term_guard_scan_files(root)
    except Exception as e:
        return InvariantResult(
            "CS-TERM-001",
            "FAIL",
            ["docs/operations/consistency-sweep.md#cs-term-001--terminology-drift-guard-verification-vs-validation"],
            f"Failed to enumerate tracked doc surfaces for terminology drift guard ({e}).",
        )

    if not targets:
        return InvariantResult(
            "CS-TERM-001",
            "FAIL",
            ["docs/operations/consistency-sweep.md#cs-term-001--terminology-drift-guard-verification-vs-validation"],
            "No tracked documentation files found for terminology drift guard scope.",
        )

    token_re = _common.re.compile(r"(?i)\b(validation|validate|validated)\b")
    offenders: list[tuple[str, int, str]] = []

    for rel in targets:
        p = _common._resolve_repo_path(root, rel, must_exist=True, must_be_file=True)
        lines = _common.read_text(p).splitlines()
        for idx, line in enumerate(lines, start=1):
            lower = line.lower()
            reason = ""
            if "deterministic validation" in lower:
                reason = "contains banned phrase 'deterministic validation'"
            elif "validation posture" in lower:
                reason = "contains banned phrase 'validation posture'"
            elif "probabilistic execution" in lower:
                reason = "contains banned phrase 'probabilistic execution'"
            elif token_re.search(line) and not any(ctx in lower for ctx in _TERM_GUARD_ALLOWED_CONTEXTS):
                reason = "contains non-mechanical validation token"
            if reason:
                offenders.append((rel, idx, reason))

    if offenders:
        offenders.sort(key=lambda t: (t[0], t[1], t[2]))
        listed = "; ".join(f"{rel}:{line} ({reason})" for rel, line, reason in offenders)
        return InvariantResult(
            "CS-TERM-001",
            "FAIL",
            ["CANONICALS.md#bounded-claim", "CANONICALS.md#terminology-boundaries"],
            "Terminology drift detected at "
            + listed
            + ". Replace claim-level wording with 'verification'; use 'schema-validate'/'schema validation' only for mechanical conformance. See CANONICALS.md#terminology-boundaries.",
        )

    return InvariantResult(
        "CS-TERM-001",
        "PASS",
        ["CANONICALS.md#bounded-claim", "CANONICALS.md#terminology-boundaries"],
        "",
    )

def _normalize_cs_can_001_subject(text: str) -> str:
    subject = _common.re.sub(r"\s+", " ", str(text or "").strip())
    if len(subject) >= 2 and subject.startswith("`") and subject.endswith("`"):
        inner = subject[1:-1].strip()
        if inner:
            subject = inner
    return _common.re.sub(r"\s+", " ", subject).casefold()

def _extract_cs_can_001_term_map_entries(term_map: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for raw_line in term_map.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("|") and line.endswith("|"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if len(cells) >= 2 and cells[0].lower() != "term":
                link_match = _common.re.search(r"\(CANONICALS\.md#([^)]+)\)", cells[1])
                if link_match is not None:
                    entries.append((cells[0], link_match.group(1)))
            continue

        link_match = _common.re.match(r"^\s*[-*+]\s+\[([^\]]+)\]\(CANONICALS\.md#([^)]+)\)\s*$", line)
        if link_match:
            entries.append((link_match.group(1), link_match.group(2)))
    return entries

def _extract_cs_can_001_term_map_subjects(term_map: str) -> set[str]:
    subjects: set[str] = set()
    for subject, _anchor_id in _extract_cs_can_001_term_map_entries(term_map):
        normalized = _normalize_cs_can_001_subject(subject)
        if normalized:
            subjects.add(normalized)
    return subjects

def _extract_cs_can_001_definitional_subject(line: str) -> str | None:
    match = _common.re.match(r"^(?P<subject>.+?)\s+is\s+(?:an|the|a)\s+.+$", str(line or "").strip(), _common.re.IGNORECASE)
    if not match:
        return None
    subject = _normalize_cs_can_001_subject(match.group("subject") or "")
    return subject or None

def check_cs_can_001(root: _common.Path) -> InvariantResult:
    """CS-CAN-001 — Terminology is pointers-only."""

    evidence = [
        "terminology.md#0-rule-of-use-canonical-pointer",
        "terminology.md#term-map",
        "CANONICALS.md#anchor-registry-stable-ids",
    ]

    term_path = _common.repo_path(root, "terminology.md")
    if not term_path.exists():
        return InvariantResult("CS-CAN-001", "FAIL", evidence, "terminology.md missing.")

    md = _common.read_text(term_path)

    rule_ok = ("MUST NOT define" in md) or ("MUST NOT define or redefine" in md)
    if not rule_ok:
        return InvariantResult(
            "CS-CAN-001",
            "FAIL",
            evidence,
            "Add explicit Rule of Use statement: terminology.md MUST NOT define or redefine canonical terms.",
        )

    try:
        report = _load_derived_canonicals_report(root)
    except _common._UserInputError as e:
        return InvariantResult(
            "CS-CAN-001",
            "FAIL",
            evidence,
            f"Failed to derive canonical anchor registry report from CANONICALS.md#anchor-registry-stable-ids ({e}).",
        )
    canonical_anchor_ids = set(report["anchor_registry_ids"])

    term_map_match = _common.re.search(r"(?is)#+\s*(?:\d+(?:\.\d+)*\.?\s*)?Term Map\b(.*?)(\n#+\s|\Z)", md)
    if term_map_match:
        term_map = term_map_match.group(1)
        links = _common.re.findall(r"\[[^\]]+\]\(([^)]+)\)", term_map)
        bad_links = [l for l in links if not l.startswith("CANONICALS.md#")]
        if bad_links:
            return InvariantResult(
                "CS-CAN-001",
                "FAIL",
                evidence,
                f"Term Map has non-canonical links (must start with CANONICALS.md#): {bad_links[:5]}",
            )
        missing_anchor_targets = sorted(
            {
                link.split("#", 1)[1]
                for link in links
                if link.startswith("CANONICALS.md#") and link.split("#", 1)[1] not in canonical_anchor_ids
            }
        )
        if missing_anchor_targets:
            sample = ", ".join(missing_anchor_targets[:8])
            extra = len(missing_anchor_targets) - 8
            suffix = "" if extra <= 0 else f" (+{extra} more)"
            return InvariantResult(
                "CS-CAN-001",
                "FAIL",
                evidence,
                "Term Map points at non-existent canonical anchors from "
                f"CANONICALS.md#anchor-registry-stable-ids: {sample}{suffix}.",
            )
        canonical_subjects = _extract_cs_can_001_term_map_subjects(term_map)
        if not canonical_subjects:
            return InvariantResult(
                "CS-CAN-001",
                "FAIL",
                evidence,
                "Populate the 'Term Map' section with canonical term pointers to CANONICALS.md#<anchor>.",
            )
    else:
        return InvariantResult(
            "CS-CAN-001",
            "FAIL",
            evidence,
            "Add a 'Term Map' section whose entries link to CANONICALS.md#<anchor>.",
        )

    remaining_lines = _strip_code_blocks_and_tables(md)
    offenders = []
    for raw_line in remaining_lines:
        line = raw_line.strip()
        if not line:
            continue
        subject = _extract_cs_can_001_definitional_subject(line)
        if subject and subject in canonical_subjects:
            offenders.append(line)
    if offenders:
        return InvariantResult(
            "CS-CAN-001",
            "FAIL",
            evidence,
            "Remove non-pointer term definitions from terminology.md (found glossary-like definitional sentences for canonical term subjects of the form '<term> is a/an/the ...').",
        )

    return InvariantResult("CS-CAN-001", "PASS", evidence, "")
