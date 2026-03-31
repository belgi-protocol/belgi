"""Regression tests for sweep helper semantics.

Goal: prevent list-returning helpers from being misread as booleans.

This specifically guards against the historic inversion bug where a check
used `if not <missing_list>:` and accidentally failed/passed the wrong way.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def test_helper_contract() -> None:
    from tools import sweep as sweep_mod

    result = sweep_mod._missing_needles("abc", ["a", "b", "c"])
    assert isinstance(result, list)
    assert result == []

    result2 = sweep_mod._missing_needles("abc", ["a", "z"])
    assert isinstance(result2, list)
    assert result2 == ["z"]


def test_known_good_must_pass(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    (tmp_path / "gates").mkdir(parents=True, exist_ok=True)
    (tmp_path / "gates" / "GATE_Q.md").write_text(
        "\n".join(
            [
                "# Gate Q",
                "Q-INTENT-001",
                "Q-INTENT-002",
                "Q-INTENT-003",
                "IntentSpec.core.md",
                "belgi/templates/IntentSpec.core.template.md",
                "schemas/IntentSpec.schema.json",
                "schemas/LockedSpec.schema.json",
            ]
        ),
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    res = sweep_mod.check_cs_is_003(tmp_path)
    assert res.invariant_id == "CS-IS-003"
    assert res.status == "PASS"


def test_known_bad_must_fail(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    # Minimal synthetic repo root sufficient for CS-IS-003 (it only reads gates/GATE_Q.md).
    (tmp_path / "gates").mkdir(parents=True, exist_ok=True)
    (tmp_path / "gates" / "GATE_Q.md").write_text(
        "\n".join(
            [
                "# Gate Q",
                "Q-INTENT-001",
                "Q-INTENT-002",
                # Intentionally omit Q-INTENT-003 and other required strings.
                "IntentSpec.core.md",
            ]
        ),
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    res = sweep_mod.check_cs_is_003(tmp_path)
    assert res.invariant_id == "CS-IS-003"
    assert res.status == "FAIL"


def test_cs_fixture_zero_001_passes_when_governed_public_surface_is_absent(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    res = sweep_mod.check_cs_fixture_zero_001(tmp_path)
    assert res.invariant_id == "CS-FIXTURE-ZERO-001"
    assert res.status == "PASS"


def test_cs_fixture_zero_001_fails_when_governed_public_surface_reappears(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    reintroduced = tmp_path / "policy" / "fixtures" / "public" / "gate_r" / "cases.json"
    reintroduced.parent.mkdir(parents=True, exist_ok=True)
    reintroduced.write_text("{\"cases\": []}\n", encoding="utf-8", errors="strict", newline="\n")

    res = sweep_mod.check_cs_fixture_zero_001(tmp_path)
    assert res.invariant_id == "CS-FIXTURE-ZERO-001"
    assert res.status == "FAIL"
    assert "policy/fixtures/public/gate_r/cases.json" in res.remediation
    assert res.details == {"reintroduced_paths": ["policy/fixtures/public/gate_r/cases.json"]}


def test_abuse_no_boolean_negation_of_missing_needles() -> None:
    txt = (REPO_ROOT / "tools" / "sweep.py").read_text(encoding="utf-8", errors="strict")

    # Guardrail: reintroducing the old inverted pattern should immediately trip CI.
    assert "if not _missing_needles(" not in txt

    # Also block the positive truthiness form; callers must name the variable explicitly.
    assert re.search(r"\bif\s+_missing_needles\(", txt) is None


def test_abuse_no_boolean_truthiness_of_seal_payload_list_helpers() -> None:
    txt = (REPO_ROOT / "tools" / "sweep.py").read_text(encoding="utf-8", errors="strict")

    helpers = [
        "_seal_payload_paths_in_fixture_dir",
    ]

    for name in helpers:
        assert f"if not {name}(" not in txt
        assert re.search(rf"\bif\s+{re.escape(name)}\(", txt) is None


def _init_tracked_temp_repo(root: Path, files: dict[str, str]) -> None:
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "sweep-tests@local"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Sweep Tests"], cwd=root, check=True)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", errors="strict", newline="\n")
    subprocess.run(["git", "add", "--all"], cwd=root, check=True)


def _write_terminology_fixture(tmp_path: Path, term_entries: list[tuple[str, str]], note_line: str) -> None:
    _write_canonicals_fixture(
        tmp_path,
        anchor_registry_ids=[anchor for _term, anchor in term_entries],
    )
    (tmp_path / "terminology.md").write_text(
        "\n".join(
            [
                "# Terminology",
                "Rule of Use: terminology.md MUST NOT define or redefine canonical terms.",
                "## Term Map",
                *[f"- [{term}](CANONICALS.md#{anchor})" for term, anchor in term_entries],
                "## Notes",
                note_line,
            ]
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def _write_canonicals_fixture(
    tmp_path: Path,
    *,
    anchor_registry_ids: list[str],
    canonical_chain: str = "P → C1 → Q → C2 → R → C3 → S",
) -> None:
    (tmp_path / "CANONICALS.md").write_text(
        "\n".join(
            [
                "# CANONICALS",
                "## Anchor Registry (Stable IDs)",
                *[f"- {anchor_id}" for anchor_id in anchor_registry_ids],
                "",
                "## 2. Canonical Chain (Canonical)",
                canonical_chain,
            ]
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def _write_running_belgi_chain_fixture(tmp_path: Path, chain: str) -> None:
    path = tmp_path / "docs" / "operations" / "running-belgi.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "# Running BELGI",
                "## 1) Overview: what happens in P → C1 → Q → C2 → R → C3 → S",
                f"Canonical chain: `{chain}` (see `../../CANONICALS.md`).",
            ]
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def test_cs_term_001_fails_on_validation_posture_phrase(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "README.md": "Two-phase validation posture\n",
            "CANONICALS.md": "Deterministic verification of probabilistic proposals.\n",
        },
    )

    res = sweep_mod.check_cs_term_001(tmp_path)
    assert res.invariant_id == "CS-TERM-001"
    assert res.status == "FAIL"
    assert "README.md:1" in res.remediation
    assert "validation posture" in res.remediation


def test_cs_term_001_allows_schema_validation_context(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "README.md": "schema validation for EvidenceManifest.schema.json\n",
            "CANONICALS.md": "Deterministic verification of probabilistic proposals.\n",
        },
    )

    res = sweep_mod.check_cs_term_001(tmp_path)
    assert res.invariant_id == "CS-TERM-001"
    assert res.status == "PASS"


def test_cs_can_001_derives_subjects_from_term_map_block() -> None:
    from tools import sweep as sweep_mod

    term_map = "\n".join(
        [
            "- [LockedSpec](CANONICALS.md#lockedspec)",
            "- [pack_id](CANONICALS.md#pack-id)",
            "- [HOTL](CANONICALS.md#hotl)",
            "- [Protocol Pack](CANONICALS.md#protocol-pack)",
            "- [Waivers](CANONICALS.md#waivers)",
            "- [Deterministic (BELGI Sense)](CANONICALS.md#deterministic-belgi)",
            "- [R-Snapshot](CANONICALS.md#r-snapshot)",
        ]
    )

    subjects = sweep_mod._extract_cs_can_001_term_map_subjects(term_map)
    expected = {
        sweep_mod._normalize_cs_can_001_subject("LockedSpec"),
        sweep_mod._normalize_cs_can_001_subject("pack_id"),
        sweep_mod._normalize_cs_can_001_subject("HOTL"),
        sweep_mod._normalize_cs_can_001_subject("Protocol Pack"),
        sweep_mod._normalize_cs_can_001_subject("Waivers"),
        sweep_mod._normalize_cs_can_001_subject("Deterministic (BELGI Sense)"),
        sweep_mod._normalize_cs_can_001_subject("R-Snapshot"),
    }
    assert expected.issubset(subjects)


def test_cs_can_001_extracts_definitional_subject_for_a_an_the() -> None:
    from tools import sweep as sweep_mod

    assert sweep_mod._extract_cs_can_001_definitional_subject("Waivers is a temporary scoped exception.") == "waivers"
    assert sweep_mod._extract_cs_can_001_definitional_subject("R-Snapshot is an immutable Gate R evidence snapshot.") == "r-snapshot"
    assert sweep_mod._extract_cs_can_001_definitional_subject("LockedSpec is the canonical lock artifact.") == "lockedspec"
    assert sweep_mod._extract_cs_can_001_definitional_subject("This is a test.") == "this"


def test_cs_can_001_rejects_term_like_definition(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_terminology_fixture(
        tmp_path,
        [("LockedSpec", "lockedspec")],
        "LockedSpec is the canonical lock artifact.",
    )

    res = sweep_mod.check_cs_can_001(tmp_path)
    assert res.invariant_id == "CS-CAN-001"
    assert res.status == "FAIL"
    assert "glossary-like definitional sentences" in res.remediation


def test_cs_can_001_rejects_lower_snake_case_definition(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_terminology_fixture(
        tmp_path,
        [("pack_id", "pack-id")],
        "pack_id is the canonical protocol identity field.",
    )

    res = sweep_mod.check_cs_can_001(tmp_path)
    assert res.invariant_id == "CS-CAN-001"
    assert res.status == "FAIL"


def test_cs_can_001_rejects_backticked_lower_snake_case_definition(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_terminology_fixture(
        tmp_path,
        [("pack_id", "pack-id")],
        "`pack_id` is the canonical protocol identity field.",
    )

    res = sweep_mod.check_cs_can_001(tmp_path)
    assert res.invariant_id == "CS-CAN-001"
    assert res.status == "FAIL"


def test_cs_can_001_rejects_multiword_title_case_definition(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_terminology_fixture(
        tmp_path,
        [("Protocol Pack", "protocol-pack")],
        "Protocol Pack is the canonical rules bundle.",
    )

    res = sweep_mod.check_cs_can_001(tmp_path)
    assert res.invariant_id == "CS-CAN-001"
    assert res.status == "FAIL"


def test_cs_can_001_rejects_allcaps_term_definition(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_terminology_fixture(
        tmp_path,
        [("HOTL", "hotl")],
        "HOTL is the human control point.",
    )

    res = sweep_mod.check_cs_can_001(tmp_path)
    assert res.invariant_id == "CS-CAN-001"
    assert res.status == "FAIL"


def test_cs_can_001_rejects_single_word_title_case_term_definition(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_terminology_fixture(
        tmp_path,
        [("Waivers", "waivers")],
        "Waivers is a temporary scoped exception.",
    )

    res = sweep_mod.check_cs_can_001(tmp_path)
    assert res.invariant_id == "CS-CAN-001"
    assert res.status == "FAIL"


def test_cs_can_001_rejects_parenthesized_term_definition(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_terminology_fixture(
        tmp_path,
        [("Deterministic (BELGI sense)", "deterministic-belgi")],
        "Deterministic (BELGI Sense) is an execution-bounded reproducibility rule.",
    )

    res = sweep_mod.check_cs_can_001(tmp_path)
    assert res.invariant_id == "CS-CAN-001"
    assert res.status == "FAIL"


def test_cs_can_001_rejects_hyphenated_term_definition(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_terminology_fixture(
        tmp_path,
        [("R-Snapshot", "r-snapshot")],
        "R-Snapshot is an immutable Gate R evidence snapshot.",
    )

    res = sweep_mod.check_cs_can_001(tmp_path)
    assert res.invariant_id == "CS-CAN-001"
    assert res.status == "FAIL"


def test_cs_can_001_allows_benign_prose_sentence(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_terminology_fixture(
        tmp_path,
        [("LockedSpec", "lockedspec")],
        "This is a test.",
    )

    res = sweep_mod.check_cs_can_001(tmp_path)
    assert res.invariant_id == "CS-CAN-001"
    assert res.status == "PASS"


def test_cs_can_001_fails_when_term_map_pointer_anchor_is_missing_from_derived_report(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_canonicals_fixture(tmp_path, anchor_registry_ids=["purpose"])
    (tmp_path / "terminology.md").write_text(
        "\n".join(
            [
                "# Terminology",
                "Rule of Use: terminology.md MUST NOT define or redefine canonical terms.",
                "## Term Map",
                "- [LockedSpec](CANONICALS.md#lockedspec)",
                "## Notes",
                "This is a note.",
            ]
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    res = sweep_mod.check_cs_can_001(tmp_path)
    assert res.invariant_id == "CS-CAN-001"
    assert res.status == "FAIL"
    assert "non-existent canonical anchors" in res.remediation
    assert "lockedspec" in res.remediation


def test_cs_can_002_uses_report_derived_chain_sequence(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_canonicals_fixture(
        tmp_path,
        anchor_registry_ids=["canonical-chain"],
        canonical_chain="P → Q → R",
    )
    _write_running_belgi_chain_fixture(tmp_path, "P → Q → R")

    res = sweep_mod.check_cs_can_002(tmp_path)
    assert res.invariant_id == "CS-CAN-002"
    assert res.status == "PASS"


def test_cs_can_002_fails_when_running_belgi_chain_drifts_from_report(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _write_canonicals_fixture(
        tmp_path,
        anchor_registry_ids=["canonical-chain"],
        canonical_chain="P → Q → R",
    )
    _write_running_belgi_chain_fixture(tmp_path, "P → R → Q")

    res = sweep_mod.check_cs_can_002(tmp_path)
    assert res.invariant_id == "CS-CAN-002"
    assert res.status == "FAIL"
    assert "Expected `P → Q → R`" in res.remediation
    assert "found `P → R → Q`" in res.remediation


def test_cs_protocol_identity_001_allows_source_as_operational_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import sweep as sweep_mod

    rel = "gates/GATE_S.md"
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "note: LockedSpec.protocol_pack.source is metadata and MUST NOT be used as an identity check.\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    monkeypatch.setattr(sweep_mod, "_PROTOCOL_IDENTITY_SOURCE_GUARD_FILES", (rel,))

    res = sweep_mod.check_cs_protocol_identity_001(tmp_path)
    assert res.invariant_id == "CS-PROTOCOL-IDENTITY-001"
    assert res.status == "PASS"


def test_cs_protocol_identity_001_fails_when_source_is_in_identity_tuple(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import sweep as sweep_mod

    rel = "gates/GATE_Q.md"
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "Active protocol context identity: pack_id, manifest_sha256, pack_name, source\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    monkeypatch.setattr(sweep_mod, "_PROTOCOL_IDENTITY_SOURCE_GUARD_FILES", (rel,))

    res = sweep_mod.check_cs_protocol_identity_001(tmp_path)
    assert res.invariant_id == "CS-PROTOCOL-IDENTITY-001"
    assert res.status == "FAIL"
    assert "gates/GATE_Q.md:1" in res.remediation


def test_cs_can_005_passes_when_package_mirror_matches_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import sweep as sweep_mod

    source_rel = "docs/operations/running-belgi.md"
    mirror_rel = "belgi/canonicals/docs/operations/running-belgi.md"
    monkeypatch.setattr(sweep_mod, "_C3_CANONICAL_MIRROR_BINDINGS", ((source_rel, mirror_rel),))

    src = tmp_path / source_rel
    dst = tmp_path / mirror_rel
    src.parent.mkdir(parents=True, exist_ok=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("stable sha40 guidance\n", encoding="utf-8", errors="strict", newline="\n")
    dst.write_text("stable sha40 guidance\n", encoding="utf-8", errors="strict", newline="\n")

    res = sweep_mod.check_cs_can_005(tmp_path)
    assert res.invariant_id == "CS-CAN-005"
    assert res.status == "PASS"


def test_cs_can_005_fails_when_package_mirror_drifts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import sweep as sweep_mod

    source_rel = "docs/operations/running-belgi.md"
    mirror_rel = "belgi/canonicals/docs/operations/running-belgi.md"
    monkeypatch.setattr(sweep_mod, "_C3_CANONICAL_MIRROR_BINDINGS", ((source_rel, mirror_rel),))

    src = tmp_path / source_rel
    dst = tmp_path / mirror_rel
    src.parent.mkdir(parents=True, exist_ok=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("stable sha40 guidance\n", encoding="utf-8", errors="strict", newline="\n")
    dst.write_text("moving ref guidance\n", encoding="utf-8", errors="strict", newline="\n")

    res = sweep_mod.check_cs_can_005(tmp_path)
    assert res.invariant_id == "CS-CAN-005"
    assert res.status == "FAIL"
    assert mirror_rel in res.remediation
    assert source_rel in res.remediation


def test_managed_sweep_surfaces_include_package_canonicals(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "belgi/canonicals/docs/operations/running-belgi.md": "# mirror\n",
        },
    )
    managed = sweep_mod._sweep_managed_surface_files(tmp_path)
    assert "belgi/canonicals/docs/operations/running-belgi.md" in managed


def test_managed_sweep_surfaces_classify_owned_categories_without_repo_parity(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "README.md": "# readme\n",
            "docs/operations/workflows.md": "# workflows\n",
            "belgi/canonicals/docs/operations/running-belgi.md": "# mirror\n",
            ".github/workflows/pull-request-proof.yml": "name: proof\n",
            ".github/scripts/validate_belgi_ref_pin.py": "print('ok')\n",
            "scripts/belgi_latest_run.sh": "#!/usr/bin/env bash\n",
            "templates/ci/github/belgi-tier1.yml": "name: template\n",
            "tools/README.md": "# tools\n",
            "tools/canonicals_report.py": "def main():\n    return 0\n",
            "tools/consistency/model.py": "# model\n",
            "tools/consistency/runner.py": "# runner\n",
            "tools/consistency/report_writer.py": "# report writer\n",
            "belgi/cli_app/commands/run.py": "# run\n",
            "docs/research/README.md": "# research\n",
            "scripts/not_belgi.sh": "#!/usr/bin/env bash\n",
        },
    )

    managed = set(sweep_mod._sweep_managed_surface_files(tmp_path))
    assert {
        "README.md",
        "docs/operations/workflows.md",
        "belgi/canonicals/docs/operations/running-belgi.md",
        ".github/workflows/pull-request-proof.yml",
        ".github/scripts/validate_belgi_ref_pin.py",
        "scripts/belgi_latest_run.sh",
        "templates/ci/github/belgi-tier1.yml",
        "tools/README.md",
        "tools/canonicals_report.py",
        "tools/consistency/model.py",
        "tools/consistency/runner.py",
        "tools/consistency/report_writer.py",
        "belgi/cli_app/commands/run.py",
    }.issubset(managed)
    assert "docs/research/README.md" not in managed
    assert "scripts/not_belgi.sh" not in managed


def test_cs_sweep_002_fails_when_managed_surface_is_unlisted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "docs/operations/workflows.md": "# workflows\n",
            ".github/workflows/pull-request-proof.yml": "name: proof\n",
            ".github/scripts/validate_belgi_ref_pin.py": "print('ok')\n",
            "scripts/belgi_latest_run.sh": "#!/usr/bin/env bash\n",
            "templates/ci/github/belgi-tier1.yml": "name: template\n",
            "tools/README.md": "# tools\n",
            "tools/canonicals_report.py": "def main():\n    return 0\n",
            "tools/consistency/model.py": "# model\n",
            "tools/consistency/runner.py": "# runner\n",
            "tools/consistency/report_writer.py": "# report writer\n",
        },
    )

    managed = sweep_mod._sweep_managed_surface_files(tmp_path)
    monkeypatch.setattr(
        sweep_mod,
        "_canonical_inputs",
        lambda _root: sorted(
            set(
                [rel for rel in managed if rel != "tools/consistency/report_writer.py"]
                + ["tools/normalize.py", "tools/rehash.py", "tools/sweep.py"]
            )
        ),
    )

    res = sweep_mod.check_cs_sweep_002(tmp_path)
    assert res.invariant_id == "CS-SWEEP-002"
    assert res.status == "FAIL"
    assert "tools/consistency/report_writer.py" in res.remediation


def test_cs_sweep_002_passes_when_managed_surface_is_listed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "docs/operations/workflows.md": "# workflows\n",
            ".github/workflows/pull-request-proof.yml": "name: proof\n",
            ".github/scripts/validate_belgi_ref_pin.py": "print('ok')\n",
            "scripts/belgi_latest_run.sh": "#!/usr/bin/env bash\n",
            "templates/ci/github/belgi-tier1.yml": "name: template\n",
            "tools/README.md": "# tools\n",
            "tools/consistency/model.py": "# model\n",
            "tools/consistency/runner.py": "# runner\n",
            "tools/consistency/report_writer.py": "# report writer\n",
        },
    )

    managed = sweep_mod._sweep_managed_surface_files(tmp_path)
    monkeypatch.setattr(
        sweep_mod,
        "_canonical_inputs",
        lambda _root: sorted(set(managed + ["tools/normalize.py", "tools/rehash.py", "tools/sweep.py"])),
    )

    res = sweep_mod.check_cs_sweep_002(tmp_path)
    assert res.invariant_id == "CS-SWEEP-002"
    assert res.status == "PASS"


def test_cs_sweep_002_fails_when_repo_root_markdown_is_unlisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import sweep as sweep_mod

    _init_tracked_temp_repo(
        tmp_path,
        {
            "CANONICALS.md": "# canon\n",
            "README.md": "# readme\n",
            "NEW_CANONICAL.md": "# new\n",
        },
    )

    monkeypatch.setattr(
        sweep_mod,
        "_canonical_inputs",
        lambda _root: [
            "CANONICALS.md",
            "README.md",
            "tools/normalize.py",
            "tools/rehash.py",
            "tools/sweep.py",
        ],
    )

    res = sweep_mod.check_cs_sweep_002(tmp_path)
    assert res.invariant_id == "CS-SWEEP-002"
    assert res.status == "FAIL"
    assert "NEW_CANONICAL.md" in res.remediation


def test_cs_sweep_001_requires_derived_report_and_consistency_engine_owner_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools import sweep as sweep_mod

    monkeypatch.setattr(sweep_mod, "_canonical_inputs", lambda _root: ["tools/normalize.py", "tools/rehash.py", "tools/sweep.py"])
    monkeypatch.setattr(sweep_mod, "_iter_schema_files", lambda _root: [])

    res = sweep_mod.check_cs_sweep_001(tmp_path)
    assert res.invariant_id == "CS-SWEEP-001"
    assert res.status == "FAIL"


def test_cs_run_002_passes_with_owner_bounded_non_owner_docs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from belgi.cli_app.commands import run as run_mod
    from tools import sweep as sweep_mod

    monkeypatch.setattr(
        run_mod,
        "_render_adopter_readme",
        lambda *, workspace_rel: "\n".join(
            [
                f"{workspace_rel}/runs/run-001/inputs/environment/toolchain-set.json",
                f"{workspace_rel}/runs/run-001/inputs/environment/tolerances.json",
                f"--toolchain-set-ref env.toolchains={workspace_rel}/runs/run-001/inputs/environment/toolchain-set.json",
                f"--tolerances-ref tier.tolerances={workspace_rel}/runs/run-001/inputs/environment/tolerances.json",
                "Optional shared run object inputs:",
                "`Tolerances.tier_id` must match the selected tier.",
                "may equal or tighten the selected tier ceilings, but BELGI rejects wider values",
            ]
        )
        + "\n",
    )
    monkeypatch.setattr(
        run_mod,
        "_render_runbook_template",
        lambda *, run_id: "\n".join(
            [
                f".belgi/runs/{run_id}/inputs/environment/toolchain-set.json",
                f".belgi/runs/{run_id}/inputs/environment/tolerances.json",
                "Optional shared environment objects:",
                f"cat > .belgi/runs/{run_id}/inputs/environment/toolchain-set.json <<'JSON'",
                f"cat > .belgi/runs/{run_id}/inputs/environment/tolerances.json <<'JSON'",
                f"--toolchain-set-ref env.toolchains=.belgi/runs/{run_id}/inputs/environment/toolchain-set.json",
                f"--tolerances-ref tier.tolerances=.belgi/runs/{run_id}/inputs/environment/tolerances.json",
                "`Tolerances.tier_id` must match the selected tier.",
                "may equal or tighten the selected tier ceilings, but BELGI rejects wider values",
                "stays within that selected tier",
            ]
        )
        + "\n",
    )

    (tmp_path / "belgi" / "cli_app" / "commands").mkdir(parents=True, exist_ok=True)
    (tmp_path / "belgi" / "cli_app" / "commands" / "run.py").write_text(
        "# stub\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "docs" / "operations").mkdir(parents=True, exist_ok=True)
    (tmp_path / "docs" / "operations" / "running-belgi.md").write_text(
        "\n".join(
            [
                "`belgi run new`",
                ".belgi/runs/<run_id>/inputs/environment/toolchain-set.json",
                ".belgi/runs/<run_id>/inputs/environment/tolerances.json",
                "docs/operations/cli.md",
                "docs/operations/operator-anchors.md",
                "docs/operations/evidence-bundles.md",
                "../../CANONICALS.md",
                "`--toolchain-set` / `--tolerances`",
            ]
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "docs" / "operations" / "operator-anchors.md").write_text(
        "\n".join(
            [
                ".belgi/runs/<run_id>/inputs/anchors/approvals/",
                ".belgi/runs/<run_id>/inputs/anchors/keys/",
                ".belgi/runs/<run_id>/inputs/anchors/signing/",
                ".belgi/runs/<run_id>/inputs/evidence/genesis_seal.json",
                "docs/operations/cli.md",
                "docs/operations/evidence-bundles.md",
                "../../CANONICALS.md",
            ]
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    res = sweep_mod.check_cs_run_002(tmp_path)
    assert res.invariant_id == "CS-RUN-002"
    assert res.status == "PASS"


def test_cs_run_002_fails_when_non_owner_docs_reintroduce_cli_catalogs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from belgi.cli_app.commands import run as run_mod
    from tools import sweep as sweep_mod

    monkeypatch.setattr(run_mod, "_render_adopter_readme", lambda *, workspace_rel: f"{workspace_rel}/runs/run-001/inputs/environment/toolchain-set.json\n{workspace_rel}/runs/run-001/inputs/environment/tolerances.json\n--toolchain-set-ref env.toolchains={workspace_rel}/runs/run-001/inputs/environment/toolchain-set.json\n--tolerances-ref tier.tolerances={workspace_rel}/runs/run-001/inputs/environment/tolerances.json\nOptional shared run object inputs:\n`Tolerances.tier_id` must match the selected tier.\nmay equal or tighten the selected tier ceilings, but BELGI rejects wider values\n")
    monkeypatch.setattr(run_mod, "_render_runbook_template", lambda *, run_id: f".belgi/runs/{run_id}/inputs/environment/toolchain-set.json\n.belgi/runs/{run_id}/inputs/environment/tolerances.json\nOptional shared environment objects:\ncat > .belgi/runs/{run_id}/inputs/environment/toolchain-set.json <<'JSON'\ncat > .belgi/runs/{run_id}/inputs/environment/tolerances.json <<'JSON'\n--toolchain-set-ref env.toolchains=.belgi/runs/{run_id}/inputs/environment/toolchain-set.json\n--tolerances-ref tier.tolerances=.belgi/runs/{run_id}/inputs/environment/tolerances.json\n`Tolerances.tier_id` must match the selected tier.\nmay equal or tighten the selected tier ceilings, but BELGI rejects wider values\nstays within that selected tier\n")

    (tmp_path / "belgi" / "cli_app" / "commands").mkdir(parents=True, exist_ok=True)
    (tmp_path / "belgi" / "cli_app" / "commands" / "run.py").write_text(
        "# stub\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "docs" / "operations").mkdir(parents=True, exist_ok=True)
    (tmp_path / "docs" / "operations" / "running-belgi.md").write_text(
        "--toolchain-set-ref <object_id>=<repo-relative-path>\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "docs" / "operations" / "operator-anchors.md").write_text(
        "belgi run \\\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    res = sweep_mod.check_cs_run_002(tmp_path)
    assert res.invariant_id == "CS-RUN-002"
    assert res.status == "FAIL"
    assert "docs/operations/running-belgi.md" in str(res.details)
    assert "docs/operations/operator-anchors.md" in str(res.details)


_CS_WVR_003_AUTHORITY_INPUTS = (
    "tiers/tier-packs.json",
    "tiers/tier-packs.md",
    "gates/GATE_Q.md",
    "docs/operations/waivers.md",
    "belgi/canonicals/docs/operations/waivers.md",
    "schemas/README.md",
)


def _seed_owner_files(root: Path, relpaths: tuple[str, ...]) -> None:
    for rel in relpaths:
        src = REPO_ROOT / rel
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(encoding="utf-8", errors="strict"), encoding="utf-8", errors="strict", newline="\n")


def _replace_fixture_text(root: Path, rel: str, old: str, new: str) -> None:
    path = root / rel
    text = path.read_text(encoding="utf-8", errors="strict")
    assert old in text, f"expected to find fixture text in {rel!r}: {old!r}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8", errors="strict", newline="\n")


def _seed_cs_wvr_003_owner_fixture(root: Path) -> None:
    _seed_owner_files(root, _CS_WVR_003_AUTHORITY_INPUTS)


def test_cs_wvr_003_passes_when_ops_limits_match_tiers_json(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _seed_cs_wvr_003_owner_fixture(tmp_path)

    res = sweep_mod.check_cs_wvr_003(tmp_path)
    assert res.invariant_id == "CS-WVR-003"
    assert res.status == "PASS"


def test_cs_wvr_003_fails_when_ops_limits_drift_from_tiers_json(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _seed_cs_wvr_003_owner_fixture(tmp_path)
    _replace_fixture_text(
        tmp_path,
        "docs/operations/waivers.md",
        "- Tier 1: waivers allowed, max 10 active",
        "- Tier 1: waivers allowed, max 2 active",
    )

    res = sweep_mod.check_cs_wvr_003(tmp_path)
    assert res.invariant_id == "CS-WVR-003"
    assert res.status == "FAIL"
    assert "tier-1@" in res.remediation


def test_cs_wvr_003_fails_when_ops_hotl_requirement_drifts_from_tiers_json(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _seed_cs_wvr_003_owner_fixture(tmp_path)
    _replace_fixture_text(
        tmp_path,
        "docs/operations/waivers.md",
        "- Tier 1: waivers allowed, max 10 active",
        "- Tier 1: waivers allowed, max 10 active, HOTL required (policy-level)",
    )

    res = sweep_mod.check_cs_wvr_003(tmp_path)
    assert res.invariant_id == "CS-WVR-003"
    assert res.status == "FAIL"
    assert "requires_HOTL=True" in res.remediation


def test_cs_wvr_003_fails_when_schema_readme_keeps_stale_tier1_warning(tmp_path: Path) -> None:
    from tools import sweep as sweep_mod

    _seed_cs_wvr_003_owner_fixture(tmp_path)
    _replace_fixture_text(
        tmp_path,
        "schemas/README.md",
        "**Scope:** Tiers where `waiver_policy.requires_HOTL == true` in `tiers/tier-packs.json` MUST include a valid HOTLApproval artifact in EvidenceManifest. In the current v1 tier policy, this means Tier-2 and Tier-3.",
        "**Scope:** Tier-2+ (audit-grade) runs MUST include a valid HOTLApproval artifact in EvidenceManifest. Tier-1 runs trigger a warning if missing.",
    )
    _replace_fixture_text(
        tmp_path,
        "schemas/README.md",
        "- Read `tiers[<tier_id>].waiver_policy.requires_HOTL` from `tiers/tier-packs.json`.\n- FAIL if `requires_HOTL == true` and no `hotl_approval` artifact is found.\n",
        "- Tier-2/3: FAIL if no `hotl_approval` artifact found.\n- Tier-1: WARNING if missing (backward compatibility).\n",
    )

    res = sweep_mod.check_cs_wvr_003(tmp_path)
    assert res.invariant_id == "CS-WVR-003"
    assert res.status == "FAIL"
    assert "schemas/README.md" in res.remediation
