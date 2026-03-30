from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local


REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_canonicals(path: Path, *, duplicate_anchor: bool = False, with_chain: bool = True) -> None:
    anchor_lines = [
        "- purpose",
        "- bounded-claim",
        "- terminology-boundaries",
        "- canonical-chain",
        "- publication-posture",
    ]
    if duplicate_anchor:
        anchor_lines.append("- canonical-chain")

    lines = [
        "# Belgi Canonicals",
        "## Anchor Registry (Stable IDs)",
        *anchor_lines,
        "",
        "## 2. Canonical Chain (Canonical)",
    ]
    if with_chain:
        lines.append("P → C1 → Q → C2 → R → C3 → S")
    path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def test_derive_canonicals_report_preserves_structural_owner_projection(tmp_path: Path) -> None:
    import tools.canonicals_report as canonicals_report

    _write_canonicals(tmp_path / "CANONICALS.md")

    assert canonicals_report.derive_canonicals_report(tmp_path) == {
        "anchor_registry_ids": [
            "purpose",
            "bounded-claim",
            "terminology-boundaries",
            "canonical-chain",
            "publication-posture",
        ],
        "canonical_chain": {"sequence": ["P", "C1", "Q", "C2", "R", "C3", "S"]},
        "owner_surface": "CANONICALS.md",
        "projection_kind": "derived-prose-owner-report",
        "report_schema_version": canonicals_report.REPORT_SCHEMA_VERSION,
    }


def test_derive_canonicals_report_extracts_only_structural_repo_truth() -> None:
    import tools.canonicals_report as canonicals_report

    report = canonicals_report.derive_canonicals_report(REPO_ROOT)

    assert set(report) == {
        "anchor_registry_ids",
        "canonical_chain",
        "owner_surface",
        "projection_kind",
        "report_schema_version",
    }
    assert report["owner_surface"] == "CANONICALS.md"
    assert report["projection_kind"] == "derived-prose-owner-report"
    assert report["report_schema_version"] == canonicals_report.REPORT_SCHEMA_VERSION
    assert report["canonical_chain"] == {"sequence": ["P", "C1", "Q", "C2", "R", "C3", "S"]}
    assert "canonical-chain" in report["anchor_registry_ids"]
    assert "publication-posture" in report["anchor_registry_ids"]


def test_derive_canonicals_report_fails_closed_when_anchor_registry_is_missing(tmp_path: Path) -> None:
    import tools.canonicals_report as canonicals_report

    (tmp_path / "CANONICALS.md").write_text(
        "# Belgi Canonicals\n## 2. Canonical Chain (Canonical)\nP → C1 → Q → C2 → R → C3 → S\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    with pytest.raises(
        canonicals_report.CanonicalsReportError,
        match="Missing required section: Anchor Registry \\(Stable IDs\\)",
    ):
        canonicals_report.derive_canonicals_report(tmp_path)


def test_derive_canonicals_report_fails_closed_when_anchor_registry_has_duplicates(tmp_path: Path) -> None:
    import tools.canonicals_report as canonicals_report

    _write_canonicals(tmp_path / "CANONICALS.md", duplicate_anchor=True)

    with pytest.raises(
        canonicals_report.CanonicalsReportError,
        match="Anchor Registry \\(Stable IDs\\) must not contain duplicate anchor ids",
    ):
        canonicals_report.derive_canonicals_report(tmp_path)


def test_derive_canonicals_report_fails_closed_when_canonical_chain_line_is_missing(tmp_path: Path) -> None:
    import tools.canonicals_report as canonicals_report

    _write_canonicals(tmp_path / "CANONICALS.md", with_chain=False)

    with pytest.raises(
        canonicals_report.CanonicalsReportError,
        match="Canonical chain section must contain one explicit arrow chain line",
    ):
        canonicals_report.derive_canonicals_report(tmp_path)


def test_main_writes_deterministic_report_bytes(tmp_path: Path) -> None:
    import tools.canonicals_report as canonicals_report

    _write_canonicals(tmp_path / "CANONICALS.md")
    rc = canonicals_report.main(
        ["--repo", str(tmp_path), "--out", "policy/derived_canonicals_report.json"]
    )

    assert rc == 0
    out_path = tmp_path / "policy" / "derived_canonicals_report.json"
    assert out_path.read_bytes() == canonicals_report._canonical_json_bytes(
        canonicals_report.derive_canonicals_report(tmp_path)
    )
