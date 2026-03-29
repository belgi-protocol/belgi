from __future__ import annotations

from pathlib import Path

from tests.helpers.repo_imports import reset_repo_local_imports

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_PATH = REPO_ROOT / "docs" / "operations" / "exit-codes.md"

reset_repo_local_imports("belgi")

from belgi.cli_app import render as cli_render


def _read_doc_lines() -> list[str]:
    return DOC_PATH.read_text(encoding="utf-8", errors="strict").splitlines()


def _parse_table_after_heading(heading: str) -> list[dict[str, str]]:
    lines = _read_doc_lines()
    for index, line in enumerate(lines):
        if line.strip() != heading:
            continue
        table_start = index + 1
        while table_start < len(lines) and not lines[table_start].startswith("|"):
            table_start += 1
        assert table_start + 1 < len(lines), f"missing table after {heading!r}"
        header_line = lines[table_start]
        separator_line = lines[table_start + 1]
        assert separator_line.startswith("|"), f"missing markdown table separator after {heading!r}"
        headers = [cell.strip() for cell in header_line.strip().strip("|").split("|")]
        rows: list[dict[str, str]] = []
        cursor = table_start + 2
        while cursor < len(lines) and lines[cursor].startswith("|"):
            values = [cell.strip() for cell in lines[cursor].strip().strip("|").split("|")]
            assert len(values) == len(headers), f"malformed row under {heading!r}: {lines[cursor]!r}"
            rows.append(dict(zip(headers, values, strict=True)))
            cursor += 1
        assert rows, f"expected at least one data row after {heading!r}"
        return rows
    raise AssertionError(f"missing heading {heading!r}")


def _parse_code_literal(value: str) -> int:
    normalized = value.strip()
    if normalized.startswith("`") and normalized.endswith("`"):
        normalized = normalized[1:-1]
    return int(normalized)


def test_public_exit_code_table_matches_render_owner() -> None:
    rows = _parse_table_after_heading("## Public CLI Surface (`belgi`)")
    actual = {
        _parse_code_literal(row["Code"]): row["Class"].strip("`")
        for row in rows
    }
    assert actual == {
        cli_render.RC_GO: "GO",
        cli_render.RC_NO_GO: "NO-GO",
        cli_render.RC_USER_ERROR: "USER_ERROR",
        cli_render.RC_INTERNAL_ERROR: "INTERNAL_ERROR",
    }


def test_default_exit_code_examples_match_render_owner() -> None:
    rows = _parse_table_after_heading("### Default public CLI boundary normalization")
    examples = [
        (_parse_code_literal(row["Raw rc"]), _parse_code_literal(row["Public CLI rc"]))
        for row in rows
    ]
    for raw_rc, expected_cli_rc in examples:
        assert cli_render._normalize_cli_exit_code(raw_rc, surface="default") == expected_cli_rc


def test_stage_forwarder_exit_code_examples_match_render_owner() -> None:
    rows = _parse_table_after_heading("### `stage` forwarder public CLI boundary normalization")
    examples = [
        (_parse_code_literal(row["Raw rc"]), _parse_code_literal(row["Public CLI rc"]))
        for row in rows
    ]
    for raw_rc, expected_cli_rc in examples:
        assert cli_render._normalize_cli_exit_code(raw_rc, surface="stage_forwarder") == expected_cli_rc
