from __future__ import annotations

from pathlib import Path

from tools.check_codeowners import find_missing_codeowners_patterns


def test_codeowners_checker_fails_on_dead_path(tmp_path: Path) -> None:
    codeowners = tmp_path / ".github" / "CODEOWNERS"
    codeowners.parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "gates").mkdir(parents=True, exist_ok=True)
    (tmp_path / "gates" / "GATE_Q.md").write_text("# Gate Q\n", encoding="utf-8", errors="strict", newline="\n")
    codeowners.write_text(
        "/gates/GATE_Q.md @owner\n/missing/path.py @owner\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    missing = find_missing_codeowners_patterns(tmp_path, codeowners)
    assert missing == [".github/CODEOWNERS:2:/missing/path.py"]


def test_codeowners_checker_passes_when_all_patterns_exist(tmp_path: Path) -> None:
    codeowners = tmp_path / ".github" / "CODEOWNERS"
    codeowners.parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "gates").mkdir(parents=True, exist_ok=True)
    (tmp_path / "schemas").mkdir(parents=True, exist_ok=True)
    (tmp_path / "gates" / "GATE_R.md").write_text("# Gate R\n", encoding="utf-8", errors="strict", newline="\n")
    (tmp_path / "schemas" / "LockedSpec.schema.json").write_text(
        "{}\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    codeowners.write_text(
        "/gates/GATE_R.md @owner\n/schemas/*.json @owner\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    missing = find_missing_codeowners_patterns(tmp_path, codeowners)
    assert missing == []
