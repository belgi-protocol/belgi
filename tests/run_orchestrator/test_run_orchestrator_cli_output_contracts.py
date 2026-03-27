from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.helpers import run_cli_harness as harness
from tests.helpers.repo_imports import BelgiCliSurface

pytestmark = pytest.mark.repo_local


@pytest.fixture(autouse=True)
def _clear_base_revision_env(monkeypatch: pytest.MonkeyPatch) -> None:
    harness.clear_base_revision_env(monkeypatch)


@pytest.fixture
def fresh_cli_surface() -> BelgiCliSurface:
    return harness.fresh_belgi_cli_surface()


_commit_file = harness._commit_file
_fresh_repo_clone = harness._fresh_repo_clone
_git_rev_parse = harness._git_rev_parse


def test_run_no_go_next_instruction_prefers_authoritative_gate_verdict(
    tmp_path: Path, fresh_cli_surface: BelgiCliSurface
) -> None:
    belgi_cli = fresh_cli_surface.cli
    chain_out_dir = tmp_path / "out"
    chain_out_dir.mkdir()
    (chain_out_dir / "GateVerdict.R.json").write_text(
        json.dumps(
            {
                "gate_id": "R",
                "verdict": "NO-GO",
                "remediation": {"next_instruction": "Do fix Gate R evidence, then re-run R."},
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (chain_out_dir / "C1IntentParseError.json").write_text(
        json.dumps(
            {"next_instruction": "Do fix IntentSpec YAML, then re-run Q."},
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    next_instruction = belgi_cli._run_no_go_next_instruction(
        chain_out_dir=chain_out_dir,
        primary_reason="chain.gate_r_verify returned rc=10",
    )

    assert next_instruction == "Do fix Gate R evidence, then re-run R."


def test_run_no_go_next_instruction_ignores_non_no_go_gate_verdict(
    tmp_path: Path, fresh_cli_surface: BelgiCliSurface
) -> None:
    belgi_cli = fresh_cli_surface.cli
    chain_out_dir = tmp_path / "out"
    chain_out_dir.mkdir()
    (chain_out_dir / "GateVerdict.R.json").write_text(
        json.dumps(
            {
                "gate_id": "R",
                "verdict": "GO",
                "remediation": {"next_instruction": "Do not show this fake gate remediation."},
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (chain_out_dir / "C1IntentParseError.json").write_text(
        json.dumps(
            {"next_instruction": "Do fix IntentSpec YAML, then re-run Q."},
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    next_instruction = belgi_cli._run_no_go_next_instruction(
        chain_out_dir=chain_out_dir,
        primary_reason="chain.compiler_c1_intent returned rc=3",
    )

    assert next_instruction == "Do fix IntentSpec YAML, then re-run Q."


def test_run_no_go_next_instruction_uses_generic_fallback_without_authoritative_artifacts(
    tmp_path: Path, fresh_cli_surface: BelgiCliSurface
) -> None:
    belgi_cli = fresh_cli_surface.cli
    next_instruction = belgi_cli._run_no_go_next_instruction(
        chain_out_dir=tmp_path / "missing-out",
        primary_reason="unexpected no-go",
    )

    assert next_instruction == "Do inspect the reported reason, fix inputs, then rerun `belgi run`."


def test_run_no_go_hyperlinks_opt_in(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    belgi_cli = fresh_cli_surface.cli
    belgi_main = fresh_cli_surface.main
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "main/forbidden_probe.md", "forbidden delta\n", "touch forbidden path")
    base_sha = _git_rev_parse(repo, "HEAD~1")

    monkeypatch.setenv("BELGI_HYPERLINKS", "1")
    monkeypatch.setattr(belgi_cli, "_stderr_supports_color", lambda: True)

    assert belgi_main(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", base_sha])
    assert rc_run == 10
    captured = capsys.readouterr()
    assert re.search(r"\x1b\]8;;file://[^\x1b]+\x1b\\verdict_[QRS]\x1b\]8;;\x1b\\", captured.err)
    assert "\x1b]8;;" in captured.err


def test_run_no_go_hyperlinks_absent_when_unset(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    belgi_cli = fresh_cli_surface.cli
    belgi_main = fresh_cli_surface.main
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "main/forbidden_probe.md", "forbidden delta\n", "touch forbidden path")
    base_sha = _git_rev_parse(repo, "HEAD~1")

    monkeypatch.delenv("BELGI_HYPERLINKS", raising=False)
    monkeypatch.setattr(belgi_cli, "_stderr_supports_color", lambda: True)

    assert belgi_main(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", base_sha])
    assert rc_run == 10
    captured = capsys.readouterr()
    assert "\x1b]8;;" not in captured.err
