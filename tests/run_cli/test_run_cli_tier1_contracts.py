from __future__ import annotations

import json
from pathlib import Path

from tests.helpers import subprocess_cli as cli_subprocess

run_belgi = cli_subprocess.run_belgi
_commit_file = cli_subprocess._commit_file
_fresh_repo_clone = cli_subprocess._fresh_repo_clone
_prepare_shared_run_intent = cli_subprocess._prepare_shared_run_intent
_remove_tests_tree_and_commit = cli_subprocess._remove_tests_tree_and_commit
_run_tier1_and_get_attempt = cli_subprocess._run_tier1_and_get_attempt
_unset_upstream_if_present = cli_subprocess._unset_upstream_if_present
_git_rev_parse = cli_subprocess._git_rev_parse
_write_applied_waiver = cli_subprocess._write_applied_waiver


def test_tier1_adopter_like_repo_without_tests_produces_test_report(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _remove_tests_tree_and_commit(repo)

    _, attempt_dir = _run_tier1_and_get_attempt(repo, capsys)
    test_report_path = attempt_dir / "repo" / "out" / "artifacts" / "tests.report.json"
    assert test_report_path.is_file()
    verify_report = json.loads((attempt_dir / "repo" / "out" / "verify_report.R.json").read_text(encoding="utf-8", errors="strict"))
    results = verify_report.get("results")
    assert isinstance(results, list)
    assert any(isinstance(entry, dict) and entry.get("check_id") == "R8" for entry in results)


def test_tier1_test_report_includes_mode_status_and_exit_code(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _remove_tests_tree_and_commit(repo)

    _, attempt_dir = _run_tier1_and_get_attempt(repo, capsys)
    test_report_path = attempt_dir / "repo" / "out" / "artifacts" / "tests.report.json"
    report = json.loads(test_report_path.read_text(encoding="utf-8", errors="strict"))

    assert report.get("mode") == "engine_smoke"
    assert report.get("status") == "pass"
    assert isinstance(report.get("exit_code"), int)
    assert isinstance(report.get("summary_text"), str) and bool(str(report["summary_text"]).strip())


def test_tier1_passes_with_valid_applied_waiver(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "src/risky_exec.py", "exec('1')\n", "add risky primitive")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()
    intent_path = _prepare_shared_run_intent(
        repo,
        capsys=capsys,
        run_id="run-tier1-waiver-pass-001",
        tier_id="tier-1",
    )

    _write_applied_waiver(
        repo,
        file_name="r8_exec.json",
        rule_id="ADV-EXEC-001",
        scope_path="src/risky_exec.py",
        expires_at="2100-01-01T00:00:00Z",
    )

    _unset_upstream_if_present(repo)
    base_sha = _git_rev_parse(repo, "HEAD~1")
    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-1",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            base_sha,
        ]
    )
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is True
    assert machine["verdict"] == "GO"
    assert machine["waivers_applied_count"] == 1
    assert machine["waivers_applied_refs"] == ["out/inputs/waivers_applied/r8_exec.json"]

    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id

    summary_obj = json.loads((attempt_dir / "run.summary.json").read_text(encoding="utf-8", errors="strict"))
    waivers_summary = summary_obj.get("waivers_applied")
    assert waivers_summary == {"count": 1, "storage_refs": ["out/inputs/waivers_applied/r8_exec.json"]}

    locked_spec = json.loads((attempt_dir / "repo" / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict"))
    assert locked_spec.get("waivers_applied") == ["out/inputs/waivers_applied/r8_exec.json"]

    gate_r = json.loads((attempt_dir / "repo" / "out" / "GateVerdict.R.json").read_text(encoding="utf-8", errors="strict"))
    assert gate_r.get("verdict") == "GO"
