from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.helpers import subprocess_cli as cli_subprocess

run_belgi = cli_subprocess.run_belgi
current_open_label = cli_subprocess.current_open_label
other_open_labels = cli_subprocess.other_open_labels
_fresh_repo_clone = cli_subprocess._fresh_repo_clone
_git_rev_parse = cli_subprocess._git_rev_parse
_list_dirs = cli_subprocess._list_dirs
_prepare_shared_run_intent = cli_subprocess._prepare_shared_run_intent
_refresh_summary_artifact_hashes = cli_subprocess._refresh_summary_artifact_hashes
_unset_upstream_if_present = cli_subprocess._unset_upstream_if_present
_write_applied_waiver = cli_subprocess._write_applied_waiver
_commit_file = cli_subprocess._commit_file


def test_run_updates_run_workspace_pointer_files_deterministically(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()
    run_id = "run-pointers-001"
    _prepare_shared_run_intent(repo, capsys=capsys, run_id=run_id, tier_id="tier-0")

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
            "--base-revision",
            head_sha,
        ]
    )
    assert rc_run == 0
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])

    run_workspace = repo / ".belgi" / "runs" / run_id
    assert (run_workspace / "run_key.txt").read_text(encoding="utf-8", errors="strict") == f"{run_key}\n"
    assert (run_workspace / "last_attempt.txt").read_text(encoding="utf-8", errors="strict") == f"{attempt_id}\n"

    open_verdict_rel = (run_workspace / "open_verdict.txt").read_text(encoding="utf-8", errors="strict").strip()
    open_evidence_rel = (run_workspace / "open_evidence.txt").read_text(encoding="utf-8", errors="strict").strip()
    assert open_verdict_rel
    assert open_evidence_rel
    assert (repo / Path(*open_verdict_rel.split("/"))).is_file()
    assert (repo / Path(*open_evidence_rel.split("/"))).is_file()
    assert open_evidence_rel == f".belgi/store/runs/{run_key}/{attempt_id}/repo/out/EvidenceManifest.json"


def test_verify_fails_closed_on_mutated_evidence_manifest(tmp_path: Path) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    rc_run = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc_run == 0

    runs_root = repo / ".belgi" / "store" / "runs"
    run_key_dir = _list_dirs(runs_root)[0]
    attempt_dir = _list_dirs(run_key_dir)[0]
    manifest_path = attempt_dir / "repo" / "out" / "EvidenceManifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="strict"))
    manifest["run_id"] = "tampered"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    rc_verify = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify == 10


def test_verify_emits_machine_result_line(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    rc_run = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc_run == 0
    _ = capsys.readouterr()

    rc_verify = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify == 0
    captured = capsys.readouterr()

    first_line = captured.out.splitlines()[0]
    machine = json.loads(first_line)
    assert machine["ok"] is True
    assert machine["verdict"] == "GO"
    assert machine["tier_id"] is None
    assert isinstance(machine["run_key"], str) and len(machine["run_key"]) == 64
    assert machine["attempt_id"] == "attempt-0001"


def test_verify_selection_explicit_flags_and_summary_tokens(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    assert run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha]) == 0
    run_first = json.loads(capsys.readouterr().out.splitlines()[0])
    run_key = str(run_first["run_key"])

    assert run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha]) == 0
    _ = capsys.readouterr()

    rc_verify = run_belgi(
        [
            "verify",
            "--repo",
            str(repo),
            "--run-key",
            run_key,
            "--attempt-id",
            "attempt-0001",
        ]
    )
    assert rc_verify == 0
    captured = capsys.readouterr()

    assert "summary: verdict=GO" in captured.err
    assert f"verified_key={run_key[:10]}" in captured.err
    assert "verified_attempt=0001" in captured.err
    assert "selected_by=explicit" in captured.err


def test_verify_selection_pointer_and_open_command_targets_real_verdict(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")
    run_id = "run-verify-pointer-001"

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    _prepare_shared_run_intent(repo, capsys=capsys, run_id=run_id, tier_id="tier-0")

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
            "--base-revision",
            head_sha,
        ]
    )
    assert rc_run == 0
    run_machine = json.loads(capsys.readouterr().out.splitlines()[0])
    run_key = str(run_machine["run_key"])
    attempt_id = str(run_machine["attempt_id"])
    verdict_path = repo / ".belgi" / "store" / "runs" / run_key / attempt_id / "repo" / "out" / "GateVerdict.R.json"
    pointer_path = repo / ".belgi" / "runs" / run_id / "open_verdict.txt"

    rc_verify = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify == 0
    captured = capsys.readouterr()

    assert "selected_by=pointer" in captured.err
    assert f"verified_key={run_key[:10]}" in captured.err
    assert current_open_label() in captured.err
    for label in other_open_labels():
        assert label not in captured.err
    assert f'"{verdict_path.resolve()}"' in captured.err
    assert f'"{pointer_path.resolve()}"' not in captured.err


def test_verify_selection_store_uses_lexicographic_run_key_then_attempt(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    rc_a = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc_a == 0
    run_a = json.loads(capsys.readouterr().out.splitlines()[0])
    run_key_a = str(run_a["run_key"])

    intent_template = _prepare_shared_run_intent(
        repo,
        capsys=capsys,
        run_id="run-verify-store-001",
        tier_id="tier-0",
    )
    intent_custom_rel = "intent_custom.md"
    (repo / intent_custom_rel).write_bytes(intent_template.read_bytes())
    rc_b = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            intent_custom_rel,
            "--base-revision",
            head_sha,
        ]
    )
    assert rc_b == 0
    run_b = json.loads(capsys.readouterr().out.splitlines()[0])
    run_key_b = str(run_b["run_key"])

    expected_run_key = max(run_key_a, run_key_b)
    rc_verify = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify == 0
    captured = capsys.readouterr()

    assert "selected_by=store" in captured.err
    assert f"verified_key={expected_run_key[:10]}" in captured.err
    assert "verified_attempt=0001" in captured.err


def test_verify_selection_skips_stale_pointer_and_uses_next_valid_pointer(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    intent_path = _prepare_shared_run_intent(repo, capsys=capsys, run_id="run-001", tier_id="tier-0")
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", "run-002"]) == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            head_sha,
        ]
    )
    assert rc_run == 0
    machine = json.loads(capsys.readouterr().out.splitlines()[0])
    expected_key = str(machine["run_key"])

    # run-002 pointers stay stale (PENDING), verify must skip them and use run-001 pointer target.
    rc_verify = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify == 0
    captured = capsys.readouterr()
    assert "selected_by=pointer" in captured.err
    assert f"verified_key={expected_key[:10]}" in captured.err


def test_verify_selection_all_stale_pointers_falls_back_to_store(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", "run-001"]) == 0
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", "run-002"]) == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc_run == 0
    machine = json.loads(capsys.readouterr().out.splitlines()[0])
    expected_key = str(machine["run_key"])

    rc_verify = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify == 0
    captured = capsys.readouterr()
    assert "selected_by=store" in captured.err
    assert f"verified_key={expected_key[:10]}" in captured.err


def test_verify_selection_all_stale_pointers_and_empty_store_fails_closed(
    tmp_path: Path, capsys: object
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    assert run_belgi(["init", "--repo", str(repo)]) == 0
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", "run-001"]) == 0
    _ = capsys.readouterr()

    rc_verify = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert "no valid pointer target" in str(machine.get("primary_reason") or "")


def test_verify_uses_anchored_time_for_waiver_expiry_replay(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "src/risky_exec.py", "exec('1')\n", "add risky primitive")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()
    intent_path = _prepare_shared_run_intent(
        repo,
        capsys=capsys,
        run_id="run-tier1-waiver-anchor-001",
        tier_id="tier-1",
    )

    _write_applied_waiver(
        repo,
        file_name="r8_anchor_replay.json",
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
    machine_run = json.loads(capsys.readouterr().out.splitlines()[0])
    run_key = str(machine_run["run_key"])
    attempt_id = str(machine_run["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id

    evidence_path = attempt_dir / "repo" / "out" / "EvidenceManifest.json"
    evidence_obj = json.loads(evidence_path.read_text(encoding="utf-8", errors="strict"))
    evidence_obj["anchored_time_utc"] = "2000-01-01T00:00:00Z"
    evidence_path.write_text(
        json.dumps(evidence_obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
    )

    waiver_path = attempt_dir / "repo" / "out" / "inputs" / "waivers_applied" / "r8_anchor_replay.json"
    waiver_obj = json.loads(waiver_path.read_text(encoding="utf-8", errors="strict"))
    waiver_obj["expires_at"] = "2000-01-02T00:00:00Z"
    waiver_path.write_text(
        json.dumps(waiver_obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
    )

    _refresh_summary_artifact_hashes(repo, attempt_dir, [evidence_path, waiver_path])

    rc_verify_1 = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify_1 == 0
    machine_verify_1 = json.loads(capsys.readouterr().out.splitlines()[0])
    assert machine_verify_1["verdict"] == "GO"

    rc_verify_2 = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify_2 == 0
    machine_verify_2 = json.loads(capsys.readouterr().out.splitlines()[0])
    assert machine_verify_2["verdict"] == "GO"


def test_verify_fails_closed_when_anchor_missing_for_applied_waiver(
    tmp_path: Path, capsys: object
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "src/risky_exec.py", "exec('1')\n", "add risky primitive")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()
    intent_path = _prepare_shared_run_intent(
        repo,
        capsys=capsys,
        run_id="run-tier1-waiver-missing-anchor-001",
        tier_id="tier-1",
    )

    _write_applied_waiver(
        repo,
        file_name="r8_missing_anchor.json",
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
    machine_run = json.loads(capsys.readouterr().out.splitlines()[0])
    run_key = str(machine_run["run_key"])
    attempt_id = str(machine_run["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id

    evidence_path = attempt_dir / "repo" / "out" / "EvidenceManifest.json"
    evidence_obj = json.loads(evidence_path.read_text(encoding="utf-8", errors="strict"))
    evidence_obj.pop("anchored_time_utc", None)
    evidence_path.write_text(
        json.dumps(evidence_obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
    )
    _refresh_summary_artifact_hashes(repo, attempt_dir, [evidence_path])

    rc_verify = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify == 10
    captured_verify = capsys.readouterr()
    machine_verify = json.loads(captured_verify.out.splitlines()[0])
    reason = str(machine_verify.get("primary_reason") or "")
    assert "anchored_time_utc" in reason
    assert "BELGI >=1.4.2" in reason
    assert "re-run `belgi run` with BELGI >=1.4.2" in captured_verify.err


@pytest.mark.parametrize(
    ("scope_path", "expires_at", "expected_reason"),
    [
        ("src/risky_exec.py", "1960-01-01T00:00:00Z", "expires_at is not after EvidenceManifest.anchored_time_utc"),
        ("src/mismatch.py", "2100-01-01T00:00:00Z", "does not match any finding by rule_id+path"),
    ],
)
def test_tier1_fails_with_expired_or_mismatched_applied_waiver(
    tmp_path: Path,
    capsys: object,
    scope_path: str,
    expires_at: str,
    expected_reason: str,
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "src/risky_exec.py", "exec('1')\n", "add risky primitive")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()
    intent_path = _prepare_shared_run_intent(
        repo,
        capsys=capsys,
        run_id="run-tier1-waiver-invalid-001",
        tier_id="tier-1",
    )

    _write_applied_waiver(
        repo,
        file_name="r8_invalid.json",
        rule_id="ADV-EXEC-001",
        scope_path=scope_path,
        expires_at=expires_at,
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
    assert rc_run == 10
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert "chain.gate_" in str(machine["primary_reason"])
    assert "NO-GO:" in str(machine["primary_reason"])
    assert expected_reason in str(machine["primary_reason"])
