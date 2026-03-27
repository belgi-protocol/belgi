from __future__ import annotations

import json
import re
from pathlib import Path

from tests.helpers import subprocess_cli as cli_subprocess

run_belgi = cli_subprocess.run_belgi
current_open_label = cli_subprocess.current_open_label
other_open_labels = cli_subprocess.other_open_labels
_commit_file = cli_subprocess._commit_file
_extract_run_human_block = cli_subprocess._extract_run_human_block
_fresh_repo_clone = cli_subprocess._fresh_repo_clone
_git_rev_parse = cli_subprocess._git_rev_parse
_open_target_labels = cli_subprocess._open_target_labels


def test_run_no_go_emits_verbatim_remediation_and_evidence_paths(
    tmp_path: Path, capsys: object
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-contract-001"
    assert run_belgi(["init", "--repo", str(repo)]) == 0
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    intent_path = repo / ".belgi" / "runs" / run_id / "inputs" / "intent" / "IntentSpec.core.md"
    intent_path.write_text(
        (
            "# IntentSpec\n\n```yaml\n"
            "intent_id: \"INTENT-001\"\n"
            "title: \"NO-GO output contract\"\n"
            "goal: \"Exercise default no-go UX output contract.\"\n"
            "scope:\n"
            "  allowed_dirs:\n"
            "    - \"main/\"\n"
            "  forbidden_dirs:\n"
            "    - \"secrets/\"\n"
            "acceptance:\n"
            "  success_criteria:\n"
            "    - \"NO-GO block is compact and deterministic.\"\n"
            "tier:\n"
            "  tier_pack_id: \"tier-1\"\n"
            "doc_impact:\n"
            "  required_paths: []\n"
            "  note_on_empty: \"No docs required.\"\n"
            "```\n"
        ),
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    _commit_file(repo, "README.md", "forbidden path change\n", "touch forbidden path")
    base_sha = _git_rev_parse(repo, "HEAD~1")

    rc_run = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-1",
            "--intent-spec",
            f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
            "--base-revision",
            base_sha,
        ]
    )
    assert rc_run == 10
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_out = repo / ".belgi" / "store" / "runs" / run_key / attempt_id / "repo" / "out"
    verdict_path = attempt_out / "GateVerdict.R.json"
    evidence_path = attempt_out / "EvidenceManifest.json"
    verdict_obj = json.loads(verdict_path.read_text(encoding="utf-8", errors="strict"))
    remediation = str(verdict_obj.get("remediation", {}).get("next_instruction", ""))
    assert remediation

    assert "summary: verdict=NO-GO tier=tier-1" in captured.err
    assert f"run={run_id}" in captured.err
    assert f"key={run_key[:10]}" in captured.err
    assert "attempt=0001" in captured.err
    assert "run_id:" not in captured.err
    assert f"cause: {machine['primary_reason']}" in captured.err
    assert f"next: {remediation}" in captured.err
    assert "\n\n[belgi run] cause:" in captured.err
    assert "\n\n[belgi run] evidence:" in captured.err
    assert "\n\n[belgi run] open:" in captured.err
    assert "[belgi run]   gate: R" in captured.err
    assert "[belgi run]   gate_status: Q=GO R=NO-GO S=missing" in captured.err
    assert "[belgi run]   verdict: .belgi/runs/run-contract-001/open_verdict.txt" in captured.err
    assert "manifest: missing" in captured.err
    labels = _open_target_labels(captured.err)
    assert labels == ["verdict_R", "intent", "waivers"]
    assert "manifest:" not in labels
    assert current_open_label() in captured.err
    for label in other_open_labels():
        assert label not in captured.err
    assert re.search(rf"{re.escape(current_open_label())} .*{re.escape(str(verdict_path.resolve()))}", captured.err)
    pointer_path = repo / ".belgi" / "runs" / run_id / "open_verdict.txt"
    assert not re.search(rf"{re.escape(current_open_label())} .*{re.escape(str(pointer_path.resolve()))}", captured.err)
    assert f'evidence_manifest_path: {evidence_path.resolve()}' not in captured.err
    block = _extract_run_human_block(captured.err)
    assert block
    assert len(block) <= 25


def test_run_no_go_plain_output_has_no_color_codes(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "main/forbidden_probe.md", "forbidden delta\n", "touch forbidden path")
    base_sha = _git_rev_parse(repo, "HEAD~1")

    env_overrides = {"NO_COLOR": "1"}
    assert run_belgi(["init", "--repo", str(repo)], env_overrides=env_overrides) == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(
        ["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", base_sha],
        env_overrides=env_overrides,
    )
    assert rc_run == 10
    captured = capsys.readouterr()
    assert "\x1b[31m" not in captured.err
    assert "\x1b[32m" not in captured.err
    assert "\x1b[33m" not in captured.err
    assert "\x1b[35m" not in captured.err


def test_run_no_go_open_helpers_include_intent_and_waiver_paths(
    tmp_path: Path, capsys: object
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-open-helper-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    assert (
        run_belgi(
            [
                "waiver",
                "new",
                "--repo",
                str(repo),
                "--run-id",
                run_id,
                "--gate",
                "R",
                "--rule-id",
                "RULE-001",
                "--waiver-id",
                "waiver-001",
                "--expires-at",
                "2100-01-01T00:00:00Z",
            ]
        )
        == 0
    )
    assert (
        run_belgi(
            [
                "waiver",
                "apply",
                "--repo",
                str(repo),
                "--run-id",
                run_id,
                "--waiver",
                f".belgi/runs/{run_id}/inputs/waivers/waiver-001.json",
            ]
        )
        == 0
    )
    _ = capsys.readouterr()

    intent_path = repo / ".belgi" / "runs" / run_id / "inputs" / "intent" / "IntentSpec.core.md"
    waiver_path = repo / ".belgi" / "runs" / run_id / "inputs" / "waivers" / "waiver-001.json"
    intent_path.write_text(
        "# bad\n\n```yaml\nintent_id \"missing-colon\"\n```\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    rc = run_belgi(
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
    assert rc == 10
    captured = capsys.readouterr()

    assert f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md" in captured.err
    assert f".belgi/runs/{run_id}/inputs/waivers" in captured.err
    assert current_open_label() in captured.err
    assert str(intent_path.resolve()) in captured.err
    assert str(waiver_path.parent.resolve()) in captured.err


def test_run_no_go_default_emits_single_platform_open_helper(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "main/forbidden_probe.md", "forbidden delta\n", "touch forbidden path")
    base_sha = _git_rev_parse(repo, "HEAD~1")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(
        ["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", base_sha],
        env_overrides={"BELGI_SHOW_ALL_OPEN": None},
    )
    assert rc_run == 10
    captured = capsys.readouterr()

    assert current_open_label() in captured.err
    for label in other_open_labels():
        assert label not in captured.err


def test_run_no_go_verbose_includes_store_paths_and_all_open_helpers(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "main/forbidden_probe.md", "forbidden delta\n", "touch forbidden path")
    base_sha = _git_rev_parse(repo, "HEAD~1")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", base_sha, "--verbose"])
    assert rc_run == 10
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    verdict_abs = repo / ".belgi" / "store" / "runs" / run_key / attempt_id / "repo" / "out" / "GateVerdict.R.json"

    assert "[belgi run]   gate_status: Q=GO R=NO-GO S=missing" in captured.err
    assert "details:" in captured.err
    assert f"run_key: {run_key}" in captured.err
    assert f"attempt_id: {attempt_id}" in captured.err
    assert f"verdict_store_path: {verdict_abs.resolve()}" in captured.err
    verdict_q_abs = repo / ".belgi" / "store" / "runs" / run_key / attempt_id / "repo" / "out" / "GateVerdict.Q.json"
    assert f"verdict_Q_path: {verdict_q_abs.resolve()}" in captured.err
    assert f"verdict_R_path: {verdict_abs.resolve()}" in captured.err
    assert "verdict_S_path:" not in captured.err
    assert "open_macos:" in captured.err
    assert "open_linux:" in captured.err
    assert "open_windows:" in captured.err


def test_run_no_go_gate_status_line_is_deterministic(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "main/forbidden_probe.md", "forbidden delta\n", "touch forbidden path")
    base_sha = _git_rev_parse(repo, "HEAD~1")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", base_sha])
    assert rc_run == 10
    captured = capsys.readouterr()

    assert "[belgi run]   gate_status: Q=GO R=NO-GO S=missing" in captured.err


def test_run_emits_machine_result_line(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc_run == 0
    captured = capsys.readouterr()

    first_line = captured.out.splitlines()[0]
    machine = json.loads(first_line)
    assert machine["ok"] is True
    assert machine["verdict"] == "GO"
    assert machine["tier_id"] == "tier-0"
    assert isinstance(machine["run_key"], str) and len(machine["run_key"]) == 64
    assert machine["attempt_id"] == "attempt-0001"
    assert machine["findings_present"] is False
    assert machine["finding_count"] == 0


def test_run_go_emits_compact_sections_and_line_bound(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")
    run_id = "run-go-001"

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()
    intent_path = repo / ".belgi" / "runs" / run_id / "inputs" / "intent" / "IntentSpec.core.md"
    intent_path.write_text(
        (
            "# IntentSpec\n\n```yaml\n"
            "intent_id: \"INTENT-GO-001\"\n"
            "title: \"GO output contract\"\n"
            "goal: \"Exercise compact GO output contract.\"\n"
            "scope:\n"
            "  allowed_dirs:\n"
            "    - \"main/\"\n"
            "  forbidden_dirs:\n"
            "    - \"secrets/\"\n"
            "acceptance:\n"
            "  success_criteria:\n"
            "    - \"GO output is compact and deterministic.\"\n"
            "tier:\n"
            "  tier_pack_id: \"tier-1\"\n"
            "doc_impact:\n"
            "  required_paths: []\n"
            "  note_on_empty: \"No docs required.\"\n"
            "```\n"
        ),
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    rc = run_belgi(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-1",
            "--intent-spec",
            f".belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
            "--base-revision",
            head_sha,
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()

    assert "summary: verdict=GO tier=tier-1" in captured.err
    assert "evidence:" in captured.err
    assert "  verdict_R:" in captured.err
    assert "  manifest:" in captured.err
    assert "  seal:" in captured.err
    assert "open:" in captured.err
    assert "  verdict_R:" in captured.err
    assert "  intent:" in captured.err
    assert "  waivers:" in captured.err
    assert "created:" not in captured.err

    block = _extract_run_human_block(captured.err, level="GO")
    assert block
    assert len(block) <= 25


def test_run_go_verbose_includes_authoritative_paths(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    rc = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha, "--verbose"])
    assert rc == 0
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_out = repo / ".belgi" / "store" / "runs" / run_key / attempt_id / "repo" / "out"

    assert "details:" in captured.err
    assert f"verdict_R_path: {(attempt_out / 'GateVerdict.R.json').resolve()}" in captured.err
    assert f"manifest_path: {(attempt_out / 'EvidenceManifest.json').resolve()}" in captured.err
    assert f"seal_path: {(attempt_out / 'SealManifest.json').resolve()}" in captured.err


def test_run_non_tty_human_output_has_no_ansi_and_machine_first_line_is_plain_json(
    tmp_path: Path,
    capsys: object,
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc_run == 0
    captured = capsys.readouterr()

    first_line = captured.out.splitlines()[0]
    machine = json.loads(first_line)
    assert machine["ok"] is True
    assert "\x1b[" not in first_line
    assert "\x1b[" not in captured.err


def test_init_output_points_to_readme_and_next_command(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    rc = run_belgi(["init", "--repo", str(repo)])
    assert rc == 0
    captured = capsys.readouterr()

    lines = [line for line in captured.err.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0].startswith("[belgi init] next:")
    assert ".belgi/README.md" in lines[0]
    assert "belgi run new --repo . --run-id run-001" in lines[0]


def test_run_new_output_is_deterministic_and_has_no_open_uri(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-new-001"

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    rc = run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id])
    assert rc == 0
    captured = capsys.readouterr()
    assert "open_uri:" not in captured.err

    expected_labels = [
        f"[belgi run new]   runbook: .belgi/runs/{run_id}/RUN.md",
        f"[belgi run new]   intent: .belgi/runs/{run_id}/inputs/intent/IntentSpec.core.md",
        f"[belgi run new]   waivers: .belgi/runs/{run_id}/inputs/waivers",
    ]
    labels = [
        line
        for line in captured.err.splitlines()
        if line.startswith("[belgi run new]   ") and "open_" not in line
    ]
    assert labels == expected_labels
    assert captured.err.count(current_open_label()) == 3
    for label in other_open_labels():
        assert label not in captured.err


def test_about_output_is_bounded_and_contains_pack_identity(tmp_path: Path, capsys: object) -> None:
    _ = tmp_path
    rc = run_belgi(["about"])
    assert rc == 0
    captured = capsys.readouterr()

    lines = [line for line in captured.out.splitlines() if line.strip()]
    assert len(lines) <= 8
    assert any(line.startswith("protocol_pack: ") for line in lines)
    assert any(line.startswith("pack_id: ") for line in lines)
    assert any(line.startswith("manifest_sha256: ") for line in lines)
    assert "resources: belgi/_protocol_packs/v1" in lines


def test_waiver_helpers_emit_created_open_and_strict_match_reminder(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-waiver-output-001"

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    rc_new = run_belgi(
        [
            "waiver",
            "new",
            "--repo",
            str(repo),
            "--run-id",
            run_id,
            "--gate",
            "R",
            "--rule-id",
            "RULE-STRICT-001",
            "--waiver-id",
            "waiver-001",
            "--expires-at",
            "2100-01-01T00:00:00Z",
        ]
    )
    assert rc_new == 0
    captured_new = capsys.readouterr()
    assert "[belgi waiver new] created: .belgi/runs/run-waiver-output-001/inputs/waivers/waiver-001.json" in captured_new.err
    assert "[belgi waiver new] open: " in captured_new.err
    assert "reminder: strict match rule_id=RULE-STRICT-001 scope=path:<repo-rel-path> expires_at=2100-01-01T00:00:00Z" in captured_new.err

    rc_apply = run_belgi(
        [
            "waiver",
            "apply",
            "--repo",
            str(repo),
            "--run-id",
            run_id,
            "--waiver",
            f".belgi/runs/{run_id}/inputs/waivers/waiver-001.json",
        ]
    )
    assert rc_apply == 0
    captured_apply = capsys.readouterr()
    assert "[belgi waiver apply] open: " in captured_apply.err
    assert "reminder: strict match gate=R rule_id=RULE-STRICT-001" in captured_apply.err
