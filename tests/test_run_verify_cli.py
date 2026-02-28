from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

import belgi.cli as belgi_cli
from belgi.cli import main as belgi_main
from belgi.core.schema import validate_schema
from belgi.core import run_orchestrator
from belgi.protocol.pack import get_builtin_protocol_context


@pytest.fixture(autouse=True)
def _clear_base_revision_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BELGI_BASE_SHA", raising=False)
    monkeypatch.delenv("GITHUB_BASE_SHA", raising=False)


def _list_dirs(path: Path) -> list[Path]:
    return sorted([p for p in path.iterdir() if p.is_dir()], key=lambda p: p.name)


def _fresh_repo_clone(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    cp = subprocess.run(
        ["git", "clone", "--quiet", "--shared", str(REPO_ROOT), str(repo)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 0, cp.stderr
    cp_cfg_email = subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp_cfg_email.returncode == 0, cp_cfg_email.stderr
    cp_cfg_name = subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test User"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp_cfg_name.returncode == 0, cp_cfg_name.stderr
    return repo


def _commit_file(repo: Path, rel: str, content: str, msg: str) -> None:
    path = repo / Path(*rel.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="strict")
    cp_add = subprocess.run(
        ["git", "-C", str(repo), "add", rel],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp_add.returncode == 0, cp_add.stderr
    cp_commit = subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", msg],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp_commit.returncode == 0, cp_commit.stderr


def _run_git(repo: Path, args: list[str]) -> None:
    cp = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 0, cp.stderr


def _git_rev_parse(repo: Path, revision: str) -> str:
    cp = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", revision],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 0, cp.stderr
    sha = cp.stdout.strip().lower()
    assert re.fullmatch(r"[0-9a-f]{40}", sha)
    return sha


def _unset_upstream_if_present(repo: Path) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "branch", "--unset-upstream"],
        capture_output=True,
        text=True,
        check=False,
    )


def _remove_tests_tree_and_commit(repo: Path) -> None:
    _run_git(repo, ["rm", "-r", "--quiet", "--ignore-unmatch", "tests"])
    _run_git(repo, ["commit", "-m", "remove tests tree"])


def _run_tier1_and_get_attempt(repo: Path, capsys: object) -> tuple[dict[str, object], Path]:
    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-1", "--base-revision", head_sha])
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "runs" / run_key / attempt_id
    assert attempt_dir.is_dir()
    return machine, attempt_dir


def _write_applied_waiver(
    repo: Path,
    *,
    file_name: str,
    rule_id: str,
    scope_path: str,
    expires_at: str,
) -> Path:
    waivers_dir = repo / ".belgi" / "waivers_applied"
    waivers_dir.mkdir(parents=True, exist_ok=True)
    waiver_path = waivers_dir / file_name
    waiver_doc = {
        "schema_version": "1.0.0",
        "waiver_id": "waiver-tier1-r8",
        "gate_id": "R",
        "rule_id": rule_id,
        "scope": f"path:{scope_path}",
        "justification": "Deterministic waiver for tier-1 integration test.",
        "mitigation": "Follow-up patch removes risky primitive.",
        "approver": "human:test@example.com",
        "created_at": "1970-01-01T00:00:00Z",
        "expires_at": expires_at,
        "audit_trail_ref": {"id": "audit-001", "storage_ref": "waivers/audit.log"},
        "status": "active",
    }
    waiver_path.write_text(
        json.dumps(waiver_doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
    )
    return waiver_path


def test_run_tier_uses_stable_run_key_and_unique_attempt_id(tmp_path: Path) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0

    rc1 = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc1 == 0

    runs_root = repo / ".belgi" / "runs"
    run_dirs = _list_dirs(runs_root)
    assert len(run_dirs) == 1
    run_key_dir = run_dirs[0]
    assert len(run_key_dir.name) == 64

    attempts_after_first = _list_dirs(run_key_dir)
    assert [p.name for p in attempts_after_first] == ["attempt-0001"]
    first_attempt = attempts_after_first[0]

    summary1 = json.loads((first_attempt / "run.summary.json").read_text(encoding="utf-8", errors="strict"))
    assert summary1["run_key"] == run_key_dir.name
    assert summary1["attempt_id"] == "attempt-0001"
    assert summary1["run_key_preimage"]["normalized_inputs"]["intent_spec_source"] == "(auto)"
    evidence1 = json.loads(
        (first_attempt / "repo" / "out" / "EvidenceManifest.json").read_text(encoding="utf-8", errors="strict")
    )
    assert evidence1["run_id"] == run_key_dir.name
    seal = json.loads((first_attempt / "repo" / "out" / "SealManifest.json").read_text(encoding="utf-8", errors="strict"))
    assert seal["run_id"] == run_key_dir.name
    prompt_hashes = json.loads(
        (first_attempt / "repo" / "out" / "prompt_block_hashes.json").read_text(encoding="utf-8", errors="strict")
    )
    assert prompt_hashes
    assert all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in prompt_hashes.values())
    assert all(v != "0" * 64 for v in prompt_hashes.values())

    rc_verify_1 = belgi_main(["verify", "--repo", str(repo)])
    assert rc_verify_1 == 0

    rc2 = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc2 == 0

    run_dirs_after_second = _list_dirs(runs_root)
    assert [p.name for p in run_dirs_after_second] == [run_key_dir.name]
    attempts_after_second = _list_dirs(run_key_dir)
    assert [p.name for p in attempts_after_second] == ["attempt-0001", "attempt-0002"]

    summary2 = json.loads((attempts_after_second[1] / "run.summary.json").read_text(encoding="utf-8", errors="strict"))
    assert summary2["run_key"] == run_key_dir.name
    assert summary2["attempt_id"] == "attempt-0002"

    rc_verify_2 = belgi_main(["verify", "--repo", str(repo)])
    assert rc_verify_2 == 0


def test_init_custom_workspace_updates_gitignore_and_run_path(tmp_path: Path) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = belgi_main(["init", "--repo", str(repo), "--workspace", ".belgi_alt"])
    assert rc_init == 0

    gitignore = (repo / ".gitignore").read_text(encoding="utf-8", errors="strict")
    assert ".belgi/" in gitignore
    assert ".belgi_alt/" in gitignore

    rc_run = belgi_main(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-1",
            "--workspace",
            ".belgi_alt",
            "--base-revision",
            head_sha,
        ]
    )
    assert rc_run == 0

    runs_root = repo / ".belgi_alt" / "runs"
    run_dirs = _list_dirs(runs_root)
    assert len(run_dirs) == 1
    attempts = _list_dirs(run_dirs[0])
    assert [p.name for p in attempts] == ["attempt-0001"]

    rc_verify = belgi_main(["verify", "--repo", str(repo), "--workspace", ".belgi_alt"])
    assert rc_verify == 0


def test_verify_fails_closed_on_mutated_evidence_manifest(tmp_path: Path) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc_run == 0

    runs_root = repo / ".belgi" / "runs"
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

    rc_verify = belgi_main(["verify", "--repo", str(repo)])
    assert rc_verify == 10


def test_run_fails_closed_when_repo_head_sha_is_unavailable(tmp_path: Path) -> None:
    rc_init = belgi_main(["init", "--repo", str(tmp_path)])
    assert rc_init == 0

    rc_run = belgi_main(["run", "--repo", str(tmp_path), "--tier", "tier-0"])
    assert rc_run == 20


def test_run_fails_closed_when_base_revision_is_unavailable(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _unset_upstream_if_present(repo)
    monkeypatch.delenv("BELGI_BASE_SHA", raising=False)
    monkeypatch.delenv("GITHUB_BASE_SHA", raising=False)

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0"])
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    reason = str(machine.get("primary_reason") or "")
    assert "base revision unavailable" in reason
    assert "--base-revision <40-hex SHA>" in reason


def test_run_revision_binding_is_authoritative_for_base_and_evaluated(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "main/forbidden_probe.md", "forbidden delta\n", "touch forbidden path")
    base_sha = _git_rev_parse(repo, "HEAD~1")
    evaluated_sha = _git_rev_parse(repo, "HEAD")

    monkeypatch.setenv("BELGI_BASE_SHA", base_sha)
    monkeypatch.delenv("GITHUB_BASE_SHA", raising=False)

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0"])
    assert rc_run == 10
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "runs" / run_key / attempt_id

    locked_spec = json.loads((attempt_dir / "repo" / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict"))
    assert str(locked_spec.get("upstream_state", {}).get("commit_sha", "")) == base_sha

    evidence_input = json.loads(
        (attempt_dir / "repo" / "out" / "EvidenceManifest.input.json").read_text(encoding="utf-8", errors="strict")
    )
    artifacts = evidence_input.get("artifacts")
    assert isinstance(artifacts, list)
    revision_binding_artifacts = [
        art
        for art in artifacts
        if isinstance(art, dict)
        and art.get("kind") == "policy_report"
        and art.get("id") == "policy.revision_binding"
    ]
    assert len(revision_binding_artifacts) == 1
    revision_binding_artifact = revision_binding_artifacts[0]
    assert revision_binding_artifact.get("produced_by") == "C1"
    storage_ref = str(revision_binding_artifact.get("storage_ref", ""))
    revision_binding_path = attempt_dir / "repo" / Path(*storage_ref.split("/"))
    revision_binding_payload = json.loads(revision_binding_path.read_text(encoding="utf-8", errors="strict"))

    policy_schema = get_builtin_protocol_context().read_json("schemas/PolicyReportPayload.schema.json")
    schema_errors = validate_schema(
        revision_binding_payload,
        policy_schema,
        root_schema=policy_schema,
        path="policy.revision_binding",
    )
    assert schema_errors == []

    assert revision_binding_payload.get("base_revision") == base_sha
    assert revision_binding_payload.get("evaluated_revision") == evaluated_sha
    checks = revision_binding_payload.get("checks")
    assert isinstance(checks, list) and len(checks) >= 1
    first_check = checks[0]
    assert isinstance(first_check, dict)
    assert first_check.get("check_id") == "REV-BIND-001"
    assert first_check.get("passed") is True
    assert first_check.get("base_revision") == base_sha
    assert first_check.get("evaluated_revision") == evaluated_sha
    assert first_check.get("discovery_method") == "ci_env"

    verify_report = json.loads((attempt_dir / "repo" / "out" / "verify_report.R.json").read_text(encoding="utf-8", errors="strict"))
    assert str(verify_report.get("repo_revision") or "") == evaluated_sha


def test_run_emits_machine_result_line(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
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


def test_verify_emits_machine_result_line(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc_run == 0
    _ = capsys.readouterr()

    rc_verify = belgi_main(["verify", "--repo", str(repo)])
    assert rc_verify == 0
    captured = capsys.readouterr()

    first_line = captured.out.splitlines()[0]
    machine = json.loads(first_line)
    assert machine["ok"] is True
    assert machine["verdict"] == "GO"
    assert machine["tier_id"] is None
    assert isinstance(machine["run_key"], str) and len(machine["run_key"]) == 64
    assert machine["attempt_id"] == "attempt-0001"


def test_tier0_emits_findings_signal_in_summary_and_machine_json(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "src/risky_exec.py", "exec('1')\n", "add risky primitive")

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    run_key = machine["run_key"]
    attempt_dir = repo / ".belgi" / "runs" / run_key / "attempt-0001"

    summary_obj = json.loads((attempt_dir / "run.summary.json").read_text(encoding="utf-8", errors="strict"))
    adv = summary_obj.get("adversarial_scan")
    assert isinstance(adv, dict)
    assert adv.get("findings_present") is True
    assert isinstance(adv.get("finding_count"), int) and int(adv["finding_count"]) > 0
    assert machine.get("findings_present") is adv["findings_present"]
    assert machine.get("finding_count") == adv["finding_count"]

    adv_report = json.loads(
        (attempt_dir / "repo" / "out" / "artifacts" / "policy.adversarial_scan.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert adv_report.get("findings_present") is True
    assert isinstance(adv_report.get("finding_count"), int) and int(adv_report["finding_count"]) > 0
    assert machine.get("findings_present") is adv_report["findings_present"]
    assert machine.get("finding_count") == adv_report["finding_count"]


def test_tier0_fails_closed_if_policy_scan_exists_but_signal_missing(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "src/risky_exec.py", "exec('1')\n", "add risky primitive")

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    original_orchestrate_chain_run = belgi_cli.orchestrate_chain_run

    def _patched_orchestrate_chain_run(*args: object, **kwargs: object) -> run_orchestrator.RunOrchestrationResult:
        result = original_orchestrate_chain_run(*args, **kwargs)
        return run_orchestrator.RunOrchestrationResult(
            chain_repo_dir=result.chain_repo_dir,
            chain_out_dir=result.chain_out_dir,
            rel_evidence_final=result.rel_evidence_final,
            rel_seal=result.rel_seal,
            rel_gate_s=result.rel_gate_s,
            chain_paths=result.chain_paths,
            adversarial_findings_count=0,
            adversarial_findings_present=False,
            applied_waiver_refs=result.applied_waiver_refs,
        )

    monkeypatch.setattr(belgi_cli, "orchestrate_chain_run", _patched_orchestrate_chain_run)

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc_run == 10
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert machine.get("findings_present") is True
    assert isinstance(machine.get("finding_count"), int) and int(machine["finding_count"]) > 0
    assert "adversarial findings signal mismatch with policy.adversarial_scan" in str(machine.get("primary_reason"))


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


def test_tier1_adopter_pytest_missing_target_skips_and_reaches_r8(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _remove_tests_tree_and_commit(repo)

    monkeypatch.setattr(
        run_orchestrator,
        "_tier_test_plan_for_tier",
        lambda **_: run_orchestrator.TierTestPlan(
            mode="adopter_pytest",
            test_path="tests/does_not_exist.py",
        ),
    )

    _, attempt_dir = _run_tier1_and_get_attempt(repo, capsys)

    test_report_path = attempt_dir / "repo" / "out" / "artifacts" / "tests.report.json"
    report = json.loads(test_report_path.read_text(encoding="utf-8", errors="strict"))
    assert report.get("mode") == "adopter_pytest"
    assert report.get("status") == "skipped_missing_target"
    assert report.get("exit_code") == 0

    verify_report = json.loads((attempt_dir / "repo" / "out" / "verify_report.R.json").read_text(encoding="utf-8", errors="strict"))
    results = verify_report.get("results")
    assert isinstance(results, list)
    assert any(isinstance(entry, dict) and entry.get("check_id") == "R8" for entry in results)


def test_tier1_adopter_pytest_existing_target_passes_and_records_report_fields(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(
        repo,
        "tests/test_adopter_target_smoke.py",
        "def test_adopter_target_smoke() -> None:\n    assert 1 == 1\n",
        "add adopter pytest target",
    )

    monkeypatch.setattr(
        run_orchestrator,
        "_tier_test_plan_for_tier",
        lambda **_: run_orchestrator.TierTestPlan(
            mode="adopter_pytest",
            test_path="tests/test_adopter_target_smoke.py",
        ),
    )

    _, attempt_dir = _run_tier1_and_get_attempt(repo, capsys)

    test_report_path = attempt_dir / "repo" / "out" / "artifacts" / "tests.report.json"
    report = json.loads(test_report_path.read_text(encoding="utf-8", errors="strict"))
    assert report.get("mode") == "adopter_pytest"
    assert report.get("status") == "pass"
    assert isinstance(report.get("exit_code"), int)


def test_tier1_passes_with_valid_applied_waiver(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "src/risky_exec.py", "exec('1')\n", "add risky primitive")

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    _write_applied_waiver(
        repo,
        file_name="r8_exec.json",
        rule_id="ADV-EXEC-001",
        scope_path="src/risky_exec.py",
        expires_at="2100-01-01T00:00:00Z",
    )

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-1", "--base-revision", head_sha])
    assert rc_run == 0
    captured = capsys.readouterr()

    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is True
    assert machine["verdict"] == "GO"
    assert machine["waivers_applied_count"] == 1
    assert machine["waivers_applied_refs"] == ["out/inputs/waivers_applied/r8_exec.json"]

    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "runs" / run_key / attempt_id

    summary_obj = json.loads((attempt_dir / "run.summary.json").read_text(encoding="utf-8", errors="strict"))
    waivers_summary = summary_obj.get("waivers_applied")
    assert waivers_summary == {"count": 1, "storage_refs": ["out/inputs/waivers_applied/r8_exec.json"]}

    locked_spec = json.loads((attempt_dir / "repo" / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict"))
    assert locked_spec.get("waivers_applied") == ["out/inputs/waivers_applied/r8_exec.json"]

    gate_r = json.loads((attempt_dir / "repo" / "out" / "GateVerdict.R.json").read_text(encoding="utf-8", errors="strict"))
    assert gate_r.get("verdict") == "GO"


@pytest.mark.parametrize(
    ("scope_path", "expires_at", "expected_reason"),
    [
        ("src/risky_exec.py", "1960-01-01T00:00:00Z", "expires_at is not after evaluated_at"),
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

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    _write_applied_waiver(
        repo,
        file_name="r8_invalid.json",
        rule_id="ADV-EXEC-001",
        scope_path=scope_path,
        expires_at=expires_at,
    )

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-1", "--base-revision", head_sha])
    assert rc_run == 10
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert "chain.gate_" in str(machine["primary_reason"])
    assert "NO-GO:" in str(machine["primary_reason"])
    assert expected_reason in str(machine["primary_reason"])


def test_run_summary_exists_on_run_tests_failure(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _fresh_repo_clone(tmp_path)

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    original_run_tools = run_orchestrator._run_tools_belgi

    def _patched_run_tools(repo_root: Path, argv: list[str], *, allowed: tuple[int, ...] = (0,)) -> int:
        if argv and argv[0] == "run-tests":
            raise ValueError(
                "tools.belgi_tools run-tests --run-id run-test-001 --out out/artifacts/tests.report.json --deterministic returned rc=1"
            )
        return original_run_tools(repo_root, argv, allowed=allowed)

    monkeypatch.setattr(run_orchestrator, "_run_tools_belgi", _patched_run_tools)

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-1", "--base-revision", head_sha])
    assert rc_run == 10
    captured_run = capsys.readouterr()
    machine_run = json.loads(captured_run.out.splitlines()[0])
    run_key = str(machine_run["run_key"])
    attempt_id = str(machine_run["attempt_id"])
    assert "run-tests" in str(machine_run["primary_reason"])
    assert "rc=1" in str(machine_run["primary_reason"])

    summary_path = repo / ".belgi" / "runs" / run_key / attempt_id / "run.summary.json"
    assert summary_path.is_file()
    summary = json.loads(summary_path.read_text(encoding="utf-8", errors="strict"))
    assert summary.get("verdict") == "NO-GO"
    assert "run-tests" in str(summary.get("primary_reason"))
    assert "rc=1" in str(summary.get("primary_reason"))

    rc_verify = belgi_main(["verify", "--repo", str(repo)])
    assert rc_verify == 10
    captured_verify = capsys.readouterr()
    machine_verify = json.loads(captured_verify.out.splitlines()[0])
    verify_reason = str(machine_verify.get("primary_reason") or "")
    assert "run-tests" in verify_reason
    assert "rc=1" in verify_reason
    assert "missing run summary" not in verify_reason
