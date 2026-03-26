from __future__ import annotations

import json
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


_assert_no_persisted_signing_material = harness._assert_no_persisted_signing_material
_commit_file = harness._commit_file
_fresh_repo_clone = harness._fresh_repo_clone
_git_rev_parse = harness._git_rev_parse
_pin_shared_path_anchor_time = harness._pin_shared_path_anchor_time
_prepare_shared_run_intent = harness._prepare_shared_run_intent
_rewrite_shared_run_intent_for_empty_doc_impact = harness._rewrite_shared_run_intent_for_empty_doc_impact
_remove_tests_tree_and_commit = harness._remove_tests_tree_and_commit
_run_tier1_and_get_attempt = harness._run_tier1_and_get_attempt
_unset_upstream_if_present = harness._unset_upstream_if_present
_write_operator_anchors = harness._write_operator_anchors
_write_run_evidence_inputs = harness._write_run_evidence_inputs


def test_run_tier2_shared_path_accepts_precomputed_seal_signature_and_verify_passes(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    belgi_main = fresh_cli_surface.main
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-tier2-signature"
    _pin_shared_path_anchor_time(monkeypatch, cli_surface=fresh_cli_surface)

    assert belgi_main(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    assert belgi_main(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic shared-path test run.",
    )
    operator_anchors = _write_operator_anchors(repo, run_id=run_id)

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run_private_key = belgi_main(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-2",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            head_sha,
            "--attestation-pubkey-ref",
            operator_anchors["attestation_pubkey_ref"],
            "--seal-pubkey-ref",
            operator_anchors["seal_pubkey_ref"],
            "--hotl-approval-ref",
            operator_anchors["hotl_approval_ref"],
            "--attestation-signing-key-ref",
            operator_anchors["attestation_signing_key_ref"],
            "--seal-private-key-ref",
            operator_anchors["seal_private_key_ref"],
        ]
    )
    assert rc_run_private_key == 0
    first_run = json.loads(capsys.readouterr().out.splitlines()[0])
    first_attempt_dir = (
        repo / ".belgi" / "store" / "runs" / str(first_run["run_key"]) / str(first_run["attempt_id"])
    )
    first_seal_manifest = json.loads(
        (first_attempt_dir / "repo" / "out" / "SealManifest.json").read_text(encoding="utf-8", errors="strict")
    )
    first_signature = str(first_seal_manifest.get("signature") or "").strip()
    assert first_signature

    seal_signature_path = repo / Path(*operator_anchors["seal_signature_ref"].split("/"))
    seal_signature_path.write_text(first_signature + "\n", encoding="utf-8", errors="strict", newline="\n")

    rc_run_signature = belgi_main(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-2",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            head_sha,
            "--attestation-pubkey-ref",
            operator_anchors["attestation_pubkey_ref"],
            "--seal-pubkey-ref",
            operator_anchors["seal_pubkey_ref"],
            "--hotl-approval-ref",
            operator_anchors["hotl_approval_ref"],
            "--attestation-signing-key-ref",
            operator_anchors["attestation_signing_key_ref"],
            "--seal-signature-ref",
            operator_anchors["seal_signature_ref"],
        ]
    )
    assert rc_run_signature == 0
    second_run = json.loads(capsys.readouterr().out.splitlines()[0])
    second_attempt_dir = (
        repo / ".belgi" / "store" / "runs" / str(second_run["run_key"]) / str(second_run["attempt_id"])
    )
    assert second_attempt_dir.is_dir()

    second_out_dir = second_attempt_dir / "repo" / "out"
    _assert_no_persisted_signing_material(second_out_dir)

    second_seal_manifest = json.loads(
        (second_out_dir / "SealManifest.json").read_text(encoding="utf-8", errors="strict")
    )
    assert second_seal_manifest.get("signature_alg") == "ed25519"
    assert second_seal_manifest.get("signature") == first_signature

    rc_verify = belgi_main(["verify", "--repo", str(repo)])
    assert rc_verify == 0
    machine_verify = json.loads(capsys.readouterr().out.splitlines()[0])
    assert machine_verify["ok"] is True
    assert machine_verify["verdict"] == "GO"
    assert machine_verify["run_key"] == second_run["run_key"]
    assert machine_verify["attempt_id"] == second_run["attempt_id"]


def test_run_tier3_shared_path_accepts_precomputed_seal_signature_and_verify_passes(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    belgi_main = fresh_cli_surface.main
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-tier3-signature"
    _pin_shared_path_anchor_time(monkeypatch, cli_surface=fresh_cli_surface)

    assert belgi_main(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    assert belgi_main(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic shared-path test run.",
        tier_id="tier-3",
    )
    operator_anchors = _write_operator_anchors(repo, run_id=run_id)
    run_evidence = _write_run_evidence_inputs(repo, run_id=run_id)

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run_private_key = belgi_main(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-3",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            head_sha,
            "--attestation-pubkey-ref",
            operator_anchors["attestation_pubkey_ref"],
            "--seal-pubkey-ref",
            operator_anchors["seal_pubkey_ref"],
            "--hotl-approval-ref",
            operator_anchors["hotl_approval_ref"],
            "--attestation-signing-key-ref",
            operator_anchors["attestation_signing_key_ref"],
            "--seal-private-key-ref",
            operator_anchors["seal_private_key_ref"],
            "--genesis-seal-ref",
            run_evidence["genesis_seal_ref"],
        ]
    )
    assert rc_run_private_key == 0
    first_run = json.loads(capsys.readouterr().out.splitlines()[0])
    first_attempt_dir = repo / ".belgi" / "store" / "runs" / str(first_run["run_key"]) / str(first_run["attempt_id"])
    first_signature = str(
        json.loads((first_attempt_dir / "repo" / "out" / "SealManifest.json").read_text(encoding="utf-8", errors="strict")).get("signature") or ""
    ).strip()
    assert first_signature

    seal_signature_path = repo / Path(*operator_anchors["seal_signature_ref"].split("/"))
    seal_signature_path.write_text(first_signature + "\n", encoding="utf-8", errors="strict", newline="\n")

    rc_run_signature = belgi_main(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-3",
            "--intent-spec",
            intent_path.relative_to(repo).as_posix(),
            "--base-revision",
            head_sha,
            "--attestation-pubkey-ref",
            operator_anchors["attestation_pubkey_ref"],
            "--seal-pubkey-ref",
            operator_anchors["seal_pubkey_ref"],
            "--hotl-approval-ref",
            operator_anchors["hotl_approval_ref"],
            "--attestation-signing-key-ref",
            operator_anchors["attestation_signing_key_ref"],
            "--seal-signature-ref",
            operator_anchors["seal_signature_ref"],
            "--genesis-seal-ref",
            run_evidence["genesis_seal_ref"],
        ]
    )
    assert rc_run_signature == 0
    second_run = json.loads(capsys.readouterr().out.splitlines()[0])
    second_attempt_dir = repo / ".belgi" / "store" / "runs" / str(second_run["run_key"]) / str(second_run["attempt_id"])
    second_out_dir = second_attempt_dir / "repo" / "out"
    _assert_no_persisted_signing_material(second_out_dir)
    second_seal_manifest = json.loads((second_out_dir / "SealManifest.json").read_text(encoding="utf-8", errors="strict"))
    assert second_seal_manifest.get("signature_alg") == "ed25519"
    assert second_seal_manifest.get("signature") == first_signature

    rc_verify = belgi_main(["verify", "--repo", str(repo)])
    assert rc_verify == 0
    machine_verify = json.loads(capsys.readouterr().out.splitlines()[0])
    assert machine_verify["ok"] is True
    assert machine_verify["verdict"] == "GO"
    assert machine_verify["run_key"] == second_run["run_key"]
    assert machine_verify["attempt_id"] == second_run["attempt_id"]


def test_tier0_fails_closed_if_policy_scan_exists_but_signal_missing(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    belgi_cli = fresh_cli_surface.cli
    belgi_main = fresh_cli_surface.main
    run_orchestrator = fresh_cli_surface.run_orchestrator
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "src/risky_exec.py", "exec('1')\n", "add risky primitive")

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()
    intent_path = _prepare_shared_run_intent(
        repo,
        capsys=capsys,
        run_id="run-tier0-signal-mismatch-001",
        tier_id="tier-0",
        cli_surface=fresh_cli_surface,
    )

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
    base_sha = _git_rev_parse(repo, "HEAD~1")
    rc_run = belgi_main(
        [
            "run",
            "--repo",
            str(repo),
            "--tier",
            "tier-0",
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
    assert machine.get("findings_present") is True
    assert isinstance(machine.get("finding_count"), int) and int(machine["finding_count"]) > 0
    assert "adversarial findings signal mismatch with policy.adversarial_scan" in str(machine.get("primary_reason"))


def test_tier1_adopter_pytest_missing_target_skips_and_reaches_r8(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
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

    _, attempt_dir = _run_tier1_and_get_attempt(repo, capsys, cli_surface=fresh_cli_surface)

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
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
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

    _, attempt_dir = _run_tier1_and_get_attempt(repo, capsys, cli_surface=fresh_cli_surface)

    test_report_path = attempt_dir / "repo" / "out" / "artifacts" / "tests.report.json"
    report = json.loads(test_report_path.read_text(encoding="utf-8", errors="strict"))
    assert report.get("mode") == "adopter_pytest"
    assert report.get("status") == "pass"
    assert isinstance(report.get("exit_code"), int)


def test_run_summary_exists_on_run_tests_failure(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    belgi_main = fresh_cli_surface.main
    run_orchestrator = fresh_cli_surface.run_orchestrator
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

    summary_path = repo / ".belgi" / "store" / "runs" / run_key / attempt_id / "run.summary.json"
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
