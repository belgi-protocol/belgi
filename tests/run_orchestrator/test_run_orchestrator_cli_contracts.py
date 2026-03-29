from __future__ import annotations

import base64
import importlib
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


def _capture_seal_signature_for_precomputed_replay(
    *,
    cli_surface: BelgiCliSurface,
    source_repo_root: Path,
    attempt_dir: Path,
    final_commit_sha: str,
    seal_signature_path: Path,
    seal_private_key_ref: str,
) -> str:
    # Generate the precomputed signature from the exact failed-at-seal attempt payload,
    # rather than harvesting a signature from a different belgi run entry path.
    run_orchestrator = cli_surface.run_orchestrator
    seal_bundle = importlib.import_module("chain.seal_bundle")
    chain_repo_dir = attempt_dir / "repo"
    locked_spec = json.loads((chain_repo_dir / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict"))
    run_id = str(locked_spec.get("run_id") or "").strip()
    belgi_version = str(locked_spec.get("belgi_version") or "").strip()
    assert run_id
    assert belgi_version
    tier_obj = locked_spec.get("tier")
    assert isinstance(tier_obj, dict)
    assert str(tier_obj.get("tier_id") or "").strip() in {"tier-2", "tier-3"}
    waiver_refs = locked_spec.get("waivers_applied")
    assert waiver_refs is None or isinstance(waiver_refs, list)

    seal_private_key = run_orchestrator._read_local_secret_text_ref(
        source_repo_root=source_repo_root,
        source_ref=seal_private_key_ref,
        label="seal private key ref",
    )
    locked_spec_path = chain_repo_dir / "out" / "LockedSpec.json"
    gate_q_path = chain_repo_dir / "out" / "GateVerdict.Q.json"
    gate_r_path = chain_repo_dir / "out" / "GateVerdict.R.json"
    evidence_path = chain_repo_dir / "out" / "EvidenceManifest.json"
    locked_ref = seal_bundle._object_ref_for_json(
        chain_repo_dir,
        locked_spec_path,
        default_id=f"lockedspec-{run_id}",
        id_key=None,
    )
    q_ref = seal_bundle._object_ref_for_json(
        chain_repo_dir,
        gate_q_path,
        default_id=f"gate-Q-{run_id}",
        id_key=None,
    )
    r_ref = seal_bundle._object_ref_for_json(
        chain_repo_dir,
        gate_r_path,
        default_id=f"gate-R-{run_id}",
        id_key=None,
    )
    evidence_ref = seal_bundle._object_ref_for_json(
        chain_repo_dir,
        evidence_path,
        default_id=f"evidence-manifest-{run_id}",
        id_key=None,
    )

    sealed_waiver_refs: list[dict[str, str]] = []
    if isinstance(waiver_refs, list):
        for waiver_ref in waiver_refs:
            if not isinstance(waiver_ref, str) or not waiver_ref.strip():
                continue
            waiver_path = seal_bundle.resolve_repo_rel_path(
                chain_repo_dir,
                waiver_ref.strip(),
                must_exist=True,
                must_be_file=True,
                allow_backslashes=True,
                forbid_symlinks=True,
            )
            waiver_doc = seal_bundle._load_json(waiver_path)
            waiver_id = waiver_doc.get("waiver_id") if isinstance(waiver_doc, dict) else None
            sealed_waiver_refs.append(
                seal_bundle._object_ref_for_json(
                    chain_repo_dir,
                    waiver_path,
                    default_id=waiver_id or f"waiver-{waiver_path.stem}",
                    id_key=None,
                )
            )

    manifest_items: list[tuple[str, object]] = [
        ("belgi_version", belgi_version),
        ("evidence_manifest_ref", evidence_ref),
        ("final_commit_sha", final_commit_sha),
        ("gate_q_verdict_ref", q_ref),
        ("gate_r_verdict_ref", r_ref),
        ("locked_spec_ref", locked_ref),
        ("run_id", run_id),
        ("schema_version", "1.0.0"),
        ("seal_hash", "0" * 64),
        ("sealed_at", run_orchestrator.FIXED_SEALED_AT),
        ("signer", run_orchestrator.FIXED_SIGNER),
        ("waivers", sealed_waiver_refs),
    ]
    manifest = dict(manifest_items)
    manifest["seal_hash"] = seal_bundle._seal_hash(manifest)
    payload_bytes = seal_bundle._seal_signature_payload(manifest)

    env = locked_spec.get("environment_envelope")
    assert isinstance(env, dict)
    seal_pubkey_ref = env.get("seal_pubkey_ref")
    assert isinstance(seal_pubkey_ref, dict)
    pub_bytes = seal_bundle._resolve_objectref_bytes(
        chain_repo_dir,
        seal_pubkey_ref,
        field="LockedSpec.environment_envelope.seal_pubkey_ref",
    )
    pub = seal_bundle._load_ed25519_public_key(pub_bytes)
    priv = seal_bundle._load_ed25519_private_key(seal_private_key.encode("utf-8", errors="strict"))
    sig_bytes = priv.sign(payload_bytes)
    seal_bundle._verify_ed25519_signature(pub, sig_bytes, payload_bytes, context="precomputed seal replay")
    signature = base64.b64encode(sig_bytes).decode("ascii")
    seal_signature_path.write_text(signature + "\n", encoding="utf-8", errors="strict", newline="\n")
    return signature


def _run_with_settled_precomputed_seal_signature(
    *,
    belgi_main: object,
    capsys: object,
    cli_surface: BelgiCliSurface,
    source_repo_root: Path,
    signature_argv: list[str],
    final_commit_sha: str,
    seal_signature_path: Path,
    seal_private_key_ref: str,
) -> tuple[str, dict[str, object], Path]:
    rc_initial = belgi_main(signature_argv)
    assert rc_initial == 10
    failed_run = json.loads(capsys.readouterr().out.splitlines()[0])

    settled_signature = ""
    for _ in range(2):
        failed_attempt_dir = (
            source_repo_root
            / ".belgi"
            / "store"
            / "runs"
            / str(failed_run["run_key"])
            / str(failed_run["attempt_id"])
        )
        settled_signature = _capture_seal_signature_for_precomputed_replay(
            cli_surface=cli_surface,
            source_repo_root=source_repo_root,
            attempt_dir=failed_attempt_dir,
            final_commit_sha=final_commit_sha,
            seal_signature_path=seal_signature_path,
            seal_private_key_ref=seal_private_key_ref,
        )

        rc_retry = belgi_main(signature_argv)
        retry_machine = json.loads(capsys.readouterr().out.splitlines()[0])
        if rc_retry == 0:
            final_attempt_dir = (
                source_repo_root
                / ".belgi"
                / "store"
                / "runs"
                / str(retry_machine["run_key"])
                / str(retry_machine["attempt_id"])
            )
            return settled_signature, retry_machine, final_attempt_dir

        assert rc_retry == 10
        failed_run = retry_machine

    pytest.fail(
        "precomputed seal replay did not settle after retrying the latest failed-at-seal payload: "
        f"{failed_run.get('primary_reason')}"
    )


def test_run_orchestrator_harness_alias_bundle_matches_helper_surface() -> None:
    alias_bundle = {
        "_assert_no_persisted_signing_material": _assert_no_persisted_signing_material,
        "_commit_file": _commit_file,
        "_fresh_repo_clone": _fresh_repo_clone,
        "_git_rev_parse": _git_rev_parse,
        "_pin_shared_path_anchor_time": _pin_shared_path_anchor_time,
        "_prepare_shared_run_intent": _prepare_shared_run_intent,
        "_rewrite_shared_run_intent_for_empty_doc_impact": _rewrite_shared_run_intent_for_empty_doc_impact,
        "_remove_tests_tree_and_commit": _remove_tests_tree_and_commit,
        "_run_tier1_and_get_attempt": _run_tier1_and_get_attempt,
        "_unset_upstream_if_present": _unset_upstream_if_present,
        "_write_operator_anchors": _write_operator_anchors,
        "_write_run_evidence_inputs": _write_run_evidence_inputs,
    }

    for name, aliased in alias_bundle.items():
        assert aliased is getattr(harness, name)


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
    seal_signature_path = repo / Path(*operator_anchors["seal_signature_ref"].split("/"))
    seal_signature_path.write_text("AAAA\n", encoding="utf-8", errors="strict", newline="\n")
    signature_argv = [
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
    settled_signature, second_run, second_attempt_dir = _run_with_settled_precomputed_seal_signature(
        belgi_main=belgi_main,
        capsys=capsys,
        cli_surface=fresh_cli_surface,
        source_repo_root=repo,
        signature_argv=signature_argv,
        final_commit_sha=head_sha,
        seal_signature_path=seal_signature_path,
        seal_private_key_ref=operator_anchors["seal_private_key_ref"],
    )
    assert second_attempt_dir.is_dir()

    second_out_dir = second_attempt_dir / "repo" / "out"
    _assert_no_persisted_signing_material(second_out_dir)

    second_seal_manifest = json.loads(
        (second_out_dir / "SealManifest.json").read_text(encoding="utf-8", errors="strict")
    )
    assert second_seal_manifest.get("signature_alg") == "ed25519"
    assert second_seal_manifest.get("signature") == settled_signature

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
    seal_signature_path = repo / Path(*operator_anchors["seal_signature_ref"].split("/"))
    seal_signature_path.write_text("AAAA\n", encoding="utf-8", errors="strict", newline="\n")
    signature_argv = [
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
    settled_signature, second_run, second_attempt_dir = _run_with_settled_precomputed_seal_signature(
        belgi_main=belgi_main,
        capsys=capsys,
        cli_surface=fresh_cli_surface,
        source_repo_root=repo,
        signature_argv=signature_argv,
        final_commit_sha=head_sha,
        seal_signature_path=seal_signature_path,
        seal_private_key_ref=operator_anchors["seal_private_key_ref"],
    )
    second_out_dir = second_attempt_dir / "repo" / "out"
    _assert_no_persisted_signing_material(second_out_dir)
    second_seal_manifest = json.loads((second_out_dir / "SealManifest.json").read_text(encoding="utf-8", errors="strict"))
    assert second_seal_manifest.get("signature_alg") == "ed25519"
    assert second_seal_manifest.get("signature") == settled_signature

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

    original_invoke_subprocess = run_orchestrator._invoke_module_subprocess

    def _patched_invoke_module_subprocess(
        module_name: str,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
    ) -> int:
        if module_name == "tools.belgi_tools" and argv and argv[0] == "run-tests":
            return 1
        return original_invoke_subprocess(module_name, argv, env=env)

    monkeypatch.setattr(run_orchestrator, "_invoke_module_subprocess", _patched_invoke_module_subprocess)

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
