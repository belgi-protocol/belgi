from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from tests.helpers import subprocess_cli as cli_subprocess
from tests.helpers.tier_fixtures import prompt_block_ids_for_tier_policy

run_belgi = cli_subprocess.run_belgi
validate_schema = cli_subprocess.validate_schema
get_builtin_protocol_context = cli_subprocess.get_builtin_protocol_context
_commit_file = cli_subprocess._commit_file
_fresh_repo_clone = cli_subprocess._fresh_repo_clone
_git_rev_parse = cli_subprocess._git_rev_parse
_list_dirs = cli_subprocess._list_dirs
_rewrite_shared_run_intent_for_empty_doc_impact = cli_subprocess._rewrite_shared_run_intent_for_empty_doc_impact
_run_git = cli_subprocess._run_git
_unset_upstream_if_present = cli_subprocess._unset_upstream_if_present
_write_operator_anchors = cli_subprocess._write_operator_anchors
_write_run_evidence_inputs = cli_subprocess._write_run_evidence_inputs
_assert_no_persisted_signing_material = cli_subprocess._assert_no_persisted_signing_material


def test_run_tier_uses_stable_run_key_and_unique_attempt_id(tmp_path: Path) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0

    rc1 = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc1 == 0

    runs_root = repo / ".belgi" / "store" / "runs"
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
    assert "toolchain_refs" not in summary1["run_key_preimage"]["normalized_inputs"]
    assert "tolerances_ref" not in summary1["run_key_preimage"]["normalized_inputs"]
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
    locked_first = json.loads(
        (first_attempt / "repo" / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict")
    )
    tier_obj = locked_first.get("tier")
    assert isinstance(tier_obj, dict)
    tier_id = tier_obj.get("tier_id")
    assert isinstance(tier_id, str) and tier_id
    expected_selected = set(prompt_block_ids_for_tier_policy(tier_id))
    assert set(prompt_hashes.keys()) == expected_selected

    rc_verify_1 = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify_1 == 0

    rc2 = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc2 == 0

    run_dirs_after_second = _list_dirs(runs_root)
    assert [p.name for p in run_dirs_after_second] == [run_key_dir.name]
    attempts_after_second = _list_dirs(run_key_dir)
    assert [p.name for p in attempts_after_second] == ["attempt-0001", "attempt-0002"]

    summary2 = json.loads((attempts_after_second[1] / "run.summary.json").read_text(encoding="utf-8", errors="strict"))
    assert summary2["run_key"] == run_key_dir.name
    assert summary2["attempt_id"] == "attempt-0002"

    rc_verify_2 = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify_2 == 0


def test_run_tier2_rejects_missing_required_operator_inputs(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(["run", "--repo", str(repo), "--tier", "tier-2", "--base-revision", head_sha])
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])

    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    reason = str(machine["primary_reason"])
    assert "--attestation-pubkey-ref" in reason
    assert "--seal-pubkey-ref" in reason
    assert "--hotl-approval-ref" in reason
    assert "--attestation-signing-key-ref" in reason
    assert "--seal-private-key-ref or --seal-signature-ref" in reason


def test_run_tier2_shared_path_accepts_valid_inputs_and_verify_passes(
    tmp_path: Path, capsys: object
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-tier2-shared"

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_new = run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id])
    assert rc_new == 0
    _ = capsys.readouterr()

    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic shared-path test run.",
    )
    operator_anchors = _write_operator_anchors(repo, run_id=run_id)

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = run_belgi(
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
    assert rc_run == 0
    captured_run = capsys.readouterr()

    machine_run = json.loads(captured_run.out.splitlines()[0])
    assert machine_run["ok"] is True
    assert machine_run["verdict"] == "GO"
    run_key = str(machine_run["run_key"])
    attempt_id = str(machine_run["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id
    assert attempt_dir.is_dir()

    locked_spec = json.loads((attempt_dir / "repo" / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict"))
    envelope = locked_spec.get("environment_envelope")
    assert isinstance(envelope, dict)
    attestation_pubkey_ref = envelope.get("attestation_pubkey_ref")
    seal_pubkey_ref = envelope.get("seal_pubkey_ref")
    assert isinstance(attestation_pubkey_ref, dict)
    assert isinstance(seal_pubkey_ref, dict)
    assert attestation_pubkey_ref.get("id") == "env.attestation_pubkey"
    assert seal_pubkey_ref.get("id") == "env.seal_pubkey"
    assert str(attestation_pubkey_ref.get("storage_ref") or "").startswith("out/inputs/anchors/keys/")
    assert str(seal_pubkey_ref.get("storage_ref") or "").startswith("out/inputs/anchors/keys/")

    evidence_manifest = json.loads((attempt_dir / "repo" / "out" / "EvidenceManifest.json").read_text(encoding="utf-8", errors="strict"))
    artifacts = evidence_manifest.get("artifacts")
    assert isinstance(artifacts, list)
    kinds = {artifact.get("kind") for artifact in artifacts if isinstance(artifact, dict)}
    assert "hotl_approval" in kinds
    assert "test_report" in kinds
    assert "env_attestation" in kinds
    out_dir = attempt_dir / "repo" / "out"
    _assert_no_persisted_signing_material(out_dir)

    hotl_artifacts = [artifact for artifact in artifacts if isinstance(artifact, dict) and artifact.get("kind") == "hotl_approval"]
    assert len(hotl_artifacts) == 1
    assert hotl_artifacts[0].get("storage_ref") == "out/inputs/anchors/approvals/hotl_approval.json"
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        storage_ref = str(artifact.get("storage_ref") or "")
        assert "attestation_signing_key" not in storage_ref
        assert "seal_private_key" not in storage_ref

    seal_manifest = json.loads((attempt_dir / "repo" / "out" / "SealManifest.json").read_text(encoding="utf-8", errors="strict"))
    assert seal_manifest.get("signature_alg") == "ed25519"
    assert isinstance(seal_manifest.get("signature"), str) and bool(str(seal_manifest["signature"]).strip())
    seal_manifest_text = json.dumps(seal_manifest, sort_keys=True)
    assert "attestation_signing_key" not in seal_manifest_text
    assert "seal_private_key" not in seal_manifest_text

    rc_verify = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify == 0
    captured_verify = capsys.readouterr()
    machine_verify = json.loads(captured_verify.out.splitlines()[0])
    assert machine_verify["ok"] is True
    assert machine_verify["verdict"] == "GO"


def test_run_tier3_rejects_missing_required_operator_and_evidence_inputs(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(["run", "--repo", str(repo), "--tier", "tier-3", "--base-revision", head_sha])
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])

    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    reason = str(machine["primary_reason"])
    anchor_reason, sep, evidence_reason = reason.partition("; ")
    assert sep == "; "
    assert anchor_reason.startswith("tier-3 requires Operator Anchors: ")
    assert "--attestation-pubkey-ref" in anchor_reason
    assert "--seal-pubkey-ref" in anchor_reason
    assert "--hotl-approval-ref" in anchor_reason
    assert "--attestation-signing-key-ref" in anchor_reason
    assert "--seal-private-key-ref or --seal-signature-ref" in anchor_reason
    assert "--genesis-seal-ref" not in anchor_reason
    assert evidence_reason == "tier-3 requires Tier-3 evidence input: --genesis-seal-ref"
    assert reason in captured.err


def test_run_tier3_rejects_missing_required_operator_anchors_with_correct_boundary(
    tmp_path: Path, capsys: object
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-tier3-missing-anchors"

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic shared-path test run.",
        tier_id="tier-3",
    )
    run_evidence = _write_run_evidence_inputs(repo, run_id=run_id)

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = run_belgi(
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
            "--genesis-seal-ref",
            run_evidence["genesis_seal_ref"],
        ]
    )
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    reason = str(machine["primary_reason"])
    assert reason.startswith("tier-3 requires Operator Anchors: ")
    assert "Tier-3 evidence input" not in reason
    assert "--genesis-seal-ref" not in reason
    assert reason in captured.err


def test_run_tier3_rejects_missing_genesis_evidence_input_with_correct_boundary(
    tmp_path: Path, capsys: object
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-tier3-missing-genesis"

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic shared-path test run.",
        tier_id="tier-3",
    )
    operator_anchors = _write_operator_anchors(repo, run_id=run_id)

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = run_belgi(
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
        ]
    )
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    reason = str(machine["primary_reason"])
    assert reason == "tier-3 requires Tier-3 evidence input: --genesis-seal-ref"
    assert "Operator Anchors" not in reason
    assert reason in captured.err


def test_run_tier3_rejects_schema_invalid_genesis_seal_input(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-tier3-invalid-genesis"

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic shared-path test run.",
        tier_id="tier-3",
    )
    operator_anchors = _write_operator_anchors(repo, run_id=run_id)
    run_evidence = _write_run_evidence_inputs(repo, run_id=run_id)
    genesis_path = repo / ".belgi" / "runs" / run_id / "inputs" / "evidence" / "genesis_seal.json"
    genesis_path.write_text("{}\n", encoding="utf-8", errors="strict", newline="\n")

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = run_belgi(
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
    assert rc_run == 20
    machine = json.loads(capsys.readouterr().out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert "--genesis-seal-ref invalid" in str(machine["primary_reason"])


def test_run_tier3_rejects_invalid_hotl_input(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-tier3-invalid-hotl"

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic shared-path test run.",
        tier_id="tier-3",
    )
    operator_anchors = _write_operator_anchors(repo, run_id=run_id)
    run_evidence = _write_run_evidence_inputs(repo, run_id=run_id)
    hotl_path = repo / ".belgi" / "runs" / run_id / "inputs" / "anchors" / "approvals" / "hotl_approval.json"
    hotl_path.write_text("{}\n", encoding="utf-8", errors="strict", newline="\n")

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = run_belgi(
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
    assert rc_run == 20
    machine = json.loads(capsys.readouterr().out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"
    assert "--hotl-approval-ref invalid" in str(machine["primary_reason"])


def test_run_tier3_shared_path_accepts_valid_inputs_and_verify_passes(
    tmp_path: Path, capsys: object
) -> None:
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-tier3-shared"

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
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
    rc_run = run_belgi(
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
    assert rc_run == 0
    captured_run = capsys.readouterr()
    machine_run = json.loads(captured_run.out.splitlines()[0])
    assert machine_run["ok"] is True
    assert machine_run["verdict"] == "GO"
    assert machine_run["tier_id"] == "tier-3"

    run_key = str(machine_run["run_key"])
    attempt_id = str(machine_run["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id
    assert attempt_dir.is_dir()

    locked_spec = json.loads((attempt_dir / "repo" / "out" / "LockedSpec.json").read_text(encoding="utf-8", errors="strict"))
    envelope = locked_spec.get("environment_envelope")
    assert isinstance(envelope, dict)
    assert str((envelope.get("attestation_pubkey_ref") or {}).get("storage_ref") or "").startswith("out/inputs/anchors/keys/")
    assert str((envelope.get("seal_pubkey_ref") or {}).get("storage_ref") or "").startswith("out/inputs/anchors/keys/")

    out_dir = attempt_dir / "repo" / "out"
    evidence_manifest = json.loads((out_dir / "EvidenceManifest.json").read_text(encoding="utf-8", errors="strict"))
    artifacts = evidence_manifest.get("artifacts")
    assert isinstance(artifacts, list)
    kinds = {artifact.get("kind") for artifact in artifacts if isinstance(artifact, dict)}
    assert {"hotl_approval", "test_report", "env_attestation", "genesis_seal"}.issubset(kinds)
    genesis_artifacts = [artifact for artifact in artifacts if isinstance(artifact, dict) and artifact.get("kind") == "genesis_seal"]
    assert len(genesis_artifacts) == 1
    assert genesis_artifacts[0].get("storage_ref") == "out/inputs/evidence/genesis_seal.json"
    _assert_no_persisted_signing_material(out_dir)

    rc_verify = run_belgi(["verify", "--repo", str(repo)])
    assert rc_verify == 0
    machine_verify = json.loads(capsys.readouterr().out.splitlines()[0])
    assert machine_verify["ok"] is True
    assert machine_verify["verdict"] == "GO"
    assert machine_verify["run_key"] == machine_run["run_key"]
    assert machine_verify["attempt_id"] == machine_run["attempt_id"]


def test_run_tier3_fails_closed_when_canonical_trust_anchor_drifts(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    run_id = "run-tier3-anchor-drift"

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    intent_path = _rewrite_shared_run_intent_for_empty_doc_impact(
        repo,
        run_id=run_id,
        note="No documentation updates are required for this deterministic shared-path test run.",
        tier_id="tier-3",
    )
    operator_anchors = _write_operator_anchors(repo, run_id=run_id)
    run_evidence = _write_run_evidence_inputs(repo, run_id=run_id)

    trust_anchor_path = repo / "belgi" / "anchor" / "v1" / "TrustAnchor.json"
    anchor_text = trust_anchor_path.read_text(encoding="utf-8", errors="strict")
    drifted_text = anchor_text.replace('"dedication": "Bilge (8)"', '"dedication": "Drifted dedication"')
    assert drifted_text != anchor_text
    trust_anchor_path.write_text(drifted_text, encoding="utf-8", errors="strict", newline="\n")
    _run_git(repo, ["add", "belgi/anchor/v1/TrustAnchor.json"])
    _run_git(repo, ["commit", "-m", "drift trust anchor"])

    _unset_upstream_if_present(repo)
    head_sha = _git_rev_parse(repo, "HEAD")
    rc_run = run_belgi(
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
    assert rc_run == 10
    machine = json.loads(capsys.readouterr().out.splitlines()[0])
    assert machine["ok"] is False
    assert machine["verdict"] == "NO-GO"


def test_init_custom_workspace_updates_gitignore_and_run_path(tmp_path: Path) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    rc_init = run_belgi(["init", "--repo", str(repo), "--workspace", ".belgi_alt"])
    assert rc_init == 0

    gitignore = (repo / ".gitignore").read_text(encoding="utf-8", errors="strict")
    assert ".belgi/" in gitignore
    assert ".belgi_alt/" in gitignore

    rc_run = run_belgi(
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

    runs_root = repo / ".belgi_alt" / "store" / "runs"
    run_dirs = _list_dirs(runs_root)
    assert len(run_dirs) == 1
    attempts = _list_dirs(run_dirs[0])
    assert [p.name for p in attempts] == ["attempt-0001"]

    rc_verify = run_belgi(["verify", "--repo", str(repo), "--workspace", ".belgi_alt"])
    assert rc_verify == 0


def test_run_migrates_legacy_run_key_directory_to_store(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    assert run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha]) == 0
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])

    store_dir = repo / ".belgi" / "store" / "runs" / run_key
    legacy_dir = repo / ".belgi" / "runs" / run_key
    store_dir.rename(legacy_dir)
    assert legacy_dir.is_dir()
    assert not store_dir.exists()

    rc_second = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc_second == 0
    _ = capsys.readouterr()
    assert store_dir.is_dir()
    assert not legacy_dir.exists()


def test_run_fails_closed_on_legacy_store_collision(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    _ = capsys.readouterr()
    assert run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha]) == 0
    captured = capsys.readouterr()
    machine_first = json.loads(captured.out.splitlines()[0])
    run_key = str(machine_first["run_key"])

    store_dir = repo / ".belgi" / "store" / "runs" / run_key
    legacy_dir = repo / ".belgi" / "runs" / run_key
    shutil.copytree(store_dir, legacy_dir)
    assert store_dir.is_dir()
    assert legacy_dir.is_dir()

    rc = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", head_sha])
    assert rc == 20
    captured_fail = capsys.readouterr()
    machine = json.loads(captured_fail.out.splitlines()[0])
    reason = str(machine.get("primary_reason") or "")
    assert "legacy/store run directory collision" in reason


def test_run_fails_closed_when_repo_head_sha_is_unavailable(tmp_path: Path) -> None:
    rc_init = run_belgi(["init", "--repo", str(tmp_path)])
    assert rc_init == 0

    rc_run = run_belgi(["run", "--repo", str(tmp_path), "--tier", "tier-0"])
    assert rc_run == 20


def test_run_fails_closed_when_base_revision_is_unavailable(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _unset_upstream_if_present(repo)

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(["run", "--repo", str(repo), "--tier", "tier-0"])
    assert rc_run == 20
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    reason = str(machine.get("primary_reason") or "")
    assert "base revision unavailable" in reason
    assert "--base-revision <40-hex SHA>" in reason


def test_run_intentspec_yaml_parse_error_includes_line_and_column(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    head_sha = _git_rev_parse(repo, "HEAD")

    assert run_belgi(["init", "--repo", str(repo)]) == 0
    run_id = "run-bad-intent-001"
    assert run_belgi(["run", "new", "--repo", str(repo), "--run-id", run_id]) == 0
    _ = capsys.readouterr()

    intent_path = repo / ".belgi" / "runs" / run_id / "inputs" / "intent" / "IntentSpec.core.md"
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
    machine = json.loads(captured.out.splitlines()[0])
    reason = str(machine.get("primary_reason") or "")
    assert "chain.compiler_c1_intent returned rc=3" in reason
    assert "IntentSpec YAML parse error" in captured.err
    assert "line " in captured.err and "column " in captured.err
    remediation_match = re.search(r"next:\s+(.+)", captured.err)
    assert remediation_match is not None
    remediation_line = remediation_match.group(1).strip()
    assert remediation_line != ""
    assert "IntentSpec.core.md" in remediation_line
    assert "line " in remediation_line and "column " in remediation_line
    assert "key: value" in remediation_line
    assert "gate_verdict_path:" not in captured.err
    assert "verdict: unavailable (no GateVerdict file produced)" in captured.err


def test_run_revision_binding_is_authoritative_for_base_and_evaluated(tmp_path: Path, capsys: object) -> None:
    repo = _fresh_repo_clone(tmp_path)
    _commit_file(repo, "main/forbidden_probe.md", "forbidden delta\n", "touch forbidden path")
    base_sha = _git_rev_parse(repo, "HEAD~1")
    evaluated_sha = _git_rev_parse(repo, "HEAD")

    rc_init = run_belgi(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = run_belgi(
        ["run", "--repo", str(repo), "--tier", "tier-0"],
        env_overrides={"BELGI_BASE_SHA": base_sha, "GITHUB_BASE_SHA": None},
    )
    assert rc_run == 10
    captured = capsys.readouterr()
    machine = json.loads(captured.out.splitlines()[0])
    run_key = str(machine["run_key"])
    attempt_id = str(machine["attempt_id"])
    attempt_dir = repo / ".belgi" / "store" / "runs" / run_key / attempt_id

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
