from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.gates.gate_test_support import (
    REPO_ROOT,
    _read_json,
    _remove_locked_spec_protocol_pack,
    _run_module,
    _setup_fake_repo_with_pack,
    _sha256_hex,
    _sync_locked_spec_protocol_identity,
    _tamper_locked_spec_pack_id,
)
from tests.helpers import builders
from tests.helpers.repo_imports import import_fresh_protocol_pack_surface

pytestmark = pytest.mark.repo_local

MANIFEST_FILENAME = import_fresh_protocol_pack_surface().manifest_filename


def _init_git_repo(repo_root: Path) -> str:
    return builders.init_git_repo(repo_root)


def _git_head(repo_root: Path) -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_root, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _git_status_porcelain(repo_root: Path) -> str:
    result = subprocess.run(["git", "status", "--porcelain"], cwd=repo_root, check=True, capture_output=True, text=True)
    return result.stdout


def _assert_clean_head(repo_root: Path, evaluated_revision: str) -> None:
    assert _git_head(repo_root) == evaluated_revision
    assert _git_status_porcelain(repo_root) == ""


def _report_results(report_obj: dict[str, Any]) -> list[dict[str, Any]]:
    results = report_obj.get("results")
    assert isinstance(results, list)
    out: list[dict[str, Any]] = []
    for row in results:
        assert isinstance(row, dict)
        out.append(row)
    return out


def _first_fail_result(results: list[dict[str, Any]]) -> dict[str, Any]:
    for row in results:
        if str(row.get("status")) == "FAIL":
            return row
    raise AssertionError("expected at least one FAIL result")


def _prepare_r_pass_tier1_repo(tmp_path: Path) -> dict[str, str]:
    return builders.build_r_repo(
        tmp_path,
        rel_root="gate_r/r_pass_tier1",
        run_id="r-pass-tier1",
    )


def _rewrite_required_report_payload_run_id(
    tmp_path: Path,
    *,
    evidence_rel: str,
    kind: str,
    artifact_id: str,
    run_id: str,
) -> None:
    evidence_path = tmp_path / evidence_rel
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)
    target = next(
        (
            row
            for row in artifacts
            if isinstance(row, dict) and row.get("kind") == kind and row.get("id") == artifact_id
        ),
        None,
    )
    assert isinstance(target, dict)
    storage_ref = target.get("storage_ref")
    assert isinstance(storage_ref, str) and storage_ref

    payload_path = tmp_path / Path(*storage_ref.split("/"))
    payload = _read_json(payload_path)
    payload["run_id"] = run_id
    payload_bytes = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8", errors="strict")
    payload_path.write_bytes(payload_bytes)
    target["hash"] = _sha256_hex(payload_bytes)
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def test_gate_r_snapshot_index_hash_mismatch_is_no_go(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    paths = builders.build_r_repo(tmp_path, rel_root="gate_r/r_pass_tier1", run_id="r-pass-tier1")
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )

    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)
    gate_q_rel = "inputs/GateVerdict.Q.json"
    (tmp_path / "inputs" / "GateVerdict.Q.json").write_text(
        json.dumps({"schema_version": "1.0.0", "run_id": "synthetic", "gate_id": "Q", "verdict": "GO"}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    evidence_path = tmp_path / paths["evidence"]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8", errors="strict"))
    assert isinstance(evidence, dict)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)
    artifacts.append(
        {
            "kind": "schema_validation",
            "id": "locked_spec",
            "hash": "0" * 64,
            "media_type": "application/json",
            "storage_ref": paths["locked"],
            "produced_by": "R",
        }
    )
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict", newline="\n")

    commit_sha = _init_git_repo(tmp_path)
    (tmp_path / "out").mkdir(parents=True, exist_ok=True)

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            gate_q_rel,
            "--evidence-manifest",
            paths["evidence"],
            "--r-snapshot-manifest-out",
            "out/EvidenceManifest.r_snapshot.json",
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.json",
            "--gate-verdict-out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gate_verdict = _read_json(tmp_path / "out" / "GateVerdict.json")
    assert gate_verdict.get("failure_category") == "FR-INVARIANT-FAILED"


def test_gate_r_snapshot_manifest_write_failure_is_no_go(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    paths = builders.build_r_repo(tmp_path, rel_root="gate_r/r_pass_tier1", run_id="r-pass-tier1")
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )

    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)
    gate_q_rel = "inputs/GateVerdict.Q.json"
    (tmp_path / "inputs" / "GateVerdict.Q.json").write_text(
        json.dumps({"schema_version": "1.0.0", "run_id": "synthetic", "gate_id": "Q", "verdict": "GO"}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)
    (tmp_path / "out").mkdir(parents=True, exist_ok=True)
    (tmp_path / "nope_dir").write_text("not a directory\n", encoding="utf-8", errors="strict", newline="\n")

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            gate_q_rel,
            "--evidence-manifest",
            paths["evidence"],
            "--r-snapshot-manifest-out",
            "nope_dir/EvidenceManifest.r_snapshot.json",
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.json",
            "--gate-verdict-out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    report = _read_json(tmp_path / "out" / "verify_report.json")
    results = _report_results(report)
    assert [str(row.get("check_id")) for row in results] == ["PROTOCOL-IDENTITY-001", "R-SNAPSHOT-INDEX-001"]
    assert [str(row.get("status")) for row in results] == ["PASS", "FAIL"]
    assert "Failed to write R-snapshot EvidenceManifest:" in str(results[1].get("message"))
    assert str(results[1].get("remediation_next_instruction")) == (
        "Do fix filesystem permissions/paths so Gate R can write the R-snapshot manifest and establish the persisted evidence anchor, then re-run R."
    )
    verdict = _read_json(tmp_path / "out" / "GateVerdict.json")
    assert verdict.get("failure_category") == "FR-INVARIANT-FAILED"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R-SNAPSHOT-INDEX-001"


def test_gate_r_requires_git_for_revision_resolution(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)

    (tmp_path / "inputs" / "LockedSpec.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "run_id": "test-strict-git",
                "tier": {"tier_id": "tier-1"},
                "upstream_state": {"commit_sha": "a" * 40, "dirty_flag": False, "repo_ref": "synthetic"},
                "protocol_pack": {
                    "pack_id": "0" * 64,
                    "manifest_sha256": "0" * 64,
                    "pack_name": "synthetic",
                    "source": "builtin",
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "inputs" / "EvidenceManifest.json").write_text(
        json.dumps({"schema_version": "1.0.0", "run_id": "test-strict-git", "artifacts": []}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "inputs" / "GateVerdict.Q.json").write_text(
        json.dumps({"schema_version": "1.0.0", "run_id": "test-strict-git", "gate_id": "Q", "verdict": "GO"}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            "inputs/LockedSpec.json",
            "--gate-q-verdict",
            "inputs/GateVerdict.Q.json",
            "--evidence-manifest",
            "inputs/EvidenceManifest.json",
            "--evaluated-revision",
            "b" * 40,
            "--out",
            "out/verify_report.json",
            "--gate-verdict-out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 3, (cp.returncode, cp.stdout, cp.stderr)
    assert "rev-parse" in (cp.stderr or "")


def test_gate_r_doc_001_required_path_not_touched_is_primary(tmp_path: Path) -> None:
    paths = builders.build_r_repo(
        tmp_path,
        rel_root="gate_r/r_doc_001_required_path_not_touched",
        run_id="r-doc-001",
        doc_impact={"required_paths": ["docs/required.md"]},
        diff_paths=["src/changed.py"],
    )
    tiers = builders.builtin_tiers()
    tiers["tiers"]["tier-1"]["doc_impact_required"] = True
    tiers_rel = builders.write_tiers_override(tmp_path, tiers)
    commit_sha = builders.init_git_repo(tmp_path)

    cp = builders.run_gate_r(
        tmp_path,
        locked_rel=paths["locked"],
        gate_q_rel=paths["gate_q_verdict"],
        evidence_rel=paths["evidence"],
        evaluated_revision=commit_sha,
        tiers_rel=tiers_rel,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / "out" / "verify_report.json")
    first_fail = _first_fail_result(_report_results(report))
    assert first_fail["check_id"] == "R-DOC-001"

    verdict = _read_json(tmp_path / "out" / "GateVerdict.R.json")
    assert verdict["failure_category"] == "FR-INVARIANT-FAILED"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0]["rule_id"] == "R-DOC-001"


def test_gate_r_protocol_identity_mismatch_pack_id(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    paths = builders.build_r_repo(tmp_path, rel_root="gate_r/r_pass_tier1", run_id="r-pass-tier1")
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )
    locked_path = tmp_path / paths["locked"]
    _tamper_locked_spec_pack_id(locked_path, "0" * 64)

    commit_sha = _init_git_repo(tmp_path)
    gate_q_rel = "inputs/GateVerdict.Q.json"
    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "inputs" / "GateVerdict.Q.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "run_id": "synthetic",
                "gate_id": "Q",
                "verdict": "GO",
                "failure_category": None,
                "failures": [],
                "evidence_manifest_ref": {"id": "evidence", "hash": "0" * 64, "storage_ref": "inputs/EvidenceManifest.Q.json"},
                "evaluated_at": "1970-01-01T00:00:00Z",
                "evaluator": "synthetic",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            gate_q_rel,
            "--evidence-manifest",
            paths["evidence"],
            "--r-snapshot-manifest-out",
            "out/EvidenceManifest.r_snapshot.json",
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.json",
            "--gate-verdict-out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    verify_report = _read_json(tmp_path / "out" / "verify_report.json")
    results = _report_results(verify_report)
    assert [str(row.get("check_id")) for row in results] == ["PROTOCOL-IDENTITY-001"]
    assert [str(row.get("status")) for row in results] == ["FAIL"]
    assert not (tmp_path / "out" / "EvidenceManifest.r_snapshot.json").exists()

    verdict = _read_json(tmp_path / "out" / "GateVerdict.json")
    assert verdict.get("failure_category") == "FR-PROTOCOL-IDENTITY-MISMATCH", verdict
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "PROTOCOL-IDENTITY-001"


def test_gate_r_ordered_results_snapshot_preflight_primary_cause(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    paths = builders.build_r_repo(tmp_path, rel_root="gate_r/r_pass_tier1", run_id="r-pass-tier1")
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )

    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    evidence["artifacts"] = "not-a-list"
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--r-snapshot-manifest-out",
            "out/EvidenceManifest.r_snapshot.json",
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.snapshot_fail.json",
            "--gate-verdict-out",
            "out/GateVerdict.snapshot_fail.json",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    verify_report = _read_json(tmp_path / "out" / "verify_report.snapshot_fail.json")
    results = _report_results(verify_report)
    assert [str(row.get("check_id")) for row in results] == ["PROTOCOL-IDENTITY-001", "R-SNAPSHOT-INDEX-001"]
    assert [str(row.get("status")) for row in results] == ["PASS", "FAIL"]
    assert not (tmp_path / "out" / "EvidenceManifest.r_snapshot.json").exists()

    gate_verdict = _read_json(tmp_path / "out" / "GateVerdict.snapshot_fail.json")
    assert gate_verdict.get("failure_category") == "FR-INVARIANT-FAILED"
    failures = gate_verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R-SNAPSHOT-INDEX-001"


def test_gate_r_normal_pass_writes_snapshot_and_executes_later_checks(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_repo(tmp_path)

    commit_sha = _init_git_repo(tmp_path)
    snapshot_path = tmp_path / "out" / "EvidenceManifest.r_snapshot.json"

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--r-snapshot-manifest-out",
            "out/EvidenceManifest.r_snapshot.json",
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.pass.json",
            "--gate-verdict-out",
            "out/GateVerdict.pass.json",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
    assert snapshot_path.exists()

    report = _read_json(tmp_path / "out" / "verify_report.pass.json")
    results = _report_results(report)
    assert [str(row.get("check_id")) for row in results[:2]] == ["PROTOCOL-IDENTITY-001", "R-SNAPSHOT-INDEX-001"]
    assert [str(row.get("status")) for row in results[:2]] == ["PASS", "PASS"]
    assert any(str(row.get("check_id")) == "R1" for row in results)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.pass.json")
    assert verdict.get("verdict") == "GO"
    assert verdict.get("failure_category") is None


def test_gate_r_head_guard_helper_detects_post_head_tracked_mutation(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    _prepare_r_pass_tier1_repo(tmp_path)

    commit_sha = _init_git_repo(tmp_path)
    _assert_clean_head(tmp_path, commit_sha)

    tracked_path = tmp_path / "src" / "changed.py"
    tracked_path.write_text("dirty\n", encoding="utf-8", errors="strict", newline="\n")

    with pytest.raises(AssertionError):
        _assert_clean_head(tmp_path, commit_sha)


@pytest.mark.parametrize(
    ("report_id", "semantic_owner"),
    [
        ("policy.invariant_eval", "R1"),
        ("policy.supplychain", "R7"),
        ("policy.adversarial_scan", "R8"),
    ],
)
def test_gate_r_foreign_run_required_policy_report_is_structurally_invalid(
    tmp_path: Path,
    report_id: str,
    semantic_owner: str,
) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_repo(tmp_path)

    _rewrite_required_report_payload_run_id(
        tmp_path,
        evidence_rel=paths["evidence"],
        kind="policy_report",
        artifact_id=report_id,
        run_id="foreign-run",
    )

    commit_sha = _init_git_repo(tmp_path)
    verify_rel = f"out/verify_report.{report_id.replace('.', '_')}.foreign_run.json"
    verdict_rel = f"out/GateVerdict.{report_id.replace('.', '_')}.foreign_run.json"
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_rel,
            "--gate-verdict-out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / verify_rel)
    results = _report_results(report)
    first_fail = _first_fail_result(results)
    assert first_fail.get("check_id") == "R4"
    assert first_fail.get("category") == "FR-SCHEMA-ARTIFACT-INVALID"
    assert "belongs to a different run" in str(first_fail.get("message"))
    assert not any(str(row.get("check_id")) == semantic_owner for row in results)

    verdict = _read_json(tmp_path / verdict_rel)
    assert verdict.get("failure_category") == "FR-SCHEMA-ARTIFACT-INVALID"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R4"
    remediation = verdict.get("remediation")
    assert isinstance(remediation, dict)
    assert remediation.get("next_instruction") == "Do regenerate the required report for the current LockedSpec.run_id then re-run R."


def test_gate_r_foreign_run_required_test_report_is_structurally_invalid(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_repo(tmp_path)

    _rewrite_required_report_payload_run_id(
        tmp_path,
        evidence_rel=paths["evidence"],
        kind="test_report",
        artifact_id="tests.report",
        run_id="foreign-run",
    )

    commit_sha = _init_git_repo(tmp_path)
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.tests_report.foreign_run.json",
            "--gate-verdict-out",
            "out/GateVerdict.tests_report.foreign_run.json",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / "out" / "verify_report.tests_report.foreign_run.json")
    results = _report_results(report)
    first_fail = _first_fail_result(results)
    assert first_fail.get("check_id") == "R4"
    assert first_fail.get("category") == "FR-SCHEMA-ARTIFACT-INVALID"
    assert "belongs to a different run" in str(first_fail.get("message"))
    assert not any(str(row.get("check_id")) == "R5" for row in results)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.tests_report.foreign_run.json")
    assert verdict.get("failure_category") == "FR-SCHEMA-ARTIFACT-INVALID"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R4"
    remediation = verdict.get("remediation")
    assert isinstance(remediation, dict)
    assert remediation.get("next_instruction") == "Do regenerate the required report for the current LockedSpec.run_id then re-run R."


@pytest.mark.parametrize(
    ("kind", "artifact_id", "semantic_owner"),
    [
        ("policy_report", "policy.invariant_eval", "R1"),
        ("policy_report", "policy.supplychain", "R7"),
        ("policy_report", "policy.adversarial_scan", "R8"),
        ("test_report", "tests.report", "R5"),
    ],
)
def test_gate_r_current_run_required_report_payloads_still_pass(
    tmp_path: Path,
    kind: str,
    artifact_id: str,
    semantic_owner: str,
) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_repo(tmp_path)
    locked = _read_json(tmp_path / paths["locked"])
    locked_run_id = str(locked.get("run_id"))

    _rewrite_required_report_payload_run_id(
        tmp_path,
        evidence_rel=paths["evidence"],
        kind=kind,
        artifact_id=artifact_id,
        run_id=locked_run_id,
    )

    commit_sha = _init_git_repo(tmp_path)
    verify_rel = f"out/verify_report.{artifact_id.replace('.', '_')}.current_run.json"
    verdict_rel = f"out/GateVerdict.{artifact_id.replace('.', '_')}.current_run.json"
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            verify_rel,
            "--gate-verdict-out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
    report = _read_json(tmp_path / verify_rel)
    assert any(str(row.get("check_id")) == semantic_owner for row in _report_results(report))
    verdict = _read_json(tmp_path / verdict_rel)
    assert verdict.get("verdict") == "GO"


def test_gate_r_missing_policy_supplychain_is_owned_by_r7(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_repo(tmp_path)

    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)
    evidence["artifacts"] = [
        row
        for row in artifacts
        if not (isinstance(row, dict) and row.get("kind") == "policy_report" and row.get("id") == "policy.supplychain")
    ]
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.r7_missing.json",
            "--gate-verdict-out",
            "out/GateVerdict.r7_missing.json",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / "out/verify_report.r7_missing.json")
    first_fail = _first_fail_result(_report_results(report))
    assert first_fail.get("check_id") == "R7"

    verdict = _read_json(tmp_path / "out/GateVerdict.r7_missing.json")
    assert verdict.get("failure_category") == "FR-SUPPLYCHAIN-SCAN-MISSING"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R7"


def test_gate_r_missing_policy_adversarial_scan_is_owned_by_r8(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_repo(tmp_path)

    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)
    evidence["artifacts"] = [
        row
        for row in artifacts
        if not (isinstance(row, dict) and row.get("kind") == "policy_report" and row.get("id") == "policy.adversarial_scan")
    ]
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.r8_missing.json",
            "--gate-verdict-out",
            "out/GateVerdict.r8_missing.json",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / "out/verify_report.r8_missing.json")
    first_fail = _first_fail_result(_report_results(report))
    assert first_fail.get("check_id") == "R8"

    verdict = _read_json(tmp_path / "out/GateVerdict.r8_missing.json")
    assert verdict.get("failure_category") == "FR-ADVERSARIAL-SCAN-MISSING"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R8"


@pytest.mark.parametrize(
    ("report_id", "expected_rule_id"),
    [
        ("policy.supplychain", "R7"),
        ("policy.adversarial_scan", "R8"),
    ],
)
def test_gate_r_duplicate_required_policy_report_is_owned_by_dedicated_check(
    tmp_path: Path,
    report_id: str,
    expected_rule_id: str,
) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = _prepare_r_pass_tier1_repo(tmp_path)

    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)
    target = next(
        (
            row
            for row in artifacts
            if isinstance(row, dict) and row.get("kind") == "policy_report" and row.get("id") == report_id
        ),
        None,
    )
    assert isinstance(target, dict)
    artifacts.append(dict(target))
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            f"out/verify_report.dup.{expected_rule_id}.json",
            "--gate-verdict-out",
            f"out/GateVerdict.dup.{expected_rule_id}.json",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    report = _read_json(tmp_path / f"out/verify_report.dup.{expected_rule_id}.json")
    first_fail = _first_fail_result(_report_results(report))
    assert first_fail.get("check_id") == expected_rule_id
    assert first_fail.get("category") == "FR-SCHEMA-ARTIFACT-INVALID"

    verdict = _read_json(tmp_path / f"out/GateVerdict.dup.{expected_rule_id}.json")
    assert verdict.get("failure_category") == "FR-SCHEMA-ARTIFACT-INVALID"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == expected_rule_id


def test_gate_r_overlay_preflight_ordering_and_optional_presence(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = builders.build_r_repo(tmp_path, rel_root="gate_r/r_pass_tier1", run_id="r-pass-tier1")
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )
    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)

    overlay_payload = {
        "schema_version": "1.0.0",
        "run_id": "r-pass-tier1",
        "generated_at": "1970-01-01T00:00:00Z",
        "summary": {"total_checks": 1, "passed": 1, "failed": 0},
        "checks": [{"check_id": "ADOPTER-POLICY-001", "passed": True}],
    }
    overlay_rel = "gate_r/r_pass_tier1/policy.overlay_requirements.json"
    overlay_path = tmp_path / Path(*overlay_rel.split("/"))
    overlay_bytes = (json.dumps(overlay_payload, indent=2, sort_keys=True) + "\n").encode("utf-8", errors="strict")
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.write_bytes(overlay_bytes)
    artifacts.append(
        {
            "kind": "policy_report",
            "id": "policy.overlay_requirements",
            "hash": _sha256_hex(overlay_bytes),
            "media_type": "application/json",
            "storage_ref": overlay_rel,
            "produced_by": "R",
        }
    )
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    protocol_manifest_path = tmp_path / "protocol_pack" / MANIFEST_FILENAME
    protocol_manifest = _read_json(protocol_manifest_path)
    (tmp_path / "belgi_pack").mkdir(parents=True, exist_ok=True)
    (tmp_path / "belgi_pack" / "DomainPackManifest.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "pack_name": "overlay-test",
                "pack_semver": "0.1.0",
                "belgi_protocol_pack_pin": {
                    "pack_name": protocol_manifest["pack_name"],
                    "pack_id": "f" * 64,
                    "manifest_sha256": _sha256_hex(protocol_manifest_path.read_bytes()),
                },
                "required_policy_check_ids": ["ADOPTER-POLICY-001"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)

    cp_overlay = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.overlay_fail.json",
            "--gate-verdict-out",
            "out/GateVerdict.overlay_fail.json",
            "--overlay",
            "belgi_pack",
        ],
        cwd=REPO_ROOT,
    )
    assert cp_overlay.returncode == 2, (cp_overlay.returncode, cp_overlay.stdout, cp_overlay.stderr)
    overlay_report = _read_json(tmp_path / "out/verify_report.overlay_fail.json")
    overlay_results = _report_results(overlay_report)
    assert [str(overlay_results[idx].get("check_id")) for idx in (0, 1, 2)] == [
        "PROTOCOL-IDENTITY-001",
        "R-SNAPSHOT-INDEX-001",
        "R-OVERLAY-001",
    ]
    assert [str(overlay_results[idx].get("status")) for idx in (0, 1, 2)] == ["PASS", "PASS", "FAIL"]

    overlay_verdict = _read_json(tmp_path / "out/GateVerdict.overlay_fail.json")
    failures = overlay_verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0].get("rule_id") == "R-OVERLAY-001"

    cp_no_overlay = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.no_overlay.json",
            "--gate-verdict-out",
            "out/GateVerdict.no_overlay.json",
        ],
        cwd=REPO_ROOT,
    )
    assert cp_no_overlay.returncode == 0, (cp_no_overlay.returncode, cp_no_overlay.stdout, cp_no_overlay.stderr)
    no_overlay_report = _read_json(tmp_path / "out/verify_report.no_overlay.json")
    no_overlay_results = _report_results(no_overlay_report)
    assert all(str(result.get("check_id")) != "R-OVERLAY-001" for result in no_overlay_results)


def test_gate_r_overlay_ignores_non_policy_payload_policy_report(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)
    paths = builders.build_r_repo(tmp_path, rel_root="gate_r/r_pass_tier1", run_id="r-pass-tier1")
    _sync_locked_spec_protocol_identity(
        tmp_path / paths["locked"],
        tmp_path / "protocol_pack" / MANIFEST_FILENAME,
    )

    evidence_path = tmp_path / paths["evidence"]
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)

    overlay_payload = {
        "schema_version": "1.0.0",
        "run_id": "r-pass-tier1",
        "generated_at": "1970-01-01T00:00:00Z",
        "summary": {"total_checks": 1, "passed": 1, "failed": 0},
        "checks": [{"check_id": "ADOPTER-POLICY-001", "passed": True}],
    }
    overlay_rel = "gate_r/r_pass_tier1/policy.overlay_requirements.json"
    overlay_path = tmp_path / Path(*overlay_rel.split("/"))
    overlay_bytes = (json.dumps(overlay_payload, indent=2, sort_keys=True) + "\n").encode("utf-8", errors="strict")
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.write_bytes(overlay_bytes)

    artifacts.append(
        {
            "kind": "policy_report",
            "id": "policy.overlay_requirements",
            "hash": _sha256_hex(overlay_bytes),
            "media_type": "application/json",
            "storage_ref": overlay_rel,
            "produced_by": "R",
        }
    )
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    protocol_manifest_path = tmp_path / "protocol_pack" / MANIFEST_FILENAME
    protocol_manifest = _read_json(protocol_manifest_path)
    (tmp_path / "belgi_pack").mkdir(parents=True, exist_ok=True)
    (tmp_path / "belgi_pack" / "DomainPackManifest.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "pack_name": "adopter-overlay",
                "pack_semver": "0.1.0",
                "belgi_protocol_pack_pin": {
                    "pack_name": protocol_manifest["pack_name"],
                    "pack_id": protocol_manifest["pack_id"],
                    "manifest_sha256": _sha256_hex(protocol_manifest_path.read_bytes()),
                },
                "required_policy_check_ids": ["ADOPTER-POLICY-001"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    commit_sha = _init_git_repo(tmp_path)
    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            paths["gate_q_verdict"],
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/verify_report.overlay.json",
            "--gate-verdict-out",
            "out/GateVerdict.R.overlay.json",
            "--overlay",
            "belgi_pack",
        ],
        cwd=REPO_ROOT,
    )
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)

    gate_verdict = _read_json(tmp_path / "out/GateVerdict.R.overlay.json")
    assert gate_verdict.get("verdict") == "GO", gate_verdict
    assert gate_verdict.get("failure_category") is None, gate_verdict


def test_gate_r_missing_protocol_pack_field(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    paths = builders.build_r_repo(tmp_path, rel_root="gate_r/r_pass_tier1", run_id="r-pass-tier1")
    locked_path = tmp_path / paths["locked"]
    _remove_locked_spec_protocol_pack(locked_path)

    commit_sha = _init_git_repo(tmp_path)
    gate_q_rel = "inputs/GateVerdict.Q.json"
    (tmp_path / "inputs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "inputs" / "GateVerdict.Q.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "run_id": "synthetic",
                "gate_id": "Q",
                "verdict": "GO",
                "failure_category": None,
                "failures": [],
                "evidence_manifest_ref": {"id": "evidence", "hash": "0" * 64, "storage_ref": "inputs/EvidenceManifest.Q.json"},
                "evaluated_at": "1970-01-01T00:00:00Z",
                "evaluator": "synthetic",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    cp = _run_module(
        "chain.gate_r_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--locked-spec",
            paths["locked"],
            "--gate-q-verdict",
            gate_q_rel,
            "--evidence-manifest",
            paths["evidence"],
            "--evaluated-revision",
            commit_sha,
            "--out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gate_verdict = _read_json(tmp_path / "out/GateVerdict.json")
    assert gate_verdict.get("failure_category") == "FR-PROTOCOL-IDENTITY-MISMATCH", gate_verdict
