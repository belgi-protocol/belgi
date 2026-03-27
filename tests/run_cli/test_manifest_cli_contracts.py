from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.helpers import subprocess_cli as cli_subprocess
from tests.run_cli._manifest_cli_helpers import seed_min_manifest, write_json

run_belgi = cli_subprocess.run_belgi


def test_manifest_add_deterministic_and_hash_correct(tmp_path: Path) -> None:
    run_id = "run-demo-001"
    artifact_path = tmp_path / ".belgi" / "runs" / run_id / "artifacts" / "policy.overlay.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_payload = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "generated_at": "1970-01-01T00:00:00Z",
        "summary": {"total_checks": 1, "passed": 1, "failed": 0},
        "checks": [{"check_id": "OVERLAY-REQ-001", "passed": True}],
    }
    write_json(artifact_path, artifact_payload)
    artifact_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()

    manifest_path = tmp_path / ".belgi" / "runs" / run_id / "EvidenceManifest.json"
    seed_min_manifest(manifest_path, run_id=run_id)

    args = [
        "manifest",
        "add",
        "--repo",
        str(tmp_path),
        "--manifest",
        ".belgi/runs/run-demo-001/EvidenceManifest.json",
        "--artifact",
        ".belgi/runs/run-demo-001/artifacts/policy.overlay.json",
        "--kind",
        "policy_report",
        "--id",
        "policy.overlay",
        "--media-type",
        "application/json",
        "--produced-by",
        "R",
    ]
    assert run_belgi(args) == 0
    first = manifest_path.read_bytes()
    obj = json.loads(first.decode("utf-8", errors="strict"))
    artifacts = obj.get("artifacts")
    assert isinstance(artifacts, list)
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact["kind"] == "policy_report"
    assert artifact["id"] == "policy.overlay"
    assert artifact["hash"] == artifact_hash
    assert artifact["storage_ref"] == ".belgi/runs/run-demo-001/artifacts/policy.overlay.json"

    assert run_belgi(args) == 0
    second = manifest_path.read_bytes()
    assert first == second


def test_manifest_add_rejects_path_traversal(tmp_path: Path) -> None:
    run_id = "run-demo-001"
    manifest_path = tmp_path / ".belgi" / "runs" / run_id / "EvidenceManifest.json"
    seed_min_manifest(manifest_path, run_id=run_id)
    outside = tmp_path.parent / "outside.json"
    write_json(outside, {"x": 1})

    rc = run_belgi(
        [
            "manifest",
            "add",
            "--repo",
            str(tmp_path),
            "--manifest",
            ".belgi/runs/run-demo-001/EvidenceManifest.json",
            "--artifact",
            "../outside.json",
            "--kind",
            "policy_report",
            "--id",
            "policy.overlay",
            "--media-type",
            "application/json",
            "--produced-by",
            "R",
        ]
    )
    assert rc != 0


def test_manifest_add_rejects_noncanonical_relpath(tmp_path: Path) -> None:
    run_id = "run-demo-001"
    manifest_path = tmp_path / ".belgi" / "runs" / run_id / "EvidenceManifest.json"
    seed_min_manifest(manifest_path, run_id=run_id)
    artifact_path = tmp_path / ".belgi" / "runs" / run_id / "artifacts" / "policy.overlay.json"
    write_json(artifact_path, {"x": 1})

    rc = run_belgi(
        [
            "manifest",
            "add",
            "--repo",
            str(tmp_path),
            "--manifest",
            "./.belgi/runs/run-demo-001/EvidenceManifest.json",
            "--artifact",
            ".belgi/runs/run-demo-001/artifacts/policy.overlay.json",
            "--kind",
            "policy_report",
            "--id",
            "policy.overlay",
            "--media-type",
            "application/json",
            "--produced-by",
            "R",
        ]
    )
    assert rc != 0


def test_manifest_add_rejects_absolute_path(tmp_path: Path) -> None:
    run_id = "run-demo-001"
    manifest_path = tmp_path / ".belgi" / "runs" / run_id / "EvidenceManifest.json"
    seed_min_manifest(manifest_path, run_id=run_id)
    artifact_path = tmp_path / ".belgi" / "runs" / run_id / "artifacts" / "policy.overlay.json"
    write_json(artifact_path, {"x": 1})

    rc = run_belgi(
        [
            "manifest",
            "add",
            "--repo",
            str(tmp_path),
            "--manifest",
            ".belgi/runs/run-demo-001/EvidenceManifest.json",
            "--artifact",
            str(artifact_path),
            "--kind",
            "policy_report",
            "--id",
            "policy.overlay",
            "--media-type",
            "application/json",
            "--produced-by",
            "R",
        ]
    )
    assert rc != 0


def test_manifest_add_rejects_symlink_artifact(tmp_path: Path) -> None:
    run_id = "run-demo-001"
    manifest_path = tmp_path / ".belgi" / "runs" / run_id / "EvidenceManifest.json"
    seed_min_manifest(manifest_path, run_id=run_id)
    target = tmp_path / "artifacts" / "policy_target.json"
    write_json(target, {"x": 1})
    link = tmp_path / "artifacts" / "policy_link.json"
    try:
        link.symlink_to(target.name)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation not supported in this test environment: {exc}")

    rc = run_belgi(
        [
            "manifest",
            "add",
            "--repo",
            str(tmp_path),
            "--manifest",
            ".belgi/runs/run-demo-001/EvidenceManifest.json",
            "--artifact",
            "artifacts/policy_link.json",
            "--kind",
            "policy_report",
            "--id",
            "policy.overlay",
            "--media-type",
            "application/json",
            "--produced-by",
            "R",
        ]
    )
    assert rc != 0
