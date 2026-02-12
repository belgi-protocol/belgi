from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.cli import main as belgi_main
from belgi.core.hash import sha256_bytes


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def _seed_min_manifest(path: Path, *, run_id: str) -> None:
    _write_json(
        path,
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "artifacts": [],
            "commands_executed": [],
            "envelope_attestation": None,
        },
    )


def test_run_new_idempotent_and_force(tmp_path: Path) -> None:
    rc_init = belgi_main(["init", "--repo", str(tmp_path)])
    assert rc_init == 0

    run_id = "run-demo-001"
    run_dir = tmp_path / ".belgi" / "runs" / run_id
    intent_path = run_dir / "IntentSpec.core.md"
    tolerances_path = run_dir / "tolerances.json"
    toolchain_path = run_dir / "toolchain.json"

    rc1 = belgi_main(["run", "new", "--repo", str(tmp_path), "--run-id", run_id])
    assert rc1 == 0
    assert intent_path.exists()
    assert tolerances_path.read_text(encoding="utf-8", errors="strict") == "{}\n"
    assert toolchain_path.read_text(encoding="utf-8", errors="strict") == "{}\n"

    baseline = {
        "intent": intent_path.read_bytes(),
        "tolerances": tolerances_path.read_bytes(),
        "toolchain": toolchain_path.read_bytes(),
    }

    intent_path.write_text("custom-intent\n", encoding="utf-8", errors="strict", newline="\n")
    tolerances_path.write_text("{\"x\":1}\n", encoding="utf-8", errors="strict", newline="\n")

    rc2 = belgi_main(["run", "new", "--repo", str(tmp_path), "--run-id", run_id])
    assert rc2 == 0
    assert intent_path.read_text(encoding="utf-8", errors="strict") == "custom-intent\n"
    assert tolerances_path.read_text(encoding="utf-8", errors="strict") == "{\"x\":1}\n"

    rc3 = belgi_main(["run", "new", "--repo", str(tmp_path), "--run-id", run_id, "--force"])
    assert rc3 == 0
    assert intent_path.read_bytes() == baseline["intent"]
    assert tolerances_path.read_bytes() == baseline["tolerances"]
    assert toolchain_path.read_bytes() == baseline["toolchain"]


def test_manifest_add_deterministic_and_hash_correct(tmp_path: Path) -> None:
    run_id = "run-demo-001"
    artifact_path = tmp_path / ".belgi" / "runs" / run_id / "artifacts" / "policy.overlay.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_payload = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "generated_at": "1970-01-01T00:00:00Z",
        "summary": {"total_checks": 1, "passed": 1, "failed": 0},
        "checks": [{"check_id": "PFY-OVERLAY-001", "passed": True}],
    }
    _write_json(artifact_path, artifact_payload)
    artifact_hash = sha256_bytes(artifact_path.read_bytes())

    manifest_path = tmp_path / ".belgi" / "runs" / run_id / "EvidenceManifest.json"
    _seed_min_manifest(manifest_path, run_id=run_id)

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
    rc1 = belgi_main(args)
    assert rc1 == 0
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

    rc2 = belgi_main(args)
    assert rc2 == 0
    second = manifest_path.read_bytes()
    assert first == second


def test_manifest_add_rejects_path_traversal(tmp_path: Path) -> None:
    run_id = "run-demo-001"
    manifest_path = tmp_path / ".belgi" / "runs" / run_id / "EvidenceManifest.json"
    _seed_min_manifest(manifest_path, run_id=run_id)
    outside = tmp_path.parent / "outside.json"
    _write_json(outside, {"x": 1})

    rc = belgi_main(
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


def test_manifest_add_rejects_symlink_artifact(tmp_path: Path) -> None:
    run_id = "run-demo-001"
    manifest_path = tmp_path / ".belgi" / "runs" / run_id / "EvidenceManifest.json"
    _seed_min_manifest(manifest_path, run_id=run_id)
    target = tmp_path / "artifacts" / "policy_target.json"
    _write_json(target, {"x": 1})
    link = tmp_path / "artifacts" / "policy_link.json"
    try:
        link.symlink_to(target.name)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"symlink creation not supported in this test environment: {e}")

    rc = belgi_main(
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
