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
    intent_path = run_dir / "inputs" / "intent" / "IntentSpec.core.md"
    waivers_dir = run_dir / "inputs" / "waivers"
    runbook_template_path = run_dir / "RUN.md"
    run_key_pointer_path = run_dir / "run_key.txt"
    last_attempt_pointer_path = run_dir / "last_attempt.txt"
    open_verdict_pointer_path = run_dir / "open_verdict.txt"
    open_evidence_pointer_path = run_dir / "open_evidence.txt"
    deprecated_intent_template_path = run_dir / "IntentSpec.md"
    tolerances_path = run_dir / "tolerances.json"
    toolchain_path = run_dir / "toolchain.json"

    rc1 = belgi_main(["run", "new", "--repo", str(tmp_path), "--run-id", run_id])
    assert rc1 == 0
    assert intent_path.exists()
    assert waivers_dir.exists()
    assert waivers_dir.is_dir()
    assert list(waivers_dir.iterdir()) == []
    assert runbook_template_path.exists()
    assert not deprecated_intent_template_path.exists()
    runbook_text = runbook_template_path.read_text(encoding="utf-8", errors="strict")
    assert "belgi waiver new --repo . --run-id" in runbook_text
    assert "belgi waiver apply --repo . --run-id" in runbook_text
    assert "belgi run --repo . --tier tier-1 --intent-spec .belgi/runs/" in runbook_text
    assert "--base-revision" in runbook_text
    assert "inputs/intent/IntentSpec.core.md" in runbook_text
    assert "inputs/waivers/waiver-001.json" in runbook_text
    assert "Artifacts are created under `.belgi/store/runs/<run_key>/<attempt_id>/`." in runbook_text
    assert tolerances_path.read_text(encoding="utf-8", errors="strict") == "{}\n"
    assert toolchain_path.read_text(encoding="utf-8", errors="strict") == "{}\n"
    assert not (run_dir / "EvidenceManifest.json").exists()
    assert run_key_pointer_path.read_text(encoding="utf-8", errors="strict") == "PENDING\n"
    assert last_attempt_pointer_path.read_text(encoding="utf-8", errors="strict") == "PENDING\n"
    assert open_verdict_pointer_path.read_text(encoding="utf-8", errors="strict") == "PENDING\n"
    assert open_evidence_pointer_path.read_text(encoding="utf-8", errors="strict") == "PENDING\n"

    baseline = {
        "intent": intent_path.read_bytes(),
        "runbook_template": runbook_template_path.read_bytes(),
        "tolerances": tolerances_path.read_bytes(),
        "toolchain": toolchain_path.read_bytes(),
        "run_key_pointer": run_key_pointer_path.read_bytes(),
        "last_attempt_pointer": last_attempt_pointer_path.read_bytes(),
        "open_verdict_pointer": open_verdict_pointer_path.read_bytes(),
        "open_evidence_pointer": open_evidence_pointer_path.read_bytes(),
    }

    intent_path.write_text("custom-intent\n", encoding="utf-8", errors="strict", newline="\n")
    runbook_template_path.write_text("custom-runbook-template\n", encoding="utf-8", errors="strict", newline="\n")
    tolerances_path.write_text("{\"x\":1}\n", encoding="utf-8", errors="strict", newline="\n")
    run_key_pointer_path.write_text("x\n", encoding="utf-8", errors="strict", newline="\n")
    last_attempt_pointer_path.write_text("y\n", encoding="utf-8", errors="strict", newline="\n")
    open_verdict_pointer_path.write_text("z\n", encoding="utf-8", errors="strict", newline="\n")
    open_evidence_pointer_path.write_text("w\n", encoding="utf-8", errors="strict", newline="\n")
    waiver_path = waivers_dir / "custom-waiver.json"
    waiver_path.write_text("{\"x\":1}\n", encoding="utf-8", errors="strict", newline="\n")

    rc2 = belgi_main(["run", "new", "--repo", str(tmp_path), "--run-id", run_id])
    assert rc2 == 0
    assert intent_path.read_text(encoding="utf-8", errors="strict") == "custom-intent\n"
    assert runbook_template_path.read_text(encoding="utf-8", errors="strict") == "custom-runbook-template\n"
    assert tolerances_path.read_text(encoding="utf-8", errors="strict") == "{\"x\":1}\n"
    assert run_key_pointer_path.read_text(encoding="utf-8", errors="strict") == "x\n"
    assert last_attempt_pointer_path.read_text(encoding="utf-8", errors="strict") == "y\n"
    assert open_verdict_pointer_path.read_text(encoding="utf-8", errors="strict") == "z\n"
    assert open_evidence_pointer_path.read_text(encoding="utf-8", errors="strict") == "w\n"
    assert waiver_path.read_text(encoding="utf-8", errors="strict") == "{\"x\":1}\n"

    rc3 = belgi_main(["run", "new", "--repo", str(tmp_path), "--run-id", run_id, "--force"])
    assert rc3 == 0
    assert intent_path.read_bytes() == baseline["intent"]
    assert runbook_template_path.read_bytes() == baseline["runbook_template"]
    assert tolerances_path.read_bytes() == baseline["tolerances"]
    assert toolchain_path.read_bytes() == baseline["toolchain"]
    assert run_key_pointer_path.read_bytes() == baseline["run_key_pointer"]
    assert last_attempt_pointer_path.read_bytes() == baseline["last_attempt_pointer"]
    assert open_verdict_pointer_path.read_bytes() == baseline["open_verdict_pointer"]
    assert open_evidence_pointer_path.read_bytes() == baseline["open_evidence_pointer"]
    assert waiver_path.read_text(encoding="utf-8", errors="strict") == "{\"x\":1}\n"


def test_init_creates_operator_readme_with_required_sections(tmp_path: Path) -> None:
    assert belgi_main(["init", "--repo", str(tmp_path)]) == 0
    readme_path = tmp_path / ".belgi" / "README.md"
    assert readme_path.is_file()

    text = readme_path.read_text(encoding="utf-8", errors="strict")
    assert "## Quickstart" in text
    assert "belgi init --repo ." in text
    assert "belgi run new --repo . --run-id run-001" in text
    assert "belgi run --repo . --tier tier-1 --intent-spec .belgi/runs/run-001/inputs/intent/IntentSpec.core.md --base-revision <SHA40>" in text
    assert "belgi verify --repo ." in text
    assert "## Layout map" in text
    assert ".belgi/runs/<run_id>/" in text
    assert ".belgi/store/runs/<run_key>/<attempt_id>/" in text
    assert "open_verdict.txt" in text
    assert "open_evidence.txt" in text
    assert "## On NO-GO" in text
    assert "gate_verdict_path" in text
    assert "evidence_manifest_path" in text
    assert "remediation.next_instruction" in text
    assert "## What this is" in text
    assert "## What this is not" in text


def test_init_rewrites_operator_readme_deterministically(tmp_path: Path) -> None:
    assert belgi_main(["init", "--repo", str(tmp_path)]) == 0
    readme_path = tmp_path / ".belgi" / "README.md"
    baseline = readme_path.read_bytes()
    assert b"\r\n" not in baseline

    readme_path.write_text("drifted-content\n", encoding="utf-8", errors="strict", newline="\n")
    assert belgi_main(["init", "--repo", str(tmp_path)]) == 0
    repaired = readme_path.read_bytes()
    assert repaired == baseline

    hash_before = sha256_bytes(repaired)
    assert belgi_main(["init", "--repo", str(tmp_path)]) == 0
    hash_after = sha256_bytes(readme_path.read_bytes())
    assert hash_after == hash_before


def test_run_new_layout_no_intentspec_md(tmp_path: Path) -> None:
    rc_init = belgi_main(["init", "--repo", str(tmp_path)])
    assert rc_init == 0

    run_id = "run-layout-001"
    rc_new = belgi_main(["run", "new", "--repo", str(tmp_path), "--run-id", run_id])
    assert rc_new == 0

    run_dir = tmp_path / ".belgi" / "runs" / run_id
    assert not (run_dir / "IntentSpec.md").exists()
    assert (run_dir / "inputs" / "intent" / "IntentSpec.core.md").is_file()
    assert (run_dir / "inputs" / "waivers").is_dir()
    assert (run_dir / "RUN.md").is_file()
    assert (run_dir / "run_key.txt").is_file()
    assert (run_dir / "last_attempt.txt").is_file()
    assert (run_dir / "open_verdict.txt").is_file()
    assert (run_dir / "open_evidence.txt").is_file()
    assert not (run_dir / "inputs" / "waivers_applied.json").exists()
    assert not (run_dir / "EvidenceManifest.json").exists()


def test_run_new_force_restores_runbook_template(tmp_path: Path) -> None:
    rc_init = belgi_main(["init", "--repo", str(tmp_path)])
    assert rc_init == 0

    run_id = "run-layout-force-001"
    run_dir = tmp_path / ".belgi" / "runs" / run_id
    runbook_path = run_dir / "RUN.md"

    rc_new = belgi_main(["run", "new", "--repo", str(tmp_path), "--run-id", run_id])
    assert rc_new == 0
    baseline = runbook_path.read_text(encoding="utf-8", errors="strict")

    runbook_path.write_text("custom-runbook\n", encoding="utf-8", errors="strict", newline="\n")
    rc_force = belgi_main(["run", "new", "--repo", str(tmp_path), "--run-id", run_id, "--force"])
    assert rc_force == 0
    assert runbook_path.read_text(encoding="utf-8", errors="strict") == baseline


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


def test_manifest_add_rejects_noncanonical_relpath(tmp_path: Path) -> None:
    run_id = "run-demo-001"
    manifest_path = tmp_path / ".belgi" / "runs" / run_id / "EvidenceManifest.json"
    _seed_min_manifest(manifest_path, run_id=run_id)
    artifact_path = tmp_path / ".belgi" / "runs" / run_id / "artifacts" / "policy.overlay.json"
    _write_json(artifact_path, {"x": 1})

    rc = belgi_main(
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
    _seed_min_manifest(manifest_path, run_id=run_id)
    artifact_path = tmp_path / ".belgi" / "runs" / run_id / "artifacts" / "policy.overlay.json"
    _write_json(artifact_path, {"x": 1})

    rc = belgi_main(
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
