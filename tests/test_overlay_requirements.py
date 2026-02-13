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

from belgi.adopter_overlay import evaluate_overlay_requirements
from belgi.cli import main as belgi_main
from belgi.core.hash import sha256_bytes
from belgi.protocol.pack import get_builtin_protocol_context


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8", errors="strict")


def test_overlay_pin_mismatch_fails_deterministically(tmp_path: Path) -> None:
    protocol = get_builtin_protocol_context()
    overlay_path = tmp_path / "belgi_pack" / "DomainPackManifest.json"
    _write_json(
        overlay_path,
        {
            "format_version": 1,
            "pack_name": "adopter-overlay",
            "pack_semver": "0.1.0",
            "belgi_protocol_pack_pin": {
                "pack_name": protocol.pack_name,
                "pack_id": "0" * 64,
                "manifest_sha256": protocol.manifest_sha256,
            },
            "required_policy_check_ids": [],
        },
    )

    failure = evaluate_overlay_requirements(
        overlay_manifest_path=overlay_path,
        repo_root=tmp_path,
        active_pack_name=protocol.pack_name,
        active_pack_id=protocol.pack_id,
        active_manifest_sha256=protocol.manifest_sha256,
        evidence_manifest={"artifacts": []},
        policy_payload_schema=json.loads((REPO_ROOT / "schemas" / "PolicyReportPayload.schema.json").read_text(encoding="utf-8", errors="strict")),
    )
    assert failure is not None
    assert failure.reason == "pin_mismatch"
    assert "pack_id" in failure.message


def test_overlay_required_policy_check_missing_fails_deterministically(tmp_path: Path) -> None:
    protocol = get_builtin_protocol_context()

    policy_payload = {
        "schema_version": "1.0.0",
        "run_id": "run-1",
        "generated_at": "1970-01-01T00:00:00Z",
        "summary": {"total_checks": 1, "passed": 1, "failed": 0},
        "checks": [{"check_id": "SOME-OTHER-CHECK", "passed": True}],
    }
    policy_path = tmp_path / "artifacts" / "policy_report.json"
    _write_json(policy_path, policy_payload)
    policy_hash = sha256_bytes(policy_path.read_bytes())

    evidence_manifest = {
        "artifacts": [
            {
                "kind": "policy_report",
                "id": "policy.custom",
                "hash": policy_hash,
                "media_type": "application/json",
                "storage_ref": "artifacts/policy_report.json",
                "produced_by": "R",
            }
        ]
    }

    overlay_path = tmp_path / "belgi_pack" / "DomainPackManifest.json"
    _write_json(
        overlay_path,
        {
            "format_version": 1,
            "pack_name": "adopter-overlay",
            "pack_semver": "0.1.0",
            "belgi_protocol_pack_pin": {
                "pack_name": protocol.pack_name,
                "pack_id": protocol.pack_id,
                "manifest_sha256": protocol.manifest_sha256,
            },
            "required_policy_check_ids": ["REQ-CHECK-001"],
        },
    )

    failure = evaluate_overlay_requirements(
        overlay_manifest_path=overlay_path,
        repo_root=tmp_path,
        active_pack_name=protocol.pack_name,
        active_pack_id=protocol.pack_id,
        active_manifest_sha256=protocol.manifest_sha256,
        evidence_manifest=evidence_manifest,
        policy_payload_schema=json.loads((REPO_ROOT / "schemas" / "PolicyReportPayload.schema.json").read_text(encoding="utf-8", errors="strict")),
    )
    assert failure is not None
    assert failure.reason == "missing_required_check"
    assert "REQ-CHECK-001" in failure.message


def test_belgi_init_is_idempotent(tmp_path: Path) -> None:
    rc1 = belgi_main(["init", "--repo", str(tmp_path)])
    assert rc1 == 0

    adopter_toml = tmp_path / ".belgi" / "adopter.toml"
    adopter_readme = tmp_path / ".belgi" / "README.md"
    intent_template = tmp_path / ".belgi" / "templates" / "IntentSpec.core.template.md"
    overlay_manifest = tmp_path / "belgi_pack" / "DomainPackManifest.json"
    assert adopter_toml.exists()
    assert adopter_readme.exists()
    assert intent_template.exists()
    assert overlay_manifest.exists()

    baseline = {
        "adopter_toml": adopter_toml.read_bytes(),
        "adopter_readme": adopter_readme.read_bytes(),
        "intent_template": intent_template.read_bytes(),
        "overlay_manifest": overlay_manifest.read_bytes(),
    }

    rc2 = belgi_main(["init", "--repo", str(tmp_path)])
    assert rc2 == 0

    assert adopter_toml.read_bytes() == baseline["adopter_toml"]
    assert adopter_readme.read_bytes() == baseline["adopter_readme"]
    assert intent_template.read_bytes() == baseline["intent_template"]
    assert overlay_manifest.read_bytes() == baseline["overlay_manifest"]


def test_belgi_init_pin_drift_requires_refresh_pin(tmp_path: Path) -> None:
    protocol = get_builtin_protocol_context()
    rc1 = belgi_main(["init", "--repo", str(tmp_path)])
    assert rc1 == 0

    stale_pack_id = "f" * 64 if protocol.pack_id != ("f" * 64) else ("e" * 64)
    adopter_toml = tmp_path / ".belgi" / "adopter.toml"
    overlay_manifest = tmp_path / "belgi_pack" / "DomainPackManifest.json"

    adopter_text = adopter_toml.read_text(encoding="utf-8", errors="strict")
    adopter_text = adopter_text.replace(protocol.pack_id, stale_pack_id)
    adopter_toml.write_text(adopter_text, encoding="utf-8", errors="strict", newline="\n")

    overlay_obj = json.loads(overlay_manifest.read_text(encoding="utf-8", errors="strict"))
    overlay_obj["belgi_protocol_pack_pin"]["pack_id"] = stale_pack_id
    _write_json(overlay_manifest, overlay_obj)

    rc2 = belgi_main(["init", "--repo", str(tmp_path)])
    assert rc2 == 1
    assert stale_pack_id in adopter_toml.read_text(encoding="utf-8", errors="strict")

    rc3 = belgi_main(["init", "--repo", str(tmp_path), "--refresh-pin"])
    assert rc3 == 0
    refreshed_toml = adopter_toml.read_text(encoding="utf-8", errors="strict")
    assert protocol.pack_id in refreshed_toml
    assert stale_pack_id not in refreshed_toml
    refreshed_overlay = json.loads(overlay_manifest.read_text(encoding="utf-8", errors="strict"))
    assert refreshed_overlay["belgi_protocol_pack_pin"]["pack_id"] == protocol.pack_id


def test_overlay_policy_report_symlink_rejected(tmp_path: Path) -> None:
    protocol = get_builtin_protocol_context()

    policy_payload = {
        "schema_version": "1.0.0",
        "run_id": "run-1",
        "generated_at": "1970-01-01T00:00:00Z",
        "summary": {"total_checks": 1, "passed": 1, "failed": 0},
        "checks": [{"check_id": "REQ-CHECK-001", "passed": True}],
    }
    policy_target = tmp_path / "artifacts" / "policy_report_target.json"
    _write_json(policy_target, policy_payload)
    policy_link = tmp_path / "artifacts" / "policy_report.json"
    try:
        policy_link.symlink_to(policy_target.name)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"symlink creation not supported in this test environment: {e}")

    evidence_manifest = {
        "artifacts": [
            {
                "kind": "policy_report",
                "id": "policy.custom",
                "hash": sha256_bytes(policy_target.read_bytes()),
                "media_type": "application/json",
                "storage_ref": "artifacts/policy_report.json",
                "produced_by": "R",
            }
        ]
    }

    overlay_path = tmp_path / "belgi_pack" / "DomainPackManifest.json"
    _write_json(
        overlay_path,
        {
            "format_version": 1,
            "pack_name": "adopter-overlay",
            "pack_semver": "0.1.0",
            "belgi_protocol_pack_pin": {
                "pack_name": protocol.pack_name,
                "pack_id": protocol.pack_id,
                "manifest_sha256": protocol.manifest_sha256,
            },
            "required_policy_check_ids": ["REQ-CHECK-001"],
        },
    )

    failure = evaluate_overlay_requirements(
        overlay_manifest_path=overlay_path,
        repo_root=tmp_path,
        active_pack_name=protocol.pack_name,
        active_pack_id=protocol.pack_id,
        active_manifest_sha256=protocol.manifest_sha256,
        evidence_manifest=evidence_manifest,
        policy_payload_schema=json.loads((REPO_ROOT / "schemas" / "PolicyReportPayload.schema.json").read_text(encoding="utf-8", errors="strict")),
    )
    assert failure is not None
    assert failure.reason == "policy_report_invalid"
    assert "symlink" in failure.message
