from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.cli import main as belgi_main
from belgi.commands.policy_stub import DEFAULT_GENERATED_AT
from belgi.core.hash import sha256_bytes
from belgi.core.schema import validate_schema
from belgi.protocol.pack import get_builtin_protocol_context


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def test_policy_stub_cli_writes_schema_valid_json(tmp_path: Path) -> None:
    out_path = tmp_path / "policy" / "policy.overlay.json"
    rc = belgi_main(
        [
            "policy",
            "stub",
            "--out",
            str(out_path),
            "--run-id",
            "run-demo-001",
            "--check-id",
            "B-CHECK",
            "--check-id",
            "A-CHECK",
            "--check-id",
            "A-CHECK",
        ]
    )
    assert rc == 0

    data = out_path.read_bytes()
    payload = json.loads(data.decode("utf-8", errors="strict"))
    assert payload["schema_version"] == "1.0.0"
    assert payload["run_id"] == "run-demo-001"
    assert payload["generated_at"] == DEFAULT_GENERATED_AT
    assert payload["summary"] == {"failed": 0, "passed": 2, "total_checks": 2}
    assert payload["checks"] == [
        {"check_id": "A-CHECK", "passed": True},
        {"check_id": "B-CHECK", "passed": True},
    ]

    schema = json.loads((REPO_ROOT / "schemas" / "PolicyReportPayload.schema.json").read_text(encoding="utf-8", errors="strict"))
    errs = validate_schema(payload, schema, root_schema=schema, path="policy_report")
    assert errs == []


def test_policy_stub_cli_is_deterministic_on_repeat(tmp_path: Path) -> None:
    out_path = tmp_path / "policy.json"
    args = [
        "policy",
        "stub",
        "--out",
        str(out_path),
        "--run-id",
        "run-demo-001",
        "--check-id",
        "PFY-OVERLAY-001",
        "--generated-at",
        "1970-01-01T00:00:00Z",
    ]
    rc1 = belgi_main(args)
    assert rc1 == 0
    first = out_path.read_bytes()

    rc2 = belgi_main(args)
    assert rc2 == 0
    second = out_path.read_bytes()
    assert first == second


def test_policy_stub_cli_missing_check_id_is_nonzero(tmp_path: Path) -> None:
    out_path = tmp_path / "policy.json"
    rc = belgi_main(
        [
            "policy",
            "stub",
            "--out",
            str(out_path),
            "--run-id",
            "run-demo-001",
        ]
    )
    assert rc != 0


def test_policy_check_overlay_cli_fail_then_pass(tmp_path: Path) -> None:
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
                "pack_id": protocol.pack_id,
                "manifest_sha256": protocol.manifest_sha256,
            },
            "required_policy_check_ids": ["PFY-OVERLAY-001"],
        },
    )

    manifest_path = tmp_path / "EvidenceManifest.json"
    _write_json(
        manifest_path,
        {
            "schema_version": "1.0.0",
            "run_id": "run-demo-001",
            "artifacts": [],
            "commands_executed": [],
            "envelope_attestation": None,
        },
    )

    rc_fail = belgi_main(
        [
            "policy",
            "check-overlay",
            "--repo",
            str(tmp_path),
            "--evidence-manifest",
            "EvidenceManifest.json",
            "--overlay",
            "belgi_pack",
        ]
    )
    assert rc_fail == 2

    artifact_path = tmp_path / "artifacts" / "policy.overlay.json"
    rc_stub = belgi_main(
        [
            "policy",
            "stub",
            "--out",
            str(artifact_path),
            "--run-id",
            "run-demo-001",
            "--check-id",
            "PFY-OVERLAY-001",
        ]
    )
    assert rc_stub == 0

    manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="strict"))
    artifacts = manifest.get("artifacts")
    assert isinstance(artifacts, list)
    artifact_bytes = artifact_path.read_bytes()
    artifacts.append(
        {
            "kind": "policy_report",
            "id": "policy.portfoly_overlay",
            "hash": sha256_bytes(artifact_bytes),
            "media_type": "application/json",
            "storage_ref": "artifacts/policy.overlay.json",
            "produced_by": "R",
        }
    )
    _write_json(manifest_path, manifest)

    rc_pass = belgi_main(
        [
            "policy",
            "check-overlay",
            "--repo",
            str(tmp_path),
            "--evidence-manifest",
            "EvidenceManifest.json",
            "--overlay",
            "belgi_pack",
        ]
    )
    assert rc_pass == 0
