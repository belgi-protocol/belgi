"""Integration tests: tools/belgi_tools.py verify-attestation signing satisfies Gate R R6.

These are ENGINE-only tests: we generate a real env_attestation artifact via the
operator CLI and feed it into the R6 check function.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _run_tool(*, tmp_repo: Path, argv: list[str], check: bool = True) -> subprocess.CompletedProcess[bytes]:
    tool = REPO_ROOT / "tools" / "belgi_tools.py"
    return subprocess.run([sys.executable, str(tool), *argv], cwd=tmp_repo, check=check, capture_output=True)


def _make_keypair_hex(seed_hex: str) -> tuple[str, bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    pk = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return pk.hex(), pk


def _build_ctx(*, tmp_repo: Path, command_log_storage_ref: str, env_att_storage_ref: str, locked_spec: dict) -> object:
    from belgi.core.hash import sha256_bytes
    from belgi.protocol.pack import get_builtin_protocol_context
    from chain.logic.r_checks.context import RCheckContext

    protocol = get_builtin_protocol_context()

    cmd_log_path = tmp_repo / Path(*command_log_storage_ref.split("/"))
    env_att_path = tmp_repo / Path(*env_att_storage_ref.split("/"))

    cmd_hash = sha256_bytes(cmd_log_path.read_bytes())
    env_bytes = env_att_path.read_bytes()
    env_hash = sha256_bytes(env_bytes)

    env_obj = json.loads(env_bytes.decode("utf-8", errors="strict"))
    attestation_id = env_obj.get("attestation_id")
    assert isinstance(attestation_id, str) and attestation_id

    evidence_manifest = {
        "schema_version": "1.0.0",
        "run_id": locked_spec.get("run_id", "run-test-001"),
        "artifacts": [
            {
                "kind": "command_log",
                "id": "command.log",
                "hash": cmd_hash,
                "media_type": "text/plain",
                "storage_ref": command_log_storage_ref,
                "produced_by": "R",
            },
            {
                "kind": "env_attestation",
                "id": attestation_id,
                "hash": env_hash,
                "media_type": "application/json",
                "storage_ref": env_att_storage_ref,
                "produced_by": "R",
            },
        ],
        "commands_executed": ["belgi verify-attestation"],
        "envelope_attestation": {
            "id": attestation_id,
            "hash": env_hash,
            "storage_ref": env_att_storage_ref,
        },
    }

    return RCheckContext(
        repo_root=tmp_repo,
        protocol=protocol,
        locked_spec_path=tmp_repo / "LockedSpec.json",
        evidence_manifest_path=tmp_repo / "EvidenceManifest.json",
        gate_verdict_path=None,
        locked_spec=locked_spec,
        evidence_manifest=evidence_manifest,
        gate_verdict=None,
        tier_params={
            "command_log_mode": "strings",
            "envelope_policy.requires_attestation": "yes",
            "envelope_policy.attestation_signature_required": "yes",
        },
        evaluated_revision="0" * 40,
        upstream_commit_sha="0" * 40,
        policy_payload_schema=protocol.read_json("schemas/PolicyReportPayload.schema.json"),
        test_payload_schema=protocol.read_json("schemas/TestReportPayload.schema.json"),
        required_policy_report_ids=[],
        required_test_report_id="tests.report",
    )


class TestR6AttestationSigningIntegration:
    def test_verify_attestation_requires_key_when_tier_requires(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()

        (tmp_repo / "out").mkdir(parents=True, exist_ok=True)
        (tmp_repo / "out" / "command.log").write_text("belgi verify-attestation\n", encoding="utf-8", newline="\n")

        seed = "11" * 32
        pub_hex, pub_bytes = _make_keypair_hex(seed)
        (tmp_repo / "out" / "attestation_pubkey.hex").write_text(pub_hex + "\n", encoding="utf-8", newline="\n")

        from belgi.core.hash import sha256_bytes

        locked_spec = {
            "run_id": "run-test-001",
            "tier": {"tier_id": "tier-2"},
            "environment_envelope": {
                "attestation_pubkey_ref": {
                    "id": "env.attestation_pubkey",
                    "hash": sha256_bytes((tmp_repo / "out" / "attestation_pubkey.hex").read_bytes()),
                    "storage_ref": "out/attestation_pubkey.hex",
                }
            },
        }
        (tmp_repo / "LockedSpec.json").write_text(json.dumps(locked_spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        # No key -> NO-GO (exit 3).
        p = _run_tool(
            tmp_repo=tmp_repo,
            argv=[
                "verify-attestation",
                "--repo",
                str(tmp_repo),
                "--run-id",
                "run-test-001",
                "--command-log",
                "out/command.log",
                "--locked-spec",
                "LockedSpec.json",
                "--out",
                "out/env_attestation.json",
                "--deterministic",
            ],
            check=False,
        )
        assert p.returncode == 3

    def test_r6_passes_with_valid_signature(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()

        (tmp_repo / "out").mkdir(parents=True, exist_ok=True)
        (tmp_repo / "out" / "command.log").write_text("belgi verify-attestation\n", encoding="utf-8", newline="\n")

        seed = "22" * 32
        pub_hex, pub_bytes = _make_keypair_hex(seed)
        (tmp_repo / "out" / "attestation_pubkey.hex").write_text(pub_hex + "\n", encoding="utf-8", newline="\n")

        from belgi.core.hash import sha256_bytes

        locked_spec = {
            "run_id": "run-test-001",
            "tier": {"tier_id": "tier-2"},
            "environment_envelope": {
                "attestation_pubkey_ref": {
                    "id": "env.attestation_pubkey",
                    "hash": sha256_bytes((tmp_repo / "out" / "attestation_pubkey.hex").read_bytes()),
                    "storage_ref": "out/attestation_pubkey.hex",
                }
            },
        }
        (tmp_repo / "LockedSpec.json").write_text(json.dumps(locked_spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        _run_tool(
            tmp_repo=tmp_repo,
            argv=[
                "verify-attestation",
                "--repo",
                str(tmp_repo),
                "--run-id",
                "run-test-001",
                "--command-log",
                "out/command.log",
                "--locked-spec",
                "LockedSpec.json",
                "--signing-key",
                seed,
                "--out",
                "out/env_attestation.json",
                "--deterministic",
            ],
        )

        from chain.logic.r_checks import r6_attestation as r6

        ctx = _build_ctx(
            tmp_repo=tmp_repo,
            command_log_storage_ref="out/command.log",
            env_att_storage_ref="out/env_attestation.json",
            locked_spec=locked_spec,
        )

        results = r6.run(ctx)
        assert len(results) == 1
        assert results[0].status == "PASS"

    def test_r6_fails_on_tampered_signature(self, tmp_path: Path) -> None:
        tmp_repo = tmp_path / "repo"
        tmp_repo.mkdir()

        (tmp_repo / "out").mkdir(parents=True, exist_ok=True)
        (tmp_repo / "out" / "command.log").write_text("belgi verify-attestation\n", encoding="utf-8", newline="\n")

        seed = "33" * 32
        pub_hex, pub_bytes = _make_keypair_hex(seed)
        (tmp_repo / "out" / "attestation_pubkey.hex").write_text(pub_hex + "\n", encoding="utf-8", newline="\n")

        from belgi.core.hash import sha256_bytes

        locked_spec = {
            "run_id": "run-test-001",
            "tier": {"tier_id": "tier-2"},
            "environment_envelope": {
                "attestation_pubkey_ref": {
                    "id": "env.attestation_pubkey",
                    "hash": sha256_bytes((tmp_repo / "out" / "attestation_pubkey.hex").read_bytes()),
                    "storage_ref": "out/attestation_pubkey.hex",
                }
            },
        }
        (tmp_repo / "LockedSpec.json").write_text(json.dumps(locked_spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        _run_tool(
            tmp_repo=tmp_repo,
            argv=[
                "verify-attestation",
                "--repo",
                str(tmp_repo),
                "--run-id",
                "run-test-001",
                "--command-log",
                "out/command.log",
                "--locked-spec",
                "LockedSpec.json",
                "--signing-key",
                seed,
                "--out",
                "out/env_attestation.json",
                "--deterministic",
            ],
        )

        p = tmp_repo / "out" / "env_attestation.json"
        obj = json.loads(p.read_text(encoding="utf-8", errors="strict"))
        assert obj.get("signature")
        # Flip one character deterministically.
        sig = str(obj["signature"])
        obj["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
        p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")

        from chain.logic.r_checks import r6_attestation as r6

        ctx = _build_ctx(
            tmp_repo=tmp_repo,
            command_log_storage_ref="out/command.log",
            env_att_storage_ref="out/env_attestation.json",
            locked_spec=locked_spec,
        )

        results = r6.run(ctx)
        assert len(results) == 1
        assert results[0].status == "FAIL"
        assert results[0].category == "FR-EVIDENCE-ATTESTATION-MISSING"
