from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from belgi.core.hash import sha256_bytes
from belgi.protocol.pack import get_builtin_protocol_context
import belgi.trust_anchor as trust_anchor
from belgi.trust_anchor import (
    TrustAnchorError,
    load_pinned_trust_anchor,
    render_trust_anchor_bytes,
    validate_genesis_seal_payload,
    validate_genesis_seal_schema,
    validate_trust_anchor_bytes,
)
from chain.logic.r_checks.context import RCheckContext
from chain.logic.r_checks.r4_schema_contract import _enforce_genesis_seal
import chain.logic.r_checks.r4_schema_contract as r4_schema_contract
import tools.report as report_tool


def _fixture_anchor_material() -> tuple[dict[str, str], str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public_key = private_key.public_key()
    payload = {
        "schema_version": "1.0.0",
        "philosophy": "Fixture philosophy",
        "dedication": "Fixture dedication",
        "architect": "Fixture architect",
    }
    signed_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8", errors="strict"
    )
    signature = base64.b64encode(private_key.sign(signed_bytes)).decode("ascii")
    public_key_hex = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return payload, public_key_hex, signature


def _fixture_anchor_bytes(
    *,
    payload: dict[str, str] | None = None,
    public_key_hex: str | None = None,
    signature: str | None = None,
) -> tuple[bytes, str]:
    default_payload, default_public_key_hex, default_signature = _fixture_anchor_material()
    anchor_bytes = render_trust_anchor_bytes(
        anchor_payload=payload or default_payload,
        public_key_hex=public_key_hex or default_public_key_hex,
        signature_alg="ed25519",
        signature=signature or default_signature,
        schema_version="1.0.0",
    )
    return anchor_bytes, sha256_bytes(anchor_bytes)


def _mutate_string(value: str) -> str:
    if not value:
        raise ValueError("cannot mutate empty string")
    chars = list(value)
    chars[0] = "0" if chars[0] != "0" else "1"
    return "".join(chars)


def test_fixture_trust_anchor_validates() -> None:
    anchor_bytes, expected_sha256 = _fixture_anchor_bytes()
    authority = validate_trust_anchor_bytes(anchor_bytes, expected_sha256=expected_sha256)
    assert authority.signature_alg == "ed25519"
    assert authority.anchor_payload["architect"] == "Fixture architect"


def test_fixture_trust_anchor_wrong_signature_fails() -> None:
    payload, public_key_hex, signature = _fixture_anchor_material()
    bad_signature = _mutate_string(signature)
    anchor_bytes, expected_sha256 = _fixture_anchor_bytes(
        payload=payload,
        public_key_hex=public_key_hex,
        signature=bad_signature,
    )
    with pytest.raises(TrustAnchorError, match="signature verification failed"):
        validate_trust_anchor_bytes(anchor_bytes, expected_sha256=expected_sha256)


def test_fixture_trust_anchor_wrong_public_key_fails() -> None:
    payload, public_key_hex, signature = _fixture_anchor_material()
    bad_public_key_hex = _mutate_string(public_key_hex)
    anchor_bytes, expected_sha256 = _fixture_anchor_bytes(
        payload=payload,
        public_key_hex=bad_public_key_hex,
        signature=signature,
    )
    with pytest.raises(TrustAnchorError, match="signature verification failed"):
        validate_trust_anchor_bytes(anchor_bytes, expected_sha256=expected_sha256)


def test_fixture_trust_anchor_field_drift_fails() -> None:
    payload, public_key_hex, signature = _fixture_anchor_material()
    drifted_payload = dict(payload)
    drifted_payload["architect"] = "Drifted architect"
    anchor_bytes, expected_sha256 = _fixture_anchor_bytes(
        payload=drifted_payload,
        public_key_hex=public_key_hex,
        signature=signature,
    )
    with pytest.raises(TrustAnchorError, match="signature verification failed"):
        validate_trust_anchor_bytes(anchor_bytes, expected_sha256=expected_sha256)


def test_fixture_trust_anchor_digest_mismatch_fails_before_semantic_use() -> None:
    anchor_bytes, expected_sha256 = _fixture_anchor_bytes()
    mutated_bytes = anchor_bytes.replace(b"Fixture philosophy", b"Fixture philosophy!")
    with pytest.raises(TrustAnchorError, match="sha256\\(bytes\\) mismatch vs pinned TrustAnchor digest"):
        validate_trust_anchor_bytes(mutated_bytes, expected_sha256=expected_sha256)


def test_verifier_and_report_share_trust_anchor_logic() -> None:
    import belgi.trust_anchor as trust_anchor

    trust_anchor_path = Path(trust_anchor.__file__).resolve()

    assert Path(r4_schema_contract.load_pinned_trust_anchor.__code__.co_filename).resolve() == trust_anchor_path
    assert Path(r4_schema_contract.validate_genesis_seal_payload.__code__.co_filename).resolve() == trust_anchor_path
    assert Path(report_tool.load_pinned_trust_anchor.__code__.co_filename).resolve() == trust_anchor_path
    assert Path(report_tool.validate_genesis_seal_schema.__code__.co_filename).resolve() == trust_anchor_path
    assert Path(report_tool.validate_genesis_seal_payload.__code__.co_filename).resolve() == trust_anchor_path


def test_legacy_genesis_payload_cannot_act_as_canonical_authority(tmp_path: Path) -> None:
    legacy_dir = tmp_path / "belgi" / "genesis"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    (legacy_dir / "GenesisSealPayload.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "philosophy": "legacy",
                "dedication": "legacy",
                "architect": "legacy",
                "signature_alg": "ed25519",
                "signature": "AAAA",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        errors="strict",
    )

    with pytest.raises(TrustAnchorError, match="failed to load canonical Tier-3 trust anchor"):
        load_pinned_trust_anchor(tmp_path)


def test_tier2_has_no_genesis_requirement() -> None:
    ctx = RCheckContext(
        repo_root=REPO_ROOT,
        protocol=get_builtin_protocol_context(),
        locked_spec_path=REPO_ROOT / "policy" / "fixtures" / "public" / "gate_r" / "r_pass_tier1" / "LockedSpec.json",
        evidence_manifest_path=REPO_ROOT / "policy" / "fixtures" / "public" / "gate_r" / "r_pass_tier1" / "EvidenceManifest.json",
        gate_verdict_path=None,
        locked_spec={"tier": {"tier_id": "tier-2"}},
        evidence_manifest={"artifacts": []},
        gate_verdict=None,
        tier_params={},
        evaluated_revision="HEAD",
        upstream_commit_sha="a" * 40,
        policy_payload_schema={},
        test_payload_schema={},
        required_policy_report_ids=[],
        required_test_report_id="tests.report",
    )

    ok, results = _enforce_genesis_seal(ctx, em_ptr="EvidenceManifest.json")
    assert ok is True
    assert results == []


def test_genesis_seal_payload_validates_under_fixture_authority() -> None:
    anchor_bytes, expected_sha256 = _fixture_anchor_bytes()
    authority = validate_trust_anchor_bytes(anchor_bytes, expected_sha256=expected_sha256)
    payload = authority.expected_genesis_seal_payload()
    validate_genesis_seal_schema(payload)
    validate_genesis_seal_payload(payload, authority=authority)


def test_report_rejects_schema_invalid_genesis_seal_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload, expected_sha256 = _write_fixture_trust_anchor_repo(tmp_path)
    monkeypatch.setattr(trust_anchor, "PINNED_TRUST_ANCHOR_SHA256", expected_sha256)

    invalid_payload = dict(payload)
    invalid_payload["unexpected"] = "extra"
    payload_path = tmp_path / "artifacts" / "genesis-seal.invalid.json"
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    payload_bytes = (json.dumps(invalid_payload, indent=2) + "\n").encode("utf-8", errors="strict")
    payload_path.write_bytes(payload_bytes)

    with pytest.raises(report_tool._UserInputError, match="payload schema invalid"):
        report_tool._extract_genesis_from_evidence(
            tmp_path,
            {"tier": {"tier_id": "tier-3"}},
            {
                "artifacts": [
                    {
                        "kind": "genesis_seal",
                        "id": "genesis.seal",
                        "hash": sha256_bytes(payload_bytes),
                        "media_type": "application/json",
                        "storage_ref": "artifacts/genesis-seal.invalid.json",
                        "produced_by": "R",
                    }
                ]
            },
        )


def _write_fixture_trust_anchor_repo(tmp_path: Path) -> tuple[dict[str, str], str]:
    anchor_bytes, expected_sha256 = _fixture_anchor_bytes()
    trust_anchor_path = tmp_path / "belgi" / "anchor" / "v1" / "TrustAnchor.json"
    trust_anchor_path.parent.mkdir(parents=True, exist_ok=True)
    trust_anchor_path.write_bytes(anchor_bytes)

    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir(parents=True, exist_ok=True)
    (schema_dir / "TrustAnchor.schema.json").write_bytes((REPO_ROOT / "schemas" / "TrustAnchor.schema.json").read_bytes())

    authority = validate_trust_anchor_bytes(anchor_bytes, expected_sha256=expected_sha256)
    return authority.expected_genesis_seal_payload(), expected_sha256


def test_r4_accepts_tier3_genesis_under_canonical_trust_anchor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload, expected_sha256 = _write_fixture_trust_anchor_repo(tmp_path)
    monkeypatch.setattr(trust_anchor, "PINNED_TRUST_ANCHOR_SHA256", expected_sha256)

    payload_path = tmp_path / "artifacts" / "genesis-seal.json"
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    payload_bytes = (json.dumps(payload, indent=2) + "\n").encode("utf-8", errors="strict")
    payload_path.write_bytes(payload_bytes)

    ctx = RCheckContext(
        repo_root=tmp_path,
        protocol=get_builtin_protocol_context(),
        locked_spec_path=tmp_path / "LockedSpec.json",
        evidence_manifest_path=tmp_path / "EvidenceManifest.json",
        gate_verdict_path=None,
        locked_spec={"tier": {"tier_id": "tier-3"}},
        evidence_manifest={
            "artifacts": [
                {
                    "kind": "genesis_seal",
                    "id": "genesis.seal",
                    "hash": sha256_bytes(payload_bytes),
                    "media_type": "application/json",
                    "storage_ref": "artifacts/genesis-seal.json",
                    "produced_by": "R",
                }
            ]
        },
        gate_verdict=None,
        tier_params={},
        evaluated_revision="HEAD",
        upstream_commit_sha="a" * 40,
        policy_payload_schema={},
        test_payload_schema={},
        required_policy_report_ids=[],
        required_test_report_id="tests.report",
    )

    ok, results = _enforce_genesis_seal(ctx, em_ptr="EvidenceManifest.json")
    assert ok is True
    assert results == []


def test_report_extracts_tier3_genesis_only_after_trust_anchor_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload, expected_sha256 = _write_fixture_trust_anchor_repo(tmp_path)
    monkeypatch.setattr(trust_anchor, "PINNED_TRUST_ANCHOR_SHA256", expected_sha256)

    payload_path = tmp_path / "artifacts" / "genesis-seal.json"
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    payload_bytes = (json.dumps(payload, indent=2) + "\n").encode("utf-8", errors="strict")
    payload_path.write_bytes(payload_bytes)

    fields, declared_hash = report_tool._extract_genesis_from_evidence(
        tmp_path,
        {"tier": {"tier_id": "tier-3"}},
        {
            "artifacts": [
                {
                    "kind": "genesis_seal",
                    "id": "genesis.seal",
                    "hash": sha256_bytes(payload_bytes),
                    "media_type": "application/json",
                    "storage_ref": "artifacts/genesis-seal.json",
                    "produced_by": "R",
                }
            ]
        },
    )

    assert fields["architect"] == "Fixture architect"
    assert declared_hash == sha256_bytes(payload_bytes)
