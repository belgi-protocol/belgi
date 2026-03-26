from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from tests.gates.gate_test_support import REPO_ROOT, _read_json, _run_module, _sha256_hex

pytestmark = pytest.mark.repo_local


def _write_json_rel(root: Path, rel: str, obj: dict) -> None:
    path = root / Path(*rel.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")


def _ed25519_pubkey_hex_from_seed(seed_hex: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return public_key.hex()


def test_seal_bundle_tier2_requires_cryptographic_signature(tmp_path: Path) -> None:
    pub_rel = "temp/seal_pubkey.hex"
    pub_hex = _ed25519_pubkey_hex_from_seed("12" * 32)
    pub_bytes = (pub_hex + "\n").encode("utf-8", errors="strict")
    (tmp_path / "temp").mkdir(parents=True, exist_ok=True)
    (tmp_path / "temp" / "seal_pubkey.hex").write_bytes(pub_bytes)
    seal_pubkey_ref = {"id": "seal-pubkey", "hash": _sha256_hex(pub_bytes), "storage_ref": pub_rel}

    _write_json_rel(
        tmp_path,
        "LockedSpec.json",
        {
            "run_id": "test-run",
            "belgi_version": "0.0.0",
            "tier": {"tier_id": "tier-2"},
            "waivers_applied": [],
            "environment_envelope": {"seal_pubkey_ref": seal_pubkey_ref},
        },
    )
    _write_json_rel(tmp_path, "Q.json", {})
    _write_json_rel(tmp_path, "R.json", {})
    _write_json_rel(tmp_path, "Evidence.json", {})

    cp = _run_module(
        "chain.seal_bundle",
        [
            "--repo",
            str(tmp_path),
            "--locked-spec",
            "LockedSpec.json",
            "--gate-q-verdict",
            "Q.json",
            "--gate-r-verdict",
            "R.json",
            "--evidence-manifest",
            "Evidence.json",
            "--final-commit-sha",
            "0" * 40,
            "--sealed-at",
            "2020-01-01T00:00:00+00:00",
            "--signer",
            "test",
            "--out",
            "out/SealManifest.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    assert "Tier-2/3 requires a cryptographic seal signature" in cp.stderr


def test_seal_bundle_tier2_rejects_invalid_precomputed_signature(tmp_path: Path) -> None:
    pub_rel = "temp/seal_pubkey.hex"
    pub_hex = _ed25519_pubkey_hex_from_seed("34" * 32)
    pub_bytes = (pub_hex + "\n").encode("utf-8", errors="strict")
    (tmp_path / "temp").mkdir(parents=True, exist_ok=True)
    (tmp_path / "temp" / "seal_pubkey.hex").write_bytes(pub_bytes)
    (tmp_path / "temp" / "seal_signature.b64").write_text(
        base64.b64encode(b"\x00" * 64).decode("ascii") + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    seal_pubkey_ref = {"id": "seal-pubkey", "hash": _sha256_hex(pub_bytes), "storage_ref": pub_rel}

    _write_json_rel(
        tmp_path,
        "LockedSpec.json",
        {
            "run_id": "test-run",
            "belgi_version": "0.0.0",
            "tier": {"tier_id": "tier-2"},
            "waivers_applied": [],
            "environment_envelope": {"seal_pubkey_ref": seal_pubkey_ref},
        },
    )
    _write_json_rel(tmp_path, "Q.json", {})
    _write_json_rel(tmp_path, "R.json", {})
    _write_json_rel(tmp_path, "Evidence.json", {})

    cp = _run_module(
        "chain.seal_bundle",
        [
            "--repo",
            str(tmp_path),
            "--locked-spec",
            "LockedSpec.json",
            "--gate-q-verdict",
            "Q.json",
            "--gate-r-verdict",
            "R.json",
            "--evidence-manifest",
            "Evidence.json",
            "--final-commit-sha",
            "0" * 40,
            "--sealed-at",
            "2020-01-01T00:00:00+00:00",
            "--signer",
            "test",
            "--seal-signature-file",
            "temp/seal_signature.b64",
            "--out",
            "out/SealManifest.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    assert "Invalid Ed25519 signature (--seal-signature)" in cp.stderr


def test_seal_bundle_tier2_accepts_private_key_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seed_hex = "56" * 32
    pub_rel = "temp/seal_pubkey.hex"
    pub_hex = _ed25519_pubkey_hex_from_seed(seed_hex)
    pub_bytes = (pub_hex + "\n").encode("utf-8", errors="strict")
    (tmp_path / "temp").mkdir(parents=True, exist_ok=True)
    (tmp_path / "temp" / "seal_pubkey.hex").write_bytes(pub_bytes)
    seal_pubkey_ref = {"id": "seal-pubkey", "hash": _sha256_hex(pub_bytes), "storage_ref": pub_rel}

    _write_json_rel(
        tmp_path,
        "LockedSpec.json",
        {
            "run_id": "test-run",
            "belgi_version": "0.0.0",
            "tier": {"tier_id": "tier-2"},
            "waivers_applied": [],
            "environment_envelope": {"seal_pubkey_ref": seal_pubkey_ref},
        },
    )
    _write_json_rel(tmp_path, "Q.json", {})
    _write_json_rel(tmp_path, "R.json", {})
    _write_json_rel(tmp_path, "Evidence.json", {})

    monkeypatch.setenv("BELGI_TEST_SEAL_PRIVATE_KEY", seed_hex + "\n")
    cp = _run_module(
        "chain.seal_bundle",
        [
            "--repo",
            str(tmp_path),
            "--locked-spec",
            "LockedSpec.json",
            "--gate-q-verdict",
            "Q.json",
            "--gate-r-verdict",
            "R.json",
            "--evidence-manifest",
            "Evidence.json",
            "--final-commit-sha",
            "0" * 40,
            "--sealed-at",
            "2020-01-01T00:00:00+00:00",
            "--signer",
            "test",
            "--seal-private-key-env",
            "BELGI_TEST_SEAL_PRIVATE_KEY",
            "--out",
            "out/SealManifest.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)
    manifest = _read_json(tmp_path / "out" / "SealManifest.json")
    assert manifest.get("signature_alg") == "ed25519"
    assert isinstance(manifest.get("signature"), str) and bool(str(manifest["signature"]).strip())
