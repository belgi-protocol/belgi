from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

from belgi.core.hash import sha256_bytes
from belgi.core.jail import resolve_repo_rel_path
from belgi.core.schema import validate_schema


TRUST_ANCHOR_RELPATH = "belgi/anchor/v1/TrustAnchor.json"
TRUST_ANCHOR_SCHEMA_RELPATH = "schemas/TrustAnchor.schema.json"
GENESIS_SEAL_SCHEMA_RELPATH = "schemas/GenesisSealPayload.schema.json"
_PACKAGED_TRUST_ANCHOR_RELPATH = ("anchor", "v1", "TrustAnchor.json")
_PACKAGED_TRUST_ANCHOR_SCHEMA_RELPATH = ("_protocol_packs", "v1", "schemas", "TrustAnchor.schema.json")
_PACKAGED_GENESIS_SEAL_SCHEMA_RELPATH = ("_protocol_packs", "v1", "schemas", "GenesisSealPayload.schema.json")

TRUST_ANCHOR_SCHEMA_VERSION = "1.0.0"
TRUST_ANCHOR_TOP_LEVEL_ORDER = (
    "schema_version",
    "anchor_payload",
    "public_key_hex",
    "signature_alg",
    "signature",
)
TRUST_ANCHOR_PAYLOAD_ORDER = (
    "schema_version",
    "philosophy",
    "dedication",
    "architect",
)

# SHA-256 over the canonical bytes of belgi/anchor/v1/TrustAnchor.json.
PINNED_TRUST_ANCHOR_SHA256 = "1be22fc6d9a65b43191be64b91b85b145a99d4cb0ac2a2e34b96bcfbd969e98d"


class TrustAnchorError(ValueError):
    """Raised when the canonical Tier-3 trust-anchor contract fails closed."""


@dataclass(frozen=True)
class TrustAnchorAuthority:
    schema_version: str
    anchor_payload: dict[str, str]
    public_key_hex: str
    signature_alg: str
    signature: str
    sha256: str
    source: str

    def expected_genesis_seal_payload(self) -> dict[str, str]:
        return {
            "schema_version": self.anchor_payload["schema_version"],
            "philosophy": self.anchor_payload["philosophy"],
            "dedication": self.anchor_payload["dedication"],
            "architect": self.anchor_payload["architect"],
            "signature_alg": self.signature_alg,
            "signature": self.signature,
        }


def _require_str(obj: dict[str, Any], key: str, *, where: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise TrustAnchorError(f"{where}: missing/invalid '{key}'")
    return value


def _canonical_signed_payload_bytes(anchor_payload: dict[str, Any]) -> bytes:
    # This matches the operator helper: compact, sorted-key JSON bytes, no trailing LF.
    return json.dumps(anchor_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8", errors="strict"
    )


def render_trust_anchor_bytes(
    *,
    anchor_payload: dict[str, Any],
    public_key_hex: str,
    signature_alg: str,
    signature: str,
    schema_version: str,
) -> bytes:
    payload = {
        "schema_version": _require_str(anchor_payload, "schema_version", where="TrustAnchor.anchor_payload"),
        "philosophy": _require_str(anchor_payload, "philosophy", where="TrustAnchor.anchor_payload"),
        "dedication": _require_str(anchor_payload, "dedication", where="TrustAnchor.anchor_payload"),
        "architect": _require_str(anchor_payload, "architect", where="TrustAnchor.anchor_payload"),
    }
    doc = {
        "schema_version": schema_version,
        "anchor_payload": payload,
        "public_key_hex": public_key_hex,
        "signature_alg": signature_alg,
        "signature": signature,
    }
    return (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8", errors="strict")


def _load_ed25519_public_key_from_hex(public_key_hex: str) -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "Missing crypto dependency for Ed25519 verification (install 'cryptography' in the declared Environment Envelope)."
        ) from e

    try:
        public_bytes = bytes.fromhex(public_key_hex)
    except ValueError as e:
        raise TrustAnchorError(f"TrustAnchor.public_key_hex is not valid hex: {e}") from e
    if len(public_bytes) != 32:
        raise TrustAnchorError(
            f"TrustAnchor.public_key_hex must encode exactly 32 raw Ed25519 public-key bytes (got {len(public_bytes)})."
        )
    try:
        return Ed25519PublicKey.from_public_bytes(public_bytes)
    except Exception as e:
        raise TrustAnchorError(f"TrustAnchor.public_key_hex is not a valid Ed25519 public key: {e}") from e


def _read_trust_anchor_bytes(repo_root: Path | None = None) -> tuple[bytes, str]:
    if repo_root is not None:
        anchor_path = resolve_repo_rel_path(
            repo_root,
            TRUST_ANCHOR_RELPATH,
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        return anchor_path.read_bytes(), TRUST_ANCHOR_RELPATH

    traversable = files("belgi").joinpath(*_PACKAGED_TRUST_ANCHOR_RELPATH)
    return traversable.read_bytes(), TRUST_ANCHOR_RELPATH


def _read_trust_anchor_schema(repo_root: Path | None = None) -> dict[str, Any]:
    if repo_root is not None:
        schema_path = resolve_repo_rel_path(
            repo_root,
            TRUST_ANCHOR_SCHEMA_RELPATH,
            must_exist=True,
            must_be_file=True,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        obj = json.loads(schema_path.read_text(encoding="utf-8", errors="strict"))
    else:
        obj = json.loads(
            files("belgi").joinpath(*_PACKAGED_TRUST_ANCHOR_SCHEMA_RELPATH).read_text(encoding="utf-8", errors="strict")
        )
    if not isinstance(obj, dict):
        raise TrustAnchorError("TrustAnchor schema is not a JSON object")
    return obj


def _read_genesis_seal_schema(repo_root: Path | None = None) -> dict[str, Any]:
    if repo_root is not None:
        try:
            schema_path = resolve_repo_rel_path(
                repo_root,
                GENESIS_SEAL_SCHEMA_RELPATH,
                must_exist=True,
                must_be_file=True,
                allow_backslashes=False,
                forbid_symlinks=True,
            )
            obj = json.loads(schema_path.read_text(encoding="utf-8", errors="strict"))
        except Exception:
            obj = json.loads(
                files("belgi")
                .joinpath(*_PACKAGED_GENESIS_SEAL_SCHEMA_RELPATH)
                .read_text(encoding="utf-8", errors="strict")
            )
    else:
        obj = json.loads(
            files("belgi").joinpath(*_PACKAGED_GENESIS_SEAL_SCHEMA_RELPATH).read_text(encoding="utf-8", errors="strict")
        )
    if not isinstance(obj, dict):
        raise TrustAnchorError("GenesisSealPayload schema is not a JSON object")
    return obj


def validate_trust_anchor_bytes(
    anchor_bytes: bytes,
    *,
    expected_sha256: str,
    source: str = TRUST_ANCHOR_RELPATH,
    schema: dict[str, Any] | None = None,
) -> TrustAnchorAuthority:
    actual_sha256 = sha256_bytes(anchor_bytes)
    if actual_sha256 != expected_sha256:
        raise TrustAnchorError(f"{source}: sha256(bytes) mismatch vs pinned TrustAnchor digest")

    try:
        obj = json.loads(anchor_bytes.decode("utf-8", errors="strict"))
    except Exception as e:
        raise TrustAnchorError(f"{source}: invalid UTF-8 JSON: {e}") from e
    if not isinstance(obj, dict):
        raise TrustAnchorError(f"{source}: expected JSON object")

    if schema is not None:
        schema_errs = validate_schema(obj, schema, root_schema=schema, path="TrustAnchor")
        if schema_errs:
            first = schema_errs[0]
            raise TrustAnchorError(f"{source}: schema invalid at {first.path}: {first.message}")

    schema_version = _require_str(obj, "schema_version", where=source)
    anchor_payload = obj.get("anchor_payload")
    if not isinstance(anchor_payload, dict):
        raise TrustAnchorError(f"{source}: missing/invalid 'anchor_payload'")
    public_key_hex = _require_str(obj, "public_key_hex", where=source)
    signature_alg = _require_str(obj, "signature_alg", where=source)
    signature = _require_str(obj, "signature", where=source)

    rendered = render_trust_anchor_bytes(
        anchor_payload=anchor_payload,
        public_key_hex=public_key_hex,
        signature_alg=signature_alg,
        signature=signature,
        schema_version=schema_version,
    )
    if rendered != anchor_bytes:
        raise TrustAnchorError(f"{source}: TrustAnchor.json must use the canonical field order and JSON byte layout")

    if signature_alg != "ed25519":
        raise TrustAnchorError(f"{source}: TrustAnchor.signature_alg must equal 'ed25519'")

    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except Exception as e:
        raise TrustAnchorError(f"{source}: TrustAnchor.signature is not valid base64: {e}") from e

    public_key = _load_ed25519_public_key_from_hex(public_key_hex)
    try:
        public_key.verify(signature_bytes, _canonical_signed_payload_bytes(anchor_payload))
    except Exception as e:
        raise TrustAnchorError(f"{source}: TrustAnchor signature verification failed under public_key_hex: {e}") from e

    return TrustAnchorAuthority(
        schema_version=schema_version,
        anchor_payload={
            "schema_version": _require_str(anchor_payload, "schema_version", where=f"{source}.anchor_payload"),
            "philosophy": _require_str(anchor_payload, "philosophy", where=f"{source}.anchor_payload"),
            "dedication": _require_str(anchor_payload, "dedication", where=f"{source}.anchor_payload"),
            "architect": _require_str(anchor_payload, "architect", where=f"{source}.anchor_payload"),
        },
        public_key_hex=public_key_hex.lower(),
        signature_alg=signature_alg,
        signature=signature,
        sha256=actual_sha256,
        source=source,
    )


def load_pinned_trust_anchor(repo_root: Path | None = None) -> TrustAnchorAuthority:
    try:
        anchor_bytes, source = _read_trust_anchor_bytes(repo_root)
        schema = _read_trust_anchor_schema(repo_root)
        return validate_trust_anchor_bytes(
            anchor_bytes,
            expected_sha256=PINNED_TRUST_ANCHOR_SHA256,
            source=source,
            schema=schema,
        )
    except TrustAnchorError:
        raise
    except Exception as e:
        raise TrustAnchorError(f"{TRUST_ANCHOR_RELPATH}: failed to load canonical Tier-3 trust anchor: {e}") from e


def validate_genesis_seal_payload(
    payload: dict[str, Any],
    *,
    authority: TrustAnchorAuthority,
    source: str = "genesis_seal",
) -> None:
    if not isinstance(payload, dict):
        raise TrustAnchorError(f"{source}: expected JSON object")

    unsigned_payload = {
        "schema_version": _require_str(payload, "schema_version", where=source),
        "philosophy": _require_str(payload, "philosophy", where=source),
        "dedication": _require_str(payload, "dedication", where=source),
        "architect": _require_str(payload, "architect", where=source),
    }
    if unsigned_payload != authority.anchor_payload:
        raise TrustAnchorError(f"{source}: payload fields do not match canonical Tier-3 TrustAnchor.anchor_payload")

    signature_alg = _require_str(payload, "signature_alg", where=source)
    if signature_alg != authority.signature_alg:
        raise TrustAnchorError(
            f"{source}: signature_alg mismatch vs canonical Tier-3 TrustAnchor ({signature_alg!r} != {authority.signature_alg!r})"
        )

    signature = _require_str(payload, "signature", where=source)
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except Exception as e:
        raise TrustAnchorError(f"{source}: signature is not valid base64: {e}") from e

    public_key = _load_ed25519_public_key_from_hex(authority.public_key_hex)
    try:
        public_key.verify(signature_bytes, _canonical_signed_payload_bytes(unsigned_payload))
    except Exception as e:
        raise TrustAnchorError(f"{source}: signature verification failed under canonical Tier-3 TrustAnchor public key: {e}") from e


def validate_genesis_seal_schema(
    payload: dict[str, Any],
    *,
    repo_root: Path | None = None,
    source: str = "genesis_seal",
) -> None:
    if not isinstance(payload, dict):
        raise TrustAnchorError(f"{source}: expected JSON object")
    schema = _read_genesis_seal_schema(repo_root)
    schema_errs = validate_schema(payload, schema, root_schema=schema, path=source)
    if schema_errs:
        first = schema_errs[0]
        raise TrustAnchorError(f"{source}: payload schema invalid at {first.path}: {first.message}")
