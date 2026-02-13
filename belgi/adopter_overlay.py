from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from belgi.core.hash import is_hex_sha256, sha256_bytes
from belgi.core.jail import resolve_storage_ref
from belgi.core.schema import validate_schema


DOMAIN_PACK_MANIFEST_FILENAME = "DomainPackManifest.json"


@dataclass(frozen=True)
class DomainOverlayManifest:
    format_version: int
    pack_name: str
    pack_semver: str
    belgi_protocol_pack_pin: dict[str, str]
    required_policy_check_ids: list[str]


@dataclass(frozen=True)
class OverlayEvaluationFailure:
    reason: str
    message: str


def _require_non_empty_string(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} missing/invalid")
    return value.strip()


def _normalize_required_policy_check_ids(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("required_policy_check_ids missing/invalid")

    out: list[str] = []
    seen: set[str] = set()
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"required_policy_check_ids[{i}] missing/invalid")
        cid = item.strip()
        if cid in seen:
            continue
        seen.add(cid)
        out.append(cid)
    return out


def load_domain_overlay_manifest(path: Path) -> DomainOverlayManifest:
    if not isinstance(path, Path):
        raise TypeError("path must be pathlib.Path")
    if not path.exists() or not path.is_file():
        raise ValueError(f"overlay manifest missing/invalid: {path}")
    if path.is_symlink():
        raise ValueError(f"symlink overlay manifest not allowed: {path}")

    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except Exception as e:
        raise ValueError(f"overlay manifest is not valid UTF-8 JSON: {e}") from e

    if not isinstance(obj, dict):
        raise ValueError("overlay manifest must be a JSON object")

    format_version = obj.get("format_version")
    if not isinstance(format_version, int) or isinstance(format_version, bool) or format_version <= 0:
        raise ValueError("format_version missing/invalid")

    pack_name = _require_non_empty_string(obj.get("pack_name"), label="pack_name")
    pack_semver = _require_non_empty_string(obj.get("pack_semver"), label="pack_semver")

    pin = obj.get("belgi_protocol_pack_pin")
    if not isinstance(pin, dict):
        raise ValueError("belgi_protocol_pack_pin missing/invalid")
    pin_pack_name = _require_non_empty_string(pin.get("pack_name"), label="belgi_protocol_pack_pin.pack_name")
    pin_pack_id = _require_non_empty_string(pin.get("pack_id"), label="belgi_protocol_pack_pin.pack_id")
    pin_manifest_sha256 = _require_non_empty_string(
        pin.get("manifest_sha256"),
        label="belgi_protocol_pack_pin.manifest_sha256",
    )

    if not is_hex_sha256(pin_pack_id):
        raise ValueError("belgi_protocol_pack_pin.pack_id must be 64-hex chars")
    if not is_hex_sha256(pin_manifest_sha256):
        raise ValueError("belgi_protocol_pack_pin.manifest_sha256 must be 64-hex chars")

    required_policy_check_ids = _normalize_required_policy_check_ids(obj.get("required_policy_check_ids"))

    return DomainOverlayManifest(
        format_version=format_version,
        pack_name=pack_name,
        pack_semver=pack_semver,
        belgi_protocol_pack_pin={
            "pack_name": pin_pack_name,
            "pack_id": pin_pack_id,
            "manifest_sha256": pin_manifest_sha256,
        },
        required_policy_check_ids=required_policy_check_ids,
    )


def _collect_passed_policy_check_ids(
    *,
    repo_root: Path,
    evidence_manifest: dict[str, Any],
    policy_payload_schema: dict[str, Any],
) -> tuple[set[str], str | None]:
    artifacts = evidence_manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return set(), "EvidenceManifest.artifacts missing/invalid"

    passed_ids: set[str] = set()
    for i, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            continue
        if artifact.get("kind") != "policy_report":
            continue

        storage_ref = artifact.get("storage_ref")
        declared_hash = artifact.get("hash")
        if not isinstance(storage_ref, str) or not storage_ref:
            return set(), f"policy_report[{i}] storage_ref missing/invalid"
        if not isinstance(declared_hash, str) or not is_hex_sha256(declared_hash):
            return set(), f"policy_report[{i}] hash missing/invalid"

        try:
            p = resolve_storage_ref(repo_root, storage_ref)
            if p.is_symlink():
                return set(), f"policy_report[{i}] symlink not allowed"
            data = p.read_bytes()
        except Exception as e:
            return set(), f"Cannot read policy_report[{i}] bytes: {e}"

        if sha256_bytes(data) != declared_hash:
            return set(), f"policy_report[{i}] sha256(bytes) mismatch"

        # Overlay scans must tolerate non-PolicyReportPayload policy_report artifacts
        # (for example policy.consistency_sweep). Such artifacts are ignored rather than
        # hard-failing, while hash/jail/symlink safety remains fail-closed above.
        try:
            payload = json.loads(data.decode("utf-8", errors="strict"))
        except Exception:
            continue

        if not isinstance(payload, dict):
            continue

        errs = validate_schema(
            payload,
            policy_payload_schema,
            root_schema=policy_payload_schema,
            path=f"policy_report[{i}]",
        )
        if errs:
            continue

        checks = payload.get("checks")
        if not isinstance(checks, list):
            continue

        for check in checks:
            if not isinstance(check, dict):
                continue
            check_id = check.get("check_id")
            passed = check.get("passed")
            if isinstance(check_id, str) and check_id and passed is True:
                passed_ids.add(check_id)

    return passed_ids, None


def evaluate_overlay_requirements(
    *,
    overlay_manifest_path: Path,
    repo_root: Path,
    active_pack_name: str,
    active_pack_id: str,
    active_manifest_sha256: str,
    evidence_manifest: dict[str, Any],
    policy_payload_schema: dict[str, Any],
) -> OverlayEvaluationFailure | None:
    try:
        overlay = load_domain_overlay_manifest(overlay_manifest_path)
    except Exception as e:
        return OverlayEvaluationFailure(reason="overlay_manifest_invalid", message=str(e))

    pin = overlay.belgi_protocol_pack_pin
    mismatches: list[str] = []
    if pin["pack_name"] != active_pack_name:
        mismatches.append(f"pack_name: declared={pin['pack_name']!r} active={active_pack_name!r}")
    if pin["pack_id"] != active_pack_id:
        mismatches.append(f"pack_id: declared={pin['pack_id']!r} active={active_pack_id!r}")
    if pin["manifest_sha256"] != active_manifest_sha256:
        mismatches.append(
            "manifest_sha256: "
            f"declared={pin['manifest_sha256']!r} active={active_manifest_sha256!r}"
        )
    if mismatches:
        return OverlayEvaluationFailure(
            reason="pin_mismatch",
            message="overlay belgi_protocol_pack_pin mismatch: " + "; ".join(mismatches),
        )

    required = overlay.required_policy_check_ids
    if not required:
        return None

    passed_ids, err = _collect_passed_policy_check_ids(
        repo_root=repo_root,
        evidence_manifest=evidence_manifest,
        policy_payload_schema=policy_payload_schema,
    )
    if err is not None:
        return OverlayEvaluationFailure(reason="policy_report_invalid", message=err)

    for check_id in required:
        if check_id not in passed_ids:
            return OverlayEvaluationFailure(
                reason="missing_required_check",
                message=f"required_policy_check_id not satisfied: {check_id}",
            )

    return None
