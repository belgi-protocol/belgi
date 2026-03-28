from __future__ import annotations

"""Repo-local synthetic tier/prompt/HOTL fixtures for tests only.

This module centralizes test-owned tier policy snapshots, prompt selection
expectations, and HOTL approval fixtures. It is not shipped runtime or
operator authority.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

__all__ = [
    "builtin_tiers",
    "hotl_approval_doc",
    "prompt_block_hashes_for_locked",
    "prompt_block_ids_for_tier_policy",
    "tier_contract",
    "tier_policy",
    "write_hotl_approval_fixture",
]


def _read_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    assert isinstance(obj, dict)
    return obj


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="strict", newline="\n")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def builtin_tiers() -> dict[str, Any]:
    return _read_json(REPO_ROOT / "tiers" / "tier-packs.json")


def tier_contract(tier_id: str, *, tiers_obj: dict[str, Any] | None = None) -> dict[str, Any]:
    tiers_source = builtin_tiers() if tiers_obj is None else tiers_obj
    tiers = tiers_source.get("tiers")
    assert isinstance(tiers, dict), "tiers/tier-packs.json missing tiers map"
    contract = tiers.get(tier_id)
    assert isinstance(contract, dict), f"missing tier contract for {tier_id}"
    return contract


def tier_policy(tier_id: str, *, tiers_obj: dict[str, Any] | None = None) -> Any:
    return _load_tier_params(tier_id, tiers_obj=tiers_obj)


def _load_tier_params(tier_id: str, *, tiers_obj: dict[str, Any] | None = None) -> Any:
    from chain.logic.tier_packs import load_tier_params

    tiers_source = builtin_tiers() if tiers_obj is None else tiers_obj
    tiers_text = json.dumps(tiers_source, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    loaded = load_tier_params(tiers_text, tier_id)
    assert loaded.params is not None, loaded.parse_error
    return loaded.params


def prompt_block_ids_for_tier_policy(
    tier_id: str,
    *,
    tiers_obj: dict[str, Any] | None = None,
) -> list[str]:
    from chain.compiler_c1_intent import _prompt_block_ids_for_tier_policy

    return list(_prompt_block_ids_for_tier_policy(_load_tier_params(tier_id, tiers_obj=tiers_obj)))


def prompt_block_hashes_for_locked(
    locked_spec: dict[str, Any],
    *,
    tiers_obj: dict[str, Any] | None = None,
) -> dict[str, str]:
    from chain.compiler_c1_intent import _render_prompt_block

    tier_obj = locked_spec.get("tier")
    assert isinstance(tier_obj, dict)
    tier_id = tier_obj.get("tier_id")
    assert isinstance(tier_id, str) and tier_id

    locked_preimage = dict(locked_spec)
    locked_preimage.pop("prompt_bundle_ref", None)

    out: dict[str, str] = {}
    for block_id in prompt_block_ids_for_tier_policy(tier_id, tiers_obj=tiers_obj):
        rendered = _render_prompt_block(block_id=block_id, locked_spec_preimage=locked_preimage)
        assert isinstance(rendered, (bytes, bytearray))
        out[str(block_id)] = _sha256_hex(bytes(rendered))
    return out


def hotl_approval_doc(
    *,
    repo_root: Path,
    run_id: str,
    locked_rel: str,
    approval_id: str = "hotl-tier2-approval",
    approver: str = "human:test@example.com",
    approved_at: str = "1970-01-01T00:00:00Z",
    justification: str = "Tier-2 shared-path approval for deterministic operator-run test.",
    audit_rel: str = "hotl_approval.log",
    audit_id: str = "audit-hotl-001",
) -> dict[str, Any]:
    locked_path = repo_root / locked_rel
    return {
        "schema_version": "1.0.0",
        "approval_id": approval_id,
        "run_id": run_id,
        "approver": approver,
        "approval_type": "pre-proposal",
        "reviewed_artifacts": [
            {
                "id": "locked.synthetic",
                "hash": _sha256_hex(locked_path.read_bytes()),
                "storage_ref": locked_rel,
            }
        ],
        "decision": "approved",
        "approved_at": approved_at,
        "justification": justification,
        "audit_trail_ref": {
            "id": audit_id,
            "storage_ref": audit_rel,
        },
    }


def write_hotl_approval_fixture(
    repo_root: Path,
    *,
    rel_root: str,
    run_id: str,
    locked_rel: str | None = None,
    audit_rel: str | None = None,
    approval_id: str = "hotl-tier2-approval",
    approver: str = "human:test@example.com",
    approved_at: str = "1970-01-01T00:00:00Z",
    justification: str = "synthetic HOTL approval for tier-2 coverage",
    audit_id: str = "audit-hotl-001",
) -> dict[str, Any]:
    locked_rel = f"{rel_root}/LockedSpec.json" if locked_rel is None else locked_rel
    audit_rel = f"{rel_root}/hotl_approval.log" if audit_rel is None else audit_rel
    hotl_rel = f"{rel_root}/hotl_approval.json"

    _write_text(repo_root / audit_rel, "synthetic HOTL audit trail\n")
    hotl_doc = hotl_approval_doc(
        repo_root=repo_root,
        run_id=run_id,
        locked_rel=locked_rel,
        approval_id=approval_id,
        approver=approver,
        approved_at=approved_at,
        justification=justification,
        audit_rel=audit_rel,
        audit_id=audit_id,
    )
    _write_json(repo_root / hotl_rel, hotl_doc)
    return {
        "audit_rel": audit_rel,
        "hotl_doc": hotl_doc,
        "hotl_rel": hotl_rel,
        "artifact": {
            "kind": "hotl_approval",
            "id": approval_id,
            "hash": _sha256_hex((repo_root / hotl_rel).read_bytes()),
            "media_type": "application/json",
            "produced_by": "C1",
            "storage_ref": hotl_rel,
        },
    }
