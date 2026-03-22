from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from belgi.protocol.pack import ProtocolContext

from .locked_object_schema import load_locked_schema_object

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class LockedTolerances:
    object_id: str
    storage_ref: str
    path: Path
    tier_id: str
    max_touched_files: int | None
    max_loc_delta: int | None


def _require_optional_nonneg_int(value: Any, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"tolerances object field {field} missing/invalid")
    return int(value)


def load_locked_tolerances(
    *,
    repo_root: Path,
    locked_spec: dict[str, Any],
    protocol: ProtocolContext | None = None,
    schema: dict[str, Any] | None = None,
) -> LockedTolerances:
    tier_obj = locked_spec.get("tier")
    if not isinstance(tier_obj, dict):
        raise ValueError("LockedSpec.tier missing/invalid")

    tolerances_ref = tier_obj.get("tolerances_ref")
    if not isinstance(tolerances_ref, dict):
        raise ValueError("LockedSpec.tier.tolerances_ref missing/invalid")

    object_id = tolerances_ref.get("id")
    declared_hash = tolerances_ref.get("hash")
    storage_ref = tolerances_ref.get("storage_ref")
    if not isinstance(object_id, str) or not object_id.strip():
        raise ValueError("LockedSpec.tier.tolerances_ref.id missing/invalid")
    if not isinstance(storage_ref, str) or not storage_ref.strip():
        raise ValueError("LockedSpec.tier.tolerances_ref.storage_ref missing/invalid")
    if not isinstance(declared_hash, str) or not _SHA256_RE.fullmatch(declared_hash):
        raise ValueError("LockedSpec.tier.tolerances_ref.hash missing/invalid")

    tolerances_obj, tolerances_path = load_locked_schema_object(
        repo_root=repo_root,
        storage_ref=storage_ref.strip(),
        declared_hash=declared_hash,
        schema_rel="schemas/Tolerances.schema.json",
        label="Tolerances",
        protocol=protocol,
        schema=schema,
    )
    tier_id = str(tolerances_obj["tier_id"]).strip()
    scope_budgets = tolerances_obj["scope_budgets"]

    return LockedTolerances(
        object_id=object_id.strip(),
        storage_ref=storage_ref.strip(),
        path=tolerances_path,
        tier_id=tier_id.strip(),
        max_touched_files=_require_optional_nonneg_int(
            scope_budgets.get("max_touched_files"),
            field="scope_budgets.max_touched_files",
        ),
        max_loc_delta=_require_optional_nonneg_int(
            scope_budgets.get("max_loc_delta"),
            field="scope_budgets.max_loc_delta",
        ),
    )
