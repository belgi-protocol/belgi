from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

INVENTORY_STYLE_INVARIANT_IDS = frozenset(
    {
        "CS-SWEEP-001",
        "CS-SWEEP-002",
        "CS-CAN-005",
        "CS-RENDER-001",
    }
)


def _sorted_unique_strings(values: Iterable[str]) -> list[str]:
    return sorted({str(value) for value in values})


def _checked_set_sha256(checked_set: Sequence[str]) -> str:
    payload = (json.dumps(list(checked_set), ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8",
        errors="strict",
    )
    return hashlib.sha256(payload).hexdigest()


def inventory_witness_details(
    *,
    checked_set: Iterable[str],
    missing: Iterable[str] = (),
    unexpected: Iterable[str] = (),
    mismatched: Iterable[str] = (),
    derived_from: Iterable[str],
) -> dict[str, Any]:
    normalized_checked_set = _sorted_unique_strings(checked_set)
    normalized_derived_from = _sorted_unique_strings(derived_from)
    if not normalized_derived_from:
        raise ValueError("inventory witness details require at least one derived_from source")

    return {
        "checked_count": len(normalized_checked_set),
        "checked_set": normalized_checked_set,
        "checked_set_sha256": _checked_set_sha256(normalized_checked_set),
        "missing": _sorted_unique_strings(missing),
        "unexpected": _sorted_unique_strings(unexpected),
        "mismatched": _sorted_unique_strings(mismatched),
        "derived_from": normalized_derived_from,
    }


def validate_inventory_witness_details(invariant_id: str, details: dict[str, Any] | None) -> None:
    if invariant_id not in INVENTORY_STYLE_INVARIANT_IDS:
        return
    if not isinstance(details, dict):
        raise ValueError(f"{invariant_id} requires structured inventory witness details.")

    required_keys = ("checked_count", "missing", "unexpected", "mismatched", "derived_from")
    missing_keys = [key for key in required_keys if key not in details]
    if missing_keys:
        raise ValueError(f"{invariant_id} inventory witness details are missing keys: {', '.join(missing_keys)}")

    checked_set = details.get("checked_set")
    checked_set_sha256 = details.get("checked_set_sha256")
    if not isinstance(checked_set, list) and not isinstance(checked_set_sha256, str):
        raise ValueError(f"{invariant_id} inventory witness details require checked_set or checked_set_sha256.")

    checked_count = details.get("checked_count")
    if not isinstance(checked_count, int) or checked_count < 0:
        raise ValueError(f"{invariant_id} inventory witness details require a non-negative checked_count.")

    if isinstance(checked_set, list):
        if not all(isinstance(item, str) for item in checked_set):
            raise ValueError(f"{invariant_id} inventory witness checked_set must contain only strings.")
        normalized_checked_set = _sorted_unique_strings(checked_set)
        if list(checked_set) != normalized_checked_set:
            raise ValueError(f"{invariant_id} inventory witness checked_set must be sorted and unique.")
        if checked_count != len(checked_set):
            raise ValueError(f"{invariant_id} inventory witness checked_count must match checked_set length.")
        if isinstance(checked_set_sha256, str) and checked_set_sha256 != _checked_set_sha256(checked_set):
            raise ValueError(f"{invariant_id} inventory witness checked_set_sha256 does not match checked_set.")
    elif checked_set_sha256 is None:
        raise ValueError(f"{invariant_id} inventory witness details must include checked_set_sha256 when checked_set is absent.")

    for key in ("missing", "unexpected", "mismatched", "derived_from"):
        value = details.get(key)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"{invariant_id} inventory witness {key} must be a list of strings.")
    if not details["derived_from"]:
        raise ValueError(f"{invariant_id} inventory witness derived_from must not be empty.")


@dataclass
class InvariantResult:
    invariant_id: str
    status: str  # PASS/FAIL
    evidence: list[str]
    remediation: str
    details: dict[str, Any] | None = None


@dataclass(frozen=True)
class RenderedConsistencyReport:
    payload: dict[str, Any]
    canonical_bytes: bytes
    sha256: str
    ordered_results: list[InvariantResult]
    passed_count: int
    failed_count: int
