from __future__ import annotations

from dataclasses import dataclass
from typing import Any


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
