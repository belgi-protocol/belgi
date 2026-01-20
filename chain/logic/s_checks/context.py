from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SCheckContext:
    repo_root: Path
    locked_spec_path: Path
    seal_manifest_path: Path
    evidence_manifest_path: Path

    locked_spec: dict[str, Any]
    seal_manifest: dict[str, Any]
    evidence_manifest: dict[str, Any]

    locked_spec_schema: dict[str, Any]
    seal_manifest_schema: dict[str, Any]
    evidence_manifest_schema: dict[str, Any]
    gate_verdict_schema: dict[str, Any]
    waiver_schema: dict[str, Any]
    replay_instructions_schema: dict[str, Any] | None

    tier_id: str
    run_id: str
