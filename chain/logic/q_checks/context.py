from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class QCheckContext:
    repo_root: Path

    run_id: str
    intent_spec_path: Path
    locked_spec_path: Path
    evidence_manifest_path: Path

    intent_spec_text: str
    yaml_block_count: int
    yaml_text: str | None
    intent_obj: dict[str, Any] | None
    yaml_parse_error: str | None

    locked_spec: dict[str, Any] | None
    evidence_manifest: dict[str, Any] | None

    tiers_md: str
    tier_id: str | None

    tier_params: dict[str, Any]

    schemas: dict[str, dict[str, Any]]
