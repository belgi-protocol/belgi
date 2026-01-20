from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from belgi.protocol.pack import ProtocolContext


@dataclass(frozen=True)
class RCheckContext:
    repo_root: Path
    protocol: ProtocolContext
    locked_spec_path: Path
    evidence_manifest_path: Path
    gate_verdict_path: Path | None
    locked_spec: dict[str, Any]
    evidence_manifest: dict[str, Any]
    gate_verdict: dict[str, Any] | None
    tier_params: dict[str, Any]

    evaluated_revision: str
    upstream_commit_sha: str

    policy_payload_schema: dict[str, Any]
    test_payload_schema: dict[str, Any]

    required_policy_report_ids: list[str]
    required_test_report_id: str

    # Optional fields added for fixture safety; defaults preserve legacy positional constructors.
    fixture_context: bool = False
    evaluated_revision_is_commit: bool = True
