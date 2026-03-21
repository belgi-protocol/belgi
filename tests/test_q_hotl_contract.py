from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "chain" or _k.startswith("chain."):
        del sys.modules[_k]

from belgi.core.hash import sha256_bytes
from belgi.protocol.pack import get_builtin_protocol_context
from chain.logic.q_checks import q_hotl_001
from chain.logic.q_checks.context import QCheckContext


def _build_ctx(*, tmp_path: Path, tier_id: str, evidence_manifest: dict[str, object]) -> QCheckContext:
    protocol = get_builtin_protocol_context()
    hotl_schema = protocol.read_json("schemas/HOTLApproval.schema.json")
    assert isinstance(hotl_schema, dict)

    tmp_path.mkdir(parents=True, exist_ok=True)
    intent_path = tmp_path / "IntentSpec.core.md"
    locked_path = tmp_path / "LockedSpec.json"
    evidence_path = tmp_path / "EvidenceManifest.json"
    intent_path.write_text("# intent\n", encoding="utf-8", errors="strict", newline="\n")
    locked_path.write_text(
        json.dumps({"run_id": "run-tier2", "tier": {"tier_id": tier_id}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    evidence_path.write_text(
        json.dumps(evidence_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )

    return QCheckContext(
        repo_root=tmp_path,
        run_id="run-tier2",
        intent_spec_path=intent_path,
        locked_spec_path=locked_path,
        evidence_manifest_path=evidence_path,
        intent_spec_text="# intent\n",
        yaml_block_count=1,
        yaml_text="intent_id: test",
        intent_obj={"intent_id": "test"},
        yaml_parse_error=None,
        locked_spec={"run_id": "run-tier2", "tier": {"tier_id": tier_id}},
        evidence_manifest=evidence_manifest,
        tiers_md="",
        tier_id=tier_id,
        tier_params={},
        schemas={"HOTLApproval": hotl_schema},
    )


def test_q_hotl_missing_artifact_fails_closed_for_tier2(tmp_path: Path) -> None:
    ctx = _build_ctx(
        tmp_path=tmp_path / "missing_hotl",
        tier_id="tier-2",
        evidence_manifest={"schema_version": "1.0.0", "run_id": "run-tier2", "artifacts": []},
    )

    results = q_hotl_001.run(ctx)
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].category == "FQ-HOTL-MISSING"


def test_q_hotl_valid_artifact_passes_for_tier2(tmp_path: Path) -> None:
    repo_root = tmp_path / "valid_hotl"
    repo_root.mkdir(parents=True, exist_ok=True)
    hotl_path = repo_root / "out" / "hotl_approval.json"
    hotl_path.parent.mkdir(parents=True, exist_ok=True)
    hotl_doc = {
        "schema_version": "1.0.0",
        "approval_id": "hotl-tier2-approval",
        "run_id": "run-tier2",
        "approver": "human:test@example.com",
        "approval_type": "pre-proposal",
        "reviewed_artifacts": [
            {"id": "intent", "hash": "0" * 64, "storage_ref": "IntentSpec.core.md"}
        ],
        "decision": "approved",
        "approved_at": "1970-01-01T00:00:00Z",
        "justification": "Tier-2 HOTL approval for deterministic contract test.",
        "audit_trail_ref": {"id": "audit-001", "storage_ref": "out/hotl_audit.log"},
    }
    hotl_path.write_text(
        json.dumps(hotl_doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    evidence_manifest = {
        "schema_version": "1.0.0",
        "run_id": "run-tier2",
        "artifacts": [
            {
                "kind": "hotl_approval",
                "id": "hotl-tier2-approval",
                "hash": sha256_bytes(hotl_path.read_bytes()),
                "media_type": "application/json",
                "storage_ref": "out/hotl_approval.json",
                "produced_by": "C1",
            }
        ],
    }
    ctx = _build_ctx(
        tmp_path=repo_root,
        tier_id="tier-2",
        evidence_manifest=evidence_manifest,
    )

    results = q_hotl_001.run(ctx)
    assert len(results) == 1
    assert results[0].status == "PASS"
