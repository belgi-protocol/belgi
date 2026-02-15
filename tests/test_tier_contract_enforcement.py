from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "chain" or _k.startswith("chain."):
        del sys.modules[_k]

from chain.logic.r_checks import r0_evidence_sufficiency
from chain.logic.tier_packs import load_tier_params


def _tier_params_map(tier_id: str) -> dict[str, Any]:
    tiers_text = (REPO_ROOT / "tiers" / "tier-packs.json").read_text(encoding="utf-8", errors="strict")
    loaded = load_tier_params(tiers_text, tier_id)
    assert loaded.params is not None, loaded.parse_error
    return loaded.to_legacy_map()


def _artifact(kind: str, artifact_id: str) -> dict[str, str]:
    return {
        "kind": kind,
        "id": artifact_id,
        "hash": "a" * 64,
        "media_type": "application/json",
        "storage_ref": f"out/{artifact_id}.json",
        "produced_by": "C1",
    }


def _structured_cmd(subcommand: str) -> dict[str, Any]:
    return {
        "argv": ["belgi", subcommand],
        "exit_code": 0,
        "started_at": "1970-01-01T00:00:00Z",
        "finished_at": "1970-01-01T00:00:00Z",
    }


def _ctx(
    *,
    tmp_path: Path,
    tier_id: str,
    artifacts: list[dict[str, str]],
    commands_executed: list[Any],
    envelope_attestation: dict[str, str] | None,
) -> Any:
    repo_root = tmp_path / "repo"
    repo_root.mkdir(parents=True, exist_ok=True)
    locked_path = repo_root / "inputs" / "LockedSpec.json"
    evidence_path = repo_root / "out" / "EvidenceManifest.json"
    locked_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    locked_path.write_text(
        json.dumps({"tier": {"tier_id": tier_id}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    evidence_path.write_text(
        json.dumps({"artifacts": artifacts}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    return SimpleNamespace(
        repo_root=repo_root,
        locked_spec_path=locked_path,
        evidence_manifest_path=evidence_path,
        locked_spec={"tier": {"tier_id": tier_id}},
        evidence_manifest={
            "artifacts": artifacts,
            "commands_executed": commands_executed,
            "envelope_attestation": envelope_attestation,
        },
        tier_params=_tier_params_map(tier_id),
    )


def _find(results: list[Any], check_id: str) -> Any:
    for r in results:
        if r.check_id == check_id:
            return r
    raise AssertionError(f"missing check result: {check_id}")


def test_tier1_missing_test_report_fails(tmp_path: Path) -> None:
    ctx = _ctx(
        tmp_path=tmp_path / "tier1_missing_test_report",
        tier_id="tier-1",
        artifacts=[
            _artifact("diff", "changes.diff"),
            _artifact("command_log", "command.log"),
            _artifact("schema_validation", "schema.lockedspec"),
            _artifact("policy_report", "policy.invariant_eval"),
            _artifact("env_attestation", "env.attestation"),
        ],
        commands_executed=[_structured_cmd("run-tests"), _structured_cmd("verify-attestation")],
        envelope_attestation={"id": "env.attestation", "hash": "b" * 64, "storage_ref": "out/env.attestation.json"},
    )
    results = r0_evidence_sufficiency.run(ctx)
    evidence = _find(results, "R0.evidence_sufficiency")
    assert evidence.status == "FAIL"
    assert "test_report" in evidence.message


def test_tier1_missing_env_attestation_fails(tmp_path: Path) -> None:
    ctx = _ctx(
        tmp_path=tmp_path / "tier1_missing_env_att",
        tier_id="tier-1",
        artifacts=[
            _artifact("diff", "changes.diff"),
            _artifact("command_log", "command.log"),
            _artifact("schema_validation", "schema.lockedspec"),
            _artifact("policy_report", "policy.invariant_eval"),
            _artifact("test_report", "tests.report"),
        ],
        commands_executed=[_structured_cmd("run-tests"), _structured_cmd("verify-attestation")],
        envelope_attestation={"id": "env.attestation", "hash": "b" * 64, "storage_ref": "out/env.attestation.json"},
    )
    results = r0_evidence_sufficiency.run(ctx)
    evidence = _find(results, "R0.evidence_sufficiency")
    assert evidence.status == "FAIL"
    assert "env_attestation" in evidence.message


def test_tier1_requires_structured_command_log(tmp_path: Path) -> None:
    ctx = _ctx(
        tmp_path=tmp_path / "tier1_mode",
        tier_id="tier-1",
        artifacts=[
            _artifact("diff", "changes.diff"),
            _artifact("command_log", "command.log"),
            _artifact("schema_validation", "schema.lockedspec"),
            _artifact("policy_report", "policy.invariant_eval"),
            _artifact("test_report", "tests.report"),
            _artifact("env_attestation", "env.attestation"),
        ],
        commands_executed=["belgi run-tests", "belgi verify-attestation"],
        envelope_attestation={"id": "env.attestation", "hash": "b" * 64, "storage_ref": "out/env.attestation.json"},
    )
    results = r0_evidence_sufficiency.run(ctx)
    cmd_mode = _find(results, "R0.command_log_mode")
    assert cmd_mode.status == "FAIL"
    assert "structured" in cmd_mode.message


def test_tier0_allows_strings_command_log(tmp_path: Path) -> None:
    ctx = _ctx(
        tmp_path=tmp_path / "tier0_mode",
        tier_id="tier-0",
        artifacts=[
            _artifact("diff", "changes.diff"),
            _artifact("command_log", "command.log"),
            _artifact("schema_validation", "schema.lockedspec"),
            _artifact("policy_report", "policy.invariant_eval"),
        ],
        commands_executed=["belgi diff-capture"],
        envelope_attestation=None,
    )
    results = r0_evidence_sufficiency.run(ctx)
    assert _find(results, "R0.tier_parse").status == "PASS"
    assert _find(results, "R0.evidence_sufficiency").status == "PASS"
    assert _find(results, "R0.command_log_mode").status == "PASS"
    assert _find(results, "R0.attestation_presence").status == "PASS"


def test_tier_difference_is_visible_and_deterministic(tmp_path: Path) -> None:
    artifacts = [
        _artifact("diff", "changes.diff"),
        _artifact("command_log", "command.log"),
        _artifact("schema_validation", "schema.lockedspec"),
        _artifact("policy_report", "policy.invariant_eval"),
    ]
    commands = ["belgi diff-capture"]

    ctx_t0 = _ctx(
        tmp_path=tmp_path / "tier_diff_t0",
        tier_id="tier-0",
        artifacts=artifacts,
        commands_executed=commands,
        envelope_attestation=None,
    )
    ctx_t1 = _ctx(
        tmp_path=tmp_path / "tier_diff_t1",
        tier_id="tier-1",
        artifacts=artifacts,
        commands_executed=commands,
        envelope_attestation=None,
    )

    res_t0 = r0_evidence_sufficiency.run(ctx_t0)
    res_t1 = r0_evidence_sufficiency.run(ctx_t1)

    assert _find(res_t0, "R0.evidence_sufficiency").status == "PASS"
    t1_evidence = _find(res_t1, "R0.evidence_sufficiency")
    assert t1_evidence.status == "FAIL"
    assert "test_report" in t1_evidence.message


def test_tier1_missing_kinds_order_is_stable(tmp_path: Path) -> None:
    ctx = _ctx(
        tmp_path=tmp_path / "tier1_order",
        tier_id="tier-1",
        artifacts=[
            _artifact("diff", "changes.diff"),
            _artifact("command_log", "command.log"),
            _artifact("schema_validation", "schema.lockedspec"),
            _artifact("policy_report", "policy.invariant_eval"),
        ],
        commands_executed=[_structured_cmd("run-tests"), _structured_cmd("verify-attestation")],
        envelope_attestation=None,
    )
    results = r0_evidence_sufficiency.run(ctx)
    evidence = _find(results, "R0.evidence_sufficiency")
    assert evidence.status == "FAIL"
    assert evidence.message.find("test_report") < evidence.message.find("env_attestation")
