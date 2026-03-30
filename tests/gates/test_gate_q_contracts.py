from __future__ import annotations

import json
import os
import re
import shutil
import stat
import time
from pathlib import Path

import pytest

from chain.logic.q_checks import q_intent_003
from chain.logic.q_checks.context import QCheckContext
from tests.gates.gate_test_support import (
    REPO_ROOT,
    _read_json,
    _remove_locked_spec_protocol_pack,
    _run_module,
    _setup_fake_repo_with_pack,
    _sha256_hex,
    _tamper_locked_spec_pack_id,
)
from tests.helpers import builders
from tests.helpers.repo_imports import import_fresh_protocol_pack_surface
from tests.helpers.tier_fixtures import write_hotl_approval_fixture

pytestmark = pytest.mark.repo_local


def _taxonomy_ids(root: Path) -> set[str]:
    text = (root / "gates" / "failure-taxonomy.md").read_text(encoding="utf-8", errors="strict")
    ids = set(re.findall(r"category_id:\s*`([^`]+)`", text))
    assert ids, "taxonomy category_id tokens not parsed"
    return ids


def _clean_dir(path: Path) -> None:
    if path.exists():
        _rmtree_retry(path)
    path.mkdir(parents=True, exist_ok=True)


def _rmtree_retry(path: Path, *, attempts: int = 12, base_delay_s: float = 0.03) -> None:
    def _onerror(func, p, exc_info):
        _ = exc_info
        try:
            os.chmod(p, stat.S_IWRITE)
        except Exception:
            pass
        func(p)

    last_exc: BaseException | None = None
    for i in range(attempts):
        try:
            shutil.rmtree(path, onerror=_onerror)
            return
        except (PermissionError, OSError) as exc:
            last_exc = exc
            if i == attempts - 1:
                raise
            time.sleep(base_delay_s * (i + 1))

    if last_exc is not None:
        raise last_exc


def test_gate_q_evidence_002_remediation_substitutes_missing_kind(tmp_path: Path) -> None:
    taxo = _taxonomy_ids(REPO_ROOT)
    paths = builders.build_q_repo(tmp_path, rel_root="gate_q/q_pass_tier0", run_id="q-evidence-002")
    intent_rel = paths["intent"]
    locked_rel = paths["locked"]
    evidence_manifest = _read_json(tmp_path / paths["evidence"])
    artifacts = evidence_manifest.get("artifacts")
    assert isinstance(artifacts, list)
    evidence_manifest["artifacts"] = [row for row in artifacts if isinstance(row, dict) and row.get("kind") != "command_log"]
    evidence_rel = "out/EvidenceManifest.missing_command_log.json"
    evidence_path = tmp_path / Path(*evidence_rel.split("/"))
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(evidence_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
    )
    verdict_rel = "out/GateVerdict.Q.missing_command_log.json"
    verdict_path = tmp_path / Path(*verdict_rel.split("/"))

    cp = _run_module(
        "chain.gate_q_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--intent-spec",
            intent_rel,
            "--locked-spec",
            locked_rel,
            "--evidence-manifest",
            evidence_rel,
            "--out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gate_verdict = _read_json(verdict_path)
    assert gate_verdict.get("failure_category") == "FQ-EVIDENCE-MISSING"
    assert gate_verdict.get("failure_category") in taxo

    remediation = ((gate_verdict.get("remediation") or {}).get("next_instruction"))
    assert isinstance(remediation, str)
    assert "command_log" in remediation
    assert "missing_kind" not in remediation


def test_gate_q_taxonomy_mismatch_is_internal_error_and_no_output(tmp_path: Path) -> None:
    fake_root = tmp_path / "fake_repo"
    _clean_dir(fake_root)

    paths = builders.build_q_repo(
        fake_root,
        rel_root="gate_q/q_intent_001_no_yaml_block",
        run_id="q-taxonomy-mismatch",
    )
    pack_root = fake_root / "protocol_pack"
    (pack_root / "gates" / "failure-taxonomy.md").write_text(
        "# Fake taxonomy\n\n- category_id: `FQ-NOT-THE-ONE`\n",
        encoding="utf-8",
        errors="strict",
    )
    pack_surface = import_fresh_protocol_pack_surface()
    manifest_filename = pack_surface.manifest_filename
    (pack_root / manifest_filename).write_bytes(pack_surface.build_manifest_bytes(pack_root=pack_root, pack_name="test-pack"))
    builders.sync_locked_spec_protocol_identity(fake_root / paths["locked"], pack_root / manifest_filename)
    (fake_root / paths["intent"]).write_text("# Intent\nNo YAML block here.\n", encoding="utf-8", errors="strict")

    out_path = fake_root / "out" / "GateVerdict.json"
    cp = _run_module(
        "chain.gate_q_verify",
        [
            "--repo",
            str(fake_root),
            "--protocol-pack",
            "protocol_pack",
            "--intent-spec",
            paths["intent"],
            "--locked-spec",
            paths["locked"],
            "--evidence-manifest",
            paths["evidence"],
            "--out",
            "out/GateVerdict.json",
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 3, (cp.returncode, cp.stdout, cp.stderr)
    assert "category_id not in taxonomy" in cp.stderr
    assert not out_path.exists()


def test_gate_q_q3_duplicate_invariant_ids_is_primary(tmp_path: Path) -> None:
    paths = builders.build_q_repo(
        tmp_path,
        rel_root="gate_q/q3_invariants_duplicate_ids",
        run_id="q3-duplicate",
        invariants=[
            {"id": "INV-001", "description": "first", "severity": "policy"},
            {"id": "INV-001", "description": "second", "severity": "policy"},
        ],
    )

    cp = builders.run_gate_q(
        tmp_path,
        intent_rel=paths["intent"],
        locked_rel=paths["locked"],
        evidence_rel=paths["evidence"],
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.Q.json")
    assert verdict["failure_category"] == "FQ-INVARIANTS-EMPTY"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0]["rule_id"] == "Q3"


def test_gate_q_q5_missing_pinned_refs_is_primary(tmp_path: Path) -> None:
    paths = builders.build_q_repo(tmp_path, rel_root="gate_q/q5_envelope_missing_pinned_refs", run_id="q5-envelope")
    locked_path = tmp_path / paths["locked"]
    locked = _read_json(locked_path)
    envelope = locked.get("environment_envelope")
    assert isinstance(envelope, dict)
    envelope["pinned_toolchain_refs"] = []
    locked_path.write_text(json.dumps(locked, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    cp = builders.run_gate_q(
        tmp_path,
        intent_rel=paths["intent"],
        locked_rel=paths["locked"],
        evidence_rel=paths["evidence"],
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.Q.json")
    assert verdict["failure_category"] == "FQ-ENVELOPE-MISSING"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0]["rule_id"] == "Q5"


def test_gate_q_q7_uses_tier_policy_override_as_supported_owner(tmp_path: Path) -> None:
    paths = builders.build_q_repo(tmp_path, rel_root="gate_q/q7_tier_unsupported", run_id="q7-tier")

    intent_path = tmp_path / paths["intent"]
    locked_path = tmp_path / paths["locked"]
    tiers = builders.builtin_tiers()
    tiers["tiers"]["tier-99"] = json.loads(json.dumps(tiers["tiers"]["tier-0"]))
    tiers_rel = builders.write_tiers_override(tmp_path, tiers)

    locked = _read_json(locked_path)
    tier = locked.get("tier")
    assert isinstance(tier, dict)
    tolerances_ref = tier.get("tolerances_ref")
    assert isinstance(tolerances_ref, dict)
    tolerances_storage_ref = tolerances_ref.get("storage_ref")
    assert isinstance(tolerances_storage_ref, str) and tolerances_storage_ref
    tolerances_path = tmp_path / tolerances_storage_ref
    tolerances = _read_json(tolerances_path)
    tolerances["tier_id"] = "tier-99"
    tolerances_bytes = (json.dumps(tolerances, indent=2, sort_keys=True) + "\n").encode("utf-8", errors="strict")
    tolerances_path.write_bytes(tolerances_bytes)
    tolerances_ref["hash"] = _sha256_hex(tolerances_bytes)
    tier["tier_id"] = "tier-99"
    tier["tier_name"] = "Tier 99"
    locked_path.write_text(json.dumps(locked, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    intent_text = intent_path.read_text(encoding="utf-8", errors="strict").replace('tier_pack_id: "tier-0"', 'tier_pack_id: "tier-99"')
    intent_path.write_text(intent_text, encoding="utf-8", errors="strict")

    cp = builders.run_gate_q(
        tmp_path,
        intent_rel=paths["intent"],
        locked_rel=paths["locked"],
        evidence_rel=paths["evidence"],
        tiers_rel=tiers_rel,
    )
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.Q.json")
    assert verdict["verdict"] == "GO"
    assert verdict["failure_category"] is None
    failures = verdict.get("failures")
    assert isinstance(failures, list)
    assert failures == []


def test_gate_q_q7_unknown_tier_still_fails_when_not_in_policy(tmp_path: Path) -> None:
    paths = builders.build_q_repo(tmp_path, rel_root="gate_q/q7_tier_unknown", run_id="q7-tier-unknown")

    intent_path = tmp_path / paths["intent"]
    locked_path = tmp_path / paths["locked"]

    locked = _read_json(locked_path)
    tier = locked.get("tier")
    assert isinstance(tier, dict)
    tolerances_ref = tier.get("tolerances_ref")
    assert isinstance(tolerances_ref, dict)
    tolerances_storage_ref = tolerances_ref.get("storage_ref")
    assert isinstance(tolerances_storage_ref, str) and tolerances_storage_ref
    tolerances_path = tmp_path / tolerances_storage_ref
    tolerances = _read_json(tolerances_path)
    tolerances["tier_id"] = "tier-99"
    tolerances_bytes = (json.dumps(tolerances, indent=2, sort_keys=True) + "\n").encode("utf-8", errors="strict")
    tolerances_path.write_bytes(tolerances_bytes)
    tolerances_ref["hash"] = _sha256_hex(tolerances_bytes)
    tier["tier_id"] = "tier-99"
    tier["tier_name"] = "Tier 99"
    locked_path.write_text(json.dumps(locked, indent=2, sort_keys=True) + "\n", encoding="utf-8", errors="strict")

    intent_text = intent_path.read_text(encoding="utf-8", errors="strict").replace('tier_pack_id: "tier-0"', 'tier_pack_id: "tier-99"')
    intent_path.write_text(intent_text, encoding="utf-8", errors="strict")

    cp = builders.run_gate_q(
        tmp_path,
        intent_rel=paths["intent"],
        locked_rel=paths["locked"],
        evidence_rel=paths["evidence"],
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.Q.json")
    assert verdict["failure_category"] == "FQ-TIER-UNKNOWN"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0]["rule_id"] == "Q7"


def test_q_intent_003_doc_impact_mapping_no_longer_depends_on_tier_params(tmp_path: Path) -> None:
    intent_path = tmp_path / "IntentSpec.core.md"
    locked_path = tmp_path / "LockedSpec.json"
    evidence_path = tmp_path / "EvidenceManifest.json"
    intent_path.write_text("# synthetic intent\n", encoding="utf-8", errors="strict")
    locked_path.write_text("{}\n", encoding="utf-8", errors="strict")
    evidence_path.write_text("{}\n", encoding="utf-8", errors="strict")

    intent_doc_impact = {
        "required_paths": [],
        "note_on_empty": "No documentation updates required for this synthetic Gate Q mapping proof.",
    }
    publication_intent = {"publish": False, "profile": "internal"}
    ctx = QCheckContext(
        repo_root=tmp_path,
        run_id="q-intent-003-tier-params-free",
        intent_spec_path=intent_path,
        locked_spec_path=locked_path,
        evidence_manifest_path=evidence_path,
        intent_spec_text="# synthetic intent\n",
        yaml_block_count=1,
        yaml_text="intent_id: q-intent-003-tier-params-free",
        intent_obj={
            "intent_id": "q-intent-003-tier-params-free",
            "title": "Synthetic mapping proof",
            "goal": "Verify LockedSpec mapping does not depend on pre-admission tier params.",
            "acceptance": {"success_criteria": ["mapping remains deterministic"]},
            "scope": {"allowed_dirs": ["src/"], "forbidden_dirs": []},
            "tier": {"tier_pack_id": "tier-2"},
            "doc_impact": intent_doc_impact,
            "publication_intent": publication_intent,
        },
        yaml_parse_error=None,
        locked_spec={
            "intent": {
                "intent_id": "q-intent-003-tier-params-free",
                "title": "Synthetic mapping proof",
                "narrative": "Verify LockedSpec mapping does not depend on pre-admission tier params.",
                "success_criteria": "- mapping remains deterministic",
                "scope": "allowed_dirs: [src/]; forbidden_dirs: []",
            },
            "constraints": {
                "allowed_paths": ["src/"],
                "forbidden_paths": [],
            },
            "tier": {
                "tier_id": "tier-2",
                "tier_name": "Tier 2",
            },
            "doc_impact": intent_doc_impact,
            "publication_intent": publication_intent,
        },
        evidence_manifest={},
        tiers_md=(REPO_ROOT / "tiers" / "tier-packs.json").read_text(encoding="utf-8", errors="strict"),
        tier_id="tier-2",
        tier_params={},
        schemas={},
    )

    results = q_intent_003.run(ctx)
    assert len(results) == 1
    assert results[0].status == "PASS"
    assert "deterministic IntentSpec mapping rules" in results[0].message


def test_gate_q_prompt_001_unlisted_repo_is_primary(tmp_path: Path) -> None:
    paths = builders.build_q_repo(
        tmp_path,
        rel_root="gate_q/q_prompt_001_unlisted_repo",
        run_id="q-prompt-001",
        allowed_repo_refs=["allowed/repo"],
        prompt_storage_ref="blocked/repo/prompt_bundle.txt",
    )

    cp = builders.run_gate_q(
        tmp_path,
        intent_rel=paths["intent"],
        locked_rel=paths["locked"],
        evidence_rel=paths["evidence"],
    )
    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.Q.json")
    assert verdict["failure_category"] == "FQ-PROMPT-SOURCE-INVALID"
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    assert failures[0]["rule_id"] == "Q-PROMPT-001"


def test_gate_q_doc_002_tier2_empty_required_paths_passes(tmp_path: Path) -> None:
    paths = builders.build_q_repo(
        tmp_path,
        rel_root="gate_q/q_doc_002_pass_tier2",
        tier_id="tier-2",
        run_id="q-doc-002",
        doc_impact={
            "required_paths": [],
            "note_on_empty": "No documentation change is required for this synthetic tier-2 run.",
        },
        publication_intent={"publish": False, "profile": "internal"},
    )
    _append_hotl_approval_artifact(
        tmp_path,
        evidence_rel=paths["evidence"],
        rel_root="gate_q/q_doc_002_pass_tier2",
        run_id="q-doc-002",
    )

    cp = builders.run_gate_q(
        tmp_path,
        intent_rel=paths["intent"],
        locked_rel=paths["locked"],
        evidence_rel=paths["evidence"],
    )
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr)

    verdict = _read_json(tmp_path / "out" / "GateVerdict.Q.json")
    assert verdict["verdict"] == "GO"
    assert verdict["failure_category"] is None


def test_gate_q_protocol_identity_mismatch_pack_id(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    paths = builders.build_q_repo(tmp_path, rel_root="gate_q/q_pass_tier0", run_id="q-pass-tier0")
    locked_path = tmp_path / paths["locked"]
    _tamper_locked_spec_pack_id(locked_path, "0" * 64)

    verdict_rel = "out/GateVerdict.json"
    verdict_path = tmp_path / "out" / "GateVerdict.json"
    cp = _run_module(
        "chain.gate_q_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--intent-spec",
            paths["intent"],
            "--locked-spec",
            paths["locked"],
            "--evidence-manifest",
            paths["evidence"],
            "--out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gate_verdict = _read_json(verdict_path)
    assert gate_verdict.get("failure_category") == "FQ-PROTOCOL-IDENTITY-MISMATCH", gate_verdict


def test_gate_q_missing_protocol_pack_field(tmp_path: Path) -> None:
    builtin_pack = REPO_ROOT / "belgi" / "_protocol_packs" / "v1"
    _setup_fake_repo_with_pack(tmp_path, builtin_pack)

    paths = builders.build_q_repo(tmp_path, rel_root="gate_q/q_pass_tier0", run_id="q-pass-tier0")
    locked_path = tmp_path / paths["locked"]
    _remove_locked_spec_protocol_pack(locked_path)

    verdict_rel = "out/GateVerdict.json"
    verdict_path = tmp_path / "out" / "GateVerdict.json"
    cp = _run_module(
        "chain.gate_q_verify",
        [
            "--repo",
            str(tmp_path),
            "--protocol-pack",
            "protocol_pack",
            "--intent-spec",
            paths["intent"],
            "--locked-spec",
            paths["locked"],
            "--evidence-manifest",
            paths["evidence"],
            "--out",
            verdict_rel,
        ],
        cwd=REPO_ROOT,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    gate_verdict = _read_json(verdict_path)
    assert gate_verdict.get("failure_category") == "FQ-PROTOCOL-IDENTITY-MISMATCH", gate_verdict


def _append_hotl_approval_artifact(repo_root: Path, *, evidence_rel: str, rel_root: str, run_id: str) -> None:
    fixture = write_hotl_approval_fixture(
        repo_root,
        rel_root=rel_root,
        run_id=run_id,
        locked_rel=f"{rel_root}/LockedSpec.json",
        approver="human:operator@example.com",
        approval_id="hotl.synthetic",
        audit_id="audit.hotl.synthetic",
    )

    evidence_path = repo_root / evidence_rel
    evidence = _read_json(evidence_path)
    artifacts = evidence.get("artifacts")
    assert isinstance(artifacts, list)
    artifacts.append(
        fixture["artifact"]
    )
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
