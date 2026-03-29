from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from belgi.core.schema import validate_schema
from tests.helpers import builders, tier_fixtures

REPO_ROOT = Path(__file__).resolve().parents[2]


def _read_json(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    assert isinstance(obj, dict)
    return obj


def _tree_snapshot(root: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            out[rel] = path.read_bytes()
    return out


def _first_failure_rule_id(verdict_path: Path) -> str:
    verdict = _read_json(verdict_path)
    failures = verdict.get("failures")
    assert isinstance(failures, list) and failures
    rule_id = failures[0].get("rule_id")
    assert isinstance(rule_id, str) and rule_id
    return rule_id


def _git(repo_root: Path, *args: str) -> str:
    cp = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return cp.stdout


def _git_head(repo_root: Path) -> str:
    return _git(repo_root, "rev-parse", "HEAD").strip()


def _git_status_porcelain(repo_root: Path) -> str:
    return _git(repo_root, "status", "--porcelain")


def test_builders_public_api_is_explicit_and_narrow() -> None:
    assert builders.__all__ == [
        "build_q_repo",
        "build_r_repo",
        "build_s_repo",
        "builtin_tiers",
        "init_git_repo",
        "run_gate_q",
        "run_gate_r",
        "sync_locked_spec_protocol_identity",
        "write_json",
        "write_text",
        "write_tiers_override",
    ]


def test_tier_fixtures_public_api_is_explicit_and_narrow() -> None:
    assert tier_fixtures.__all__ == [
        "builtin_tiers",
        "hotl_approval_doc",
        "prompt_block_hashes_for_locked",
        "prompt_block_ids_for_tier_policy",
        "tier_contract",
        "tier_policy",
        "write_hotl_approval_fixture",
    ]


def test_tier_policy_returns_tier_params_shape_and_matches_owner_path() -> None:
    from chain.logic.tier_packs import TierParams, load_tier_params

    tiers = tier_fixtures.builtin_tiers()
    tiers_text = json.dumps(tiers, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    owner = load_tier_params(tiers_text, "tier-1")
    assert owner.params is not None, owner.parse_error

    helper = tier_fixtures.tier_policy("tier-1", tiers_obj=tiers)
    assert isinstance(helper, TierParams)
    assert helper == owner.params


def test_tier_policy_preserves_override_semantics_against_owner_path() -> None:
    from chain.logic.tier_packs import TierParams, load_tier_params

    tiers = tier_fixtures.builtin_tiers()
    tier0 = tiers["tiers"]["tier-0"]
    assert isinstance(tier0, dict)
    tier0["command_log_mode"] = "structured"
    tier0["test_policy"]["required"] = True
    tier0["envelope_policy"]["requires_attestation"] = True

    tiers_text = json.dumps(tiers, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    owner = load_tier_params(tiers_text, "tier-0")
    assert owner.params is not None, owner.parse_error

    helper = tier_fixtures.tier_policy("tier-0", tiers_obj=tiers)
    assert isinstance(helper, TierParams)
    assert helper == owner.params
    assert helper.command_log_mode == "structured"
    assert helper.test_policy_required == "yes"
    assert helper.envelope_policy_requires_attestation == "yes"


def test_build_q_repo_is_deterministic_for_same_explicit_inputs(tmp_path: Path) -> None:
    common_kwargs = {
        "rel_root": "synthetic/q",
        "tier_id": "tier-0",
        "run_id": "q-deterministic",
        "allowed_dirs": ["src/"],
        "forbidden_dirs": ["docs/private/"],
        "success_criteria": ["criterion-a"],
        "doc_impact": {
            "required_paths": ["docs/guide.md"],
            "note_on_empty": "doc update required",
        },
        "invariants": [
            {
                "id": "INV-DET-001",
                "description": "deterministic synthetic invariant",
                "severity": "policy",
            }
        ],
        "allowed_repo_refs": ["github.com/example/repo"],
        "publication_intent": {"publish": True, "profile": "public"},
        "waivers_applied": ["waivers/waiver-001.json"],
    }
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"

    first_paths = builders.build_q_repo(first_root, **common_kwargs)
    second_paths = builders.build_q_repo(second_root, **common_kwargs)

    assert first_paths == second_paths
    assert _tree_snapshot(first_root) == _tree_snapshot(second_root)


def test_build_q_repo_preserves_explicit_empty_lists_and_invalid_tiers(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    paths = builders.build_q_repo(
        repo_root,
        rel_root="synthetic/q-empty",
        run_id="q-empty",
        allowed_dirs=[],
        forbidden_dirs=[],
        success_criteria=[],
        invariants=[],
        waivers_applied=[],
    )

    locked = _read_json(repo_root / paths["locked"])
    intent_text = (repo_root / paths["intent"]).read_text(encoding="utf-8", errors="strict")

    assert locked["constraints"]["allowed_paths"] == []
    assert locked["constraints"]["forbidden_paths"] == []
    assert locked["invariants"] == []
    assert locked["waivers_applied"] == []
    assert "allowed_dirs: []" in intent_text
    assert "forbidden_dirs: []" in intent_text
    assert "success_criteria: []" in intent_text

    bad_repo = tmp_path / "bad-tier-source"
    try:
        builders.build_q_repo(bad_repo, rel_root="synthetic/q-bad-tier", run_id="q-bad-tier", tiers_obj={})
    except AssertionError as exc:
        assert "tiers/tier-packs.json missing tiers map" in str(exc)
    else:
        raise AssertionError("builders.build_q_repo should not silently replace an invalid explicit tiers_obj")


def test_build_q_repo_only_adds_optional_authority_fields_when_requested(tmp_path: Path) -> None:
    default_root = tmp_path / "default"
    default_paths = builders.build_q_repo(default_root, rel_root="synthetic/q-default", run_id="q-default")
    default_locked = _read_json(default_root / default_paths["locked"])
    default_intent = (default_root / default_paths["intent"]).read_text(encoding="utf-8", errors="strict")

    assert "allowed_repo_refs" not in default_locked
    assert "publication_intent" not in default_locked
    assert "publication_intent:" not in default_intent

    explicit_root = tmp_path / "explicit"
    explicit_paths = builders.build_q_repo(
        explicit_root,
        rel_root="synthetic/q-explicit",
        run_id="q-explicit",
        allowed_repo_refs=["github.com/example/repo"],
        publication_intent={"publish": True, "profile": "public"},
    )
    explicit_locked = _read_json(explicit_root / explicit_paths["locked"])

    assert explicit_locked["allowed_repo_refs"] == ["github.com/example/repo"]
    assert explicit_locked["publication_intent"] == {"publish": True, "profile": "public"}


def test_build_q_repo_emits_current_lockedspec_and_evidence_shapes(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    paths = builders.build_q_repo(repo_root, rel_root="synthetic/q-contract", run_id="q-contract")

    locked = _read_json(repo_root / paths["locked"])
    toolchain_set = _read_json(repo_root / paths["toolchain_set"])
    tolerances = _read_json(repo_root / paths["tolerances"])
    evidence = _read_json(repo_root / paths["evidence"])

    assert locked["belgi_version"] == builders._current_belgi_version()
    assert locked["tier"]["tolerances_ref"]["id"] == "tier.tolerances"
    assert "toolchain_set_ref" not in locked["tier"]
    assert locked["environment_envelope"]["toolchain_set_ref"]["id"] == "env.toolchains"
    assert locked["environment_envelope"]["pinned_toolchain_refs"] == [
        {
            "id": "toolchain.main",
            "hash": "0" * 64,
            "storage_ref": "out/inputs/toolchain.json",
        }
    ]
    assert locked["upstream_state"] == {
        "commit_sha": "0" * 40,
        "dirty_flag": False,
        "repo_ref": "synthetic",
    }

    assert toolchain_set == {
        "schema_version": "1.0.0",
        "toolchain_set_id": "env.toolchains",
        "refs": [],
    }
    assert tolerances["schema_version"] == "1.0.0"
    assert tolerances["tier_id"] == "tier-0"
    assert set(tolerances) == {"schema_version", "tier_id", "scope_budgets"}

    artifact_kinds = [artifact["kind"] for artifact in evidence["artifacts"]]
    assert artifact_kinds == ["command_log", "policy_report", "schema_validation"]
    assert "prompt_bundle" not in artifact_kinds
    assert "repo_diff" not in artifact_kinds

    locked_schema = _read_json(REPO_ROOT / "schemas" / "LockedSpec.schema.json")
    evidence_schema = _read_json(REPO_ROOT / "schemas" / "EvidenceManifest.schema.json")
    toolchain_schema = _read_json(REPO_ROOT / "schemas" / "ToolchainSet.schema.json")
    tolerances_schema = _read_json(REPO_ROOT / "schemas" / "Tolerances.schema.json")

    assert validate_schema(locked, locked_schema, root_schema=locked_schema, path="LockedSpec") == []
    assert validate_schema(evidence, evidence_schema, root_schema=evidence_schema, path="EvidenceManifest") == []
    assert validate_schema(toolchain_set, toolchain_schema, root_schema=toolchain_schema, path="ToolchainSet") == []
    assert validate_schema(tolerances, tolerances_schema, root_schema=tolerances_schema, path="Tolerances") == []


def test_build_q_repo_does_not_repair_a_q3_invalid_request(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    paths = builders.build_q_repo(
        repo_root,
        rel_root="synthetic/q-q3-invalid",
        run_id="q-q3-invalid",
        invariants=[
            {"id": "INV-001", "description": "first", "severity": "policy"},
            {"id": "INV-001", "description": "second", "severity": "policy"},
        ],
    )

    cp = builders.run_gate_q(
        repo_root,
        intent_rel=paths["intent"],
        locked_rel=paths["locked"],
        evidence_rel=paths["evidence"],
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    assert _first_failure_rule_id(repo_root / "out" / "GateVerdict.Q.json") == "Q3"


def test_build_r_repo_does_not_mask_r_doc_001_ownership(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    tiers = tier_fixtures.builtin_tiers()
    tiers["tiers"]["tier-1"]["doc_impact_required"] = True
    paths = builders.build_r_repo(
        repo_root,
        rel_root="synthetic/r-doc-required",
        run_id="r-doc-required",
        tiers_obj=tiers,
        doc_impact={
            "required_paths": ["docs/guide.md"],
            "note_on_empty": "doc update required",
        },
        diff_paths=["src/changed.py"],
    )
    tiers_rel = builders.write_tiers_override(repo_root, tiers)
    commit_sha = builders.init_git_repo(repo_root)

    diff_text = (repo_root / "synthetic" / "r-doc-required" / "repo.diff.patch").read_text(encoding="utf-8", errors="strict")
    assert "docs/guide.md" not in diff_text
    assert "src/changed.py" in diff_text

    cp = builders.run_gate_r(
        repo_root,
        locked_rel=paths["locked"],
        gate_q_rel=paths["gate_q_verdict"],
        evidence_rel=paths["evidence"],
        evaluated_revision=commit_sha,
        tiers_rel=tiers_rel,
    )

    assert cp.returncode == 2, (cp.returncode, cp.stdout, cp.stderr)
    assert _first_failure_rule_id(repo_root / "out" / "GateVerdict.R.json") == "R-DOC-001"


def test_build_r_repo_uses_current_evidence_kinds_only(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    paths = builders.build_r_repo(repo_root, rel_root="synthetic/r-contract", run_id="r-contract")

    evidence = _read_json(repo_root / paths["evidence"])
    artifact_kinds = [artifact["kind"] for artifact in evidence["artifacts"]]

    assert artifact_kinds == [
        "diff",
        "policy_report",
        "policy_report",
        "policy_report",
        "test_report",
        "command_log",
        "schema_validation",
        "env_attestation",
    ]
    assert "repo_diff" not in artifact_kinds
    assert "prompt_bundle" not in artifact_kinds
    assert evidence["envelope_attestation"]["id"] == "env.attestation"
    assert evidence["envelope_attestation"]["storage_ref"].endswith("env_attestation.json")


def test_init_git_repo_returns_final_clean_head_for_positive_r_setup(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    paths = builders.build_r_repo(repo_root, rel_root="synthetic/r-pass", run_id="r-pass")

    evaluated_revision = builders.init_git_repo(repo_root)

    assert evaluated_revision == _git_head(repo_root)
    assert _git_status_porcelain(repo_root) == ""

    locked = _read_json(repo_root / paths["locked"])
    upstream_state = locked.get("upstream_state")
    assert isinstance(upstream_state, dict)
    commit_sha = upstream_state.get("commit_sha")
    assert isinstance(commit_sha, str) and len(commit_sha) == 40
    assert commit_sha != "0" * 40
    assert commit_sha != evaluated_revision

    changed_paths = _git(repo_root, "diff", "--name-only", f"{commit_sha}..{evaluated_revision}").splitlines()
    assert changed_paths == ["src/changed.py"]


def test_post_head_tracked_mutation_is_visible_before_positive_r_invocation(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    builders.build_r_repo(repo_root, rel_root="synthetic/r-pass", run_id="r-pass")

    evaluated_revision = builders.init_git_repo(repo_root)
    assert _git_status_porcelain(repo_root) == ""

    tracked_path = repo_root / "src" / "changed.py"
    tracked_path.write_text("dirty\n", encoding="utf-8", errors="strict", newline="\n")

    assert _git_head(repo_root) == evaluated_revision
    status = _git_status_porcelain(repo_root)
    assert status != ""
    assert "src/changed.py" in status.replace("\\", "/")
