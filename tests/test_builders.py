from __future__ import annotations

import json
import os
from pathlib import Path

import builders


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
    tiers = builders.builtin_tiers()
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
