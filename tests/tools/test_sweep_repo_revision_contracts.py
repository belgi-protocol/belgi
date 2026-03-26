from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.helpers import builders

pytestmark = pytest.mark.repo_local


def _init_git_repo(repo_root: Path) -> str:
    return builders.init_git_repo(repo_root)


def _git_commit_allow_empty(repo_root: Path, message: str) -> str:
    subprocess.run(["git", "commit", "--allow-empty", "-m", message], cwd=repo_root, check=True, capture_output=True)
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_root, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _git_tree_sha(repo_root: Path) -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=repo_root, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def test_sweep_repo_revision_uses_tree_sha_stable_under_empty_commit(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("hello\n", encoding="utf-8", errors="strict", newline="\n")
    head_1 = _init_git_repo(tmp_path)
    tree_1 = _git_tree_sha(tmp_path)

    head_2 = _git_commit_allow_empty(tmp_path, "empty")
    tree_2 = _git_tree_sha(tmp_path)

    assert head_2 != head_1
    assert tree_2 == tree_1

    from tools.sweep import _git_tree_sha as sweep_git_tree_sha

    assert sweep_git_tree_sha(tmp_path) == tree_1


def test_sweep_repo_revision_ignores_consistency_sweep_outputs(tmp_path: Path) -> None:
    (tmp_path / "policy").mkdir(parents=True, exist_ok=True)
    (tmp_path / "policy" / "consistency_sweep.json").write_text(
        "{\"artifact_id\":\"policy.consistency_sweep\"}\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "policy" / "consistency_sweep.summary.md").write_text(
        "# summary\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "a.txt").write_text("hello\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    from tools.sweep import CANONICAL_SWEEP_OUT, CANONICAL_SWEEP_SUMMARY, _git_tree_sha_excluding
    from tools.sweep import _git_tree_sha as sweep_git_tree_sha

    tree_full_1 = sweep_git_tree_sha(tmp_path)
    tree_excluding_1 = _git_tree_sha_excluding(tmp_path, [CANONICAL_SWEEP_OUT, CANONICAL_SWEEP_SUMMARY])

    (tmp_path / "policy" / "consistency_sweep.json").write_text(
        "{\"artifact_id\":\"policy.consistency_sweep\",\"v\":2}\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    subprocess.run(["git", "add", "policy/consistency_sweep.json"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "update sweep"], cwd=tmp_path, check=True, capture_output=True)

    tree_full_2 = sweep_git_tree_sha(tmp_path)
    tree_excluding_2 = _git_tree_sha_excluding(tmp_path, [CANONICAL_SWEEP_OUT, CANONICAL_SWEEP_SUMMARY])

    assert tree_full_2 != tree_full_1
    assert tree_excluding_2 == tree_excluding_1


def test_sweep_repo_revision_blob_override_changes_tree(tmp_path: Path) -> None:
    (tmp_path / "policy").mkdir(parents=True, exist_ok=True)
    (tmp_path / "policy" / "consistency_sweep.json").write_text(
        "{\"artifact_id\":\"policy.consistency_sweep\"}\n",
        encoding="utf-8",
        errors="strict",
        newline="\n",
    )
    (tmp_path / "a.txt").write_text("hello\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    from tools.sweep import CANONICAL_SWEEP_OUT, _git_tree_sha_excluding

    tree_base = _git_tree_sha_excluding(tmp_path, [CANONICAL_SWEEP_OUT])
    tree_override = _git_tree_sha_excluding(
        tmp_path,
        [CANONICAL_SWEEP_OUT],
        blob_overrides={"a.txt": b"override\n"},
    )

    assert tree_override != tree_base


def test_sweep_repo_revision_blob_override_preserves_executable_mode(tmp_path: Path) -> None:
    (tmp_path / "x.sh").write_text("echo hi\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    subprocess.run(["git", "config", "core.filemode", "true"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "add", "x.sh"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "update-index", "--chmod=+x", "x.sh"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add exec"], cwd=tmp_path, check=True, capture_output=True)

    from tools.sweep import _git_tree_sha_excluding

    tree_override = _git_tree_sha_excluding(tmp_path, [], blob_overrides={"x.sh": b"override\n"})
    cp = subprocess.run(
        ["git", "ls-tree", tree_override, "--", "x.sh"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    mode = cp.stdout.strip().split(" ", 1)[0]
    assert mode == "100755"
