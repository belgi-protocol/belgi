from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.repo_local

ERGONOMIC_FILES = [
    REPO_ROOT / "scripts" / "belgi_latest_run.ps1",
    REPO_ROOT / "scripts" / "belgi_latest_run.sh",
    REPO_ROOT / "scripts" / "belgi_latest_run.py",
    REPO_ROOT / "scripts" / "belgi_wip_commit_run_reset.ps1",
    REPO_ROOT / "docs" / "operations" / "cli.md",
]


def test_helpers_are_adopter_agnostic() -> None:
    blocklist = [
        "portfoly",
        "overlay-capsule",
        "/users/batu/documents/github/portfoly",
    ]
    offenders: list[str] = []

    for path in ERGONOMIC_FILES:
        text = path.read_text(encoding="utf-8", errors="strict").lower()
        for token in blocklist:
            if token in text:
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}: {token}")

    assert offenders == [], "adopter identifiers leaked into canonical ergonomics surfaces:\n" + "\n".join(offenders)

def _pwsh_binary() -> str:
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("pwsh is required for WIP helper behavior tests")
    return pwsh


def _init_git_repo(repo_root: Path) -> None:
    repo_root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=repo_root, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_root, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_root, check=True, capture_output=True, text=True)
    (repo_root / "README.md").write_text("# test\n", encoding="utf-8", errors="strict", newline="\n")
    subprocess.run(["git", "add", "README.md"], cwd=repo_root, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo_root, check=True, capture_output=True, text=True)


def _run_wip_helper(repo_root: Path) -> subprocess.CompletedProcess[str]:
    helper = REPO_ROOT / "scripts" / "belgi_wip_commit_run_reset.ps1"
    return subprocess.run(
        [_pwsh_binary(), "-NoProfile", "-File", str(helper), "-Repo", str(repo_root)],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )


def _assert_fail_closed_preflight(cp: subprocess.CompletedProcess[str], message_fragment: str) -> None:
    assert cp.returncode != 0
    assert message_fragment in (cp.stderr + cp.stdout).lower()


def test_wip_helper_rejects_staged_changes_before_running_belgi(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    (repo / "README.md").write_text("# staged\n", encoding="utf-8", errors="strict", newline="\n")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True, capture_output=True, text=True)

    cp = _run_wip_helper(repo)

    _assert_fail_closed_preflight(cp, "staged changes detected")


def test_wip_helper_rejects_merge_in_progress_before_wip_commit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_git_repo(repo)
    git_dir = (repo / ".git").resolve()
    (git_dir / "MERGE_HEAD").write_text("0" * 40 + "\n", encoding="utf-8", errors="strict", newline="\n")

    cp = _run_wip_helper(repo)

    _assert_fail_closed_preflight(cp, "merge in progress")


@pytest.mark.parametrize("path", ERGONOMIC_FILES)
def test_ergonomic_files_exist(path: Path) -> None:
    assert path.is_file(), f"expected file missing: {path.relative_to(REPO_ROOT).as_posix()}"
