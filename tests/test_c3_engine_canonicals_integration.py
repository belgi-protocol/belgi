from __future__ import annotations

import json
import subprocess
import sys
from importlib.resources import files as resource_files
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.cli import main as belgi_main


@pytest.fixture(autouse=True)
def _clear_base_revision_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BELGI_BASE_SHA", raising=False)
    monkeypatch.delenv("GITHUB_BASE_SHA", raising=False)


def _init_min_git_repo(tmp_path: Path, *, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, capture_output=True, text=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True, capture_output=True, text=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test User"], check=True, capture_output=True, text=True)
    (repo / "README.md").write_text("# adopter\n", encoding="utf-8", errors="strict")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, capture_output=True, text=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "init"], check=True, capture_output=True, text=True)
    return repo


def _builtin_canonical_bytes(name: str) -> bytes:
    return resource_files("belgi").joinpath("canonicals", name).read_bytes()


def _head_sha(repo: Path) -> str:
    cp = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return cp.stdout.strip().lower()


def test_tier0_run_succeeds_without_repo_root_canonical_docs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _init_min_git_repo(tmp_path)
    assert not (repo / "CANONICALS.md").exists()
    assert not (repo / "terminology.md").exists()
    assert not (repo / "trust-model.md").exists()

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", _head_sha(repo)])
    captured = capsys.readouterr()
    assert rc_run == 0, captured.err
    assert "missing path in scope" not in captured.err

    machine = json.loads(captured.out.splitlines()[0])
    assert machine["ok"] is True
    assert machine["verdict"] == "GO"


def test_tier0_run_uses_engine_canonicals_when_repo_has_collision(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _init_min_git_repo(tmp_path)
    (repo / "terminology.md").write_text("ADOPTER COLLISION\n", encoding="utf-8", errors="strict")
    subprocess.run(["git", "-C", str(repo), "add", "terminology.md"], check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "add conflicting terminology"], check=True, capture_output=True, text=True
    )

    rc_init = belgi_main(["init", "--repo", str(repo)])
    assert rc_init == 0
    _ = capsys.readouterr()

    rc_run = belgi_main(["run", "--repo", str(repo), "--tier", "tier-0", "--base-revision", _head_sha(repo)])
    captured = capsys.readouterr()
    assert rc_run == 0, captured.err

    machine = json.loads(captured.out.splitlines()[0])
    run_key = machine["run_key"]
    attempt_repo = repo / ".belgi" / "runs" / run_key / "attempt-0001" / "repo"

    staged_term = attempt_repo / ".belgi" / "engine" / "c3_canonicals" / "terminology.md"
    bundled_term = attempt_repo / "out" / "bundle" / "terminology.md"
    assert staged_term.is_file()
    assert bundled_term.is_file()

    engine_bytes = _builtin_canonical_bytes("terminology.md")
    assert staged_term.read_bytes() == engine_bytes
    assert bundled_term.read_bytes() == engine_bytes
    assert bundled_term.read_bytes() != b"ADOPTER COLLISION\n"
