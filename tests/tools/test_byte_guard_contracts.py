from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.helpers import builders

pytestmark = pytest.mark.repo_local


def _init_git_repo(repo_root: Path) -> str:
    return builders.init_git_repo(repo_root)


def test_cs_byte_001_tracked_only_ignores_untracked_crlf(tmp_path: Path) -> None:
    (tmp_path / "tracked_lf.txt").write_text("ok\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    (tmp_path / "untracked_crlf.txt").write_bytes(b"bad\r\n")

    from tools.normalize import scan_byte_guard

    report = scan_byte_guard(tmp_path, tracked_only=True, mode="check")
    assert report["status"] == "PASS"
    assert report["counts"]["drift_files"] == 0


def test_cs_byte_001_tracked_only_fails_on_tracked_crlf(tmp_path: Path) -> None:
    (tmp_path / "good.txt").write_text("ok\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    (tmp_path / "tracked_crlf.txt").write_bytes(b"line1\r\nline2\r\n")
    subprocess.run(["git", "add", "tracked_crlf.txt"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add crlf"], cwd=tmp_path, check=True, capture_output=True)

    from tools.normalize import scan_byte_guard

    report = scan_byte_guard(tmp_path, tracked_only=True, mode="check")
    assert report["status"] == "FAIL"
    paths = sorted(d["path"] for d in report["drift_files"])
    assert paths == ["tracked_crlf.txt"]


def test_byte_guard_reports_binary_extension_unsafe_hits(tmp_path: Path) -> None:
    (tmp_path / "ok.txt").write_text("ok\n", encoding="utf-8", errors="strict", newline="\n")
    _init_git_repo(tmp_path)

    (tmp_path / "file.pdf").write_bytes(b"%PDF-1.4\r\n")
    subprocess.run(["git", "add", "file.pdf"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add pdf"], cwd=tmp_path, check=True, capture_output=True)

    from tools.normalize import scan_byte_guard

    report = scan_byte_guard(tmp_path, tracked_only=True, mode="check")
    assert report["status"] == "PASS"
    assert report["counts"]["skipped"] >= 1
    unsafe = report.get("unsafe_drift_files")
    assert isinstance(unsafe, list)
    paths = sorted(d["path"] for d in unsafe if isinstance(d, dict) and isinstance(d.get("path"), str))
    assert paths == ["file.pdf"]
