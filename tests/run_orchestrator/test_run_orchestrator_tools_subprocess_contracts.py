from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.helpers.repo_imports import BelgiCliSurface, import_fresh_belgi_cli_surface

pytestmark = pytest.mark.repo_local


@pytest.fixture
def fresh_cli_surface() -> BelgiCliSurface:
    return import_fresh_belgi_cli_surface()


def test_run_tools_belgi_uses_child_python_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    calls: list[tuple[list[str], dict[str, object]]] = []

    def _fake_subprocess_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[object]:
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(args=cmd, returncode=0)

    monkeypatch.setattr(run_orchestrator.subprocess, "run", _fake_subprocess_run)

    rc = run_orchestrator._run_tools_belgi(
        tmp_path,
        ["run-tests", "--run-id", "run-test-001", "--out", "out/artifacts/tests.report.json", "--deterministic"],
    )

    assert rc == 0
    assert calls == [
        (
            [
                sys.executable,
                "-m",
                "tools.belgi_tools",
                "run-tests",
                "--run-id",
                "run-test-001",
                "--out",
                "out/artifacts/tests.report.json",
                "--deterministic",
                "--repo",
                str(tmp_path),
            ],
            {"check": False, "shell": False},
        )
    ]
