from __future__ import annotations

import os
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


def test_orchestrate_preserves_parent_ci_while_c1_uses_child_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    captured: dict[str, object] = {}

    class _StopAfterC1(RuntimeError):
        pass

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)

    def _fake_run_module_subprocess_expect_rc(
        module_name: str,
        argv: list[str],
        *,
        allowed: tuple[int, ...] = (0,),
        env: dict[str, str] | None = None,
    ) -> None:
        captured["module_name"] = module_name
        captured["argv"] = list(argv)
        captured["allowed"] = allowed
        captured["env"] = None if env is None else dict(env)
        raise _StopAfterC1("stop after c1")

    monkeypatch.setenv("CI", "1")
    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(run_orchestrator, "run_supplychain_scan", lambda **_: 0)
    monkeypatch.setattr(run_orchestrator, "ensure_chain_templates", lambda **_: None)
    monkeypatch.setattr(
        run_orchestrator,
        "_run_module_subprocess_expect_rc",
        _fake_run_module_subprocess_expect_rc,
    )

    with pytest.raises(_StopAfterC1, match="stop after c1"):
        run_orchestrator.orchestrate_chain_run(
            source_repo_root=tmp_path / "src",
            chain_repo_dir=tmp_path / "chain",
            run_key="run-key",
            tier_id="tier-0",
            base_revision="0123456789abcdef0123456789abcdef01234567",
            evaluated_revision="89abcdef012345670123456789abcdef01234567",
            revision_discovery_method="explicit",
            upstream_ref=None,
            intent_bytes=b"intent",
            protocol=fresh_cli_surface.get_builtin_protocol_context(),
        )

    assert captured["module_name"] == "chain.compiler_c1_intent"
    assert captured["allowed"] == (0,)
    child_env = captured["env"]
    assert isinstance(child_env, dict)
    assert "CI" not in child_env
    assert os.environ.get("CI") == "1"
