from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.repo_imports import BelgiCliSurface, import_fresh_belgi_cli_surface

pytestmark = pytest.mark.repo_local


@pytest.fixture
def fresh_cli_surface() -> BelgiCliSurface:
    return import_fresh_belgi_cli_surface()


def test_orchestrate_runs_supplychain_before_template_hydration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    events: list[str] = []

    class _StopAfterEnsure(RuntimeError):
        pass

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)

    def _fake_supplychain_scan(
        *,
        repo: Path,
        base_revision: str,
        evaluated_revision: str,
        declared_toolchain_refs: list[str],
        out_path: Path,
        deterministic: bool,
        run_id: str = "unknown",
    ) -> int:
        events.append("supplychain")
        return 0

    def _fake_ensure_chain_templates(*, chain_repo_root: Path) -> None:
        events.append("hydrate")
        raise _StopAfterEnsure("stop after hydration")

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(run_orchestrator, "run_supplychain_scan", _fake_supplychain_scan)
    monkeypatch.setattr(run_orchestrator, "ensure_chain_templates", _fake_ensure_chain_templates)

    with pytest.raises(_StopAfterEnsure, match="stop after hydration"):
        run_orchestrator.orchestrate_chain_run(
            source_repo_root=tmp_path / "src",
            chain_repo_dir=tmp_path / "chain",
            run_key="run-key",
            tier_id="tier-0",
            base_revision="0123456789abcdef0123456789abcdef01234567",
            evaluated_revision="0123456789abcdef0123456789abcdef01234567",
            revision_discovery_method="explicit",
            upstream_ref=None,
            intent_bytes=b"intent",
            protocol=fresh_cli_surface.get_builtin_protocol_context(),
        )

    assert events == ["supplychain", "hydrate"]


def test_orchestrate_passes_evaluated_revision_to_supplychain_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh_cli_surface: BelgiCliSurface,
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    observed_revisions: dict[str, object] = {}

    class _StopAfterEnsure(RuntimeError):
        pass

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)

    def _fake_supplychain_scan(
        *,
        repo: Path,
        base_revision: str,
        evaluated_revision: str,
        declared_toolchain_refs: list[str],
        out_path: Path,
        deterministic: bool,
        run_id: str = "unknown",
    ) -> int:
        observed_revisions["base_revision"] = base_revision
        observed_revisions["evaluated_revision"] = evaluated_revision
        observed_revisions["declared_toolchain_refs"] = list(declared_toolchain_refs)
        return 0

    def _fake_ensure_chain_templates(*, chain_repo_root: Path) -> None:
        raise _StopAfterEnsure("stop after hydration")

    base_revision = "0123456789abcdef0123456789abcdef01234567"
    evaluated_revision = "89abcdef012345670123456789abcdef01234567"

    monkeypatch.setattr(run_orchestrator, "_command_log_mode_for_tier", lambda **_: "strings")
    monkeypatch.setattr(run_orchestrator, "_git_clone_at_commit", _fake_clone_at_commit)
    monkeypatch.setattr(run_orchestrator, "run_supplychain_scan", _fake_supplychain_scan)
    monkeypatch.setattr(run_orchestrator, "ensure_chain_templates", _fake_ensure_chain_templates)

    with pytest.raises(_StopAfterEnsure, match="stop after hydration"):
        run_orchestrator.orchestrate_chain_run(
            source_repo_root=tmp_path / "src",
            chain_repo_dir=tmp_path / "chain",
            run_key="run-key",
            tier_id="tier-0",
            base_revision=base_revision,
            evaluated_revision=evaluated_revision,
            revision_discovery_method="explicit",
            upstream_ref=None,
            intent_bytes=b"intent",
            protocol=fresh_cli_surface.get_builtin_protocol_context(),
        )

    assert observed_revisions == {
        "base_revision": base_revision,
        "evaluated_revision": evaluated_revision,
        "declared_toolchain_refs": ["toolchain.main=out/inputs/toolchain.json"],
    }
