from __future__ import annotations

from importlib.resources import files as resource_files
from pathlib import Path

import pytest

from belgi.core import run_orchestrator
from belgi.core.run_orchestrator import ensure_chain_templates


def _builtin_template_bytes(name: str) -> bytes:
    return resource_files("belgi").joinpath("templates", name).read_bytes()


def test_builtin_template_resources_are_readable() -> None:
    prompt_bytes = _builtin_template_bytes("PromptBundle.blocks.md")
    docs_bytes = _builtin_template_bytes("DocsCompiler.template.md")

    assert prompt_bytes
    assert docs_bytes


def test_ensure_chain_templates_hydrates_missing_templates(tmp_path: Path) -> None:
    ensure_chain_templates(chain_repo_root=tmp_path)

    prompt_path = tmp_path / "belgi" / "templates" / "PromptBundle.blocks.md"
    docs_path = tmp_path / "belgi" / "templates" / "DocsCompiler.template.md"

    assert prompt_path.is_file()
    assert docs_path.is_file()
    assert prompt_path.read_bytes() == _builtin_template_bytes("PromptBundle.blocks.md")
    assert docs_path.read_bytes() == _builtin_template_bytes("DocsCompiler.template.md")

    # Idempotency for deterministic re-entry.
    ensure_chain_templates(chain_repo_root=tmp_path)


def test_ensure_chain_templates_fail_closed_on_mismatch(tmp_path: Path) -> None:
    prompt_path = tmp_path / "belgi" / "templates" / "PromptBundle.blocks.md"
    prompt_path.parent.mkdir(parents=True, exist_ok=True)
    prompt_path.write_bytes(b"override-not-allowed\n")

    with pytest.raises(ValueError) as exc:
        ensure_chain_templates(chain_repo_root=tmp_path)

    message = str(exc.value)
    assert "CHAIN_TEMPLATE_MISMATCH: belgi/templates/PromptBundle.blocks.md" in message
    assert "adopter overrides are not allowed" in message


def test_orchestrate_runs_supplychain_before_template_hydration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []

    class _StopAfterEnsure(RuntimeError):
        pass

    def _fake_clone_at_commit(*, source_repo: Path, dest_repo: Path, commit_sha: str) -> None:
        source_repo.mkdir(parents=True, exist_ok=True)
        dest_repo.mkdir(parents=True, exist_ok=True)

    def _fake_supplychain_scan(
        *,
        repo: Path,
        evaluated_revision: str,
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
            repo_head_sha="0123456789abcdef0123456789abcdef01234567",
            intent_bytes=b"intent",
            protocol=object(),
        )

    assert events == ["supplychain", "hydrate"]
