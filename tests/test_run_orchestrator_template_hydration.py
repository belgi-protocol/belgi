from __future__ import annotations

from importlib.resources import files as resource_files
from pathlib import Path

import pytest

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
