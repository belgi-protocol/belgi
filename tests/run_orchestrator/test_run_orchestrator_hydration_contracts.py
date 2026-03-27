from __future__ import annotations

from importlib.resources import files as resource_files
from pathlib import Path

import pytest

from tests.helpers.repo_imports import BelgiCliSurface, import_fresh_belgi_cli_surface

pytestmark = pytest.mark.repo_local


@pytest.fixture
def fresh_cli_surface() -> BelgiCliSurface:
    return import_fresh_belgi_cli_surface()


def _builtin_template_bytes(name: str) -> bytes:
    return resource_files("belgi").joinpath("templates", name).read_bytes()


def _builtin_canonical_bytes(*parts: str) -> bytes:
    return resource_files("belgi").joinpath("canonicals", *parts).read_bytes()


def test_builtin_template_resources_are_readable() -> None:
    prompt_bytes = _builtin_template_bytes("PromptBundle.blocks.md")
    docs_bytes = _builtin_template_bytes("DocsCompiler.template.md")

    assert prompt_bytes
    assert docs_bytes


def test_builtin_canonical_resources_are_readable() -> None:
    canonical_bytes = _builtin_canonical_bytes("CANONICALS.md")
    terminology_bytes = _builtin_canonical_bytes("terminology.md")
    trust_model_bytes = _builtin_canonical_bytes("trust-model.md")

    assert canonical_bytes
    assert terminology_bytes
    assert trust_model_bytes


def test_ensure_chain_templates_hydrates_missing_templates(
    tmp_path: Path, fresh_cli_surface: BelgiCliSurface
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    run_orchestrator.ensure_chain_templates(chain_repo_root=tmp_path)

    prompt_path = tmp_path / "belgi" / "templates" / "PromptBundle.blocks.md"
    docs_path = tmp_path / "belgi" / "templates" / "DocsCompiler.template.md"

    assert prompt_path.is_file()
    assert docs_path.is_file()
    assert prompt_path.read_bytes() == _builtin_template_bytes("PromptBundle.blocks.md")
    assert docs_path.read_bytes() == _builtin_template_bytes("DocsCompiler.template.md")

    # Idempotency for deterministic re-entry.
    run_orchestrator.ensure_chain_templates(chain_repo_root=tmp_path)


def test_ensure_chain_templates_fail_closed_on_mismatch(
    tmp_path: Path, fresh_cli_surface: BelgiCliSurface
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    prompt_path = tmp_path / "belgi" / "templates" / "PromptBundle.blocks.md"
    prompt_path.parent.mkdir(parents=True, exist_ok=True)
    prompt_path.write_bytes(b"override-not-allowed\n")

    with pytest.raises(ValueError) as exc:
        run_orchestrator.ensure_chain_templates(chain_repo_root=tmp_path)

    message = str(exc.value)
    assert "CHAIN_TEMPLATE_MISMATCH: belgi/templates/PromptBundle.blocks.md" in message
    assert "adopter overrides are not allowed" in message


def test_ensure_chain_c3_canonicals_hydrates_missing_files(
    tmp_path: Path, fresh_cli_surface: BelgiCliSurface
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    run_orchestrator.ensure_chain_c3_canonicals(chain_repo_root=tmp_path)

    root = tmp_path / ".belgi" / "engine" / "c3_canonicals"
    canonical_path = root / "CANONICALS.md"
    terminology_path = root / "terminology.md"
    trust_model_path = root / "trust-model.md"
    operator_anchors_path = root / "docs" / "operations" / "operator-anchors.md"

    assert canonical_path.is_file()
    assert terminology_path.is_file()
    assert trust_model_path.is_file()
    assert operator_anchors_path.is_file()
    assert canonical_path.read_bytes() == _builtin_canonical_bytes("CANONICALS.md")
    assert terminology_path.read_bytes() == _builtin_canonical_bytes("terminology.md")
    assert trust_model_path.read_bytes() == _builtin_canonical_bytes("trust-model.md")
    assert operator_anchors_path.read_bytes() == _builtin_canonical_bytes(
        "docs", "operations", "operator-anchors.md"
    )

    # Idempotency for deterministic re-entry.
    run_orchestrator.ensure_chain_c3_canonicals(chain_repo_root=tmp_path)


def test_ensure_chain_c3_canonicals_fail_closed_on_mismatch(
    tmp_path: Path, fresh_cli_surface: BelgiCliSurface
) -> None:
    run_orchestrator = fresh_cli_surface.run_orchestrator
    term_path = tmp_path / ".belgi" / "engine" / "c3_canonicals" / "terminology.md"
    term_path.parent.mkdir(parents=True, exist_ok=True)
    term_path.write_bytes(b"override-not-allowed\n")

    with pytest.raises(ValueError) as exc:
        run_orchestrator.ensure_chain_c3_canonicals(chain_repo_root=tmp_path)

    message = str(exc.value)
    assert "CHAIN_CANONICAL_MISMATCH: .belgi/engine/c3_canonicals/terminology.md" in message
    assert "staged engine canonicals are immutable" in message
