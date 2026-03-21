from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / ".github" / "scripts" / "resolve_belgi_workflow_inputs.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("resolve_belgi_workflow_inputs_script", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_resolve_workflow_inputs_prefers_explicit_inputs() -> None:
    module = _load_module()

    resolved = module.resolve_workflow_inputs(
        belgi_ref_input="0123456789abcdef0123456789abcdef01234567",
        belgi_repo_url_input="https://example.invalid/belgi.git",
        vars_json=json.dumps(
            {
                "BELGI_REF": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "BELGI_REPO_URL": "https://example.invalid/ignored.git",
            }
        ),
    )

    assert resolved == {
        "BELGI_REF": "0123456789abcdef0123456789abcdef01234567",
        "BELGI_REPO_URL": "https://example.invalid/belgi.git",
        "BELGI_REF_SHORT": "0123456789ab",
    }


def test_resolve_workflow_inputs_uses_repo_vars_and_default_url() -> None:
    module = _load_module()

    resolved = module.resolve_workflow_inputs(
        belgi_ref_input="",
        belgi_repo_url_input="",
        vars_json=json.dumps({"BELGI_REF": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}),
    )

    assert resolved == {
        "BELGI_REF": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "BELGI_REPO_URL": "https://github.com/belgi-protocol/belgi.git",
        "BELGI_REF_SHORT": "aaaaaaaaaaaa",
    }


def test_resolve_workflow_inputs_rejects_secret_like_repository_vars() -> None:
    module = _load_module()

    with pytest.raises(module.WorkflowInputResolutionError) as excinfo:
        module.resolve_workflow_inputs(
            belgi_ref_input="",
            belgi_repo_url_input="",
            vars_json=json.dumps({"API_TOKEN": "secret-value"}),
        )

    assert "Do not store secrets in repository variables; use GitHub Secrets." in str(excinfo.value)
    assert "secret-value" not in str(excinfo.value)


def test_resolve_workflow_inputs_requires_non_empty_belgi_ref() -> None:
    module = _load_module()

    with pytest.raises(module.WorkflowInputResolutionError) as excinfo:
        module.resolve_workflow_inputs(
            belgi_ref_input="",
            belgi_repo_url_input="",
            vars_json="{}",
        )

    assert "BELGI_REF is required." in str(excinfo.value)
