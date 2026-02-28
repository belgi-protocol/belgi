from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from tools.github_vars_sanitize import SecretLikeVariableError, sanitize_vars_map


def test_sanitize_vars_map_preserves_allowlist_and_strips_values() -> None:
    raw = json.dumps(
        {
            "BELGI_REF": "  abcdef1234567890abcdef1234567890abcdef12  ",
            "BELGI_REPO_URL": "  https://example.invalid/repo.git  ",
        }
    )
    got = sanitize_vars_map(raw)
    assert got == {
        "BELGI_REF": "abcdef1234567890abcdef1234567890abcdef12",
        "BELGI_REPO_URL": "https://example.invalid/repo.git",
    }


def test_sanitize_vars_map_ignores_non_allowlisted_keys() -> None:
    raw = json.dumps(
        {
            "BELGI_REF": "abcdef1234567890abcdef1234567890abcdef12",
            "BELGI_REPO_URL": "https://example.invalid/repo.git",
            "UNRELATED_FLAG": "yes",
            "ANOTHER_VALUE": "x",
        }
    )
    got = sanitize_vars_map(raw)
    assert got == {
        "BELGI_REF": "abcdef1234567890abcdef1234567890abcdef12",
        "BELGI_REPO_URL": "https://example.invalid/repo.git",
    }


def test_sanitize_vars_map_rejects_secret_like_keys_without_leaking_value() -> None:
    secret_value = "top-secret-value"
    raw = json.dumps(
        {
            "BELGI_REF": "abcdef1234567890abcdef1234567890abcdef12",
            "API_TOKEN": secret_value,
        }
    )
    with pytest.raises(SecretLikeVariableError) as excinfo:
        sanitize_vars_map(raw)
    msg = str(excinfo.value)
    assert "Do not store secrets in repository variables; use GitHub Secrets." in msg
    assert secret_value not in msg


def test_sanitize_vars_map_invalid_json_returns_empty() -> None:
    assert sanitize_vars_map("{not-json") == {}
