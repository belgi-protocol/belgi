from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.helpers.script_loader import load_script_module

SCRIPT_PATH = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "validate_belgi_ref_pin.py"


def _load_validator_module():
    return load_script_module("validate_belgi_ref_pin_script", SCRIPT_PATH)


@pytest.mark.parametrize(
    "ref_value",
    [
        "0123456789abcdef0123456789abcdef01234567",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ],
)
def test_validate_belgi_ref_pin_accepts_40_hex_sha(ref_value: str) -> None:
    module = _load_validator_module()
    ok, msg = module.validate_belgi_ref_pin(ref_value)
    assert ok is True
    assert "immutable SHA pin" in msg


@pytest.mark.parametrize(
    "ref_value",
    [
        "",
        "main",
        "master",
        "latest",
        "HEAD",
        "deadbeef",
        "v1.1.0",
        "feature/branch",
        "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
    ],
)
def test_validate_belgi_ref_pin_rejects_non_immutable_refs(ref_value: str) -> None:
    module = _load_validator_module()
    ok, msg = module.validate_belgi_ref_pin(ref_value)
    assert ok is False
    assert "FAIL-CLOSED" in msg
    assert "^[0-9a-f]{40}$" in msg
    assert "reproducibility and integrity" in msg


def test_validator_cli_returns_nonzero_for_floating_ref() -> None:
    cp = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--ref", "main"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode != 0
    assert "FAIL-CLOSED" in cp.stderr


def test_validator_cli_returns_zero_for_pinned_ref() -> None:
    cp = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--ref", "0123456789abcdef0123456789abcdef01234567"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cp.returncode == 0
    assert "immutable SHA pin" in cp.stdout
