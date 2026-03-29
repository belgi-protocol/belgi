from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_local


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_protocol_pack_is_data_only_no_py() -> None:
    root = _repo_root()
    pack_root = root / "belgi" / "_protocol_packs"
    assert pack_root.exists() and pack_root.is_dir()

    offenders: list[str] = []
    for p in sorted(pack_root.rglob("*.py")):
        offenders.append(p.relative_to(root).as_posix())

    assert offenders == [], f"Protocol pack must be data-only; found python files: {offenders}"
