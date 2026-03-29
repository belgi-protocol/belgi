from __future__ import annotations

from pathlib import Path

import pytest

from belgi.protocol.pack import MANIFEST_FILENAME, build_manifest_bytes

pytestmark = pytest.mark.repo_local


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="strict", newline="\n")


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _build_clean_check_drift_repo(repo_root: Path) -> None:
    canonical_files = {
        "schemas/IntentSpec.schema.json": "{}\n",
        "gates/GATE_Q.md": "# Gate Q\n\nDeterministic text.\n",
        "tiers/tier-packs.md": "# Tiers\n\nTier text.\n",
    }
    pack_root = repo_root / "belgi" / "_protocol_packs" / "v1"

    for rel, text in canonical_files.items():
        _write_text(repo_root / rel, text)
        _write_text(pack_root / rel, text)

    manifest_bytes = build_manifest_bytes(pack_root=pack_root, pack_name="test-pack")
    _write_bytes(pack_root / MANIFEST_FILENAME, manifest_bytes)


def test_check_drift_main_passes_for_matching_mirrors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import tools.check_drift as check_drift

    _build_clean_check_drift_repo(tmp_path)
    monkeypatch.setattr(check_drift, "REPO_ROOT", tmp_path)

    rc = check_drift.main()

    assert rc == 0
    assert "OK: No drift detected, pack shape valid." in capsys.readouterr().out


def test_check_drift_main_reports_content_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import tools.check_drift as check_drift

    _build_clean_check_drift_repo(tmp_path)
    _write_text(tmp_path / "gates" / "GATE_Q.md", "# Gate Q\n\nDrifted root text.\n")
    monkeypatch.setattr(check_drift, "REPO_ROOT", tmp_path)

    rc = check_drift.main()

    assert rc == 1
    err = capsys.readouterr().err
    assert "CONTENT DRIFT DETECTED:" in err
    assert "gates/GATE_Q.md: DRIFT (root != pack)" in err


def test_check_drift_main_reports_pack_shape_violation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import tools.check_drift as check_drift

    _build_clean_check_drift_repo(tmp_path)
    (tmp_path / "belgi" / "_protocol_packs" / "v1" / "unexpected").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(check_drift, "REPO_ROOT", tmp_path)

    rc = check_drift.main()

    assert rc == 1
    err = capsys.readouterr().err
    assert "PACK SHAPE VIOLATION:" in err
    assert "unexpected directory: unexpected" in err


def test_check_drift_main_reports_manifest_violation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import tools.check_drift as check_drift

    _build_clean_check_drift_repo(tmp_path)
    _write_text(tmp_path / "belgi" / "_protocol_packs" / "v1" / MANIFEST_FILENAME, "{}\n")
    monkeypatch.setattr(check_drift, "REPO_ROOT", tmp_path)

    rc = check_drift.main()

    assert rc == 1
    err = capsys.readouterr().err
    assert "PACK MANIFEST VIOLATION:" in err
