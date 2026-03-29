from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.helpers.repo_imports import reset_repo_local_imports

reset_repo_local_imports("belgi")

from belgi.protocol.pack import (
    _is_pack_content_file,
    build_manifest_bytes,
    canonical_json_bytes,
    compute_pack_id,
    scan_pack_dir,
    validate_manifest_bytes,
)


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_pack_content_filter_excludes_scaffolding() -> None:
    """Test that _is_pack_content_file correctly filters scaffolding."""
    assert not _is_pack_content_file("ProtocolPackManifest.json")
    assert not _is_pack_content_file("schemas/__init__.py")
    assert not _is_pack_content_file("gates/helper.py")
    assert not _is_pack_content_file("tiers/utils.pyc")
    assert not _is_pack_content_file("schemas/cache.pyo")
    assert not _is_pack_content_file("schemas/__pycache__/foo.cpython-311.pyc")
    assert not _is_pack_content_file("schemas/.DS_Store")
    assert not _is_pack_content_file("gates/.gitkeep")
    assert not _is_pack_content_file("README.md")
    assert not _is_pack_content_file("VERSION")
    assert not _is_pack_content_file("docs/foo.md")

    assert _is_pack_content_file("schemas/IntentSpec.schema.json")
    assert _is_pack_content_file("gates/GATE_Q.md")
    assert _is_pack_content_file("gates/failure-taxonomy.md")
    assert _is_pack_content_file("tiers/tier-packs.md")
    assert _is_pack_content_file("tiers/tier-packs.json")
    assert _is_pack_content_file("schemas/README.md")


def test_pack_id_stable_with_scaffolding_changes(tmp_path: Path) -> None:
    """Test that pack_id does not change when scaffolding files change."""
    pack_root = tmp_path / "pack"
    pack_root.mkdir(parents=True, exist_ok=True)

    _write_bytes(pack_root / "schemas" / "IntentSpec.schema.json", b'{"title":"IntentSpec"}\n')
    _write_bytes(pack_root / "gates" / "GATE_Q.md", b"# Gate Q\n")
    _write_bytes(pack_root / "tiers" / "tier-packs.md", b"# Tiers\n")

    entries_baseline = scan_pack_dir(pack_root)
    pack_id_baseline = compute_pack_id(entries_baseline)

    _write_bytes(pack_root / "schemas" / "__init__.py", b"# init\n")
    entries_after_init = scan_pack_dir(pack_root)
    pack_id_after_init = compute_pack_id(entries_after_init)
    assert pack_id_after_init == pack_id_baseline, "__init__.py should not affect pack_id"

    _write_bytes(pack_root / "schemas" / "__pycache__" / "foo.cpython-311.pyc", b"\x00\x00")
    entries_after_pycache = scan_pack_dir(pack_root)
    pack_id_after_pycache = compute_pack_id(entries_after_pycache)
    assert pack_id_after_pycache == pack_id_baseline, "__pycache__ should not affect pack_id"

    _write_bytes(pack_root / "gates" / "helper.py", b"def foo(): pass\n")
    entries_after_py = scan_pack_dir(pack_root)
    pack_id_after_py = compute_pack_id(entries_after_py)
    assert pack_id_after_py == pack_id_baseline, ".py files should not affect pack_id"

    _write_bytes(pack_root / "schemas" / ".DS_Store", b"\x00\x00\x00\x01")
    entries_after_ds = scan_pack_dir(pack_root)
    pack_id_after_ds = compute_pack_id(entries_after_ds)
    assert pack_id_after_ds == pack_id_baseline, ".DS_Store should not affect pack_id"

    _write_bytes(pack_root / "schemas" / "IntentSpec.schema.json", b'{"title":"IntentSpec","modified":true}\n')
    entries_after_content = scan_pack_dir(pack_root)
    pack_id_after_content = compute_pack_id(entries_after_content)
    assert pack_id_after_content != pack_id_baseline, "protocol content change MUST affect pack_id"


def test_scan_rejects_symlink_pack_root(tmp_path: Path) -> None:
    pack_root = tmp_path / "pack"
    real = tmp_path / "real"
    real.mkdir(parents=True, exist_ok=True)
    _write_bytes(real / "schemas" / "A.schema.json", b"{}\n")

    try:
        pack_root.symlink_to(real, target_is_directory=True)
    except OSError as e:
        if getattr(e, "winerror", None) == 1314:
            pytest.skip("symlink creation not permitted (WinError 1314)")
        raise

    with pytest.raises(ValueError, match=r"symlink directory not allowed"):
        scan_pack_dir(pack_root)


def test_scan_rejects_symlink_dir(tmp_path: Path) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir(parents=True, exist_ok=True)

    real_dir = tmp_path / "real_dir"
    real_dir.mkdir(parents=True, exist_ok=True)
    _write_bytes(real_dir / "X.txt", b"x")

    try:
        (pack_root / "schemas").symlink_to(real_dir, target_is_directory=True)
    except OSError as e:
        if getattr(e, "winerror", None) == 1314:
            pytest.skip("symlink creation not permitted (WinError 1314)")
        raise

    with pytest.raises(ValueError, match=r"symlink directory not allowed"):
        scan_pack_dir(pack_root)


def test_manifest_files_are_sorted_by_relpath(tmp_path: Path) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir(parents=True, exist_ok=True)

    _write_bytes(pack_root / "tiers" / "tier-packs.md", b"# tiers\n")
    _write_bytes(pack_root / "schemas" / "B.schema.json", b"{\"b\":2}\n")
    _write_bytes(pack_root / "schemas" / "A.schema.json", b"{\"a\":1}\n")
    _write_bytes(pack_root / "gates" / "GATE_Q.md", b"Q\n")

    manifest = json.loads(build_manifest_bytes(pack_root=pack_root, pack_name="test-pack", pack_semver="0.0.0").decode("utf-8"))
    files = manifest.get("files")
    assert isinstance(files, list)
    relpaths = [row["relpath"] for row in files]
    assert relpaths == sorted(relpaths)


def test_manifest_pack_id_matches_computed(tmp_path: Path) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir(parents=True, exist_ok=True)

    _write_bytes(pack_root / "schemas" / "IntentSpec.schema.json", b"{}\n")
    _write_bytes(pack_root / "gates" / "failure-taxonomy.md", b"taxonomy\n")

    manifest_bytes = build_manifest_bytes(pack_root=pack_root, pack_name="test-pack")
    manifest = json.loads(manifest_bytes.decode("utf-8"))

    entries = scan_pack_dir(pack_root)
    assert manifest["pack_id"] == compute_pack_id(entries)


def test_validate_manifest_fails_closed_on_mismatch(tmp_path: Path) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir(parents=True, exist_ok=True)

    _write_bytes(pack_root / "schemas" / "LockedSpec.schema.json", b"{}\n")
    _write_bytes(pack_root / "gates" / "GATE_R.md", b"R\n")

    manifest_bytes = build_manifest_bytes(pack_root=pack_root, pack_name="test-pack")
    validate_manifest_bytes(pack_root=pack_root, manifest_bytes=manifest_bytes)

    obj = json.loads(manifest_bytes.decode("utf-8"))
    obj["pack_id"] = "0" * 64
    tampered = canonical_json_bytes(obj)

    with pytest.raises(ValueError, match=r"pack_id mismatch"):
        validate_manifest_bytes(pack_root=pack_root, manifest_bytes=tampered)


def test_validate_manifest_rejects_non_hex_pack_id(tmp_path: Path) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir(parents=True, exist_ok=True)

    _write_bytes(pack_root / "schemas" / "LockedSpec.schema.json", b"{}\n")
    _write_bytes(pack_root / "gates" / "GATE_R.md", b"R\n")

    manifest_bytes = build_manifest_bytes(pack_root=pack_root, pack_name="test-pack")
    obj = json.loads(manifest_bytes.decode("utf-8"))
    obj["pack_id"] = "g" * 64
    tampered = canonical_json_bytes(obj)

    with pytest.raises(ValueError, match=r"manifest\.pack_id must be 64-hex chars"):
        validate_manifest_bytes(pack_root=pack_root, manifest_bytes=tampered)


def test_validate_manifest_rejects_non_hex_file_sha256(tmp_path: Path) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir(parents=True, exist_ok=True)

    _write_bytes(pack_root / "schemas" / "LockedSpec.schema.json", b"{}\n")
    _write_bytes(pack_root / "gates" / "GATE_R.md", b"R\n")

    manifest_bytes = build_manifest_bytes(pack_root=pack_root, pack_name="test-pack")
    obj = json.loads(manifest_bytes.decode("utf-8"))
    assert isinstance(obj.get("files"), list) and obj["files"], "test requires at least one file"
    obj["files"][0]["sha256"] = "z" * 64
    tampered = canonical_json_bytes(obj)

    with pytest.raises(ValueError, match=r"manifest\.files\[0\]\.sha256 must be 64-hex chars"):
        validate_manifest_bytes(pack_root=pack_root, manifest_bytes=tampered)
