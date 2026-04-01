"""Protocol pack lifecycle tests: determinism, tamper detection, identity consistency.

These tests verify:
1. Pack build produces identical manifest bytes on repeated runs (determinism)
2. Tampering with any file causes verification to fail
3. load_protocol_context_from_dir returns pack_id/manifest_sha256 consistent with manifest
4. Symlinks are rejected anywhere under pack root

ACCEPTANCE CRITERIA:
- `belgi pack build` produces deterministic manifest (same inputs -> identical bytes)
- `belgi pack verify` fails on any drift/tamper
- Protocol context identity fields match manifest
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from tests.helpers.repo_imports import reset_repo_local_imports

reset_repo_local_imports("belgi")

from belgi.core.hash import sha256_bytes
from belgi.core.json_canon import canonical_json_bytes
from belgi.protocol.pack import (
    MANIFEST_FILENAME,
    DevOverrideNotAllowedError,
    build_manifest_bytes,
    build_manifest_obj,
    compute_pack_id,
    load_protocol_context_from_dir,
    scan_pack_dir,
    validate_manifest_bytes,
)
from belgi.protocol.pack_surface_inventory import PACK_CONTENT_PREFIXES


@pytest.fixture
def temp_pack_dir() -> Path:
    """Create a minimal protocol pack directory for testing."""
    tmpdir = tempfile.mkdtemp(prefix="belgi_pack_test_")
    pack_root = Path(tmpdir)

    schemas_dir = pack_root / "schemas"
    schemas_dir.mkdir()
    (schemas_dir / "Test.schema.json").write_bytes(
        b'{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}\n'
    )

    gates_dir = pack_root / "gates"
    gates_dir.mkdir()
    (gates_dir / "GATE_TEST.md").write_bytes(b"# Test Gate\n\nTest content.\n")

    tiers_dir = pack_root / "tiers"
    tiers_dir.mkdir()
    (tiers_dir / "test-tiers.md").write_bytes(b"# Test Tiers\n\nTier-0 description.\n")

    yield pack_root

    shutil.rmtree(tmpdir, ignore_errors=True)


class TestPackBuildDeterminism:
    """Verify pack build produces identical manifest bytes on repeated runs."""

    def test_build_manifest_bytes_identical_on_repeated_calls(self, temp_pack_dir: Path) -> None:
        """Same pack directory produces identical manifest bytes."""
        b1 = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        b2 = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        assert b1 == b2, "manifest bytes must be identical on repeated builds"

    def test_build_manifest_bytes_canonical_json(self, temp_pack_dir: Path) -> None:
        """Manifest bytes must be canonical JSON."""
        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        parsed = json.loads(manifest_bytes.decode("utf-8"))
        re_canonical = canonical_json_bytes(parsed)
        assert manifest_bytes == re_canonical, "manifest bytes must be canonical"

    def test_build_manifest_bytes_ends_with_lf(self, temp_pack_dir: Path) -> None:
        """Manifest bytes must end with LF (POSIX newline)."""
        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        assert manifest_bytes.endswith(b"\n"), "manifest must end with LF"

    def test_scan_pack_dir_stable_ordering(self, temp_pack_dir: Path) -> None:
        """scan_pack_dir must return entries in stable sorted order."""
        entries1 = scan_pack_dir(temp_pack_dir)
        entries2 = scan_pack_dir(temp_pack_dir)

        assert len(entries1) == len(entries2)
        for e1, e2 in zip(entries1, entries2, strict=True):
            assert e1.relpath == e2.relpath
            assert e1.sha256 == e2.sha256
            assert e1.size_bytes == e2.size_bytes

        relpaths = [e.relpath for e in entries1]
        assert relpaths == sorted(relpaths), "entries must be sorted by relpath"

    def test_pack_id_stable_across_builds(self, temp_pack_dir: Path) -> None:
        """pack_id must be stable across builds."""
        obj1 = build_manifest_obj(pack_root=temp_pack_dir, pack_name="test-pack")
        obj2 = build_manifest_obj(pack_root=temp_pack_dir, pack_name="test-pack")
        assert obj1["pack_id"] == obj2["pack_id"], "pack_id must be stable"


class TestPackTamperDetection:
    """Verify tampering with any file causes verification to fail."""

    def test_tamper_file_content_fails_verify(self, temp_pack_dir: Path) -> None:
        """Editing file content causes validation failure."""
        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        (temp_pack_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)
        validate_manifest_bytes(pack_root=temp_pack_dir, manifest_bytes=manifest_bytes)

        schema_file = temp_pack_dir / "schemas" / "Test.schema.json"
        original = schema_file.read_bytes()
        schema_file.write_bytes(original + b"// tampered\n")

        with pytest.raises(ValueError, match="do not match"):
            validate_manifest_bytes(pack_root=temp_pack_dir, manifest_bytes=manifest_bytes)

    def test_tamper_add_file_fails_verify(self, temp_pack_dir: Path) -> None:
        """Adding a new file causes validation failure."""
        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        (temp_pack_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)

        (temp_pack_dir / "schemas" / "NewSchema.schema.json").write_bytes(b'{"type":"string"}\n')

        with pytest.raises(ValueError, match="do not match"):
            validate_manifest_bytes(pack_root=temp_pack_dir, manifest_bytes=manifest_bytes)

    def test_tamper_delete_file_fails_verify(self, temp_pack_dir: Path) -> None:
        """Deleting a file causes validation failure."""
        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        (temp_pack_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)

        (temp_pack_dir / "gates" / "GATE_TEST.md").unlink()

        with pytest.raises(ValueError, match="do not match"):
            validate_manifest_bytes(pack_root=temp_pack_dir, manifest_bytes=manifest_bytes)

    def test_tamper_pack_id_in_manifest_fails_verify(self, temp_pack_dir: Path) -> None:
        """Tampering with pack_id in manifest causes validation failure."""
        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        parsed = json.loads(manifest_bytes.decode("utf-8"))
        parsed["pack_id"] = "0" * 64
        tampered_bytes = canonical_json_bytes(parsed)

        with pytest.raises(ValueError, match="pack_id mismatch"):
            validate_manifest_bytes(pack_root=temp_pack_dir, manifest_bytes=tampered_bytes)

    def test_tamper_pack_name_changes_manifest_sha256(self, temp_pack_dir: Path) -> None:
        """Changing pack_name changes manifest_sha256 (detected via binding)."""
        b1 = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="pack-a")
        b2 = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="pack-b")

        sha1 = sha256_bytes(b1)
        sha2 = sha256_bytes(b2)

        p1 = json.loads(b1.decode("utf-8"))
        p2 = json.loads(b2.decode("utf-8"))
        assert p1["pack_id"] == p2["pack_id"], "pack_id should not change with pack_name"
        assert sha1 != sha2, "manifest_sha256 should differ when pack_name changes"


class TestProtocolContextIdentity:
    """Verify load_protocol_context_from_dir returns identity consistent with manifest."""

    def test_context_pack_id_matches_manifest(self, temp_pack_dir: Path) -> None:
        """ProtocolContext.pack_id matches manifest.pack_id."""
        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        (temp_pack_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)

        ctx = load_protocol_context_from_dir(pack_root=temp_pack_dir, source="override")

        parsed = json.loads(manifest_bytes.decode("utf-8"))
        assert ctx.pack_id == parsed["pack_id"]

    def test_context_manifest_sha256_matches_computed(self, temp_pack_dir: Path) -> None:
        """ProtocolContext.manifest_sha256 matches sha256 of manifest bytes."""
        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        (temp_pack_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)

        ctx = load_protocol_context_from_dir(pack_root=temp_pack_dir, source="override")
        expected_sha = sha256_bytes(manifest_bytes)
        assert ctx.manifest_sha256 == expected_sha

    def test_context_pack_name_matches_manifest(self, temp_pack_dir: Path) -> None:
        """ProtocolContext.pack_name matches manifest.pack_name."""
        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="custom-pack-name")
        (temp_pack_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)

        ctx = load_protocol_context_from_dir(pack_root=temp_pack_dir, source="override")
        assert ctx.pack_name == "custom-pack-name"

    def test_context_source_recorded(self, temp_pack_dir: Path) -> None:
        """ProtocolContext.source records how pack was loaded."""
        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        (temp_pack_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)

        ctx = load_protocol_context_from_dir(pack_root=temp_pack_dir, source="override")
        assert ctx.source == "override"


class TestSymlinkRejection:
    """Verify symlinks are rejected anywhere under pack root."""

    @pytest.mark.skipif(os.name == "nt", reason="symlinks may require admin on Windows")
    def test_symlink_file_rejected(self, temp_pack_dir: Path) -> None:
        """Symlink file in pack is rejected."""
        target = temp_pack_dir / "schemas" / "Test.schema.json"
        link = temp_pack_dir / "schemas" / "Link.schema.json"
        link.symlink_to(target)

        with pytest.raises(ValueError, match="symlink"):
            scan_pack_dir(temp_pack_dir)

    @pytest.mark.skipif(os.name == "nt", reason="symlinks may require admin on Windows")
    def test_symlink_dir_rejected(self, temp_pack_dir: Path) -> None:
        """Symlink directory in pack is rejected."""
        target = temp_pack_dir / "schemas"
        link = temp_pack_dir / "schemas_link"
        link.symlink_to(target)

        with pytest.raises(ValueError, match="symlink"):
            scan_pack_dir(temp_pack_dir)

    @pytest.mark.skipif(os.name == "nt", reason="symlinks may require admin on Windows")
    def test_symlink_in_excluded_dir_still_rejected(self, temp_pack_dir: Path) -> None:
        """Symlinks inside excluded dirs (like __pycache__) are still rejected."""
        pycache = temp_pack_dir / "__pycache__"
        pycache.mkdir()
        target = temp_pack_dir / "schemas" / "Test.schema.json"
        link = pycache / "sneaky_link"
        link.symlink_to(target)

        with pytest.raises(ValueError, match="symlink"):
            scan_pack_dir(temp_pack_dir)


class TestDevOverrideGuard:
    """Verify dev-override requires BELGI_DEV=1 and forbids CI."""

    def test_dev_override_without_belgi_dev_fails(self, temp_pack_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """dev-override without BELGI_DEV=1 is rejected."""
        monkeypatch.delenv("BELGI_DEV", raising=False)
        monkeypatch.delenv("CI", raising=False)

        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        (temp_pack_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)

        with pytest.raises(DevOverrideNotAllowedError, match="BELGI_DEV=1"):
            load_protocol_context_from_dir(pack_root=temp_pack_dir, source="dev-override")

    def test_dev_override_in_ci_fails(self, temp_pack_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """dev-override in CI environment is rejected."""
        monkeypatch.setenv("BELGI_DEV", "1")
        monkeypatch.setenv("CI", "true")

        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        (temp_pack_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)

        with pytest.raises(DevOverrideNotAllowedError, match="CI"):
            load_protocol_context_from_dir(pack_root=temp_pack_dir, source="dev-override")

    def test_dev_override_with_belgi_dev_succeeds(self, temp_pack_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """dev-override with BELGI_DEV=1 and no CI succeeds."""
        monkeypatch.setenv("BELGI_DEV", "1")
        monkeypatch.delenv("CI", raising=False)

        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        (temp_pack_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)

        ctx = load_protocol_context_from_dir(pack_root=temp_pack_dir, source="dev-override")
        assert ctx.source == "dev-override"


class TestComputePackId:
    """Verify pack_id computation details."""

    def test_pack_id_is_64_hex_chars(self, temp_pack_dir: Path) -> None:
        """pack_id must be 64 hex characters (SHA-256)."""
        entries = scan_pack_dir(temp_pack_dir)
        pack_id = compute_pack_id(entries)

        assert len(pack_id) == 64
        assert all(c in "0123456789abcdef" for c in pack_id)

    def test_pack_id_excludes_manifest(self, temp_pack_dir: Path) -> None:
        """pack_id computation excludes manifest file."""
        manifest_bytes = build_manifest_bytes(pack_root=temp_pack_dir, pack_name="test-pack")
        (temp_pack_dir / MANIFEST_FILENAME).write_bytes(manifest_bytes)

        entries = scan_pack_dir(temp_pack_dir)
        relpaths = [e.relpath for e in entries]
        assert MANIFEST_FILENAME not in relpaths

        pack_id_with = compute_pack_id(entries)

        (temp_pack_dir / MANIFEST_FILENAME).unlink()
        entries_without = scan_pack_dir(temp_pack_dir)
        pack_id_without = compute_pack_id(entries_without)

        assert pack_id_with == pack_id_without

    def test_pack_id_excludes_scaffolding(self, temp_pack_dir: Path) -> None:
        """pack_id excludes scaffolding files (__init__.py, .pyc, etc.)."""
        (temp_pack_dir / "__init__.py").write_bytes(b"# scaffolding\n")
        (temp_pack_dir / "schemas" / "__init__.py").write_bytes(b"# scaffolding\n")

        entries = scan_pack_dir(temp_pack_dir)
        relpaths = [e.relpath for e in entries]

        assert "__init__.py" not in relpaths
        assert "schemas/__init__.py" not in relpaths

        for rp in relpaths:
            assert rp.startswith(PACK_CONTENT_PREFIXES)
