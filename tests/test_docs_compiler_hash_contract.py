from __future__ import annotations

import importlib
import json
import shutil
import sys
from importlib.resources import files as resource_files
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.core.hash import sha256_bytes
import chain.compiler_c3_docs as c3_docs
from chain.compiler_c3_docs import _compute_bundle_root_sha256, _compute_bundle_sha256


def _get_builtin_protocol_context_dynamic() -> object:
    # Full-suite runs may temporarily clear `belgi` from sys.modules in other tests.
    # Re-import from module path each call to keep resource lookup stable.
    importlib.import_module("belgi")
    pack_mod = importlib.import_module("belgi.protocol.pack")
    return getattr(pack_mod, "get_builtin_protocol_context")()


def _fixture_bundled_files(*, manifest_entry_sha: str) -> list[dict[str, object]]:
    return [
        {
            "path": "zeta.md",
            "sha256": "f" * 64,
            "size_bytes": 7,
            "media_type": "text/markdown; charset=utf-8",
        },
        {
            "path": "docs_bundle_manifest.json",
            "sha256": manifest_entry_sha,
            "size_bytes": 11,
            "media_type": "application/json",
        },
        {
            "path": "alpha.md",
            "sha256": "1" * 64,
            "size_bytes": 8,
            "media_type": "text/markdown; charset=utf-8",
        },
        {
            "path": "TOC.md",
            "sha256": "2" * 64,
            "size_bytes": 9,
            "media_type": "text/markdown; charset=utf-8",
        },
    ]


def _locked_protocol_identity(protocol: object) -> dict[str, object]:
    return {
        "protocol_pack": {
            "pack_id": str(getattr(protocol, "pack_id")),
            "manifest_sha256": str(getattr(protocol, "manifest_sha256")),
            "pack_name": str(getattr(protocol, "pack_name")),
        }
    }


def test_c3_bundle_sha256_fixture_contract_is_sorted_and_non_circular() -> None:
    bundled_files = _fixture_bundled_files(manifest_entry_sha="0" * 64)
    got = _compute_bundle_sha256(bundled_files=bundled_files)

    expected_payload = (
        "TOC.md\n"
        + ("2" * 64)
        + "\n"
        + "alpha.md\n"
        + ("1" * 64)
        + "\n"
        + "zeta.md\n"
        + ("f" * 64)
        + "\n"
    ).encode("utf-8", errors="strict")
    expected = sha256_bytes(expected_payload)
    assert got == expected

    # Manifest-entry hash changes must not affect bundle_sha256.
    bundled_files_manifest_changed = _fixture_bundled_files(manifest_entry_sha="9" * 64)
    assert _compute_bundle_sha256(bundled_files=bundled_files_manifest_changed) == got


def test_c3_bundle_root_sha256_fixture_contract() -> None:
    bundle_sha256 = _compute_bundle_sha256(bundled_files=_fixture_bundled_files(manifest_entry_sha="0" * 64))
    manifest_sha256 = "a" * 64

    got = _compute_bundle_root_sha256(
        docs_bundle_manifest_sha256=manifest_sha256,
        bundle_sha256=bundle_sha256,
    )

    expected_payload = f"manifest\n{manifest_sha256}\nbundle\n{bundle_sha256}\n".encode(
        "utf-8", errors="strict"
    )
    assert got == sha256_bytes(expected_payload)


def test_docs_compiler_template_hash_contract_guard() -> None:
    template = (REPO_ROOT / "belgi" / "templates" / "DocsCompiler.template.md").read_text(
        encoding="utf-8", errors="strict"
    )
    template_lc = template.lower()

    required_claims = [
        'path == "docs_bundle_manifest.json"` from `bundle_sha256` computation.',
        "Build UTF-8 payload as exact concatenation of `<path>\\n<sha256>\\n` for each sorted entry.",
        '`bundle_root_sha256 = sha256("manifest\\n" + docs_bundle_manifest_sha256 + "\\nbundle\\n" + bundle_sha256 + "\\n")`.',
    ]
    for claim in required_claims:
        assert claim.lower() in template_lc

    stale_claims = [
        "for each file in order: `<sha256>  <path>\\n`",
        'followed by `"MANIFEST\\n" + sha256(manifest_bytes) + "\\n"`',
        "The manifest file itself is part of the bundle and must be included in the file list and hash computation.",
    ]
    for claim in stale_claims:
        assert claim.lower() not in template_lc


def test_c3_source_resolution_materializes_protocol_bound_canonicals_without_staged_dir(tmp_path: Path) -> None:
    protocol = _get_builtin_protocol_context_dynamic()
    locked = _locked_protocol_identity(protocol)
    source_root, source_tmp = c3_docs._resolve_c3_source_root(
        repo_root=tmp_path,
        protocol=protocol,
        locked_spec=locked,
        out_bundle_dir_path=tmp_path / "out" / "bundle",
    )
    try:
        assert source_tmp is not None
        assert source_root == source_tmp
        assert not (tmp_path / ".belgi" / "engine" / "c3_canonicals").exists()
        assert (source_root / "CANONICALS.md").is_file()
        assert (source_root / "gates" / "GATE_R.md").is_file()
        assert (source_root / "tiers" / "tier-packs.json").is_file()
        assert (source_root / "schemas" / "LockedSpec.schema.json").is_file()
        assert (source_root / "docs" / "operations" / "running-belgi.md").is_file()
    finally:
        if source_tmp is not None and source_tmp.exists():
            shutil.rmtree(source_tmp)


def test_c3_source_resolution_fail_closed_has_remediation_when_materialization_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol = _get_builtin_protocol_context_dynamic()
    locked = _locked_protocol_identity(protocol)

    def _boom(*, protocol: object, target_root: Path) -> None:
        raise c3_docs._UserInputError("simulated missing canonical sources")

    monkeypatch.setattr(c3_docs, "_materialize_protocol_bound_c3_source_root", _boom)
    with pytest.raises(c3_docs._UserInputError) as exc:
        c3_docs._resolve_c3_source_root(
            repo_root=tmp_path,
            protocol=protocol,
            locked_spec=locked,
            out_bundle_dir_path=tmp_path / "out" / "bundle",
        )
    msg = str(exc.value)
    assert ".belgi/engine/c3_canonicals" in msg
    assert "remediation.next_instruction=" in msg


def test_c3_source_resolution_rebuilds_staged_cache_on_identity_mismatch(tmp_path: Path) -> None:
    protocol = _get_builtin_protocol_context_dynamic()
    locked = _locked_protocol_identity(protocol)
    staged_root = tmp_path / ".belgi" / "engine" / "c3_canonicals"
    staged_root.mkdir(parents=True, exist_ok=True)
    (staged_root / "terminology.md").write_text("STALE CACHE\n", encoding="utf-8", errors="strict")
    stale_meta = {
        "protocol_pack_id": "0" * 64,
        "protocol_pack_manifest_sha256": "1" * 64,
        "protocol_pack_name": "stale-pack",
    }
    (staged_root / ".cache_meta.json").write_text(
        json.dumps(stale_meta, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        errors="strict",
    )

    source_root, source_tmp = c3_docs._resolve_c3_source_root(
        repo_root=tmp_path,
        protocol=protocol,
        locked_spec=locked,
        out_bundle_dir_path=tmp_path / "out" / "bundle",
    )
    assert source_tmp is None
    assert source_root == staged_root

    expected_meta = {
        "protocol_pack_id": str(getattr(protocol, "pack_id")),
        "protocol_pack_manifest_sha256": str(getattr(protocol, "manifest_sha256")),
        "protocol_pack_name": str(getattr(protocol, "pack_name")),
    }
    rebuilt_meta = json.loads((staged_root / ".cache_meta.json").read_text(encoding="utf-8", errors="strict"))
    assert rebuilt_meta == expected_meta

    builtin_term = resource_files("belgi").joinpath("canonicals", "terminology.md").read_bytes()
    assert (staged_root / "terminology.md").read_bytes() == builtin_term
