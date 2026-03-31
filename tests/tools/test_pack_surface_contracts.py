from __future__ import annotations

import inspect

import pytest

from belgi.protocol import pack_surface_inventory as inventory

pytestmark = pytest.mark.repo_local


def test_pack_surface_inventory_exports_current_protocol_owner_truth() -> None:
    assert inventory.MANIFEST_FILENAME == "ProtocolPackManifest.json"
    assert inventory.PACK_CONTENT_PREFIXES == ("schemas/", "gates/", "tiers/")
    assert inventory.iter_pack_content_prefixes() == ("schemas/", "gates/", "tiers/")
    assert inventory.PACK_ALLOWED_FOLDERS == frozenset({"schemas", "gates", "tiers"})
    assert inventory.iter_pack_allowed_folders() == ("schemas", "gates", "tiers")
    assert inventory.PACK_ALLOWED_FILES == frozenset({inventory.MANIFEST_FILENAME})
    assert inventory.iter_pack_allowed_files() == (inventory.MANIFEST_FILENAME,)
    assert inventory.C3_CANONICAL_MIRROR_BINDINGS == inventory.iter_c3_canonical_mirror_bindings()


def test_pack_surface_inventory_propagates_directly_to_build_drift_sweep_and_live_scanner() -> None:
    import belgi.protocol.pack as pack
    import tools.build_builtin_pack as build_builtin_pack
    import tools.check_drift as check_drift
    from tools.consistency.invariants import canonicals

    assert pack.MANIFEST_FILENAME is inventory.MANIFEST_FILENAME
    assert pack.PACK_CONTENT_PREFIXES is inventory.PACK_CONTENT_PREFIXES

    assert build_builtin_pack.MANIFEST_FILENAME is inventory.MANIFEST_FILENAME
    assert build_builtin_pack.PACK_ALLOWED_FOLDERS is inventory.PACK_ALLOWED_FOLDERS
    assert build_builtin_pack.PACK_ALLOWED_FILES is inventory.PACK_ALLOWED_FILES
    assert build_builtin_pack.C3_CANONICAL_MIRROR_BINDINGS is inventory.C3_CANONICAL_MIRROR_BINDINGS

    assert check_drift.MANIFEST_FILENAME is inventory.MANIFEST_FILENAME
    assert check_drift.PACK_ALLOWED_FOLDERS is inventory.PACK_ALLOWED_FOLDERS
    assert check_drift.PACK_ALLOWED_FILES is inventory.PACK_ALLOWED_FILES

    mirror_default = inspect.signature(canonicals.check_cs_can_005).parameters["mirror_bindings"].default
    assert mirror_default is inventory.C3_CANONICAL_MIRROR_BINDINGS
