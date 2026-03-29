from __future__ import annotations

import importlib.resources
import json

from tests.helpers.repo_imports import reset_repo_local_imports

reset_repo_local_imports("belgi")

from belgi.core.json_canon import canonical_json_bytes
from belgi.protocol.pack import MANIFEST_FILENAME, validate_manifest_bytes_tree


def test_builtin_pack_manifest_validates_on_resource_tree() -> None:
    root = importlib.resources.files("belgi").joinpath("_protocol_packs", "v1")
    manifest_node = root.joinpath(MANIFEST_FILENAME)
    manifest_bytes = manifest_node.read_bytes()
    validate_manifest_bytes_tree(pack_root=root, manifest_bytes=manifest_bytes)


def test_builtin_pack_manifest_bytes_canonical_and_stable() -> None:
    root = importlib.resources.files("belgi").joinpath("_protocol_packs", "v1")
    with importlib.resources.as_file(root) as pack_root:
        manifest_path = pack_root / MANIFEST_FILENAME
        b1 = manifest_path.read_bytes()
        b2 = manifest_path.read_bytes()
        assert b1 == b2
        assert b1.endswith(b"\n")

        parsed = json.loads(b1.decode("utf-8"))
        assert b1 == canonical_json_bytes(parsed)
