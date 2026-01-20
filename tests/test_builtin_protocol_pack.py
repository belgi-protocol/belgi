from __future__ import annotations

import json
import importlib.resources
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
for _k in list(sys.modules.keys()):
    if _k == "belgi" or _k.startswith("belgi."):
        del sys.modules[_k]

from belgi.core.json_canon import canonical_json_bytes
from belgi.protocol.pack import MANIFEST_FILENAME, validate_manifest_bytes


def test_builtin_pack_manifest_validates() -> None:
    root = importlib.resources.files("belgi").joinpath("_protocol_packs", "v1")
    with importlib.resources.as_file(root) as pack_root:
        manifest_path = pack_root / MANIFEST_FILENAME
        manifest_bytes = manifest_path.read_bytes()
        validate_manifest_bytes(pack_root=pack_root, manifest_bytes=manifest_bytes)


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
