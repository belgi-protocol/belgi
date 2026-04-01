from __future__ import annotations

from tools._shared import common as _common
from tools._sweep.input_surface_spec import (
    DECLARED_FIXED_INPUT_FAMILIES,
)
from tools._sweep.managed_surfaces import _sweep_managed_surface_files


def _iter_declared_fixed_input_files() -> list[str]:
    relpaths: set[str] = set()
    for _family_name, members in DECLARED_FIXED_INPUT_FAMILIES:
        for rel in members:
            relpaths.add(_common._validate_repo_rel(rel))
    return sorted(relpaths)


def _iter_schema_files(repo_root: _common.Path) -> list[str]:
    schemas_dir = _common._resolve_repo_path(repo_root, "schemas", must_exist=True, must_be_file=False)

    out: list[str] = []
    for p in sorted(schemas_dir.glob("*.schema.json"), key=lambda x: x.name):
        rel = p.resolve().relative_to(repo_root.resolve()).as_posix()
        out.append(rel)
    return out


def _iter_builtin_protocol_pack_files(repo_root: _common.Path) -> list[str]:
    """Deterministically enumerate builtin protocol pack files.

    These are part of the governed surface because the active builtin pack
    identity is authoritative and the manifest is validated against its tree.
    Fail-closed on symlinks.
    """

    pack_root = _common._resolve_repo_path(repo_root, "belgi/_protocol_packs/v1", must_exist=True, must_be_file=False)
    if not pack_root.is_dir():
        raise _common._UserInputError("builtin protocol pack root is not a directory: belgi/_protocol_packs/v1")

    out: list[str] = []
    for dirpath, dirnames, filenames in _common.os.walk(pack_root, followlinks=False):
        d = _common.Path(dirpath)
        if d.is_symlink():
            raise _common._UserInputError(f"symlink directory not allowed under belgi/_protocol_packs/v1: {d}")
        dirnames.sort()
        filenames.sort()
        for name in filenames:
            p = d / name
            if p.is_symlink():
                raise _common._UserInputError(f"symlink file not allowed under belgi/_protocol_packs/v1: {p}")
            rel = p.resolve().relative_to(repo_root.resolve()).as_posix()
            out.append(rel)

    out.sort()
    return out


def _canonical_inputs(repo_root: _common.Path) -> list[str]:
    base = _iter_declared_fixed_input_files()

    # managed_surface_spec.py owns the family law; managed_surfaces.py resolves
    # the concrete tracked set, which canonical inputs then compose.
    base.extend(_sweep_managed_surface_files(repo_root))

    # Dynamic, authoritative schema surface.
    base.extend(_iter_schema_files(repo_root))

    # Dynamic, authoritative builtin protocol pack surface.
    base.extend(_iter_builtin_protocol_pack_files(repo_root))

    # Normalize, de-dup, stable order.
    canon = sorted(set(_common._validate_repo_rel(p) for p in base))
    return canon
