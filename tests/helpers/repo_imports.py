from __future__ import annotations

"""Repo-local import hygiene under tests/helpers for heavyweight BELGI tests.

This module is not shipped runtime or tooling authority.
It exists only to centralize deterministic local imports for tests.
"""

import importlib
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]


def _ensure_repo_root_on_syspath() -> None:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))


def _clear_module_prefix(prefix: str) -> None:
    for name in sorted(list(sys.modules)):
        if name == prefix or name.startswith(f"{prefix}."):
            del sys.modules[name]


def _import_fresh(*module_names: str, reset_prefixes: tuple[str, ...]) -> tuple[ModuleType, ...]:
    _ensure_repo_root_on_syspath()
    importlib.invalidate_caches()
    for prefix in reset_prefixes:
        _clear_module_prefix(prefix)
    return tuple(importlib.import_module(name) for name in module_names)


@dataclass(frozen=True)
class BelgiCliSurface:
    cli: ModuleType
    main: Callable[[list[str]], int]
    run_orchestrator: ModuleType
    validate_schema: Callable[..., list[Any]]
    get_builtin_protocol_context: Callable[[], Any]
    load_pinned_trust_anchor: Callable[..., Any]


def import_fresh_belgi_cli_surface() -> BelgiCliSurface:
    cli, run_orchestrator, schema, pack, trust_anchor = _import_fresh(
        "belgi.cli",
        "belgi.core.run_orchestrator",
        "belgi.core.schema",
        "belgi.protocol.pack",
        "belgi.trust_anchor",
        reset_prefixes=("belgi",),
    )
    return BelgiCliSurface(
        cli=cli,
        main=cli.main,
        run_orchestrator=run_orchestrator,
        validate_schema=schema.validate_schema,
        get_builtin_protocol_context=pack.get_builtin_protocol_context,
        load_pinned_trust_anchor=trust_anchor.load_pinned_trust_anchor,
    )


@dataclass(frozen=True)
class CoreSurface:
    normalize_repo_rel: Callable[[str], str]
    normalize_repo_rel_path: Callable[[str], str]
    parse_rfc3339: Callable[[str], Any]
    validate_schema: Callable[..., list[Any]]


def import_fresh_core_surface() -> CoreSurface:
    jail, schema = _import_fresh(
        "belgi.core.jail",
        "belgi.core.schema",
        reset_prefixes=("belgi",),
    )
    return CoreSurface(
        normalize_repo_rel=jail.normalize_repo_rel,
        normalize_repo_rel_path=jail.normalize_repo_rel_path,
        parse_rfc3339=schema.parse_rfc3339,
        validate_schema=schema.validate_schema,
    )


@dataclass(frozen=True)
class ProtocolPackSurface:
    manifest_filename: str
    build_manifest_bytes: Callable[[Path], bytes]


def import_fresh_protocol_pack_surface() -> ProtocolPackSurface:
    (pack,) = _import_fresh("belgi.protocol.pack", reset_prefixes=("belgi",))
    return ProtocolPackSurface(
        manifest_filename=pack.MANIFEST_FILENAME,
        build_manifest_bytes=pack.build_manifest_bytes,
    )
