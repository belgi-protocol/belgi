#!/usr/bin/env python3
"""Unified sweeper entrypoint.

This file is the canonical sweep CLI.

Commands:
- consistency: generate policy/consistency_sweep.json (canonical)
"""

# maintainer marker: bk_ycanary_7f3a9c2d

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Callable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]

# Allow running from outside the repo by pinning imports to this repo root.
repo_root_str = str(REPO_ROOT)
if repo_root_str in sys.path:
    sys.path.remove(repo_root_str)
sys.path.insert(0, repo_root_str)

from tools.consistency import common as _common
from tools.consistency import inputs as _inputs_owner
from tools.consistency import registry as _registry_owner
from tools.consistency.model import InvariantResult
from tools.consistency.runner import run_consistency_sweep

CANONICAL_SWEEP_OUT = _common.CANONICAL_SWEEP_OUT
CANONICAL_SWEEP_SUMMARY = _common.CANONICAL_SWEEP_SUMMARY
CONSISTENCY_SPEC_DOC = _common.CONSISTENCY_SPEC_DOC
_UserInputError = _common._UserInputError
_validate_repo_rel = _common._validate_repo_rel
_resolve_repo_path = _common._resolve_repo_path
_git_tree_sha_excluding_impl = _common._git_tree_sha_excluding
read_text = _common.read_text

_SPEC_INVARIANT_ID_RE = re.compile(r"(?m)^\s*-\s*invariant_id:\s*(CS-[A-Z0-9_-]+)\s*$")

def _extract_spec_invariant_ids(repo_root: Path) -> list[str]:
    """Extract invariant IDs from the canonical consistency sweep spec.

    Deterministic and fail-closed: empty or duplicate IDs are NO-GO.
    """

    spec_path = _resolve_repo_path(repo_root, CONSISTENCY_SPEC_DOC, must_exist=True, must_be_file=True)
    txt = read_text(spec_path)
    ids = _SPEC_INVARIANT_ID_RE.findall(txt)
    if not ids:
        raise _UserInputError(f"no invariant_id entries found in {CONSISTENCY_SPEC_DOC}")

    seen: set[str] = set()
    dups: list[str] = []
    for inv in ids:
        if inv in seen and inv not in dups:
            dups.append(inv)
        seen.add(inv)

    if dups:
        raise _UserInputError(f"duplicate invariant_id entries in {CONSISTENCY_SPEC_DOC}: {sorted(dups)}")

    return sorted(seen)

def _git_tree_sha_excluding(
    repo_root: Path,
    exclude_paths: Sequence[str],
    *,
    blob_overrides: dict[str, bytes] | None = None,
) -> str:
    return _git_tree_sha_excluding_impl(repo_root, exclude_paths, blob_overrides=blob_overrides)


def _canonical_inputs(repo_root: Path) -> list[str]:
    return _inputs_owner._canonical_inputs(repo_root)


def _sweep_managed_surface_files(root: Path) -> list[str]:
    return _inputs_owner._sweep_managed_surface_files(root)


def _invariant_registry() -> dict[str, Callable[[Path], InvariantResult]]:
    return _registry_owner.invariant_registry()

def _consistency_sweep_main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".", help="Repo root path")
    ap.add_argument(
        "--out",
        default=CANONICAL_SWEEP_OUT,
        help=f"Output JSON path (MUST be {CANONICAL_SWEEP_OUT})",
    )
    ap.add_argument("--tool-name", default="consistency-sweep", help="Tool name for report")
    ap.add_argument("--tool-version", default="1.0.0", help="Tool version for report")
    ap.add_argument(
        "--inputs",
        nargs="*",
        default=[],
        help="Additional repo-relative input files to include (canonical core inputs are always included)",
    )
    args = ap.parse_args(argv)

    # Deterministic contract: the consistency sweep artifact location is fixed and
    # is consumed as evidence by downstream verification. Fail closed if asked to
    # emit the canonical artifact elsewhere.
    if args.out.replace("\\\\", "/") != CANONICAL_SWEEP_OUT:
        print(
            f"NO-GO: --out must be '{CANONICAL_SWEEP_OUT}' (required by the evidence contract).",
            file=sys.stderr,
        )
        raise SystemExit(2)

    root = Path(args.repo).resolve()
    if not root.exists() or not root.is_dir():
        raise _UserInputError(f"repo root is not a directory: {root}")
    out_path = _resolve_repo_path(root, args.out, must_exist=False)
    return run_consistency_sweep(
        root=root,
        out_path=out_path,
        output_label=args.out,
        tool_name=args.tool_name,
        tool_version=args.tool_version,
        extra_inputs=args.inputs or [],
        canonical_sweep_out=CANONICAL_SWEEP_OUT,
        canonical_sweep_summary=CANONICAL_SWEEP_SUMMARY,
        consistency_spec_doc=CONSISTENCY_SPEC_DOC,
        validate_repo_rel=_validate_repo_rel,
        extract_spec_invariant_ids=_extract_spec_invariant_ids,
        invariant_registry=_invariant_registry,
        canonical_inputs=_canonical_inputs,
        repo_revision_getter=_git_tree_sha_excluding,
        resolve_existing_repo_file=lambda repo_root, rel: _resolve_repo_path(
            repo_root,
            rel,
            must_exist=True,
            must_be_file=True,
        ),
    )

def _parse_args(argv: Sequence[str] | None) -> tuple[argparse.Namespace, list[str]]:
    ap = argparse.ArgumentParser(description="Unified sweeper entrypoint")
    ap.add_argument(
        "cmd",
        choices=["consistency"],
        help="Subcommand",
    )
    ap.add_argument("args", nargs=argparse.REMAINDER, help="Subcommand args (optional leading '--' accepted)")
    ns = ap.parse_args(list(argv) if argv is not None else None)
    rest = [a for a in ns.args if a != "--"]
    return ns, rest

def main(argv: list[str] | None = None) -> int:
    try:
        ns, rest = _parse_args(argv)

        if ns.cmd == "consistency":
            return int(_consistency_sweep_main(rest))

        raise _UserInputError(f"Unknown command: {ns.cmd}")
    except _UserInputError as e:
        print(f"NO-GO: {e}")
        return 2
    except json.JSONDecodeError as e:
        print(f"NO-GO: JSON parse error: {e}")
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
