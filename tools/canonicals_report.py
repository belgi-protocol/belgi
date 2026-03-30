#!/usr/bin/env python3
"""Derive a bounded structural report from CANONICALS.md.

This report is projection-level only. It exposes only finite, mechanically
expressed owner surfaces without re-owning prose-law semantics.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from belgi.core.jail import resolve_repo_rel_path, safe_relpath

REPORT_SCHEMA_VERSION = "1.0.0"

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")


class CanonicalsReportError(RuntimeError):
    pass


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def _canonical_json_bytes(obj: object) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8", errors="strict"
    )


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def _extract_markdown_section(md: str, heading_title: str) -> str:
    lines = md.splitlines()
    start: int | None = None
    level = 0
    for idx, line in enumerate(lines):
        match = _HEADING_RE.match(line)
        if match is None:
            continue
        if match.group(2).strip() == heading_title:
            start = idx + 1
            level = len(match.group(1))
            break
    if start is None:
        raise CanonicalsReportError(f"Missing required section: {heading_title}")

    end = len(lines)
    for idx in range(start, len(lines)):
        match = _HEADING_RE.match(lines[idx])
        if match is not None and len(match.group(1)) <= level:
            end = idx
            break
    return "\n".join(lines[start:end]).strip()


def _derive_anchor_registry_ids(md: str) -> list[str]:
    section = _extract_markdown_section(md, "Anchor Registry (Stable IDs)")
    ids: list[str] = []
    for raw_line in section.splitlines():
        match = re.match(r"^\s*-\s*([a-z0-9][a-z0-9-]*)\s*$", raw_line)
        if match is not None:
            ids.append(match.group(1))
    if not ids:
        raise CanonicalsReportError("Anchor Registry (Stable IDs) must contain at least one anchor id.")
    if len(set(ids)) != len(ids):
        raise CanonicalsReportError("Anchor Registry (Stable IDs) must not contain duplicate anchor ids.")
    return ids


def _derive_canonical_chain(md: str) -> dict[str, object]:
    section = _extract_markdown_section(md, "2. Canonical Chain (Canonical)")
    line = next((raw.strip() for raw in section.splitlines() if "→" in raw), "")
    if not line:
        raise CanonicalsReportError("Canonical chain section must contain one explicit arrow chain line.")
    sequence = [part.strip(" `") for part in line.split("→")]
    if not sequence or any(not stage for stage in sequence):
        raise CanonicalsReportError("Canonical chain line is malformed.")
    return {"sequence": sequence}


def derive_canonicals_report(repo_root: Path) -> dict[str, object]:
    canonicals_path = resolve_repo_rel_path(
        repo_root,
        "CANONICALS.md",
        must_exist=True,
        must_be_file=True,
        allow_backslashes=False,
        forbid_symlinks=True,
    )
    md = _read_text(canonicals_path)
    return {
        "anchor_registry_ids": _derive_anchor_registry_ids(md),
        "canonical_chain": _derive_canonical_chain(md),
        "owner_surface": "CANONICALS.md",
        "projection_kind": "derived-prose-owner-report",
        "report_schema_version": REPORT_SCHEMA_VERSION,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Derive a bounded structural report from CANONICALS.md")
    ap.add_argument("--repo", required=True, help="Repo root")
    ap.add_argument("--out", help="Optional repo-relative output path for the derived JSON report")
    args = ap.parse_args(argv)

    try:
        repo_root = Path(str(args.repo)).resolve()
        if not repo_root.exists() or not repo_root.is_dir():
            raise CanonicalsReportError(f"--repo does not exist or is not a directory: {repo_root}")
        report = derive_canonicals_report(repo_root)
        data = _canonical_json_bytes(report)
        if args.out:
            out_path = resolve_repo_rel_path(
                repo_root,
                str(args.out),
                must_exist=False,
                must_be_file=None,
                allow_backslashes=False,
                forbid_symlinks=True,
            )
            _write_atomic(out_path, data)
            print(f"Wrote: {safe_relpath(repo_root, out_path)}", file=sys.stderr)
        else:
            sys.stdout.write(data.decode("utf-8", errors="strict"))
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
