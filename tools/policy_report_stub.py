#!/usr/bin/env python3
"""Deterministic PolicyReportPayload stub generator for adopter overlay proofs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from belgi.core.hash import sha256_bytes
from belgi.core.jail import resolve_repo_rel_path, safe_relpath


DEFAULT_GENERATED_AT = "1970-01-01T00:00:00Z"


def _parse_check(raw: str) -> tuple[str, bool]:
    s = str(raw or "").strip()
    if not s:
        raise ValueError("empty --check value")
    if ":" not in s:
        return s, True
    cid, v = s.split(":", 1)
    cid = cid.strip()
    if not cid:
        raise ValueError("check_id must not be empty")
    vv = v.strip().lower()
    if vv in ("1", "true", "pass", "passed", "go"):
        return cid, True
    if vv in ("0", "false", "fail", "failed", "no-go"):
        return cid, False
    raise ValueError(f"unsupported check status value for {cid!r}: {v!r}")


def _parse_checks(raw_values: list[str]) -> list[dict[str, object]]:
    if not raw_values:
        raise ValueError("at least one --check is required")
    checks: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw in raw_values:
        cid, passed = _parse_check(raw)
        if cid in seen:
            raise ValueError(f"duplicate check_id is not allowed: {cid!r}")
        seen.add(cid)
        checks.append({"check_id": cid, "passed": passed})
    checks.sort(key=lambda c: str(c["check_id"]))
    return checks


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate deterministic PolicyReportPayload stub JSON")
    ap.add_argument("--repo", required=True, help="Repo root")
    ap.add_argument("--out", required=True, help="Repo-relative output JSON path")
    ap.add_argument("--run-id", required=True, help="Run id for PolicyReportPayload")
    ap.add_argument(
        "--check",
        action="append",
        default=[],
        help="Check entry CHECK_ID or CHECK_ID:true|false (repeatable; default status=true if omitted)",
    )
    ap.add_argument("--schema-version", default="1.0.0", help="schema_version (default: 1.0.0)")
    ap.add_argument("--generated-at", default=DEFAULT_GENERATED_AT, help=f"generated_at (default: {DEFAULT_GENERATED_AT})")
    ap.add_argument("--overwrite", action="store_true", help="Overwrite output if it exists")
    args = ap.parse_args(argv)

    try:
        repo_root = Path(str(args.repo)).resolve()
        if not repo_root.exists() or not repo_root.is_dir():
            print(f"ERROR: --repo does not exist or is not a directory: {repo_root}", file=sys.stderr)
            return 3
        if repo_root.is_symlink():
            print(f"ERROR: symlink repo root not allowed: {repo_root}", file=sys.stderr)
            return 3

        out_path = resolve_repo_rel_path(
            repo_root,
            str(args.out),
            must_exist=False,
            must_be_file=None,
            allow_backslashes=False,
            forbid_symlinks=True,
        )
        if out_path.exists():
            if out_path.is_symlink() or not out_path.is_file():
                print(f"ERROR: invalid output path (must be regular file): {out_path}", file=sys.stderr)
                return 3
            if not bool(args.overwrite):
                print(f"ERROR: output exists (use --overwrite): {safe_relpath(repo_root, out_path)}", file=sys.stderr)
                return 3

        checks = _parse_checks([str(x) for x in args.check])
        passed_count = sum(1 for c in checks if c.get("passed") is True)
        failed_count = len(checks) - passed_count

        payload = {
            "schema_version": str(args.schema_version),
            "run_id": str(args.run_id),
            "generated_at": str(args.generated_at),
            "summary": {
                "total_checks": len(checks),
                "passed": passed_count,
                "failed": failed_count,
            },
            "checks": checks,
        }
        raw = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
        _write_atomic(out_path, raw)
        print(f"Wrote: {safe_relpath(repo_root, out_path)}")
        print(f"SHA-256: {sha256_bytes(raw)}")
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
