from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from belgi.core.jail import ensure_within_root, safe_relpath
from belgi.core.json_canon import canonical_json_bytes
from belgi.core.time import utc_timestamp_iso_z


def _run_git(repo: Path, args: list[str]) -> str:
    p = subprocess.run(
        ["git", "-C", str(repo)] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(f"git failed: {' '.join(args)} :: {p.stderr.strip()}")
    return p.stdout
def run_supplychain_scan(
    *,
    repo: Path,
    evaluated_revision: str,
    out_path: Path,
    deterministic: bool,
    run_id: str = "unknown",
) -> int:
    repo = repo.resolve()
    ensure_within_root(repo, repo)

    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a non-empty string")

    dirty_txt = _run_git(repo, ["status", "--porcelain"])
    dirty = bool(dirty_txt.strip())

    # changed paths between evaluated_revision and HEAD
    names = _run_git(repo, ["diff", "--name-only", evaluated_revision, "HEAD"]).splitlines()
    changed_paths: list[str] = []
    for n in names:
        n = n.strip()
        if not n:
            continue
        p = (repo / Path(*n.split("/"))).resolve()
        ensure_within_root(repo, p)
        changed_paths.append(safe_relpath(repo, p))
    changed_paths = sorted(set(changed_paths))

    passed = not dirty
    checks: list[dict[str, Any]] = [
        {
            "check_id": "policy.supplychain.clean_worktree",
            "passed": passed,
            "message": "Working tree is clean." if passed else "Working tree is dirty (uncommitted changes present).",
        }
    ]

    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "run_id": run_id.strip(),
        "generated_at": utc_timestamp_iso_z(deterministic=deterministic),
        "report_type": "supplychain_scan",
        "summary": {
            "total_checks": len(checks),
            "passed": 1 if passed else 0,
            "failed": 0 if passed else 1,
        },
        "checks": checks,
        # Extension fields (allowed by PolicyReportPayload.additionalProperties).
        "evaluated_revision": evaluated_revision,
        "dirty": dirty,
        "changed_paths": changed_paths,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(canonical_json_bytes(payload))

    return 0 if passed else 2
