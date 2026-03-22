from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Iterable

from belgi.core.jail import ensure_within_root, safe_relpath
from belgi.core.json_canon import canonical_json_bytes
from belgi.core.time import utc_timestamp_iso_z


def _run_git(repo: Path, args: list[str]) -> str:
    p = subprocess.run(
        ["git", "-C", str(repo)] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
    )
    if p.returncode != 0:
        raise RuntimeError(f"git failed: {' '.join(args)} :: {p.stderr.strip()}")
    return p.stdout


_DECLARATION_BASENAMES = {
    ".python-version",
    ".tool-versions",
    "Cargo.lock",
    "Cargo.toml",
    "Gemfile",
    "Gemfile.lock",
    "Pipfile",
    "Pipfile.lock",
    "composer.json",
    "composer.lock",
    "go.mod",
    "go.sum",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pyproject.toml",
    "runtime.txt",
    "setup.cfg",
    "setup.py",
    "tox.ini",
    "uv.lock",
    "yarn.lock",
}


def _normalize_repo_relpath(repo: Path, raw: str) -> str:
    rel = Path(*str(raw).strip().split("/"))
    normalized = (repo / rel).resolve()
    ensure_within_root(repo, normalized)
    return safe_relpath(repo, normalized)


def _parse_changed_paths(repo: Path, *, base_revision: str, evaluated_revision: str) -> list[str]:
    output = _run_git(
        repo,
        ["diff", "--name-status", "--find-renames", base_revision, evaluated_revision, "--", "."],
    )
    changed_paths: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0]
        if status.startswith(("R", "C")) and len(parts) >= 3:
            candidate = parts[-1]
        else:
            candidate = parts[1]
        changed_paths.append(_normalize_repo_relpath(repo, candidate))
    return sorted(set(changed_paths))


def _normalize_declared_toolchain_refs(repo: Path, refs: Iterable[str]) -> list[str]:
    normalized: list[str] = []
    for raw in refs:
        text = str(raw or "").strip()
        if not text:
            continue
        storage_ref = text.split("=", 1)[1] if "=" in text else text
        normalized.append(_normalize_repo_relpath(repo, storage_ref))
    return sorted(set(normalized))


def _is_named_supplychain_surface(path: str) -> bool:
    basename = Path(path).name
    if basename in _DECLARATION_BASENAMES:
        return True
    if basename.startswith("requirements") and basename.endswith(".txt"):
        return True
    if basename.startswith("constraints") and basename.endswith(".txt"):
        return True
    return False


def run_supplychain_scan(
    *,
    repo: Path,
    base_revision: str,
    evaluated_revision: str,
    declared_toolchain_refs: Iterable[str] = (),
    out_path: Path,
    deterministic: bool,
    run_id: str = "unknown",
) -> int:
    repo = repo.resolve()
    ensure_within_root(repo, repo)

    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a non-empty string")

    changed_paths = _parse_changed_paths(
        repo,
        base_revision=base_revision,
        evaluated_revision=evaluated_revision,
    )
    declared_paths = _normalize_declared_toolchain_refs(repo, declared_toolchain_refs)
    relevant_changed_paths = sorted(
        {
            path
            for path in changed_paths
            if _is_named_supplychain_surface(path) or path in declared_paths
        }
    )
    unaccounted_paths = sorted(path for path in relevant_changed_paths if path not in declared_paths)

    passed = len(unaccounted_paths) == 0
    checks: list[dict[str, Any]] = [
        {
            "check_id": "policy.supplychain.declared_change_accounting",
            "passed": passed,
            "message": (
                "No unaccounted dependency/toolchain declaration changes detected in the base->evaluated diff."
                if passed
                else f"Unaccounted dependency/toolchain declaration changes detected: {len(unaccounted_paths)}."
            ),
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
        "base_revision": base_revision,
        "evaluated_revision": evaluated_revision,
        "changed_paths": changed_paths,
        "declared_toolchain_refs": declared_paths,
        "relevant_changed_paths": relevant_changed_paths,
        "unaccounted_paths": unaccounted_paths,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(canonical_json_bytes(payload))

    return 0
