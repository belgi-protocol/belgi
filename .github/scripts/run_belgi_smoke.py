#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


BELGI_RESULT_PREFIX = "BELGI_RESULT"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def _run(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )


def _as_sha40(raw: str) -> str | None:
    candidate = str(raw or "").strip().lower()
    if SHA40_RE.fullmatch(candidate):
        return candidate
    return None


def _git_resolve_sha40(repo_root: Path, revision: str) -> str | None:
    cp = _run(["git", "rev-parse", "--verify", f"{revision}^{{commit}}"], cwd=repo_root)
    if cp.returncode != 0:
        return None
    return _as_sha40(cp.stdout)


def _resolve_base_revision(repo_root: Path) -> tuple[str | None, str | None]:
    for env_name in ("BELGI_BASE_SHA", "GITHUB_BASE_SHA"):
        raw = os.environ.get(env_name, "")
        if not str(raw).strip():
            continue
        sha = _as_sha40(raw)
        if sha is None:
            return None, f"{env_name} must be a stable 40-hex commit SHA"
        return sha, None

    parent_sha = _git_resolve_sha40(repo_root, "HEAD~1")
    if parent_sha is not None:
        return parent_sha, None

    head_sha = _git_resolve_sha40(repo_root, "HEAD")
    if head_sha is not None:
        return head_sha, None

    return None, "unable to resolve base revision from env or git history"


def _first_line_machine_json(stdout_text: str, *, label: str) -> dict[str, object]:
    lines = stdout_text.splitlines()
    if not lines:
        raise ValueError(f"{label}: missing stdout machine result line")
    first = lines[0].strip()
    if not first:
        raise ValueError(f"{label}: empty first stdout line")
    payload = first
    if first.startswith(BELGI_RESULT_PREFIX):
        payload = first[len(BELGI_RESULT_PREFIX) :].strip()
    try:
        obj = json.loads(payload)
    except Exception as e:
        raise ValueError(f"{label}: first stdout line is not valid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError(f"{label}: first stdout line JSON must be an object")
    if not isinstance(obj.get("ok"), bool):
        raise ValueError(f"{label}: machine JSON missing boolean 'ok'")
    if not isinstance(obj.get("verdict"), str):
        raise ValueError(f"{label}: machine JSON missing string 'verdict'")
    return obj


def _assert_success(cp: subprocess.CompletedProcess[str], *, label: str) -> None:
    if cp.returncode == 0:
        return
    raise RuntimeError(
        f"{label} failed rc={cp.returncode}\n"
        f"stdout:\n{cp.stdout}\n"
        f"stderr:\n{cp.stderr}"
    )


def _append_github_output(*, run_key: str, attempt_id: str, attempt_dir: Path, run_log: Path) -> None:
    out_path = os.environ.get("GITHUB_OUTPUT", "").strip()
    if not out_path:
        return
    with Path(out_path).open("a", encoding="utf-8", errors="strict") as handle:
        handle.write(f"run_key={run_key}\n")
        handle.write(f"attempt_id={attempt_id}\n")
        handle.write(f"attempt_dir={attempt_dir.as_posix()}\n")
        handle.write(f"run_log={run_log.as_posix()}\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="run_belgi_smoke",
        description="Cross-platform BELGI smoke runner for init/run/verify and artifact assertions.",
    )
    ap.add_argument("--repo", default=".", help="Repo root (default: .)")
    ap.add_argument("--tier", choices=("tier-0", "tier-1"), default="tier-0")
    ap.add_argument("--bundle-check", action="store_true", help="Run belgi bundle check after verify")
    ap.add_argument(
        "--belgi-executable",
        default="",
        help="Path to belgi executable (default: resolve from PATH).",
    )
    ns = ap.parse_args(argv)

    repo_root = Path(ns.repo).resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        return _fail(f"invalid repo root: {repo_root}")

    belgi_bin = str(ns.belgi_executable or "").strip()
    if not belgi_bin:
        belgi_bin = shutil.which("belgi") or ""
    if not belgi_bin:
        return _fail("missing belgi executable in PATH")

    workspace_dir = repo_root / ".belgi"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    run_log_path = workspace_dir / "run.stdout.log"

    cp_init = _run([belgi_bin, "init", "--repo", "."], cwd=repo_root)
    try:
        _assert_success(cp_init, label="belgi init")
    except RuntimeError as e:
        return _fail(str(e))

    base_revision, base_error = _resolve_base_revision(repo_root)
    if base_revision is None:
        return _fail(base_error or "unable to resolve base revision")

    cp_run = _run(
        [belgi_bin, "run", "--repo", ".", "--tier", ns.tier, "--base-revision", base_revision],
        cwd=repo_root,
    )
    try:
        _assert_success(cp_run, label=f"belgi run --tier {ns.tier}")
    except RuntimeError as e:
        return _fail(str(e))

    run_log_text = cp_run.stdout
    if run_log_text and not run_log_text.endswith("\n"):
        run_log_text += "\n"
    run_log_path.write_text(run_log_text, encoding="utf-8", errors="strict")

    try:
        run_obj = _first_line_machine_json(cp_run.stdout, label="belgi run")
    except ValueError as e:
        return _fail(str(e))

    run_key = run_obj.get("run_key")
    attempt_id = run_obj.get("attempt_id")
    if not isinstance(run_key, str) or not run_key:
        return _fail("belgi run: missing run_key in machine JSON")
    if not isinstance(attempt_id, str) or not attempt_id:
        return _fail("belgi run: missing attempt_id in machine JSON")

    attempt_dir = workspace_dir / "runs" / run_key / attempt_id
    if not attempt_dir.is_dir():
        return _fail(f"missing attempt directory: {attempt_dir}")
    summary_path = attempt_dir / "run.summary.json"
    if not summary_path.is_file():
        return _fail(f"missing run.summary.json: {summary_path}")
    out_dir = attempt_dir / "repo" / "out"
    if not out_dir.is_dir():
        return _fail(f"missing chain out directory: {out_dir}")

    cp_verify = _run([belgi_bin, "verify", "--repo", "."], cwd=repo_root)
    try:
        _assert_success(cp_verify, label="belgi verify")
    except RuntimeError as e:
        return _fail(str(e))

    try:
        _ = _first_line_machine_json(cp_verify.stdout, label="belgi verify")
    except ValueError as e:
        return _fail(str(e))

    if ns.bundle_check:
        cp_bundle = _run(
            [
                belgi_bin,
                "bundle",
                "check",
                "--in",
                out_dir.as_posix(),
                "--demo",
                "--verbose",
            ],
            cwd=repo_root,
        )
        try:
            _assert_success(cp_bundle, label="belgi bundle check --demo --verbose")
        except RuntimeError as e:
            return _fail(str(e))

    _append_github_output(
        run_key=run_key,
        attempt_id=attempt_id,
        attempt_dir=attempt_dir,
        run_log=run_log_path,
    )

    print(
        json.dumps(
            {
                "ok": True,
                "tier": ns.tier,
                "run_key": run_key,
                "attempt_id": attempt_id,
                "attempt_dir": attempt_dir.as_posix(),
                "run_log": run_log_path.as_posix(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
